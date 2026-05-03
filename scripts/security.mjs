import dns from "dns/promises";
import net from "net";
import ipaddr from "ipaddr.js";

/**
 * Why this module exists:
 * We want a single place that defines URL/network safety policy.
 * The browser route handler and the initial top-level URL validation should
 * both rely on the same rules.
 */

/**
 * Explicit scheme policy for outbound requests.
 * - http/https: allowed to proceed to hostname/IP validation
 * - data/blob/about/file/javascript: blocked
 */
export const SCHEME_POLICY = Object.freeze({
  "http:": "allow",
  "https:": "allow",
  "data:": "block",
  "blob:": "block",
  "about:": "block",
  "file:": "block",
  "javascript:": "block"
});

/**
 * Hostnames that must never be contacted directly.
 * We block localhost-like names in addition to private/reserved IP ranges.
 */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "localhost.localdomain",
  "local",
  "ip6-localhost",
  "ip6-loopback",
  "metadata.google.internal"
]);

/**
 * Reserved / private / special ranges.
 * This is broader than just RFC1918 because SSRF often targets link-local,
 * loopback, documentation ranges, multicast, unspecified, and cloud-like internals.
 */
const BLOCKED_CIDRS = [
  // IPv4
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",

  // IPv6
  "::/128",
  "::1/128",
  "::ffff:0:0/96",
  "64:ff9b::/96",
  "100::/64",
  "2001::/32",
  "2001:2::/48",
  "2001:db8::/32",
  "2001:10::/28",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8"
];

const PARSED_BLOCKED_CIDRS = BLOCKED_CIDRS.map((cidr) => ipaddr.parseCIDR(cidr));

/**
 * A bounded per-run DNS safety cache.
 *
 * Why bounded/per-run:
 * - avoids unbounded memory growth
 * - avoids persisting trust across runs
 *
 * Trade-off:
 * - caching successful DNS checks weakens protection slightly against extremely
 *   rapid DNS rebinding during the same run
 * - therefore it is only a best-effort performance optimization
 */
export function createSafeHostCache(limit = 500) {
  const map = new Map();

  return {
    get(key) {
      return map.get(key);
    },
    set(key, value) {
      if (map.size >= limit && !map.has(key)) {
        const firstKey = map.keys().next().value;
        map.delete(firstKey);
      }
      map.set(key, value);
    },
    has(key) {
      return map.has(key);
    },
    clear() {
      map.clear();
    },
    size() {
      return map.size;
    }
  };
}

function isBlockedHostname(hostname) {
  const lower = hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.has(lower)) return true;
  if (lower.endsWith(".localhost")) return true;
  if (lower.endsWith(".local")) return true;

  return false;
}

function isIpLiteral(hostname) {
  return net.isIP(hostname) !== 0;
}

function isBlockedIp(ip) {
  let addr;
  try {
    addr = ipaddr.parse(ip);
  } catch {
    return true;
  }

  return PARSED_BLOCKED_CIDRS.some(([range, prefix]) => addr.kind() === range.kind() && addr.match([range, prefix]));
}

/**
 * Resolve all A and AAAA records. We treat resolution failure as unsafe.
 * That is the safer default for a zero-trust tool.
 */
export async function resolveAll(hostname) {
  const [v4, v6] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname)
  ]);

  const ips = [];

  if (v4.status === "fulfilled") ips.push(...v4.value);
  if (v6.status === "fulfilled") ips.push(...v6.value);

  return [...new Set(ips)];
}

/**
 * Validate a URL for initial navigation or subresource fetch.
 *
 * Returns structured data so callers can:
 * - fail closed
 * - record why something was blocked
 * - categorize blocking reason as scheme / dns / policy / invalid
 */
export async function checkUrlSafety(rawUrl, cache) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return {
      ok: false,
      category: "invalid",
      reason: "invalid-url",
      normalizedUrl: null,
      hostname: null,
      protocol: null,
      resolvedIps: []
    };
  }

  const protocol = url.protocol;
  const schemeDecision = SCHEME_POLICY[protocol];

  if (!schemeDecision) {
    return {
      ok: false,
      category: "scheme",
      reason: "unknown-scheme",
      normalizedUrl: url.href,
      hostname: url.hostname || null,
      protocol,
      resolvedIps: []
    };
  }

  if (schemeDecision === "block") {
    return {
      ok: false,
      category: "scheme",
      reason: `blocked-scheme:${protocol}`,
      normalizedUrl: url.href,
      hostname: url.hostname || null,
      protocol,
      resolvedIps: []
    };
  }

  if (protocol !== "http:" && protocol !== "https:") {
    return {
      ok: false,
      category: "scheme",
      reason: `unsupported-scheme:${protocol}`,
      normalizedUrl: url.href,
      hostname: url.hostname || null,
      protocol,
      resolvedIps: []
    };
  }

  const hostname = url.hostname.toLowerCase();

  if (!hostname) {
    return {
      ok: false,
      category: "invalid",
      reason: "missing-hostname",
      normalizedUrl: url.href,
      hostname: null,
      protocol,
      resolvedIps: []
    };
  }

  if (isBlockedHostname(hostname)) {
    return {
      ok: false,
      category: "policy",
      reason: "blocked-hostname",
      normalizedUrl: url.href,
      hostname,
      protocol,
      resolvedIps: []
    };
  }

  if (isIpLiteral(hostname)) {
    return {
      ok: false,
      category: "policy",
      reason: "ip-literal-disallowed",
      normalizedUrl: url.href,
      hostname,
      protocol,
      resolvedIps: [hostname]
    };
  }

  const cacheKey = `${protocol}//${hostname}`;
  const cached = cache?.get(cacheKey);
  if (cached?.ok) {
    return {
      ...cached,
      normalizedUrl: url.href
    };
  }

  let resolvedIps;
  try {
    resolvedIps = await resolveAll(hostname);
  } catch {
    return {
      ok: false,
      category: "dns",
      reason: "dns-resolution-failed",
      normalizedUrl: url.href,
      hostname,
      protocol,
      resolvedIps: []
    };
  }

  if (!resolvedIps.length) {
    return {
      ok: false,
      category: "dns",
      reason: "no-dns-records",
      normalizedUrl: url.href,
      hostname,
      protocol,
      resolvedIps: []
    };
  }

  for (const ip of resolvedIps) {
    if (isBlockedIp(ip)) {
      return {
        ok: false,
        category: "dns",
        reason: "resolved-to-blocked-ip",
        normalizedUrl: url.href,
        hostname,
        protocol,
        resolvedIps
      };
    }
  }

  const safeResult = {
    ok: true,
    category: null,
    reason: null,
    normalizedUrl: url.href,
    hostname,
    protocol,
    resolvedIps
  };

  cache?.set(cacheKey, safeResult);
  return safeResult;
}

export function trimExtractedUrlCandidate(candidate) {
  /**
   * Why this exists:
   * commit messages often contain trailing punctuation, e.g.
   *   https://example.com),
   *   https://example.com.
   *
   * We trim common trailing punctuation conservatively.
   */
  let out = candidate.trim();

  while (
    out.length > 0 &&
    /[),.;!?'"`\]]$/.test(out)
  ) {
    const last = out[out.length - 1];

    if (last === ")") {
      const opens = [...out].filter((c) => c === "(").length;
      const closes = [...out].filter((c) => c === ")").length;
      if (closes <= opens) break;
    }

    out = out.slice(0, -1);
  }

  return out;
}

export function extractUrlsFromText(text) {
  if (!text || typeof text !== "string") return [];

  const matches = text.match(/https?:\/\/[^\s<>"'`]+/g) || [];
  const cleaned = matches.map(trimExtractedUrlCandidate).filter(Boolean);

  return [...new Set(cleaned)];
}
