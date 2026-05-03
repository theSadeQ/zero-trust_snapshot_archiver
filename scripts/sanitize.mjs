import * as cheerio from "cheerio";
import { absolutizeSrcset } from "./srcset.mjs";

/**
 * Policy choices:
 *
 * 1) data: is blocked everywhere for simplicity and safety.
 *    Why: data URLs can embed executable or tracking content and create edge
 *    cases. A consistent fail-closed rule is easier to reason about.
 *
 * 2) Forms are neutralized, not removed.
 *    Why: preserving form structure is better for visual fidelity, while
 *    removing action/method and submit controls prevents submission.
 *
 * 3) Existing <base> tags are removed and exactly one controlled <base> is inserted.
 *    Why: a hostile page can manipulate relative URL resolution. We want a
 *    deterministic base for the archived document.
 */

const URL_ATTRS = [
  "href",
  "src",
  "poster",
  "action",
  "formaction",
  "cite",
  "data"
];

const SRCSET_ATTRS = ["srcset"];

const RESOURCE_HINT_SELECTORS = [
  'link[rel="preload"]',
  'link[rel="prefetch"]',
  'link[rel="preconnect"]',
  'link[rel="dns-prefetch"]',
  'link[rel="modulepreload"]',
  'link[rel="prerender"]'
].join(",");

function isDangerousUrlValue(raw) {
  if (!raw) return true;
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();

  return (
    lower.startsWith("javascript:") ||
    lower.startsWith("data:") ||
    lower.startsWith("blob:") ||
    lower.startsWith("file:") ||
    lower.startsWith("about:")
  );
}

function normalizeResolvableUrl(rawValue, baseUrl) {
  if (!rawValue) return null;
  if (isDangerousUrlValue(rawValue)) return null;

  try {
    const abs = new URL(rawValue, baseUrl);
    if (abs.protocol !== "http:" && abs.protocol !== "https:") return null;
    return abs.href;
  } catch {
    return null;
  }
}

function ensureHead($) {
  if ($("html").length === 0) {
    $.root().prepend("<html><head></head><body></body></html>");
  } else if ($("head").length === 0) {
    $("html").prepend("<head></head>");
  }
}

export function sanitizeHtml(html, baseUrl) {
  const $ = cheerio.load(html, {
    decodeEntities: false
  });

  // Remove active/executable or nested browsing content.
  $("script, iframe, frame, object, embed").remove();

  // Remove dangerous resource hints and refresh redirects.
  $(RESOURCE_HINT_SELECTORS).remove();
  $('meta[http-equiv]').each((_, el) => {
    const value = ($(el).attr("http-equiv") || "").trim().toLowerCase();
    if (value === "refresh") {
      $(el).remove();
    }
  });

  // Strip inline event handlers and dangerous inline styles that can load URLs.
  $("*").each((_, el) => {
    const attribs = { ...(el.attribs || {}) };

    for (const [name, value] of Object.entries(attribs)) {
      const lower = name.toLowerCase();

      if (lower.startsWith("on")) {
        $(el).removeAttr(name);
        continue;
      }

      if (lower === "style" && typeof value === "string") {
        // Conservative choice: remove styles containing url(...) or expression(...)
        // to avoid dynamic fetches or legacy script-like behavior.
        const styleLower = value.toLowerCase();
        if (styleLower.includes("url(") || styleLower.includes("expression(")) {
          $(el).removeAttr(name);
        }
      }
    }
  });

  // Neutralize URL-bearing attributes.
  for (const attr of URL_ATTRS) {
    $(`[${attr}]`).each((_, el) => {
      const rawValue = $(el).attr(attr);
      const safeValue = normalizeResolvableUrl(rawValue, baseUrl);
      if (!safeValue) {
        $(el).removeAttr(attr);
      } else {
        $(el).attr(attr, safeValue);
      }
    });
  }

  // Rewrite srcset safely.
  for (const attr of SRCSET_ATTRS) {
    $(`[${attr}]`).each((_, el) => {
      const rawValue = $(el).attr(attr);
      const rewritten = absolutizeSrcset(rawValue, baseUrl, normalizeResolvableUrl);
      if (!rewritten) {
        $(el).removeAttr(attr);
      } else {
        $(el).attr(attr, rewritten);
      }
    });
  }

  // Remove base tags first, then insert exactly one controlled base.
  $("base").remove();
  ensureHead($);
  $("head").prepend(`<base href="${new URL(baseUrl).href}">`);

  // Neutralize forms but preserve structure.
  $("form").each((_, form) => {
    $(form).removeAttr("action");
    $(form).removeAttr("method");
    $(form).removeAttr("target");
    $(form).removeAttr("enctype");

    $(form)
      .find("input, button")
      .each((__, field) => {
        const type = (($(field).attr("type") || "").trim().toLowerCase());

        if (type === "submit" || type === "image" || type === "button") {
          $(field).remove();
          return;
        }

        if (field.tagName?.toLowerCase() === "button") {
          $(field).remove();
        }
      });
  });

  return $.html();
}
