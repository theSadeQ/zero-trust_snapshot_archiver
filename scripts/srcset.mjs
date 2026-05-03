/**
 * Why this exists:
 * `srcset` is not safely handled by naive string splitting because candidates
 * may have irregular whitespace and malformed entries.
 *
 * This parser intentionally supports common valid syntax:
 * - URL
 * - URL <width>w
 * - URL <density>x
 *
 * If a candidate is malformed, it is dropped.
 * If the overall result becomes empty, callers should remove the `srcset`.
 */

/**
 * Split a srcset string on top-level commas.
 * For the subset we support, commas are candidate separators.
 */
function splitCandidates(input) {
  const parts = [];
  let current = "";

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];
    if (ch === ",") {
      if (current.trim()) parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }

  if (current.trim()) parts.push(current.trim());
  return parts;
}

function parseSingleCandidate(candidate) {
  const tokens = candidate.trim().split(/\s+/).filter(Boolean);

  if (tokens.length === 0) return null;
  if (tokens.length > 2) return null;

  const url = tokens[0];
  const descriptor = tokens[1] ?? null;

  if (!url) return null;

  if (descriptor === null) {
    return { url, descriptor: null };
  }

  if (/^\d+w$/.test(descriptor)) {
    const value = Number(descriptor.slice(0, -1));
    if (!Number.isInteger(value) || value <= 0) return null;
    return { url, descriptor };
  }

  if (/^\d*\.?\d+x$/.test(descriptor)) {
    const value = Number(descriptor.slice(0, -1));
    if (!Number.isFinite(value) || value <= 0) return null;
    return { url, descriptor };
  }

  return null;
}

export function parseSrcset(input) {
  if (!input || typeof input !== "string") return [];

  const candidates = splitCandidates(input);
  const parsed = [];

  for (const candidate of candidates) {
    const item = parseSingleCandidate(candidate);
    if (item) parsed.push(item);
  }

  return parsed;
}

export function absolutizeSrcset(input, baseUrl, resolver) {
  const parsed = parseSrcset(input);
  const rewritten = [];

  for (const item of parsed) {
    const abs = resolver(item.url, baseUrl);
    if (!abs) continue;
    rewritten.push(item.descriptor ? `${abs} ${item.descriptor}` : abs);
  }

  return rewritten.join(", ");
}
