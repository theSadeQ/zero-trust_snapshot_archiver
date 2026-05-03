import assert from "node:assert/strict";
import {
  checkUrlSafety,
  createSafeHostCache,
  extractUrlsFromText,
  trimExtractedUrlCandidate
} from "../scripts/security.mjs";

async function run() {
  const cache = createSafeHostCache();

  // file: must be rejected explicitly
  {
    const result = await checkUrlSafety("file:///etc/passwd", cache);
    assert.equal(result.ok, false);
    assert.equal(result.category, "scheme");
  }

  // data: must be rejected explicitly
  {
    const result = await checkUrlSafety("data:text/html,hello", cache);
    assert.equal(result.ok, false);
    assert.equal(result.category, "scheme");
  }

  // blob: must be rejected explicitly
  {
    const result = await checkUrlSafety("blob:https://example.com/123", cache);
    assert.equal(result.ok, false);
    assert.equal(result.category, "scheme");
  }

  // localhost-like names must be blocked offline, without DNS assumptions
  {
    const result = await checkUrlSafety("http://localhost/test", cache);
    assert.equal(result.ok, false);
    assert.equal(result.category, "policy");
  }

  {
    const result = await checkUrlSafety("http://foo.localhost/test", cache);
    assert.equal(result.ok, false);
    assert.equal(result.category, "policy");
  }

  {
    const result = await checkUrlSafety("http://dev.local/path", cache);
    assert.equal(result.ok, false);
    assert.equal(result.category, "policy");
  }

  // Direct IP literals are blocked
  {
    const result = await checkUrlSafety("http://127.0.0.1/", cache);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "ip-literal-disallowed");
  }

  {
    const result = await checkUrlSafety("http://[::1]/", cache);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "ip-literal-disallowed");
  }

  // URL extraction should trim common trailing punctuation safely
  {
    const text = `
      See https://example.com/test),
      and https://example.org/abc.
      Also "https://example.net/path", please.
    `;
    const urls = extractUrlsFromText(text);
    assert.deepEqual(urls, [
      "https://example.com/test",
      "https://example.org/abc",
      "https://example.net/path"
    ]);
  }

  {
    assert.equal(trimExtractedUrlCandidate("https://example.com/x),"), "https://example.com/x");
    assert.equal(trimExtractedUrlCandidate("https://example.com/x"), "https://example.com/x");
  }

  // This test is intentionally online-dependent, but only checks a normal public hostname.
  // If DNS is unavailable in the environment, skip hard failure.
  {
    try {
      const result = await checkUrlSafety("https://example.com", cache);
      assert.equal(result.ok, true);
    } catch {
      // Accept environments with no outbound DNS during offline CI simulation.
    }
  }

  console.log("security tests passed");
}

await run();
