import assert from "node:assert/strict";
import { sanitizeHtml } from "../scripts/sanitize.mjs";
import { parseSrcset } from "../scripts/srcset.mjs";

function includesOnce(haystack, needle) {
  return haystack.split(needle).length - 1 === 1;
}

function run() {
  const baseUrl = "https://example.com/base/page.html";

  // Scripts, event handlers, and dangerous hrefs/srcs must go away
  {
    const input = `
      <html>
        <head>
          <base href="https://evil.example/">
          <base href="https://evil2.example/">
          <script>alert(1)</script>
          <meta http-equiv="refresh" content="0;url=https://evil.example/">
          <link rel="preload" href="/x.js">
        </head>
        <body onload="alert(1)">
          <a href="javascript:alert(1)" onclick="x()">bad</a>
          <img src="data:image/png;base64,aaaa" onerror="y()">
          <div style="background-image:url(https://evil.example/a.png)">x</div>
        </body>
      </html>
    `;

    const out = sanitizeHtml(input, baseUrl);

    assert.equal(out.includes("<script"), false);
    assert.equal(out.includes("onload="), false);
    assert.equal(out.includes("onclick="), false);
    assert.equal(out.includes("onerror="), false);
    assert.equal(out.includes('href="javascript:'), false);
    assert.equal(out.includes('src="data:'), false);
    assert.equal(out.includes("http-equiv"), false);
    assert.equal(out.includes('rel="preload"'), false);
    assert.equal(out.includes("background-image"), false);
    assert.equal(includesOnce(out, "<base "), true);
    assert.equal(out.includes('href="https://example.com/base/page.html"'), true);
  }

  // Forms are neutralized, not removed
  {
    const input = `
      <form action="https://evil.example/submit" method="post" target="_blank" enctype="multipart/form-data">
        <input type="text" name="q" value="x">
        <input type="submit" value="Go">
        <button type="submit">Send</button>
      </form>
    `;

    const out = sanitizeHtml(input, baseUrl);

    assert.equal(out.includes("<form"), true);
    assert.equal(out.includes("action="), false);
    assert.equal(out.includes("method="), false);
    assert.equal(out.includes("target="), false);
    assert.equal(out.includes("enctype="), false);
    assert.equal(out.includes('type="submit"'), false);
    assert.equal(out.includes("<button"), false);
    assert.equal(out.includes('type="text"'), true);
  }

  // data:/blob:/file:/about: should be removed consistently
  {
    const input = `
      <a href="data:text/html,hi">a</a>
      <img src="blob:https://example.com/x">
      <form action="file:///etc/passwd"></form>
      <blockquote cite="about:blank"></blockquote>
    `;
    const out = sanitizeHtml(input, baseUrl);

    assert.equal(out.includes("data:text/html"), false);
    assert.equal(out.includes("blob:https://"), false);
    assert.equal(out.includes("file:///"), false);
    assert.equal(out.includes("about:blank"), false);
  }

  // Relative URLs should be absolutized
  {
    const input = `
      <a href="/hello">hi</a>
      <img src="img/pic.png">
    `;
    const out = sanitizeHtml(input, baseUrl);

    assert.equal(out.includes('href="https://example.com/hello"'), true);
    assert.equal(out.includes('src="https://example.com/base/img/pic.png"'), true);
  }

  // srcset parsing: 480w, 2x, no descriptor, whitespace, malformed
  {
    const parsed = parseSrcset("small.jpg 480w, retina.jpg 2x, plain.jpg, bad.jpg 3q, weird.jpg   1.5x");
    assert.deepEqual(parsed, [
      { url: "small.jpg", descriptor: "480w" },
      { url: "retina.jpg", descriptor: "2x" },
      { url: "plain.jpg", descriptor: null },
      { url: "weird.jpg", descriptor: "1.5x" }
    ]);
  }

  {
    const input = `<img srcset="small.jpg 480w, retina.jpg 2x, plain.jpg, bad.jpg 3q">`;
    const out = sanitizeHtml(input, baseUrl);

    assert.equal(out.includes("bad.jpg 3q"), false);
    assert.equal(out.includes("https://example.com/base/small.jpg 480w"), true);
    assert.equal(out.includes("https://example.com/base/retina.jpg 2x"), true);
    assert.equal(out.includes("https://example.com/base/plain.jpg"), true);
  }

  // Duplicate base cleanup with missing head
  {
    const input = `
      <html>
        <body>
          <base href="https://evil.example/">
          <a href="child">child</a>
        </body>
      </html>
    `;
    const out = sanitizeHtml(input, baseUrl);

    assert.equal(includesOnce(out, "<base "), true);
    assert.equal(out.includes('href="https://example.com/base/page.html"'), true);
    assert.equal(out.includes('href="https://example.com/base/child"'), true);
  }

  console.log("sanitize tests passed");
}

run();
