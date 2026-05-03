import fs from "fs/promises";
import path from "path";
import crypto from "crypto";
import { chromium } from "playwright";
import {
  checkUrlSafety,
  createSafeHostCache,
  extractUrlsFromText
} from "./security.mjs";
import { sanitizeHtml } from "./sanitize.mjs";

const RESULTS_DIR = path.resolve("results");

const MAX_URLS = parsePositiveInt(process.env.MAX_URLS, 10);
const MAX_PAGE_MS = parsePositiveInt(process.env.MAX_PAGE_MS, 45000);
const MAX_SCREENSHOT_HEIGHT = parsePositiveInt(process.env.MAX_SCREENSHOT_HEIGHT, 15000);
const MAX_SCROLL_STEPS = parsePositiveInt(process.env.MAX_SCROLL_STEPS, 10);
const MAX_SCROLL_WAIT_MS = parsePositiveInt(process.env.MAX_SCROLL_WAIT_MS, 350);
const FINAL_SETTLE_MS = parsePositiveInt(process.env.FINAL_SETTLE_MS, 700);
const FONTS_TIMEOUT_MS = parsePositiveInt(process.env.FONTS_TIMEOUT_MS, 3000);
const STABILIZE_LOOPS = parsePositiveInt(process.env.STABILIZE_LOOPS, 8);
const STABILIZE_WAIT_MS = parsePositiveInt(process.env.STABILIZE_WAIT_MS, 300);

function parsePositiveInt(value, fallback) {
  const num = Number.parseInt(String(value ?? ""), 10);
  return Number.isInteger(num) && num > 0 ? num : fallback;
}

function nowIso() {
  return new Date().toISOString();
}

function shaId(input) {
  return crypto.createHash("sha256").update(input).digest("hex").slice(0, 12);
}

async function ensureResultsDir() {
  await fs.mkdir(RESULTS_DIR, { recursive: true });
}

async function writeJson(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
}

function withTimeout(promiseFactory, ms, label = "operation") {
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`${label}-timeout-after-${ms}ms`));
    }, ms);
  });

  return Promise.race([
    Promise.resolve().then(promiseFactory),
    timeoutPromise
  ]).finally(() => clearTimeout(timer));
}

async function readUrlsFromOptionalFile(filePath) {
  if (!filePath) return [];

  const content = await fs.readFile(filePath, "utf8");
  return content
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function parseManualUrls(raw) {
  if (!raw) return [];
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function uniquePreserveOrder(items) {
  const seen = new Set();
  const out = [];

  for (const item of items) {
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }

  return out;
}

async function collectInputUrls() {
  const fromManual = parseManualUrls(process.env.MANUAL_URLS);
  const fromFile = await readUrlsFromOptionalFile(process.env.INPUT_URLS_FILE);
  const fromCommit = extractUrlsFromText(process.env.COMMIT_MESSAGE || "");

  return uniquePreserveOrder([
    ...fromManual,
    ...fromFile,
    ...fromCommit
  ]).slice(0, MAX_URLS);
}

async function waitForDocumentReady(page) {
  await page.waitForFunction(
    () => document.readyState === "interactive" || document.readyState === "complete",
    { timeout: 5000 }
  );
}

async function waitForFonts(page) {
  await page.evaluate(
    async (timeoutMs) => {
      if (!document.fonts || !document.fonts.ready) return;

      await Promise.race([
        document.fonts.ready.catch(() => {}),
        new Promise((resolve) => setTimeout(resolve, timeoutMs))
      ]);
    },
    FONTS_TIMEOUT_MS
  );
}

async function boundedAutoScroll(page) {
  for (let i = 0; i < MAX_SCROLL_STEPS; i += 1) {
    await page.evaluate(() => {
      const step = Math.max(window.innerHeight || 800, 400);
      window.scrollBy(0, step);
    });
    await page.waitForTimeout(MAX_SCROLL_WAIT_MS);
  }

  await page.evaluate(() => window.scrollTo(0, 0));
}

async function stabilizeLayout(page) {
  let previous = null;
  let stableCount = 0;

  for (let i = 0; i < STABILIZE_LOOPS; i += 1) {
    const snapshot = await page.evaluate(() => ({
      bodyScrollHeight: document.body?.scrollHeight ?? 0,
      bodyOffsetHeight: document.body?.offsetHeight ?? 0,
      docScrollHeight: document.documentElement?.scrollHeight ?? 0,
      docOffsetHeight: document.documentElement?.offsetHeight ?? 0,
      innerWidth: window.innerWidth ?? 0,
      innerHeight: window.innerHeight ?? 0
    }));

    if (
      previous &&
      previous.bodyScrollHeight === snapshot.bodyScrollHeight &&
      previous.bodyOffsetHeight === snapshot.bodyOffsetHeight &&
      previous.docScrollHeight === snapshot.docScrollHeight &&
      previous.docOffsetHeight === snapshot.docOffsetHeight &&
      previous.innerWidth === snapshot.innerWidth &&
      previous.innerHeight === snapshot.innerHeight
    ) {
      stableCount += 1;
    } else {
      stableCount = 0;
    }

    previous = snapshot;

    if (stableCount >= 2) break;
    await page.waitForTimeout(STABILIZE_WAIT_MS);
  }
}

async function detectChallenges(page, responseStatus) {
  const suspicionReasons = [];

  if (typeof responseStatus === "number" && [403, 429, 503].includes(responseStatus)) {
    suspicionReasons.push(`status:${responseStatus}`);
  }

  const bodyText = await page.evaluate(() => {
    const text = document.body?.innerText || "";
    return text.slice(0, 5000);
  });

  const lowerText = bodyText.toLowerCase();
  const phrases = [
    "verify you are human",
    "enable javascript",
    "attention required",
    "checking your browser",
    "temporarily blocked",
    "access denied",
    "captcha"
  ];

  for (const phrase of phrases) {
    if (lowerText.includes(phrase)) {
      suspicionReasons.push(`text:${phrase}`);
    }
  }

  const selectorChecks = [
    '[id*="captcha" i]',
    '[class*="captcha" i]',
    'iframe[title*="challenge" i]',
    'form[action*="captcha" i]',
    '[data-sitekey]'
  ];

  for (const selector of selectorChecks) {
    const found = await page.locator(selector).count().catch(() => 0);
    if (found > 0) {
      suspicionReasons.push(`selector:${selector}`);
    }
  }

  return {
    suspicious: suspicionReasons.length > 0,
    suspicionReasons: [...new Set(suspicionReasons)]
  };
}

function getStructuredBlockedReason(safetyResult) {
  return {
    category: safetyResult.category || "policy",
    reason: safetyResult.reason || "blocked"
  };
}

async function getScreenshotClip(page) {
  const metrics = await page.evaluate((maxHeight) => {
    const doc = document.documentElement;
    const body = document.body;

    const widthCandidates = [
      doc?.clientWidth ?? 0,
      doc?.scrollWidth ?? 0,
      doc?.offsetWidth ?? 0,
      body?.clientWidth ?? 0,
      body?.scrollWidth ?? 0,
      body?.offsetWidth ?? 0,
      window.innerWidth ?? 0
    ].filter((n) => Number.isFinite(n) && n > 0);

    const heightCandidates = [
      doc?.clientHeight ?? 0,
      doc?.scrollHeight ?? 0,
      doc?.offsetHeight ?? 0,
      body?.clientHeight ?? 0,
      body?.scrollHeight ?? 0,
      body?.offsetHeight ?? 0,
      window.innerHeight ?? 0
    ].filter((n) => Number.isFinite(n) && n > 0);

    const width = Math.max(...widthCandidates, 1280);
    const fullHeight = Math.max(...heightCandidates, 720);
    const clippedHeight = Math.min(fullHeight, maxHeight);

    return {
      width,
      fullHeight,
      clippedHeight
    };
  }, MAX_SCREENSHOT_HEIGHT);

  const width = Math.max(1, Math.floor(metrics.width));
  const height = Math.max(1, Math.floor(metrics.clippedHeight));
  const fullHeight = Math.max(1, Math.floor(metrics.fullHeight));

  return {
    clip: { x: 0, y: 0, width, height },
    width,
    height,
    fullHeight,
    wasClipped: fullHeight > height
  };
}

async function processUrl(browser, url, safeHostCache) {
  const pageId = shaId(url);
  const startedAt = Date.now();

  const pageManifest = {
    id: pageId,
    originalUrl: url,
    finalUrl: null,
    title: null,
    status: null,
    htmlFilename: null,
    screenshotFilename: null,
    perPageManifestFilename: `${pageId}.json`,
    blockedRequestsSample: [],
    blockedRequestsCount: 0,
    suspicious: false,
    suspicionReasons: [],
    screenshot: null,
    timing: {
      startedAt: new Date(startedAt).toISOString(),
      finishedAt: null,
      durationMs: null
    },
    error: null
  };

  const initialSafety = await checkUrlSafety(url, safeHostCache);
  if (!initialSafety.ok) {
    pageManifest.error = {
      phase: "preflight",
      category: initialSafety.category,
      reason: initialSafety.reason,
      message: "initial URL blocked by safety policy"
    };

    pageManifest.timing.finishedAt = nowIso();
    pageManifest.timing.durationMs = Date.now() - startedAt;
    return pageManifest;
  }

  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 900 }
  });

  const page = await context.newPage();

  try {
    await page.route("**/*", async (route) => {
      const request = route.request();
      const requestUrl = request.url();
      const resourceType = request.resourceType();

      const blockedByPolicyType = new Set([
        "media",
        "websocket"
      ]);

      if (blockedByPolicyType.has(resourceType)) {
        pageManifest.blockedRequestsCount += 1;
        if (pageManifest.blockedRequestsSample.length < 25) {
          pageManifest.blockedRequestsSample.push({
            url: requestUrl,
            resourceType,
            category: "policy",
            reason: `resource-type-blocked:${resourceType}`
          });
        }
        await route.abort();
        return;
      }

      const safety = await checkUrlSafety(requestUrl, safeHostCache);
      if (!safety.ok) {
        pageManifest.blockedRequestsCount += 1;
        if (pageManifest.blockedRequestsSample.length < 25) {
          const structured = getStructuredBlockedReason(safety);
          pageManifest.blockedRequestsSample.push({
            url: requestUrl,
            resourceType,
            category: structured.category,
            reason: structured.reason
          });
        }
        await route.abort();
        return;
      }

      await route.continue();
    });

    const response = await withTimeout(
      () => page.goto(url, { waitUntil: "domcontentloaded", timeout: MAX_PAGE_MS }),
      MAX_PAGE_MS + 1000,
      "goto"
    );

    pageManifest.status = response?.status() ?? null;
    pageManifest.finalUrl = page.url();

    // Validate final URL after redirects too.
    const finalSafety = await checkUrlSafety(pageManifest.finalUrl, safeHostCache);
    if (!finalSafety.ok) {
      throw new Error(`redirect-blocked:${finalSafety.category}:${finalSafety.reason}`);
    }

    await withTimeout(() => waitForDocumentReady(page), 6000, "document-ready");
    await withTimeout(() => boundedAutoScroll(page), Math.max(5000, MAX_SCROLL_STEPS * MAX_SCROLL_WAIT_MS + 1000), "auto-scroll");
    await withTimeout(() => waitForFonts(page), FONTS_TIMEOUT_MS + 1500, "fonts-ready");
    await withTimeout(() => stabilizeLayout(page), STABILIZE_LOOPS * STABILIZE_WAIT_MS + 1500, "stabilize-layout");
    await page.waitForTimeout(FINAL_SETTLE_MS);

    pageManifest.title = await page.title().catch(() => null);

    const challenge = await withTimeout(
      () => detectChallenges(page, pageManifest.status),
      4000,
      "challenge-detection"
    );
    pageManifest.suspicious = challenge.suspicious;
    pageManifest.suspicionReasons = challenge.suspicionReasons;

    const rawHtml = await withTimeout(() => page.content(), 5000, "page-content");
    const sanitizedHtml = sanitizeHtml(rawHtml, page.url());

    const htmlFilename = `${pageId}.html`;
    const screenshotFilename = `${pageId}.png`;
    const htmlPath = path.join(RESULTS_DIR, htmlFilename);
    const screenshotPath = path.join(RESULTS_DIR, screenshotFilename);

    await fs.writeFile(htmlPath, sanitizedHtml, "utf8");

    const screenshotInfo = await withTimeout(() => getScreenshotClip(page), 4000, "screenshot-metrics");

    await withTimeout(
      () =>
        page.screenshot({
          path: screenshotPath,
          type: "png",
          clip: screenshotInfo.clip
        }),
      10000,
      "screenshot"
    );

    pageManifest.htmlFilename = htmlFilename;
    pageManifest.screenshotFilename = screenshotFilename;
    pageManifest.screenshot = {
      width: screenshotInfo.width,
      height: screenshotInfo.height,
      fullHeight: screenshotInfo.fullHeight,
      wasClipped: screenshotInfo.wasClipped
    };
  } catch (error) {
    pageManifest.error = {
      phase: "processing",
      category: "runtime",
      reason: "page-processing-failed",
      message: error?.message || String(error)
    };
  } finally {
    await page.close().catch(() => {});
    await context.close().catch(() => {});
    pageManifest.timing.finishedAt = nowIso();
    pageManifest.timing.durationMs = Date.now() - startedAt;
  }

  return pageManifest;
}

async function main() {
  await ensureResultsDir();

  const runManifest = {
    startedAt: nowIso(),
    finishedAt: null,
    config: {
      maxUrls: MAX_URLS,
      maxPageMs: MAX_PAGE_MS,
      maxScreenshotHeight: MAX_SCREENSHOT_HEIGHT
    },
    input: {
      hasCommitMessage: Boolean(process.env.COMMIT_MESSAGE),
      manualUrlsProvided: Boolean(process.env.MANUAL_URLS),
      inputUrlsFile: process.env.INPUT_URLS_FILE || null
    },
    pages: [],
    summary: {
      requestedCount: 0,
      processedCount: 0,
      successCount: 0,
      failureCount: 0,
      suspiciousCount: 0
    },
    fatalError: null
  };

  let browser = null;

  try {
    const urls = await collectInputUrls();
    runManifest.summary.requestedCount = urls.length;

    const safeHostCache = createSafeHostCache(500);

    browser = await chromium.launch({
      headless: true
    });

    for (const url of urls) {
      const pageManifest = await withTimeout(
        () => processUrl(browser, url, safeHostCache),
        MAX_PAGE_MS + 15000,
        "per-page"
      );

      runManifest.pages.push(pageManifest);

      await writeJson(
        path.join(RESULTS_DIR, pageManifest.perPageManifestFilename),
        pageManifest
      );
    }
  } catch (error) {
    runManifest.fatalError = {
      category: "runtime",
      reason: "run-failed",
      message: error?.message || String(error)
    };
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }

    runManifest.summary.processedCount = runManifest.pages.length;
    runManifest.summary.successCount = runManifest.pages.filter((p) => !p.error).length;
    runManifest.summary.failureCount = runManifest.pages.filter((p) => Boolean(p.error)).length;
    runManifest.summary.suspiciousCount = runManifest.pages.filter((p) => p.suspicious).length;
    runManifest.finishedAt = nowIso();

    await writeJson(path.join(RESULTS_DIR, "run-manifest.json"), runManifest);
  }
}

await main();
