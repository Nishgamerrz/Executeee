import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import http from "node:http";
import test from "node:test";
import { promisify } from "node:util";
import worker, { _internal } from "../src/index.js";

const execFileAsync = promisify(execFile);

const WORKER_URL = "https://executeee.nishkarshrana10.workers.dev/";
const CURL_HEADERS = {
  "User-Agent": "curl/8.7.1",
  Accept: "*/*",
  "CF-Connecting-IP": "203.0.113.10",
};

async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

test("Browsers, bots, scrapers, extra paths, and query params all get ONLY 'err occured'", async () => {
  _internal.resetState();

  const blockedRequests = [
    // Chrome / Safari / Firefox browser visit
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Sec-Fetch-Mode": "navigate",
        "Accept-Language": "en-US,en;q=0.9",
        "CF-Connecting-IP": "198.51.100.1",
      },
    }),
    // Browser spoofing curl User-Agent (still sends Sec-Fetch / Accept-Language)
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "curl/8.7.1",
        Accept: "*/*",
        "Sec-Fetch-Mode": "cors",
        "CF-Connecting-IP": "198.51.100.2",
      },
    }),
    // Python requests scraper
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "python-requests/2.32.3",
        Accept: "*/*",
        "CF-Connecting-IP": "198.51.100.3",
      },
    }),
    // Node fetch / undici scraper
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "node",
        Accept: "*/*",
        "CF-Connecting-IP": "198.51.100.4",
      },
    }),
    // Go scraper
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "Go-http-client/2.0",
        Accept: "*/*",
        "CF-Connecting-IP": "198.51.100.5",
      },
    }),
    // wget
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "Wget/1.24.5",
        Accept: "*/*",
        "CF-Connecting-IP": "198.51.100.6",
      },
    }),
    // curl with query parameter probing
    new Request(`${WORKER_URL}?raw=1`, {
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.7" },
    }),
    // curl on random path
    new Request(`${WORKER_URL}cm.py`, {
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.8" },
    }),
    // Plain HTTP request
    new Request("http://executeee.nishkarshrana10.workers.dev/", {
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.9" },
    }),
    // Direct POST with no signed handshake token
    new Request(WORKER_URL, {
      method: "POST",
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.10" },
    }),
  ];

  for (const req of blockedRequests) {
    const res = await worker.fetch(req);
    assert.equal(res.status, 403);
    assert.equal(await res.text(), "err occured\n");
    assert.equal(res.headers.get("X-Robots-Tag"), "noindex, nofollow, noarchive, nosnippet");
  }
});

test("Full terminal handshake works, hides upstream URL, and blocks token replay & IP spoofing", async () => {
  _internal.resetState();

  // Stage 1: GET / as genuine curl
  const stage1 = await worker.fetch(new Request(WORKER_URL, { headers: CURL_HEADERS }));
  assert.equal(stage1.status, 200);
  const sh = await stage1.text();

  // Valid POSIX sh syntax
  execFileSync("sh", ["-n"], { input: sh });

  // Upstream GitHub URL and cm.py source are NEVER exposed in Stage 1
  assert.ok(!sh.includes("githubusercontent.com"));
  assert.ok(!sh.includes("Nish12345678910111"));

  // Extract handshake token and challenge
  const tokMatch = sh.match(/TOK='([^']+)'/);
  const chalMatch = sh.match(/\$TOK:([a-f0-9]{24})/);
  assert.ok(tokMatch && chalMatch);
  const token = tokMatch[1];
  const challenge = chalMatch[1];
  const proof = await sha256Hex(`${token}:${challenge}`);

  const sampleCmPy = '#!/usr/bin/env python3\nprint("Console Manager running")\n';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(sampleCmPy, { status: 200 });

  try {
    // Attempt from a different IP with stolen token -> blocked ('err occured')
    const wrongIp = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: {
          ...CURL_HEADERS,
          "CF-Connecting-IP": "192.0.2.99",
          "X-Session": token,
          "X-Proof": proof,
        },
      }),
    );
    assert.equal(wrongIp.status, 403);
    assert.equal(await wrongIp.text(), "err occured\n");

    // Attempt with wrong proof -> blocked ('err occured')
    const badProof = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: {
          ...CURL_HEADERS,
          "X-Session": token,
          "X-Proof": "0".repeat(64),
        },
      }),
    );
    assert.equal(badProof.status, 403);
    assert.equal(await badProof.text(), "err occured\n");

    // Legitimate Stage 2 POST from same IP/UA -> returns cm.py
    const stage2 = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: {
          ...CURL_HEADERS,
          "X-Session": token,
          "X-Proof": proof,
        },
      }),
    );
    assert.equal(stage2.status, 200);
    assert.equal(await stage2.text(), sampleCmPy);

    // Replay exact same token a second time -> blocked ('err occured')
    const replay = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: {
          ...CURL_HEADERS,
          "X-Session": token,
          "X-Proof": proof,
        },
      }),
    );
    assert.equal(replay.status, 403);
    assert.equal(await replay.text(), "err occured\n");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Rate limiter returns 'err occured' when an IP spams requests", async () => {
  _internal.resetState();
  const headers = { ...CURL_HEADERS, "CF-Connecting-IP": "203.0.113.77" };

  for (let i = 0; i < 10; i++) {
    const ok = await worker.fetch(new Request(WORKER_URL, { headers }));
    assert.equal(ok.status, 200);
  }
  const limited = await worker.fetch(new Request(WORKER_URL, { headers }));
  assert.equal(limited.status, 403);
  assert.equal(await limited.text(), "err occured\n");
});

test("Optional AUTH_TOKEN blocks even genuine curl without key and returns 'err occured'", async () => {
  _internal.resetState();
  const env = { AUTH_TOKEN: "my-private-key-99", SIGNING_SECRET: "super-random-secret" };

  const denied = await worker.fetch(new Request(WORKER_URL, { headers: CURL_HEADERS }), env);
  assert.equal(denied.status, 403);
  assert.equal(await denied.text(), "err occured\n");

  const allowed = await worker.fetch(
    new Request(WORKER_URL, {
      headers: { ...CURL_HEADERS, "X-Key": "my-private-key-99" },
    }),
    env,
  );
  assert.equal(allowed.status, 200);
  const sh = await allowed.text();
  execFileSync("sh", ["-n"], { input: sh });
  assert.ok(sh.includes("-H 'X-Key: my-private-key-99'"));
});

test("End-to-end real `curl -fsSL <url> | sh` executes cm.py while browser/scraper gets 'err occured'", async () => {
  _internal.resetState();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response('#!/usr/bin/env python3\nprint("CM_EXECUTED_OK")\n', { status: 200 });

  const server = http.createServer(async (req, res) => {
    const url = `http://127.0.0.1:${server.address().port}${req.url}`;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === "string") headers.set(k, v);
    }
    headers.set("CF-Connecting-IP", "198.51.100.88");
    const wr = await worker.fetch(new Request(url, { method: req.method, headers }), {
      ALLOW_NON_TTY: "1",
    });
    res.writeHead(wr.status, Object.fromEntries(wr.headers.entries()));
    res.end(await wr.text());
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const { stdout: termOut } = await execFileAsync("sh", ["-c", `curl -fsSL ${base} | sh`]);
    assert.equal(termOut.trim(), "CM_EXECUTED_OK");

    const { stdout: browserOut } = await execFileAsync("sh", [
      "-c",
      `curl -s -A "Mozilla/5.0 Chrome/131" -H "Accept: text/html" ${base}`,
    ]);
    assert.equal(browserOut, "err occured\n");
  } finally {
    server.close();
    globalThis.fetch = originalFetch;
  }
});
