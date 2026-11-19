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

test("Browsers, AI fetchers, bots, scrapers, paths, and query params all receive ONLY 'err occured'", async () => {
  _internal.resetState();

  const blocked = [
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131.0",
        Accept: "text/html,application/xhtml+xml",
        "Sec-Fetch-Mode": "navigate",
        "CF-Connecting-IP": "198.51.100.1",
      },
    }),
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "ChatGPT-User/1.0",
        Accept: "*/*",
        "CF-Connecting-IP": "198.51.100.2",
      },
    }),
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "python-requests/2.32.3",
        Accept: "*/*",
        "CF-Connecting-IP": "198.51.100.3",
      },
    }),
    new Request(WORKER_URL, {
      headers: {
        "User-Agent": "curl/8.7.1",
        Accept: "*/*",
        "Accept-Language": "en-US",
        "CF-Connecting-IP": "198.51.100.4",
      },
    }),
    new Request(`${WORKER_URL}cm.py`, {
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.5" },
    }),
    new Request(`${WORKER_URL}?x=1`, {
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.6" },
    }),
    new Request(WORKER_URL, {
      method: "POST",
      headers: { ...CURL_HEADERS, "CF-Connecting-IP": "198.51.100.7" },
    }),
  ];

  for (const req of blocked) {
    const res = await worker.fetch(req);
    assert.equal(res.status, 403);
    assert.equal(await res.text(), "err occured\n");
  }
});

test("Stage 1 contains zero installer/python/GitHub code; Stage 2 runs once then blocks replay & other IPs", async () => {
  _internal.resetState();

  const s1 = await worker.fetch(new Request(WORKER_URL, { headers: CURL_HEADERS }));
  assert.equal(s1.status, 200);
  const loader = await s1.text();
  execFileSync("sh", ["-n"], { input: loader });

  // Zero installer logic, zero cm.py references, zero GitHub URLs in GET /
  assert.ok(!loader.includes("githubusercontent.com"));
  assert.ok(!loader.includes("cm.py"));
  assert.ok(!loader.includes("python3"));
  assert.ok(!loader.includes("install_python3"));

  const tok = loader.match(/T='([^']+)'/)?.[1];
  const chal = loader.match(/\$T:([a-f0-9]{24})/)?.[1];
  assert.ok(tok && chal);
  const proof = await sha256Hex(`${tok}:${chal}`);

  const sampleCm = '#!/usr/bin/env python3\nprint("Console Manager OK")\n';
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(sampleCm, { status: 200 });

  try {
    // Different IP trying to redeem token -> err occured
    const stolen = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: {
          ...CURL_HEADERS,
          "CF-Connecting-IP": "192.0.2.55",
          "X-Session": tok,
          "X-Proof": proof,
        },
      }),
    );
    assert.equal(stolen.status, 403);
    assert.equal(await stolen.text(), "err occured\n");

    // Valid same-IP redemption -> returns valid POSIX sh runner
    const s2 = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: { ...CURL_HEADERS, "X-Session": tok, "X-Proof": proof },
      }),
    );
    assert.equal(s2.status, 200);
    const runner = await s2.text();
    execFileSync("sh", ["-n"], { input: runner });
    assert.ok(runner.includes("install_python3()"));
    assert.ok(runner.includes('print("Console Manager OK")'));

    // Second redemption of same token -> err occured
    const replay = await worker.fetch(
      new Request(WORKER_URL, {
        method: "POST",
        headers: { ...CURL_HEADERS, "X-Session": tok, "X-Proof": proof },
      }),
    );
    assert.equal(replay.status, 403);
    assert.equal(await replay.text(), "err occured\n");
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("Rate limiter blocks repeated requests with 'err occured'", async () => {
  _internal.resetState();
  const headers = { ...CURL_HEADERS, "CF-Connecting-IP": "203.0.113.99" };
  for (let i = 0; i < 8; i++) {
    assert.equal((await worker.fetch(new Request(WORKER_URL, { headers }))).status, 200);
  }
  const blocked = await worker.fetch(new Request(WORKER_URL, { headers }));
  assert.equal(blocked.status, 403);
  assert.equal(await blocked.text(), "err occured\n");
});

test("End-to-end `curl -fsSL <url> | sh` works seamlessly with zero keys", async () => {
  _internal.resetState();
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response('#!/usr/bin/env python3\nimport sys; print("LIVE_OK", sys.version_info[0])\n', {
      status: 200,
    });

  const server = http.createServer(async (req, res) => {
    const url = `http://127.0.0.1:${server.address().port}${req.url}`;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === "string") headers.set(k, v);
    }
    headers.set("CF-Connecting-IP", "198.51.100.200");
    const wr = await worker.fetch(new Request(url, { method: req.method, headers }), {
      ALLOW_NON_TTY: "1",
    });
    res.writeHead(wr.status, Object.fromEntries(wr.headers.entries()));
    res.end(await wr.text());
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const { stdout } = await execFileAsync("sh", ["-c", `curl -fsSL ${base} | sh`]);
    assert.equal(stdout.trim(), "LIVE_OK 3");

    const { stdout: browser } = await execFileAsync("sh", [
      "-c",
      `curl -s -A "Mozilla/5.0" -H "Accept: text/html" ${base}`,
    ]);
    assert.equal(browser, "err occured\n");
  } finally {
    server.close();
    globalThis.fetch = origFetch;
  }
});
