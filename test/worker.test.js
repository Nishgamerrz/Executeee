import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import worker from "../src/index.js";

const WORKER_URL = "https://executeee.example.workers.dev";
const CM_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

test("GET / with curl returns valid POSIX shell script with security headers", async () => {
  const res = await worker.fetch(
    new Request(`${WORKER_URL}/`, { headers: { "User-Agent": "curl/8.7.1" } }),
  );
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(res.headers.get("X-Frame-Options"), "DENY");
  assert.match(res.headers.get("Strict-Transport-Security") || "", /max-age=31536000/);

  const body = await res.text();
  assert.match(body, /^#!\/bin\/sh\n/);
  assert.ok(body.includes(CM_URL));
  assert.ok(body.includes("ssl.create_default_context()"));
  assert.ok(body.includes("mkdtemp"));

  // Validate POSIX shell syntax
  execFileSync("sh", ["-n"], { input: body });

  // Validate embedded Python syntax
  const match = body.match(/<<'__CM_PY_EOF__'\n([\s\S]*?)\n__CM_PY_EOF__/);
  assert.ok(match, "embedded Python snippet found");
  execFileSync("python3", ["-c", "import ast,sys; ast.parse(sys.stdin.read())"], {
    input: match[1],
  });
});

test("GET / with PowerShell User-Agent returns PowerShell launcher", async () => {
  const res = await worker.fetch(
    new Request(`${WORKER_URL}/`, {
      headers: { "User-Agent": "Mozilla/5.0 WindowsPowerShell/5.1.22621" },
    }),
  );
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes("$ErrorActionPreference = 'Stop'"));
  assert.ok(body.includes(CM_URL));
});

test("GET / in a browser returns copy-paste HTML landing page", async () => {
  const res = await worker.fetch(
    new Request(`${WORKER_URL}/`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        Accept: "text/html,application/xhtml+xml",
      },
    }),
  );
  assert.equal(res.status, 200);
  assert.match(res.headers.get("Content-Type") || "", /^text\/html/);
  const html = await res.text();
  assert.ok(html.includes(`curl -fsSL ${WORKER_URL} | sh`));
  assert.ok(html.includes(`irm ${WORKER_URL} | iex`));
});

test("GET /cmd generates valid single-line Python for Windows CMD", async () => {
  const res = await worker.fetch(new Request(`${WORKER_URL}/cmd`));
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.startsWith("@echo off\r\n"));
  const pyMatch = body.match(/python3 -c "([^"]+)"/);
  assert.ok(pyMatch);
  execFileSync("python3", ["-c", "import ast,sys; ast.parse(sys.stdin.read())"], {
    input: pyMatch[1],
  });
});

test("GET /raw returns the exact python3 -c one-liner", async () => {
  const res = await worker.fetch(new Request(`${WORKER_URL}/raw`));
  assert.equal(res.status, 200);
  const body = (await res.text()).trim();
  assert.equal(
    body,
    `python3 -c "import sys,os,tempfile as t,urllib.request as u,subprocess as s;p=os.path.join(t.gettempdir(),'cm.py');u.urlretrieve('${CM_URL}',p);s.run([sys.executable,p],check=True)"`,
  );
});

test("HTTP requests redirect permanently to HTTPS", async () => {
  const res = await worker.fetch(new Request("http://executeee.example.workers.dev/sh"));
  assert.equal(res.status, 308);
  assert.equal(res.headers.get("Location"), "https://executeee.example.workers.dev/sh");
});

test("Non-GET/HEAD methods are rejected with 405", async () => {
  const res = await worker.fetch(new Request(`${WORKER_URL}/`, { method: "POST" }));
  assert.equal(res.status, 405);
  assert.equal(res.headers.get("Allow"), "GET, HEAD");
});

test("Optional AUTH_TOKEN locks down execution endpoints", async () => {
  const env = { AUTH_TOKEN: "super-secret-token" };

  const unauth = await worker.fetch(new Request(`${WORKER_URL}/sh`), env);
  assert.equal(unauth.status, 401);

  const wrong = await worker.fetch(
    new Request(`${WORKER_URL}/sh`, { headers: { Authorization: "Bearer wrong" } }),
    env,
  );
  assert.equal(wrong.status, 401);

  const ok = await worker.fetch(
    new Request(`${WORKER_URL}/sh`, {
      headers: { Authorization: "Bearer super-secret-token" },
    }),
    env,
  );
  assert.equal(ok.status, 200);

  // Health stays public for uptime probes
  const health = await worker.fetch(new Request(`${WORKER_URL}/health`), env);
  assert.equal(health.status, 200);
});

test("Optional CM_SHA256 embeds strict hash check into shell & /py proxy", async () => {
  const sampleScript = '#!/usr/bin/env python3\n"""Console Manager test"""\nprint("ok")\n';
  const digestBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sampleScript));
  const goodHash = Array.from(new Uint8Array(digestBuf), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
  const badHash = "0".repeat(64);

  const shRes = await worker.fetch(new Request(`${WORKER_URL}/sh`), { CM_SHA256: goodHash });
  const shBody = await shRes.text();
  assert.ok(shBody.includes(goodHash));
  const shPy = shBody.match(/<<'__CM_PY_EOF__'\n([\s\S]*?)\n__CM_PY_EOF__/);
  assert.ok(shPy);
  execFileSync("python3", ["-c", "import ast,sys; ast.parse(sys.stdin.read())"], {
    input: shPy[1],
  });

  const cmdRes = await worker.fetch(new Request(`${WORKER_URL}/cmd`), { CM_SHA256: goodHash });
  const cmdBody = await cmdRes.text();
  const cmdPy = cmdBody.match(/python3 -c "([^"]+)"/);
  assert.ok(cmdPy);
  execFileSync("python3", ["-c", "import ast,sys; ast.parse(sys.stdin.read())"], {
    input: cmdPy[1],
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(sampleScript, { status: 200 });
  try {
    const pyOk = await worker.fetch(new Request(`${WORKER_URL}/py`), { CM_SHA256: goodHash });
    assert.equal(pyOk.status, 200);
    assert.equal(pyOk.headers.get("X-Content-SHA256"), goodHash);

    const pyBad = await worker.fetch(new Request(`${WORKER_URL}/py`), { CM_SHA256: badHash });
    assert.equal(pyBad.status, 502);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
