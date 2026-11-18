import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import worker from "../src/index.js";

const WORKER_URL = "https://executeee.nishkarshrana10.workers.dev";
const CM_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

test("GET / always returns plain shell script (curl AND browsers — no HTML)", async () => {
  for (const headers of [
    { "User-Agent": "curl/8.7.1" },
    { "User-Agent": "Mozilla/5.0", Accept: "text/html,application/xhtml+xml" },
  ]) {
    const res = await worker.fetch(new Request(`${WORKER_URL}/`, { headers }));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("Content-Type"), "text/plain; charset=utf-8");
    assert.equal(res.headers.get("X-Content-Type-Options"), "nosniff");
    assert.equal(res.headers.get("X-Frame-Options"), "DENY");
    assert.match(res.headers.get("Strict-Transport-Security") || "", /max-age=31536000/);

    const body = await res.text();
    assert.match(body, /^#!\/bin\/sh\n/);
    assert.ok(!body.includes("<!doctype html>"));
    assert.ok(body.includes("install_python3()"));
    assert.ok(body.includes("pkg install -y python"));
    assert.ok(body.includes("apt-get install -y python3 ca-certificates"));
    assert.ok(body.includes(CM_URL));
    assert.ok(body.includes("ssl.create_default_context()"));
    assert.ok(body.includes("mkdtemp"));

    // Validate POSIX sh syntax
    execFileSync("sh", ["-n"], { input: body });

    // Validate embedded Python syntax
    const match = body.match(/<<'__CM_PY_EOF__'\n([\s\S]*?)\n__CM_PY_EOF__/);
    assert.ok(match);
    execFileSync("python3", ["-c", "import ast,sys; ast.parse(sys.stdin.read())"], {
      input: match[1],
    });
  }
});

test("HTTP redirects permanently to HTTPS", async () => {
  const res = await worker.fetch(new Request("http://executeee.nishkarshrana10.workers.dev/"));
  assert.equal(res.status, 308);
  assert.equal(res.headers.get("Location"), "https://executeee.nishkarshrana10.workers.dev/");
});

test("Non-GET/HEAD methods are rejected with 405 and unknown paths return 404", async () => {
  const post = await worker.fetch(new Request(`${WORKER_URL}/`, { method: "POST" }));
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("Allow"), "GET, HEAD");

  const notFound = await worker.fetch(new Request(`${WORKER_URL}/random`));
  assert.equal(notFound.status, 404);
});

test("Optional AUTH_TOKEN protects /", async () => {
  const env = { AUTH_TOKEN: "secret-123" };

  assert.equal((await worker.fetch(new Request(`${WORKER_URL}/`), env)).status, 401);
  assert.equal(
    (
      await worker.fetch(
        new Request(`${WORKER_URL}/`, { headers: { Authorization: "Bearer wrong" } }),
        env,
      )
    ).status,
    401,
  );
  assert.equal(
    (
      await worker.fetch(
        new Request(`${WORKER_URL}/`, { headers: { Authorization: "Bearer secret-123" } }),
        env,
      )
    ).status,
    200,
  );
});

test("Optional CM_SHA256 embeds valid SHA-256 verification in Python", async () => {
  const hash = "a".repeat(64);
  const res = await worker.fetch(new Request(`${WORKER_URL}/`), { CM_SHA256: hash });
  const body = await res.text();
  assert.ok(body.includes(hash));

  const match = body.match(/<<'__CM_PY_EOF__'\n([\s\S]*?)\n__CM_PY_EOF__/);
  assert.ok(match);
  execFileSync("python3", ["-c", "import ast,sys; ast.parse(sys.stdin.read())"], {
    input: match[1],
  });
});
