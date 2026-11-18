/**
 * Cloudflare Worker — fast, hardened launcher for Console Manager (cm.py).
 *
 * Usage:
 *   Linux / macOS / Termux:  curl -fsSL https://<worker>.workers.dev | sh
 *   Windows PowerShell:      irm https://<worker>.workers.dev | iex
 *   Windows CMD:             curl -fsSL https://<worker>.workers.dev/cmd -o "%TEMP%\cm.cmd" && "%TEMP%\cm.cmd"
 *   Direct Python:           curl -fsSL https://<worker>.workers.dev/py | python3
 *
 * Optional secret (Cloudflare Worker Settings -> Variables and Secrets):
 *   AUTH_TOKEN  — if set, requests must send `Authorization: Bearer <AUTH_TOKEN>`
 *                 or `X-Auth-Token: <AUTH_TOKEN>`.
 *   CM_SHA256   — if set, verifies the exact SHA-256 hash of cm.py before running.
 */

const SOURCE_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

const MAX_SCRIPT_BYTES = 1024 * 1024; // 1 MiB safety cap

const BASE_SECURITY_HEADERS = Object.freeze({
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Cache-Control": "no-store, max-age=0",
});

/**
 * Builds the Python one-liner code executed on the client:
 * - Enforces verified HTTPS (ssl.create_default_context) + 60s timeout
 * - Enforces a 1 MiB download limit and optional SHA-256 pin
 * - Writes to a private 0700 temp directory (prevents /tmp symlink attacks)
 * - Runs `[sys.executable, p]` with `check=True` and cleans up afterwards
 */
function buildPythonCode(expectedSha256 = "") {
  const cleanHash = /^[a-fA-F0-9]{64}$/.test(expectedSha256)
    ? expectedSha256.toLowerCase()
    : "";

  const hashLine = cleanHash
    ? [
        "    import hashlib as h",
        "    digest = h.sha256(b).hexdigest()",
        `    if digest != '${cleanHash}':`,
        "        raise RuntimeError(f'SHA-256 mismatch: {digest}')",
      ]
    : [];

  return [
    "import os, shutil, ssl, subprocess as s, sys, tempfile as t, urllib.request as u",
    "d = t.mkdtemp(prefix='cm-')",
    "try:",
    "    p = os.path.join(d, 'cm.py')",
    `    req = u.Request('${SOURCE_URL}', headers={'User-Agent': 'ConsoleManager-Worker/1.0'})`,
    "    with u.urlopen(req, timeout=60, context=ssl.create_default_context()) as r:",
    `        b = r.read(${MAX_SCRIPT_BYTES + 1})`,
    `    if not (0 < len(b) <= ${MAX_SCRIPT_BYTES}):`,
    "        raise RuntimeError('invalid payload size')",
    ...hashLine,
    "    with open(p, 'wb') as f:",
    "        f.write(b)",
    "    s.run([sys.executable, p], check=True)",
    "finally:",
    "    shutil.rmtree(d, ignore_errors=True)",
  ].join("\n");
}

/** Exact single-line command requested, preserved for `/raw` or simple copy-paste. */
const EXACT_ONELINER =
  `python3 -c "import sys,os,tempfile as t,urllib.request as u,subprocess as s;` +
  `p=os.path.join(t.gettempdir(),'cm.py');` +
  `u.urlretrieve('${SOURCE_URL}',p);` +
  `s.run([sys.executable,p],check=True)"`;

/** POSIX `sh` script served for `curl -fsSL https://<worker> | sh`. */
function buildShellScript(expectedSha256 = "") {
  const pyCode = buildPythonCode(expectedSha256);
  return `#!/bin/sh
set -eu

if command -v python3 >/dev/null 2>&1; then
  PY="python3"
elif command -v python >/dev/null 2>&1 && python -c "import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
  PY="python"
else
  echo "Error: Python 3 is required. Install python3 and try again." >&2
  exit 1
fi

CODE=$(cat <<'__CM_PY_EOF__'
${pyCode}
__CM_PY_EOF__
)

if ( : </dev/tty ) 2>/dev/null; then
  exec "$PY" -c "$CODE" </dev/tty
else
  exec "$PY" -c "$CODE"
fi
`;
}

/** PowerShell script served for `irm https://<worker> | iex` or `/ps1`. */
function buildPowerShellScript(expectedSha256 = "") {
  const pyCode = buildPythonCode(expectedSha256);
  return `$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Find-Python3 {
  foreach ($candidate in @('python3', 'py', 'python')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    try {
      if ($candidate -eq 'py') {
        $ver = & py -3 --version 2>&1
        if ("$ver" -match '^Python 3\\.') { return @('py', '-3') }
      } else {
        $ver = & $candidate --version 2>&1
        if ("$ver" -match '^Python 3\\.') { return @($candidate) }
      }
    } catch {}
  }
  return $null
}

$py = Find-Python3
if (-not $py) {
  throw 'Python 3 is required. Install Python 3 (check "Add python.exe to PATH") and re-run.'
}

$code = @'
${pyCode}
'@

if ($py.Length -gt 1) {
  & $py[0] $py[1] -c $code
} else {
  & $py[0] -c $code
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
`;
}

/** Windows CMD batch script served at `/cmd`. */
function buildCmdScript(expectedSha256 = "") {
  const cleanHash = /^[a-fA-F0-9]{64}$/.test(expectedSha256)
    ? expectedSha256.toLowerCase()
    : "";
  const hashPart = cleanHash
    ? `import hashlib as h;h.sha256(b).hexdigest()=='${cleanHash}' or sys.exit('SHA-256 mismatch');`
    : "";
  const oneLine =
    "import sys,os,ssl,shutil,tempfile as t,urllib.request as u,subprocess as s;" +
    "d=t.mkdtemp(prefix='cm-');p=os.path.join(d,'cm.py');" +
    `r=u.urlopen(u.Request('${SOURCE_URL}',headers={'User-Agent':'ConsoleManager-Worker/1.0'}),timeout=60,context=ssl.create_default_context());` +
    `b=r.read(${MAX_SCRIPT_BYTES + 1});r.close();` +
    `(0<len(b)<=${MAX_SCRIPT_BYTES}) or (shutil.rmtree(d,True),sys.exit('invalid payload size'));` +
    hashPart +
    "f=open(p,'wb');f.write(b);f.close();" +
    "rc=s.run([sys.executable,p]).returncode;shutil.rmtree(d,ignore_errors=True);sys.exit(rc)";

  return (
    "@echo off\r\n" +
    "setlocal\r\n" +
    "where python3 >nul 2>nul && (python3 --version 2>nul | findstr /B \"Python 3.\" >nul) && (\r\n" +
    `  python3 -c "${oneLine}"\r\n` +
    "  exit /b %ERRORLEVEL%\r\n" +
    ")\r\n" +
    "where py >nul 2>nul && (py -3 --version 2>nul | findstr /B \"Python 3.\" >nul) && (\r\n" +
    `  py -3 -c "${oneLine}"\r\n` +
    "  exit /b %ERRORLEVEL%\r\n" +
    ")\r\n" +
    "where python >nul 2>nul && (python --version 2>nul | findstr /B \"Python 3.\" >nul) && (\r\n" +
    `  python -c "${oneLine}"\r\n` +
    "  exit /b %ERRORLEVEL%\r\n" +
    ")\r\n" +
    "echo Error: Python 3 is required. Install Python 3 and try again. 1>&2\r\n" +
    "exit /b 1\r\n"
  );
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Minimal HTML page when visited directly in a browser. */
function buildHtmlPage(origin) {
  const safeOrigin = escapeHtml(origin);
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Console Manager — Quick Run</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: #0b0914;
      color: #f3f0ff;
      display: grid;
      place-items: center;
      padding: 24px;
    }
    main {
      width: 100%;
      max-width: 720px;
      background: #141024;
      border: 1px solid #2c224d;
      border-radius: 16px;
      padding: 28px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
    }
    h1 { margin: 0 0 6px; font-size: 1.4rem; }
    p { margin: 0 0 20px; color: #b5abd6; font-size: 0.95rem; }
    .item { margin-bottom: 16px; }
    .label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #a78bfa;
      margin-bottom: 6px;
    }
    .cmd {
      display: flex;
      gap: 10px;
      align-items: center;
      background: #090712;
      border: 1px solid #261d42;
      border-radius: 10px;
      padding: 10px 12px;
    }
    code {
      flex: 1;
      overflow-x: auto;
      white-space: nowrap;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.88rem;
      color: #ede9fe;
    }
    button {
      background: #7c3aed;
      color: #fff;
      border: 0;
      border-radius: 8px;
      padding: 7px 12px;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { background: #6d28d9; }
    footer {
      margin-top: 20px;
      padding-top: 14px;
      border-top: 1px solid #241c3d;
      font-size: 0.8rem;
      color: #8f84b3;
    }
    a { color: #c4b5fd; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <main>
    <h1>Console Manager Launcher</h1>
    <p>Paste the command for your terminal to download and run <code>cm.py</code> over verified HTTPS.</p>

    <div class="item">
      <span class="label">Linux / Ubuntu / Termux / macOS</span>
      <div class="cmd">
        <code id="c-sh">curl -fsSL ${safeOrigin} | sh</code>
        <button type="button" data-copy="c-sh">Copy</button>
      </div>
    </div>

    <div class="item">
      <span class="label">Windows PowerShell</span>
      <div class="cmd">
        <code id="c-ps1">irm ${safeOrigin} | iex</code>
        <button type="button" data-copy="c-ps1">Copy</button>
      </div>
    </div>

    <div class="item">
      <span class="label">Windows CMD</span>
      <div class="cmd">
        <code id="c-cmd">curl -fsSL ${safeOrigin}/cmd -o "%TEMP%\\cm.cmd" &amp;&amp; "%TEMP%\\cm.cmd"</code>
        <button type="button" data-copy="c-cmd">Copy</button>
      </div>
    </div>

    <div class="item">
      <span class="label">Direct Python 3 (Single Hop)</span>
      <div class="cmd">
        <code id="c-py">curl -fsSL ${safeOrigin}/py | python3</code>
        <button type="button" data-copy="c-py">Copy</button>
      </div>
    </div>

    <footer>
      Endpoints:
      <a href="/sh">/sh</a> &middot;
      <a href="/ps1">/ps1</a> &middot;
      <a href="/cmd">/cmd</a> &middot;
      <a href="/py">/py</a> &middot;
      <a href="/raw">/raw</a> &middot;
      <a href="${SOURCE_URL}" rel="noopener noreferrer">Source (cm.py)</a>
    </footer>
  </main>
  <script>
    document.querySelectorAll("button[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const el = document.getElementById(btn.dataset.copy);
        if (!el) return;
        await navigator.clipboard.writeText(el.textContent);
        const prev = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = prev; }, 1400);
      });
    });
  </script>
</body>
</html>
`;
}

/** Constant-time string comparison using SHA-256 digests (avoids timing leaks). */
async function timingSafeEqualStr(a, b) {
  const enc = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const viewA = new Uint8Array(hashA);
  const viewB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i];
  }
  return diff === 0;
}

async function isAuthorized(request, env) {
  const requiredToken = typeof env?.AUTH_TOKEN === "string" ? env.AUTH_TOKEN.trim() : "";
  if (!requiredToken) return true;

  const authHeader = request.headers.get("Authorization") || "";
  const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const headerToken = (request.headers.get("X-Auth-Token") || "").trim();
  const candidate = bearer || headerToken;
  if (!candidate) return false;

  return timingSafeEqualStr(candidate, requiredToken);
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

function textResponse(body, status = 200, extraHeaders = {}, isHead = false) {
  return new Response(isHead ? null : body, {
    status,
    headers: {
      ...BASE_SECURITY_HEADERS,
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
      "Content-Type": "text/plain; charset=utf-8",
      ...extraHeaders,
    },
  });
}

/** Proxies `cm.py` from GitHub with edge caching, size cap, and optional SHA-256 check. */
async function servePythonScript(env, isHead) {
  let upstream;
  try {
    upstream = await fetch(SOURCE_URL, {
      cf: { cacheTtl: 60, cacheEverything: true },
      headers: { "User-Agent": "ConsoleManager-Worker/1.0" },
    });
  } catch {
    return textResponse("Error: failed to fetch upstream installer.\n", 502, {}, isHead);
  }

  if (!upstream.ok) {
    return textResponse(
      `Error: upstream returned HTTP ${upstream.status}.\n`,
      502,
      {},
      isHead,
    );
  }

  const declaredLen = Number(upstream.headers.get("content-length") || "0");
  if (declaredLen > MAX_SCRIPT_BYTES) {
    return textResponse("Error: upstream payload failed size check.\n", 502, {}, isHead);
  }

  const buffer = await upstream.arrayBuffer();
  if (buffer.byteLength === 0 || buffer.byteLength > MAX_SCRIPT_BYTES) {
    return textResponse("Error: upstream payload failed size check.\n", 502, {}, isHead);
  }

  const expectedHash =
    typeof env?.CM_SHA256 === "string" && /^[a-fA-F0-9]{64}$/.test(env.CM_SHA256.trim())
      ? env.CM_SHA256.trim().toLowerCase()
      : "";

  const actualHash = await sha256Hex(buffer);
  if (expectedHash && actualHash !== expectedHash) {
    return textResponse("Error: upstream payload failed SHA-256 verification.\n", 502, {}, isHead);
  }

  const scriptText = new TextDecoder("utf-8", { fatal: false }).decode(buffer);
  if (!scriptText.includes("Console Manager")) {
    return textResponse("Error: upstream payload failed integrity check.\n", 502, {}, isHead);
  }

  return textResponse(
    scriptText,
    200,
    {
      "Content-Type": "text/x-python; charset=utf-8",
      "Cache-Control": "public, max-age=60",
      "X-Content-SHA256": actualHash,
    },
    isHead,
  );
}

function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function detectClientKind(request) {
  const ua = (request.headers.get("User-Agent") || "").toLowerCase();
  const accept = (request.headers.get("Accept") || "").toLowerCase();

  if (ua.includes("powershell")) return "ps1";
  if (
    ua.includes("curl/") ||
    ua.includes("wget/") ||
    ua.includes("httpie/") ||
    ua.includes("fetch/") ||
    ua.includes("python-urllib")
  ) {
    return "sh";
  }
  if (accept.includes("text/html")) return "html";
  return "sh";
}

export default {
  async fetch(request, env = {}) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return textResponse("Method Not Allowed\n", 405, { Allow: "GET, HEAD" });
    }
    const isHead = request.method === "HEAD";
    const url = new URL(request.url);

    // Enforce HTTPS everywhere except local development.
    if (url.protocol === "http:" && !isLocalHost(url.hostname)) {
      url.protocol = "https:";
      return new Response(null, {
        status: 308,
        headers: {
          ...BASE_SECURITY_HEADERS,
          Location: url.toString(),
        },
      });
    }

    const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

    if (path === "/health" || path === "/healthz") {
      return textResponse("ok\n", 200, {}, isHead);
    }

    if (!(await isAuthorized(request, env))) {
      return textResponse(
        "Unauthorized\n",
        401,
        { "WWW-Authenticate": 'Bearer realm="executeee"' },
        isHead,
      );
    }

    const expectedSha256 = typeof env?.CM_SHA256 === "string" ? env.CM_SHA256.trim() : "";

    switch (path) {
      case "/": {
        const client = detectClientKind(request);
        if (client === "ps1") {
          return textResponse(buildPowerShellScript(expectedSha256), 200, { Vary: "User-Agent, Accept" }, isHead);
        }
        if (client === "html") {
          return new Response(isHead ? null : buildHtmlPage(url.origin), {
            status: 200,
            headers: {
              ...BASE_SECURITY_HEADERS,
              "Content-Type": "text/html; charset=utf-8",
              "Content-Security-Policy":
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
              Vary: "User-Agent, Accept",
            },
          });
        }
        return textResponse(buildShellScript(expectedSha256), 200, { Vary: "User-Agent, Accept" }, isHead);
      }

      case "/sh":
      case "/install.sh":
        return textResponse(buildShellScript(expectedSha256), 200, {}, isHead);

      case "/ps1":
      case "/install.ps1":
        return textResponse(buildPowerShellScript(expectedSha256), 200, {}, isHead);

      case "/cmd":
      case "/install.cmd":
        return textResponse(buildCmdScript(expectedSha256), 200, {}, isHead);

      case "/py":
      case "/cm.py":
        return servePythonScript(env, isHead);

      case "/raw":
        return textResponse(`${EXACT_ONELINER}\n`, 200, {}, isHead);

      default:
        return textResponse("Not Found\n", 404, {}, isHead);
    }
  },
};
