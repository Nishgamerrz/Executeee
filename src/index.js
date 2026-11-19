/**
 * Cloudflare Worker — terminal-only, anti-scraper launcher for cm.py.
 *
 * - Browsers, link previews, crawlers, and HTTP scrapers receive ONLY: `err occured`
 * - Real terminal execution (`curl -fsSL <worker-url> | sh`) completes a 15-second,
 *   single-use, IP/UA/colo-bound HMAC + SHA-256 handshake, fetches cm.py server-side
 *   (never exposing the upstream URL), auto-installs Python 3 if missing, runs cm.py
 *   in a private 0700 temp directory, and wipes it on exit.
 *
 * Optional Cloudflare Worker Secrets (Settings -> Variables and Secrets):
 *   SIGNING_SECRET — secret key used to sign 15s one-time session tokens (recommended)
 *   SOURCE_URL     — override upstream cm.py URL privately
 *   GITHUB_TOKEN   — GitHub token if hosting cm.py in a private repository
 *   CM_SHA256      — pin exact SHA-256 hash of cm.py
 *   AUTH_TOKEN     — require `Authorization: Bearer <token>` or `X-Key: <token>`
 *   ALLOW_NON_TTY  — set to "1" only if you need to run inside headless CI with no /dev/tty
 */

const DEFAULT_SOURCE_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

const ERR_TEXT = "err occured\n";
const TOKEN_TTL_MS = 15_000; // 15 seconds
const MAX_SCRIPT_BYTES = 1024 * 1024; // 1 MiB
const RATE_WINDOW_MS = 60_000; // 1 minute
const RATE_MAX_REQUESTS = 10; // per IP per minute (covers GET + POST handshake)

const CURL_UA_RE = /^curl\/\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9._-]+)?$/;

// Headers sent by browsers, webviews, link unfurlers, proxies, and browser-based scrapers.
const FORBIDDEN_HEADERS = Object.freeze([
  "sec-fetch-mode",
  "sec-fetch-site",
  "sec-fetch-dest",
  "sec-fetch-user",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "upgrade-insecure-requests",
  "accept-language",
  "referer",
  "origin",
  "cookie",
  "dnt",
  "sec-gpc",
  "x-requested-with",
  "purpose",
  "sec-purpose",
]);

const BASE_HEADERS = Object.freeze({
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

// Per-isolate replay protection & sliding-window IP rate limiter.
const usedNonces = new Map(); // nonce -> expiresAt
const ipHits = new Map(); // ip -> { count, resetAt }

const encoder = new TextEncoder();

function errResponse(isHead = false) {
  return new Response(isHead ? null : ERR_TEXT, {
    status: 403,
    headers: BASE_HEADERS,
  });
}

function okResponse(body, isHead = false) {
  return new Response(isHead ? null : body, {
    status: 200,
    headers: BASE_HEADERS,
  });
}

function pruneMaps(now) {
  if (usedNonces.size > 500) {
    for (const [k, exp] of usedNonces) {
      if (exp <= now) usedNonces.delete(k);
    }
  }
  if (ipHits.size > 1000) {
    for (const [ip, entry] of ipHits) {
      if (entry.resetAt <= now) ipHits.delete(ip);
    }
  }
}

function checkRateLimit(ip, now) {
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

function getClientBinding(request) {
  const ip = getClientIp(request);
  const ua = request.headers.get("User-Agent") || "";
  const colo = request.cf?.colo || "local";
  return `${ip}|${ua}|${colo}`;
}

/** Strictly accepts only genuine `curl` CLI requests; rejects browsers, bots, and scrapers. */
function isGenuineCurlRequest(request) {
  if (request.cf?.botManagement?.verifiedBot === true) {
    return false;
  }

  const ua = request.headers.get("User-Agent") || "";
  if (!CURL_UA_RE.test(ua)) {
    return false;
  }

  const accept = request.headers.get("Accept") || "";
  if (accept !== "*/*") {
    return false;
  }

  for (const header of FORBIDDEN_HEADERS) {
    if (request.headers.has(header)) {
      return false;
    }
  }

  return true;
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
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

/** Constant-time string comparison using SHA-256 digests. */
async function timingSafeEqualStr(a, b) {
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(String(a))),
    crypto.subtle.digest("SHA-256", encoder.encode(String(b))),
  ]);
  const viewA = new Uint8Array(hashA);
  const viewB = new Uint8Array(hashB);
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i];
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
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return toHex(sig);
}

function getSigningSecret(env, host) {
  const custom = typeof env?.SIGNING_SECRET === "string" ? env.SIGNING_SECRET.trim() : "";
  if (custom) return custom;
  const auth = typeof env?.AUTH_TOKEN === "string" ? env.AUTH_TOKEN.trim() : "";
  return `executeee-v2-hmac::${host}::${auth}`;
}

async function issueHandshake(request, env, host, now) {
  const exp = now + TOKEN_TTL_MS;
  const nonce = randomHex(16);
  const challenge = randomHex(12);
  const bindingHash = await sha256Hex(getClientBinding(request));
  const payload = `${exp}.${nonce}.${challenge}`;
  const sig = await hmacHex(getSigningSecret(env, host), `${payload}.${bindingHash}`);
  return { token: `${payload}.${sig}`, challenge };
}

async function verifyAndConsumeHandshake(request, env, host, now) {
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
  if (!Number.isSafeInteger(exp) || now > exp || exp - now > TOKEN_TTL_MS + 5_000) {
    return false;
  }

  // Block replay within token window.
  if (usedNonces.has(nonce)) {
    return false;
  }

  const bindingHash = await sha256Hex(getClientBinding(request));
  const expectedSig = await hmacHex(
    getSigningSecret(env, host),
    `${expStr}.${nonce}.${challenge}.${bindingHash}`,
  );
  if (!(await timingSafeEqualStr(sig, expectedSig))) {
    return false;
  }

  const expectedProof = await sha256Hex(`${token}:${challenge}`);
  if (!(await timingSafeEqualStr(proof, expectedProof))) {
    return false;
  }

  usedNonces.set(nonce, exp + 5_000);
  return true;
}

async function isAuthorized(request, env) {
  const requiredToken = typeof env?.AUTH_TOKEN === "string" ? env.AUTH_TOKEN.trim() : "";
  if (!requiredToken) return true;

  const authHeader = request.headers.get("Authorization") || "";
  const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const headerKey = (request.headers.get("X-Key") || "").trim();
  const candidate = bearer || headerKey;
  if (!candidate) return false;

  return timingSafeEqualStr(candidate, requiredToken);
}

/**
 * Stage-1 shell bootstrap:
 * - Verifies execution inside a real interactive terminal (/dev/tty)
 * - Completes the 15s single-use SHA-256 handshake over POST to fetch the payload
 *   directly into a private 0700 temp directory (no upstream URL exposed)
 * - Auto-installs Python 3 if missing across Linux, Termux, macOS, and Git Bash
 * - Executes payload with /dev/tty attached and wipes temp directory on exit
 */
function buildStage1Shell(origin, token, challenge, requireTty, forwardAuth) {
  const ttyGuard = requireTty
    ? `if ! ( : </dev/tty ) 2>/dev/null; then
  printf 'err occured\\n' >&2
  exit 1
fi
HAS_TTY=1`
    : `HAS_TTY=0
if ( : </dev/tty ) 2>/dev/null; then
  HAS_TTY=1
fi`;

  // If AUTH_TOKEN was supplied on GET, forward it cleanly on the POST handshake only
  // after sanitizing to safe token characters (prevents shell injection).
  const safeAuth =
    forwardAuth && /^[A-Za-z0-9._~+/-]+=*$/.test(forwardAuth) ? forwardAuth : "";
  const authCurlArg = safeAuth ? ` -H 'X-Key: ${safeAuth}'` : "";

  return `#!/bin/sh
set -eu

${ttyGuard}

calc_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    printf '%s' "$1" | openssl dgst -sha256 -r | cut -d' ' -f1
  else
    return 1
  fi
}

TOK='${token}'
PRF="$(calc_sha256 "$TOK:${challenge}")" || { printf 'err occured\\n' >&2; exit 1; }

umask 077
TMP_BASE="\${TMPDIR:-}"
if [ -z "$TMP_BASE" ] || [ ! -d "$TMP_BASE" ]; then
  if [ -n "\${PREFIX:-}" ] && [ -d "$PREFIX/tmp" ]; then
    TMP_BASE="$PREFIX/tmp"
  else
    TMP_BASE="/tmp"
  fi
fi
WORK_DIR="$(mktemp -d "$TMP_BASE/cm.XXXXXXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM HUP
TARGET="$WORK_DIR/cm.py"

if ! curl -fsSL -X POST --data '' -H "X-Session: $TOK" -H "X-Proof: $PRF"${authCurlArg} '${origin}/' -o "$TARGET" 2>/dev/null; then
  printf 'err occured\\n' >&2
  exit 1
fi

if [ ! -s "$TARGET" ]; then
  printf 'err occured\\n' >&2
  exit 1
fi

run_priv() {
  if [ "$(id -u 2>/dev/null || echo 1)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    if [ "$HAS_TTY" -eq 1 ]; then sudo "$@" </dev/tty; else sudo -n "$@"; fi
  elif command -v doas >/dev/null 2>&1; then
    if [ "$HAS_TTY" -eq 1 ]; then doas "$@" </dev/tty; else doas -n "$@"; fi
  else
    echo "Error: root/sudo privileges are required to install Python 3." >&2
    return 1
  fi
}

is_termux() {
  case "\${PREFIX:-}" in *com.termux*) return 0 ;; esac
  [ -d "/data/data/com.termux/files/usr" ]
}

find_python3() {
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c "import sys,ssl,urllib.request; sys.exit(0 if sys.version_info[0] >= 3 else 1)" >/dev/null 2>&1; then
        PY="$candidate"
        return 0
      fi
    fi
  done
  return 1
}

install_python3() {
  echo "Python 3 not found — installing Python 3 automatically..."
  if is_termux && command -v pkg >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive pkg update -y </dev/null
    DEBIAN_FRONTEND=noninteractive pkg install -y python </dev/null
  elif command -v apt-get >/dev/null 2>&1; then
    run_priv env DEBIAN_FRONTEND=noninteractive apt-get update -y
    run_priv env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    run_priv apk add --no-cache python3 ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    run_priv dnf install -y python3 ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    run_priv yum install -y python3 ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    if [ -n "\${MSYSTEM:-}" ]; then
      pacman -Sy --noconfirm python ca-certificates
    else
      run_priv pacman -Sy --noconfirm python ca-certificates
    fi
  elif command -v zypper >/dev/null 2>&1; then
    run_priv zypper --non-interactive install python3 ca-certificates
  elif command -v brew >/dev/null 2>&1; then
    NONINTERACTIVE=1 brew install python3
    for d in /opt/homebrew/bin /usr/local/bin; do
      [ -d "$d" ] && PATH="$d:$PATH"
    done
    export PATH
  elif command -v winget.exe >/dev/null 2>&1; then
    winget.exe install -e --id Python.Python.3.12 --scope user --accept-source-agreements --accept-package-agreements
    if [ -n "\${LOCALAPPDATA:-}" ]; then
      for d in "$LOCALAPPDATA"/Programs/Python/Python3*; do
        [ -d "$d" ] && PATH="$d:$PATH"
      done
      export PATH
    fi
  else
    echo "Error: could not install Python 3 automatically. Please install python3 and retry." >&2
    exit 1
  fi
}

PY=""
if ! find_python3; then
  install_python3
  hash -r 2>/dev/null || true
  if ! find_python3; then
    echo "Error: Python 3 installed, but python3 was not found in PATH." >&2
    exit 1
  fi
fi

if [ "$HAS_TTY" -eq 1 ]; then
  "$PY" "$TARGET" </dev/tty
else
  "$PY" "$TARGET"
fi
`;
}

/** Fetches cm.py server-side so the upstream URL is never exposed to clients. */
async function fetchUpstreamPayload(env) {
  const sourceUrl =
    typeof env?.SOURCE_URL === "string" && env.SOURCE_URL.trim().startsWith("https://")
      ? env.SOURCE_URL.trim()
      : DEFAULT_SOURCE_URL;

  const headers = { "User-Agent": "Executeee-Worker/2.0" };
  const ghToken = typeof env?.GITHUB_TOKEN === "string" ? env.GITHUB_TOKEN.trim() : "";
  if (ghToken) {
    headers.Authorization = `Bearer ${ghToken}`;
    headers.Accept = "application/vnd.github.raw";
  }

  let upstream;
  try {
    upstream = await fetch(sourceUrl, {
      cf: ghToken ? { cacheTtl: 0 } : { cacheTtl: 60, cacheEverything: true },
      headers,
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

  const expectedHash =
    typeof env?.CM_SHA256 === "string" && /^[a-fA-F0-9]{64}$/.test(env.CM_SHA256.trim())
      ? env.CM_SHA256.trim().toLowerCase()
      : "";

  if (expectedHash) {
    const actualHash = await sha256Hex(buffer);
    if (actualHash !== expectedHash) return null;
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(buffer);
}

export default {
  async fetch(request, env = {}) {
    const isHead = request.method === "HEAD";

    // Only GET (stage 1) and POST (signed stage 2) on exact root path `/` are allowed.
    if (request.method !== "GET" && request.method !== "POST") {
      return errResponse(isHead);
    }

    const url = new URL(request.url);
    if (url.protocol === "http:" && !isLocalHost(url.hostname)) {
      return errResponse(false);
    }

    // Reject every path other than `/` and reject any query parameters.
    if (url.pathname !== "/" || url.search !== "") {
      return errResponse(false);
    }

    const now = Date.now();
    if (!checkRateLimit(getClientIp(request), now)) {
      return errResponse(false);
    }

    // Reject all browsers, webviews, bots, crawlers, and non-curl scrapers.
    if (!isGenuineCurlRequest(request)) {
      return errResponse(false);
    }

    // Optional secret token check.
    if (!(await isAuthorized(request, env))) {
      return errResponse(false);
    }

    // Stage 1: `curl -fsSL https://<worker> | sh` -> issue 15s single-use signed handshake.
    if (request.method === "GET") {
      const { token, challenge } = await issueHandshake(request, env, url.host, now);
      const requireTty = String(env?.ALLOW_NON_TTY || "") !== "1";
      const authHeader = request.headers.get("Authorization") || "";
      const forwardAuth = authHeader.startsWith("Bearer ")
        ? authHeader.slice(7).trim()
        : (request.headers.get("X-Key") || "").trim();
      const shell = buildStage1Shell(url.origin, token, challenge, requireTty, forwardAuth);
      return okResponse(shell, false);
    }

    // Stage 2: verify signed single-use token + SHA-256 proof + IP/UA/colo binding, then serve cm.py.
    if (!(await verifyAndConsumeHandshake(request, env, url.host, now))) {
      return errResponse(false);
    }

    const payload = await fetchUpstreamPayload(env);
    if (!payload) {
      return errResponse(false);
    }

    return okResponse(payload, false);
  },
};

export const _internal = { resetState: () => { usedNonces.clear(); ipHits.clear(); } };
