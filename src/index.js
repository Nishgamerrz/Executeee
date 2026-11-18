/**
 * Cloudflare Worker — fast, hardened auto-Python + cm.py shell launcher.
 *
 * Run:
 *   curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
 *
 * Optional Worker secrets (Settings -> Variables and Secrets):
 *   AUTH_TOKEN — require `Authorization: Bearer <token>` or `X-Auth-Token: <token>`
 *   CM_SHA256  — verify exact SHA-256 hash of cm.py before execution
 */

const SOURCE_URL =
  "https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py";

const MAX_SCRIPT_BYTES = 1024 * 1024; // 1 MiB safety cap

const SECURITY_HEADERS = Object.freeze({
  "Content-Type": "text/plain; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Cache-Control": "no-store, max-age=0",
});

function buildPythonCode(expectedSha256 = "") {
  const cleanHash = /^[a-fA-F0-9]{64}$/.test(expectedSha256)
    ? expectedSha256.toLowerCase()
    : "";

  const hashLines = cleanHash
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
    ...hashLines,
    "    with open(p, 'wb') as f:",
    "        f.write(b)",
    "    s.run([sys.executable, p], check=True)",
    "finally:",
    "    shutil.rmtree(d, ignore_errors=True)",
  ].join("\n");
}

function buildShellScript(expectedSha256 = "") {
  const pyCode = buildPythonCode(expectedSha256);

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
    if [ "$HAS_TTY" -eq 1 ]; then
      sudo "$@" </dev/tty
    else
      sudo -n "$@"
    fi
  elif command -v doas >/dev/null 2>&1; then
    if [ "$HAS_TTY" -eq 1 ]; then
      doas "$@" </dev/tty
    else
      doas -n "$@"
    fi
  else
    echo "Error: root/sudo privileges are required to install Python 3." >&2
    return 1
  fi
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

is_termux() {
  case "\${PREFIX:-}" in
    *com.termux*) return 0 ;;
  esac
  [ -d "/data/data/com.termux/files/usr" ]
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
    echo "Error: could not detect a supported package manager. Please install python3 manually." >&2
    exit 1
  fi
}

PY=""
if ! find_python3; then
  install_python3
  hash -r 2>/dev/null || true
  if ! find_python3; then
    echo "Error: Python 3 installation finished, but python3 is still not in PATH." >&2
    exit 1
  fi
fi

CODE=$(cat <<'__CM_PY_EOF__'
${pyCode}
__CM_PY_EOF__
)

if [ "$HAS_TTY" -eq 1 ]; then
  exec "$PY" -c "$CODE" </dev/tty
else
  exec "$PY" -c "$CODE"
fi
`;
}

/** Constant-time string comparison using SHA-256 digests. */
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

function respond(body, status = 200, extraHeaders = {}, isHead = false) {
  return new Response(isHead ? null : body, {
    status,
    headers: { ...SECURITY_HEADERS, ...extraHeaders },
  });
}

function isLocalHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export default {
  async fetch(request, env = {}) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return respond("Method Not Allowed\n", 405, { Allow: "GET, HEAD" });
    }

    const isHead = request.method === "HEAD";
    const url = new URL(request.url);

    // Enforce HTTPS everywhere except local dev.
    if (url.protocol === "http:" && !isLocalHost(url.hostname)) {
      url.protocol = "https:";
      return new Response(null, {
        status: 308,
        headers: { ...SECURITY_HEADERS, Location: url.toString() },
      });
    }

    const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;

    if (path === "/health") {
      return respond("ok\n", 200, {}, isHead);
    }

    if (path !== "/" && path !== "/sh" && path !== "/install.sh") {
      return respond("Not Found\n", 404, {}, isHead);
    }

    if (!(await isAuthorized(request, env))) {
      return respond("Unauthorized\n", 401, { "WWW-Authenticate": 'Bearer realm="executeee"' }, isHead);
    }

    const expectedSha256 = typeof env?.CM_SHA256 === "string" ? env.CM_SHA256.trim() : "";
    return respond(buildShellScript(expectedSha256), 200, {}, isHead);
  },
};
