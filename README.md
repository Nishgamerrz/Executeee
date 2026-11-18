# Executeee — Cloudflare Worker Launcher

Zero-dependency, edge-fast Cloudflare Worker that securely launches [`cm.py`](https://raw.githubusercontent.com/Nishgamerrz/Nish12345678910111.github.io/main/cm.py) from a short Worker URL.

## Run from Terminal

> `curl` by itself only downloads text — pipe it to `sh` (or `python3` / `iex`) to execute it immediately:

### Linux / Ubuntu / Termux / macOS
```sh
curl -fsSL https://<your-worker>.workers.dev | sh
```

### Direct Python 3 (fastest — single HTTP hop via edge-cached `/py`)
```sh
curl -fsSL https://<your-worker>.workers.dev/py | python3
```

### Windows PowerShell
```powershell
irm https://<your-worker>.workers.dev | iex
```

### Windows CMD
```cmd
curl -fsSL https://<your-worker>.workers.dev/cmd -o "%TEMP%\cm.cmd" && "%TEMP%\cm.cmd"
```

*(Opening `https://<your-worker>.workers.dev` in a browser shows a one-click copy page.)*

---

## Endpoints

| Path | Description |
| --- | --- |
| `/` | Auto-detects `curl`/`wget` (`sh`), PowerShell (`ps1`), or browser (HTML copy page) |
| `/sh`, `/install.sh` | POSIX shell launcher running hardened `python3 -c` (reattaches `/dev/tty` for interactive prompts) |
| `/ps1`, `/install.ps1` | PowerShell launcher (enforces TLS 1.2/1.3, detects `python3` / `py -3` / `python`) |
| `/cmd`, `/install.cmd` | Windows CMD batch launcher |
| `/py`, `/cm.py` | Edge-cached (60s) verified proxy of `cm.py` for `curl -fsSL <url>/py \| python3` |
| `/raw` | Exact raw `python3 -c "..."` one-liner |
| `/health` | Returns `ok` (`200`) |

---

## Security Built In

- **Pinned upstream URL** — hardcoded to your `cm.py` over HTTPS (no query-param URL overrides, zero open-redirect/SSRF/injection surface).
- **Verified TLS & safe temp files** — enforces `ssl.create_default_context()`, 1 MiB payload cap, and an isolated `0700` temp directory (`tempfile.mkdtemp`) cleaned up on exit (avoids `/tmp/cm.py` symlink races).
- **Strict HTTP hardening** — `GET`/`HEAD` only (`405` otherwise), `308` HTTPS redirect, HSTS, `nosniff`, `DENY` framing, and strict CSP.
- **Optional secret token (`AUTH_TOKEN`)** — add `AUTH_TOKEN` in Worker **Settings → Variables and Secrets** to make the Worker private (constant-time Bearer check):
  ```sh
  curl -fsSL -H "Authorization: Bearer YOUR_TOKEN" https://<your-worker>.workers.dev | sh
  ```
- **Optional SHA-256 pin (`CM_SHA256`)** — add `CM_SHA256` in Worker secrets/variables to verify the exact SHA-256 hash of `cm.py` before executing.

---

## Deploy from GitHub (2 ways)

### Option 1 — Cloudflare Dashboard (easiest, no tokens needed)
1. Go to **Cloudflare Dashboard → Compute (Workers) → Workers & Pages → Create → Import a repository**.
2. Select `Nishgamerrz/Executeee`.
3. Leave build command blank and deploy command as `npx wrangler deploy` — click **Save and Deploy**. Every push to `main` auto-deploys.

### Option 2 — GitHub Actions (included in `.github/workflows/deploy.yml`)
1. In GitHub repo **Settings → Secrets and variables → Actions**, add:
   - `CLOUDFLARE_API_TOKEN` — Cloudflare API token with the **Edit Cloudflare Workers** template.
   - `CLOUDFLARE_ACCOUNT_ID` — your Cloudflare Account ID (shown on the Workers overview page).
2. Merge/push to `main` (or trigger **Actions → Deploy Cloudflare Worker → Run workflow**).

---

## Local Dev & Tests

```sh
npm test          # run unit + syntax verification tests
npm install
npm run dev       # run locally with Wrangler
```
