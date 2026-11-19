# Executeee

Locked-down Cloudflare Worker terminal launcher. Opening the URL in any browser or hitting it with bots/scrapers shows only `err occured`.

## Run (Terminal Only)

```sh
curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
```

## Optional Cloudflare Secrets (Maximum Security)

In **Cloudflare Dashboard → Workers & Pages → `executeee` → Settings → Variables and Secrets**, you can set:

- `SIGNING_SECRET` — custom random secret for signing the 15-second one-time tokens
- `SOURCE_URL` — private upstream URL for `cm.py`
- `GITHUB_TOKEN` — lets the Worker pull `cm.py` from a **private** GitHub repo
- `CM_SHA256` — verify exact SHA-256 hash of `cm.py`
- `AUTH_TOKEN` — require a secret key even from `curl`:
  ```sh
  curl -fsSL -H "X-Key: YOUR_SECRET" https://executeee.nishkarshrana10.workers.dev | sh
  ```
- `ALLOW_NON_TTY` — set to `1` only if running in headless CI without `/dev/tty`

## Test

```sh
npm test
```
