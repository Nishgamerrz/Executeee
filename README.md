# Executeee

Zero-config Cloudflare Worker launcher. Browsers, bots, AI crawlers, scrapers, expired tokens, and replayed sessions return only `err occcured`.

## Run

```sh
curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
```

Or download and inspect first:

```sh
curl -fsSL https://executeee.nishkarshrana10.workers.dev -o script.sh
cat script.sh
sh script.sh
```

## What you see

- **Browser / scraper / AI fetcher:** `err occured` (403)
- **Real terminal:** A 20-second "Setting up everything..." spinner, then a fake "HACKING DEVICE..." prank animation with scrolling hacker text, ending with `ACCESS GRANTED / DEVICE P0WNED`. Harmless fun — no files are modified, nothing is installed.

## Security

- `GET /` returns only a 10-second single-use session token (zero installer code, zero URLs)
- `POST /` requires a valid SHA-256 proof bound to IP + curl UA + Cloudflare colo
- Tokens expire after 10 seconds and cannot be reused
- Per-IP rate limiting blocks spam
- All non-terminal clients get `err occured`
