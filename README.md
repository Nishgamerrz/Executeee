# Executeee

Fast, zero-dependency Cloudflare Worker shell launcher — no HTML page, just plain script. Automatically installs `python3` if missing (Termux `pkg`, Ubuntu/Debian `apt`, Alpine `apk`, Fedora/RHEL `dnf`/`yum`, Arch `pacman`, openSUSE `zypper`, macOS `brew`, Git Bash `winget`), then securely downloads and runs `cm.py`.

## Run

```sh
curl -fsSL https://executeee.nishkarshrana10.workers.dev | sh
```

## Optional Worker Secrets

Set in Cloudflare **Workers & Pages → `executeee` → Settings → Variables and Secrets**:

- `AUTH_TOKEN` — require a Bearer token:
  ```sh
  curl -fsSL -H "Authorization: Bearer YOUR_TOKEN" https://executeee.nishkarshrana10.workers.dev | sh
  ```
- `CM_SHA256` — verify the exact SHA-256 hash of `cm.py` before running.

## Test

```sh
npm test
```
