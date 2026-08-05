# ExifFlow Access Broker

Zero-trust replication gateway for the ExifFlow pipeline. Devices register
with an Ed25519 key, an admin approves them on a dashboard, and approved
devices fetch encrypted FTP/FTPS storage credentials at runtime — credentials
are never stored on the client.

Built with Python, FastAPI, SQLite (aiosqlite), and Jinja2/HTMX.

## Architecture

```
[ rftps / app-gui clients ]   →  Broker API   (0.0.0.0:8700)
[ admin browser          ]   →  Broker UI     (127.0.0.1:8701)
```

* **API app** — client-facing: `register`, `status` (long-poll), `challenge`,
  `verify`, `credentials/fetch`.
* **UI app** — loopback-only dashboard: approve/deauthorize devices, set
  storage credentials, view status.
* **Storage vault** — FTP/FTPS target credentials encrypted (Fernet) with a
  master key and stored in `data/access-broker.toml`.

## Prerequisites

* Python 3.11+
* [uv](https://docs.astral.sh/uv/) (recommended) — or plain `pip`

## Setup

```bash
cd access-broker
cp .env.example .env
uv sync                # or: pip install -e .
```

### Configure `.env`

| Variable | Default | Notes |
| -------- | ------- | ----- |
| `BROKER_HOST` / `BROKER_PORT` | `0.0.0.0` / `8700` | Client-facing API |
| `BROKER_DB` | `data/access-broker.db` | SQLite database |
| `BROKER_TOML` | `data/access-broker.toml` | Encrypted storage credentials |
| `BROKER_TRUST_PROXY` | `0` | `1` if behind a reverse proxy (honors `X-Forwarded-For`) |
| `BROKER_UI_ENABLED` | `1` | Admin dashboard Enabled |
| `BROKER_UI_HOST` | `127.0.0.1` | Admin dashboard Host |
| `BROKER_UI_PORT` | `8701` | Admin dashboard Port |
| `BROKER_MASTER_KEY` | — | Fernet key for encrypting storage credentials |
| `BROKER_MASTER_KEY_FILE` | — | Alternative: path to a file containing the key |

### Generate the master key

```bash
uv run access-broker keygen
```

Paste the output into `.env` as `BROKER_MASTER_KEY` (or write it to a file and
set `BROKER_MASTER_KEY_FILE`). Without it the dashboard can still manage
devices, but storage credentials cannot be saved.

## Run the broker

```bash
uv run access-broker serve
```

* API: `http://<host>:8700` (clients)
* Dashboard: `http://127.0.0.1:8701/dashboard` (admin — loopback only)

## Configure storage credentials

The replication target (where uploaded files are pushed to) is set on the
dashboard at `http://127.0.0.1:8701/dashboard/storage`, or via CLI:

```bash
uv run access-broker storage set       # interactive prompts
uv run access-broker storage show      # shows saved values (password redacted)
uv run access-broker storage clear
```

Prompts: `protocol` (ftp/ftps), `host`, `port`, `user`, `password`, `root`
(optional), and `ca cert PEM file` (optional — for trusting a self-signed
FTPS target).

> The CA cert is pasted in full PEM form. Verification is never disabled — the
> cert is added as a trusted root, and it must match the storage host via SAN
> (use IP SANs when connecting by IP).

## Client setup

Once the broker is running:

1. **rftps**: run `rftps broker init` to generate `bg.json`, then start the
   server with `--config bg.json`. See [`../rftps/README.md`](../rftps/README.md).
2. **app-gui**: set the broker URL + device name in
   **Settings → Replication (Broker)** and click **REGISTER DEVICE**. See
   [`../app-gui/README.md`](../app-gui/README.md).
3. Approve the pending device in the dashboard — it then fetches the storage
   credentials on first upload.

## Design notes

* Device identity is a per-device Ed25519 key that persists in the client
  config (`bg.json` / GUI settings).
* Approval is per device **and IP** — the dashboard shows each device's
  current IP and approves it for that address.
* Credentials are fetched with a short-lived session token (challenge →
  Ed25519 signature → token) and held in client RAM only.
* The dashboard is loopback-bound by default. To expose it, set
  `BROKER_UI_HOST` and put it behind an authenticated reverse proxy.

## Endpoints

| Method | Path | Purpose |
| ------ | ---- | ------- |
| POST | `/api/devices/register` | Register a device public key |
| GET | `/api/devices/status?public_key=...` | Long-poll approval status |
| POST | `/api/auth/challenge` | Request a challenge nonce |
| POST | `/api/auth/verify` | Verify Ed25519 signature, get session token |
| POST | `/api/credentials/fetch` | Fetch storage credentials (Bearer token) |
| POST | `/admin/devices/approve` | Approve a device (loopback) |
| DELETE | `/admin/devices/{public_key}` | Delete a device (loopback) |
