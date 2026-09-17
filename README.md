# EVulnTasker v1.0 Beta

**Elizarov Vulnerabilities Tasking Manager Platform**

EVulnTasker is a Linux appliance for risk-based vulnerability tasking. It watches how CVE intelligence arrives in the organization (a local inbox folder, SMB shares, an Exchange mailbox, or ATOM/RSS feeds), pulls out CVE IDs and product identity, optionally asks NVD and FIRST EPSS for scores, and then compares that identity to a local **Internal systems** catalog. When a row matches, the Act step opens owner and threat-hunting work: Jira, Monday.com, SMTP email, or an internal CRM, plus Sigma/SIEM hunt text from the same pass.

The product is meant for a single RHEL or Ubuntu host. One systemd service (`evulntasker`) runs the HTTP UI, the pipeline worker, and the pollers. Matching never calls CMDB, Sonatype, or ITNM per CVE; those systems only teach the local catalog on a schedule. The UI is **English only**. This phase stays on **HTTP port 8080** (no TLS). Leave `EVULNTASKER_BASIC_AUTH_*` blank for an open lab, or set both to get a browser Basic Auth prompt without changing the port.

Open `http://127.0.0.1:8080` after install. Module detail: [`FUNCTIONALITY.md`](FUNCTIONALITY.md). Remaining gaps: [`GAPS.md`](GAPS.md). Lab risk survey: [`PT-RISK-SURVEY.md`](PT-RISK-SURVEY.md).

---

## Open source libraries

EVulnTasker is a Python 3.11+ application. These are the third-party Open Source packages from `requirements.txt` (BSD / MIT / Apache-2.0 / PSF and similar licenses — see each project).

| Library | License (typical) | What EVulnTasker uses it for |
|---------|-------------------|------------------------------|
| **FastAPI** | MIT | REST API under `/api` and the ASGI app |
| **Uvicorn** | BSD-3 | Production HTTP server (systemd `ExecStart`) |
| **Starlette** | BSD-3 | Middleware, static files, request/response |
| **Jinja2** | BSD-3 | English HTML dashboard and mail HTML |
| **python-multipart** | Apache-2.0 | Form and CSV uploads |
| **orjson** | Apache-2.0 / MIT | Fast JSON encode/decode |
| **Pydantic** | MIT | Request bodies and Settings models |
| **pydantic-settings** | MIT | Load `.env` / `EVULNTASKER_*` |
| **SQLAlchemy 2** | MIT | ORM (SQLite or PostgreSQL) |
| **Alembic** | MIT | Schema migrations when `alembic/versions` exists |
| **psycopg2-binary** | LGPL-3.0 | PostgreSQL driver (skipped on Python 3.14) |
| **greenlet** | MIT | SQLAlchemy async/greenlet support |
| **httpx** | BSD-3 | NVD, EPSS, ATOM, Jira, inventory, AI HTTP |
| **aiohttp** | Apache-2.0 | Extra async HTTP client |
| **APScheduler** | MIT | Timed Local / SMB / Outlook / ATOM / inventory polls |
| **exchangelib** | BSD-2 | On-prem Exchange / Outlook ingest |
| **aiosmtplib** | MIT | SMTP relay and Gmail Act mail |
| **smbprotocol** | MIT | SMB/CIFS file ingest (AD/LDAP account) |
| **python-dateutil** | BSD-3 / Apache-2.0 | CVE / feed date parsing |
| **tenacity** | Apache-2.0 | NVD/EPSS retries |
| **structlog** | MIT / Apache-2.0 | Structured pipeline logs |
| **Celery** + **Redis** | BSD-3 / MIT | Optional multi-node workers (not required on one host) |
| **pytest** / **pytest-asyncio** | MIT | Test suite |

SQLite ships with Python. PostgreSQL is optional and installed separately if you switch **Settings → Database**.

---

## Install from scratch

Default production path: **`/opt/evulntasker`**. Systemd unit: **`evulntasker`**. URL: **`http://127.0.0.1:8080`**.

Need **Python 3.11+** (3.12 / 3.13 / 3.14 are fine; `psycopg2-binary` is skipped on 3.14), **git**, **sudo**, and **systemd**. On RHEL use AppStream `python3.11` (and `python3.11-venv` if you run the tree without `setup.sh`).

### 1. Clone

```bash
git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker
cd evulntasker
```

If you received a copy of the tree (USB, share) instead of git, `cd` into that directory. The rest of the steps are the same: you must be in the folder that contains `setup.sh`, `app.py`, and `app/`.

### 2. Online install

The target host can reach PyPI. From the cloned tree:

```bash
sudo ./setup.sh
```

That copies the application to `/opt/evulntasker`, creates a venv, installs wheels from the internet, writes `.env` from `.env.example` (mode `600`), applies the schema, and enables `evulntasker.service` on HTTP `:8080`.

Useful flags:

```bash
sudo ./setup.sh --port 8080          # default; stays HTTP, no TLS
sudo ./setup.sh --prefix /opt/evulntasker
sudo ./setup.sh --user evulntasker   # service account (default: the sudo user)
sudo ./setup.sh --no-service         # files only; start with python3 app.py
# sudo ./setup.sh --open-firewall    # firewalld TCP 8080 — lab LAN only; prefer Basic Auth first
```

Open `http://127.0.0.1:8080`. On first boot edit `/opt/evulntasker/.env` if you want HTTP Basic:

```bash
# /opt/evulntasker/.env
EVULNTASKER_BASIC_AUTH_USER=lab
EVULNTASKER_BASIC_AUTH_PASSWORD=change-me
sudo systemctl restart evulntasker
```

Leave those two keys blank to keep the lab UI open.

### 3. Offline install (air-gapped)

Two machines: a **build host with internet**, and a **target with no internet**.

**On the build host**

```bash
git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker
cd evulntasker
./package_offline.sh
```

That downloads wheels into `vendor/wheels` and writes `dist/EVulnTasker-offline-<arch>-py<ver>-<date>.zip` (source, `setup.sh`, docs, wheels). Optional: `./package_offline.sh --python python3.11 --output dist`.

Copy the ZIP to the target (USB, scp, and so on).

**On the target**

```bash
unzip EVulnTasker-offline-*.zip
cd EVulnTasker-offline-*
sudo ./setup.sh --offline
```

`--offline` installs only from `vendor/wheels`. It does not call PyPI. The result is the same layout: `/opt/evulntasker`, systemd unit, HTTP `:8080`.

### 4. After a fresh install (online or offline)

```bash
sudo systemctl status evulntasker
sudo journalctl -u evulntasker -f
```

Browser: `http://127.0.0.1:8080` (LAN: `http://<host-ip>:8080`). Health: `GET /healthz`. `/docs` is hidden when `EVULNTASKER_ENV=production` (the systemd unit sets that).

Then in the UI:

1. **Internal systems** — add products or import CSV (`/api/inventory/template.csv`). CMDB / Sonatype / ITNM are optional later teachers.
2. **Settings → Feeds → Local** — a folder on this Linux host under an allowed root (`/tmp`, `/var/evulntasker`, `/opt/evulntasker/inbox`, `data/inbox`). Enable the feed on **Input Sources**, then Sync now.
3. **Settings → Enrichment / Internet intel** — turn NVD/EPSS on only if lookups should run.
4. **Settings → AI modules** — leave off if the organization must not call an LLM.
5. **Settings → Ticketing** — Enable Email / Jira / Monday / CRM as needed. Optional **Allowed recipient domains**. Edit **Message** templates.
6. Watch **Live Workflow**, **Incoming CVEs**, and **Actions**.

Local inbox extra roots: `EVULNTASKER_LOCAL_INGEST_ALLOW` in `.env`. After any Python change under `app/`:

```bash
sudo systemctl restart evulntasker
```

Hard-refresh the browser (Ctrl+Shift+R) after UI changes.

### 5. Upgrade (keeps the database)

From a new clone or unzipped offline tree that already has wheels:

```bash
# online host
cd evulntasker
sudo ./setup.sh --upgrade

# air-gapped host
cd EVulnTasker-offline-*
sudo ./setup.sh --offline --upgrade
```

Schema is additive. Existing CVE and catalog rows stay. A DB backup is taken first (default `/var/backups/evulntasker`).

### 6. Uninstall

```bash
sudo ./uninstall.sh --yes
```

Stops `evulntasker` (and leftover `vaict` / `vulnintel` units), copies the database (Incoming CVEs + Internal systems) aside, then deletes the install and `.env`. Gmail, SMTP, and Basic Auth secrets are **not** in that backup.

### 7. Optional: run from the clone without systemd

For a laptop or a checkout that should not touch `/opt`:

```bash
git clone <YOUR_EVULNTASKER_GIT_URL> evulntasker
cd evulntasker
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt          # online
# pip install --no-index --find-links vendor/wheels -r requirements.txt   # after package_offline.sh
cp .env.example .env
python3 app.py
```

Still HTTP `http://127.0.0.1:8080`.

---

## What it does

| Step | Name | What actually runs |
|------|------|---------------------|
| 1 | **Ingest** | Local folder, SMB/CIFS, Outlook/Exchange mailbox, ATOM/RSS feeds |
| 2 | **Extract** | CVE regex plus vendor / product / version from labeled text, CSV, JSON, or CPE. LLM only if no CVE ID is found and AI modules are enabled |
| 3 | **Enrich** | Optional. When on: NVD 2.0 (CVSS, CWE, attack vector) + FIRST EPSS. LLM rewrite only if AI is on and mode is **EVulnTasker AI**. When off: skip lookups and continue to matching |
| 4 | **Match** | Local **Internal systems** catalog only. That catalog is seeded at setup (hand/CSV) and later taught by CMDB / Sonatype / ITNM on a schedule (new equipment only) — those APIs are not called here. Linux kernel CVEs also hit distro OS rows. LLM may infer an owner only if nothing matches and AI is on — it does not invent catalog rows |
| 5 | **Act** | Per-provider tickets (Jira, Monday.com, Email, Internal CRM), Sigma/SIEM detections, optional Exchange/Gmail notify. Tickets use **Message** templates. AI is not required |

A CVE already in the database is not run through enrich/match/act again, except ATOM feed refreshes which update fields and re-enrich.

---

## Screens

Sidebar groups:

**Overview Dashboards**

- **Main** — pipeline KPIs
- **Status** — live CVE queue (stage, priority, owner team, tickets)

**Databases**

- **Internal systems** — in-org products. Seeded by hand or CSV; Sonatype IQ harvests applications and libraries on Enable save; CMDB / ITNM add only new equipment on a schedule
- **Incoming CVEs** — every CVE stored by EVulnTasker. Click a row for Live Workflow stations; the CVE ID opens the full record

**Pipeline**

- **Input Sources** — Local / SMB / Outlook / ATOM (one row per ATOM URL) plus NVD/EPSS lookup Enable. Enable/Pause is auto-poll; Sync now pulls once even if paused. Connection details stay under Settings → Feeds
- **Extraction** — ingest events (one row per file or feed item) and extracted CVE records
- **Enrichment** — NVD/EPSS/AI fill; records stay listed after later stages
- **Asset matching** — hits against Internal systems
- **Actions** — owner ticket, hunt ticket, detections

**System**

- **Debugger** — walk a CVE through every stage using live Settings. Each stage explains what ran, who matched and why (or why not), and who would be notified. Nothing is stored and nothing is sent
- **Settings** — database, reset, feeds, enrichment, intel, AI, inventory teachers (CMDB / Sonatype / ITNM), ticketing, message layout

CVE detail (`/vulnerabilities/{cve_id}`): description, matches, tickets, hunting pack, audit trail, **Re-run pipeline** (Live Workflow) and **Run debugger** (dry-run only).

Health check: `GET /healthz` (always unauthenticated). `/docs`, `/redoc`, and `/openapi.json` are served only when `EVULNTASKER_ENV` is not `production`.

---

## Settings

| Tab | Purpose |
|-----|---------|
| **Database** | SQLite, local PostgreSQL on this Linux host, or external PostgreSQL. Existing SQLite rows are not copied |
| **Reset** | Two separate wipes. **Reset Internal systems** deletes the catalog and match links. **Delete all CVEs** removes Incoming CVEs plus pipeline history, tickets, and detections. Each asks for confirmation. Keeps DB connection, feed configs, and integration settings |
| **Feeds** | Local folder, SMB, Outlook/Exchange, ATOM URLs and intervals. Enable/Pause and Sync now live on **Input Sources**. ATOM polling does **not** fetch NVD/EPSS — those stay enrichment lookups |
| **Enrichment** | Enable / Disable the enrich stage (`ENRICHMENT_ENABLED`). Independent of AI |
| **Internet intel** | NVD / EPSS lookup URLs, per-source **Enable lookup**, optional API keys. **Ignore CVEs published before** (`INTEL_START_DATE`) applies to **every ingest path**: Local, SMB, Outlook/Exchange, ATOM, inline CVE, webhooks, and the Debugger. A CVE already stored can still be enriched by ID |
| **AI modules** | Global Enable / Disable (`AI_ENABLED`). When on, pick one provider (Gemini, ChatGPT, Azure OpenAI, GitHub Copilot) and a mode (see below) |
| **Inventory** | CMDB / ITNM teach Internal systems on a schedule (typically 24 hours, new equipment only). Sonatype IQ also harvests on Enable save (apps + libraries from the latest report). They are not pipeline steps. Matching always reads the local catalog (`INVENTORY_SYNC_ENABLED` defaults off until a live host exists) |
| **Ticketing** | Separate Enable for Jira, Monday.com, Email (SMTP), Internal CRM. Hunt **Permanent email**; fallback owner email only when Internal systems `owner_email` is blank. Optional **Allowed recipient domains** (blank = any domain) |
| **Message** | Owner and hunt subject/body templates (`{{cve_id}}`, `{{summary}}`, …). Used even when AI is off |

### AI modes (only when AI is enabled)

| Mode | Enrichment | Extract / Match |
|------|-----------|-----------------|
| **EVulnTasker AI** | After NVD/EPSS, the selected provider may rewrite the owner-facing description and fill missing vendor/product | LLM fallback still allowed |
| **Org LLM only** | No rewrite inside EVulnTasker; NVD/ingest wording is kept | Extract/match LLM still allowed |

**Disable** on the same tab turns off **all** LLM calls. Tickets still open from Ticketing + Message.

---

## Ingest details

| Source | Notes |
|-------|--------|
| **Local folder** | Path on the EVulnTasker **Linux host**, not on the analyst PC. Must sit under an allowed inbox root (`/tmp`, `/var/evulntasker`, `/opt/evulntasker/inbox`, `data/inbox`, plus `EVULNTASKER_LOCAL_INGEST_ALLOW`). `.txt`, HTML, CSV, JSON, logs. Each file is kept as an Extraction ingest event, including files that add only one new CVE or whose IDs were already known. Subject to `INTEL_START_DATE` |
| **SMB / CIFS** | One or more locations, shared AD/LDAP account. Subject to `INTEL_START_DATE` |
| **Outlook / Exchange** | On-prem unread mail scanned for CVE IDs. Subject to `INTEL_START_DATE` |
| **ATOM / RSS** | Seeded on install (CISA, Ubuntu, Microsoft MSRC, Exploit-DB). Subject to `INTEL_START_DATE` |

`POST /api/webhooks/{token}` still exists in the API. There is **no** webhook Settings UI; leftover webhook source rows are cleaned up.

---

## Architecture

Single Linux process (systemd unit `evulntasker`):

- FastAPI HTTP API + Jinja2 UI
- In-process asyncio pipeline worker (events persisted first, then drained)
- APScheduler for Local / SMB / Outlook / ATOM polling, and for Internal systems sampling when inventory sync is enabled

Optional: Celery + Redis for multi-node workers (not required on a single host).

Data store: **SQLite** for first install, **PostgreSQL** for production (`Settings → Database`).

If a ticketing provider is enabled but not configured, that provider stores a **dry-run** ticket (pipeline still completes). Missing AI keys are not dry-run — the LLM is simply skipped.

### Application packages (`app/`)

| Package | Responsibility |
|---------|----------------|
| `app.main` | FastAPI app, lifespan |
| `app.config` | `.env` settings |
| `app.web` | HTML pages, CSS, JavaScript |
| `app.api` | REST: dashboard, pipeline queues, inventory, sources, settings, debug |
| `app.pipeline` | Five-step orchestrator |
| `app.integrations` | NVD, EPSS, ticketing (Jira / Monday / mail / CRM), Exchange, SMB, SMTP, Gmail, SIEM, AI |
| `app.services` | Ingestion, intel sources, ATOM catalog, mail templates, DB settings |
| `app.workers` | asyncio queue, APScheduler, optional Celery |
| `app.models` / `app.schemas` / `app.utils` | ORM, API contracts, CVE regex and intel window |

---

## Repository layout

```
.
├── app.py                      # Dev launcher: python3 app.py
├── app/                        # Python package
├── alembic/                    # DB migrations
├── systemd/evulntasker.service  # systemd unit template
├── scripts/                    # Install helpers and integration CLIs
├── tests/
├── requirements.txt
├── requirements.lock.txt
├── .env.example
├── EVulnTasker-ICON.png
├── package_offline.sh
├── setup.sh                    # Install / upgrade (default /opt/evulntasker)
├── uninstall.sh
├── README.md
├── FUNCTIONALITY.md
├── GAPS.md                     # Remaining work
└── PT-RISK-SURVEY.md           # Lab risk survey (HTTP :8080)
```

Do **not** commit `venv/`, `.env`, `data/`, `logs/`, or `vendor/wheels/`.

---

## Configuration

Copy `.env.example` to `.env` (or let `setup.sh` do it). Most operator knobs are also saved from Settings. Runtime keys use `EVULNTASKER_*`; `VULNINTEL_*` from older installs is still read.

| Variable | Purpose |
|----------|---------|
| `EVULNTASKER_ENV` | `development` / `staging` / `production` (production hides `/docs`) |
| `EVULNTASKER_HOST` / `EVULNTASKER_PORT` | Bind address (default `0.0.0.0:8080`, HTTP) |
| `EVULNTASKER_BASIC_AUTH_USER` / `EVULNTASKER_BASIC_AUTH_PASSWORD` | Optional HTTP Basic. Blank = open UI. `/healthz` and `/api/webhooks/{token}` stay open |
| `EVULNTASKER_LOCAL_INGEST_ALLOW` | Extra Local-folder roots (comma-separated). Defaults already include `/tmp` and `/var/evulntasker` |
| `EVULNTASKER_DATABASE_URL` | SQLite or `postgresql+psycopg2://…` |
| `ENRICHMENT_ENABLED` | Off = skip NVD/EPSS and AI rewrite; still match and act |
| `INTEL_START_DATE` | Skip ingest for CVEs before this date (YYYY-MM-DD). Applies to Local, SMB, mail, ATOM, inline, webhooks, and Debugger |
| `NVD_ENABLED` / `EPSS_ENABLED` | Lookup switches (also per-row Enable lookup in the GUI) |
| `NVD_API_KEY` | Optional; raises NVD rate limits |
| `AI_ENABLED` | Global LLM gate |
| `AI_PROVIDER` | `gemini` / `chatgpt` / `azure_openai` / `github_copilot` |
| `AI_ENRICHMENT_MODE` | `direct` (EVulnTasker AI) or `org_llm` |
| `AI_API_KEY` / `AI_API_BASE` / `AI_MODEL` | Selected provider |
| `TICKETING_JIRA_ENABLED` / `_MONDAY_` / `_EMAIL_` / `_CUSTOM_` | Per-provider Enable |
| `SMTP_RELAY_*` | Settings → Ticketing → Email |
| `TICKETING_HUNT_EMAIL` | Permanent hunt mailbox (blank = skip) |
| `TICKETING_FALLBACK_OWNER_EMAIL` | Only if the matched system has no `owner_email` |
| `TICKETING_EMAIL_DOMAINS` | Comma-separated domains allowed for owner/hunt mail (blank = any) |
| `JIRA_*` / `MONDAY_*` / `CUSTOM_*` | Provider endpoints and projects |
| `EXCHANGE_*` | Outlook ingest (also stored on the Outlook source) |
| `CMDB_*` / `SONATYPE_*` / `ITNM_*` | Inventory teachers: sample the network and insert new equipment into Internal systems. Not used per CVE |
| `INVENTORY_SYNC_ENABLED` / `INVENTORY_SYNC_SECONDS` | Periodic catalog sampling (default off; interval 24 hours). Independent of the CVE pipeline |
| `GMAIL_*` | Optional Act HTML mail (not on the Settings form) |
| `CELERY_BROKER_URL` | Optional; default worker is in-process |

---

## Tests

```bash
source venv/bin/activate
pytest
```

On a host whose system Python cannot import the venv wheels (for example 3.14 vs 3.12), run pytest with that venv’s interpreter.

---

## Remaining work

See [`GAPS.md`](GAPS.md). This phase stays on **HTTP :8080** (no TLS). For a host that is more than a closed lab, set `EVULNTASKER_BASIC_AUTH_USER` / `EVULNTASKER_BASIC_AUTH_PASSWORD` and do **not** pass `--open-firewall` unless that prompt is on. A full login page and roles are still outstanding.

---

## License

Use and redistribute according to your organization's policy. Add a `LICENSE` file before publishing if you intend an open-source release. Third-party packages keep their own licenses (table above).
