# EVulnTasker v1.0 Beta

**Elizarov Vulnrabilities Tasking Manager Platform**

AI-Powered RBVM — Risk-Based Vulnerability Management for Linux (RHEL / Ubuntu).

EVulnTasker ingests CVE intelligence from files, mail, and ATOM feeds, extracts identifiers, optionally enriches from NVD/EPSS, matches vendor/product against a local Internal systems catalog, and opens owner and threat-hunting tasks (Jira, Monday.com, email, or an internal CRM). Sigma rules and SIEM hunting queries are generated in the same Act step.

The user interface is **English only**. There is no login.

Default URL after start: `http://127.0.0.1:8080` (service bind `0.0.0.0:8080`).

A Hebrew module catalog lives in [`FUNCTIONALITY.md`](FUNCTIONALITY.md). Remaining work is listed in [`GAPS.md`](GAPS.md).

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

CVE detail (`/vulnerabilities/{cve_id}`): description, matches, tickets, hunting pack, audit trail, **Re-run pipeline**.

Health check: `GET /healthz`.

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
| **Ticketing** | Separate Enable for Jira, Monday.com, Email (SMTP), Internal CRM. Hunt **Permanent email**; fallback owner email only when Internal systems `owner_email` is blank |
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
| **Local folder** | Path on the EVulnTasker **Linux host**, not on the analyst PC. `.txt`, HTML, CSV, JSON, logs. Each file is kept as an Extraction ingest event, including files that add only one new CVE or whose IDs were already known. Subject to `INTEL_START_DATE` |
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

---

## Python stack

Requires **Python 3.11+** (3.12 / 3.13 / 3.14 are supported; `psycopg2-binary` is skipped on 3.14).

### Third-party packages (`requirements.txt`)

| Package | Role |
|---------|------|
| **FastAPI** / **Uvicorn** / **Starlette** | HTTP API and ASGI server |
| **Jinja2** / **python-multipart** | HTML UI and forms |
| **orjson** | Fast JSON |
| **Pydantic** / **pydantic-settings** | Validation and `.env` |
| **SQLAlchemy 2** / **Alembic** | ORM and migrations |
| **psycopg2-binary** | PostgreSQL (Python &lt; 3.14) |
| **httpx** / **aiohttp** | NVD, EPSS, Jira, Monday, AI, inventory APIs |
| **APScheduler** | Timed polling |
| **exchangelib** | Exchange / Outlook |
| **aiosmtplib** | SMTP mail relay |
| **smbprotocol** | SMB/CIFS |
| **python-dateutil** / **tenacity** / **structlog** | Dates, NVD/EPSS retries, structured logs |
| **Celery** + **Redis** | Optional distributed workers |
| **pytest** / **pytest-asyncio** | Tests |

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
└── GAPS.md                     # Remaining work
```

Do **not** commit `venv/`, `.env`, `data/`, `logs/`, or `vendor/wheels/`.

---

## Quick start (development)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 app.py
```

Then open `http://127.0.0.1:8080`.

Typical first-run path:

1. **Internal systems** — add products or import CSV (`/api/inventory/template.csv`). CMDB / Sonatype / ITNM are optional later teachers, not required for matching.
2. **Settings → Feeds → Local** — folder on this server. Enable the feed on **Input Sources**, then Sync now (or drop a `.txt` with `CVE-YYYY-NNNNN`).
3. **Settings → Enrichment** — Enable only if NVD/EPSS should run; turn lookup sources on under **Internet intel**.
4. **Settings → AI modules** — Disable if the organization must not call an LLM.
5. **Settings → Ticketing** — Enable Jira / Monday / Email / CRM as needed. Edit **Message** templates.
6. Watch **Extraction → Incoming CVEs → Status → Actions**.

Health: `GET /healthz`.

---

## Production install (Linux)

Default install path: **`/opt/evulntasker`**. A systemd unit named **`evulntasker`** is enabled.

### Online

```bash
sudo ./setup.sh
```

### Offline (air-gapped)

On a machine with internet:

```bash
./package_offline.sh
```

Copy `dist/EVulnTasker-offline-*.zip` to the target, unzip, then:

```bash
sudo ./setup.sh --offline
```

### Upgrade (keeps the existing database)

```bash
sudo ./setup.sh --offline --upgrade
```

Schema changes are applied additively (`create_all` / Alembic). Existing rows are not wiped. A DB backup is taken first.

After changing Python under `app/`, restart:

```bash
sudo systemctl restart evulntasker
```

Static JS/CSS is cache-busted; use a hard refresh (Ctrl+Shift+R) after UI changes.

### Service

```bash
sudo systemctl start evulntasker
sudo systemctl stop evulntasker
sudo systemctl restart evulntasker
sudo systemctl status evulntasker
sudo journalctl -u evulntasker -f
```

### Uninstall

```bash
sudo ./uninstall.sh --yes
```

Removes the application and the `evulntasker` unit (also stops leftover `vaict` / `vulnintel` units if present). A copy of the database — including the Internal systems catalog — is left under `/var/backups/evulntasker`. `.env` secrets (including `GMAIL_APP_PASSWORD`) are wiped and are not in that backup.

---

## Remaining work

See [`GAPS.md`](GAPS.md). Highest priority: login if the port is exposed beyond a lab.

## Configuration

Copy `.env.example` to `.env`. Most operator knobs are also saved from Settings. Runtime keys use `EVULNTASKER_*`; `VULNINTEL_*` from older installs is still read.

| Variable | Purpose |
|----------|---------|
| `EVULNTASKER_ENV` | `development` / `staging` / `production` |
| `EVULNTASKER_HOST` / `EVULNTASKER_PORT` | Bind address (default `0.0.0.0:8080`) |
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

## License

Use and redistribute according to your organization's policy. Add a `LICENSE` file before publishing if you intend an open-source release.
