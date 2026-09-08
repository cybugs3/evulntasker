# EVulnTasker v1.0 Beta

**Elizarov Vulnrabilities Tasking Manager Platform**

AI-Powered RBVM — Risk-Based Vulnerability Management platform for Linux (RHEL / Ubuntu).

EVulnTasker ingests CVE intelligence, enriches it, matches it to organizational assets, and opens owner and threat-hunting tasks — including Sigma rules and SIEM hunting queries.

The user interface is **English only**.

---

## What it does

| Step | Name | Description |
|------|------|-------------|
| 1 | **Ingest** | Webhooks, scheduled API feeds, Exchange mailbox, SMB/CIFS file share |
| 2 | **Extract** | CVE regex plus vendor / product / version from labeled text, CSV, JSON, or CPE |
| 3 | **Enrich** | NVD 2.0 (CVSS, CWE, attack vector) + FIRST EPSS; AI fills remaining gaps |
| 4 | **Match** | CMDB, Sonatype, and local inventory; AI ownership fallback |
| 5 | **Act** | Jira tasks for owners and hunters, Exchange mail, DB status |

If Jira, Exchange, or AI keys are not configured, the pipeline still completes in **dry-run** mode (no credentials required for demos).

---

## Screens

- **Dashboard** — CVE queue, severity, pipeline status
- **Input Sources** — webhooks, API feeds, mailbox listeners
- **Repositories** — NVD, EPSS, and other intelligence feeds
- **Settings** — system database (SQLite, local PostgreSQL on this Linux host, or external PostgreSQL) plus SMB/CIFS, local folder, Outlook, and Web API sources
- **Vulnerability detail** — enrichment, asset matches, tickets, detections

Default URL after start: `http://127.0.0.1:8080`

---

## Architecture

Single Linux process (systemd unit `evulntasker`):

- FastAPI HTTP API + Jinja2 dashboard
- In-process asyncio pipeline worker
- APScheduler for feed / mailbox polling

Optional: Celery + Redis for multi-node workers (not required for a single host).

Data store: **SQLite** for development and first install, **PostgreSQL** for production.

---

## Python stack

Requires **Python 3.11+** (3.12 / 3.13 / 3.14 are supported).

### Standard library

| Module | Used for |
|--------|---------|
| `asyncio` | In-process work queue |
| `logging` / `logging.handlers` | journald + rotating file logs |
| `pathlib` | Paths for data, logs, static files |
| `json` | Webhook / AI payloads |
| `re` | CVE identifier extraction (`CVE-YYYY-NNNNN`) |
| `secrets` | Webhook tokens |
| `datetime` | Timestamps (UTC) |
| `functools` | Cached settings (`lru_cache`) |
| `dataclasses` | Extraction results |
| `contextlib` | FastAPI lifespan |
| `typing` / `collections.abc` | Type hints |
| `importlib.util` | `app.py` launcher (loads the `app/` package) |
| `socket` | LAN URL printed at startup |
| `os`, `sys` | Process / venv launcher |

### Third-party packages (`requirements.txt`)

| Package | Role |
|---------|--------|
| **FastAPI** | REST API and application framework |
| **Uvicorn** | ASGI server |
| **Starlette** | HTTP primitives (via FastAPI) |
| **Jinja2** | HTML dashboard templates |
| **python-multipart** | Form / multipart parsing |
| **orjson** | Fast JSON |
| **Pydantic** / **pydantic-settings** | Validation and `.env` configuration |
| **SQLAlchemy 2** | ORM (SQLite / PostgreSQL) |
| **Alembic** | Schema migrations |
| **psycopg2-binary** | PostgreSQL driver (Python &lt; 3.14) |
| **greenlet** | SQLAlchemy async-friendly greenlets |
| **httpx** | NVD, EPSS, Jira, CMDB, Sonatype, AI HTTP clients |
| **aiohttp** | Async HTTP (feeds / workers) |
| **APScheduler** | Timed polling of API feeds and Exchange |
| **exchangelib** | Microsoft Exchange / Outlook |
| **smbprotocol** | SMB/CIFS file share (AD/LDAP credentials) |
| **python-dateutil** | Date parsing |
| **tenacity** | Retries for NVD / EPSS |
| **structlog** | Structured logging helpers |
| **Celery** + **Redis** | Optional distributed workers |
| **pytest** / **pytest-asyncio** | Tests |

### Built-in application modules (`app/`)

| Package | Responsibility |
|---------|--------------|
| `app.main` | FastAPI app, HTML routes, lifespan |
| `app.config` | Environment / `.env` settings |
| `app.logging_conf` | Logging to stderr and rotating files |
| `app.db.session` | SQLAlchemy engine and sessions |
| `app.models` | ORM: CVE, assets, sources, Jira, detections, pipeline |
| `app.schemas` | API contracts |
| `app.api` | REST: dashboard, sources, repositories, webhooks, vulnerabilities |
| `app.pipeline` | Five-step orchestrator |
| `app.integrations.nvd` | National Vulnerability Database 2.0 |
| `app.integrations.epss` | FIRST Exploit Prediction Scoring System |
| `app.integrations.jira` | Jira Cloud / Server |
| `app.integrations.exchange` | Exchange mailbox |
| `app.integrations.cmdb` | CMDB asset lookup |
| `app.integrations.sonatype` | Sonatype IQ / Nexus |
| `app.integrations.ai_copilot` | OpenAI-compatible LLM fallback |
| `app.integrations.siem` | Sigma + KQL / XQL / AQK / EKQL templates |
| `app.workers.queue` | asyncio queue |
| `app.workers.scheduler` | APScheduler jobs |
| `app.workers.celery_app` | Optional Celery app |
| `app.services` | Ingestion + first-run seed |
| `app.utils.cve` | CVE regex and CVSS helpers |
| `app.web` | Templates, CSS, JavaScript |

---

## Repository layout

```
.
├── app.py                    # Dev launcher: python3 app.py
├── app/                      # Python package
├── alembic/                  # DB migrations
├── systemd/evulntasker.service     # systemd unit template
├── scripts/                  # Shared install helpers
├── tests/
├── requirements.txt
├── .env.example
├── EVulnTasker-ICON.png            # Brand icon (served as favicon / sidebar)
├── package_offline.sh       # Build offline ZIP (wheels included)
├── setup.sh                 # Install / upgrade (default prefix /opt/evulntasker)
├── uninstall.sh              # Remove install; keep a DB backup
└── README.md
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

Sample webhook (copy the token from **Input Sources**):

```bash
curl -X POST http://127.0.0.1:8080/api/webhooks/<token> \
  -H 'Content-Type: application/json' \
  -d '{"cve_id":"CVE-2021-44228","summary":"Log4Shell"}'
```

Health check: `GET /healthz`

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

Removes the application and the `evulntasker` unit. A copy of the database is left under `/var/backups/evulntasker`.

---

## Configuration

Copy `.env.example` to `.env`. Variables include:

| Variable | Purpose |
|----------|---------|
| `VULNINTEL_ENV` | `development` / `staging` / `production` |
| `VULNINTEL_HOST` / `VULNINTEL_PORT` | Bind address (default `0.0.0.0:8080`) |
| `VULNINTEL_DATABASE_URL` | SQLite or `postgresql+psycopg2://…` |
| `NVD_API_KEY` | Optional; raises NVD rate limits |
| `JIRA_*` | Jira project for owners and hunting |
| `EXCHANGE_*` | Mailbox listener |
| `CMDB_*` / `SONATYPE_*` | Asset matching |
| `AI_API_KEY` / `AI_MODEL` | OpenAI-compatible copilot |

---

## Tests

```bash
source venv/bin/activate
pytest
```

---

## License

Use and redistribute according to your organization's policy. Add a `LICENSE` file before publishing if you intend an open-source release.
