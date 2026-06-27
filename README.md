# VulnVision

**Enterprise Cybersecurity Intelligence Platform**

VulnVision is a production-grade network vulnerability scanning and security assessment platform built with Python, Flask, and SQLAlchemy. It performs automated host discovery, port scanning, service detection, OS fingerprinting, and vulnerability analysis with a full-featured web dashboard.

---

## Features

- **Network Scanning** — Discover hosts via ARP, ICMP, and TCP probes across CIDR ranges, IP ranges, and single targets
- **Port Scanning** — Concurrent TCP connect scanning with configurable port ranges (default, full 1-65535, or custom)
- **Service Detection** — Identify services by port mapping and banner fingerprinting (SSH, HTTP, FTP, MySQL, PostgreSQL, etc.)
- **OS Fingerprinting** — Estimate operating systems from port signatures, banners, and TTL analysis
- **Vulnerability Detection** — 7 detection modules covering Telnet, FTP, SMB, weak services, HTTP headers, admin panels, and insecure protocols
- **Exploitability Analysis** — Composite risk scoring combining severity, exposure, reachability, and attack surface
- **Attack Path Generation** — Graph-based attack chain analysis identifying multi-step compromise paths
- **Security Debt Tracking** — Quantified debt scoring across vulnerability, legacy service, exposure, and configuration dimensions
- **Remediation Engine** — Prioritized remediation recommendations with fix guidance, effort estimates, and risk reduction metrics
- **Report Generation** — PDF, CSV, and JSON report formats with executive summaries and technical details
- **Enterprise Dashboard** — Dark-themed web interface with real-time scan progress, severity charts, and filterable data tables

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12+, Flask 3.x |
| Database | SQLite via SQLAlchemy 2.x |
| Frontend | Jinja2 Templates, Chart.js 4, Vanilla CSS |
| Scanning | Socket, Subprocess, Scapy (optional) |
| Concurrency | concurrent.futures.ThreadPoolExecutor |
| Reports | ReportLab (PDF), CSV, JSON |
| Server | Waitress (Windows) / Gunicorn (Linux) |

---

## Installation

### 1. Clone the repository

```bash
git clone <repository-url>
cd VulnVision
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize the database

```bash
python -c "from backend.app import create_app; app = create_app(); print('Database initialized')"
```

### 5. Run the application

```bash
python run.py
```

The application will be available at `http://localhost:5000`.

---

## Project Structure

```
VulnVision/
├── backend/
│   ├── api/                    # REST API blueprints
│   │   ├── dashboard.py        # Page routes (SSR)
│   │   ├── scans.py            # Scan management API
│   │   ├── hosts.py            # Host management API
│   │   ├── vulnerabilities.py  # Vulnerability management API
│   │   ├── attack_paths.py     # Attack path API
│   │   ├── security_debt.py    # Security debt API
│   │   ├── reports.py          # Report generation API
│   │   └── remediation.py      # Remediation API
│   ├── models/                 # SQLAlchemy models
│   │   ├── base.py             # DB instance, TimestampMixin, SerializeMixin
│   │   ├── scan.py             # Scan model
│   │   ├── host.py             # Host model
│   │   ├── port.py             # Port model
│   │   ├── vulnerability.py    # Vulnerability model
│   │   ├── attack_path.py      # Attack path model
│   │   ├── security_debt.py    # Security debt model
│   │   ├── report.py           # Report model
│   │   └── audit_log.py        # Audit log model
│   ├── repositories/           # Data access layer
│   ├── services/               # Business logic
│   │   ├── scanner/            # Network scanning engine
│   │   ├── vulnerability/      # Vulnerability detection
│   │   ├── attack_path/        # Attack path generation
│   │   ├── security_debt/      # Security debt calculation
│   │   ├── remediation/        # Remediation recommendations
│   │   └── reporting/          # Report generation (PDF/CSV/JSON)
│   ├── middleware/             # Error handling middleware
│   ├── utils/                  # Logging, exceptions
│   ├── app.py                  # Flask application factory
│   └── config.py               # Configuration management
├── frontend/
│   ├── templates/              # Jinja2 HTML templates
│   └── static/
│       ├── css/main.css        # Full design system
│       ├── js/                 # Client-side JavaScript
│       └── img/                # SVG assets
├── database/                   # SQLite DB storage
├── tests/                      # Pytest test suite
├── requirements.txt            # Python dependencies
├── run.py                      # Application entry point
└── README.md
```

---

## API Endpoints

### Scans
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/scans/` | List all scans |
| `POST` | `/api/scans/` | Create and start a new scan |
| `GET` | `/api/scans/<scan_id>` | Get scan details |
| `DELETE` | `/api/scans/<scan_id>` | Delete/cancel a scan |
| `GET` | `/api/scans/<scan_id>/hosts` | Get hosts for a scan |
| `GET` | `/api/scans/<scan_id>/vulnerabilities` | Get vulnerabilities for a scan |
| `GET` | `/api/scans/statistics` | Aggregated scan statistics |

### Hosts
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/hosts/` | List all hosts |
| `GET` | `/api/hosts/<host_id>` | Get host details with ports and vulns |
| `GET` | `/api/hosts/<host_id>/ports` | Get ports for a host |
| `GET` | `/api/hosts/<host_id>/vulnerabilities` | Get vulnerabilities for a host |
| `GET` | `/api/hosts/statistics` | Host statistics |

### Vulnerabilities
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/vulnerabilities/` | List all vulnerabilities |
| `GET` | `/api/vulnerabilities/<vuln_id>` | Get vulnerability details |
| `PATCH` | `/api/vulnerabilities/<vuln_id>/status` | Update vulnerability status |
| `GET` | `/api/vulnerabilities/statistics` | Vulnerability statistics |
| `GET` | `/api/vulnerabilities/severity-distribution` | Severity distribution |

### Attack Paths
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/attack-paths/` | List attack paths |
| `POST` | `/api/attack-paths/generate` | Generate attack paths for a scan |
| `GET` | `/api/attack-paths/statistics` | Attack path statistics |

### Security Debt
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/security-debt/` | Latest security debt |
| `GET` | `/api/security-debt/history` | Debt history |
| `GET` | `/api/security-debt/trend` | Debt trend data |
| `POST` | `/api/security-debt/calculate` | Calculate debt for a scan |

### Reports
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/reports/` | List all reports |
| `POST` | `/api/reports/` | Generate a new report |
| `GET` | `/api/reports/<report_id>/download` | Download a report file |
| `DELETE` | `/api/reports/<report_id>` | Delete a report |

### Remediation
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/remediation/` | Get remediation recommendations |
| `POST` | `/api/remediation/generate` | Generate recommendations |
| `GET` | `/api/remediation/priorities` | Prioritized remediation list |

---

## Running Tests

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ -v --cov=backend --cov-report=term-missing
```

---

## Configuration

Configuration is managed via environment variables:

| Variable | Default | Description |
|---|---|---|
| `VULNVISION_ENV` | `development` | Environment: development, production, testing |
| `VULNVISION_SECRET_KEY` | (dev key) | Flask secret key |
| `VULNVISION_PORT` | `5000` | Server port |
| `DATABASE_URL` | `sqlite:///database/vulnvision.db` | Database connection string |
| `LOG_LEVEL` | `INFO` | Logging level |
| `SCANNER_MAX_THREADS` | `50` | Max concurrent scan threads |
| `SCANNER_TIMEOUT` | `5` | Socket timeout in seconds |
| `REPORT_COMPANY` | `VulnVision Security` | Company name for reports |

---
## Note

This project is under active development. Some features may be incomplete or behave unexpectedly, and bugs may be present. Feedback and contributions are welcome.

## License

MIT License
