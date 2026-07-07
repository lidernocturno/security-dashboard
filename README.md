# VPS Security Dashboard

Real-time security monitoring dashboard for Linux VPS servers. Built to monitor attack attempts, track threat actors geographically, and audit server security configuration continuously.

## What it does

- **Live attack map** — visualizes SSH brute force, credential stuffing, and web scanning attempts in real time, geo-located by IP using CrowdSec + GeoIP
- **Security audit** — runs every hour, checks SSH hardening, UFW port exposure, Docker containers, immutable files, and unauthorized users
- **File watcher** — monitors critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) for unauthorized changes
- **Telegram alerts** — sends instant notifications when misconfigurations or intrusions are detected
- **Attack analysis** — classifies attack techniques (SSH brute force, user enumeration, credential stuffing, web scanning) with explanations and defenses

## Stack

- **CrowdSec** — community threat intelligence, firewall bouncer
- **fail2ban** — SSH jail, automated IP banning
- **GeoLite2** — IP geolocation (City + ASN databases)
- **Python 3** — data collection, audit scripts, Telegram bot
- **Vanilla HTML/CSS/JS + Chart.js + Leaflet** — dashboard UI (no build step required)
- **UFW** — Linux firewall, Tailscale-aware rule checking

## Scripts

| Script | Frequency | Description |
|--------|-----------|-------------|
| `collect_data.py` | Every 5 min | Parses CrowdSec, fail2ban, auth.log → outputs `attacks.json` |
| `security_audit.py` | Every hour | Proactive config checker, alerts on issues |
| `file_watcher.py` | Every 5 min | Monitors critical files for unauthorized modifications |
| `resource_monitor.py` | Every 5 min | CPU, RAM, disk — alerts on thresholds |
| `telegram_report.py` | Daily | Sends security summary report |
| `telegram_commands.py` | On demand | Telegram bot for querying status |
| `backup_general.py` | Daily | Backs up configs and sends via Telegram |

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/lidernocturno/security-dashboard
cd security-dashboard

# 2. Install dependencies
pip install geoip2 python-telegram-bot

# 3. Configure environment variables
export BOT_TOKEN="your_telegram_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
export VPS_PUBLIC_IP="your.vps.ip"
export VPS_LAT="your_lat"
export VPS_LON="your_lon"

# 4. Install CrowdSec + fail2ban (required)
# https://docs.crowdsec.net/docs/getting_started/install_crowdsec/
# sudo apt install fail2ban

# 5. Add crons
crontab -e
# */5 * * * * python3 /path/to/scripts/collect_data.py
# 0 * * * * python3 /path/to/scripts/security_audit.py
# */5 * * * * python3 /path/to/scripts/file_watcher.py
# */5 * * * * python3 /path/to/scripts/resource_monitor.py

# 6. Serve the dashboard
python3 server.py  # serves on :8088 by default
```

## Dashboard features

- **Attack heatmap** — world map with animated attack origins
- **Country ranking** — top attacking countries with flag emojis
- **Attack techniques** — breakdown of methods with explanations
- **Ban list** — IP addresses currently banned by fail2ban
- **Attempt log** — recent SSH/web attack attempts

## Context

This dashboard was built to monitor a production Linux VPS running multiple services (N8N, AI agents, web apps). The server receives thousands of attack attempts per day — this tool makes that visible and actionable.

---

**Author:** [lidernocturno.dev](https://lidernocturno.dev) — Independent security consultant, Mexico City
