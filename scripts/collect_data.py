#!/usr/bin/env python3
"""
VPS Security Dashboard - Data Collector
Collects attack data from CrowdSec, fail2ban, auth.log, and GeoIP.
Outputs JSON for the dashboard to consume.
"""

import json
import subprocess
import re
import os
import sys
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from pathlib import Path

# Paths
GEOIP_DB = "/var/lib/crowdsec/data/GeoLite2-City.mmdb"
ASN_DB = "/var/lib/crowdsec/data/GeoLite2-ASN.mmdb"
OUTPUT_DIR = Path("/home/your_user/security-dashboard/data")
OUTPUT_FILE = OUTPUT_DIR / "attacks.json"
HISTORY_FILE = OUTPUT_DIR / "attack_history.json"  # Persistent history — never loses data

# VPS location (Hostinger, Boston, US)
VPS_LAT = float(os.environ.get("VPS_LAT", "0"))
VPS_LON = float(os.environ.get("VPS_LON", "0"))
VPS_IP = os.environ.get("VPS_PUBLIC_IP", "0.0.0.0")

# Country code to flag emoji mapping
def cc_to_flag(cc):
    if not cc or len(cc) != 2:
        return "🏴"
    return chr(0x1F1E6 + ord(cc[0]) - ord('A')) + chr(0x1F1E6 + ord(cc[1]) - ord('A'))

# Country code to name
COUNTRY_NAMES = {
    "CN": "China", "RU": "Russia", "US": "United States", "BR": "Brazil",
    "KR": "South Korea", "IN": "India", "VN": "Vietnam", "ID": "Indonesia",
    "DE": "Germany", "FR": "France", "NL": "Netherlands", "GB": "United Kingdom",
    "JP": "Japan", "TW": "Taiwan", "HK": "Hong Kong", "SG": "Singapore",
    "TH": "Thailand", "PK": "Pakistan", "BD": "Bangladesh", "IR": "Iran",
    "UA": "Ukraine", "PL": "Poland", "RO": "Romania", "BG": "Bulgaria",
    "AR": "Argentina", "MX": "Mexico", "CO": "Colombia", "CL": "Chile",
    "CA": "Canada", "AU": "Australia", "ZA": "South Africa", "EG": "Egypt",
    "TR": "Turkey", "SA": "Saudi Arabia", "AE": "UAE", "IT": "Italy",
    "ES": "Spain", "PT": "Portugal", "SE": "Sweden", "NO": "Norway",
    "FI": "Finland", "DK": "Denmark", "CZ": "Czechia", "HU": "Hungary",
    "GR": "Greece", "IL": "Israel", "MY": "Malaysia", "PH": "Philippines",
    "BE": "Belgium", "IE": "Ireland", "CH": "Switzerland", "AT": "Austria",
    "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "RS": "Serbia",
    "HR": "Croatia", "SK": "Slovakia", "SI": "Slovenia", "MD": "Moldova",
    "BY": "Belarus", "GE": "Georgia", "KZ": "Kazakhstan", "UZ": "Uzbekistan",
    "NG": "Nigeria", "KE": "Kenya", "GH": "Ghana", "TZ": "Tanzania",
    "MA": "Morocco", "TN": "Tunisia", "DZ": "Algeria", "ET": "Ethiopia",
    "PE": "Peru", "EC": "Ecuador", "VE": "Venezuela", "BO": "Bolivia",
    "UY": "Uruguay", "PY": "Paraguay", "CR": "Costa Rica", "PA": "Panama",
    "DO": "Dominican Republic", "GT": "Guatemala", "HN": "Honduras",
    "NP": "Nepal", "LK": "Sri Lanka", "MM": "Myanmar", "KH": "Cambodia",
    "LA": "Laos", "MN": "Mongolia", "AF": "Afghanistan", "IQ": "Iraq",
    "SY": "Syria", "YE": "Yemen", "JO": "Jordan", "LB": "Lebanon",
    "OM": "Oman", "QA": "Qatar", "BH": "Bahrain", "KW": "Kuwait",
    "NZ": "New Zealand", "FJ": "Fiji",
}

def get_country_name(cc):
    return COUNTRY_NAMES.get(cc, cc or "Unknown")

# GeoIP lookup
try:
    import maxminddb
    geo_reader = maxminddb.open_database(GEOIP_DB)
    asn_reader = maxminddb.open_database(ASN_DB)
    HAS_GEOIP = True
except Exception:
    HAS_GEOIP = False
    geo_reader = None
    asn_reader = None

import ipaddress

# Tailscale CGNAT range: 100.x.x.x/10 (covers 100.64.x.x – 100.127.x.x)
_TAILSCALE_NET = ipaddress.ip_network("100.x.x.x/10")

def is_private_ip(ip_str):
    """Check if an IP is private/internal (Docker, LAN, loopback, Tailscale CGNAT)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip in _TAILSCALE_NET)
    except ValueError:
        return True

# Fallback country centroids — used when GeoIP DB lacks exact coords
COUNTRY_CENTROIDS = {
    "AF": (33.93, 67.71), "AL": (41.15, 20.17), "DZ": (28.03, 1.66),
    "AO": (-11.20, 17.87), "AR": (-38.42, -63.62), "AM": (40.07, 45.04),
    "AU": (-25.27, 133.78), "AT": (47.52, 14.55), "AZ": (40.14, 47.58),
    "BH": (26.00, 50.55), "BD": (23.68, 90.36), "BY": (53.71, 27.95),
    "BE": (50.50, 4.47), "BO": (-16.29, -63.59), "BA": (43.92, 17.68),
    "BR": (-14.24, -51.93), "BG": (42.73, 25.49), "KH": (12.57, 104.99),
    "CA": (56.13, -106.35), "CL": (-35.68, -71.54), "CN": (35.86, 104.20),
    "CO": (4.57, -74.30), "CR": (9.75, -83.75), "HR": (45.10, 15.20),
    "CZ": (49.82, 15.47), "DK": (56.26, 9.50), "DO": (18.74, -70.16),
    "EC": (-1.83, -78.18), "EG": (26.82, 30.80), "SV": (13.79, -88.90),
    "EE": (58.60, 25.01), "ET": (9.15, 40.49), "FI": (61.92, 25.75),
    "FR": (46.23, 2.21), "GE": (42.32, 43.36), "DE": (51.17, 10.45),
    "GH": (7.95, -1.02), "GR": (39.07, 21.82), "GT": (15.78, -90.23),
    "HN": (15.20, -86.24), "HK": (22.32, 114.17), "HU": (47.16, 19.50),
    "IN": (20.59, 78.96), "ID": (-0.79, 113.92), "IR": (32.43, 53.69),
    "IQ": (33.22, 43.68), "IE": (53.41, -8.24), "IL": (31.05, 34.85),
    "IT": (41.87, 12.57), "JP": (36.20, 138.25), "JO": (30.59, 36.24),
    "KZ": (48.02, 66.92), "KE": (-0.02, 37.91), "KR": (35.91, 127.77),
    "KW": (29.31, 47.48), "LA": (19.86, 102.50), "LV": (56.88, 24.60),
    "LB": (33.85, 35.86), "LT": (55.17, 23.88), "LU": (49.82, 6.13),
    "MY": (4.21, 108.00), "MX": (23.63, -102.55), "MD": (47.41, 28.37),
    "MN": (46.86, 103.85), "MA": (31.79, -7.09), "MZ": (-18.67, 35.53),
    "MM": (17.08, 96.19), "NP": (28.39, 84.12), "NL": (52.13, 5.29),
    "NZ": (-40.90, 174.89), "NG": (9.08, 8.68), "NO": (60.47, 8.47),
    "OM": (21.51, 55.92), "PK": (30.38, 69.35), "PS": (31.95, 35.23),
    "PA": (8.54, -80.78), "PY": (-23.44, -58.44), "PE": (-9.19, -75.02),
    "PH": (12.88, 121.77), "PL": (51.92, 19.15), "PT": (39.40, -8.22),
    "QA": (25.35, 51.18), "RO": (45.94, 24.97), "RU": (61.52, 105.32),
    "SA": (23.89, 45.08), "RS": (44.02, 21.01), "SG": (1.35, 103.82),
    "SK": (48.67, 19.70), "SI": (46.15, 14.99), "ZA": (-30.56, 22.94),
    "ES": (40.46, -3.75), "LK": (7.87, 80.77), "SE": (60.13, 18.64),
    "CH": (46.82, 8.23), "SY": (34.80, 38.99), "TW": (23.70, 120.96),
    "TZ": (-6.37, 34.89), "TH": (15.87, 100.99), "TN": (33.89, 9.54),
    "TR": (38.96, 35.24), "UA": (48.38, 31.17), "AE": (23.42, 53.85),
    "GB": (55.38, -3.44), "US": (37.09, -95.71), "UY": (-32.52, -55.77),
    "UZ": (41.38, 64.59), "VE": (6.42, -66.59), "VN": (14.06, 108.28),
    "YE": (15.55, 48.52), "ZW": (-19.02, 29.15),
}

def geoip_lookup(ip):
    """Look up GeoIP data for an IP address."""
    result = {"country": "??", "country_name": "Unknown", "city": "", "lat": 0, "lon": 0, "asn": "", "org": ""}
    if not HAS_GEOIP or not ip or is_private_ip(ip):
        return result
    try:
        data = geo_reader.get(ip)
        if data:
            cc = data.get("country", {}).get("iso_code", "??")
            result["country"] = cc
            result["country_name"] = get_country_name(cc)
            result["city"] = data.get("city", {}).get("names", {}).get("en", "")
            loc = data.get("location", {})
            lat = loc.get("latitude", 0)
            lon = loc.get("longitude", 0)
            # Use country centroid as fallback when DB lacks exact coords
            if (not lat and not lon) and cc in COUNTRY_CENTROIDS:
                lat, lon = COUNTRY_CENTROIDS[cc]
            result["lat"] = lat
            result["lon"] = lon
    except Exception:
        pass
    try:
        asn_data = asn_reader.get(ip)
        if asn_data:
            result["asn"] = f"AS{asn_data.get('autonomous_system_number', '')}"
            result["org"] = asn_data.get("autonomous_system_organization", "")
    except Exception:
        pass
    return result


def get_crowdsec_alerts():
    """Get CrowdSec alerts."""
    alerts = []
    try:
        output = subprocess.check_output(
            ["sudo", "cscli", "alerts", "list", "-l", "500", "-o", "json"],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        data = json.loads(output) if output.strip() else []
        for alert in data:
            source = alert.get("source", {})
            ip = source.get("ip", "")
            scenario = alert.get("scenario", "")
            created = alert.get("created_at", "")
            geo = geoip_lookup(ip)
            alerts.append({
                "ip": ip,
                "scenario": scenario,
                "timestamp": created,
                "source": "crowdsec",
                **geo
            })
    except Exception as e:
        print(f"CrowdSec alerts error: {e}", file=sys.stderr)
    return alerts


def get_crowdsec_decisions():
    """Get active CrowdSec decisions (bans)."""
    decisions = []
    try:
        output = subprocess.check_output(
            ["sudo", "cscli", "decisions", "list", "-l", "500", "-o", "json"],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        data = json.loads(output) if output.strip() else []
        if data is None:
            data = []
        for dec in data:
            ip = dec.get("value", "")
            scenario = dec.get("scenario", "")
            duration = dec.get("duration", "")
            geo = geoip_lookup(ip)
            decisions.append({
                "ip": ip,
                "scenario": scenario,
                "duration": duration,
                "source": "crowdsec",
                **geo
            })
    except Exception as e:
        print(f"CrowdSec decisions error: {e}", file=sys.stderr)
    return decisions


def get_fail2ban_data():
    """Get fail2ban banned IPs and stats."""
    result = {"currently_banned": 0, "total_banned": 0, "total_failed": 0, "banned_ips": []}
    try:
        output = subprocess.check_output(
            ["sudo", "fail2ban-client", "status", "sshd"],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        for line in output.split("\n"):
            if "Currently banned" in line:
                result["currently_banned"] = int(re.search(r'(\d+)', line).group(1))
            elif "Total banned" in line:
                result["total_banned"] = int(re.search(r'(\d+)', line).group(1))
            elif "Total failed" in line:
                result["total_failed"] = int(re.search(r'(\d+)', line).group(1))
            elif "Banned IP list" in line:
                ips = line.split(":", 1)[1].strip().split()
                for ip in ips:
                    ip = ip.strip()
                    if ip:
                        geo = geoip_lookup(ip)
                        result["banned_ips"].append({"ip": ip, **geo})
    except Exception as e:
        print(f"Fail2ban error: {e}", file=sys.stderr)
    return result


def parse_auth_log():
    """Parse auth.log for SSH failed attempts with timestamps."""
    attacks = []
    ip_attempts = Counter()
    user_attempts = Counter()
    hourly = defaultdict(int)
    methods = Counter()

    now = datetime.now()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_7d = now - timedelta(days=7)

    log_files = ["/var/log/auth.log", "/var/log/auth.log.1"]

    # Regex patterns - supports both ISO 8601 and classic syslog timestamps
    # ISO: 2026-03-01T00:00:37.242822+00:00
    # Classic: Mar  1 00:00:37
    ts_pattern = r'(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:\d{2}|\w+\s+\d+\s+[\d:]+)'

    failed_pass = re.compile(ts_pattern + r'\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)')
    invalid_user = re.compile(ts_pattern + r'\s+\S+\s+sshd\[\d+\]:\s+Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)')
    conn_closed = re.compile(ts_pattern + r'\s+\S+\s+sshd\[\d+\]:\s+Connection closed by (?:invalid user |authenticating user )?(\S+)?\s*(\d+\.\d+\.\d+\.\d+)')
    preauth_disconnect = re.compile(ts_pattern + r'\s+\S+\s+sshd\[\d+\]:\s+Disconnected from (?:invalid user |authenticating user )?(\S+)?\s*(\d+\.\d+\.\d+\.\d+).*\[preauth\]')

    for logfile in log_files:
        try:
            output = subprocess.check_output(
                ["sudo", "cat", logfile],
                stderr=subprocess.DEVNULL, timeout=10
            ).decode(errors='replace')
        except Exception:
            continue

        for line in output.split("\n"):
            ip = None
            user = None
            method = None

            m = failed_pass.search(line)
            if m:
                ts_str, user, ip = m.group(1), m.group(2), m.group(3)
                method = "SSH Brute Force (password)"

            if not ip:
                m = invalid_user.search(line)
                if m:
                    ts_str, user, ip = m.group(1), m.group(2), m.group(3)
                    method = "SSH Invalid User"

            if not ip:
                m = preauth_disconnect.search(line)
                if m:
                    ts_str, user, ip = m.group(1), m.group(2) or "unknown", m.group(3)
                    method = "SSH Pre-auth Disconnect"

            if not ip:
                m = conn_closed.search(line)
                if m:
                    ts_str, user, ip = m.group(1), m.group(2) or "unknown", m.group(3)
                    method = "SSH Connection Probe"

            if ip and method:
                # Skip private/Docker IPs (172.x, 10.x, 192.168.x, 127.x)
                if is_private_ip(ip):
                    continue

                # Parse timestamp - ISO 8601 or classic syslog
                try:
                    if 'T' in ts_str and '-' in ts_str[:4]:
                        # ISO 8601: 2026-03-01T00:00:37.242822+00:00
                        ts_clean = ts_str.split('.')[0] if '.' in ts_str else ts_str.split('+')[0]
                        ts = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
                    else:
                        # Classic: Mar  1 00:00:37
                        ts = datetime.strptime(f"{now.year} {ts_str}", "%Y %b %d %H:%M:%S")
                        if ts > now + timedelta(days=1):
                            ts = ts.replace(year=now.year - 1)
                except Exception:
                    ts = now

                ip_attempts[ip] += 1
                user_attempts[user] += 1
                methods[method] += 1
                hourly[ts.strftime("%Y-%m-%d %H:00")] += 1

                # Only keep last 7 days for detailed entries
                if ts >= cutoff_7d:
                    attacks.append({
                        "ip": ip,
                        "user": user,
                        "method": method,
                        "timestamp": ts.isoformat(),
                    })

    # GeoIP enrich top attackers
    top_ips = []
    for ip, count in ip_attempts.most_common():
        geo = geoip_lookup(ip)
        top_ips.append({
            "ip": ip,
            "attempts": count,
            "flag": cc_to_flag(geo["country"]),
            **geo
        })

    return {
        "attacks": attacks[-5000:],  # Last 5000 entries max
        "top_ips": top_ips,  # ALL IPs, no limit
        "top_users": [{"user": u, "attempts": c} for u, c in user_attempts.most_common()],
        "methods": [{"method": m, "count": c} for m, c in methods.most_common()],
        "hourly": [{"hour": h, "count": c} for h, c in sorted(hourly.items())[-72:]],
        "total_attempts": sum(ip_attempts.values()),
    }


def get_ufw_blocked():
    """Parse UFW logs for blocked connections.
    UFW BLOCK entries come from the kernel and land in syslog/kern.log,
    NOT in a systemd 'ufw' unit — so we read syslog directly.
    """
    blocked = Counter()
    port_scan = Counter()
    protocols = Counter()
    output = ""

    # Primary: syslog (kernel messages with UFW BLOCK go here on Ubuntu)
    for syslog in ["/var/log/syslog", "/var/log/kern.log"]:
        try:
            out = subprocess.check_output(
                ["sudo", "grep", "-h", "UFW BLOCK", syslog],
                stderr=subprocess.DEVNULL, timeout=15
            ).decode(errors='replace')
            if out.strip():
                output += out
                break
        except Exception:
            continue

    # Fallback: journalctl kernel messages
    if not output.strip():
        try:
            output = subprocess.check_output(
                ["sudo", "journalctl", "-k", "--since", "7 days ago", "--no-pager", "-q"],
                stderr=subprocess.DEVNULL, timeout=15
            ).decode(errors='replace')
        except Exception:
            output = ""

    re_src = re.compile(r'SRC=(\d+\.\d+\.\d+\.\d+)')
    re_dpt = re.compile(r'DPT=(\d+)')
    re_proto = re.compile(r'PROTO=(\w+)')
    for line in output.split("\n"):
        if "UFW BLOCK" not in line:
            continue
        m_src = re_src.search(line)
        m_dpt = re_dpt.search(line)
        m_proto = re_proto.search(line)
        if not (m_src and m_proto):
            continue
        ip = m_src.group(1)
        proto = m_proto.group(1)
        port = m_dpt.group(1) if m_dpt else "0"
        if is_private_ip(ip):
            continue
        blocked[ip] += 1
        port_scan[port] += 1
        protocols[proto] += 1

    top_blocked = []
    for ip, count in blocked.most_common(200):
        geo = geoip_lookup(ip)
        top_blocked.append({"ip": ip, "count": count, **geo})

    return {
        "blocked_ips": top_blocked,
        "targeted_ports": [{"port": p, "count": c, "service": get_service_name(p)} for p, c in port_scan.most_common(20)],
        "protocols": [{"proto": p, "count": c} for p, c in protocols.most_common()],
        "total_blocked": sum(blocked.values()),
    }


def get_service_name(port):
    """Map common ports to service names."""
    services = {
        "22": "SSH", "80": "HTTP", "443": "HTTPS", "21": "FTP", "23": "Telnet",
        "25": "SMTP", "53": "DNS", "110": "POP3", "143": "IMAP", "3306": "MySQL",
        "5432": "PostgreSQL", "3389": "RDP", "8080": "HTTP-Alt", "8443": "HTTPS-Alt",
        "445": "SMB", "139": "NetBIOS", "1433": "MSSQL", "6379": "Redis",
        "27017": "MongoDB", "9200": "Elasticsearch", "5900": "VNC",
        "2222": "SSH-Alt", "8888": "HTTP-Alt2", "50001": "AgentZero",
    }
    return services.get(str(port), f"Port {port}")


def get_system_stats():
    """Get current system stats."""
    stats = {}
    try:
        # Uptime
        with open("/proc/uptime") as f:
            uptime_sec = float(f.read().split()[0])
            days = int(uptime_sec // 86400)
            hours = int((uptime_sec % 86400) // 3600)
            stats["uptime"] = f"{days}d {hours}h"

        # Load average
        with open("/proc/loadavg") as f:
            stats["load"] = f.read().split()[:3]

        # Memory
        mem_output = subprocess.check_output(["free", "-m"], timeout=5).decode()
        for line in mem_output.split("\n"):
            if line.startswith("Mem:"):
                parts = line.split()
                stats["ram_total_mb"] = int(parts[1])
                stats["ram_used_mb"] = int(parts[2])
                stats["ram_percent"] = round(int(parts[2]) / int(parts[1]) * 100, 1)

        # Disk
        disk_output = subprocess.check_output(["df", "-h", "/"], timeout=5).decode()
        parts = disk_output.split("\n")[1].split()
        stats["disk_total"] = parts[1]
        stats["disk_used"] = parts[2]
        stats["disk_percent"] = parts[4]

        # Docker containers
        try:
            containers = subprocess.check_output(
                ["docker", "ps", "--format", "{{.Names}}:{{.Status}}"],
                timeout=5
            ).decode().strip().split("\n")
            stats["containers"] = [{"name": c.split(":")[0], "status": c.split(":", 1)[1]} for c in containers if c]
        except Exception:
            stats["containers"] = []

    except Exception as e:
        print(f"System stats error: {e}", file=sys.stderr)

    return stats


def get_attack_explanations():
    """Educational content about attack methods."""
    return [
        {
            "method": "SSH Brute Force",
            "icon": "🔑",
            "severity": "high",
            "description": "Automated password guessing attack against SSH service. Bots try thousands of username/password combinations.",
            "how_it_works": "Attackers use tools like Hydra, Medusa, or custom scripts to systematically try common passwords (root/123456, admin/admin, etc.) against SSH port 22.",
            "defense": "Fail2ban (active), CrowdSec (active), key-only auth, non-standard port",
            "learn_more": "https://attack.mitre.org/techniques/T1110/001/"
        },
        {
            "method": "Port Scanning",
            "icon": "🔍",
            "severity": "medium",
            "description": "Reconnaissance technique to discover open ports and running services on the server.",
            "how_it_works": "Tools like Nmap, Masscan, or ZMap send SYN/ACK packets to all 65535 ports looking for responses. Open ports reveal attack surface.",
            "defense": "UFW firewall (active), CrowdSec detection, Tailscale-only services",
            "learn_more": "https://attack.mitre.org/techniques/T1046/"
        },
        {
            "method": "SSH Invalid User",
            "icon": "👤",
            "severity": "medium",
            "description": "Attempting to log in with usernames that don't exist on the system. Part of user enumeration attacks.",
            "how_it_works": "Bots try common usernames (root, admin, ubuntu, test, oracle, postgres) to find valid accounts before brute forcing passwords.",
            "defense": "Fail2ban bans after 5 attempts, CrowdSec community blocklists",
            "learn_more": "https://attack.mitre.org/techniques/T1078/"
        },
        {
            "method": "SSH Pre-auth Disconnect",
            "icon": "🔌",
            "severity": "low",
            "description": "Connection drops before authentication completes. Often automated scanning or vulnerability probing.",
            "how_it_works": "Bots connect to SSH, grab the banner (version info), then disconnect. Used to fingerprint SSH versions and check for CVEs like regreSSHion (CVE-2024-6387).",
            "defense": "CrowdSec ssh-cve-2024-6387 scenario (active), keep OpenSSH updated",
            "learn_more": "https://attack.mitre.org/techniques/T1595/002/"
        },
        {
            "method": "HTTP Exploit Scanning",
            "icon": "🌐",
            "severity": "high",
            "description": "Automated scans looking for vulnerable web applications, APIs, and known CVEs.",
            "how_it_works": "Bots scan for common paths (/wp-admin, /phpmyadmin, /.env, /api) and try known exploits against web frameworks.",
            "defense": "No public web services exposed, UFW blocks external HTTP",
            "learn_more": "https://attack.mitre.org/techniques/T1190/"
        },
        {
            "method": "Credential Stuffing",
            "icon": "📋",
            "severity": "high",
            "description": "Using leaked username/password pairs from data breaches to try logging in.",
            "how_it_works": "Attackers buy credential dumps from the dark web and automatically test them against SSH, email, and web services.",
            "defense": "Unique passwords, key-based SSH auth, fail2ban rate limiting",
            "learn_more": "https://attack.mitre.org/techniques/T1110/004/"
        }
    ]


def load_history():
    """Load persistent attack history — accumulates ALL attacks ever seen."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"ips": {}, "countries": {}, "first_seen": datetime.now().isoformat()}


def save_history(history):
    """Save persistent attack history."""
    history["last_updated"] = datetime.now().isoformat()
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


def _upsert_ip(history, ip, geo, attempts=1, source="unknown"):
    """Add or update an IP in the history dict."""
    if is_private_ip(ip):
        return
    now_iso = datetime.now().isoformat()
    lat = geo.get("lat", 0)
    lon = geo.get("lon", 0)
    cc = geo.get("country", "??")
    # Apply centroid fallback if coords are missing but country is known
    if (not lat and not lon) and cc in COUNTRY_CENTROIDS:
        lat, lon = COUNTRY_CENTROIDS[cc]
    if ip not in history["ips"]:
        history["ips"][ip] = {
            "first_seen": now_iso,
            "total_attempts": 0,
            "country": cc,
            "country_name": geo.get("country_name", "Unknown"),
            "city": geo.get("city", ""),
            "lat": lat,
            "lon": lon,
            "org": geo.get("org", ""),
            "asn": geo.get("asn", ""),
            "sources": [],
        }
    entry = history["ips"][ip]
    entry["total_attempts"] = max(entry.get("total_attempts", 0), attempts)
    entry["last_seen"] = now_iso
    # Update coords if we now have better ones
    if lat and not entry.get("lat"):
        entry["lat"] = lat
    if lon and not entry.get("lon"):
        entry["lon"] = lon
    if source not in entry.get("sources", []):
        entry.setdefault("sources", []).append(source)


def merge_history(history, current_ips, current_ufw, crowdsec_alerts=None, crowdsec_decisions=None):
    """Merge current data into persistent history. Never lose data."""
    now_iso = datetime.now().isoformat()

    # Merge auth.log IPs
    for entry in current_ips:
        ip = entry.get("ip", "")
        if not ip:
            continue
        geo = {k: entry.get(k, v) for k, v in
               [("country","??"),("country_name","Unknown"),("city",""),("lat",0),("lon",0),("org",""),("asn","")]}
        _upsert_ip(history, ip, geo, entry.get("attempts", 1), "auth.log")

    # Merge UFW blocked IPs
    for entry in current_ufw:
        ip = entry.get("ip", "")
        if not ip:
            continue
        geo = {k: entry.get(k, v) for k, v in
               [("country","??"),("country_name","Unknown"),("city",""),("lat",0),("lon",0),("org",""),("asn","")]}
        _upsert_ip(history, ip, geo, entry.get("count", 1), "ufw")

    # Merge CrowdSec alerts (IPs blocked at network level — main source)
    for entry in (crowdsec_alerts or []):
        ip = entry.get("ip", "")
        if not ip:
            continue
        geo = {k: entry.get(k, v) for k, v in
               [("country","??"),("country_name","Unknown"),("city",""),("lat",0),("lon",0),("org",""),("asn","")]}
        if not geo["lat"] or not geo["lon"]:
            geo = geoip_lookup(ip)
        _upsert_ip(history, ip, geo, 1, "crowdsec_alert")

    # Merge CrowdSec decisions (active bans)
    for entry in (crowdsec_decisions or []):
        ip = entry.get("ip", "")
        if not ip:
            continue
        geo = {k: entry.get(k, v) for k, v in
               [("country","??"),("country_name","Unknown"),("city",""),("lat",0),("lon",0),("org",""),("asn","")]}
        if not geo["lat"] or not geo["lon"]:
            geo = geoip_lookup(ip)
        _upsert_ip(history, ip, geo, 1, "crowdsec_decision")

    # Rebuild country totals from all IPs in history
    history["countries"] = {}
    for ip, data in history["ips"].items():
        cc = data.get("country", "??")
        if cc not in history["countries"]:
            history["countries"][cc] = {"name": get_country_name(cc), "total": 0, "ips": 0}
        history["countries"][cc]["total"] += data.get("total_attempts", 1)
        history["countries"][cc]["ips"] += 1

    if not history.get("first_seen"):
        history["first_seen"] = now_iso

    return history


def main():
    print(f"[{datetime.now().isoformat()}] Collecting security data...", file=sys.stderr)

    # Collect all data
    auth_data = parse_auth_log()
    fail2ban = get_fail2ban_data()
    crowdsec_alerts = get_crowdsec_alerts()
    crowdsec_decisions = get_crowdsec_decisions()
    ufw_data = get_ufw_blocked()
    system = get_system_stats()
    explanations = get_attack_explanations()

    # Load and merge persistent history — includes CrowdSec IPs (blocked before sshd)
    history = load_history()
    history = merge_history(
        history,
        auth_data["top_ips"],
        ufw_data["blocked_ips"],
        crowdsec_alerts=crowdsec_alerts,
        crowdsec_decisions=crowdsec_decisions,
    )
    save_history(history)

    # Build attacker list and country stats from HISTORY (accumulated forever)
    country_counter = Counter()
    all_attacker_coords = []
    seen_ips = set()

    # First: add ALL IPs from persistent history (this is the master source)
    for ip, data in history["ips"].items():
        cc = data.get("country", "??")
        attempts = data.get("total_attempts", 1)
        country_counter[cc] += attempts
        seen_ips.add(ip)
        if data.get("lat") and data.get("lon"):
            all_attacker_coords.append({
                "ip": ip,
                "lat": data["lat"],
                "lon": data["lon"],
                "country": cc,
                "country_name": data.get("country_name", "Unknown"),
                "city": data.get("city", ""),
                "attempts": attempts,
                "org": data.get("org", ""),
                "asn": data.get("asn", ""),
            })

    countries = []
    for cc, count in country_counter.most_common():  # ALL countries, no limit
        countries.append({
            "code": cc,
            "name": get_country_name(cc),
            "flag": cc_to_flag(cc),
            "attacks": count,
            "percent": round(count / max(sum(country_counter.values()), 1) * 100, 1)
        })

    # Build final output
    dashboard_data = {
        "generated_at": datetime.now().isoformat(),
        "vps": {
            "ip": VPS_IP,
            "lat": VPS_LAT,
            "lon": VPS_LON,
            "hostname": "your-vps-hostname.example.com"
        },
        "summary": {
            "total_ssh_attempts": auth_data["total_attempts"],
            "total_ufw_blocked": ufw_data["total_blocked"],
            "fail2ban_currently_banned": fail2ban["currently_banned"],
            "fail2ban_total_banned": fail2ban["total_banned"],
            "crowdsec_alerts": len(crowdsec_alerts),
            "crowdsec_active_bans": len(crowdsec_decisions),
            "unique_attackers": len(history["ips"]),  # ALL unique IPs ever seen
            "countries_attacking": len(countries),
            "history_since": history.get("first_seen", "unknown"),
        },
        "countries": countries,
        "attackers": all_attacker_coords,  # ALL attackers on map, no limit
        "top_ips": auth_data["top_ips"],  # ALL IPs
        "top_users": auth_data["top_users"],
        "methods": auth_data["methods"],
        "hourly_timeline": auth_data["hourly"],
        "ufw": ufw_data,
        "fail2ban": fail2ban,
        "crowdsec": {
            "alerts": crowdsec_alerts[:50],
            "decisions": crowdsec_decisions[:50],
        },
        "system": system,
        "attack_explanations": explanations,
    }

    # Write output
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(dashboard_data, f, indent=2, ensure_ascii=False)

    print(f"[{datetime.now().isoformat()}] Data written to {OUTPUT_FILE}", file=sys.stderr)
    print(f"  Attackers: {len(all_attacker_coords)}, Countries: {len(countries)}, SSH attempts: {auth_data['total_attempts']}", file=sys.stderr)


if __name__ == "__main__":
    main()
