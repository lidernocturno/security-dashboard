#!/usr/bin/env python3
"""
Security Audit Script — Proactive configuration checker
Runs every hour. Alerts via Telegram if something is misconfigured.

Checks:
1. UFW: no public ports that should be Tailscale-only
2. SSH: password auth disabled, root login disabled
3. Services: all expected containers/services running
4. CrowdSec: bouncer active
5. fail2ban: sshd jail active
6. Critical files: immutable flags intact
7. Unauthorized users: no new users/sudoers
"""

import os
import subprocess
import sys
import urllib.request
import urllib.parse
import json
import re
from pathlib import Path

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Ports that MUST be Tailscale-only (not open to public)
TAILSCALE_ONLY_PORTS = {
    "22": "SSH",
    "3001": "Uptime Kuma",
    "5678": "N8N",
    "8088": "Security Dashboard",
    "50001": "Agent Zero",
}

# Expected running containers
EXPECTED_CONTAINERS = ["agent-zero", "n8n", "uptime-kuma"]

# Expected running services
EXPECTED_SERVICES = ["security-dashboard", "telegram-bridge"]

# Files that should be immutable (chattr +i)
IMMUTABLE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/fstab",
]

# State file to avoid repeat alerts
STATE_FILE = Path(__file__).parent.parent / "data" / "audit_state.json"


def send_telegram(text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
    }).encode()
    try:
        req = urllib.request.Request(url, data=data)
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception as e:
        print(f"Telegram error: {e}", file=sys.stderr)
        return None


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout.strip()
    except Exception:
        return ""


def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"alerted": []}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def check_ufw_public_ports():
    """Check if any Tailscale-only ports are exposed to the public."""
    issues = []
    output = run("sudo ufw status")

    for line in output.split("\n"):
        line = line.strip()
        if not line or line.startswith("Status") or line.startswith("To") or line.startswith("--"):
            continue

        # Skip rules that are on tailscale0 interface — those are fine
        if "tailscale0" in line:
            continue

        # Skip rules restricted to Tailscale subnet
        if "100.x.x.x/10" in line:
            continue

        # Check if any of our protected ports appear in a public rule
        for port, service in TAILSCALE_ONLY_PORTS.items():
            # Match port patterns like "22/tcp", "22 ", "3001/tcp"
            if re.search(rf'\b{port}(/tcp|/udp)?\b', line):
                if "ALLOW" in line and "Anywhere" in line:
                    issues.append(f"Puerto {port} ({service}) ABIERTO al público: {line}")

    return issues


def check_ssh_config():
    """Check SSH hardening."""
    issues = []
    sshd_config = run("sudo cat /etc/ssh/sshd_config 2>/dev/null")

    # Check password authentication
    for line in sshd_config.split("\n"):
        line = line.strip()
        if line.startswith("#"):
            continue
        if re.match(r"PasswordAuthentication\s+yes", line, re.IGNORECASE):
            issues.append("SSH: PasswordAuthentication está en YES (debería ser no)")
        if re.match(r"PermitRootLogin\s+yes\b", line, re.IGNORECASE):
            issues.append("SSH: PermitRootLogin está en YES (debería ser prohibit-password o no)")

    return issues


def check_containers():
    """Check expected Docker containers are running."""
    issues = []
    output = run("docker ps --format '{{.Names}}' 2>/dev/null")
    running = set(output.split("\n")) if output else set()

    for name in EXPECTED_CONTAINERS:
        if name not in running:
            issues.append(f"Container '{name}' NO está corriendo")

    return issues


def check_services():
    """Check expected systemd services are active."""
    issues = []
    for svc in EXPECTED_SERVICES:
        output = run(f"systemctl is-active {svc}.service 2>/dev/null")
        if output != "active":
            issues.append(f"Servicio '{svc}' NO está activo (estado: {output})")

    return issues


def check_crowdsec():
    """Check CrowdSec is running with active bouncer."""
    issues = []

    # CrowdSec service
    cs_status = run("systemctl is-active crowdsec 2>/dev/null")
    if cs_status != "active":
        issues.append("CrowdSec NO está activo")
        return issues

    # Bouncer registered
    bouncers = run("sudo cscli bouncers list -o raw 2>/dev/null")
    if not bouncers or "firewall" not in bouncers.lower():
        issues.append("CrowdSec firewall bouncer NO registrado")

    return issues


def check_fail2ban():
    """Check fail2ban sshd jail is active."""
    issues = []
    output = run("sudo fail2ban-client status sshd 2>/dev/null")
    if "sshd" not in output:
        issues.append("fail2ban jail 'sshd' NO está activo")

    return issues


def check_immutable():
    """Check critical files still have immutable flag."""
    issues = []
    for f in IMMUTABLE_FILES:
        output = run(f"lsattr {f} 2>/dev/null")
        if output and "i" not in output.split()[0]:
            issues.append(f"Archivo {f} perdió flag inmutable (chattr +i)")

    return issues


def check_unauthorized_users():
    """Check for unexpected sudoers or new users with UID > 1000."""
    issues = []

    # Expected users with UID >= 1000
    # ubuntu = Hostinger default user (UID 1000), kept for compatibility
    expected_users = {"your_username", "ubuntu", "nobody", "nfsnobody"}
    passwd = run("getent passwd")
    for line in passwd.split("\n"):
        parts = line.split(":")
        if len(parts) >= 3:
            user, uid = parts[0], int(parts[2]) if parts[2].isdigit() else 0
            if uid >= 1000 and uid < 65534 and user not in expected_users:
                issues.append(f"Usuario inesperado: {user} (UID {uid})")

    # Check sudoers.d for unexpected files
    sudoers_d = run("ls /etc/sudoers.d/ 2>/dev/null")
    expected_sudoers = {"README", "your_username", "90-cloud-init-users"}
    for f in sudoers_d.split("\n"):
        f = f.strip()
        if f and f not in expected_sudoers:
            issues.append(f"Archivo sudoers inesperado: /etc/sudoers.d/{f}")

    return issues


def main():
    all_issues = []

    checks = [
        ("UFW Puertos Públicos", check_ufw_public_ports),
        ("SSH Config", check_ssh_config),
        ("Containers Docker", check_containers),
        ("Servicios Systemd", check_services),
        ("CrowdSec", check_crowdsec),
        ("fail2ban", check_fail2ban),
        ("Archivos Inmutables", check_immutable),
        ("Usuarios/Sudoers", check_unauthorized_users),
    ]

    for name, check_fn in checks:
        try:
            issues = check_fn()
            for issue in issues:
                all_issues.append((name, issue))
        except Exception as e:
            all_issues.append((name, f"Error ejecutando check: {e}"))

    if not all_issues:
        # All good — no alert needed
        # Save clean state
        save_state({"alerted": [], "last_clean": str(__import__('datetime').datetime.now())})
        print("Audit OK — no issues found", file=sys.stderr)
        return

    # Load state to avoid repeat alerts
    state = load_state()
    new_issues = []
    for category, issue in all_issues:
        issue_key = f"{category}:{issue}"
        if issue_key not in state.get("alerted", []):
            new_issues.append((category, issue))

    if not new_issues:
        print(f"Audit: {len(all_issues)} issues known, already alerted", file=sys.stderr)
        return

    # Build alert message
    lines = ["🚨 <b>AUDITORÍA DE SEGURIDAD — PROBLEMAS DETECTADOS</b>", ""]

    for category, issue in all_issues:
        is_new = any(c == category and i == issue for c, i in new_issues)
        marker = "🆕" if is_new else "⚠️"
        lines.append(f"{marker} <b>[{category}]</b>")
        lines.append(f"   {issue}")
        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append(f"Total problemas: <b>{len(all_issues)}</b> ({len(new_issues)} nuevos)")
    lines.append("")
    lines.append("🔧 Revisar y corregir lo antes posible.")

    text = "\n".join(lines)
    result = send_telegram(text)

    if result and result.get("ok"):
        # Save alerted issues to avoid repeats
        alerted = [f"{c}:{i}" for c, i in all_issues]
        save_state({"alerted": alerted, "last_alert": str(__import__('datetime').datetime.now())})
        print(f"Audit: {len(new_issues)} new issues alerted via Telegram", file=sys.stderr)
    else:
        print(f"Audit: Failed to send Telegram alert", file=sys.stderr)


if __name__ == "__main__":
    main()
