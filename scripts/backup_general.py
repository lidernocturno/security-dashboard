#!/usr/bin/env python3
"""
General VPS Backup — backs up Docker volumes, configs, and scripts.
Creates a tar.gz, sends to Telegram as document.
Runs via cron weekly (Sundays 11:00am).
"""

import http.client
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.parse

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

BACKUP_DIR = "/tmp/vps-backup"
MAX_TELEGRAM_SIZE = 49 * 1024 * 1024  # 49MB (Telegram limit ~50MB)

# Directories to backup
BACKUP_TARGETS = [
    # (source_path, archive_name, description)
    ("/home/your_user/agent-zero/a0-data", "agent-zero-data", "Agent Zero data (knowledge, memories, settings)"),
    ("/home/your_user/agent-zero/telegram", "agent-zero-telegram", "Telegram bridge scripts"),
    ("/home/your_user/agent-zero/docker-compose.yml", "agent-zero-compose", "Agent Zero docker-compose"),
    ("/home/your_user/uptime-kuma/data", "uptime-kuma-data", "Uptime Kuma database + config"),
    ("/home/your_user/uptime-kuma/docker-compose.yml", "uptime-kuma-compose", "Uptime Kuma docker-compose"),
    ("/home/your_user/n8n/docker-compose.yml", "n8n-compose", "N8N docker-compose"),
    ("/home/your_user/n8n/n8n-data", "n8n-data", "N8N workflows + credentials"),
    ("/home/your_user/security-dashboard", "security-dashboard", "Security dashboard (scripts, pages, data)"),
    ("/home/your_user/scripts", "scripts", "General scripts"),
]

# Config files to include
CONFIG_FILES = [
    "/etc/fail2ban/jail.local",
    "/etc/crowdsec/parsers/s02-enrich/tailscale-whitelist.yaml",
]


def send_telegram_file(filepath, caption):
    """Send a file to Telegram via multipart upload."""
    boundary = "----VPSBackupBoundary"
    filename = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        file_data = f.read()

    body = []
    body.append(f"--{boundary}".encode())
    body.append(b'Content-Disposition: form-data; name="chat_id"')
    body.append(b"")
    body.append(CHAT_ID.encode())

    body.append(f"--{boundary}".encode())
    body.append(b'Content-Disposition: form-data; name="caption"')
    body.append(b"")
    body.append(caption.encode())

    body.append(f"--{boundary}".encode())
    body.append(b'Content-Disposition: form-data; name="parse_mode"')
    body.append(b"")
    body.append(b"HTML")

    body.append(f"--{boundary}".encode())
    body.append(f'Content-Disposition: form-data; name="document"; filename="{filename}"'.encode())
    body.append(b"Content-Type: application/gzip")
    body.append(b"")
    body.append(file_data)
    body.append(f"--{boundary}--".encode())

    body_bytes = b"\r\n".join(body)

    conn = http.client.HTTPSConnection("api.telegram.org")
    conn.request(
        "POST",
        f"/bot{BOT_TOKEN}/sendDocument",
        body=body_bytes,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    resp = conn.getresponse()
    result = json.loads(resp.read())
    conn.close()

    if not result.get("ok"):
        print(f"Telegram error: {result}", file=sys.stderr)
        return False
    return True


def send_telegram_msg(text):
    """Send a text message."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
    }).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=10)
    except Exception as e:
        print(f"Telegram error: {e}", file=sys.stderr)


def format_size(size_bytes):
    """Format bytes to human-readable."""
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024*1024):.1f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes} B"


def main():
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_file = f"/tmp/vps_backup_{timestamp}.tar.gz"

    # Build list of existing paths to backup
    existing = []
    skipped = []

    for target in BACKUP_TARGETS:
        path = target[0]
        if os.path.exists(path):
            existing.append(path)
        else:
            skipped.append(path)

    for cf in CONFIG_FILES:
        if os.path.exists(cf):
            existing.append(cf)

    if not existing:
        send_telegram_msg("<b>VPS BACKUP FAILED</b>\nNo backup targets found.")
        sys.exit(1)

    # Create tar.gz (exclude .git, __pycache__, node_modules, *.pyc)
    cmd = [
        "tar", "czf", backup_file,
        "--exclude=.git",
        "--exclude=__pycache__",
        "--exclude=node_modules",
        "--exclude=*.pyc",
        "--exclude=*.log",
        "--warning=no-file-changed",
    ] + existing

    try:
        subprocess.run(cmd, timeout=120, check=False, capture_output=True)
    except subprocess.TimeoutExpired:
        send_telegram_msg("<b>VPS BACKUP FAILED</b>\ntar command timed out.")
        sys.exit(1)

    if not os.path.exists(backup_file):
        send_telegram_msg("<b>VPS BACKUP FAILED</b>\nBackup file not created.")
        sys.exit(1)

    file_size = os.path.getsize(backup_file)

    if file_size > MAX_TELEGRAM_SIZE:
        send_telegram_msg(
            f"<b>VPS BACKUP WARNING</b>\n"
            f"Backup too large for Telegram: {format_size(file_size)}\n"
            f"Saved locally: {backup_file}"
        )
        print(f"Backup too large: {format_size(file_size)}", file=sys.stderr)
        return

    # Build caption
    caption = (
        f"<b>VPS FULL BACKUP</b>\n"
        f"<code>your-vps-hostname.example.com</code>\n\n"
        f"<b>Size:</b> {format_size(file_size)}\n"
        f"<b>Date:</b> {time.strftime('%Y-%m-%d %H:%M')}\n\n"
        f"<b>Included ({len(existing)} items):</b>\n"
    )

    for target in BACKUP_TARGETS:
        if target[0] in existing:
            caption += f"  - {target[2]}\n"

    if skipped:
        caption += f"\n<b>Skipped:</b> {len(skipped)} (not found)"

    success = send_telegram_file(backup_file, caption)

    # Cleanup
    os.remove(backup_file)

    if success:
        print(f"Backup sent: {format_size(file_size)}, {len(existing)} items", file=sys.stderr)
    else:
        print("Backup failed to send", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
