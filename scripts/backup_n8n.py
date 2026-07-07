#!/usr/bin/env python3
"""
N8N Workflow Backup — exports all workflows as JSON and sends to Telegram.
Runs via cron weekly (Sundays).
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
N8N_API_URL = os.environ.get("N8N_API_URL", "http://localhost:5678")
N8N_API_KEY = os.environ.get("N8N_API_KEY", "")


def n8n_api(endpoint):
    """Call N8N API and return JSON response."""
    url = f"{N8N_API_URL}/api/v1/{endpoint}"
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": N8N_API_KEY})
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        print(f"N8N API error: {e}", file=sys.stderr)
        return None


def send_telegram_file(filepath, caption):
    """Send a file to Telegram."""
    import http.client
    import mimetypes

    boundary = "----BackupBoundary"
    filename = os.path.basename(filepath)

    with open(filepath, "rb") as f:
        file_data = f.read()

    body = []
    # chat_id field
    body.append(f"--{boundary}".encode())
    body.append(b'Content-Disposition: form-data; name="chat_id"')
    body.append(b"")
    body.append(CHAT_ID.encode())
    # caption field
    body.append(f"--{boundary}".encode())
    body.append(b'Content-Disposition: form-data; name="caption"')
    body.append(b"")
    body.append(caption.encode())
    # parse_mode field
    body.append(f"--{boundary}".encode())
    body.append(b'Content-Disposition: form-data; name="parse_mode"')
    body.append(b"")
    body.append(b"HTML")
    # document field
    body.append(f"--{boundary}".encode())
    body.append(f'Content-Disposition: form-data; name="document"; filename="{filename}"'.encode())
    body.append(b"Content-Type: application/json")
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
    """Send a text message to Telegram."""
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


def main():
    # Get all workflows
    result = n8n_api("workflows")
    if not result or "data" not in result:
        send_telegram_msg("<b>N8N BACKUP FAILED</b>\nCould not fetch workflows from API.")
        sys.exit(1)

    workflows = result["data"]
    if not workflows:
        send_telegram_msg("<b>N8N BACKUP</b>\nNo workflows found.")
        return

    # Export each workflow with full details
    full_workflows = []
    for wf in workflows:
        detail = n8n_api(f"workflows/{wf['id']}")
        if detail:
            full_workflows.append(detail)
        else:
            full_workflows.append(wf)

    # Create backup file
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_data = {
        "backup_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "n8n_url": N8N_API_URL,
        "workflow_count": len(full_workflows),
        "workflows": full_workflows,
    }

    tmpdir = tempfile.mkdtemp()
    backup_file = os.path.join(tmpdir, f"n8n_workflows_{timestamp}.json")

    with open(backup_file, "w") as f:
        json.dump(backup_data, f, indent=2)

    file_size = os.path.getsize(backup_file)
    size_str = f"{file_size / 1024:.1f} KB" if file_size >= 1024 else f"{file_size} B"

    caption = (
        f"<b>N8N WORKFLOW BACKUP</b>\n"
        f"<code>your-vps-hostname.example.com</code>\n\n"
        f"<b>Workflows:</b> {len(full_workflows)}\n"
        f"<b>Size:</b> {size_str}\n"
        f"<b>Date:</b> {time.strftime('%Y-%m-%d %H:%M')}"
    )

    wf_list = "\n".join(f"  - {wf.get('name', '?')} (ID: {wf.get('id', '?')})" for wf in full_workflows)
    caption += f"\n\n<b>Included:</b>\n{wf_list}"

    success = send_telegram_file(backup_file, caption)

    # Cleanup
    os.remove(backup_file)
    os.rmdir(tmpdir)

    if success:
        print(f"Backup sent: {len(full_workflows)} workflows, {size_str}", file=sys.stderr)
    else:
        print("Backup failed to send", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
