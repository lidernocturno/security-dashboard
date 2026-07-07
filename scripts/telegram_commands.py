#!/usr/bin/env python3
"""
VPS Telegram Bot Commands
Listens for commands from Telegram and responds with VPS info.
Commands: /vps, /resources, /containers, /security, /dashboard
Uses getUpdates polling (no conflict with Agent Zero bridge).
"""

import json
import subprocess
import urllib.request
import urllib.parse
import sys
import time
import os

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
OFFSET_FILE = "/tmp/telegram_commands_offset"
DASHBOARD_URL = "http://100.x.x.x:8088"


def telegram_api(method, params=None):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    if params:
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=data)
    else:
        req = urllib.request.Request(url)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        print(f"API error: {e}", file=sys.stderr)
        return None


def send_message(text):
    return telegram_api("sendMessage", {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    })


def cmd_vps():
    """Full VPS status."""
    try:
        # Uptime
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
        days = int(secs // 86400)
        hours = int((secs % 86400) // 3600)
        mins = int((secs % 3600) // 60)
        uptime = f"{days}d {hours}h {mins}m"

        # Load
        with open("/proc/loadavg") as f:
            load = " ".join(f.read().split()[:3])

        # RAM
        mem = subprocess.check_output(["free", "-h"], timeout=5).decode()
        for line in mem.split("\n"):
            if line.startswith("Mem:"):
                parts = line.split()
                ram = f"{parts[2]}/{parts[1]}"

        # Disk
        disk_out = subprocess.check_output(["df", "-h", "/"], timeout=5).decode()
        dp = disk_out.split("\n")[1].split()
        disk = f"{dp[2]}/{dp[1]} ({dp[4]})"

        # Containers
        containers = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}: {{.Status}}"],
            timeout=5
        ).decode().strip()

        # Tailscale
        ts = subprocess.check_output(["tailscale", "status", "--peers=false"], timeout=5).decode().strip()

        msg = f"<b>VPS STATUS</b>\n<code>your-vps-hostname.example.com</code>\n\n"
        msg += f"<b>Uptime:</b> {uptime}\n"
        msg += f"<b>Load:</b> {load}\n"
        msg += f"<b>RAM:</b> {ram}\n"
        msg += f"<b>Disk:</b> {disk}\n\n"
        msg += f"<b>Containers:</b>\n<code>{containers}</code>\n\n"
        msg += f"<b>Tailscale:</b>\n<code>{ts}</code>\n\n"
        msg += f"<b>Dashboard:</b> {DASHBOARD_URL}"
        return msg
    except Exception as e:
        return f"Error: {e}"


def cmd_resources():
    """Detailed resource usage."""
    try:
        cpu_out = subprocess.check_output(["top", "-bn1"], timeout=10).decode()
        cpu_line = [l for l in cpu_out.split("\n") if "Cpu" in l][0]

        mem = subprocess.check_output(["free", "-h"], timeout=5).decode()
        disk = subprocess.check_output(["df", "-h", "/", "/home"], timeout=5).decode()

        # Top processes by memory
        ps = subprocess.check_output(
            ["ps", "aux", "--sort=-%mem"],
            timeout=5
        ).decode().split("\n")[1:6]
        top_procs = "\n".join(f"  {p.split()[10] if len(p.split())>10 else '?'}: {p.split()[3]}% RAM" for p in ps if p.strip())

        msg = f"<b>VPS RESOURCES</b>\n\n"
        msg += f"<b>CPU:</b>\n<code>{cpu_line.strip()}</code>\n\n"
        msg += f"<b>Memory:</b>\n<code>{mem.strip()}</code>\n\n"
        msg += f"<b>Disk:</b>\n<code>{disk.strip()}</code>\n\n"
        msg += f"<b>Top processes (RAM):</b>\n<code>{top_procs}</code>"
        return msg
    except Exception as e:
        return f"Error: {e}"


def cmd_containers():
    """Docker container details."""
    try:
        output = subprocess.check_output(
            ["docker", "ps", "-a", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"],
            timeout=5
        ).decode()

        stats = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "{{.Name}}: CPU {{.CPUPerc}}, RAM {{.MemUsage}}"],
            timeout=10
        ).decode()

        msg = f"<b>DOCKER CONTAINERS</b>\n\n"
        msg += f"<code>{output.strip()}</code>\n\n"
        msg += f"<b>Resource usage:</b>\n<code>{stats.strip()}</code>"
        return msg
    except Exception as e:
        return f"Error: {e}"


def cmd_security():
    """Security status summary."""
    try:
        # Fail2ban
        f2b = subprocess.check_output(
            ["sudo", "fail2ban-client", "status", "sshd"],
            timeout=5
        ).decode()

        # CrowdSec
        cs_alerts = subprocess.check_output(
            ["sudo", "cscli", "alerts", "list", "-l", "5"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode()

        cs_decisions = subprocess.check_output(
            ["sudo", "cscli", "decisions", "list", "-l", "5"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode()

        # UFW
        ufw = subprocess.check_output(
            ["sudo", "ufw", "status"],
            timeout=5
        ).decode().split("\n")[0]

        msg = f"<b>SECURITY STATUS</b>\n\n"
        msg += f"<b>UFW:</b> {ufw.strip()}\n\n"
        msg += f"<b>Fail2ban (SSH):</b>\n<code>{f2b.strip()}</code>\n\n"
        msg += f"<b>CrowdSec Alerts:</b>\n<code>{cs_alerts.strip()[:500]}</code>\n\n"
        msg += f"<b>CrowdSec Decisions:</b>\n<code>{cs_decisions.strip()[:300]}</code>\n\n"
        msg += f"<b>Dashboard:</b> {DASHBOARD_URL}"
        return msg
    except Exception as e:
        return f"Error: {e}"


def cmd_help():
    return """<b>VPS Commands</b>

/vps — Full server status
/resources — CPU, RAM, disk details
/containers — Docker containers status
/security — Fail2ban, CrowdSec, UFW
/dashboard — Link to security dashboard
/help — This message"""


COMMANDS = {
    "/vps": cmd_vps,
    "/resources": cmd_resources,
    "/containers": cmd_containers,
    "/security": cmd_security,
    "/dashboard": lambda: f"<b>Security Dashboard:</b>\n{DASHBOARD_URL}",
    "/help": cmd_help,
}


def get_offset():
    try:
        with open(OFFSET_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_offset(offset):
    with open(OFFSET_FILE, "w") as f:
        f.write(str(offset))


def process_updates():
    """Check for new commands and respond."""
    offset = get_offset()
    result = telegram_api("getUpdates", {
        "offset": offset,
        "timeout": 1,
        "allowed_updates": '["message"]',
    })

    if not result or not result.get("ok"):
        return

    for update in result.get("result", []):
        update_id = update["update_id"]
        save_offset(update_id + 1)

        msg = update.get("message", {})
        chat_id = str(msg.get("chat", {}).get("id", ""))
        text = msg.get("text", "").strip()

        # Only respond to owner
        if chat_id != CHAT_ID:
            continue

        # Check if it's a VPS command
        cmd = text.split()[0].lower() if text else ""
        # Handle commands with @botname suffix
        cmd = cmd.split("@")[0]

        if cmd in COMMANDS:
            response = COMMANDS[cmd]()
            send_message(response)
            print(f"Responded to {cmd}", file=sys.stderr)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "daemon":
        # Run continuously
        print("Bot commands daemon started", file=sys.stderr)
        while True:
            try:
                process_updates()
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
            time.sleep(3)
    else:
        # Single check (for cron)
        process_updates()


if __name__ == "__main__":
    main()
