#!/usr/bin/env python3
"""
VPS Resource Monitor — alerts to Telegram if CPU/RAM/disk exceed thresholds.
Runs via cron every 15 minutes.
"""

import json
import subprocess
import urllib.request
import urllib.parse
import sys

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Thresholds (percent)
CPU_THRESHOLD = 80
RAM_THRESHOLD = 80
DISK_THRESHOLD = 80
SWAP_THRESHOLD = 50

# State file to avoid spamming (only alert once per issue)
STATE_FILE = "/tmp/resource_monitor_state.json"


def send_telegram(text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
    }).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(url, data=payload), timeout=10)
        return True
    except Exception as e:
        print(f"Telegram error: {e}", file=sys.stderr)
        return False


def get_cpu():
    """Get CPU usage from /proc/stat (1-second sample)."""
    try:
        with open("/proc/stat") as f:
            line1 = f.readline().split()
        import time
        time.sleep(1)
        with open("/proc/stat") as f:
            line2 = f.readline().split()
        idle1 = int(line1[4])
        idle2 = int(line2[4])
        total1 = sum(int(x) for x in line1[1:])
        total2 = sum(int(x) for x in line2[1:])
        delta_total = total2 - total1
        delta_idle = idle2 - idle1
        if delta_total == 0:
            return 0
        return round((1 - delta_idle / delta_total) * 100, 1)
    except Exception:
        # Fallback to load average
        with open("/proc/loadavg") as f:
            load = float(f.read().split()[0])
        import os
        cores = os.cpu_count() or 2
        return round(min(load / cores * 100, 100), 1)


def get_ram():
    """Get RAM usage percent."""
    output = subprocess.check_output(["free", "-m"], timeout=5).decode()
    for line in output.split("\n"):
        if line.startswith("Mem:"):
            parts = line.split()
            total, used = int(parts[1]), int(parts[2])
            return round(used / total * 100, 1), used, total
    return 0, 0, 0


def get_swap():
    """Get swap usage percent."""
    output = subprocess.check_output(["free", "-m"], timeout=5).decode()
    for line in output.split("\n"):
        if line.startswith("Swap:"):
            parts = line.split()
            total, used = int(parts[1]), int(parts[2])
            if total == 0:
                return 0, 0, 0
            return round(used / total * 100, 1), used, total
    return 0, 0, 0


def get_disk():
    """Get disk usage percent for /."""
    output = subprocess.check_output(["df", "-h", "/"], timeout=5).decode()
    parts = output.split("\n")[1].split()
    pct = int(parts[4].rstrip('%'))
    return pct, parts[2], parts[1]


def get_containers():
    """Check Docker containers health."""
    try:
        output = subprocess.check_output(
            ["docker", "ps", "-a", "--format", "{{.Names}}|{{.Status}}"],
            timeout=5
        ).decode().strip()
        down = []
        for line in output.split("\n"):
            if not line:
                continue
            name, status = line.split("|", 1)
            if "Up" not in status:
                down.append(f"{name} ({status})")
        return down
    except Exception:
        return []


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def main():
    cpu = get_cpu()
    ram_pct, ram_used, ram_total = get_ram()
    swap_pct, swap_used, swap_total = get_swap()
    disk_pct, disk_used, disk_total = get_disk()
    containers_down = get_containers()

    state = load_state()
    alerts = []

    # Check thresholds
    if cpu >= CPU_THRESHOLD:
        if not state.get("cpu_alert"):
            alerts.append(f"<b>CPU:</b> {cpu}% (threshold: {CPU_THRESHOLD}%)")
            state["cpu_alert"] = True
    else:
        if state.get("cpu_alert"):
            alerts.append(f"<b>CPU:</b> recovered to {cpu}%")
        state["cpu_alert"] = False

    if ram_pct >= RAM_THRESHOLD:
        if not state.get("ram_alert"):
            alerts.append(f"<b>RAM:</b> {ram_pct}% ({ram_used}/{ram_total}MB) (threshold: {RAM_THRESHOLD}%)")
            state["ram_alert"] = True
    else:
        if state.get("ram_alert"):
            alerts.append(f"<b>RAM:</b> recovered to {ram_pct}%")
        state["ram_alert"] = False

    if disk_pct >= DISK_THRESHOLD:
        if not state.get("disk_alert"):
            alerts.append(f"<b>Disk:</b> {disk_pct}% ({disk_used}/{disk_total}) (threshold: {DISK_THRESHOLD}%)")
            state["disk_alert"] = True
    else:
        if state.get("disk_alert"):
            alerts.append(f"<b>Disk:</b> recovered to {disk_pct}%")
        state["disk_alert"] = False

    if swap_pct >= SWAP_THRESHOLD:
        if not state.get("swap_alert"):
            alerts.append(f"<b>Swap:</b> {swap_pct}% ({swap_used}/{swap_total}MB) (threshold: {SWAP_THRESHOLD}%)")
            state["swap_alert"] = True
    else:
        if state.get("swap_alert"):
            alerts.append(f"<b>Swap:</b> recovered to {swap_pct}%")
        state["swap_alert"] = False

    if containers_down:
        down_str = ", ".join(containers_down)
        if state.get("containers_down") != down_str:
            alerts.append(f"<b>Containers DOWN:</b> {down_str}")
            state["containers_down"] = down_str
    else:
        if state.get("containers_down"):
            alerts.append("<b>Containers:</b> all recovered and running")
        state["containers_down"] = ""

    save_state(state)

    if alerts:
        msg = "<b>VPS RESOURCE ALERT</b>\n"
        msg += "<code>your-vps-hostname.example.com</code>\n\n"
        msg += "\n".join(alerts)
        msg += f"\n\n<b>Current:</b> CPU {cpu}% | RAM {ram_pct}% | Disk {disk_pct}% | Swap {swap_pct}%"
        send_telegram(msg)
        print(f"ALERT sent: {', '.join(a[:30] for a in alerts)}", file=sys.stderr)
    else:
        print(f"OK: CPU {cpu}% | RAM {ram_pct}% | Disk {disk_pct}% | Swap {swap_pct}%", file=sys.stderr)


if __name__ == "__main__":
    main()
