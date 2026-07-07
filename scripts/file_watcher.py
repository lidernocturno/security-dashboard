#!/usr/bin/env python3
"""
Critical File Watcher — detects modifications to protected files and alerts via Telegram.
Identifies WHO/WHAT process made the change using /proc and Docker inspection.
Runs via cron every 15 minutes.
"""

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.parse

from email_alert import send_email

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
STATE_FILE = "/tmp/file_watcher_state.json"
LOG_FILE = "/home/your_user/security-dashboard/logs/modifications.log"

# Clasificación de modificadores
# - LEGITIMATE: cambios esperados de Claude, crons, skills → NO alertar
# - SUSPICIOUS: Agent Zero (tras incidente 12 Abr $4 USD) + Unknown → SÍ alertar
# - CRITICAL_FILES: alertar SIEMPRE sin importar quién (sudoers, UFW, SSH, GPG)
LEGITIMATE_MODIFIERS = {
    "Claude Code",
    "Claude Code (node)",
    "Python script",
    "Cron job",
    "Shell command",
    "Docker: n8n", "Docker: n8n-agentzero", "Docker: n8n-openclaw",
    "Docker: uptime-kuma", "Docker: dockge-dockge-1",
    "Docker: agents-db", "Docker: postforge-db", "Docker: ci-db",
    "Docker: nexus", "Docker: crawl4ai",
}

SUSPICIOUS_MODIFIERS = {
    "Agent Zero",
    "Docker: agent-zero",
    "Unknown",
    "Manual edit (SSH)",  # edición manual vía vim/nano — sospechoso si no lo esperabas
}

CRITICAL_FILES = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d/your_user",
    "/etc/ufw/user.rules",
    "/etc/ufw/user6.rules",
    "/etc/ssh/sshd_config",
}

# Files where auto-checkpoint changes are safe (don't alert even for legit modifiers)
AUTO_CHECKPOINT_SAFE = {
    "/home/your_user/.claude/projects/-home-your_user/memory/session.md",
    "/home/your_user/.claude/projects/-home-your_user/memory/changes-log.md",
}


def log_modification(filepath, modifier, details, alerted):
    """Log every modification locally, whether or not alerted."""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as f:
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            status = "ALERTED" if alerted else "SILENT"
            f.write(f"{ts} [{status}] {filepath} by={modifier} details={details}\n")
    except Exception:
        pass


def classify_alert(filepath, modifier):
    """Decide if we alert. Returns (should_alert, reason)."""
    # 1. Critical files — always alert
    if filepath in CRITICAL_FILES:
        return True, "critical_file"
    # 2. Suspicious modifier — alert
    if modifier in SUSPICIOUS_MODIFIERS or modifier.startswith("Docker: agent-zero"):
        return True, f"suspicious_modifier:{modifier}"
    # 3. Legitimate modifier — silent
    if modifier in LEGITIMATE_MODIFIERS:
        return False, f"legitimate:{modifier}"
    # 4. Anything starting with "Docker:" that we don't know → suspicious
    if modifier.startswith("Docker:"):
        return True, f"unknown_docker:{modifier}"
    # 5. Default: alert (be safe on modifiers we don't classify)
    return True, f"unclassified:{modifier}"


SNAPSHOT_DIR = "/tmp/file_watcher_snapshots"


def _snapshot_path(filepath):
    safe = filepath.replace("/", "_").lstrip("_")
    return os.path.join(SNAPSHOT_DIR, safe)


def is_only_auto_checkpoint(filepath):
    """Check if the ONLY new content appended to this file is AUTO-CHECKPOINT lines.
    Uses local snapshot (independent of git state — no race conditions).
    Returns True if safe to skip alert."""
    if filepath not in AUTO_CHECKPOINT_SAFE:
        return False
    try:
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        current = open(filepath, "r", encoding="utf-8", errors="replace").read()
        snap_path = _snapshot_path(filepath)

        if not os.path.exists(snap_path):
            # First time — write snapshot, cannot determine safety, err on side of silence
            # since session-watchdog is the overwhelming common case
            open(snap_path, "w", encoding="utf-8").write(current)
            return True

        previous = open(snap_path, "r", encoding="utf-8", errors="replace").read()

        # Always update snapshot at the end
        _result = False
        try:
            # Must be a pure append (prefix match)
            if not current.startswith(previous):
                _result = False
                return _result
            delta = current[len(previous):]
            if not delta.strip():
                _result = True
                return _result
            new_lines = delta.splitlines()
            safe_patterns = ("AUTO-CHECKPOINT", "_last action:")
            _result = all(
                (not line.strip()) or any(p in line for p in safe_patterns)
                for line in new_lines
            )
            return _result
        finally:
            open(snap_path, "w", encoding="utf-8").write(current)
    except Exception:
        return False


# Critical files to monitor — (path, description)
WATCHED_FILES = [
    # === AGENT ZERO INTERNALS ===
    # API keys, model config, tokens — if these change, AZ behavior changes or breaks
    ("/home/your_user/agent-zero/a0-data/.env", "AZ API Keys (.env)"),
    ("/home/your_user/agent-zero/a0-data/secrets.env", "AZ Secrets (secrets.env)"),
    ("/home/your_user/agent-zero/a0-data/settings.json", "AZ Settings (modelo, params)"),
    # Knowledge — credenciales, reglas, guías
    ("/home/your_user/agent-zero/a0-data/knowledge/main/credenciales.md.gpg", "AZ Bóveda Credenciales"),
    ("/home/your_user/agent-zero/a0-data/knowledge/main/vps-workspace-rules.md", "AZ Workspace Rules"),
    ("/home/your_user/agent-zero/a0-data/knowledge/main/claude-rc-persistente.md", "AZ Claude RC Guide"),
    ("/home/your_user/agent-zero/a0-data/knowledge/main/guia-claude-code-remoto.md", "AZ Claude Code Guide"),
    # Scheduler
    ("/home/your_user/agent-zero/a0-data/scheduler/tasks.json", "AZ Scheduled Tasks"),
    # Telegram bridge
    ("/home/your_user/agent-zero/telegram/telegram_bridge.py", "Telegram Bridge"),
    ("/home/your_user/agent-zero/telegram/start.sh", "Bridge Start Script"),
    ("/home/your_user/agent-zero/telegram/requirements.txt", "Bridge Dependencies"),
    # Docker compose files
    ("/home/your_user/agent-zero/docker-compose.yml", "Agent Zero Docker Compose"),
    ("/home/your_user/n8n/docker-compose.yml", "N8N Docker Compose"),
    ("/home/your_user/uptime-kuma/docker-compose.yml", "Uptime Kuma Docker Compose"),
    # === SECURITY DASHBOARD ===
    ("/home/your_user/security-dashboard/server.py", "Dashboard Web Server"),
    ("/home/your_user/security-dashboard/index.html", "Dashboard Main Page"),
    ("/home/your_user/security-dashboard/scripts/collect_data.py", "Data Collector"),
    ("/home/your_user/security-dashboard/scripts/telegram_report.py", "Telegram Reports"),
    ("/home/your_user/security-dashboard/scripts/resource_monitor.py", "Resource Monitor"),
    ("/home/your_user/security-dashboard/scripts/backup_n8n.py", "N8N Backup Script"),
    ("/home/your_user/security-dashboard/scripts/backup_general.py", "General Backup Script"),
    # === OPENCLAW ===
    ("/home/your_user/.openclaw/openclaw.json", "OpenClaw Config Principal"),
    ("/home/your_user/.openclaw/identity/IDENTITY.md", "OpenClaw Identity (HackBoy)"),
    ("/home/your_user/.openclaw/identity/USER.md", "OpenClaw User Profile"),
    ("/home/your_user/.openclaw/identity/BOOTSTRAP.md", "OpenClaw Bootstrap"),
    ("/home/your_user/.openclaw/identity/SOUL.md", "OpenClaw Soul"),
    # === MISSION CONTROL ===
    ("/home/your_user/mission-control/.env", "Mission Control Config (.env)"),
    ("/home/your_user/mission-control/src/components/nav-rail.tsx", "MC Nav Rail (custom)"),
    # === CLAUDE CODE MEMORY ===
    ("/home/your_user/CLAUDE.md", "CLAUDE.md (instrucciones globales)"),
    ("/home/your_user/.claude/projects/-home-your_user/memory/MEMORY.md", "Claude Memory Index"),
    ("/home/your_user/.claude/projects/-home-your_user/memory/session.md", "Claude Session State"),
    ("/home/your_user/.claude/projects/-home-your_user/memory/projects.md", "Claude Projects Index"),
    ("/home/your_user/.claude/projects/-home-your_user/memory/changes-log.md", "Claude Changes Log"),
    # === SYSTEM ===
    ("/etc/systemd/system/security-dashboard.service", "Dashboard Service"),
    ("/etc/systemd/system/telegram-bridge.service", "Bridge Service"),
    ("/etc/systemd/system/mission-control.service", "Mission Control Service"),
    ("/etc/systemd/system/clawharbor.service", "ClawHarbor Service"),
    # === FIREWALL ===
    ("/etc/ufw/user.rules", "UFW Firewall Rules (IPv4)"),
    ("/etc/ufw/user6.rules", "UFW Firewall Rules (IPv6)"),
    ("/etc/ssh/sshd_config", "SSH Server Config"),
    # === SCRIPTS ===
    ("/home/your_user/scripts/git-auto-snapshot.sh", "Git Auto-Snapshot"),
]

# Directories to scan for NEW files (detect if AZ creates something unexpected)
WATCHED_DIRS = [
    ("/home/your_user/agent-zero/a0-data/knowledge/main", "AZ Knowledge"),
    ("/home/your_user/agent-zero/a0-data/skills", "AZ Skills"),
    ("/home/your_user/.openclaw/skills", "OpenClaw Skills"),
    ("/home/your_user/.openclaw/hooks", "OpenClaw Hooks"),
    ("/home/your_user/.openclaw/identity", "OpenClaw Identity"),
]


def send_telegram(text):
    """Send alert to Telegram."""
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


def file_hash(filepath):
    """Get SHA256 hash of a file."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def file_size(filepath):
    """Get file size in bytes."""
    try:
        return os.path.getsize(filepath)
    except Exception:
        return 0


def file_mtime(filepath):
    """Get file modification time."""
    try:
        return os.path.getmtime(filepath)
    except Exception:
        return 0


def get_active_sessions():
    """Get active SSH sessions to identify which device is connected."""
    sessions = []
    try:
        output = subprocess.check_output(
            ["who", "-u"], timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        for line in output.split("\n"):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                user = parts[0]
                ip = parts[-1].strip("()")
                # Map known IPs to device names
                device_map = {
                    "100.x.x.x": "MacBook",
                    "100.x.x.x": "iPhone",
                    "100.x.x.x": "iPad",
                    "100.x.x.x": "VPS local",
                    "tmux": "tmux (Remote Control)",
                }
                device = device_map.get(ip, ip)
                sessions.append({"user": user, "ip": ip, "device": device})
    except Exception:
        pass
    return sessions


def identify_modifier(filepath):
    """Try to identify what process recently modified the file.
    Uses multiple methods: lsof, recent processes, Docker container detection."""

    modifier = "Unknown"
    details = ""

    # Method 1: Check if file was recently written by a known process via lsof
    try:
        lsof_out = subprocess.check_output(
            ["lsof", filepath], timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        if lsof_out:
            lines = lsof_out.split("\n")[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    proc_name = parts[0]
                    pid = parts[1]
                    modifier, details = identify_by_pid(pid, proc_name)
                    if modifier != "Unknown":
                        return modifier, details
    except Exception:
        pass

    # Method 2: Check recent audit log for this file
    try:
        audit_out = subprocess.check_output(
            ["sudo", "ausearch", "-f", filepath, "-ts", "recent", "--format", "text"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()
        if audit_out:
            # Look for process info in audit
            for line in audit_out.split("\n"):
                if "comm=" in line:
                    comm = extract_field(line, "comm=")
                    pid_str = extract_field(line, "pid=")
                    if comm:
                        modifier, details = identify_by_comm(comm, pid_str)
                        if modifier != "Unknown":
                            return modifier, details
    except Exception:
        pass

    # Method 3: Check recent file modification against running containers
    try:
        mtime = file_mtime(filepath)
        now = time.time()
        if now - mtime < 900:  # modified in last 15 min
            # Check Docker containers that mount this path
            containers = subprocess.check_output(
                ["docker", "ps", "--format", "{{.Names}}"],
                timeout=5
            ).decode().strip().split("\n")
            for container in containers:
                if not container:
                    continue
                try:
                    inspect = subprocess.check_output(
                        ["docker", "inspect", "--format", "{{json .Mounts}}", container],
                        timeout=5
                    ).decode()
                    mounts = json.loads(inspect)
                    for mount in mounts:
                        src = mount.get("Source", "")
                        if filepath.startswith(src):
                            return f"Docker: {container}", f"Mount: {src}"
                except Exception:
                    continue
    except Exception:
        pass

    return modifier, details


def identify_by_pid(pid, proc_name=""):
    """Identify process by PID — check if it's in a Docker container."""
    try:
        # Check cgroup to see if PID is in a container
        cgroup_file = f"/proc/{pid}/cgroup"
        if os.path.exists(cgroup_file):
            with open(cgroup_file) as f:
                cgroup = f.read()
            if "docker" in cgroup or "containerd" in cgroup:
                # Extract container ID
                for line in cgroup.split("\n"):
                    if "docker" in line:
                        parts = line.split("/")
                        container_id = parts[-1][:12] if parts else "?"
                        # Get container name
                        try:
                            name = subprocess.check_output(
                                ["docker", "inspect", "--format", "{{.Name}}", container_id],
                                timeout=5, stderr=subprocess.DEVNULL
                            ).decode().strip().lstrip("/")
                            return f"Docker: {name}", f"PID {pid}, container {container_id}"
                        except Exception:
                            return f"Docker container", f"PID {pid}, ID {container_id}"

        # Check process name
        if proc_name:
            return identify_by_comm(proc_name, pid)

        # Read cmdline
        cmdline_file = f"/proc/{pid}/cmdline"
        if os.path.exists(cmdline_file):
            with open(cmdline_file) as f:
                cmdline = f.read().replace("\x00", " ").strip()
            if "claude" in cmdline.lower() or "node" in cmdline.lower():
                return "Claude Code", f"PID {pid}"
            elif "python" in cmdline.lower():
                return "Python script", f"PID {pid}: {cmdline[:80]}"

    except Exception:
        pass

    return "Unknown", f"PID {pid}"


def identify_by_comm(comm, pid_str=""):
    """Identify modifier by process command name."""
    comm = comm.strip('"').lower()
    pid_info = f"PID {pid_str}" if pid_str else ""

    if "agent" in comm or "a0" in comm:
        return "Agent Zero", pid_info
    elif "claude" in comm:
        return "Claude Code", pid_info
    elif "node" in comm:
        return "Claude Code (node)", pid_info
    elif "python" in comm:
        return "Python script", pid_info
    elif "vim" in comm or "nano" in comm or "vi" in comm:
        return "Manual edit (SSH)", pid_info
    elif "cron" in comm:
        return "Cron job", pid_info
    elif "docker" in comm:
        return "Docker", pid_info
    elif "sed" in comm or "awk" in comm or "tee" in comm:
        return "Shell command", pid_info

    return "Unknown", f"{comm} {pid_info}"


def extract_field(line, field):
    """Extract a field value from audit log line."""
    try:
        idx = line.index(field)
        value = line[idx + len(field):].split()[0]
        return value.strip('"')
    except Exception:
        return ""


def get_git_diff(filepath):
    """Get git diff for the file if it's in a repo."""
    try:
        # Find the repo root
        dirpath = os.path.dirname(filepath)
        root = subprocess.check_output(
            ["git", "-C", dirpath, "rev-parse", "--show-toplevel"],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()

        rel_path = os.path.relpath(filepath, root)

        diff = subprocess.check_output(
            ["git", "-C", root, "diff", "--stat", rel_path],
            timeout=5, stderr=subprocess.DEVNULL
        ).decode().strip()

        if not diff:
            diff = subprocess.check_output(
                ["git", "-C", root, "diff", "--stat", "HEAD~1", rel_path],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode().strip()

        return diff[:200] if diff else ""
    except Exception:
        return ""


def load_state():
    """Load previous file states."""
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state):
    """Save current file states."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def main():
    state = load_state()
    alerts = []

    for filepath, description in WATCHED_FILES:
        current_hash = file_hash(filepath)
        current_size = file_size(filepath)
        current_mtime = file_mtime(filepath)

        key = filepath
        prev = state.get(key, {})
        prev_hash = prev.get("hash")

        # First run — just record state
        if prev_hash is None:
            state[key] = {
                "hash": current_hash,
                "size": current_size,
                "mtime": current_mtime,
            }
            continue

        # File deleted
        if current_hash is None and prev_hash is not None:
            alerts.append(
                f"<b>DELETED:</b> {description}\n"
                f"<code>{filepath}</code>\n"
                f"<b>By:</b> checking..."
            )
            state[key] = {"hash": None, "size": 0, "mtime": 0}
            continue

        # File changed
        if current_hash != prev_hash:
            # Skip alert if it's just an auto-checkpoint (session-watchdog)
            if is_only_auto_checkpoint(filepath):
                log_modification(filepath, "auto-checkpoint", "session-watchdog", alerted=False)
                state[key] = {
                    "hash": current_hash,
                    "size": current_size,
                    "mtime": current_mtime,
                }
                continue

            modifier, details = identify_modifier(filepath)

            # Nueva clasificación allowlist/suspicious/critical
            should_alert, reason = classify_alert(filepath, modifier)
            log_modification(filepath, modifier, f"{details} | reason={reason}", alerted=should_alert)
            if not should_alert:
                state[key] = {
                    "hash": current_hash,
                    "size": current_size,
                    "mtime": current_mtime,
                }
                continue

            size_diff = current_size - prev.get("size", 0)
            size_str = f"+{size_diff}" if size_diff >= 0 else str(size_diff)

            git_diff = get_git_diff(filepath)
            diff_line = f"\n<b>Git:</b> <code>{git_diff}</code>" if git_diff else ""

            mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_mtime))

            # Get active sessions to show which device
            sessions = get_active_sessions()
            device_line = ""
            if sessions:
                devices = list(set(s["device"] for s in sessions))
                device_line = f"\n<b>Dispositivos conectados:</b> {', '.join(devices)}"

            alert = (
                f"<b>{description}</b>\n"
                f"<code>{filepath}</code>\n"
                f"<b>Modified:</b> {mtime_str}\n"
                f"<b>By:</b> {modifier}"
            )
            if details:
                alert += f" ({details})"
            alert += f"\n<b>Size:</b> {current_size} bytes ({size_str} bytes)"
            alert += device_line
            alert += diff_line

            alerts.append(alert)

            state[key] = {
                "hash": current_hash,
                "size": current_size,
                "mtime": current_mtime,
            }

    # Check watched directories for new/deleted files
    for dirpath, dir_desc in WATCHED_DIRS:
        dir_key = f"__dir__{dirpath}"
        try:
            current_files = set()
            for root, dirs, files in os.walk(dirpath):
                # Skip hidden dirs and __pycache__
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
                for fname in files:
                    if fname.startswith('.'):
                        continue
                    fpath = os.path.join(root, fname)
                    rel = os.path.relpath(fpath, dirpath)
                    current_files.add(rel)
        except Exception:
            current_files = set()

        prev_files = set(state.get(dir_key, []))

        # First run
        if not prev_files and dir_key not in state:
            state[dir_key] = sorted(current_files)
            continue

        new_files = current_files - prev_files
        removed_files = prev_files - current_files

        for nf in sorted(new_files):
            full_path = os.path.join(dirpath, nf)
            sz = file_size(full_path)
            sz_str = f"{sz / 1024:.1f} KB" if sz >= 1024 else f"{sz} B"
            alerts.append(
                f"<b>NEW FILE in {dir_desc}</b>\n"
                f"<code>{nf}</code>\n"
                f"<b>Size:</b> {sz_str}"
            )

        for rf in sorted(removed_files):
            alerts.append(
                f"<b>DELETED from {dir_desc}</b>\n"
                f"<code>{rf}</code>"
            )

        state[dir_key] = sorted(current_files)

    save_state(state)

    if alerts:
        msg = "<b>FILE MODIFICATION ALERT</b>\n"
        msg += f"<code>your-vps-hostname.example.com</code>\n\n"
        msg += "\n\n".join(alerts)
        msg += "\n\n<i>Check git diff for details. Use git checkout to revert.</i>"
        send_telegram(msg)
        send_email(f"FILE ALERT: {len(alerts)} archivo(s) modificado(s)", msg)
        print(f"ALERT: {len(alerts)} file(s) modified (Telegram + Email)", file=sys.stderr)
    else:
        print("OK: no changes detected", file=sys.stderr)


if __name__ == "__main__":
    main()
