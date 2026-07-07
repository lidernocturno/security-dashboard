#!/usr/bin/env python3
"""
Security Dashboard - Telegram Report
Sends a formatted security report to Telegram.
Can be run via cron or triggered by the dashboard refresh.
"""

import json
import sys
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta
import os

from email_alert import send_email

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
DATA_FILE = Path("/home/your_user/security-dashboard/data/attacks.json")
DASHBOARD_URL = "http://100.x.x.x:8088"
STATE_FILE = Path("/tmp/telegram_alerts_state.json")
MAX_ALERTS_PER_DAY = 5          # Límite de alertas por día
MIN_INTERVAL_MINUTES = 288       # 24h / 5 = 4.8h entre alertas normales


def load_alert_state():
    """Cargar estado de alertas desde archivo."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    # Estado inicial
    return {
        "alerts_sent_today": 0,
        "last_alert_time": None,
        "daily_reset_time": datetime.now().replace(hour=0, minute=0, second=0).isoformat(),
        "pending_alerts": []  # Alertas de bajo riesgo en espera
    }


def save_alert_state(state):
    """Guardar estado de alertas en archivo."""
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def should_send_alert(risk_level):
    """Decide si enviar alerta basado en riesgo y límites."""
    now = datetime.now()
    state = load_alert_state()
    
    # Reset diario
    reset_time = datetime.fromisoformat(state["daily_reset_time"])
    if now >= reset_time + timedelta(days=1):
        state["alerts_sent_today"] = 0
        state["daily_reset_time"] = now.replace(hour=0, minute=0, second=0).isoformat()
        state["pending_alerts"] = []
    
    # Alertas críticas (alto riesgo) se envían inmediatamente, sin límites
    if risk_level == "critical":
        return True, "high_risk"
    
    # Alertas normales: verificar límite diario
    if state["alerts_sent_today"] >= MAX_ALERTS_PER_DAY:
        return False, "daily_limit_exceeded"
    
    # Verificar intervalo mínimo
    if state["last_alert_time"]:
        last_time = datetime.fromisoformat(state["last_alert_time"])
        elapsed = (now - last_time).total_seconds() / 60  # minutos
        if elapsed < MIN_INTERVAL_MINUTES:
            return False, "interval_not_reached"
    
    # Se puede enviar
    state["alerts_sent_today"] += 1
    state["last_alert_time"] = now.isoformat()
    save_alert_state(state)
    return True, "ok"


def send_telegram(text, parse_mode="HTML"):
    """Send a message to Telegram."""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": "true",
    }).encode()
    req = urllib.request.Request(url, data=payload)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return json.loads(resp.read())
    except Exception as e:
        print(f"Telegram error: {e}", file=sys.stderr)
        return None


def format_report(data):
    """Format the security report for Telegram."""
    s = data["summary"]
    now = datetime.now().strftime("%d %b %Y | %H:%M CST")

    lines = []
    lines.append(f"<b>REPORTE DE SEGURIDAD VPS</b>")
    lines.append(f"<code>{now}</code>")
    lines.append("")

    # Big numbers
    lines.append(f"<b>Intentos SSH:</b> <code>{s['total_ssh_attempts']:,}</code>")
    lines.append(f"<b>Atacantes unicos:</b> <code>{s['unique_attackers']}</code>")
    lines.append(f"<b>Paises:</b> <code>{s['countries_attacking']}</code>")
    lines.append(f"<b>IPs baneadas (total):</b> <code>{s['fail2ban_total_banned']}</code>")
    lines.append(f"<b>Alertas CrowdSec:</b> <code>{s['crowdsec_alerts']}</code>")
    lines.append("")

    # ALL countries (not just top 7)
    lines.append("<b>Paises atacantes (TODOS):</b>")
    for c in data["countries"]:
        bar = "█" * max(1, int(c["percent"] / 3))
        lines.append(f"  {c['flag']} {c['name']}: <code>{c['attacks']:,}</code> ({c['percent']}%) {bar}")
    lines.append("")

    # Methods with details
    lines.append("<b>Metodos de ataque:</b>")
    for m in data["methods"]:
        icon = {"SSH Brute Force (password)": "🔑", "SSH Invalid User": "👤",
                "SSH Connection Probe": "🔌", "SSH Pre-auth Disconnect": "⚡"}.get(m["method"], "📡")
        lines.append(f"  {icon} {m['method']}: <code>{m['count']:,}</code>")
    lines.append("")

    # Top 10 attackers with full details
    lines.append("<b>Top 10 atacantes:</b>")
    for i, a in enumerate(data["top_ips"][:10], 1):
        flag = a.get("flag", "🏴")
        city = a.get("city", "??")
        country = a.get("country_name", "??")
        org = a.get("org", "")
        asn = a.get("asn", "")
        lines.append(f"  {i}. {flag} <code>{a['ip']}</code> — {a['attempts']:,} intentos")
        lines.append(f"     {country}, {city}")
        if org:
            lines.append(f"     <i>{org}</i> {asn}")
    lines.append("")

    # Top usernames (more)
    lines.append("<b>Usuarios mas atacados:</b>")
    users = [f"{u['user']}({u['attempts']:,})" for u in data["top_users"][:15]]
    lines.append(f"  <code>{' '.join(users)}</code>")
    lines.append("")

    # UFW blocked summary
    ufw = data.get("ufw", {})
    if ufw.get("total_blocked", 0) > 0:
        lines.append(f"<b>UFW Bloqueados:</b> <code>{ufw['total_blocked']:,}</code> conexiones")
        ports = ufw.get("targeted_ports", [])[:5]
        if ports:
            port_str = ", ".join(f"{p['service']}:{p['count']}" for p in ports)
            lines.append(f"  Puertos: <code>{port_str}</code>")
        lines.append("")

    # System
    sys_info = data.get("system", {})
    if sys_info:
        lines.append(f"<b>Sistema:</b> RAM {sys_info.get('ram_percent', '?')}% | Disk {sys_info.get('disk_percent', '?')} | Up {sys_info.get('uptime', '?')}")
    lines.append("")

    lines.append(f"<b>Dashboard:</b> {DASHBOARD_URL}")

    return "\n".join(lines)


def cc_to_flag(cc):
    """Country code to flag emoji."""
    if not cc or len(cc) != 2 or cc == "??":
        return "🏴"
    try:
        return chr(0x1F1E6 + ord(cc[0]) - ord('A')) + chr(0x1F1E6 + ord(cc[1]) - ord('A'))
    except Exception:
        return "🏴"


# Attack method descriptions for email report
METHOD_INFO = {
    "SSH Brute Force (password)": {
        "name": "SSH Brute Force (contraseñas)",
        "desc": "Prueba miles de contraseñas conocidas intentando adivinar credenciales válidas.",
        "mitre": "T1110.001 — Password Guessing",
        "defense": "fail2ban + CrowdSec banean la IP tras 5 intentos fallidos",
    },
    "SSH Invalid User": {
        "name": "SSH Usuarios Inválidos",
        "desc": "Intenta conectarse con usuarios inexistentes (root, admin, ubuntu, test...) para encontrar cuentas activas.",
        "mitre": "T1110.003 — Password Spraying / User Enumeration",
        "defense": "SSH rechaza usuarios desconocidos; fail2ban banea tras intentos repetidos",
    },
    "SSH Pre-auth Disconnect": {
        "name": "SSH Disconnect Pre-auth",
        "desc": "Abre conexiones SSH y las cierra antes de autenticar — escanea versión/banner del servidor.",
        "mitre": "T1046 — Network Service Discovery",
        "defense": "UFW limita rate de conexiones; CrowdSec detecta patrones de escaneo",
    },
    "SSH Connection Probe": {
        "name": "SSH Connection Probe",
        "desc": "Prueba si el puerto SSH está abierto y registra la versión del servidor.",
        "mitre": "T1046 — Network Service Discovery",
        "defense": "CrowdSec bloquea scanners conocidos; UFW filtra IPs reincidentes",
    },
    "Port Scanning": {
        "name": "Port Scanning",
        "desc": "Escanea múltiples puertos buscando servicios vulnerables (Nmap, Masscan, Shodan).",
        "mitre": "T1046 — Network Service Scanning",
        "defense": "UFW bloquea todo tráfico excepto puertos autorizados; CrowdSec detecta patrones",
    },
    "HTTP Exploit Scanning": {
        "name": "HTTP Exploit Scanning",
        "desc": "Busca CVEs conocidos en servicios web: log4shell, shellshock, PHP exploits, panel de admin.",
        "mitre": "T1190 — Exploit Public-Facing Application",
        "defense": "CrowdSec HTTP bouncer bloquea IPs con comportamiento de exploit scanning",
    },
}


def evaluate_danger(data):
    """
    Evalúa si la actividad actual merece un email.
    Retorna (is_dangerous: bool, risk_level: str, reasons: list).
    Umbrales calibrados para un VPS real:
    - >=50 intentos SSH en 24h → peligro medio
    - >=200 intentos SSH en 24h → peligro alto
    - >=1 IP con >100 intentos → peligro alto
    - CrowdSec con alertas de brute-force activas → peligro alto
    """
    reasons = []
    risk = "none"

    cutoff = datetime.now() - timedelta(hours=24)
    total_24h = 0
    ip_counts_24h = {}

    for attack in data.get("attacks", []):
        try:
            ts = datetime.fromisoformat(attack["timestamp"])
        except (ValueError, KeyError):
            continue
        if ts >= cutoff:
            total_24h += 1
            ip = attack["ip"]
            ip_counts_24h[ip] = ip_counts_24h.get(ip, 0) + 1

    # Check for high-volume single-IP attack
    top_ip = max(ip_counts_24h.items(), key=lambda x: x[1]) if ip_counts_24h else None
    if top_ip and top_ip[1] >= 100:
        risk = "high"
        reasons.append(f"IP {top_ip[0]} con {top_ip[1]:,} intentos en 24h")
    elif total_24h >= 200:
        risk = "high"
        reasons.append(f"{total_24h:,} intentos SSH totales en 24h")
    elif total_24h >= 50:
        if risk == "none":
            risk = "medium"
        reasons.append(f"{total_24h:,} intentos SSH en 24h")

    # CrowdSec brute-force alerts
    cs_alerts = data.get("crowdsec", {}).get("alerts", [])
    critical_cs = [a for a in cs_alerts if "ssh-bf" in a.get("scenario", "") and "slow" not in a.get("scenario", "")]
    if critical_cs:
        risk = "high"
        reasons.append(f"CrowdSec: {len(critical_cs)} alertas de brute-force SSH activas")
    elif cs_alerts:
        if risk == "none":
            risk = "medium"
        reasons.append(f"CrowdSec: {len(cs_alerts)} alertas activas")

    # UFW high-volume blocking
    ufw_total = data.get("ufw", {}).get("total_blocked", 0)
    if ufw_total >= 5000:
        if risk == "none":
            risk = "medium"
        reasons.append(f"UFW bloqueó {ufw_total:,} conexiones")

    is_dangerous = risk in ("medium", "high")
    return is_dangerous, risk, reasons


def build_email_report(data):
    """
    Construye email de alerta de seguridad.
    Formato: países atacantes + resumen de métodos + qué defensas los pararon.
    NO es por ataque individual — es un resumen consolidado.
    """
    now = datetime.now().strftime("%d %b %Y %H:%M CST")
    s = data["summary"]
    _, risk, reasons = evaluate_danger(data)

    risk_label = {"high": "🔴 RIESGO ALTO", "medium": "🟡 RIESGO MEDIO"}.get(risk, "🟢 INFO")
    lines = []
    lines.append(f"<b>{risk_label} — Actividad de ataque detectada</b>")
    lines.append(f"<code>{now}</code>")
    lines.append("")

    # Motivos del alerta
    lines.append("<b>Por qué se envió este alerta:</b>")
    for r in reasons:
        lines.append(f"  • {r}")
    lines.append("")

    # Resumen numérico
    lines.append("<b>Resumen 24 horas:</b>")
    lines.append(f"  • Intentos SSH: <code>{s['total_ssh_attempts']:,}</code>")
    lines.append(f"  • IPs únicas atacantes: <code>{s['unique_attackers']}</code>")
    lines.append(f"  • Países involucrados: <code>{s['countries_attacking']}</code>")
    lines.append(f"  • IPs baneadas (total histórico): <code>{s['fail2ban_total_banned']}</code>")
    if s.get('crowdsec_alerts'):
        lines.append(f"  • Alertas CrowdSec activas: <code>{s['crowdsec_alerts']}</code>")
    ufw_total = data.get("ufw", {}).get("total_blocked", 0)
    if ufw_total:
        lines.append(f"  • UFW bloqueó: <code>{ufw_total:,}</code> conexiones")
    lines.append("")

    # Lista de países atacantes (TODOS con bandera)
    countries = data.get("countries", [])
    if countries:
        lines.append("<b>Países atacantes:</b>")
        for c in countries:
            flag = cc_to_flag(c.get("code", "??"))
            bar_pct = c.get("percent", 0)
            bar = "█" * max(1, int(bar_pct / 5))
            lines.append(f"  {flag} <b>{c['name']}</b> — <code>{c['attacks']:,}</code> ataques ({bar_pct}%) {bar}")
        lines.append("")

    # Métodos de ataque con explicación
    methods = data.get("methods", [])
    if methods:
        lines.append("<b>Métodos de ataque utilizados:</b>")
        for m in methods:
            method_name = m["method"]
            count = m["count"]
            info = METHOD_INFO.get(method_name, {})
            display_name = info.get("name", method_name)
            desc = info.get("desc", "")
            mitre = info.get("mitre", "")
            lines.append(f"")
            lines.append(f"  🔸 <b>{display_name}</b> — <code>{count:,}</code> veces")
            if desc:
                lines.append(f"     <i>Qué hace:</i> {desc}")
            if mitre:
                lines.append(f"     <i>MITRE ATT&CK:</i> {mitre}")
        lines.append("")

    # Qué defensas lo bloquearon
    lines.append("<b>Defensas que actuaron:</b>")

    f2b = data.get("fail2ban", {})
    if f2b.get("total_banned", 0):
        lines.append(f"  🛡️ <b>fail2ban</b> — Baneó <code>{f2b['total_banned']}</code> IPs en total")
        lines.append(f"     Regla: 5 intentos fallidos → ban 1 hora → logs enviados automáticamente")

    cs_alerts = data.get("crowdsec", {}).get("alerts", [])
    cs_decs = data.get("crowdsec", {}).get("decisions", [])
    if cs_alerts or cs_decs:
        lines.append(f"  🛡️ <b>CrowdSec</b> — {len(cs_alerts)} alertas, {len(cs_decs)} IPs en lista negra activa")
        lines.append(f"     Escenarios detectados: brute-force, user-enum, slow-scan → ban inmediato")

    if ufw_total:
        top_ports = data.get("ufw", {}).get("targeted_ports", [])[:5]
        port_str = ", ".join(f"{p['service']} ({p['count']})" for p in top_ports) if top_ports else ""
        lines.append(f"  🛡️ <b>UFW Firewall</b> — Bloqueó <code>{ufw_total:,}</code> conexiones no autorizadas")
        if port_str:
            lines.append(f"     Puertos más atacados: {port_str}")

    lines.append(f"  🛡️ <b>Tailscale</b> — Acceso admin solo vía VPN privada, no expuesto a internet")
    lines.append("")
    lines.append(f"<b>Dashboard completo:</b> {DASHBOARD_URL}")

    return "\n".join(lines)


def check_alerts(data):
    """Evalúa si hay actividad peligrosa y construye alertas para Telegram."""
    alerts = []
    is_dangerous, risk, reasons = evaluate_danger(data)

    if not is_dangerous:
        return []

    # Build Telegram alert (concise)
    s = data["summary"]
    risk_icon = "🔴" if risk == "high" else "🟡"
    parts = [f"{risk_icon} <b>VPS Security Alert</b>"]
    for r in reasons:
        parts.append(f"  • {r}")
    parts.append("")

    # Countries summary (top 5)
    countries = data.get("countries", [])
    if countries:
        top5 = countries[:5]
        country_str = " | ".join(f"{cc_to_flag(c.get('code','??'))} {c['name']} ({c['attacks']})" for c in top5)
        parts.append(f"<b>Países:</b> {country_str}")

    # Methods summary
    methods = data.get("methods", [])
    if methods:
        method_str = ", ".join(f"{m['method'].replace('SSH ','')}: {m['count']}" for m in methods[:4])
        parts.append(f"<b>Métodos:</b> {method_str}")

    parts.append(f"<b>Defensas:</b> fail2ban {data.get('fail2ban',{}).get('total_banned',0)} bans | CrowdSec {s.get('crowdsec_alerts',0)} alertas | UFW {data.get('ufw',{}).get('total_blocked',0)} bloqueados")
    parts.append(f"<a href='{DASHBOARD_URL}'>Ver dashboard completo</a>")

    alerts.append({
        "text": "\n".join(parts),
        "risk": risk,
    })
    return alerts


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "report"

    if not DATA_FILE.exists():
        print("Data file not found. Run collect_data.py first.", file=sys.stderr)
        sys.exit(1)

    with open(DATA_FILE) as f:
        data = json.load(f)

    if mode == "report":
        # Regular report → Telegram ONLY (no email by default)
        text = format_report(data)
        if len(text) <= 4096:
            send_telegram(text)
            print("Report sent to Telegram", file=sys.stderr)
        else:
            sections = text.split("\n\n")
            chunk = ""
            msg_count = 0
            for section in sections:
                if len(chunk) + len(section) + 2 > 4000:
                    if chunk:
                        send_telegram(chunk)
                        msg_count += 1
                    chunk = section
                else:
                    chunk = chunk + "\n\n" + section if chunk else section
            if chunk:
                send_telegram(chunk)
                msg_count += 1
            print(f"Report sent to Telegram ({msg_count} msgs)", file=sys.stderr)

    elif mode == "alerts":
        alerts = check_alerts(data)
        if not alerts:
            print("No dangerous activity detected — no alert sent", file=sys.stderr)
            return

        for alert in alerts:
            risk = alert.get("risk", "low")
            text = alert["text"]

            can_send, reason = should_send_alert(risk)
            if can_send:
                # Send Telegram alert
                send_telegram(text)
                print(f"Telegram alert sent (risk: {risk})", file=sys.stderr)

                # Send email ONLY for medium/high risk — with full detailed report
                if risk in ("medium", "high"):
                    risk_label = "RIESGO ALTO" if risk == "high" else "RIESGO MEDIO"
                    email_subject = f"[VPS ALERTA {risk_label}] {data['summary']['countries_attacking']} países atacantes"
                    email_body = build_email_report(data)
                    if send_email(email_subject, email_body):
                        print(f"Email alert sent (risk: {risk})", file=sys.stderr)
                    else:
                        print(f"Email send failed", file=sys.stderr)
            else:
                print(f"Alert throttled (risk: {risk}, reason: {reason})", file=sys.stderr)


if __name__ == "__main__":
    main()
