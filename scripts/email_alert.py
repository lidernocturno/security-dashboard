#!/usr/bin/env python3
"""Email alert — sends alerts via Gmail SMTP to both email addresses."""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import html
import re

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
EMAIL_TO = os.environ.get("EMAIL_TO", "").split(",")


def strip_html(text):
    """Convert HTML to plain text for email."""
    text = re.sub(r'<b>(.*?)</b>', r'*\1*', text)
    text = re.sub(r'<i>(.*?)</i>', r'\1', text)
    text = re.sub(r'<code>(.*?)</code>', r'\1', text)
    text = re.sub(r'<a href=["\']([^"\']*)["\']>([^<]*)</a>', r'\2 (\1)', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    return text


def wrap_html(body_html):
    """Wrap Telegram-style HTML into a proper email HTML document."""
    # Convert Telegram HTML tags to proper email HTML
    body = body_html
    # Convert newlines to <br>
    body = body.replace("\n", "<br>\n")

    # Gmail strips <style> tags — must use inline styles + table for black background
    # Replace Telegram HTML tags with styled versions
    body = re.sub(r'<b>(.*?)</b>', r'<b style="color:#00ccff;">\1</b>', body)
    body = re.sub(r'<code>(.*?)</code>', r'<code style="background:#1a1a1a;color:#00ff88;padding:2px 5px;border-radius:3px;font-family:monospace;">\1</code>', body)
    body = re.sub(r'<i>(.*?)</i>', r'<i style="color:#888888;">\1</i>', body)
    body = re.sub(r'<a href=', r'<a style="color:#4488ff;" href=', body)

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background-color:#000000;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#000000;">
<tr><td align="center" style="padding:20px 10px;">
<table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color:#000000;border:1px solid #333333;border-radius:8px;">

<tr><td style="background-color:#0d0d0d;padding:16px;text-align:center;border-bottom:2px solid #ff4444;border-radius:8px 8px 0 0;">
  <span style="color:#ff4444;font-family:monospace;font-size:18px;font-weight:bold;">VPS SECURITY ALERT</span>
</td></tr>

<tr><td style="background-color:#000000;padding:20px;color:#e0e0e0;font-family:'Courier New',monospace;font-size:14px;line-height:1.6;">
{body}
</td></tr>

<tr><td style="background-color:#0d0d0d;padding:12px;text-align:center;border-top:1px solid #333333;border-radius:0 0 8px 8px;">
  <span style="color:#555555;font-family:monospace;font-size:11px;">your-vps-hostname.example.com | Security Dashboard</span>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def send_email(subject, body_html):
    """Send email alert via Gmail SMTP. Returns True on success."""
    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"VPS Alertas <{SMTP_USER}>"
        msg["To"] = ", ".join(EMAIL_TO)
        msg["Subject"] = f"[VPS] {subject}"

        plain = strip_html(body_html)
        full_html = wrap_html(body_html)

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(full_html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, EMAIL_TO, msg.as_string())
        return True
    except Exception as e:
        print(f"Email error: {e}", file=__import__('sys').stderr)
        return False
