# SATPOL — VPS Security System 🛡️

Sistem keamanan VPS otomatis: **deteksi serangan real-time → auto-ban permanent → notif Telegram**.

> Dibuat untuk Autumn. Satpol PP digital — jagain VPS 24/7, ga ada ampun buat attacker.

## Fitur

- **Deteksi real-time** (scan tiap 5 detik): SQLi, XSS, RCE, SSRF, path traversal, SSH brute-force, scanner, webhook abuse
- **Auto-ban permanent** — 1x percobaan mencurigakan → IP banned selamanya (fail2ban + nftables kernel level)
- **Notif Telegram** — tiap event 1 chat, lengkap: negara asal IP, ISP, vektor, payload, aksi
- **Nginx WAF** — filter payload di level web (429), semua request ke-log
- **Whitelist** — IP lu ga akan pernah ke-ban
- **Geo lookup** — tau attacker dari negara mana + ISP apa
- **Zero LLM** — Python murni, ga butuh AI, ga ada timeout

## Arsitektur

```
Internet → Nginx WAF (:80) → aplikasi lu (127.0.0.1:PORT)
              │  (block payload → 429, log semua request)
              ▼
        satpol-daemon (systemd, scan tiap 5 detik)
              ├── deteksi (19 rule: SQLi/XSS/RCE/SSRF/brute-force)
              ├── auto-ban (fail2ban → nftables, permanent)
              └── notif Telegram (1 chat per event)
```

## Install (VPS Ubuntu/Debian baru)

```bash
# 1. Clone
git clone https://github.com/USERNAME/satpol.git
cd satpol

# 2. Install (interactive — isi IP, whitelist, token Telegram)
sudo ./install.sh

# 3. Selesai — SATPOL langsung jalan
```

Install script bakal:
1. Install dependency (nginx, fail2ban, python3)
2. Setup `/opt/satpol/` + config
3. Pasang nginx WAF (block payload, log semua request)
4. Pasang fail2ban (1x percobaan → ban permanent)
5. Pasang systemd service (auto-restart)
6. Verifikasi semua jalan

## Konfigurasi

Setelah install, konfigurasi ada di:
- `/etc/satpol/env` — Telegram token, chat ID (permission 600, cuma root)
- `/etc/fail2ban/jail.local` — whitelist, maxretry, bantime
- `/etc/nginx/sites-available/sentinel-waf` — rule WAF
- `/opt/satpol/state/` — data runtime (events, strikes, geo cache)

## Perintah

```bash
# Liat status
systemctl status satpol-daemon
journalctl -u satpol-daemon -f    # log real-time

# Liat IP yang ke-ban
fail2ban-client status sshd
fail2ban-client status nginx-waf

# Unban IP (kalau salah ban)
fail2ban-client set sshd unbanip <IP>

# Manual scan sekali
python3 /opt/satpol/sentinel-worker.py --run-once

# Reset state
python3 /opt/satpol/sentinel-worker.py --reset
```

## Rule Deteksi

| Tipe | Severity | CWE | CVSS |
|------|----------|-----|------|
| OS Command Injection | 🔴 Critical | CWE-78 | 9.8 |
| SQL Injection (time-based) | 🔴 Critical | CWE-89 | 9.8 |
| SSRF | 🔴 Critical | CWE-918 | 9.1 |
| SQL Injection | 🔴 Critical | CWE-89 | 8.6 |
| XSS | 🟠 High | CWE-79 | 8.2 |
| LFI/RCE | 🟠 High | CWE-98 | 8.1 |
| Webhook HMAC fail | 🟠 High | CWE-345 | 8.1 |
| SSH Brute-force | 🟠 High | CWE-307 | 7.5 |
| Path Traversal | 🟠 High | CWE-22 | 7.5 |
| DoS Flood | 🟠 High | CWE-400 | 7.5 |
| Deserialization | 🟡 Medium | CWE-502 | 6.5 |
| Config Probe | 🟡 Medium | CWE-200 | 5.3 |
| Scanner/Recon | 🔵 Low | CWE-200 | 3.1 |

Semua severity → **auto-ban permanent** (1x langsung).

## Keamanan

- Token Telegram cuma di `/etc/satpol/env` (600, root only)
- Whitelist IP lu di `jail.local` — ga akan ke-ban
- Zero LLM — ga ada API call ke AI, ga ada timeout, ga ada biaya
- State data cuma di VPS, ga pernah dikirim keluar

## Lisensi

Private — untuk Autumn. Jangan share tanpa izin.
