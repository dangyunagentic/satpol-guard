#!/usr/bin/env bash
# ============================================================
# SATPOL — VPS Security System Installer
# Deploy otomatis: nginx WAF + deteksi + auto-ban + Telegram
# ============================================================
set -e

echo "🛡️  SATPOL INSTALLER"
echo "======================"

# --- Cek root ---
if [[ $EUID -ne 0 ]]; then
    echo "❌ Jalanin sebagai root: sudo ./install.sh"
    exit 1
fi

# --- Deteksi OS ---
if ! grep -qiE "ubuntu|debian" /etc/os-release; then
    echo "⚠️  SATPOL dioptimasi buat Ubuntu/Debian. Lanjut? (y/n)"
    read -r ans
    [[ "$ans" != "y" ]] && exit 1
fi

# --- Input konfigurasi ---
echo ""
echo "Masukkan konfigurasi SATPOL (Enter = default):"
echo ""

# VPS IP (default: IP publik sendiri)
VPS_IP_DEFAULT=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "0.0.0.0")
read -rp "IP VPS ini [$VPS_IP_DEFAULT]: " VPS_IP
VPS_IP=${VPS_IP:-$VPS_IP_DEFAULT}

# Whitelist (IP yang ga akan pernah di-ban — IP rumah/kantor lu)
read -rp "Whitelist IP 1 (IP lu, kosongin kalau ga ada): " WL1
read -rp "Whitelist IP 2 (opsional): " WL2
read -rp "Whitelist IP 3 (opsional): " WL3

# Port backend aplikasi (default: web 8080, api 3001)
read -rp "Port web app (backend, di belakang WAF) [8080]: " WEB_PORT
WEB_PORT=${WEB_PORT:-8080}
read -rp "Port API app [3001]: " API_PORT
API_PORT=${API_PORT:-3001}

# Telegram
read -rp "Telegram Bot Token: " TG_TOKEN
read -rp "Telegram Chat ID (tujuan notif): " TG_CHAT
read -rp "Telegram Thread ID (opsional, kalau pake forum topic): " TG_THREAD

# --- Validasi minimal ---
if [[ -z "$TG_TOKEN" || -z "$TG_CHAT" ]]; then
    echo "❌ Token & Chat ID wajib diisi"
    exit 1
fi

echo ""
echo "=== 1/6 Install dependency ==="
apt-get update -qq
apt-get install -y -qq curl nginx fail2ban python3 python3-pip >/dev/null 2>&1

echo "=== 2/6 Setup direktori ==="
mkdir -p /opt/satpol/state /etc/satpol
cp sentinel-worker.py /opt/satpol/sentinel-worker.py
chmod +x /opt/satpol/sentinel-worker.py

echo "=== 3/6 Konfigurasi (ganti placeholder) ==="
# Siapkan jail.local dengan whitelist
sed -e "s|{{VPS_IP}}|$VPS_IP|g" \
    -e "s|{{WHITELIST_1}}|${WL1:-127.0.0.1}|g" \
    -e "s|{{WHITELIST_2}}|${WL2:-}|g" \
    -e "s|{{WHITELIST_3}}|${WL3:-}|g" \
    config/jail.local > /etc/fail2ban/jail.local

# Filter nginx
cp config/nginx-sentinel.conf /etc/fail2ban/filter.d/nginx-sentinel.conf

# Nginx WAF (ganti port backend)
sed -e "s|{{WEB_PORT}}|$WEB_PORT|g" \
    -e "s|{{API_PORT}}|$API_PORT|g" \
    config/sentinel-waf > /etc/nginx/sites-available/sentinel-waf
ln -sf /etc/nginx/sites-available/sentinel-waf /etc/nginx/sites-enabled/sentinel-waf
# Hapus default site biar ga konflik
rm -f /etc/nginx/sites-enabled/default

# Env (token, chat) — permission 600, cuma root yang bisa baca
cat > /etc/satpol/env <<EOF
TELEGRAM_BOT_TOKEN=$TG_TOKEN
TELEGRAM_SENTINEL_CHAT=$TG_CHAT
TELEGRAM_SENTINEL_THREAD=$TG_THREAD
EOF
chmod 600 /etc/satpol/env

echo "=== 4/6 Setup systemd service ==="
sed "s|{{VPS_IP}}|$VPS_IP|g" config/sentinel-daemon.service > /etc/systemd/system/satpol-daemon.service
systemctl daemon-reload
systemctl enable satpol-daemon

echo "=== 5/6 Start layanan ==="
systemctl restart fail2ban
systemctl restart nginx
systemctl start satpol-daemon

echo "=== 6/6 Verifikasi ==="
sleep 3
if systemctl is-active --quiet satpol-daemon; then
    echo "✅ SATPOL daemon: ACTIVE"
else
    echo "❌ SATPOL daemon: GAGAL — cek journalctl -u satpol-daemon"
fi
if nginx -t 2>/dev/null; then
    echo "✅ Nginx WAF: VALID"
else
    echo "❌ Nginx config error — cek /etc/nginx/sites-available/sentinel-waf"
fi
echo "✅ fail2ban: $(fail2ban-client status 2>/dev/null | grep 'Jail list' || echo 'check manual')"
echo ""
echo "🎉 SATPOL TERPASANG!"
echo "   - Web WAF: http://$VPS_IP (block SQLi/XSS/RCE → 429)"
echo "   - Notif: Telegram ke chat $TG_CHAT"
echo "   - Log: journalctl -u satpol-daemon -f"
echo ""
echo "⚠️  PENTING: pastikan port 80 & 22 kebuka di firewall VPS lu (ufw/cloud security group)"
