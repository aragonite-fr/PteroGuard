#!/bin/sh
# Installe ou met à jour ptero-guard (à lancer avec sudo).
set -e
cd "$(dirname "$0")"
install -d -m 755 /opt/ptero-guard
install -d -m 700 /etc/ptero-guard /var/lib/ptero-guard /var/log/ptero-guard
install -m 755 ptero_guard.py /opt/ptero-guard/ptero_guard.py
[ -f /etc/ptero-guard/config.toml ] || install -m 600 config.toml /etc/ptero-guard/config.toml
[ -f /etc/ptero-guard/webhook ] || install -m 600 /dev/null /etc/ptero-guard/webhook
ln -sf /opt/ptero-guard/ptero_guard.py /usr/local/bin/ptero-guard
install -m 644 ptero-guard.service /etc/systemd/system/ptero-guard.service
cat > /etc/logrotate.d/ptero-guard <<'R'
/var/log/ptero-guard/alertes.jsonl {
    monthly
    rotate 12
    compress
    missingok
    notifempty
    copytruncate
}
R
systemctl daemon-reload
systemctl enable ptero-guard
systemctl restart ptero-guard
systemctl --no-pager status ptero-guard | head -5
