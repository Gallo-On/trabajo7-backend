#!/bin/sh
set -eu

mkdir -p /var/log/backend /var/log/fail2ban /var/run/fail2ban
touch /var/log/backend/access.log /var/log/backend/auth-failures.log /var/log/fail2ban.log
rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid

python /app/app.py >> /var/log/backend/access.log 2>&1 &
fail2ban-client -x start

exec tail -F /var/log/backend/access.log /var/log/backend/auth-failures.log /var/log/fail2ban.log