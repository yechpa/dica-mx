#!/bin/bash
set -e

MAIL_DOMAIN="${MAIL_DOMAIN:-labdomain.test}"
TEST_USER="${TEST_USER:-test}"
OPEN_RELAY="${OPEN_RELAY:-false}"   # "true" pour simuler un relais ouvert (test du cas RISQUE)

echo "[entrypoint] domaine de test : ${MAIL_DOMAIN}"
echo "[entrypoint] boite interne   : ${TEST_USER}@${MAIL_DOMAIN}"
echo "[entrypoint] relais ouvert   : ${OPEN_RELAY}"

# --- identite du serveur -------------------------------------------------
postconf -e "myhostname = mail.${MAIL_DOMAIN}"
postconf -e "mydomain = ${MAIL_DOMAIN}"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"

# --- journaux verbeux, utiles pour lire les codes SMTP exacts ------------
postconf -e "smtpd_banner = \$myhostname ESMTP (lab DICA-MX, non-production)"
postconf -e "disable_vrfy_command = no"

# --- comportement relais --------------------------------------------------
# On garde toujours la meme clause de restriction : Postfix moderne refuse
# de demarrer smtpd si smtpd_relay_restrictions ne se termine pas par une
# clause de securite reconnue (defer_unauth_destination, reject_unauth_
# destination, etc.) -- un simple "permit" final est rejete au demarrage.
#
# Par defaut (OPEN_RELAY=false) : comportement standard d'un Postfix
# "Internet Site" fraichement installe -> relais refuse pour toute
# destination hors mydestination (code 454/554 Relay access denied).
#
# OPEN_RELAY=true : on elargit mynetworks a 0.0.0.0/0, donc
# permit_mynetworks matche systematiquement avant d'atteindre la clause de
# refus -> relais effectivement ouvert, pour valider que bdika_mx.py
# detecte bien le cas RISQUE sur le test de relais.
postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination"
if [ "${OPEN_RELAY}" = "true" ]; then
    postconf -e "mynetworks = 0.0.0.0/0"
else
    postconf -e "mynetworks = 127.0.0.0/8, [::1]/128"
fi

# --- boite interne de controle --------------------------------------------
id -u "${TEST_USER}" >/dev/null 2>&1 || useradd -m "${TEST_USER}"

# --- demarrage -------------------------------------------------------------
rsyslogd
postfix start-fg &
PID=$!

# tail du log pour voir les transactions SMTP en direct dans `docker compose logs`
touch /var/log/mail.log
tail -F /var/log/mail.log &

wait "$PID"
