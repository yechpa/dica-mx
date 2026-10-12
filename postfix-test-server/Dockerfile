FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

# postfix: le MTA de test
# mailutils: pour lire le courrier livre localement (commande `mail`)
# rsyslog: postfix log vers /var/log/mail.log via syslog
RUN apt-get update && apt-get install -y --no-install-recommends \
        postfix \
        mailutils \
        rsyslog \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25

ENTRYPOINT ["/entrypoint.sh"]
