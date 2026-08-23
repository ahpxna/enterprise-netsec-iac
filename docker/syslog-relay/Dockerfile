FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       rsyslog rsyslog-gnutls \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/cxyz

COPY rsyslog.conf /etc/rsyslog.conf
EXPOSE 6514/tcp
CMD ["/usr/sbin/rsyslogd", "-n"]
