FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       chrony dnsmasq dnsutils freeradius freeradius-utils iproute2 \
       netcat-openbsd openssh-server python3 rsyslog rsyslog-gnutls \
       supervisor tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log/supervisor /etc/ssh/sshd_config.d

COPY supervisord.conf /etc/supervisor/conf.d/cxyz.conf

EXPOSE 22/tcp 53/tcp 53/udp 123/udp 1812/udp 1813/udp
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
