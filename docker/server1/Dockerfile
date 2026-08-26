FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

# Fixed archive timestamp makes apt resolution reproducible for a given commit.
ARG DEBIAN_SNAPSHOT=20260820T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm-updates main" \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
       > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       dnsmasq dnsutils freeradius freeradius-utils iproute2 \
       netcat-openbsd openssh-server python3 rsyslog rsyslog-gnutls \
       supervisor tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log/supervisor /etc/ssh/sshd_config.d

COPY supervisord.conf /etc/supervisor/conf.d/cxyz.conf

EXPOSE 22/tcp 53/tcp 53/udp 1812/udp 1813/udp
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
