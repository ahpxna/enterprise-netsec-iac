FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG DEBIAN_SNAPSHOT=20260820T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
       > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       rsyslog rsyslog-gnutls \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/cxyz

COPY rsyslog.conf /etc/rsyslog.conf
EXPOSE 6514/tcp
CMD ["/usr/sbin/rsyslogd", "-n"]
