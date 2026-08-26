FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       rsyslog rsyslog-gnutls \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/log/cxyz

COPY rsyslog.conf /etc/rsyslog.conf
EXPOSE 6514/tcp
CMD ["/usr/sbin/rsyslogd", "-n"]
