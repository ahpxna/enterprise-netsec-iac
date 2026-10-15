# Single image for every SOC Python service (inference API, feature worker,
# enrichment worker, decision runner, response orchestrator). Services differ only
# by command and mounted identity; none receives another service's credentials.
FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

# Fixed archive timestamp makes apt resolution reproducible for a given commit.
ARG DEBIAN_SNAPSHOT=20260820T000000Z
RUN rm -f /etc/apt/sources.list.d/debian.sources \
    && printf '%s\n' \
       "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
       "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
       > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && printf '%s\n' \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ bookworm main" \
       "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ bookworm-security main" \
       > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Hash-locked dependencies: pip refuses anything not in the lock.
COPY requirements-soc-service.lock /tmp/requirements-soc-service.lock
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements-soc-service.lock \
    && rm -f /tmp/requirements-soc-service.lock

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin soc \
    && mkdir -p /app /var/lib/soc && chown soc:soc /var/lib/soc && chmod 0700 /var/lib/soc

WORKDIR /app
COPY ai /app/ai
COPY response /app/response
COPY schemas /app/schemas
COPY soc/__init__.py /app/soc/__init__.py
COPY soc/workers /app/soc/workers

ENV PATH=/opt/venv/bin:$PATH PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER soc
