"""Private, mutual-TLS entrypoint: python -m ai.api.serve."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import socket
import ssl


def main() -> None:
    import uvicorn

    host = os.environ.get("SOC_AI_BIND", "127.0.0.1")
    if host == "container-address":
        # Single-network container: bind the one private address Docker assigned.
        host = socket.gethostbyname(socket.gethostname())
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast or not address.is_private:
        raise SystemExit("SOC_AI_BIND must be an explicit private or loopback IP")
    names = ("SOC_AI_SERVER_CERT", "SOC_AI_SERVER_KEY", "SOC_AI_CLIENT_CA")
    files = {}
    for name in names:
        path = Path(os.environ[name])
        if not path.is_file():
            raise SystemExit(f"missing {name}")
        files[name] = str(path)
    if not os.environ.get("SOC_AI_METADATA_SHA256"):
        raise SystemExit("SOC_AI_METADATA_SHA256 deployment approval is required")
    uvicorn.run(
        "ai.api.main:app", host=host, port=int(os.environ.get("SOC_AI_PORT", "8443")),
        ssl_certfile=files["SOC_AI_SERVER_CERT"],
        ssl_keyfile=files["SOC_AI_SERVER_KEY"],
        ssl_ca_certs=files["SOC_AI_CLIENT_CA"], ssl_cert_reqs=ssl.CERT_REQUIRED,
        proxy_headers=False, access_log=False, limit_concurrency=32,
    )


if __name__ == "__main__":
    main()
