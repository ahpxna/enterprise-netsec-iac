#!/usr/bin/env python3
"""Create/refresh the least-privilege Wazuh API identity used by the orchestrator.

Run INSIDE the manager container (``make soc-ai-wazuh-user``): it reads the
administrator API credentials from the container's own environment and the new
identity's password from ``RESPONSE_API_PASSWORD``.  The identity may only run
Active Response commands, read agents and read FIM data - it cannot read alerts,
manage users, or change configuration.  TLS is verified against the Wazuh root CA.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

BASE = "https://wazuh.manager:55000"
CA = "/etc/ssl/root-ca.pem"
USER = "cxyz-response"
POLICY_NAME, ROLE_NAME = "cxyz-response-policy", "cxyz-response-role"
POLICY = {
    "actions": ["active-response:command", "agent:read", "syscheck:read"],
    "resources": ["agent:id:*"],
    "effect": "allow",
}
CONTEXT = ssl.create_default_context(cafile=CA)


def call(method: str, path: str, token: str | None = None, body: dict | None = None,
         basic: tuple[str, str] | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(":".join(basic).encode()).decode()
    elif token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        BASE + path, method=method, headers=headers,
        data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(request, context=CONTEXT, timeout=20) as reply:
            return json.load(reply)
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{method} {path} failed with HTTP {exc.code}") from None


def find(token: str, collection: str, field: str, value: str) -> dict | None:
    items = call("GET", f"/security/{collection}?limit=500", token)["data"]["affected_items"]
    return next((item for item in items if item.get(field) == value), None)


def main() -> int:
    password = os.environ.get("RESPONSE_API_PASSWORD", "")
    if len(password) < 12:
        print("RESPONSE_API_PASSWORD must be supplied (>= 12 characters)", file=sys.stderr)
        return 2
    token = call("POST", "/security/user/authenticate", basic=(os.environ["API_USERNAME"], os.environ["API_PASSWORD"]))["data"]["token"]
    policy = find(token, "policies", "name", POLICY_NAME) or call(
        "POST", "/security/policies", token, {"name": POLICY_NAME, "policy": POLICY})["data"]["affected_items"][0]
    role = find(token, "roles", "name", ROLE_NAME) or call(
        "POST", "/security/roles", token, {"name": ROLE_NAME})["data"]["affected_items"][0]
    if policy["id"] not in role.get("policies", []):
        call("POST", f"/security/roles/{role['id']}/policies?policy_ids={policy['id']}", token)
    user = find(token, "users", "username", USER)
    if user is None:
        user = call("POST", "/security/users", token, {"username": USER, "password": password})["data"]["affected_items"][0]
    else:
        call("PUT", f"/security/users/{user['id']}", token, {"password": password})
    if role["id"] not in user.get("roles", []):
        call("POST", f"/security/users/{user['id']}/roles?role_ids={role['id']}", token)
    print(f"Wazuh API identity {USER} is provisioned with role {ROLE_NAME} (password not shown)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
