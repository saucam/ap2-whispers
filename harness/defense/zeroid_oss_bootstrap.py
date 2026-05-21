#!/usr/bin/env python3
"""Bootstrap a standalone ZeroID instance for the AP2 Whispers OSS measurement.

Creates:
  1. The identity for `ap2-session-bugsbunny` (the AP2 demo's named login,
     SPIFFE-safe form).
  2. An OAuth2 confidential client linked to that identity, with
     grant_type=client_credentials and scope=account:read. The client_id
     equals the identity's external_id (zeroid binds them by that).
  3. Writes ./zeroid_oss_client.env -- KEY=VALUE for
     client_id / client_secret / account_id / project_id, sourced by the
     AP2 harness.

Idempotent. Uses only the public ZeroID HTTP API. No internal-service secrets.
"""

import json
import os
import sys
import urllib.error
import urllib.request

BASE = "http://localhost:8899"
ADMIN = BASE + "/api/v1"
ACCT = "ap2demo"
PROJ = "ap2"
EXT_ID = "ap2-session-bugsbunny"
TENANT_HDR = {
    "X-Account-ID": ACCT,
    "X-Project-ID": PROJ,
    "Content-Type": "application/json",
}


def _req(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def ensure_identity():
    body = {
        "external_id": EXT_ID,
        "name": "AP2 session principal " + EXT_ID,
        "identity_type": "service",
        "owner_user_id": EXT_ID,
    }
    st, resp = _req("POST", ADMIN + "/identities", TENANT_HDR, body)
    if st in (200, 201) and isinstance(resp, dict) and resp.get("id"):
        sys.stderr.write("[bootstrap] created identity " + resp["id"] + "\n")
        return resp["id"]
    st2, resp2 = _req(
        "GET", ADMIN + "/identities?search=" + EXT_ID + "&limit=50", TENANT_HDR
    )
    items = resp2.get("identities") or resp2.get("items") or resp2.get("data") or []
    for it in items:
        if it.get("external_id") == EXT_ID:
            sys.stderr.write("[bootstrap] reusing existing identity " + it["id"] + "\n")
            return it["id"]
    raise SystemExit(
        "could not ensure identity: create=%s/%s  lookup=%s/%s"
        % (st, resp, st2, resp2)
    )


def ensure_client(identity_id):
    body = {
        "client_id": EXT_ID,
        "name": "AP2 session client " + EXT_ID,
        "description": "client_credentials client for AP2 v1 creds-provider session binding.",
        "confidential": True,
        "token_endpoint_auth_method": "client_secret_basic",
        "grant_types": ["client_credentials"],
        "scopes": ["account:read"],
        "access_token_ttl": 900,
        "identity_id": identity_id,
    }
    st, resp = _req("POST", ADMIN + "/oauth/clients", TENANT_HDR, body)
    if st in (200, 201) and isinstance(resp, dict):
        secret = resp.get("client_secret") or (resp.get("body") or {}).get("client_secret")
        if secret:
            sys.stderr.write("[bootstrap] created OAuth client " + EXT_ID + "\n")
            return secret
    if st == 409:
        st2, resp2 = _req("GET", ADMIN + "/oauth/clients", TENANT_HDR)
        cid_uuid = None
        for c in resp2.get("clients") or []:
            if c.get("client_id") == EXT_ID:
                cid_uuid = c.get("id")
                break
        if not cid_uuid:
            raise SystemExit("client " + EXT_ID + " 409 but not in list")
        st3, resp3 = _req(
            "POST", ADMIN + "/oauth/clients/" + cid_uuid + "/rotate-secret",
            TENANT_HDR, {},
        )
        secret = resp3.get("client_secret") or (resp3.get("body") or {}).get("client_secret")
        if not secret:
            raise SystemExit("rotate-secret returned no client_secret: %s/%s" % (st3, resp3))
        sys.stderr.write("[bootstrap] rotated secret for existing client " + EXT_ID + "\n")
        return secret
    raise SystemExit("oauth client register failed: %s/%s" % (st, resp))


def main():
    identity_id = ensure_identity()
    secret = ensure_client(identity_id)
    out_path = os.environ.get("AP2_ZEROID_OSS_CLIENT_ENV", "./zeroid_oss_client.env")
    out = (
        "AP2_ZEROID_OSS_BASE=http://localhost:8899\n"
        "AP2_ZEROID_OSS_ACCOUNT=" + ACCT + "\n"
        "AP2_ZEROID_OSS_PROJECT=" + PROJ + "\n"
        "AP2_ZEROID_OSS_CLIENT_ID=" + EXT_ID + "\n"
        "AP2_ZEROID_OSS_CLIENT_SECRET=" + secret + "\n"
        "AP2_ZEROID_OSS_PRINCIPAL=bugsbunny@gmail.com\n"
    )
    with open(out_path, "w") as f:
        f.write(out)
    os.chmod(out_path, 0o600)
    print("wrote " + out_path)
    print(out)


if __name__ == "__main__":
    main()
