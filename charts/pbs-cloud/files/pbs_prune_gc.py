#!/usr/bin/env python3
# NOTE: Keep this file in sync with scripts/pbs_prune_gc.py
import argparse
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request


def env(name, default=None):
    value = os.getenv(name)
    return default if value is None or value == "" else value


def parse_bool(value, default=False):
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def request_json(method, url, data=None, headers=None, ctx=None):
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = json.dumps(data).encode("utf-8")
        elif isinstance(data, str):
            body = data.encode("utf-8")
        else:
            body = data
    req = urllib.request.Request(url, data=body, method=method)
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def login(base_url, username, password, ctx):
    payload = urllib.parse.urlencode({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/api2/json/access/ticket", data=payload, method="POST")
    with urllib.request.urlopen(req, context=ctx) as resp:
        data = json.loads(resp.read().decode("utf-8")).get("data", {})
    ticket = data.get("ticket")
    csrf = data.get("CSRFPreventionToken")
    if not ticket or not csrf:
        raise RuntimeError("Failed to get ticket/CSRF token")
    cookie = f"PBSAuthCookie={urllib.parse.quote(ticket)}"
    return {"Cookie": cookie, "CSRFPreventionToken": csrf, "Content-Type": "application/json"}


def main():
    parser = argparse.ArgumentParser(description="Prune all backup groups, then run GC.")
    parser.add_argument("--url", default=env("PBS_URL", "https://localhost:8007"))
    parser.add_argument("--username", default=env("PBS_USERNAME", "root@pam"))
    parser.add_argument("--password", default=env("PBS_PASSWORD"))
    parser.add_argument("--password-file", default=env("PBS_PASSWORD_FILE"))
    parser.add_argument("--api-token", default=env("PBS_API_TOKEN"))
    parser.add_argument("--store", default=env("PBS_STORE", "default"))
    parser.add_argument("--dry-run", action="store_true", default=parse_bool(env("PBS_DRY_RUN")))
    parser.add_argument("--keep-last", type=int, default=env("PBS_KEEP_LAST"))
    parser.add_argument("--keep-daily", type=int, default=env("PBS_KEEP_DAILY"))
    parser.add_argument("--keep-weekly", type=int, default=env("PBS_KEEP_WEEKLY"))
    parser.add_argument("--keep-monthly", type=int, default=env("PBS_KEEP_MONTHLY"))
    parser.add_argument("--keep-yearly", type=int, default=env("PBS_KEEP_YEARLY"))
    parser.add_argument("--insecure", action="store_true", default=parse_bool(env("PBS_INSECURE", "1")))
    args = parser.parse_args()

    ctx = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
    headers = {}

    if args.api_token:
        headers["Authorization"] = f"Bearer {args.api_token}"
        headers["Content-Type"] = "application/json"
    else:
        password = args.password
        if not password and args.password_file:
            with open(args.password_file, "r") as f:
                password = f.read().strip()
        if not password:
            raise SystemExit("PBS_PASSWORD or PBS_PASSWORD_FILE is required when PBS_API_TOKEN is not set.")
        headers = login(args.url.rstrip("/"), args.username, password, ctx)

    base = args.url.rstrip("/")
    groups = request_json(
        "GET",
        f"{base}/api2/json/admin/datastore/{args.store}/groups?limit=200",
        headers={"Cookie": headers.get("Cookie", ""), "Authorization": headers.get("Authorization", "")},
        ctx=ctx,
    ).get("data", [])

    print(f"Groups found: {len(groups)}")

    for group in groups:
        backup_type = group.get("backup-type")
        backup_id = group.get("backup-id")
        ns = group.get("ns")
        if not backup_type or not backup_id:
            continue
        payload = {"backup_type": backup_type, "backup_id": backup_id, "dry_run": args.dry_run}
        if ns:
            payload["ns"] = ns
        if args.keep_last is not None:
            payload["keep_last"] = int(args.keep_last)
        if args.keep_daily is not None:
            payload["keep_daily"] = int(args.keep_daily)
        if args.keep_weekly is not None:
            payload["keep_weekly"] = int(args.keep_weekly)
        if args.keep_monthly is not None:
            payload["keep_monthly"] = int(args.keep_monthly)
        if args.keep_yearly is not None:
            payload["keep_yearly"] = int(args.keep_yearly)

        request_json(
            "POST",
            f"{base}/api2/json/admin/datastore/{args.store}/prune",
            data=payload,
            headers=headers,
            ctx=ctx,
        )
        print(f"Prune triggered: {backup_type}/{backup_id} ns={ns or 'root'}")

    request_json(
        "POST",
        f"{base}/api2/json/admin/datastore/{args.store}/gc",
        data={},
        headers=headers,
        ctx=ctx,
    )
    print("GC triggered")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise
