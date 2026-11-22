#!/usr/bin/env python3
"""Stream a completed Windows IDS JSONL scan into TagEngine without buffering it in RAM.

Required environment:
  ENTEC_API_TOKEN   Bearer token configured on TagEngine
Optional environment:
  TAGENGINE_URL     Default: http://127.0.0.1:3000
  BEAN_VOLUME_ID    Default: COMPUTERNAME (or hostname)
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit


def upload_once(file_path: Path, base_url: str, token: str, volume_id: str,
                label: str, scan_id: str, timeout: int) -> tuple[int, str]:
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("TAGENGINE_URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("TAGENGINE_URL must not contain credentials, query, or fragment")
    local_http = parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if parsed.scheme != "https" and not local_http:
        raise ValueError("HTTP is permitted only for loopback TagEngine; use HTTPS remotely")

    endpoint = (parsed.path.rstrip("/") + "/api/ids/ingest") or "/api/ids/ingest"
    if parsed.scheme == "https":
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                           timeout=timeout, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)

    size = file_path.stat().st_size
    try:
        conn.putrequest("POST", endpoint)
        conn.putheader("Authorization", "Bearer " + token)
        conn.putheader("Content-Type", "application/x-ndjson")
        conn.putheader("Content-Length", str(size))
        conn.putheader("X-Scan-ID", scan_id)
        conn.putheader("X-Volume-ID", volume_id)
        conn.putheader("X-Scan-Label", label)
        conn.endheaders()
        with file_path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                conn.send(chunk)
        response = conn.getresponse()
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl", required=True, help="Completed scanner JSONL output file")
    parser.add_argument("--url", default=os.environ.get("TAGENGINE_URL", "http://127.0.0.1:3000"))
    parser.add_argument("--volume-id", default=os.environ.get("BEAN_VOLUME_ID") or
                        os.environ.get("COMPUTERNAME") or socket.gethostname())
    parser.add_argument("--label", default="Windows IDS scan")
    parser.add_argument("--scan-id", default=str(uuid.uuid4()))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    token = os.environ.get("ENTEC_API_TOKEN", "").strip()
    if not token:
        parser.error("ENTEC_API_TOKEN is required")
    source = Path(args.jsonl).expanduser().resolve()
    if not source.is_file():
        parser.error(f"JSONL file not found: {source}")
    if source.stat().st_size == 0:
        parser.error("JSONL file is empty")
    if not args.volume_id.strip() or len(args.volume_id) > 128:
        parser.error("--volume-id must contain 1-128 characters")
    if not 1 <= args.timeout <= 3600:
        parser.error("--timeout must be from 1 to 3600 seconds")

    last_error = None
    for attempt in range(1, 4):
        try:
            status, body = upload_once(source, args.url, token, args.volume_id,
                                       args.label, args.scan_id, args.timeout)
            if 200 <= status < 300:
                try:
                    result = json.loads(body)
                except json.JSONDecodeError:
                    print(body)
                    return 1
                print(json.dumps(result, indent=2))
                return 0
            if status < 500 and status != 409:
                print(f"TagEngine rejected the scan (HTTP {status}): {body}", file=sys.stderr)
                return 1
            last_error = f"HTTP {status}: {body}"
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            last_error = str(exc)
        if attempt < 3:
            time.sleep(2 ** attempt)

    print(f"TagEngine upload failed after 3 attempts: {last_error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
