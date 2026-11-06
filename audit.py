#!/usr/bin/env python3
"""Audit GET /api/anchors against the third parties its own contract names.

Keyless, read-only. Three legs, three checks:

  base     read the tx on a Base node, decode input as UTF-8, compare to payload
  ots      recompute sha256(payload) and find it inside the served .ots proof
  archive  fetch the capture the row cites and compare it to the row's payload

Controls (the point of the exercise):
  control 0  a KNOWN-GOOD base row must PASS. If the subject cannot succeed,
             every later verdict is a statement about the harness.
  control 1  a payload with one byte changed must FAIL the ots digest check.
  control 2  two rows citing one capture with different payloads cannot both
             be right; that is arithmetic, not a network call.

Every finding this script prints has a control above it that would have caught
the script lying.
"""

import argparse
import datetime
import gzip
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

API = "https://1f916.ai/api"
RPC = "https://mainnet.base.org"
UA = "citizen01-anchor-audit/1.0 (read-only; no key)"
MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00"
OTS_SHA256 = b"\x08"

failures = []


def note(ok, label, detail=""):
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(label)
    return ok


def fetch(url, tries=4, binary=False):
    """Fetch with backoff. Returns bytes, or None when the party is unreachable."""
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in (429, 502, 503):
                time.sleep(3 * (i + 1))
                continue
            return None
        except Exception as e:  # noqa: BLE001
            last = type(e).__name__
            time.sleep(2 * (i + 1))
    print(f"    (unreachable after {tries} tries: {url} — {last})")
    return None


def getj(url):
    raw = fetch(url)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={
        "Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.load(r)


def ts(ms):
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.UTC) \
        .strftime("%Y-%m-%d %H:%M:%SZ")


def walk_anchors(max_pages=12, backwards=True):
    """Walk the table.

    backwards=True starts at the newest row (the current state, which is what a
    reader acts on). backwards=False starts at id 1 (the early era, which is
    where the controls live). The two are not interchangeable: a control that
    passes on 2026-09-25 says nothing about a leg that broke on 2026-11-06.
    """
    rows = []
    if backwards:
        d0 = getj(f"{API}/anchors")
        if not d0:
            return []
        head = d0.get("head_id")
        url = f"{API}/anchors?before_id={head}" if head else f"{API}/anchors"
    else:
        url = f"{API}/anchors"
    for _ in range(max_pages):
        d = getj(url)
        if not d or "anchors" not in d:
            break
        rows += d["anchors"]
        if not d.get("has_more"):
            break
        if backwards:
            nxt = d.get("next_before_id") or min(r["id"] for r in d["anchors"])
            url = f"{API}/anchors?before_id={nxt}"
        else:
            nxt = d.get("next_since_id")
            if not nxt:
                break
            url = f"{API}/anchors?since_id={nxt}"
        time.sleep(1.0)
    return sorted(rows, key=lambda r: r["id"])


# ---------------------------------------------------------------- base leg

def base_tx(checkpoint_root, base_address=None):
    """Read a Base tx used as an anchor: returns (payload_text, block_number)."""
    tx = checkpoint_root
    a = rpc("eth_getTransactionByHash", [tx])["result"]
    if not a:
        return None, None
    raw = bytes.fromhex(a["input"][2:]).decode("utf-8", "replace")
    return raw, int(a["blockNumber"], 16)


def check_base(rows, control_rows=None, sample=3):
    print("\n== base leg: tx input must decode to the row's payload ==")
    ctrl = control_rows if control_rows is not None else rows
    confirmed = [r for r in rows if r["kind"] == "base" and r["status"] == "confirmed"]
    failed = [r for r in rows if r["kind"] == "base" and r["status"] == "failed"]

    # control 0: an OLD confirmed row is the subject. It must succeed. This is
    # deliberately taken from the early era, because a verifier that cannot
    # reproduce a row the chain itself confirms is not measuring the writer.
    ctrl_confirmed = [r for r in ctrl if r["kind"] == "base" and r["status"] == "confirmed"]
    if ctrl_confirmed:
        c = min(ctrl_confirmed, key=lambda r: r["id"])
        payload, block = base_tx(c["target"])
        if payload is None:
            note(False, "control 0: subject reachable",
                 "Base RPC returned nothing; every verdict below is uninformative")
            return
        note(payload == c["payload"], "control 0: oldest confirmed row reproduces",
             f"row {c['id']} block {block}")
        if payload != c["payload"]:
            print("    ABORT: the verifier cannot reproduce a known-good row.")
            return

    # the actual check, on a sample of recent confirmed rows
    recent = sorted(confirmed, key=lambda r: -r["id"])[:sample]
    for r in recent:
        payload, block = base_tx(r["target"])
        note(payload == r["payload"], f"base row {r['id']} input == payload",
             f"block {block}")

    # the stall. Only meaningful on the recent window.
    if failed:
        first = min(failed, key=lambda r: r["id"])
        lines = (first.get("error") or "").splitlines()
        status_line = next((l for l in lines if "Status:" in l), "") or (lines[0] if lines else "?")
        print(f"\n  stalled: {len(failed)} failed base rows, "
              f"first at {ts(first['created_at'])}")
        print(f"  error: {status_line.strip()}")
        tail = 0
        for r in sorted([x for x in rows if x["kind"] == "base"], key=lambda r: -r["id"]):
            if r["status"] != "failed":
                break
            tail += 1
        note(tail > 1, "base leg is failing repeatedly (not a one-off)",
             f"{tail} consecutive failed rows at the newest end")
        if confirmed:
            last_ok = max(confirmed, key=lambda r: r["id"])
            gap = (first["created_at"] - last_ok["created_at"]) / 60000
            print(f"  last confirmed base: row {last_ok['id']} at "
                  f"{ts(last_ok['created_at'])} ({gap:.0f} min before the first failure)")

    # block_number population
    nulls = [r for r in recent if r["block_number"] is None]
    if nulls:
        print(f"\n  block_number null on {len(nulls)}/{len(recent)} recent confirmed rows"
              " (contract: 'the block it was mined in')")


# ----------------------------------------------------------------- ots leg

def check_ots(rows, sample=2):
    print("\n== ots leg: the proof must commit to the payload by sha256 ==")
    ots = [r for r in rows if r["kind"] == "ots" and r["status"] == "confirmed"]
    if not ots:
        note(False, "ots: at least one confirmed row to check", "none in window")
        return
    for r in sorted(ots, key=lambda r: -r["id"])[:sample]:
        txt = fetch(f"{API}/anchors/{r['id']}.txt")
        proof = fetch(f"{API}/anchors/{r['id']}.ots")
        if txt is None or proof is None:
            note(False, f"ots row {r['id']}: both files served", "fetch failed")
            continue
        digest = hashlib.sha256(txt).digest()
        note(txt.decode().strip() == r["payload"],
             f"ots row {r['id']}: served .txt == row payload")
        note(proof.startswith(MAGIC), f"ots row {r['id']}: valid OTS magic")
        note(OTS_SHA256 + digest in proof,
             f"ots row {r['id']}: proof commits to sha256(payload)",
             digest.hex()[:16] + "...")

        # control 1: a one-byte change must not be found
        bad = bytearray(txt)
        bad[0] ^= 0xFF
        note(OTS_SHA256 + hashlib.sha256(bytes(bad)).digest() not in proof,
             f"control 1: row {r['id']}: mutated payload is NOT in the proof")

    pend = [r for r in rows if r["kind"] == "ots" and r["status"] == "pending"]
    if pend:
        now = max(r["created_at"] for r in rows)
        oldest = min(pend, key=lambda r: r["created_at"])
        age = (now - oldest["created_at"]) / 3600000
        print(f"  pending: {len(pend)} rows, oldest {age:.1f} h "
              f"(observed max upgrade latency ~9 h)")


# ------------------------------------------------------------- archive leg

def wayback_payload(capture_url):
    """Fetch a capture in raw id_ form and return the checkpoint payload it serves."""
    if "/web/" not in capture_url:
        return None
    stamp = capture_url.split("/web/")[1][:14]
    orig = capture_url.split("/web/")[1]
    orig = orig[14:].lstrip("_/")
    orig = orig.lstrip("i").lstrip("d").lstrip("_")
    if orig.startswith("/"):
        orig = orig[1:]
    url = f"https://web.archive.org/web/{stamp}id_/{orig}"
    raw = fetch(url)
    if not raw:
        return None
    for blob in (raw,):
        try:
            doc = json.loads(gzip.decompress(blob))
        except Exception:  # noqa: BLE001
            try:
                doc = json.loads(blob)
            except Exception:  # noqa: BLE001
                return None
        break
    for c in doc.get("checkpoints", []):
        if c.get("log") == "identity_events":
            return (f"1f916.checkpoint.v1:identity_events:{c['tree_size']}:"
                    f"{c['root']}:{c['created_at']}")
    return None


def check_archive(rows, fetch_captures=2):
    print("\n== archive leg: one capture holds one checkpoint ==")
    arch = [r for r in rows if r["kind"] == "archive"]
    confirmed = [r for r in arch if r["status"] == "confirmed"]
    by_target = {}
    for r in confirmed:
        by_target.setdefault(r["target"], []).append(r)

    print(f"  {len(confirmed)} confirmed archive rows over {len(by_target)} distinct captures")
    for tgt, rs in sorted(by_target.items(), key=lambda kv: -len(kv[1]))[:4]:
        sizes = sorted({r["payload"].split(":")[2] for r in rs})
        stamp = tgt.split("/web/")[1][:14] if "/web/" in tgt else "?"
        print(f"    capture {stamp}: {len(rs)} rows claim sizes {sizes}")

    # control 2: arithmetic, no network. Two different payloads cannot share a capture.
    multi = [rs for rs in by_target.values() if len({r["payload"] for r in rs}) > 1]
    note(len(multi) > 0,
         "control 2: at least one capture is claimed by two different payloads",
         f"{len(multi)} of {len(by_target)} captures")

    # the real check: does the capture serve the payload the row names?
    targets = [t for t, rs in sorted(by_target.items(), key=lambda kv: -len(kv[1]))
               if "/web/" in t][:fetch_captures]
    for tgt in targets:
        rs = by_target[tgt]
        served = wayback_payload(tgt)
        if served is None:
            note(False, f"capture {tgt.split('/web/')[1][:14]}: fetchable", "archive refused or changed shape")
            continue
        stamp = datetime.datetime.strptime(tgt.split("/web/")[1][:14], "%Y%m%d%H%M%S") \
            .replace(tzinfo=datetime.UTC)
        print(f"\n    capture {stamp.strftime('%Y-%m-%d %H:%M:%SZ')} serves size {served.split(':')[2]}")
        matches = [r for r in rs if r["payload"] == served]
        for r in rs:
            pt = int(r["payload"].split(":")[-1])
            late = (pt - stamp.timestamp() * 1000) / 60000
            flag = "MATCH" if r["payload"] == served else "NO"
            if late > 0:
                flag += f", payload written {late:+.0f} min AFTER the capture"
            print(f"      row {r['id']} size {r['payload'].split(':')[2]:>6}  {flag}")
        note(len(matches) == len(rs),
             f"capture {stamp.strftime('%m-%d %H:%M')}: every citing row matches",
             f"{len(matches)}/{len(rs)}")

    dedup = [r for r in arch if "already captured" in (r.get("error") or "")]
    if dedup:
        dedup.sort(key=lambda r: r["created_at"])
        gaps = [(dedup[i + 1]["created_at"] - dedup[i]["created_at"]) / 60000
                for i in range(len(dedup) - 1)]
        if gaps:
            print(f"\n  dedup loop: {len(dedup)} rows report 'already captured', "
                  f"median interval {sorted(gaps)[len(gaps) // 2]:.0f} min")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selfcheck", action="store_true",
                    help="only run control 0: a known-good base row must reproduce")
    ap.add_argument("--pages", type=int, default=6)
    args = ap.parse_args()

    print(f"audit at {datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    rows = walk_anchors(max_pages=args.pages, backwards=True)
    if not rows:
        print("no rows: /api/anchors unreachable or empty")
        return 2
    print(f"walked {len(rows)} recent rows, id {rows[0]['id']}..{rows[-1]['id']}")

    # the control era: one page from id 1, where the verifier has known-good rows
    ctrl = walk_anchors(max_pages=1, backwards=False)

    check_base(rows, control_rows=ctrl)
    if not args.selfcheck:
        check_ots(rows)
        check_archive(rows)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
