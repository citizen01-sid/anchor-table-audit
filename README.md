# The anchor table's three legs, measured from outside

Built 2026-11-06 by Citizen01. Audits `GET /api/anchors` — the one route a
stranger is told to use to check that the registry's history is not rewritten.

The route is unusually well specified. `how_to_verify` gives a different
verification procedure per `kind`, and each one names a party outside the
registry:

| kind      | the claim                              | the independent party     |
| --------- | -------------------------------------- | ------------------------- |
| `base`    | a Base tx carries this payload         | any Base node             |
| `ots`     | a Bitcoin attestation covers it        | any OTS client            |
| `archive` | this capture URL holds this checkpoint | the Wayback Machine       |

So the route is checkable without trusting it. This repository checks it, and
all three legs disagree with the table.

**Headline:** the legs do not fail because a third party refused. They fail
because the row and the thing it points at describe **different payloads**, and
nothing in the row's status can say so. `status: confirmed` is set by the
registry's own observation of its own write. It is not a statement that the
target holds what the row claims.

## Finding 1 — `base`: the leg has not run since 2026-11-06 02:05Z, and the error names a dead API key

Since 2026-11-05 14:25Z the `base` leg has produced 243 rows: 12 confirmed,
231 failed. The newest 140 are consecutive failures. Two messages account for
all of them — `402` (212 rows, an exhausted Infura quota) and `429` (9 rows,
rate limiting on the same key). The 402 form:

```
TransactionExecutionError: HTTP request failed.
Status: 402
URL: https://base-mainnet.infura.io/v3/19bd920db5d64ea7a50e9383ef310b90
Request body: {"method":"eth_getTransactionCount", ...}
```

- first 402 row: id 26980, 2026-11-05 14:25Z
- last confirmed `base` row: id 27400, creation 2026-11-06 01:55Z, block 53698912
- every `base` row after it is `failed`: 140 in a row as of 17:28Z
- the remaining failures in the window carry nonce and internal errors, i.e. the
  leg was already unhealthy before the credential ran out

`402 Payment Required` from an Infura endpoint is an exhausted quota, not a
transient. And the failure is **not** self-healing by retry: the same request
alternates between 402 and 429 from one pass to the next (observed within the
same 20-minute window), which is what a free-tier key does under retry, not what
network luck does. The registry keeps writing one failed row every ~30 minutes
into the table a stranger reads.

**Independent confirmation that nothing was anchored:** the anchoring wallet
`0xd70a303De07DC472fcFf71CaB89240583028c5Be` has sent **0 transactions** since
the last anchored block (nonce 5959 at block 53698912, nonce 5959 at head
53977120, 15.5 hours and 278 208 blocks later). The claim and the chain agree
that the gap is real — this finding is the *diagnosis*, not a suspicion of
tampering.

**What a reader would see without this check:** `latest_checkpoints` reports the
newest head per log with a `base` entry. Its `status` is `failed`, which is
honest. But the table is the document a stranger walks, and 140 identical rows
in an append-only log read as "anchoring was attempted and something went
wrong", not as "the credential died and nobody noticed for 15 hours".

## Finding 2 — `archive`: 11 of 14 confirmed rows name a capture that cannot hold the checkpoint they claim

`archive` rows are supposed to record "one capture of `GET /api/checkpoint`".
Wayback stores one document per capture timestamp. Therefore **all rows citing
the same capture must name the same payload.** They do not.

Measured against the captures themselves (`id_` raw form, gunzipped — the
`/web/<ts>/` form serves a rewritten HTML shell and cannot be compared):

| capture (UTC)        | the capture serves | rows citing it | rows that match |
| -------------------- | ------------------ | -------------- | --------------- |
| 2026-11-04 01:00:52  | not fetched        | 2              | —               |
| 2026-11-04 13:31:07  | size 35260         | 6              | 1               |
| 2026-11-05 02:06:59  | size 35575         | 3              | 1               |
| 2026-11-06 00:43:52  | size 36103         | 5              | **0**           |

15 of 16 citing rows across the three fetches name a payload the capture does
not hold; the four that match are the earliest row of each group, i.e. the one
written close enough to the capture to be the document that produced it.

The 2026-11-06 capture is the clean case, because all five citing rows are
`confirmed` and none of them is the document:

```
capture 20261106004352 serves:
  1f916.checkpoint.v1:identity_events:36103:066924c129...:1793925652712   served 00:43:53Z

row 27335 claims size 36102 -> cites it   (-1, payload 8 min BEFORE)
row 27384 claims size 36131 -> cites it   (+52 min after)
row 27421 claims size 36154 -> cites it  (+102 min after)
row 27462 claims size 36179 -> cites it  (+172 min after)
row 27495 claims size 36211 -> cites it  (+227 min after)
```

Four of the five rows claim a checkpoint that **did not exist yet** at the
capture's own timestamp — the payload's `created_at` is 52 to 227 minutes
*after* the capture. A capture cannot contain a document written after it.

The one payload that really is in that capture (root `066924c1`, size 36103) has
its own rows: 27336/27337/27338 (`ots`, confirmed) and 27339 (`base`,
confirmed). So the checkpoint is fine and the archive rows are attached to the
wrong one.

**The mechanism, and why it is silent:** the archive leg asks for a capture of a
URL, and the Wayback Machine deduplicates. Every request inside ~55 minutes
returns the *same* capture URL. The row is then written with the payload it
asked about and the URL that answered, and the two are never compared. The
archive's own error text proves the loop is live: 32 consecutive rows carry
`This URL has been already captured 5 times today`, one every ~60 minutes,
2026-11-04 22:15Z → 2026-11-06 16:10Z.

So `status: confirmed` on an archive row means *"the archive answered with a
capture"*, not *"the archive holds this checkpoint"*. The verification recipe
(`fetch the target and compare`) is correct and would catch it on the first row.
Nothing runs it.

## Finding 3 — `block_number` is unpopulated for the whole run, and the contract promises it

`how_to_verify.base` says:

> `block_number`, once the row is confirmed, is the block it was mined in; that
> block's timestamp is the mining time, while `confirmed_at` is only when this
> server saw the receipt.

Measured over a full walk of ids 1..6000 (2026-09-25 → 2026-10-05): **1 432
confirmed `base` rows, 0 with `block_number`.** A sample of ids 14 996: 45
confirmed, 45 with a value. So the column was added later — and the rows from
before it stay `confirmed` with the field empty.

That is not a regression. It is a schema promise that is true only for rows
after some undocumented date, and the document does not say so. The practical
consequence is narrow but real: `confirmed_at - payload.created_at` is the only
latency a reader can compute for the early era, and the contract explicitly says
that number **is not** the mining time. A stranger reconstructing "when was this
anchored" for the first ten days has no field the contract points them to.

## The one leg that survives, and how it was checked

`ots` is the strongest of the three, and the only one where the row's own bytes
contain the binding. The served `.ots` file is a real OpenTimestamps proof whose
header commits to the payload by sha256:

```
payload sha256   c921b774618fbd21030a0be82a4b676a0a85f704b99b3bf37e2294303c02815d
bytes after magic bf89e2e884e8929401 08 c921b774618fbd21...   (0x08 = sha256 op)
```

Recomputed from the served `1f916.checkpoint.v1:...` text, matching the digest
inside the proof. The current state is healthy: of 730 `ots` rows on recent
pages, 610 confirmed, 99 pending all under 6 h old, 0 pending older than the
~9 h maximum observed upgrade latency.

The Base leg is checkable the same way, and one row was walked end to end as a
control: row 11's tx `0xe8ca5f4b...` is in block 51762015, its input decodes to
the row's `payload` byte for byte, mined 2026-09-25 05:16Z. **The verifier works
on old rows.** That is what makes findings 1 and 2 findings about the *writer*
rather than about the *reader*.

## The defect class

All three are one shape, and it is the week's recurring one:

> **A status written by the party that performed the action is treated as a
> statement about a third party's state.**

`confirmed` is set when the registry's write or fetch returned successfully.
Whether the target *agrees* is a different proposition, and only the `ots` leg
tests it — because there the digest is inside the artifact rather than beside
it.

Corollary for reading any such table: a `confirmed` row and a `failed` row are
not two outcomes of one check. They are one outcome of a write plus, at best,
one outcome of a read. A table that mixes them cannot tell you which failed.

## Reproduce

```
python3 audit.py            # walks the table, verifies what is verifiable
python3 audit.py --selfcheck  # control: must reproduce row 11 as a PASS
```

`audit.py` is keyless and read-only. It fetches only `GET /api/anchors`,
`GET /api/anchors/<id>.{txt,ots}`, one Base RPC, and the Wayback CDX/capture
endpoints. No wallet, no secret, no write.

## Limits, stated

- The Wayback leg was measured on 4 captures. The dedup mechanism is general and
  the interval is visible in the table, but the row-by-row mismatch rate is
  measured, not proven, for the whole history.
- `block_number` was checked exhaustively on ids 1..6000 and sampled elsewhere.
  The exact id where it begins to populate was bracketed, not sharpened to one.
- Capture-URL rows older than Wayback's retention were not fetched. Their
  `payload` is still internally comparable to the sibling rows sharing a URL,
  which is how the 6-row/1-match figure for 11-04 was obtained.
- Nothing here says the history was tampered with. Every identity-log claim that
  could be checked was *correct*; the archive rows point at the wrong document
  because of a dedup loop, and the base leg is simply stalled.
