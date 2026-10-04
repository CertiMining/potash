#!/usr/bin/env python3
"""Ask the cluster what the announced deployment holds, and name anything LIVE-VALUES.txt does not.

The rule is that no synthetic artifact carries a value from a live deployment. A list of those values
built from memory has the same defect as a fixture built from memory: the first version of
LIVE-VALUES.txt omitted three of the six signatures the deployment held, one of which a review found
and two of which nothing had.

**This is the third version of this check and the second rewrite.** The history matters, because each
earlier version reported "nothing missing" in cases where it had not looked:

1. Signatures only, read only from accounts the list already named, first fifty without paging, and a
   JSON-RPC error read as an empty result — so it could pass having asked nothing.
2. Paging, retries and error propagation were added. A scoped review then found three more: accounts
   were still *selected from the list* rather than discovered from the chain, so an unlisted
   checkpoint stayed invisible; a malformed response such as `{}` produced `result: null`, which the
   readers treated as an empty account; and most value classes in the list — program ids, the
   ProgramData address, both authorities, the LogConfig address, byte encodings, receipt digests —
   were never compared against anything, so removing one exited 0.

What this version does: `getProgramAccounts` enumerates every account the announced program owns, so
discovery comes from the chain. Each account is decoded at §2.4's offsets and **the fields named below**
are compared: root, publication slot, publication timestamp, receipt digest, authority. That is not every
value inside an account, and an earlier version of this paragraph said it was — a review found a live
checkpoint bump sitting in a synthetic fixture while this script reported nothing missing, because it
never reads offset 99 (PR #57, round two, H-01). The program account gives the ProgramData address, which
gives the upgrade authority. **Transaction ids** are paged to exhaustion for the program and every account it owns. That is the
`signature` field of each `getSignaturesForAddress` entry, which is a transaction's *first* signature —
not every signature it carries. A review found the announced deployment's 13 transactions hold 25
signatures between them, so 12 co-signatures are neither listed nor compared (H-29). An earlier version
of the message below said "every signature", which was false. A response without a `result` member is a failure, not an absence.

**What it still cannot do, stated rather than implied.** A superseded deployment's values are not
reachable from the announced one: `HS82CAXg…` and `jzJzgKWM…` are in the list by hand and this check
neither confirms nor refutes them — a review swept all 29 entries and named 27, the two exceptions
being exactly those. It also cannot prove the list is minimal: an entry for something that never
existed on chain would sit there unchallenged.

**And it refuses rather than guesses.** An account the program owns whose length, discriminator or
schema version this script does not recognise makes the whole run exit non-zero. Reading offsets whose
meaning has not been established would be worse, but so is passing: the script cannot say the list
holds an account's values when it cannot read the account. A third version of this fallback checked
the address and carried on, with a comment claiming it failed closed, and a review proved it did not by
building a 106-byte account under schema 2 with unlisted bytes inside and watching the run exit 0.

Run it after every publish cycle. Each adds a signature, a checkpoint account, a root, and later a
receipt digest.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIST = ROOT / "LIVE-VALUES.txt"
PROGRAM_FILE = ROOT / "ANNOUNCED_PROGRAM_ID"
RPC = os.environ.get("CERTIMINING_RPC", "https://api.devnet.solana.com")

# §2.4's CheckpointAccount: 8 discriminator, 2 schema, 8 epoch, 32 root, 8 slot, 8 unix, 32 receipt
# digest, 1 anchor kind, 1 bump, 6 reserved.
CHECKPOINT_LEN = 106
CHECKPOINT_ROOT = (18, 50)
CHECKPOINT_SLOT = (50, 58)
CHECKPOINT_UNIX = (58, 66)
CHECKPOINT_RECEIPT = (66, 98)
# §2.4's LogConfig: 8 discriminator, 2 schema, 32 authority, then heights and epochs.
LOG_CONFIG_LEN = 68
LOG_CONFIG_AUTHORITY = (10, 42)

# §2.4 states the Anchor discriminator as the first 8 bytes of SHA-256("account:" ‖ StructName), and
# the schema version in the two bytes after it. **Length alone does not establish either.** A review
# found this decoder choosing a layout by size, so any 106-byte account the program owned would have
# had bytes 18..50 read as a root; under another schema those offsets may mean something else. The
# discriminators are computed here rather than copied, for the reason §2.4 gives for computing the
# address: a constant transcribed by hand is a second opinion about what the program wrote.
SCHEMA_VERSION = 1


def le_u64(data: bytes, span: tuple) -> int:
    """A little-endian u64 at §2.4's offsets."""
    return int.from_bytes(data[span[0] : span[1]], "little", signed=False)


def le_i64(data: bytes, span: tuple) -> int:
    """A little-endian i64. `published_unix` is signed in §2.4, so it is read signed here."""
    return int.from_bytes(data[span[0] : span[1]], "little", signed=True)


def discriminator(struct_name: str) -> bytes:
    import hashlib

    return hashlib.sha256(f"account:{struct_name}".encode()).digest()[:8]


CHECKPOINT_DISCRIMINATOR = discriminator("CheckpointAccount")
LOG_CONFIG_DISCRIMINATOR = discriminator("LogConfig")


def schema_1(data: bytes, expected: bytes) -> bool:
    """The account is this struct, under the schema whose offsets are the ones below."""
    return (
        len(data) >= 10
        and data[0:8] == expected
        and int.from_bytes(data[8:10], "little") == SCHEMA_VERSION
    )


class Unreachable(RuntimeError):
    """The cluster could not be asked. Never an absence."""


#: What each method's `result` must look like. A response carrying a `result` member is not thereby an
#: answer: `getProgramAccounts` returning `null` was read as "this program owns nothing", which is the
#: same silent pass as a missing account, one layer further in. A review found it.
RESULT_SHAPE: dict[str, type | tuple[type, ...]] = {
    "getProgramAccounts": list,
    "getSignaturesForAddress": list,
    "getAccountInfo": dict,
}


def rpc(method: str, params: list) -> object:
    """One JSON-RPC call, retried through rate limiting, and strict about what an answer is."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    wait = 2.0
    last = ""
    for _ in range(6):
        request = urllib.request.Request(
            RPC, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as e:  # 429 and friends
            last = f"HTTP {e.code}"
        except Exception as e:  # transport, timeout, or a body that is not JSON
            last = str(e)
        else:
            if "error" in payload:
                last = f"RPC error {json.dumps(payload['error'])}"
            elif "result" not in payload:
                # `{}` is not an empty result. A response that carries neither `result` nor `error`
                # is malformed, and reading it as "this account does not exist" is how a check
                # reports that it found nothing when it never asked.
                last = f"malformed response, no result member: {json.dumps(payload)[:120]}"
            else:
                result = payload["result"]
                expected = RESULT_SHAPE.get(method)
                if expected is not None and not isinstance(result, expected):
                    # A `null` where an array belongs is malformed, not empty. Accepting it turned
                    # "the cluster did not answer this properly" into "the program owns nothing".
                    last = (
                        f"malformed {method} result: expected {expected}, got "
                        f"{json.dumps(result)[:120]}"
                    )
                else:
                    return result
        time.sleep(wait)
        wait *= 2
    raise Unreachable(f"{RPC}: {method} failed after 6 attempts ({last})")


def listed_values() -> dict[str, str]:
    """Every value the list holds, mapped to what it says the value is."""
    out: dict[str, str] = {}
    for line in LIST.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        value, _, what = line.partition("  ")
        out[value.strip().lower()] = what.strip()
    if not out:
        raise SystemExit(f"live-values: {LIST} lists nothing")
    return out


def signatures_for(address: str) -> list[str]:
    """Every signature for an address, paged to exhaustion rather than capped."""
    found: list[str] = []
    before = None
    while True:
        params: list = [address, {"limit": 1000}]
        if before is not None:
            params[1]["before"] = before
        page = rpc("getSignaturesForAddress", params) or []
        if not page:
            return found
        found.extend(entry["signature"] for entry in page)
        before = page[-1]["signature"]
        if len(found) > 100_000:
            raise Unreachable(f"{address}: more than 100000 signatures")


def hex32(data: bytes, span: tuple[int, int]) -> str:
    return "0x" + data[span[0] : span[1]].hex()


def base58_decode(text: str) -> bytes:
    """Base58 to the 32 bytes it spells, so both spellings of one address can be compared."""
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for character in text.encode():
        index = alphabet.find(bytes([character]))
        if index < 0:
            raise SystemExit(f"live-values: {text!r} is not base58")
        n = n * 58 + index
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    leading = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading + body


def base58(data: bytes) -> str:
    """Base58 with the Bitcoin alphabet, for turning 32 account bytes into the spelling the list uses."""
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, remainder = divmod(n, 58)
        out.append(alphabet[remainder])
    for byte in data:
        if byte != 0:
            break
        out.append(alphabet[0])
    return bytes(reversed(out)).decode()


def main() -> int:
    if not LIST.exists():
        raise SystemExit(f"live-values: {LIST} is missing")
    if not PROGRAM_FILE.exists():
        raise SystemExit(f"live-values: {PROGRAM_FILE} is missing")

    program = ""
    for token in PROGRAM_FILE.read_text().split():
        if 32 <= len(token) <= 44 and token.isalnum():
            program = token
            break
    if not program:
        raise SystemExit(f"live-values: no program id in {PROGRAM_FILE}")

    listed = listed_values()
    missing: list[str] = []
    #: Reasons the check cannot report completeness at all, as opposed to values it found unlisted.
    #: A refusal is unconditional: no entry in the list can satisfy it, because the point is that the
    #: script does not know what it is looking at.
    refusals: list[str] = []

    def check(value: str, what: str) -> None:
        if value.lower() not in listed:
            missing.append(f"{what}: {value}")

    def check_address(raw: bytes, what: str) -> None:
        """Both spellings of an address, because the list carries both.

        `LIVE-VALUES.txt` holds base58 *and* the 32 bytes as hex for the program id and the LogConfig
        address, because a fixture can quote either. Only base58 was compared, so deleting the hex
        line left the check passing — a review removed `0xa2f283cb…fb7ee` and it exited 0.
        """
        check(base58(raw), what)
        check("0x" + raw.hex(), f"{what}, as bytes")

    program_bytes = base58_decode(program)
    check_address(program_bytes, "the announced program id")

    # The program account, which names its ProgramData, which names the upgrade authority.
    account = rpc("getAccountInfo", [program, {"encoding": "base64"}])
    value = (account or {}).get("value")
    if not value:
        raise Unreachable(f"{program}: the cluster does not know this program")
    data = base64.b64decode(value["data"][0])
    # An upgradeable program account is a 4-byte tag then the 32-byte ProgramData address.
    if len(data) >= 36:
        program_data = base58(data[4:36])
        check(program_data, "the ProgramData address")
        pd = rpc("getAccountInfo", [program_data, {"encoding": "base64"}])
        pd_value = (pd or {}).get("value")
        if pd_value:
            pd_data = base64.b64decode(pd_value["data"][0])
            # 4-byte tag, 8-byte slot, 1-byte option, then the 32-byte upgrade authority.
            if len(pd_data) >= 45 and pd_data[12] == 1:
                check(base58(pd_data[13:45]), "the upgrade authority")

    # **Discovery from the chain, not from the list.** Every account the program owns.
    owned = rpc("getProgramAccounts", [program, {"encoding": "base64"}]) or []
    addresses = [program]
    for entry in owned:
        address = entry["pubkey"]
        addresses.append(address)
        account_data = base64.b64decode(entry["account"]["data"][0])
        raw_address = base58_decode(address)
        if len(account_data) == CHECKPOINT_LEN and schema_1(account_data, CHECKPOINT_DISCRIMINATOR):
            check_address(raw_address, "a checkpoint address")
            check(hex32(account_data, CHECKPOINT_ROOT), f"a root stored at {address}")
            # **The publication slot and timestamp, added after a review (PR #57, round one, High).**
            # Both are values the deployment produced and both were invisible to this script and
            # unlistable in LIVE-VALUES.txt, which accepted only hex and base58. A fixture carried a
            # real slot beside a fabricated root and a fabricated receipt digest and both halves of the
            # gate exited 0. They are little-endian u64 and i64 at §2.4's offsets, compared as the
            # decimal text the list holds.
            check(str(le_u64(account_data, CHECKPOINT_SLOT)), f"a published slot stored at {address}")
            check(str(le_i64(account_data, CHECKPOINT_UNIX)), f"a published timestamp stored at {address}")
            digest = hex32(account_data, CHECKPOINT_RECEIPT)
            if int(digest, 16) != 0:
                check(digest, f"a receipt digest stored at {address}")
        elif len(account_data) == LOG_CONFIG_LEN and schema_1(account_data, LOG_CONFIG_DISCRIMINATOR):
            check_address(raw_address, "the LogConfig address")
            check(base58(account_data[LOG_CONFIG_AUTHORITY[0] : LOG_CONFIG_AUTHORITY[1]]),
                  "the checkpoint authority")
        else:
            # **Fail closed, unconditionally.** An earlier version checked the address and carried on,
            # with a comment claiming it failed closed; it did not. If both spellings of the address
            # happened to be listed, an account carrying unlisted values inside it exited 0 — a review
            # built one with an unknown discriminator and another with schema 2 and watched both pass.
            #
            # Not reading offsets whose meaning has not been established is right, and it is exactly
            # why this cannot report completeness: the script does not know what a layout it does not
            # recognise contains, so it cannot say the list holds everything. Listing the address does
            # not establish anything about the interior. A new account shape is a person's problem, and
            # they find out here.
            check_address(raw_address, "an unrecognised account's address")
            refusals.append(
                f"{address} is owned by the program and this script cannot read it: "
                f"{len(account_data)} bytes, discriminator "
                f"{account_data[0:8].hex() if len(account_data) >= 8 else '(too short)'}, schema "
                f"{int.from_bytes(account_data[8:10], 'little') if len(account_data) >= 10 else '(too short)'}. "
                "Nothing inside it was read, so the list cannot be shown to hold its values. Teach this "
                "script the layout, or record why the account is out of scope."
            )

    for address in addresses:
        for signature in signatures_for(address):
            check(signature, f"a signature touching {address}")

    for line in dict.fromkeys(refusals):
        print(f"live-values: {line}", file=sys.stderr)
    for line in dict.fromkeys(missing):
        print(f"live-values: {line} is not in {LIST.name}", file=sys.stderr)

    if refusals:
        print(
            f"live-values: {len(set(refusals))} account(s) the program owns could not be read, so "
            "this check cannot say the list is complete.",
            file=sys.stderr,
        )
        return 1
    if missing:
        print(
            f"live-values: {len(set(missing))} value(s) on chain are not listed. "
            "Add them, with what each one is.",
            file=sys.stderr,
        )
        return 1

    # Bounded to what was actually compared. "The chain holds nothing the list does not" was falsified by
    # a live bump this script does not read; a success message may not claim more than its own coverage.
    print(
        f"live-values: of the fields this script reads — addresses, roots, publication slots and "
        f"timestamps, receipt digests, the authority and every **transaction id** "
        f"`getSignaturesForAddress` returns — the chain holds nothing {LIST.name} does not. Not read: "
        f"bumps and epoch numbers, which are review-enforced (H-20), and the co-signatures inside each "
        f"transaction (H-29)."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Unreachable as e:
        print(f"live-values: {e}", file=sys.stderr)
        sys.exit(1)
