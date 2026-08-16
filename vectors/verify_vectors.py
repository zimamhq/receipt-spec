#!/usr/bin/env python3
"""Cross-language byte-identity verifier for the Zimam receipt vectors.

Standard library only. Re-derives every canonical form (RFC 8785 JCS) and
every sha256: digest in vectors.json, byte-compares against what the
TypeScript implementation committed, and re-walks the receipt chain links.

The JCS here is a deliberate SUBSET: Zimam signed payloads carry integers
only (the float_in_signed_field guard enforces it), so ECMAScript number
serialisation reduces to plain integer printing and the remaining sharp
edge is key ordering — UTF-16 code units, NOT code points. A naive
`sorted(dict)` puts U+FFFF before an emoji; JCS does the opposite, because
the emoji's first surrogate (0xD83D) sorts below 0xFFFF. That single case
is why this script exists.

Exit code 0 = every byte identical. Anything else prints the first
divergence and exits 1.
"""
import hashlib
import json
import pathlib
import sys


def _dump_str(value: str) -> str:
    # json.dumps with ensure_ascii=False matches ECMAScript JSON.stringify:
    # short escapes for \b \t \n \f \r \" \\, \u00XX (lowercase) for other
    # control characters, everything else literal.
    return json.dumps(value, ensure_ascii=False)


def jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError(f"float in signed field: {value!r} — the format forbids it")
    if isinstance(value, str):
        return _dump_str(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # THE sharp edge: RFC 8785 sorts keys by UTF-16 code units.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_dump_str(k)}:{jcs(v)}" for k, v in items) + "}"
    raise TypeError(f"not JSON: {type(value)}")


def sha256_wire(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def fail(name: str, what: str, expected: str, got: str) -> None:
    print(f"MISMATCH [{name}] {what}")
    print(f"  expected: {expected[:120]}")
    print(f"  got:      {got[:120]}")
    sys.exit(1)


def main() -> None:
    path = pathlib.Path(__file__).parent / "vectors.json"
    doc = json.loads(path.read_text(encoding="utf-8"))

    checked = 0
    for case in doc["canonicalization"]:
        computed = jcs(case["input"])
        if computed != case["jcs"]:
            fail(case["name"], "canonical form", case["jcs"], computed)
        if sha256_wire(computed) != case["sha256"]:
            fail(case["name"], "sha256", case["sha256"], sha256_wire(computed))
        checked += 1

    previous = None
    for case in doc["receipts"]:
        computed = jcs(case["payload"])
        if computed != case["jcs"]:
            fail(case["name"], "canonical form", case["jcs"], computed)
        if sha256_wire(computed) != case["sha256"]:
            fail(case["name"], "sha256", case["sha256"], sha256_wire(computed))
        link = case["payload"]["previous_receipt_hash"]
        expected_link = "sha256:" + "0" * 64 if previous is None else sha256_wire(jcs(previous))
        if link != expected_link:
            fail(case["name"], "previous_receipt_hash (payload-only chain link)", expected_link, link)
        previous = case["payload"]
        checked += 1

    # Signatures are Ed25519 over the same JCS bytes; verifying them needs a
    # crypto dependency, so it is opt-in — byte-identity is this script's job.
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(doc["test_key"]["public_pem"].encode("ascii"))
        import base64

        for case in doc["receipts"]:
            sig = case["signature"]["signature"]
            raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
            key.verify(raw, jcs(case["payload"]).encode("utf-8"))
            checked += 1
        print(f"OK — {checked} checks, byte-identical, signatures verified")
    except ImportError:
        print(f"OK — {checked} checks, byte-identical (install 'cryptography' to also verify signatures)")


if __name__ == "__main__":
    main()
