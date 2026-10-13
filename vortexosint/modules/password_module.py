"""
Password Module - Secure password & passphrase utilities.

- Cryptographically secure generation (secrets module, never random)
- Memorable passphrases from a built-in wordlist
- Strength / entropy / crack-time audit (passwords never written to disk)
- Salted hashing (sha256/sha512/sha3_256/sha1/md5) for storage comparison

Secrets are only ever printed to the screen: --output files contain
parameters and scores, never raw passwords.
"""

import argparse
import getpass
import hashlib
import math
import secrets
import sys

from vortexosint.core.banner import print_module_banner
from vortexosint.core import ui

LOWER = "abcdefghijklmnopqrstuvwxyz"
UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("0O1lI")

# Shown when a password is requested but not piped on the command line.
PROMPT_SENTINEL = "__prompt__"

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "1234567890", "qwerty", "azerty", "abc123", "password1", "123123",
    "admin", "letmein", "welcome", "monkey", "dragon", "master",
    "football", "superman", "iloveyou", "starwars", "trustno1",
    "sunshine", "princess", "azerty123", "motdepasse", "bonjour",
    "amour", "champion", "doudou", "liverpool", "baseball",
}

# 128-word list (7 bits of entropy per word), lowercase, easy to type.
WORDLIST = (
    "falcon river stone cloud ember wolf maple harbor comet lantern meadow "
    "onyx pepper quartz willow aspen birch cedar dune frost grove inlet lagoon "
    "mesa oasis prairie reef summit tide tundra valley zephyr amber basil cider "
    "cocoa honey ginger mango olive onion thyme vanilla wheat acorn bloom clover "
    "daisy fern moss anchor beacon bridge castle dagger engine flame gate hammer "
    "island jewel kite ladder magnet nail ocean piano drum flute violin trumpet "
    "clock compass globe knife lens mirror phone radio rope scale shield tiger "
    "eagle shark snake horse sheep goat goose duck frog crab whale mouse rabbit "
    "bear lion apple grape melon berry peach plum cherry orange lime kiwi fig "
    "date bread toast crust crumb chair table shelf lamp couch desk stool bench "
    "porch patio attic cellar garden yard fence"
).split()

HASH_ALGOS = ("sha256", "sha512", "sha3_256", "sha1", "md5")


def run(args: argparse.Namespace) -> int:
    """Run the password module."""
    print_module_banner("PASSWORD", "Secure passwords, passphrases & strength audit")

    if getattr(args, "check", None) is not None:
        return check_mode(args)
    if getattr(args, "hash", None) is not None:
        return hash_mode(args)
    if getattr(args, "passphrase", False):
        return passphrase_mode(args)
    return generate_mode(args)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _secret(prompt_text: str) -> str:
    """Read a password without echo when possible."""
    try:
        if sys.stdin.isatty():
            return getpass.getpass(f"{prompt_text}: ")
    except (EOFError, KeyboardInterrupt):
        raise
    return ui.ask(prompt_text, "")


def _clamp(value: int, low: int, high: int, name: str) -> int:
    if value < low:
        ui.warning(f"{name} too small — clamped to {low}.")
        return low
    if value > high:
        ui.warning(f"{name} too large — clamped to {high}.")
        return high
    return value


def _human_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    minute, hour, day, year = 60, 3600, 86400, 365.25 * 86400
    if seconds < minute:
        return f"{seconds:.1f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.1f} minutes"
    if seconds < day:
        return f"{seconds / hour:.1f} hours"
    if seconds < year:
        return f"{seconds / day:.1f} days"
    years = seconds / year
    if years < 1_000:
        return f"{years:,.0f} years"
    if years < 1_000_000:
        return f"{years / 1_000:,.1f} thousand years"
    return "over a million years"


def _pool_for(password: str) -> int:
    pool = 0
    if any(c in LOWER for c in password):
        pool += 26
    if any(c in UPPER for c in password):
        pool += 26
    if any(c in DIGITS for c in password):
        pool += 10
    if any(c in SYMBOLS for c in password):
        pool += len(SYMBOLS)
    if any(c not in (LOWER + UPPER + DIGITS + SYMBOLS) for c in password):
        pool += 32  # other unicode / punctuation
    return pool or 26


def _save(meta: dict, args: argparse.Namespace):
    """Persist non-sensitive metadata only (never raw passwords)."""
    if not getattr(args, "output", None):
        return
    fmt = getattr(args, "format", "json")
    try:
        if fmt == "json":
            import json
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
        elif fmt == "csv":
            import csv
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["key", "value"])
                for k, v in meta.items():
                    w.writerow([k, v])
        else:
            with open(args.output, "w", encoding="utf-8") as f:
                for k, v in meta.items():
                    f.write(f"{k}: {v}\n")
        ui.success(f"Metadata saved to {args.output} (no secrets stored)")
    except OSError as e:
        ui.error(f"Could not write {args.output}: {e}")


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def generate_mode(args: argparse.Namespace) -> int:
    length = _clamp(int(getattr(args, "length", 20) or 20), 4, 256, "Length")
    count = _clamp(int(getattr(args, "count", 5) or 5), 1, 50, "Count")

    classes = [LOWER]
    if not getattr(args, "no_uppercase", False):
        classes.append(UPPER)
    if not getattr(args, "no_digits", False):
        classes.append(DIGITS)
    if not getattr(args, "no_symbols", False):
        classes.append(SYMBOLS)

    pool = "".join(classes)
    if not getattr(args, "allow_ambiguous", False):
        pool = "".join(c for c in pool if c not in AMBIGUOUS)
    if len(pool) < 8:
        ui.error("Character pool too small.")
        return 1

    rng = secrets.SystemRandom()
    ui.headline(f"Generating {count} password(s) — {length} chars from {len(pool)} symbols")
    bits = length * math.log2(len(pool))
    ui.info(f"Entropy: ~{bits:.0f} bits each — crack time {_human_duration(2 ** (bits - 1) / 1e10)}")
    print()
    for _ in range(count):
        # Guarantee at least one char from every enabled class.
        chars = [rng.choice(cls) for cls in classes]
        chars += [rng.choice(pool) for _ in range(length - len(chars))]
        rng.shuffle(chars)
        print("".join(chars[:length]))
    print()
    ui.warning("Displayed on screen only — never saved to disk.")
    _save({"mode": "generate", "length": length, "count": count,
           "pool_size": len(pool), "bits_per_password": round(bits, 1)}, args)
    ui.divider()
    return 0


def passphrase_mode(args: argparse.Namespace) -> int:
    words = _clamp(int(getattr(args, "words", 5) or 5), 2, 24, "Words")
    sep = getattr(args, "separator", "-") or "-"
    phrase = sep.join(secrets.choice(WORDLIST) for _ in range(words))
    bits = words * math.log2(len(WORDLIST))
    ui.headline(f"Passphrase — {words} words (~{bits:.0f} bits)")
    print()
    print(phrase)
    print()
    if bits < 60:
        ui.warning("Below 60 bits — use 9+ words for high-value accounts.")
    else:
        ui.success(f"Crack time {_human_duration(2 ** (bits - 1) / 1e10)}")
    ui.warning("Displayed on screen only — never saved to disk.")
    _save({"mode": "passphrase", "words": words, "bits": round(bits, 1)}, args)
    ui.divider()
    return 0


def _audit(password: str) -> dict:
    lowered = password.lower()
    pool = _pool_for(password)
    bits = len(password) * math.log2(pool)
    classes = sum([
        any(c in LOWER for c in password),
        any(c in UPPER for c in password),
        any(c in DIGITS for c in password),
        any(c in SYMBOLS or c not in (LOWER + UPPER + DIGITS + SYMBOLS) for c in password),
    ])
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if classes >= 3:
        score += 1
    if len(password) >= 16 and classes == 4:
        score += 1
    if bits >= 60:
        score += 1
    score = min(score, 5)
    if lowered in COMMON_PASSWORDS:
        score = 0
    labels = ["Very weak", "Very weak", "Weak", "Fair", "Strong", "Excellent"]
    return {
        "length": len(password),
        "classes": classes,
        "pool": pool,
        "bits": bits,
        "score": score,
        "label": labels[score],
        "common": lowered in COMMON_PASSWORDS,
        "crack_time": _human_duration(2 ** (bits - 1) / 1e10),
    }


def check_mode(args: argparse.Namespace) -> int:
    raw = args.check
    if raw == PROMPT_SENTINEL:
        raw = _secret("Password to audit (hidden)")
    else:
        ui.warning("Tip: run `--check` without a value to type it hidden "
                   "(CLI args stay in shell history).")
    if not raw:
        ui.error("Empty password — nothing to audit.")
        return 1
    a = _audit(raw)
    ui.headline("Strength audit")
    ui.info(f"Length: {a['length']} chars · classes: {a['classes']}/4 · "
            f"entropy: ~{a['bits']:.0f} bits")
    ui.info(f"Crack time @10B guesses/s: {a['crack_time']}")
    if a["common"]:
        ui.error("Found in common-password lists — score 0/5. Do not use it.")
    elif a["score"] >= 4:
        ui.success(f"Score {a['score']}/5 — {a['label']}")
    else:
        ui.warning(f"Score {a['score']}/5 — {a['label']}")
    if a["score"] < 4 and not a["common"]:
        ui.info("Improve it: 16+ chars mixing lower/upper/digits/symbols, "
                "or a 9-word passphrase.")
    _save({"mode": "check", "score": f"{a['score']}/5", "label": a["label"],
           "length": a["length"], "bits": round(a["bits"], 1),
           "common": a["common"]}, args)
    ui.divider()
    return 0


def hash_mode(args: argparse.Namespace) -> int:
    raw = args.hash
    if raw == PROMPT_SENTINEL:
        raw = _secret("Password to hash (hidden)")
    if not raw:
        ui.error("Empty password — nothing to hash.")
        return 1
    algo = (getattr(args, "algo", "sha256") or "sha256").lower()
    if algo not in HASH_ALGOS:
        ui.error(f"Unknown algo '{algo}'. Choose: {', '.join(HASH_ALGOS)}")
        return 1
    salt = getattr(args, "salt", None) or secrets.token_hex(16)
    digest = hashlib.new(algo, (salt + raw).encode("utf-8")).hexdigest()
    if algo in ("md5", "sha1"):
        ui.warning(f"{algo} is broken for password storage — prefer sha256+ or a "
                   f"dedicated KDF (bcrypt/argon2). Shown for compatibility only.")
    ui.headline(f"Hash ({algo}, salted)")
    print(f"  algo   : {algo}")
    print(f"  salt   : {salt}")
    print(f"  digest : {digest}")
    print()
    _save({"mode": "hash", "algo": algo, "salt": salt, "digest": digest}, args)
    ui.divider()
    return 0
