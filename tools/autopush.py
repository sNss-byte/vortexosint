#!/usr/bin/env python3
"""
Surveillance auto-push pour VortexOSINT (stdlib uniquement).

Des qu'un fichier suivi ou nouveau change dans le depot :
  1. controles locaux (compilation + smoke test du CLI)
  2. commit automatique
  3. push vers origin/main
  4. verification via l'API GitHub (le SHA distant == HEAD local)

Utilisation :
    python tools/autopush.py [--once] [--dry-run] [--interval 2] [--debounce 5]

Laisse-le tourner dans un terminal. Ctrl+C pour arreter.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "env",
             ".pytest_cache", ".tox", "htmlcov", ".eggs"}
SKIP_EXT = {".pyc", ".pyo"}


def sh(*cmd):
    """Run a command in ROOT, return (code, output)."""
    try:
        out = subprocess.run(cmd, cwd=ROOT, capture_output=True,
                             text=True, timeout=120)
        return out.returncode, (out.stdout + out.stderr).strip()
    except Exception as e:  # noqa: BLE001 - watcher must never crash
        return 1, str(e)


def snapshot():
    """Map relative path -> (size, mtime) for watched files."""
    state = {}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SKIP_EXT:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, ROOT)
            try:
                st = os.stat(full)
                state[rel] = (st.st_size, st.st_mtime_ns)
            except OSError:
                continue
    return state


def repo_slug():
    """owner/repo parsed from origin URL, or None."""
    code, out = sh("git", "remote", "get-url", "origin")
    if code != 0:
        return None
    url = out.strip().rstrip("/").removesuffix(".git")
    if url.startswith("git@"):
        url = url.split(":", 1)[-1]
    else:
        url = url.split("://", 1)[-1].split("@", 1)[-1]
    parts = url.strip("/").split("/")
    if len(parts) >= 2 and "github.com" in parts[0]:
        return "/".join(parts[-2:])
    return None


def local_checks(changed):
    """Compile changed .py files + CLI smoke test. Return (ok, message)."""
    py_files = [f for f in changed if f.endswith(".py")]
    if py_files:
        code, out = sh(sys.executable, "-m", "py_compile", *py_files)
        if code != 0:
            return False, f"py_compile KO:\n{out}"
    code, out = sh(sys.executable, "-m", "vortexosint", "--version")
    if code != 0:
        return False, f"smoke test (--version) KO:\n{out}"
    return True, "controles OK"


def api_verify(slug, head_sha, tries=6):
    """Poll GitHub API until remote main == local HEAD. Return True/False."""
    url = f"https://api.github.com/repos/{slug}/commits/main"
    for _ in range(tries):
        try:
            req = urllib.request.Request(
                url, headers={"Accept": "application/vnd.github+json",
                              "User-Agent": "vortexosint-autopush"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.load(resp)
            if data.get("sha", "").lower() == head_sha.lower():
                return True
        except Exception:  # noqa: BLE001 - retry on any transient error
            pass
        time.sleep(5)
    return False


def act_once(dry_run=False):
    """Commit + push + verify current changes. Return True if pushed+verified."""
    code, status = sh("git", "status", "--porcelain")
    if code != 0 or not status:
        return False
    changed = [line[3:] for line in status.splitlines()]
    print(f"[autopush] changements : {', '.join(changed)}", flush=True)

    ok, msg = local_checks(changed)
    print(f"[autopush] {msg}", flush=True)
    if not ok:
        print("[autopush] push annule (corrige puis sauvegarde a nouveau).", flush=True)
        return False
    if dry_run:
        print("[autopush] dry-run : commit/push ignores.", flush=True)
        return False

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    code, out = sh("git", "add", "-A")
    code, out = sh("git", "commit", "-m", f"Auto: {ts} ({len(changed)} fichier(s))")
    if code != 0:
        print(f"[autopush] commit KO : {out}", flush=True)
        return False

    code, head = sh("git", "rev-parse", "HEAD")
    head = head.strip()
    code, out = sh("git", "push", "origin", "main")
    if code != 0:
        print("[autopush] push refuse, tentative pull --rebase...", flush=True)
        sh("git", "pull", "--rebase", "origin", "main")
        code, out = sh("git", "push", "origin", "main")
    if code != 0:
        print(f"[autopush] push KO : {out}", flush=True)
        return False

    slug = repo_slug()
    if slug and api_verify(slug, head):
        print(f"[autopush] GitHub OK : {slug}@main == {head[:7]}", flush=True)
        return True
    print("[autopush] push envoye mais verification API indecise "
          "(reessaie au prochain changement).", flush=True)
    return False


def main():
    ap = argparse.ArgumentParser(description="Auto commit/push/verify pour VortexOSINT.")
    ap.add_argument("--once", action="store_true", help="un seul passage puis stop")
    ap.add_argument("--dry-run", action="store_true", help="detecte et controle sans pousser")
    ap.add_argument("--interval", type=float, default=2.0, help="scrutation (s)")
    ap.add_argument("--debounce", type=float, default=5.0, help="delai calme avant push (s)")
    args = ap.parse_args()

    print(f"[autopush] surveillance de {ROOT} (Ctrl+C pour arreter)", flush=True)
    prev = snapshot()
    last_change = 0.0
    pending = False

    try:
        while True:
            time.sleep(args.interval)
            cur = snapshot()
            if cur != prev:
                prev = cur
                pending = True
                last_change = time.time()
                if args.once:
                    act_once(dry_run=args.dry_run)
                    return 0
            if pending and (time.time() - last_change) >= args.debounce:
                pending = False
                act_once(dry_run=args.dry_run)
                prev = snapshot()  # re-sync (ex: __pycache__ regeneres)
    except KeyboardInterrupt:
        print("\n[autopush] arret.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
