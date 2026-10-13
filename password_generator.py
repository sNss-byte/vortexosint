#!/usr/bin/env python3
"""
Generateur de mots de passe securise — script 100 % autonome (stdlib uniquement).

Utilisation :
    python password_generator.py

Le script demande : longueur, types de caracteres, quantite — puis affiche
les mots de passe dans un format lisible avec niveau de securite.
"""

import math
import secrets
import subprocess
import sys

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("0O1lI")

BAR = "=" * 58


def ask(question, default=""):
    """Pose une question, Entree = valeur par defaut. None si EOF (Ctrl+Z)."""
    suffix = f" [{default}]" if default != "" else ""
    try:
        value = input(f"{question}{suffix} : ").strip()
    except EOFError:
        return None
    return value if value else default


def ask_yes_no(question, default_yes=True):
    """Question oui/non. Retourne True/False, None si EOF."""
    hint = "O/n" if default_yes else "o/N"
    answer = ask(question + f" ({hint})", "")
    if answer is None:
        return None
    if answer == "":
        return default_yes
    return answer.lower() in ("o", "oui", "y", "yes")


def ask_int(question, default, low, high):
    """Demande un nombre entier borne. None si EOF."""
    while True:
        raw = ask(question, str(default))
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            print(f"  -> Entre un nombre entre {low} et {high}.")
            continue
        if value < low:
            print(f"  -> Minimum {low}, valeur ajustee.")
            return low
        if value > high:
            print(f"  -> Maximum {high}, valeur ajustee.")
            return high
        return value


def strength_label(bits):
    """Niveau de securite lisible selon l'entropie."""
    if bits < 50:
        return "Faible"
    if bits < 70:
        return "Correct"
    if bits < 90:
        return "Fort"
    return "Excellent"


def generate_one(length, classes):
    """Genere un mot de passe : 1 caractere garanti par classe + tirage CSPRNG."""
    rng = secrets.SystemRandom()
    chars = [rng.choice(cls) for cls in classes]
    pool = "".join(classes)
    chars += [rng.choice(pool) for _ in range(length - len(chars))]
    rng.shuffle(chars)
    return "".join(chars[:length])


def copy_to_clipboard(text):
    """Copie dans le presse-papiers (Windows/macOS/Linux). False si impossible."""
    try:
        if sys.platform.startswith("win"):
            subprocess.run(["clip"], input=text.encode("utf-8"),
                           check=True, stdout=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
        else:
            for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "-b"]):
                try:
                    subprocess.run(cmd, input=text.encode("utf-8"),
                                   check=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                    break
                except FileNotFoundError:
                    continue
            else:
                return False
        return True
    except Exception:
        return False


def configure():
    """Demande les reglages. Retourne un dict ou None si abandon (EOF)."""
    print()
    print("--- Reglages ---")
    length = ask_int("Nombre de caracteres", 16, 4, 128)
    if length is None:
        return None
    upper = ask_yes_no("Inclure les MAJUSCULES (A-Z) ?", True)
    lower = ask_yes_no("Inclure les minuscules (a-z) ?", True)
    digits = ask_yes_no("Inclure les CHIFFRES (0-9) ?", True)
    symbols = ask_yes_no(f"Inclure les SPECIAUX ({SYMBOLS}) ?", True)
    if None in (upper, lower, digits, symbols):
        return None

    classes = []
    names = []
    if lower:
        classes.append("abcdefghijklmnopqrstuvwxyz")
        names.append("minuscules")
    if upper:
        classes.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        names.append("MAJUSCULES")
    if digits:
        classes.append("0123456789")
        names.append("chiffres")
    if symbols:
        classes.append(SYMBOLS)
        names.append("speciaux")
    if not classes:
        print("  -> Choisis au moins un type de caracteres, on recommence.")
        return configure()

    if ask_yes_no("Exclure les ambigus (0, O, 1, l, I) ?", True):
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
        names.append("sans ambigus")

    if length < len(classes):
        print(f"  -> Longueur trop petite, ajustee a {len(classes)}.")
        length = len(classes)

    count = ask_int("Combien de mots de passe ?", 5, 1, 50)
    if count is None:
        return None

    pool_size = sum(len(c) for c in classes)
    return {"length": length, "classes": classes, "names": names,
            "count": count, "pool_size": pool_size}


def show_passwords(passwords, cfg):
    """Affichage lisible : un bloc numerote par mot de passe + niveau."""
    bits = cfg["length"] * math.log2(cfg["pool_size"])
    print()
    print(BAR)
    print(f"  {len(passwords)} mot(s) de passe | {cfg['length']} caracteres | "
          f"{', '.join(cfg['names'])}")
    print(f"  Securite : {strength_label(bits)} (~{bits:.0f} bits d'entropie)")
    print(BAR)
    for i, pwd in enumerate(passwords, start=1):
        print(f"  [{i}] {pwd}")
    print(BAR)
    print("  Astuce : ils ne sont jamais enregistres sur disque.")
    print()


def main():
    print(BAR)
    print("  GENERATEUR DE MOTS DE PASSE SECURISES")
    print("  (Ctrl+Z puis Entree pour quitter a tout moment)")
    print(BAR)

    cfg = configure()
    if cfg is None:
        print("\nAbandon.")
        return 0
    passwords = [generate_one(cfg["length"], cfg["classes"])
                 for _ in range(cfg["count"])]
    show_passwords(passwords, cfg)

    while True:
        choice = ask("Que faire ? [R]egenerer  [C]opier  [N]ouvelle config  [Q]uitter", "Q")
        if choice is None:
            break
        choice = choice.lower()
        if choice in ("q", "quitter", ""):
            break
        if choice in ("r", "regenerer"):
            passwords = [generate_one(cfg["length"], cfg["classes"])
                         for _ in range(cfg["count"])]
            show_passwords(passwords, cfg)
        elif choice in ("n", "nouvelle"):
            cfg = configure()
            if cfg is None:
                break
            passwords = [generate_one(cfg["length"], cfg["classes"])
                         for _ in range(cfg["count"])]
            show_passwords(passwords, cfg)
        elif choice in ("c", "copier"):
            raw = ask(f"Numero a copier (1-{len(passwords)})", "1")
            if raw is None:
                break
            try:
                idx = int(raw)
            except ValueError:
                print("  -> Numero invalide.")
                continue
            if 1 <= idx <= len(passwords):
                if copy_to_clipboard(passwords[idx - 1]):
                    print("  -> Copie dans le presse-papiers !")
                else:
                    print("  -> Presse-papiers indisponible sur ce systeme.")
            else:
                print("  -> Numero invalide.")
        else:
            print("  -> Choix inconnu (R, C, N ou Q).")

    print("\nA bientot — ne partage jamais tes mots de passe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
