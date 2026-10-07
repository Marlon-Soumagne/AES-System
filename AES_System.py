"""
Schema:   RSA-OAEP-SHA256  (Key-Encapsulation)
        + AES-256-GCM      (Datenverschlüsselung)
        + PBKDF2-SHA256    (Passwort → Schlüsselableitung)
"""

import base64
import json
import sys
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


AES_KEY_LEN    = 32          # AES-256 → 32 Byte
GCM_NONCE_LEN  = 16          # 128-Bit Nonce (≥ 96 Bit empfohlen)
GCM_TAG_LEN    = 16          # 128-Bit Authentifizierungs-Tag (Maximum)
PBKDF2_SALT    = 32          # 256-Bit Salt
PBKDF2_ITER    = 600_000     # OWASP-Empfehlung 2023 für PBKDF2-HMAC-SHA256
RSA_KEY_SIZE   = 4096        # Produktionsstandard; Minimum: 2048


def _b64enc(data: bytes) -> str:
    """Bytes → URL-safe Base64-String (kein Padding-Problem mit JSON)."""
    return base64.b64encode(data).decode("ascii")


def _b64dec(s: str) -> bytes:
    """Base64-String → Bytes; wirft ValueError bei ungültiger Eingabe."""
    try:
        return base64.b64decode(s)
    except Exception as exc:
        raise ValueError(f"Ungültige Base64-Daten: {exc}") from exc


def _require_keys(d: dict, *keys: str) -> None:
    """Stellt sicher, dass alle Pflichtfelder im JSON vorhanden sind."""
    missing = [k for k in keys if k not in d]
    if missing:
        raise ValueError(f"Fehlende Felder im Paket: {missing}")


def password_encrypt(plaintext: str, password: str) -> str:
    """
    Verschlüsselt `plaintext` symmetrisch mit AES-256-GCM.
    Der AES-Schlüssel wird mittels PBKDF2-HMAC-SHA256 aus `password` abgeleitet.

    Rückgabe: JSON-String mit allen nötigen Parametern für die Entschlüsselung.

    Sicherheitseigenschaften:
    ─ Authentifizierte Verschlüsselung (GCM-Tag verhindert Manipulation)
    ─ Zufälliger Salt + Nonce → kein Key-/Nonce-Reuse möglich
    ─ PBKDF2 mit 600.000 Iterationen erschwert Brute-Force
    """
    salt  = get_random_bytes(PBKDF2_SALT)
    nonce = get_random_bytes(GCM_NONCE_LEN)

    # Schlüsselableitung: PBKDF2-HMAC-SHA256
    key = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=AES_KEY_LEN,
        count=PBKDF2_ITER,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest(),
    )

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))

    payload = {
        "version":    1,
        "scheme":     "PBKDF2-SHA256+AES-256-GCM",
        "iterations": PBKDF2_ITER,
        "salt":       _b64enc(salt),
        "nonce":      _b64enc(nonce),
        "ciphertext": _b64enc(ciphertext),
        "tag":        _b64enc(tag),
    }
    return json.dumps(payload, separators=(",", ":"))


def password_decrypt(encrypted_json: str, password: str) -> str:
    """
    Entschlüsselt ein von `password_encrypt()` erzeugtes JSON-Paket.

    Wirft ValueError wenn:
    ─ Das Paket syntaktisch ungültig ist
    ─ Das Passwort falsch ist
    ─ Der Ciphertext oder Tag manipuliert wurde
    (Kein differenzierter Fehlerhinweis, um Timing-Angriffe zu erschweren.)
    """
    try:
        data = json.loads(encrypted_json)
        _require_keys(data, "salt", "nonce", "ciphertext", "tag")
        salt       = _b64dec(data["salt"])
        nonce      = _b64dec(data["nonce"])
        ciphertext = _b64dec(data["ciphertext"])
        tag        = _b64dec(data["tag"])
        iterations = int(data.get("iterations", PBKDF2_ITER))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("Ungültiges oder beschädigtes Verschlüsselungspaket.") from exc

    key = PBKDF2(
        password.encode("utf-8"),
        salt,
        dkLen=AES_KEY_LEN,
        count=iterations,
        prf=lambda p, s: HMAC.new(p, s, SHA256).digest(),
    )
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        # Generische Meldung – kein Leak, ob Passwort oder Tag falsch war
        raise ValueError(
            "Entschlüsselung fehlgeschlagen – falsches Passwort oder Daten manipuliert."
        ) from exc

    return plaintext.decode("utf-8")


def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> Tuple[str, str]:
    """
    Erzeugt ein RSA-Schlüsselpaar in PEM-Format.
    Gibt (public_pem, private_pem) zurück.
    """
    if key_size < 2048:
        raise ValueError("RSA-Schlüsselgröße muss mindestens 2048 Bit betragen.")
    key = RSA.generate(key_size)
    return (
        key.publickey().export_key("PEM").decode("ascii"),
        key.export_key("PEM").decode("ascii"),
    )


def save_pem(pem: str, filename: str) -> None:
    """Speichert einen PEM-String in eine Datei."""
    with open(filename, "w", encoding="ascii") as f:
        f.write(pem)


def load_pem(filename: str) -> str:
    """Lädt einen PEM-String aus einer Datei."""
    try:
        with open(filename, "r", encoding="ascii") as f:
            return f.read()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"Schlüsseldatei nicht gefunden: '{filename}'") from exc



def hybrid_encrypt(plaintext: str, public_pem: str) -> str:
    """
    Hybrides Verschlüsselungsschema – analog zu TLS-KEM:

    ┌─────────────────────────────────────────────────────────┐
    │  1. Zufälligen AES-256-Session-Key erzeugen             │
    │  2. Plaintext   →  AES-256-GCM(session_key)             │
    │  3. session_key →  RSA-OAEP-SHA256(public_key)          │
    └─────────────────────────────────────────────────────────┘

    Sicherheitseigenschaften:
    ─ Session-Key nie im Klartext übertragen
    ─ OAEP mit SHA-256 verhindert Padding-Oracle-Angriffe (vs. PKCS#1 v1.5)
    ─ GCM-Tag sichert Integrität der Nutzdaten
    ─ Frischer Nonce + Session-Key pro Nachricht → Perfect Forward Secrecy-ähnlich
    """
    # Schritt 1 – ephemerer Session-Key & Nonce
    session_key = get_random_bytes(AES_KEY_LEN)
    nonce       = get_random_bytes(GCM_NONCE_LEN)

    # Schritt 2 – Datenverschlüsselung mit AES-256-GCM
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext.encode("utf-8"))

    # Schritt 3 – Key-Encapsulation mit RSA-OAEP-SHA256
    public_key     = RSA.import_key(public_pem)
    cipher_rsa     = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    encrypted_key  = cipher_rsa.encrypt(session_key)

    payload = {
        "version":    1,
        "scheme":     "RSA-OAEP-SHA256+AES-256-GCM",
        "enc_key":    _b64enc(encrypted_key),   # RSA-verschlüsselter Session-Key
        "nonce":      _b64enc(nonce),
        "ciphertext": _b64enc(ciphertext),
        "tag":        _b64enc(tag),
    }
    return json.dumps(payload, separators=(",", ":"))


def hybrid_decrypt(encrypted_json: str, private_pem: str) -> str:
    """
    Entschlüsselt ein von `hybrid_encrypt()` erzeugtes JSON-Paket.

    Wirft ValueError wenn:
    ─ Das Paket ungültig ist
    ─ Der private Schlüssel nicht passt
    ─ Der GCM-Tag die Authentifizierung verweigert
    """
    try:
        data = json.loads(encrypted_json)
        _require_keys(data, "enc_key", "nonce", "ciphertext", "tag")
        encrypted_key = _b64dec(data["enc_key"])
        nonce         = _b64dec(data["nonce"])
        ciphertext    = _b64dec(data["ciphertext"])
        tag           = _b64dec(data["tag"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError("Ungültiges oder beschädigtes Verschlüsselungspaket.") from exc

    # Session-Key entschlüsseln (RSA-OAEP)
    try:
        private_key = RSA.import_key(private_pem)
        cipher_rsa  = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        session_key = cipher_rsa.decrypt(encrypted_key)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            "RSA-Entschlüsselung fehlgeschlagen – falscher Schlüssel oder Paket beschädigt."
        ) from exc

    # Daten entschlüsseln + GCM-Tag verifizieren
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LEN)
    try:
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise ValueError(
            "AES-Authentifizierung fehlgeschlagen – Ciphertext manipuliert."
        ) from exc

    return plaintext.decode("utf-8")


_MENU = """
╔══════════════════════════════════════╗
║   Hybride Kryptografie  v2           ║
╠══════════════════════════════════════╣
║  1) Passwort-Verschlüsselung (AES)   ║
║  2) Passwort-Entschlüsselung (AES)   ║
║  3) RSA-Schlüsselpaar erzeugen       ║
║  4) Hybrid-Verschlüsseln (RSA+AES)   ║
║  5) Hybrid-Entschlüsseln (RSA+AES)   ║
║  0) Beenden                          ║
╚══════════════════════════════════════╝"""


def _read_multiline(prompt: str) -> str:
    print(prompt)
    print("(Leere Zeile zum Beenden)")
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    return "\n".join(lines)


def _load_or_input_key(kind: str) -> str:
    """Fragt, ob ein PEM-Key aus Datei geladen oder manuell eingegeben wird."""
    if input(f"{kind} aus Datei laden? (j/n): ").strip().lower() == "j":
        return load_pem(input("Dateiname: ").strip())
    return _read_multiline(f"{kind} eingeben:")


def main() -> None:
    print(_MENU)
    choice = input("Auswahl: ").strip()

    if choice == "1":
        msg = input("Klartext: ")
        pw  = input("Passwort: ")
        print("\n[Verschlüsselt]\n" + password_encrypt(msg, pw))

    elif choice == "2":
        pkg = input("JSON-Paket einfügen: ")
        pw  = input("Passwort: ")
        try:
            print("\n[Klartext]\n" + password_decrypt(pkg, pw))
        except ValueError as err:
            print(f"\n[Fehler] {err}", file=sys.stderr)

    elif choice == "3":
        raw  = input("Schlüsselgröße (2048/4096) [4096]: ").strip()
        size = int(raw) if raw.isdigit() else 4096
        print(f"Erzeuge {size}-Bit RSA-Schlüsselpaar …")
        pub, priv = generate_rsa_keypair(size)
        print(f"\n[Public Key]\n{pub}")
        print(f"\n[Private Key]\n{priv}")
        if input("\nIn Dateien speichern? (j/n): ").strip().lower() == "j":
            save_pem(pub,  "public_key.pem")
            save_pem(priv, "private_key.pem")
            print("Gespeichert: public_key.pem  /  private_key.pem")

    elif choice == "4":
        msg = input("Klartext: ")
        try:
            pub = _load_or_input_key("Public Key")
            print("\n[Verschlüsselt]\n" + hybrid_encrypt(msg, pub))
        except (ValueError, FileNotFoundError) as err:
            print(f"\n[Fehler] {err}", file=sys.stderr)

    elif choice == "5":
        pkg = input("JSON-Paket einfügen: ")
        try:
            priv = _load_or_input_key("Private Key")
            print("\n[Klartext]\n" + hybrid_decrypt(pkg, priv))
        except (ValueError, FileNotFoundError) as err:
            print(f"\n[Fehler] {err}", file=sys.stderr)

    elif choice == "0":
        sys.exit(0)

    else:
        print("Ungültige Auswahl (0–5).", file=sys.stderr)


if __name__ == "__main__":
    main()
