# Hybrides Kryptografie-System (RSA-OAEP + AES-256-GCM + PBKDF2)

Ein leichtgewichtiges, aber extrem solides Python-Tool zur sicheren Ende-zu-Ende-Verschlüsselung. Das Projekt kombiniert symmetrische Datenverschlüsselung, asymmetrischen Schlüsselaustausch und gehärtete passwortbasierte Schlüsselableitung nach modernen Industriestandards (OWASP & NIST).

---

## Features

- **Hybride Verschlüsselung (RSA-OAEP + AES-256-GCM):**
  - **Asymmetrisch:** RSA-4096 mit OAEP-SHA256-Padding für sichere Key-Encapsulation (Schutz vor Padding-Oracle-Angriffen).
  - **Symmetrisch:** AES-256-GCM für performante Nutzdaten-Verschlüsselung inklusive Authentifizierung (AEAD).
- **Passwortbasierte Verschlüsselung (PBKDF2-HMAC-SHA256):**
  - Schlüsselableitung mit **600.000 Iterationen** (entspricht aktuellen OWASP-Empfehlungen).
  - Zufälliger 256-Bit-Salt verhindert Rainbow-Table-Angriffe.
- **Integritätsschutz & Authentizität:**
  - Authentifizierter GCM-Tag schützt vor Manipulation (Data Tampering).
- **Sicherheitsfokussiertes Design:**
  - Frische Zufallswerte (`Salt`, `Nonce`, `Session-Key`) pro Nachricht gegen Key-Reuse.
  - Generische Fehlermeldungen bei der Entschlüsselung zur Verhinderung von Timing-Side-Channel-Angriffen.
- **Interaktives Terminal-Menü & Portable JSON-Payloads.**

---

## Architekturübersicht

Hybride Verschlüsselung nutzt die Stärken beider Welten: Die Geschwindigkeit von AES für die Daten und die Flexibilität von RSA für den Schlüsselaustausch.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Hybrides Verschlüsselungsschema                 │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Generierung eines ephemeren (einmaligen) AES-256 Session-Keys      │
│ 2. Datenverschlüsselung: Plaintext ──(AES-256-GCM)──> Ciphertext + Tag │
│ 3. Key-Encapsulation:    Session-Key ──(RSA-OAEP)───> Encrypted Key    │
└────────────────────────────────────────────────────────────────────────┘
```

### Kryptografische Komponenten

| Komponenten-Typ | Verfahren / Algorithmus | Spezifikation / Parameter |
| :--- | :--- | :--- |
| **Passwort-Derivation** | PBKDF2-HMAC-SHA256 | 600.000 Iterationen, 32-Byte Salt |
| **Datenverschlüsselung** | AES-256-GCM | 256-Bit Key, 128-Bit Nonce, 128-Bit Tag |
| **Schlüsselaustausch** | RSA-OAEP | 4096 Bit Schlüsselgröße, MGF1/SHA-256 |

---

## Installation

### Voraussetzungen
- Python 3.8+

### 1. Repository klonen oder herunterladen
```bash
git clone https://github.com/dein-username/hybrid-crypto-python.git
cd hybrid-crypto-python
```

### 2. Abhängigkeiten installieren
Das Projekt nutzt [PyCryptodome](https://www.pycryptodome.org/) für die kryptografischen Primitiven:

```bash
pip install pycryptodome
```

---

## Nutzung & Code-Beispiele

Das Skript kann sowohl als **interaktives Terminal-Programm** gestartet als auch als **Modul in eigenen Python-Projekten** importiert werden.

### 1. Interaktives Menü ausführen

```bash
python main.py
```

Beispiel-Menüoberfläche:
```text
╔══════════════════════════════════════╗
║   Hybride Kryptografie  v2           ║
╠══════════════════════════════════════╣
║  1) Passwort-Verschlüsselung (AES)   ║
║  2) Passwort-Entschlüsselung (AES)   ║
║  3) RSA-Schlüsselpaar erzeugen       ║
║  4) Hybrid-Verschlüsseln (RSA+AES)   ║
║  5) Hybrid-Entschlüsseln (RSA+AES)   ║
║  0) Beenden                          ║
╚══════════════════════════════════════╝
```

---

### 2. Code-Beispiele für eigene Integrationen

#### A) Passwort-Verschlüsselung (AES-256-GCM + PBKDF2)
```python
from main import password_encrypt, password_decrypt

secret_text = "Geheime Botschaft"
password = "MeinStarkesPasswort123!"

# Verschlüsseln
encrypted_payload = password_encrypt(secret_text, password)
print("Verschlüsseltes JSON:", encrypted_payload)

# Entschlüsseln
decrypted_text = password_decrypt(encrypted_payload, password)
print("Entschlüsselt:", decrypted_text)
```

#### B) Hybride Verschlüsselung (RSA-4096 + AES-256-GCM)
```python
from main import generate_rsa_keypair, hybrid_encrypt, hybrid_decrypt

# 1. RSA-Schlüsselpaar generieren
public_key_pem, private_key_pem = generate_rsa_keypair(key_size=4096)

# 2. Nachricht mit dem Public Key verschlüsseln
message = "Vertrauliche Nachricht für Empfänger"
encrypted_json = hybrid_encrypt(message, public_key_pem)

# 3. Empfänger entschlüsselt mit seinem Private Key
decrypted_message = hybrid_decrypt(encrypted_json, private_key_pem)
print("Ergebnis:", decrypted_message)
```

---

## Datenformat (JSON Payload)

Die Ausgabe der Verschlüsselungsfunktionen ist ein kompaktes JSON-Paket. Alle Binärdaten (Nonces, Tags, Ciphertexts) sind URL-safe Base64-kodiert:

```json
{
  "version": 1,
  "scheme": "RSA-OAEP-SHA256+AES-256-GCM",
  "enc_key": "Base64-verschlüsselter-Session-Key...",
  "nonce": "Base64-GCM-Nonce...",
  "ciphertext": "Base64-Verschlüsselter-Text...",
  "tag": "Base64-GCM-Authentifizierungs-Tag..."
}
```

---

## Sicherheitshinweise

- **Private Keys schützen:** Der erzeugte RSA Private Key wird unverschlüsselt im PEM-Format gespeichert. In einer Produktionsumgebung sollte er mit einem Passwort schlüsselsicher auf der Festplatte abgelegt werden.
- **Integritätsgarantie:** Wird ein einziges Zeichen des JSON-Pakets manipuliert, schlägt `cipher.decrypt_and_verify()` fehl und die Entschlüsselung bricht sofort ab.
```
eof

Die `README.md` ist mit allen wichtigen Kapiteln (Architektur, Installation, Code-Beispielen und Sicherheitshinweisen) einsatzbereit für dein Repository.

<ElicitationsGroup message="Wie möchtest du als Nächstes vorgehen?">
  <Elicitation label="CLI-Argumente mit argparse hinzufügen" query="Erweitere das Python-Skript um CLI-Parameter (argparse), damit man es direkt per Terminal-Befehl aufrufen kann."/>
  <Elicitation label="Unit-Tests für das Skript erstellen" query="Schreibe passende pytest-Unit-Tests für die Verschlüsselungs- und Entschlüsselungsfunktionen."/>
</ElicitationsGroup>
