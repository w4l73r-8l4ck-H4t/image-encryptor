#!/usr/bin/env python3
"""
encrypt_image.py

Encrypt a PNG file using a passphrase-derived symmetric key.

- Key derivation: Scrypt
- Authenticated encryption: AES-256-GCM
- Output format: custom binary container
  [magic:8][version:1][scrypt_n:4][scrypt_r:4][scrypt_p:4]
  [salt_len:2][nonce_len:2][salt][nonce][ciphertext_and_tag]

Usage:
    python3 encrypt_image.py image.png "your secret passphrase"
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"IMGCRYPT"
VERSION = 1

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the passphrase using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt bytes and return the full binary container."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(passphrase, salt)

    aesgcm = AESGCM(key)

    header = struct.pack(
        ">8sBIIIHH",
        MAGIC,
        VERSION,
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        SALT_LEN,
        NONCE_LEN,
    )

    ciphertext = aesgcm.encrypt(nonce, plaintext, header)

    return header + salt + nonce + ciphertext


def validate_png(path: Path) -> None:
    if path.suffix.lower() != ".png":
        raise ValueError("Input file must have a .png extension.")
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")

    with path.open("rb") as f:
        sig = f.read(8)

    if sig != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Input file does not appear to be a valid PNG file.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Encrypt a PNG image with a passphrase."
    )
    parser.add_argument("image", help="Path to the input .png file")
    parser.add_argument("secret_key", help="Passphrase used for encryption")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    in_path = Path(args.image)

    try:
        validate_png(in_path)

        plaintext = in_path.read_bytes()
        encrypted = encrypt_bytes(plaintext, args.secret_key)

        out_path = in_path.with_name(in_path.name + ".enc")
        # Exclusive create prevents accidental overwrite.
        with out_path.open("xb") as f:
            f.write(encrypted)

        print(f"Encrypted: {in_path}")
        print(f"Output:    {out_path}")
        return 0

    except FileExistsError:
        print("Error: output file already exists. Remove it first or rename the input.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
