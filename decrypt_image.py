#!/usr/bin/env python3
"""
decrypt_image.py

Decrypt a .enc file created by encrypt_image.py and recover the original PNG.

Input format:
  [magic:8][version:1][scrypt_n:4][scrypt_r:4][scrypt_p:4]
  [salt_len:2][nonce_len:2][salt][nonce][ciphertext_and_tag]

Usage:
    python3 decrypt_image.py image.png.enc "your secret passphrase"
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"IMGCRYPT"
VERSION = 1
KEY_LEN = 32


def derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Derive the AES key from the passphrase and Scrypt parameters."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=n,
        r=r,
        p=p,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def decrypt_container(blob: bytes, passphrase: str) -> bytes:
    """Parse the container and return the decrypted plaintext."""
    header_len = struct.calcsize(">8sBIIIHH")
    if len(blob) < header_len:
        raise ValueError("Encrypted file is too short.")

    magic, version, n, r, p, salt_len, nonce_len = struct.unpack(
        ">8sBIIIHH", blob[:header_len]
    )

    if magic != MAGIC:
        raise ValueError("Invalid file format or magic header.")
    if version != VERSION:
        raise ValueError(f"Unsupported file version: {version}")

    expected_min_len = header_len + salt_len + nonce_len + 16
    if len(blob) < expected_min_len:
        raise ValueError("Encrypted file is truncated or malformed.")

    offset = header_len
    salt = blob[offset : offset + salt_len]
    offset += salt_len

    nonce = blob[offset : offset + nonce_len]
    offset += nonce_len

    ciphertext = blob[offset:]
    header = blob[:header_len]

    key = derive_key(passphrase, salt, n, r, p)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed: wrong passphrase or file has been tampered with."
        ) from exc

    return plaintext


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Decrypt a .enc image file created by encrypt_image.py."
    )
    parser.add_argument("encrypted_file", help="Path to the .enc file")
    parser.add_argument("secret_key", help="Passphrase used for encryption")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    in_path = Path(args.encrypted_file)

    try:
        if not in_path.is_file():
            raise FileNotFoundError(f"Input file not found: {in_path}")

        blob = in_path.read_bytes()
        plaintext = decrypt_container(blob, args.secret_key)

        if in_path.name.endswith(".png.enc"):
            out_path = in_path.with_name(in_path.name[:-4])
        elif in_path.suffix == ".enc":
            out_path = in_path.with_suffix("")
        else:
            out_path = in_path.with_name(in_path.name + ".dec.png")

        with out_path.open("xb") as f:
            f.write(plaintext)

        print(f"Decrypted: {in_path}")
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
