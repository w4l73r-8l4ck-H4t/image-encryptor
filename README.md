# Image Encryptor

A small tool for encrypting PNG images with a passphrase.

I wrote this because too many people confuse obscurity with security. Hiding a file is easy. Protecting it properly is something else.

This repo contains:

* `encrypt_image.py` — encrypt a `.png` into a `.enc` file
* `decrypt_image.py` — restore the original image with the correct key

It uses:

* **Scrypt** for key derivation
* **AES-GCM** for authenticated encryption

No shortcuts. No homemade crypto. No half measures.

## Install

```bash
pip install cryptography
```

## Usage

```bash
python3 encrypt_image.py image.png "your secret passphrase"
python3 decrypt_image.py image.png.enc "your secret passphrase"
```

If the key is wrong, decryption fails. If the file was modified, decryption fails.

As it should.

Security is not magic. It is process.
