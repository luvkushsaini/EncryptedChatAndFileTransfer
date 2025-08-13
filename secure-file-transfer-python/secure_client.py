#!/usr/bin/env python3
"""
Secure File Transfer — Client
Performs authenticated connect, then either:
(1) download a file (server encrypts with our RSA public key), or
(2) upload a file (we encrypt with server's RSA public key).
"""

import os
import socket
from typing import Tuple

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto import Random

# ------------------------------- Config ------------------------------------ #
HOST = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR: Tuple[str, int] = (HOST, PORT)
ENC = "utf-8"
BUF = 1024

# change these to whatever you want to test
DOWNLOAD_SOURCE_NAME = "hawk.png"   # when choice == 1 (download), ask server for this
UPLOAD_TARGET_NAME = "output.png"   # when choice == 2 (upload), save decrypted file as this

BEGIN_TOKEN = b"BEGIN"
END_TOKEN = b"ENDED"
# --------------------------------------------------------------------------- #


def log(msg: str) -> None:
    print(f"[CLIENT] {msg}")


def hybrid_encrypt_for_pub(pub_pem: str, src_path: str, out_bundle: str = "bundle.enc") -> str:
    """Encrypt file with AES-EAX; encrypt AES key with RSA-OAEP (using given public key)."""
    aes_key = get_random_bytes(16)

    rsa_pub = RSA.import_key(pub_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_pub)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    with open(src_path, "rb") as f:
        raw = f.read()

    aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes.encrypt_and_digest(raw)

    with open(out_bundle, "wb") as f:
        f.write(enc_aes_key)
        f.write(aes.nonce)
        f.write(tag)
        f.write(ciphertext)

    return out_bundle


def hybrid_decrypt_with_priv(bundle_path: str, priv_pem: bytes, out_path: str) -> str:
    with open(bundle_path, "rb") as f:
        enc_aes_key = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    rsa_priv = RSA.import_key(priv_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_priv)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = aes.decrypt_and_verify(ciphertext, tag)

    with open(out_path, "wb") as f:
        f.write(data)

    return out_path


def main() -> None:
    # connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(ADDR)

    # ---- auth flow ----
    prompt = sock.recv(2048).decode(ENC)
    username = input(prompt)
    sock.send(username.encode(ENC))

    prompt = sock.recv(2048).decode(ENC)
    password = input(prompt)
    sock.send(password.encode(ENC))

    status = sock.recv(2048).decode(ENC)
    log(f"Auth: {status}")
    if status == "Login Failed":
        sock.close()
        return

    # ---- menu ----
    print(""" Choose operation:
    1 : Download file
    2 : Upload file
    3 : Exit
    """)
    choice = input("OPTION: ").strip()
    sock.send(choice.encode(ENC))

    if choice == "1":
        # Generate ephemeral keypair; send public key to server
        rnd = Random.new().read
        rsa = RSA.generate(2048, rnd)
        pub_pem = rsa.publickey().export_key()
        priv_pem = rsa.export_key()

        # send filename we want
        sock.send(DOWNLOAD_SOURCE_NAME.encode(ENC))
        _ = sock.recv(BUF)  # "Filename received."

        # send our public key so server can encrypt for us
        sock.send(pub_pem)
        log("Sent public key")

        # receive encrypted bundle
        bundle = "rec.enc"
        with open(bundle, "wb") as f:
            while True:
                chunk = sock.recv(BUF)
                if chunk == BEGIN_TOKEN:
                    continue
                if chunk == END_TOKEN:
                    break
                f.write(chunk)

        # ack from server
        ack = sock.recv(BUF).decode(ENC)
        log(f"Server says: {ack}")

        # decrypt bundle with our private key
        out_path = hybrid_decrypt_with_priv(bundle, priv_pem, DOWNLOAD_SOURCE_NAME)
        log(f"Decrypted to: {out_path}")

        try:
            os.remove(bundle)
        except FileNotFoundError:
            pass

    elif choice == "2":
        # tell server the destination filename it should write
        sock.send(UPLOAD_TARGET_NAME.encode(ENC))
        _ = sock.recv(BUF)  # "Filename received."

        # receive server's public key
        pub_pem = sock.recv(BUF).decode(ENC)
        log("Received server public key")

        # encrypt local file and send bundle
        bundle = hybrid_encrypt_for_pub(pub_pem, UPLOAD_TARGET_NAME)

        with open(bundle, "rb") as f:
            sock.send(BEGIN_TOKEN)
            while True:
                chunk = f.read(BUF)
                sock.send(chunk)
                if not chunk:
                    break
            sock.send(END_TOKEN)

        sock.send(b"File data received")
        try:
            os.remove(bundle)
        except FileNotFoundError:
            pass

    else:
        sock.close()
        return

    sock.close()


if __name__ == "__main__":
    main()
