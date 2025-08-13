#!/usr/bin/env python3
"""
Secure File Transfer — Server
Hybrid crypto (RSA + AES) over TCP sockets with basic username/password auth
and simple multi-client handling via threads.

Protocol snippets:
- Text is UTF-8. Binary file payload is bracketed by BEGIN / ENDED tokens.
- AES (EAX) protects confidentiality + integrity of file contents.
- RSA (OAEP) transports the ephemeral AES session key.
"""

import os
import socket
import threading
import hashlib
from typing import Tuple, Dict

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes, random
from Crypto import Random

# ------------------------------- Config ------------------------------------ #
HOST = socket.gethostbyname(socket.gethostname())
PORT = 4455
ADDR: Tuple[str, int] = (HOST, PORT)
BUF = 1024
ENC = "utf-8"

# very simple in-memory user store (username -> sha256(password))
USER_STORE: Dict[str, str] = {}

BEGIN_TOKEN = b"BEGIN"
END_TOKEN = b"ENDED"

# --------------------------------------------------------------------------- #


def log(msg: str) -> None:
    print(f"[SERVER] {msg}")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode(ENC)).hexdigest()


def hybrid_encrypt_file(pub_pem: str, plaintext_path: str, bundle_path: str = "bundle.enc") -> str:
    """Encrypt file with AES-EAX; encrypt AES key with RSA-OAEP. Save combined bundle."""
    # 1) Random AES key
    aes_key = get_random_bytes(16)

    # 2) RSA key from client/server (PEM)
    rsa_key = RSA.import_key(pub_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # 3) AES-EAX encrypt file bytes
    with open(plaintext_path, "rb") as f:
        raw = f.read()

    aes_cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(raw)

    # 4) Write bundle: [enc_aes_key | nonce | tag | ciphertext]
    with open(bundle_path, "wb") as f:
        f.write(enc_aes_key)
        f.write(aes_cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    return bundle_path


def hybrid_decrypt_file(bundle_path: str, priv_pem: bytes, out_path: str) -> str:
    """Reverse of hybrid_encrypt_file — returns output filepath."""
    with open(bundle_path, "rb") as f:
        enc_aes_key = f.read(256)   # 2048-bit RSA -> 256 bytes
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    rsa_priv = RSA.import_key(priv_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_priv)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    try:
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
        data = aes_cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        log("Decryption or tag verification failed.")
        raise

    with open(out_path, "wb") as f:
        f.write(data)

    return out_path


def serve_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    log(f"Connected: {addr}")

    # ---- very light auth flow ----
    conn.send(b"ENTER USERNAME : ")
    username = conn.recv(2048).decode(ENC).strip()

    conn.send(b"ENTER PASSWORD : ")
    password = conn.recv(2048).decode(ENC).strip()
    password_hash = sha256(password)

    if username not in USER_STORE:
        USER_STORE[username] = password_hash
        conn.send(b"Registeration Successful")
        log(f"Registered user: {username}")
    else:
        if USER_STORE[username] != password_hash:
            conn.send(b"Login Failed")
            log(f"Auth failed for {username}")
            conn.close()
            return
        conn.send(b"Connection Successful")
        log(f"Authenticated user: {username}")

    # ---- main menu ----
    choice = conn.recv(BUF).decode(ENC).strip()
    if choice == "1":
        # client is downloading: server needs client's RSA pubkey to encrypt file key
        log("Download request received")

        # 1) filename
        filename = conn.recv(BUF).decode(ENC).strip()
        conn.send("Filename received.".encode(ENC))

        # 2) pubkey from client
        client_pub_pem = conn.recv(BUF).decode(ENC)
        log("Public key received from client")

        # 3) hybrid encrypt + send
        bundle_path = hybrid_encrypt_file(client_pub_pem, filename)

        log(f"Sending encrypted bundle: {bundle_path}")
        with open(bundle_path, "rb") as f:
            conn.send(BEGIN_TOKEN)
            while True:
                chunk = f.read(BUF)
                conn.send(chunk)
                if not chunk:
                    break
            conn.send(END_TOKEN)

        conn.send("File data received".encode(ENC))
        try:
            os.remove(bundle_path)
        except FileNotFoundError:
            pass

    elif choice == "2":
        # client is uploading: server generates a keypair, sends pubkey, then receives bundle
        log("Upload request received")

        # ephemeral RSA keypair
        rnd = Random.new().read
        rsa_key = RSA.generate(2048, rnd)
        pub_pem = rsa_key.publickey().export_key()
        priv_pem = rsa_key.export_key()

        # 1) filename (destination name)
        filename = conn.recv(BUF).decode(ENC).strip()
        conn.send("Filename received.".encode(ENC))

        # 2) send public key
        conn.send(pub_pem)
        log("Public key sent to client")

        # 3) receive encrypted bundle
        bundle_path = "rec.enc"
        with open(bundle_path, "wb") as f:
            while True:
                chunk = conn.recv(BUF)
                if chunk == BEGIN_TOKEN:
                    continue
                if chunk == END_TOKEN:
                    break
                f.write(chunk)

        confirm = conn.recv(BUF).decode(ENC)
        log(f"Client says: {confirm}")

        # 4) decrypt and save
        out_path = hybrid_decrypt_file(bundle_path, priv_pem, filename)
        log(f"Decrypted and saved: {out_path}")

        try:
            os.remove(bundle_path)
        except FileNotFoundError:
            pass

    # close per request
    conn.close()
    log(f"Disconnected: {addr}")


def main() -> None:
    log("Booting server...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    server.listen()
    log(f"Listening on {ADDR}")

    active = 0
    while True:
        conn, address = server.accept()
        t = threading.Thread(target=serve_client, args=(conn, address), daemon=True)
        t.start()
        active += 1
        log(f"Active connections: {active}")


if __name__ == "__main__":
    main()
