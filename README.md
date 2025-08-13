# Secure File Transfer System (SFTS)

A lightweight Python-based application for transferring files securely over a network using **AES encryption** and socket programming.
Designed for ease of use and portability, this system ensures that files are encrypted before transmission and decrypted on arrival.

---

## 🚀 Features

* **End-to-end Encryption** — Uses AES to secure files during transfer.
* **Simple Setup** — Works over LAN or Wi-Fi using standard Python sockets.
* **Cross-Platform** — Runs on any OS with Python 3.x installed.
* **Two-Part System**:

  * **Server** — Receives encrypted files and decrypts them.
  * **Client** — Encrypts and sends files to the server.

---

## 🛠️ How It Works

1. The **Client** reads the file and encrypts it using a shared secret key.
2. The encrypted file is transmitted over a TCP socket connection.
3. The **Server** receives the file, decrypts it with the same secret key, and saves it locally.

---

## 📦 Requirements

* Python 3.x
* `cryptography` library

Install dependencies with:

```bash
pip install cryptography
```

---

## 📂 Project Structure

```
├── server.py    # Runs the secure file receiver
├── client.py    # Sends encrypted files to the server
└── README.md    # Documentation
```

---

## ▶️ Usage

### 1️⃣ Start the Server

```bash
python server.py
```

The server will listen for incoming file transfers.

### 2️⃣ Run the Client

```bash
python client.py
```

You will be prompted to enter:

* **Server IP address**
* **File path** of the file to send

---

## 🔒 Security Notes

* Uses AES-256 encryption for data confidentiality.
* Both client and server must share the **same encryption key**.
* Change the `SECRET_KEY` in both files before using in production.

---

## 📌 Example

**On Server Machine:**

```bash
python server.py
```

**On Client Machine:**

```bash
python client.py
# Enter server IP (e.g., 192.168.1.5)
# Enter file path (e.g., /home/user/document.pdf)
```
