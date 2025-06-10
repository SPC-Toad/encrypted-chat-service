# 🔐 Secure Chat App — DIY Signal-Style Encrypted Messaging

## 🧭 Overview

This is a simplified 1-on-1 encrypted messaging application built from scratch to study both **OSI/TCP-IP networking models** and **modern cryptographic security**. It draws direct inspiration from Signal Protocol (X3DH + Double Ratchet Algorithm) and implements secure key exchange, message encryption, and forward secrecy.

The goal: Make secure communication understandable—without magic.

---

## 📚 Table of Contents

* [Motivation](#motivation)
* [How It Works (In Depth)](#how-it-works-in-depth)

  * [Simplified Key Agreement (IK + EK)](#1-simplified-key-agreement-ik--ek-only)
  * [Double Ratchet Algorithm](#2-double-ratchet-algorithm)
  * [ChaCha20-Poly1305 Encryption](#3-chacha20-poly1305-encryption)
  * [Message Format](#4-message-format-whats-actually-sent)
  * [Security Properties](#5-security-properties-achieved)
  * [Differences from Full X3DH](#6-differences-from-full-x3dh)
* [Real-Time Demo](#real-time-demo)
* [Tech Stack](#tech-stack)
* [Things I Learned](#things-i-learned)
* [Resources](#resources)
* [Author](#author)

---

## 🚀 Motivation

I built this project to deepen my understanding of how data travels from **Layer 1 (Physical)** to **Layer 7 (Application)** in the OSI model—focusing especially on **security** at the upper layers.

Rather than rely on high-level abstractions, I used mid-level cryptographic primitives (`X25519`, `ChaCha20-Poly1305`, `HKDF`) to manually piece together Signal’s core protocol flows.

---

## ⚙️ How It Works (In Depth)

This application implements a **simplified version** of the Signal Protocol—focusing on:

1. **Key Agreement using X25519** (not full X3DH)
2. **Double Ratchet Algorithm** for forward secrecy
3. **ChaCha20-Poly1305 encryption** for confidentiality + integrity

### 🔐 1. Simplified Key Agreement (IK + EK only)

Each client generates:

* A long-term **Identity Key (IK)**: a persistent `X25519` keypair on Curve25519
* A one-time **Ephemeral Key (EK)**: used per session for forward secrecy

Only **public keys** are exchanged between clients.

Each side computes the **shared secret** using:

```python
shared_secret = X25519_private_key.exchange(peer_ephemeral_public_key)
```

This shared secret is then used to derive an initial root key:

```python
root_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b"\x00" * 32,
    info=b"initial root key"
).derive(shared_secret)
```

This `root_key` initializes the Double Ratchet.

### 🔁 2. Double Ratchet Algorithm

Each message is encrypted with a fresh key.

Each client maintains:

* A **root key**
* A **chain key** for sending or receiving
* A **ratchet keypair** (rotated when needed)

Message flow:

1. Advance chain key → derive `message_key`
2. Encrypt message with `message_key`
3. Rotate ratchet keys if peer’s public key changes
4. Recompute shared secret and new `root_key`

This ensures **forward secrecy** and **post-compromise security**.

### 🔐 3. ChaCha20-Poly1305 Encryption

ChaCha20 is used with Poly1305 for encryption and authentication.

```python
cipher = ChaCha20Poly1305(message_key)
ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)
```

Each message gets a new nonce and key.

### 📡 4. Message Format (What’s Actually Sent)

```json
{
    "type": "chat",
    "sender": "user",
    "ek_public": "<base64-encoded ephemeral public key>",
    "nonce": "<base64-encoded nonce>",
    "ciphertext": "<base64-encoded ciphertext>",
}
```

The server never sees plaintext—only relays ciphertext.

### 🛡️ 5. Security Properties (Achieved)

* ✅ **Confidentiality**: Encryption with fresh keys
* ✅ **Integrity**: Poly1305 MAC
* ✅ **Forward Secrecy**: New key per message
* ✅ **Post-Compromise Security**: New DH key breaks past access
* ❌ **Async Start**: Both clients must be online

### 🔄 6. Differences from Full X3DH

| Feature            | Full X3DH              | This Project            |
| ------------------ | ---------------------- | ----------------------- |
| Identity Key       | ✅                      | ✅                       |
| Ephemeral Key      | ✅                      | ✅                       |
| Signed Prekey      | ✅                      | ❌                       |
| One-Time Prekey    | ✅                      | ❌                       |
| Asynchronous Start | ✅                      | ❌ (synchronous only)    |
| Authentication     | Stronger (via SPK sig) | Weaker (implicit trust) |

---

## 🎥 Real-Time Demo

A full terminal-recorded session showing:
* What a client sends to the server (raw TCP data)
* How the encrypted packet looks in transit (non-human-readable)
* What each client sees before & after encryption

https://github.com/user-attachments/assets/2de91535-f279-4bc3-bbd9-c3d24fa34493

---

## 🛠️ Tech Stack

* **Python 3.11+**
* `cryptography` for X25519 & HKDF
* `pycryptodome` for ChaCha20-Poly1305
* `socket` for TCP client/server
* `prompt_toolkit` for interactive terminal UI

---

## 🧠 Things I Learned

* Port `5222` is commonly used by messaging protocols (like WhatsApp) as it is offical XMPP port
* Synchronization between sender/receiver is critical (race condition bugs!)
* Forward secrecy works only if keys are rotated properly

---

## 📖 Resources

* [Signal Protocol Whitepaper](https://signal.org/docs/)
* [Curve25519 / X25519 Docs](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/)
* [ChaCha20Poly1305](https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20_poly1305.html)
* [Prompt Toolkit](https://python-prompt-toolkit.readthedocs.io/en/master/)
* [Computerphile Videos on E2EE](https://www.youtube.com/@Computerphile)
* [FUTO on Signal Protocol](https://www.youtube.com/watch?v=kdlzSZxMpgw&ab_channel=FUTO)

---

## 👤 Author

**Sangyun Kim**
> Built to demystify encrypted chat—one ratchet at a time.
