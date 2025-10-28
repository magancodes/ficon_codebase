# Secure, Decentralized Peer-to-Peer Chat

**Authors: Maganjot Singh, Sumit**

[![Project Status](https://img.shields.io/badge/status-in%20development-orange)](https://github.com/example/repo)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/example/repo/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## 📖 About This Project

This project is a secure, decentralized, and serverless peer-to-peer chat system designed for local area networks (LANs). It provides a "Discord-like" real-time chat experience without relying on any central servers, ensuring that all communication is completely private, authenticated, and resilient.

This system is built from the ground up, featuring a custom reliable transport protocol over UDP and a state-of-the-art, multi-layered security framework to protect against both passive eavesdropping and active network attacks.

## ✨ Core Features

* **Serverless P2P Architecture:** No central server or internet connection is required. All communication is directly peer-to-peer.
* **Zero-Configuration Discovery:** Automatically finds other users on the local network using **mDNS / DNS-SD (Zeroconf)**.
* **True End-to-End Encryption (E2EE):** All messages are secured using modern authenticated encryption (AEAD).
* **Advanced Security:** Implements **Forward Secrecy** and **Post-Compromise Security** inspired by the Signal Protocol's Double Ratchet algorithm.
* **MITM Resistant:** An authenticated key exchange protocol (ECDH + Ed25519) prevents man-in-the-middle attacks.
* **Reliable & Fast Transport:** A custom Go-Back-N ARQ protocol built on UDP provides reliable, in-order message delivery without TCP's head-of-line blocking.

## 🏛️ Architectural Overview

The system is built on a layered stack that separates transport, security, and discovery.

1.  **Transport Layer (Custom UDP Protocol):**
    A custom reliable transport protocol is implemented in user-space over UDP. It uses a multi-threaded engine (Sender, Receiver, Timer) to manage a TCP-like connection, complete with a 3-way handshake, sequence numbers, and a Go-Back-N ARQ mechanism for guaranteed, in-order delivery.

2.  **Security Framework (E2EE):**
    A robust, multi-layered security framework is built directly on top of the transport layer. It uses an authenticated key exchange to establish a shared secret and then encrypts all further communication. Crucially, the unencrypted transport header is used as **Associated Data (AD)** in the AEAD operation, cryptographically binding the packet metadata to its payload and preventing tampering.

3.  **Peer Discovery (Zeroconf):**
    To achieve a zero-configuration user experience, the application uses **mDNS (Multicast DNS)** and **DNS-SD (Service Discovery)**. Each client advertises its presence on the `_lan-chat._udp.local` service, publishing its display name and long-term public identity key in a DNS `TXT` record. This allows clients to automatically discover each other and bootstrap the trust needed for the authenticated key exchange.

## 🔒 Security Model

The system is designed to be secure against both passive eavesdroppers and active attackers (e.g., Man-in-the-Middle) on the local network. Our security is built on a selection of modern, well-vetted cryptographic primitives.

| Function | Algorithm | Recommended Library Function (libsodium) |
| :--- | :--- | :--- |
| **Long-Term Identity** | **Ed25519** (Digital Signature) | `crypto_sign_keypair` |
| **Key Agreement** | **ECDH (X25519)** | `crypto_kx_keypair` |
| **Symmetric Encryption**| **XChaCha20-Poly1305** (AEAD) | `crypto_aead_xchacha20poly1305_ietf_encrypt` |
| **General-Purpose Hash** | **BLAKE2b** | `crypto_generichash` |

For ongoing conversations, the protocol implements a **Double Ratchet** algorithm. This provides:
* **Forward Secrecy:** A compromise of session keys at one point in time does not allow an attacker to decrypt past messages.
* **Post-Compromise Security:** The protocol can "heal" itself, re-establishing security for future messages even after a device's state has been compromised.

## 🛠️ Technology Stack

This project is designed with security and performance as primary goals.

* **Language:** **Rust** is the recommended language due to its compile-time guarantees for memory safety and thread safety, which are critical for building secure, concurrent network applications.
* **Cryptography:** **libsodium** (or its Rust bindings) is used for all cryptographic operations. It provides a high-level, audited, and easy-to-use API that abstracts away the complexities of low-level crypto.
* **Peer Discovery:** A cross-platform **Zeroconf** library (e.g., `zeroconf` crate for Rust) is used to handle the mDNS/DNS-SD protocol.

