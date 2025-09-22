# APKG — Arshavir Package Format (V1)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Made with ❤️ by Arshavir](https://img.shields.io/badge/Made%20by-Arshavir%20Mirzakhani-red)](#)

**APKG (Arshavir Package Format)** is a lightweight, open-source, and mod-friendly archive format designed for game engines.  
It provides **fast file access**, an **extensible structure**, and optional **AES-256-GCM encryption** for protecting assets using [libsodium](https://doc.libsodium.org/).

---

## ✨ Features
- 🔹 Simple, predictable binary layout (easy to parse in C++, Python, etc.)
- 🔹 Fast random file access (no extraction required)
- 🔹 Optional strong encryption (libsodium, AES-256-GCM)
- 🔹 Designed for **mods and game engine workflows** in mind
- 🔹 Open and extensible (MIT licensed)

---

## 📦 Format Structure

An **APKG** file consists of three main parts:
1. Header 
2. HeaderExtra (optional)
3. Block (file table + data)


### **1. Header**
| Field             | Type     | Description                        |
|-------------------|----------|------------------------------------|
| Magic             | char[4]  | Always `"APKG"`                    |
| Version           | uint32   | Format version (e.g. `1`)          |
| Flags             | uint32   | `0x1 = Encrypted`, else `0`        |
| DevSigLen         | uint32   | Length of developer signature      |
| DevSignature      | bytes    | Developer string (e.g. `"ASTAR"`) |
| FileCount         | uint32   | Number of files in package         |
| FileTableOffset   | uint64   | Absolute offset of block start     |

---

### **2. HeaderExtra (only if encrypted)**
| Field     | Type   | Description                           |
|-----------|--------|---------------------------------------|
| SaltLen   | uint32 | Length of salt                        |
| Salt      | bytes  | Random salt for PBKDF2 key derivation |
| NonceLen  | uint32 | Length of AES-GCM nonce               |
| Nonce     | bytes  | Random nonce for encryption           |

---

### **3. Block**
The block contains both the **file table** and **file data**.

#### File Table (per file entry):
| Field     | Type     | Description                          |
|-----------|----------|--------------------------------------|
| NameLen   | uint32   | Length of filename                   |
| Name      | bytes    | Filename (UTF-8)                     |
| Offset    | uint64   | Offset relative to start of dataBlock|
| Size      | uint64   | File size in bytes                   |

#### File Data:
Concatenation of all files' raw contents.  
Offsets in the file table point into this region.

---

## 🔐 Encryption
- Optional per-package encryption (entire block is encrypted as one).  
- **Algorithm**: AES-256-GCM (with authentication).  
- **Key derivation**: PBKDF2-HMAC-SHA256 using the provided password and stored salt.  
- **Nonce**: Random, stored in `HeaderExtra`.  

If the `FLAG_ENCRYPTED` bit is set, the block must be decrypted before parsing.

---

