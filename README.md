# APKG — Arshavir Package Format (V1)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Made with ❤️ by Arshavir](https://img.shields.io/badge/Made%20by-Arshavir%20Mirzakhani-red)](#)

**APKG (Arshavir Package Format)** is a lightweight, open-source, and mod-friendly archive format designed for game engines.  
It provides **fast file access**, an **extensible structure**, and optional **XSalsa20+Poly1305 encryption** for protecting assets using [libsodium](https://doc.libsodium.org/).

---

## ✨ Features
- 🔹 Simple, predictable binary layout (easy to parse in C++)
- 🔹 Fast random file access (no extraction required)
- 🔹 Optional strong encryption (libsodium, XSalsa20 + Poly1305)
- 🔹 Designed for mods and game engine workflows
- 🔹 Open and extensible (MIT licensed)

---

## 📦 Format Structure

An **APKG** file consists of three main parts:
1. Header 
2. HeaderExtra (optional)
3. Block (file table + data)


### **1. Header**
| Field             | Type     | Description                            |
|-------------------|----------|----------------------------------------|
| Magic             | char[4]  | Always `"APKG"`                        |
| Version           | uint32   | Format version (e.g. `1`)              |
| Flags             | uint32   | `0x1 = Encrypted`, else `0`            |
| DevSigLen         | uint32   | Length of developer signature          |
| DevSignature      | bytes    | Developer string (e.g. `"SIGNATURE"`)  |
| FileCount         | uint32   | Number of files in package             |
| FileTableOffset   | uint64   | Absolute offset of block start         |

---

### **2. HeaderExtra (only if encrypted)**
| Field     | Type   | Description                           |
|-----------|--------|---------------------------------------|
| SaltLen   | uint32 | Length of salt                        |
| Salt      | bytes  | Random salt for Argon2 key derivation |
| NonceLen  | uint32 | Length of XSalsa20+Poly1305 nonce     |
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
- **Algorithm**: XSalsa20 + Poly1305 via libsodium crypto_secretbox.
- **Key derivation**: Argon2i using provided password and stored salt.
- **Nonce**: Random, stored in `HeaderExtra`.  

If the `FLAG_ENCRYPTED` bit is set, the block must be decrypted before parsing.

---

## 🚀 Example Usage

### C++

```c++
#include "apkg.h"
#include <iostream>
#include <sodium.h>
#include <string>
#include <vector>

int main() {
	if (sodium_init() < 0) {
		std::cerr << "libsodium initialization failed!" << std::endl;
		return 1;
	}

	// ---------------------------
	// Create an APKG archive
	// ---------------------------
	try {
		APKGWriter writer("example.apkg", "ARSHAVIR", ""); // No password encryption

		// Add files to the archive
		writer.add_file("test.txt"); // Text file

		// Save the archive to disk
		writer.save();
		std::cout << "Archive created successfully." << std::endl;
	} catch (const std::exception& e) {
		std::cerr << "Error creating archive: " << e.what() << std::endl;
		return 1;
	}

	// ---------------------------
	// Read from the archive
	// ---------------------------
	try {
		APKGReader reader("example.apkg", ""); // Password empty

		// Read a single file
		std::vector<uint8_t> textData = reader.read_file("test.txt");

		std::cout << "--- Contents of test.txt ---" << std::endl;
		// Properly print text without garbage
		std::cout.write(reinterpret_cast<const char*>(textData.data()), textData.size());
		std::cout << std::endl << "-----------------------------" << std::endl;

		// Extract all files to a folder
		reader.extract_all("extracted_files");
		std::cout << "All files extracted to 'extracted_files/' folder." << std::endl;

		// Optional: print metadata
		std::cout << "Archive Developer Signature: " << reader.get_dev_signature() << std::endl;
		std::cout << "Archive Version: " << reader.get_version() << std::endl;
		std::cout << "Encrypted? " << (reader.is_encrypted() ? "Yes" : "No") << std::endl;
	} catch (const std::exception& e) {
		std::cerr << "Error reading archive: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
```