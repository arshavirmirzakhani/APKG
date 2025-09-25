# APKG — Arshavir Package Format (V1)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Made with ❤️ by Arshavir](https://img.shields.io/badge/Made%20by-Arshavir%20Mirzakhani-red)](#)

**APKG (Arshavir Package Format)** is a lightweight, open-source, and mod-friendly archive format designed for game engines.  
It provides **fast file access**, an **extensible structure**, and optional **XSalsa20+Poly1305 encryption** for protecting assets using [libsodium](https://doc.libsodium.org/) and **per-file compression** using [zlib](https://zlib.net/).

---

## ✨ Features
- 🔹 Simple, predictable binary layout (easy to parse in C++)
- 🔹 Fast random file access (no extraction required)
- 🔹 Optional strong encryption (libsodium, XSalsa20 + Poly1305)
- 🔹 Designed for mods and game engine workflows
- 🔹 Open and extensible (MIT licensed)

---

## 📦 Format Structure

An **APKG** file consists of four main parts:
1. Header
2. HeaderExtra (optional, only if encrypted)
3. File Table (metadata only)
4. File Data Block (all file contents concatenated)

### Diagram of format structure
```
+-------------------+
| Header            |
+-------------------+
| HeaderExtra (opt) |
+-------------------+
| File Table        |
+-------------------+
| File Data Block   |
+-------------------+
```


### **1. Header**
| Field        | Type    | Description                           |
| ------------ | ------- | ------------------------------------- |
| Magic        | char[4] | Always `"APKG"`                       |
| Version      | uint32  | Format version (currently `1`)        |
| Flags        | uint32  | `0x1 = Encrypted`, `0x2 = Compressed` |
| DevSigLen    | uint32  | Length of developer signature         |
| DevSignature | bytes   | Developer string (e.g. `"SIGNATURE"`) |
| FileCount    | uint32  | Number of files in package            |
| FTableOffset | uint64  | Absolute offset of file table         |
| FTableSize   | uint64  | Size of file table in bytes           |
| FDataOffset  | uint64  | Absolute offset of file data block    |


---

### **2. HeaderExtra (only if FLAG_ENCRYPTED is set)**
| Field    | Type   | Description                           |
| -------- | ------ | ------------------------------------- |
| SaltLen  | uint32 | Length of salt                        |
| Salt     | bytes  | Random salt for Argon2 key derivation |
| NonceLen | uint32 | Length of XSalsa20+Poly1305 nonce     |
| Nonce    | bytes  | Random nonce for encryption           |

---

### **3. File Table (metadata only)**
| Field        | Type   | Description                                     |
| ------------ | ------ | ----------------------------------------------- |
| NameLen      | uint32 | Length of filename (UTF-8)                      |
| Name         | bytes  | Filename (supports subdirectories like `a/b.c`) |
| Offset       | uint64 | Offset relative to start of File Data block     |
| Size         | uint64 | Stored size (compressed if FLAG_COMPRESSED)     |
| OriginalSize | uint64 | Original uncompressed size (for decompression)  |


### **4. File Data Block**
Concatenation of all file contents.
- If FLAG_COMPRESSED, each file is compressed individually.
- If FLAG_ENCRYPTED, this entire block is encrypted as one (metadata stays plaintext).
---

## 🔐 Encryption
- Optional per-package encryption (applies to the entire **File Data Block**).  
- Metadata (file table, filenames, offsets, sizes) remains in plaintext.  
- **Algorithm**: XSalsa20 + Poly1305 via libsodium `crypto_secretbox`.  
- **Key derivation**: Argon2i using provided password and stored salt.  
- **Nonce**: Random, stored in `HeaderExtra`.  

If the `FLAG_ENCRYPTED` bit is set, the file data block must be decrypted before file extraction.

---

## 🗜 Compression
- Compression is per-file, not per-package.
- Each file is compressed independently using zlib (DEFLATE).
- OriginalSize in the file table ensures files can be decompressed.

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
		std::cout << "Compressed? " << (reader.is_compressed() ? "Yes" : "No") << std::endl;
	} catch (const std::exception& e) {
		std::cerr << "Error reading archive: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
```