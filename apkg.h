#pragma once

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <vector>

const char MAGIC[4]	      = {'A', 'P', 'K', 'G'};	     // File magic identifier
const uint32_t FLAG_ENCRYPTED = 0x1;			     // Flag indicating archive is encrypted
const size_t SALT_SIZE	      = 16;			     // Size of salt for key derivation
const size_t NONCE_SIZE	      = crypto_secretbox_NONCEBYTES; // XSalsa20 nonce size (24 bytes)
const size_t KEY_SIZE	      = crypto_secretbox_KEYBYTES;   // XSalsa20 key size (32 bytes)

/// Structure representing a file to be added to the archive
struct FileEntry {
		std::string name;	   // File name inside the archive
		std::vector<uint8_t> data; // File content
};

/// APKGWriterV1 class
///
/// This class provides functionality to create APKG archives with optional
/// encryption. Encryption uses libsodium SecretBox (XSalsa20 + Poly1305) with
/// Argon2i key derivation.
class APKGWriter {
		std::string path;	      // Path to save the archive
		std::string dev_sig;	      // Developer signature stored in archive header
		std::vector<FileEntry> files; // List of files to include in the archive
		std::string password;	      // Optional password for encryption

	public:
		/// Constructor
		/// @param p Path to save the archive
		/// @param sig Developer signature (default "")
		/// @param pwd Optional password for encryption
		APKGWriter(const std::string& p, const std::string& sig = "", const std::string& pwd = "") : path(p), dev_sig(sig), password(pwd) {}

		/// Add a file to the archive
		/// @param filepath Path to the source file
		/// @param arcname Optional name inside the archive; defaults to the filename
		void add_file(const std::string& filepath, const std::string& arcname = "") {
			std::ifstream file(filepath, std::ios::binary);
			if (!file) throw std::runtime_error("Failed to open file: " + filepath);

			// Read file into vector
			std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
			files.push_back({arcname.empty() ? std::filesystem::path(filepath).filename().string() : arcname, data});
		}

		/// Save the archive to disk
		///
		/// This function performs the following steps:
		/// 1. Builds the file table and concatenates all file data
		/// 2. Optionally encrypts the data using password-derived key
		/// 3. Writes the header, optional encryption metadata, and file block
		void save() {
			std::vector<uint8_t> file_table; // Stores file names, offsets, and sizes
			std::vector<uint8_t> file_data;	 // Concatenated file contents
			uint64_t current_offset = 0;

			// Build file table
			for (auto& file : files) {
				uint32_t name_len = (uint32_t)file.name.size();
				file_table.insert(file_table.end(), (uint8_t*)&name_len, (uint8_t*)&name_len + 4);
				file_table.insert(file_table.end(), file.name.begin(), file.name.end());

				uint64_t offset = current_offset;
				uint64_t size	= file.data.size();
				file_table.insert(file_table.end(), (uint8_t*)&offset, (uint8_t*)&offset + 8);
				file_table.insert(file_table.end(), (uint8_t*)&size, (uint8_t*)&size + 8);

				file_data.insert(file_data.end(), file.data.begin(), file.data.end());
				current_offset += size;
			}

			// Combine file table and file data
			std::vector<uint8_t> block = file_table;
			block.insert(block.end(), file_data.begin(), file_data.end());

			uint32_t flags = 0;
			std::vector<uint8_t> header_extra; // Stores salt & nonce if encrypted

			// Encrypt the block if password is provided
			if (!password.empty()) {
				// Generate random salt for key derivation
				std::vector<uint8_t> salt(SALT_SIZE);
				randombytes_buf(salt.data(), SALT_SIZE);

				// Derive key from password and salt using Argon2i
				std::vector<uint8_t> key(KEY_SIZE);
				if (crypto_pwhash(key.data(), KEY_SIZE, password.c_str(), password.size(), salt.data(), crypto_pwhash_OPSLIMIT_MODERATE,
						  crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2I13) != 0) {
					throw std::runtime_error("Key derivation failed");
				}

				// Generate random nonce for SecretBox encryption
				std::vector<uint8_t> nonce(NONCE_SIZE);
				randombytes_buf(nonce.data(), NONCE_SIZE);

				// Encrypt the combined block
				std::vector<uint8_t> cipher(block.size() + crypto_secretbox_MACBYTES);
				if (crypto_secretbox_easy(cipher.data(), block.data(), block.size(), nonce.data(), key.data()) != 0) {
					throw std::runtime_error("Encryption failed");
				}

				// Store salt and nonce in header
				header_extra.insert(header_extra.end(), (uint8_t*)&SALT_SIZE, (uint8_t*)&SALT_SIZE + 4);
				header_extra.insert(header_extra.end(), salt.begin(), salt.end());
				header_extra.insert(header_extra.end(), (uint8_t*)&NONCE_SIZE, (uint8_t*)&NONCE_SIZE + 4);
				header_extra.insert(header_extra.end(), nonce.begin(), nonce.end());

				// Replace plaintext block with encrypted ciphertext
				block = cipher;
				flags |= FLAG_ENCRYPTED;
			}

			// Write archive file
			std::ofstream out(path, std::ios::binary);
			out.write(MAGIC, 4); // File magic

			uint32_t version = 1;
			out.write((char*)&version, 4); // Version number
			out.write((char*)&flags, 4);   // Flags

			// Developer signature
			uint32_t sig_len = (uint32_t)dev_sig.size();
			out.write((char*)&sig_len, 4);
			out.write(dev_sig.data(), sig_len);

			// Number of files
			uint32_t file_count = (uint32_t)files.size();
			out.write((char*)&file_count, 4);

			// Placeholder for file_table offset
			uint64_t ftable_offset_pos = out.tellp();
			uint64_t placeholder	   = 0;
			out.write((char*)&placeholder, 8);

			// Write header_extra (salt + nonce)
			out.write((char*)header_extra.data(), header_extra.size());

			// Write file table + data block
			uint64_t file_table_offset = out.tellp();
			out.write((char*)block.data(), block.size());

			// Backpatch the file_table offset
			out.seekp(ftable_offset_pos);
			out.write((char*)&file_table_offset, 8);
		}
};

/// Structure representing a file entry in the archive
struct FileEntryRead {
		std::string name; // File name inside archive
		uint64_t offset;  // Offset relative to start of data block
		uint64_t size;	  // File size
};

/// APKGReaderV1 class
///
/// This class provides functionality to read APKG archives (V1) created
/// with APKGWriterV1. It supports optional decryption using XSalsa20+Poly1305
/// with Argon2i key derivation.
class APKGReader {
		std::string path;		  // Archive file path
		std::vector<FileEntryRead> files; // List of file entries
		std::vector<uint8_t> data_block;  // Concatenated file data
		std::string dev_sig;		  // Developer signature from header
		uint32_t version;		  // Archive version
		uint32_t flags;			  // Archive flags (encryption, etc.)

	public:
		/// Constructor
		/// @param p Archive file path
		/// @param password Optional password for decryption if archive is encrypted
		APKGReader(const std::string& p, const std::string& password = "") : path(p) {
			std::ifstream in(path, std::ios::binary);
			if (!in) throw std::runtime_error("Failed to open file: " + path);

			// Read and verify magic
			char magic[4];
			in.read(magic, 4);
			if (std::memcmp(magic, MAGIC, 4) != 0) throw std::runtime_error("Invalid APKG file");

			// Read version and flags
			in.read(reinterpret_cast<char*>(&version), 4);
			in.read(reinterpret_cast<char*>(&flags), 4);

			// Read developer signature
			uint32_t sig_len;
			in.read(reinterpret_cast<char*>(&sig_len), 4);
			dev_sig.resize(sig_len);
			in.read(dev_sig.data(), sig_len);

			// Read file count
			uint32_t file_count;
			in.read(reinterpret_cast<char*>(&file_count), 4);

			// Read file_table offset
			uint64_t file_table_offset;
			in.read(reinterpret_cast<char*>(&file_table_offset), 8);

			// Read optional header_extra (salt + nonce)
			std::vector<uint8_t> header_extra;
			if (file_table_offset > in.tellg()) {
				size_t header_extra_len = file_table_offset - in.tellg();
				header_extra.resize(header_extra_len);
				in.read(reinterpret_cast<char*>(header_extra.data()), header_extra_len);
			}

			// Read the remaining block (file table + data)
			std::vector<uint8_t> block((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

			// Decrypt if needed
			if (flags & FLAG_ENCRYPTED) {
				if (password.empty()) throw std::runtime_error("Archive is encrypted but no password provided");

				size_t ptr	  = 0;
				uint32_t salt_len = *reinterpret_cast<uint32_t*>(header_extra.data() + ptr);
				ptr += 4;
				std::vector<uint8_t> salt(header_extra.begin() + ptr, header_extra.begin() + ptr + salt_len);
				ptr += salt_len;

				uint32_t nonce_len = *reinterpret_cast<uint32_t*>(header_extra.data() + ptr);
				ptr += 4;
				std::vector<uint8_t> nonce(header_extra.begin() + ptr, header_extra.begin() + ptr + nonce_len);

				// Derive key from password + salt using Argon2i
				std::vector<uint8_t> key(KEY_SIZE);
				if (crypto_pwhash(key.data(), KEY_SIZE, password.c_str(), password.size(), salt.data(), crypto_pwhash_OPSLIMIT_MODERATE,
						  crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2I13) != 0) {
					throw std::runtime_error("Key derivation failed");
				}

				// Decrypt the block
				std::vector<uint8_t> decrypted(block.size() - crypto_secretbox_MACBYTES);
				if (crypto_secretbox_open_easy(decrypted.data(), block.data(), block.size(), nonce.data(), key.data()) != 0) {
					throw std::runtime_error("Decryption failed or archive tampered with");
				}
				block = std::move(decrypted);
			}

			// Parse file table
			size_t ptr = 0;
			for (uint32_t i = 0; i < file_count; ++i) {
				uint32_t name_len = *reinterpret_cast<uint32_t*>(block.data() + ptr);
				ptr += 4;
				std::string name(reinterpret_cast<char*>(block.data() + ptr), name_len);
				ptr += name_len;

				uint64_t offset = *reinterpret_cast<uint64_t*>(block.data() + ptr);
				ptr += 8;
				uint64_t size = *reinterpret_cast<uint64_t*>(block.data() + ptr);
				ptr += 8;

				files.push_back({name, offset, size});
			}

			// Store remaining block as data_block
			data_block.assign(block.begin() + ptr, block.end());
		}

		/// Read a specific file into memory
		/// @param filename Name of the file inside archive
		/// @return Vector of bytes containing file data
		std::vector<uint8_t> read_file(const std::string& filename) {
			for (const auto& f : files) {
				if (f.name == filename) return std::vector<uint8_t>(data_block.begin() + f.offset, data_block.begin() + f.offset + f.size);
			}
			throw std::runtime_error("File not found in archive: " + filename);
		}

		/// Extract all files to a directory
		/// @param outdir Output directory path
		void extract_all(const std::string& outdir) {
			std::filesystem::create_directories(outdir);
			for (const auto& f : files) {
				std::filesystem::path outpath = std::filesystem::path(outdir) / f.name;
				std::filesystem::create_directories(outpath.parent_path());
				std::ofstream out(outpath, std::ios::binary);
				out.write(reinterpret_cast<const char*>(data_block.data() + f.offset), f.size);
			}
		}

		/// Get the developer signature stored in the archive
		std::string get_dev_signature() const { return dev_sig; }

		/// Get the archive version
		uint32_t get_version() const { return version; }

		/// Check if archive is encrypted
		bool is_encrypted() const { return flags & FLAG_ENCRYPTED; }
};
