// =============================
// APKG — Arshavir Package Format
// MIT License (c) 2025 Arshavir Mirzakhani
// =============================
//
// Format overview:
//   [ MAGIC(4) | version(4) | flags(4) ]
//   [ dev_sig_len(4) | dev_sig(...) ]
//   [ file_count(4) ]
//   [ ftable_offset(8) | ftable_size(8) | fdata_offset(8) ]
//   [ header_extra (salt/nonce if encrypted) ]
//   [ file_table entries ]
//   [ file_data block ]
//
// Each file_table entry:
//   [ name_len(4) | name(...) | offset(8) | size(8) | original_size(8) ]
//
// Offsets are relative to start of file_data block.
// Compression/encryption applies only to file_data.
//

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
#include <zlib.h>

// File format magic identifier
const char MAGIC[4] = {'A', 'P', 'K', 'G'};

// Archive flags
const uint32_t FLAG_ENCRYPTED  = 0x1; // Archive contents are encrypted
const uint32_t FLAG_COMPRESSED = 0x2; // Files are individually compressed

// Crypto parameters
const size_t SALT_SIZE	= 16;			       // Salt size for key derivation
const size_t NONCE_SIZE = crypto_secretbox_NONCEBYTES; // Nonce size for XSalsa20 (24 bytes)
const size_t KEY_SIZE	= crypto_secretbox_KEYBYTES;   // Key size for XSalsa20 (32 bytes)

// Represents a file being packed into an archive
struct FileEntry {
		std::string name;	   // File name inside the archive
		std::vector<uint8_t> data; // File content (compressed or raw depending on settings)
		size_t original_size = 0;  // Original uncompressed file size
};

// Represents metadata for a file read from an archive
struct FileEntryRead {
		std::string name;	// File name inside the archive
		uint64_t offset;	// Offset of file in data block
		uint64_t size;		// Stored size (compressed if FLAG_COMPRESSED)
		uint64_t original_size; // Uncompressed size
};

// Compress raw data with zlib (best compression).
// @param input Raw data
// @return Compressed data
std::vector<uint8_t> compress_data(const std::vector<uint8_t>& input) {
	uLongf compressed_size = compressBound(input.size());
	std::vector<uint8_t> compressed(compressed_size);

	if (compress2(compressed.data(), &compressed_size, input.data(), input.size(), Z_BEST_COMPRESSION) != Z_OK) {
		throw std::runtime_error("Compression failed");
	}

	compressed.resize(compressed_size);
	return compressed;
}

// Decompress data using zlib.
// @param input Compressed data
// @param original_size Expected uncompressed size
// @return Decompressed data
std::vector<uint8_t> decompress_data(const std::vector<uint8_t>& input, size_t original_size) {
	std::vector<uint8_t> output(original_size);
	uLongf out_size = original_size;

	if (uncompress(output.data(), &out_size, input.data(), input.size()) != Z_OK) {
		throw std::runtime_error("Decompression failed");
	}

	output.resize(out_size);
	return output;
}

// APKGWriter class
//
// Writes APKG archives.
// This class provides functionality to create APKG archives with optional
// encryption. Encryption uses libsodium SecretBox (XSalsa20 + Poly1305) with
// Argon2i key derivation.
class APKGWriter {
		std::string path;	      // Path to save the archive
		std::string dev_sig;	      // Developer signature stored in archive header
		std::vector<FileEntry> files; // List of files to include in the archive
		std::string password;	      // Optional password for encryption
		bool compress;		      // Optional file compression

	public:
		// Constructor
		// @param p Path to save the archive
		// @param sig Developer signature (default "")
		// @param pwd Optional password for encryption
		// @param com Optional file compression
		APKGWriter(const std::string& p, const std::string& sig = "", const std::string& pwd = "", const bool& com = false)
		    : path(p), dev_sig(sig), password(pwd), compress(com) {}

		// Add a file to the archive
		// @param filepath Path to the source file
		// @param arcname Optional name inside the archive; defaults to the filename
		void add_file(const std::string& filepath, const std::string& arcname = "") {
			std::ifstream file(filepath, std::ios::binary);
			if (!file) throw std::runtime_error("Failed to open file: " + filepath);

			// Read file into vector
			std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
			files.push_back({arcname.empty() ? std::filesystem::path(filepath).filename().string() : arcname, data});
		}

		// Save the archive to disk.
		//
		// Steps:
		//  1. Build a metadata table for all files (name, offset, size, original_size).
		//  2. Concatenate all file contents into a single file_data block.
		//  3. Optionally compress individual files.
		//  4. Optionally encrypt the file_data block (metadata remains plaintext).
		//  5. Write header + metadata + data in the format.

		void save() {
			std::vector<uint8_t> file_table; // Metadata block
			std::vector<uint8_t> file_data;	 // Concatenated file contents
			uint64_t current_offset = 0;

			// Build metadata + file_data
			for (auto& file : files) {
				file.original_size = file.data.size();
				if (compress) {
					file.data = compress_data(file.data);
				}

				uint32_t name_len = (uint32_t)file.name.size();
				file_table.insert(file_table.end(), (uint8_t*)&name_len, (uint8_t*)&name_len + 4);
				file_table.insert(file_table.end(), file.name.begin(), file.name.end());

				uint64_t offset = current_offset;
				uint64_t size	= file.data.size();
				uint64_t orig	= file.original_size;

				file_table.insert(file_table.end(), (uint8_t*)&offset, (uint8_t*)&offset + 8);
				file_table.insert(file_table.end(), (uint8_t*)&size, (uint8_t*)&size + 8);
				file_table.insert(file_table.end(), (uint8_t*)&orig, (uint8_t*)&orig + 8);

				file_data.insert(file_data.end(), file.data.begin(), file.data.end());
				current_offset += size;
			}

			uint32_t flags = 0;
			std::vector<uint8_t> header_extra;

			// Optional encryption step
			std::vector<uint8_t> final_data = file_data;
			if (!password.empty()) {
				std::vector<uint8_t> salt(SALT_SIZE);
				randombytes_buf(salt.data(), SALT_SIZE);

				std::vector<uint8_t> key(KEY_SIZE);
				if (crypto_pwhash(key.data(), KEY_SIZE, password.c_str(), password.size(), salt.data(), crypto_pwhash_OPSLIMIT_MODERATE,
						  crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2I13) != 0) {
					throw std::runtime_error("Key derivation failed");
				}

				std::vector<uint8_t> nonce(NONCE_SIZE);
				randombytes_buf(nonce.data(), NONCE_SIZE);

				std::vector<uint8_t> cipher(final_data.size() + crypto_secretbox_MACBYTES);
				if (crypto_secretbox_easy(cipher.data(), final_data.data(), final_data.size(), nonce.data(), key.data()) != 0) {
					throw std::runtime_error("Encryption failed");
				}

				// Store salt + nonce into header
				header_extra.insert(header_extra.end(), (uint8_t*)&SALT_SIZE, (uint8_t*)&SALT_SIZE + 4);
				header_extra.insert(header_extra.end(), salt.begin(), salt.end());
				header_extra.insert(header_extra.end(), (uint8_t*)&NONCE_SIZE, (uint8_t*)&NONCE_SIZE + 4);
				header_extra.insert(header_extra.end(), nonce.begin(), nonce.end());

				final_data = std::move(cipher);
				flags |= FLAG_ENCRYPTED;
			}

			if (compress) {
				flags |= FLAG_COMPRESSED;
			}

			// === Write file ===
			std::ofstream out(path, std::ios::binary);
			out.write(MAGIC, 4);

			uint32_t version = 1; // version 1
			out.write((char*)&version, 4);
			out.write((char*)&flags, 4);

			// Developer signature
			uint32_t sig_len = (uint32_t)dev_sig.size();
			out.write((char*)&sig_len, 4);
			out.write(dev_sig.data(), sig_len);

			// Number of files
			uint32_t file_count = (uint32_t)files.size();
			out.write((char*)&file_count, 4);

			// Reserve spots for offsets
			uint64_t ftable_offset = 0, ftable_size = 0, fdata_offset = 0;
			std::streampos ftable_offset_pos = out.tellp();
			out.write((char*)&ftable_offset, 8);
			out.write((char*)&ftable_size, 8);
			out.write((char*)&fdata_offset, 8);

			// Write header_extra
			out.write((char*)header_extra.data(), header_extra.size());

			// Write file_table
			ftable_offset = out.tellp();
			ftable_size   = file_table.size();
			out.write((char*)file_table.data(), ftable_size);

			// Write file_data (or encrypted data block)
			fdata_offset = out.tellp();
			out.write((char*)final_data.data(), final_data.size());

			// Backpatch offsets
			out.seekp(ftable_offset_pos);
			out.write((char*)&ftable_offset, 8);
			out.write((char*)&ftable_size, 8);
			out.write((char*)&fdata_offset, 8);
		}
};

// APKGReader class
//
// Reads APKG archives.
class APKGReader {
		std::string path;		  // Archive file path
		std::vector<FileEntryRead> files; // File metadata entries
		std::vector<uint8_t> data_block;  // File contents (possibly decrypted)
		std::string dev_sig;		  // Developer signature
		uint32_t version;		  // Archive version
		uint32_t flags;			  // Flags
	public:
		APKGReader(const std::string& p, const std::string& password = "") : path(p) {
			std::ifstream in(path, std::ios::binary);
			if (!in) throw std::runtime_error("Failed to open file: " + path);

			// Magic check
			char magic[4];
			in.read(magic, 4);
			if (std::memcmp(magic, MAGIC, 4) != 0) {
				throw std::runtime_error("Invalid APKG file");
			}

			// Header
			in.read(reinterpret_cast<char*>(&version), 4);
			in.read(reinterpret_cast<char*>(&flags), 4);

			// Signature
			uint32_t sig_len;
			in.read(reinterpret_cast<char*>(&sig_len), 4);
			dev_sig.resize(sig_len);
			in.read(dev_sig.data(), sig_len);

			// File count
			uint32_t file_count;
			in.read(reinterpret_cast<char*>(&file_count), 4);

			// === NEW FORMAT (separated metadata & data) ===
			uint64_t ftable_offset, ftable_size, fdata_offset;
			in.read(reinterpret_cast<char*>(&ftable_offset), 8);
			in.read(reinterpret_cast<char*>(&ftable_size), 8);
			in.read(reinterpret_cast<char*>(&fdata_offset), 8);

			// Read header_extra (salt + nonce)
			std::streampos pos_after_offsets = in.tellg();
			size_t header_extra_len		 = ftable_offset - pos_after_offsets;
			std::vector<uint8_t> header_extra(header_extra_len);
			in.read(reinterpret_cast<char*>(header_extra.data()), header_extra_len);

			// Read file_table
			in.seekg(ftable_offset);
			std::vector<uint8_t> file_table(ftable_size);
			in.read(reinterpret_cast<char*>(file_table.data()), ftable_size);

			// Read file_data (possibly encrypted)
			in.seekg(fdata_offset);
			std::vector<uint8_t> block((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

			// Decrypt file data if needed
			if (flags & FLAG_ENCRYPTED) {
				if (password.empty()) throw std::runtime_error("Archive is encrypted but no password provided");
				block = decrypt_block(block, header_extra, password);
			}

			// Parse file table
			size_t ptr = 0;
			for (uint32_t i = 0; i < file_count; ++i) {
				uint32_t name_len = *reinterpret_cast<uint32_t*>(file_table.data() + ptr);
				ptr += 4;

				std::string name(reinterpret_cast<char*>(file_table.data() + ptr), name_len);
				ptr += name_len;

				uint64_t offset = *reinterpret_cast<uint64_t*>(file_table.data() + ptr);
				ptr += 8;
				uint64_t size = *reinterpret_cast<uint64_t*>(file_table.data() + ptr);
				ptr += 8;
				uint64_t orig = *reinterpret_cast<uint64_t*>(file_table.data() + ptr);
				ptr += 8;

				files.push_back({name, offset, size, orig});
			}

			data_block = std::move(block);
		}

		// Decrypt helper
		static std::vector<uint8_t> decrypt_block(const std::vector<uint8_t>& block, const std::vector<uint8_t>& header_extra,
							  const std::string& password) {
			size_t ptr	  = 0;
			uint32_t salt_len = *reinterpret_cast<const uint32_t*>(header_extra.data() + ptr);
			ptr += 4;
			std::vector<uint8_t> salt(header_extra.begin() + ptr, header_extra.begin() + ptr + salt_len);
			ptr += salt_len;

			uint32_t nonce_len = *reinterpret_cast<const uint32_t*>(header_extra.data() + ptr);
			ptr += 4;
			std::vector<uint8_t> nonce(header_extra.begin() + ptr, header_extra.begin() + ptr + nonce_len);

			std::vector<uint8_t> key(KEY_SIZE);
			if (crypto_pwhash(key.data(), KEY_SIZE, password.c_str(), password.size(), salt.data(), crypto_pwhash_OPSLIMIT_MODERATE,
					  crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_ARGON2I13) != 0) {
				throw std::runtime_error("Key derivation failed");
			}

			std::vector<uint8_t> decrypted(block.size() - crypto_secretbox_MACBYTES);
			if (crypto_secretbox_open_easy(decrypted.data(), block.data(), block.size(), nonce.data(), key.data()) != 0) {
				throw std::runtime_error("Decryption failed or archive tampered with");
			}
			return decrypted;
		}

		// Read a file
		std::vector<uint8_t> read_file(const std::string& filename) {
			for (const auto& f : files) {
				if (f.name == filename) {
					std::vector<uint8_t> raw(data_block.begin() + f.offset, data_block.begin() + f.offset + f.size);
					if (flags & FLAG_COMPRESSED) {
						return decompress_data(raw, f.original_size);
					}
					return raw;
				}
			}
			throw std::runtime_error("File not found in archive: " + filename);
		}

		// Extract all files
		void extract_all(const std::string& outdir) {
			std::filesystem::create_directories(outdir);
			for (const auto& f : files) {
				std::filesystem::path outpath = std::filesystem::path(outdir) / f.name;
				std::filesystem::create_directories(outpath.parent_path());

				std::vector<uint8_t> raw(data_block.begin() + f.offset, data_block.begin() + f.offset + f.size);
				std::vector<uint8_t> output = (flags & FLAG_COMPRESSED) ? decompress_data(raw, f.original_size) : raw;

				std::ofstream out(outpath, std::ios::binary);
				out.write(reinterpret_cast<const char*>(output.data()), output.size());
			}
		}

		std::string get_dev_signature() const { return dev_sig; }
		uint32_t get_version() const { return version; }
		bool is_encrypted() const { return flags & FLAG_ENCRYPTED; }
		bool is_compressed() const { return flags & FLAG_COMPRESSED; }
};
