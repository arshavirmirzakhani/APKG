# ============================================= #
# APKG (Arshavir's Package Format) Python API   #
# ============================================= #
# MIT License                                   #
# Copyright (c) 2025 Arshavir Mirzakhani        #
# ============================================= #

import os
import struct
import secrets
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

MAGIC = b"APKG"  # Magic Value
FLAG_ENCRYPTED = 0x1

# KDF parameters
KDF_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_SIZE = 12
AES_KEY_SIZE = 32  # AES-256


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive an AES key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password)


class APKGWriterV1:
    def __init__(
        self, path: str, developer_signature: str = "SIGNATURE", password: bytes = b""
    ):
        """
        Create an APKG archive writer.

        Args:
            path: Path to save the archive.
            developer_signature: Optional developer signature string.
            password: Optional password for AES-GCM encryption.
        """
        self.path = path
        self.dev_sig = developer_signature.encode("utf-8")
        self.files = []
        self.password = password

    def add_file(self, filepath: str, arcname: Optional[str] = None):
        """Add a file to the archive."""
        arcname = arcname or os.path.basename(filepath)
        with open(filepath, "rb") as f:
            data = f.read()
        self.files.append((arcname, data))

    def save(self):
        """Write the archive to disk."""
        # Build file table and data block
        file_table = b""
        file_data = b""
        current_offset = 0
        for name, data in self.files:
            name_bytes = name.encode("utf-8")
            file_table += struct.pack("<I", len(name_bytes)) + name_bytes
            file_table += struct.pack("<Q", current_offset) + struct.pack(
                "<Q", len(data)
            )
            file_data += data
            current_offset += len(data)

        block = file_table + file_data
        flags = 0
        header_extra = b""

        if self.password:
            # Encrypt block
            salt = secrets.token_bytes(SALT_SIZE)
            key = derive_key(self.password, salt)
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(NONCE_SIZE)
            cipher = aesgcm.encrypt(nonce, block, associated_data=None)
            header_extra = (
                struct.pack("<I", len(salt))
                + salt
                + struct.pack("<I", len(nonce))
                + nonce
            )
            block = cipher
            flags |= FLAG_ENCRYPTED

        with open(self.path, "wb") as f:
            f.write(MAGIC)
            f.write(struct.pack("<I", 1))  # Version
            f.write(struct.pack("<I", flags))
            f.write(struct.pack("<I", len(self.dev_sig)))
            f.write(self.dev_sig)
            f.write(struct.pack("<I", len(self.files)))

            f_table_offset_pos = f.tell()
            f.write(struct.pack("<Q", 0))  # placeholder for file_table offset
            f.write(header_extra)

            file_table_offset = f.tell()
            f.write(block)

            # Backpatch file_table offset
            f.seek(f_table_offset_pos)
            f.write(struct.pack("<Q", file_table_offset))


class APKGReader:
    def __init__(self, path: str, password: bytes = b""):
        """
        Read an APKG archive.

        Args:
            path: Path to the archive.
            password: Password for decryption (if encrypted).
        """
        self.path = path
        self.files = {}
        self.dev_sig = ""
        self.version = 0
        self.data_block = b""

        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != MAGIC:
                raise ValueError("Invalid APKG file")

            self.version = struct.unpack("<I", f.read(4))[0]
            flags = struct.unpack("<I", f.read(4))[0]

            sig_len = struct.unpack("<I", f.read(4))[0]
            self.dev_sig = f.read(sig_len).decode("utf-8")

            file_count = struct.unpack("<I", f.read(4))[0]
            file_table_offset = struct.unpack("<Q", f.read(8))[0]

            header_extra_len = file_table_offset - f.tell()
            header_extra = f.read(header_extra_len) if header_extra_len > 0 else b""

            block = f.read()

        if flags & FLAG_ENCRYPTED:
            if not password:
                raise ValueError("Archive is encrypted but no password provided")

            ptr = 0
            salt_len = struct.unpack_from("<I", header_extra, ptr)[0]
            ptr += 4
            salt = header_extra[ptr : ptr + salt_len]
            ptr += salt_len

            nonce_len = struct.unpack_from("<I", header_extra, ptr)[0]
            ptr += 4
            nonce = header_extra[ptr : ptr + nonce_len]

            key = derive_key(password, salt)
            aesgcm = AESGCM(key)
            try:
                block = aesgcm.decrypt(nonce, block, associated_data=None)
            except Exception as e:
                raise ValueError("Decryption failed or archive tampered with") from e

        ptr = 0
        for _ in range(file_count):
            name_len = struct.unpack_from("<I", block, ptr)[0]
            ptr += 4
            name = block[ptr : ptr + name_len].decode("utf-8")
            ptr += name_len
            offset = struct.unpack_from("<Q", block, ptr)[0]
            ptr += 8
            size = struct.unpack_from("<Q", block, ptr)[0]
            ptr += 8
            self.files[name] = (offset, size)

        self.data_block = block[ptr:]

    def extract(self, outdir: str):
        """Extract all files to the specified directory."""
        os.makedirs(outdir, exist_ok=True)
        for name, (offset, size) in self.files.items():
            data = self.data_block[offset : offset + size]
            outpath = os.path.join(outdir, name)
            os.makedirs(os.path.dirname(outpath), exist_ok=True)
            with open(outpath, "wb") as f:
                f.write(data)

    def read_file(self, filename: str) -> bytes:
        """
        Read a specific file from the archive into memory.

        Args:
            filename: Name of the file in the archive.

        Returns:
            File data as bytes.

        Raises:
            KeyError: If the file does not exist in the archive.
        """
        if filename not in self.files:
            raise KeyError(f"File '{filename}' not found in archive")
        offset, size = self.files[filename]
        return self.data_block[offset : offset + size]


# Example usage
if __name__ == "__main__":
    PASSWORD = b"123abc"

    writer = APKGWriterV1("example.apkg", "SIGNATURE", password=PASSWORD)

    writer.add_file("test.txt")
    writer.save()

    reader = APKGReader("example.apkg", password=PASSWORD)

    reader.extract("output/")

    file_data = reader.read_file("test.txt")
    print(file_data.decode("utf-8"))
