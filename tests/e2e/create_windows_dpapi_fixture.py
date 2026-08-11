#!/usr/bin/env python3
"""Create a deterministic-shape Chromium v10 fixture for the current Windows user."""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import sys


class DataBlob(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("data", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def protect_for_current_user(plaintext: bytes) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("DPAPI fixtures can only be created on Windows")
    buffer = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    input_blob = DataBlob(len(plaintext), buffer)
    output_blob = DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0x1,  # CRYPTPROTECT_UI_FORBIDDEN
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        kernel32.LocalFree(ctypes.cast(output_blob.data, ctypes.c_void_p))


def encrypt_v10(node: str, key: bytes, value: str) -> bytes:
    program = r"""
const crypto = require("node:crypto");
const inputs = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const key = Buffer.from(inputs.key, "hex");
const value = Buffer.from(inputs.value, "utf8");
const nonce = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
const encrypted = Buffer.concat([cipher.update(value), cipher.final()]);
process.stdout.write(
  Buffer.concat([Buffer.from("v10"), nonce, encrypted, cipher.getAuthTag()]).toString("base64"),
);
"""
    result = subprocess.run(
        [node, "-e", program],
        input=json.dumps({"key": key.hex(), "value": value}),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return base64.b64decode(result.stdout, validate=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--domain", default=".example.test")
    parser.add_argument("--cookie-name", default="rookie_ci")
    parser.add_argument("--cookie-value", default="bar")
    args = parser.parse_args()

    if sys.platform != "win32":
        parser.error("this fixture requires Windows DPAPI")
    node = shutil.which("node")
    if node is None:
        parser.error("node is required to generate AES-256-GCM ciphertext")
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        parser.error(f"output directory is not empty: {output}")
    network = output / "Default" / "Network"
    network.mkdir(parents=True, exist_ok=True)

    aes_key = secrets.token_bytes(32)
    encrypted_key = b"DPAPI" + protect_for_current_user(aes_key)
    local_state = output / "Local State"
    local_state.write_text(
        json.dumps(
            {
                "os_crypt": {
                    "encrypted_key": base64.b64encode(encrypted_key).decode("ascii")
                },
                "profile": {"last_used": "Default"},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    encrypted_value = encrypt_v10(node, aes_key, args.cookie_value)
    cookies_db = network / "Cookies"
    with sqlite3.connect(cookies_db) as connection:
        connection.executescript(
            """
            CREATE TABLE meta (
              key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY,
              value LONGVARCHAR
            );
            INSERT INTO meta (key, value) VALUES ('version', '23');
            CREATE TABLE cookies (
              host_key TEXT NOT NULL,
              path TEXT NOT NULL,
              is_secure INTEGER NOT NULL,
              expires_utc INTEGER NOT NULL,
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              encrypted_value BLOB,
              is_httponly INTEGER NOT NULL,
              samesite INTEGER NOT NULL
            );
            """
        )
        connection.execute(
            """
            INSERT INTO cookies (
              host_key, path, is_secure, expires_utc, name, value,
              encrypted_value, is_httponly, samesite
            ) VALUES (?, '/', 0, ?, ?, '', ?, 1, 1)
            """,
            (
                args.domain,
                11_644_473_600_000_000 + 1_900_000_000 * 1_000_000,
                args.cookie_name,
                encrypted_value,
            ),
        )

    print(
        json.dumps(
            {
                "user_data_dir": str(output),
                "local_state": str(local_state),
                "cookies_db": str(cookies_db),
                "domain": args.domain,
                "cookie_name": args.cookie_name,
                "encrypted_prefix": "v10",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
