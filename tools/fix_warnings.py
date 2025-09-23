#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WARN = ROOT / "warnings.txt"
BUILDER = ROOT / "src" / "builder.rs"


def ensure_imports(builder_text: str) -> str:
    # Insert required imports for macro expansions if missing
    needed = [
        "Kyber", "Encryption", "Decryption", "Kyber1024", "Kyber768", "Kyber512",
        "Data", "AES", "AES_CBC", "AesGcmSiv", "AesCtr", "AesXts", "XChaCha20", "XChaCha20Poly1305",
        "Signature", "Falcon1024", "Falcon512", "Dilithium2", "Dilithium3", "Dilithium5", "Message", "Detached",
    ]

    # Find the end of the initial use-block to append within it
    lines = builder_text.splitlines()
    insert_idx = None
    for i, line in enumerate(lines[:200]):
        if line.strip().startswith("use crate::core::{"):
            insert_idx = i
            break

    # Build import line
    import_line = (
        "use crate::core::kyber::{" + ", ".join(needed[:13]) + "};\n"
        "use crate::core::kdf::{" + ", ".join(needed[13:]) + "};"
    )

    if import_line in builder_text:
        return builder_text

    # Also clean up any aliases that may hide original names
    builder_text = re.sub(
        r"use\s+crate::core::\{\s*kdf::\{[^}]*\}\s*,\s*kyber::key_controler::\{",
        "use crate::core::{\n    kdf::{Falcon1024, Falcon512, Dilithium2, Dilithium3, Dilithium5, Signature, Message, Detached},\n    kyber::key_controler::{",
        builder_text,
        flags=re.MULTILINE,
    )

    # Insert the kyber/kdf type imports just after the first core import group
    if insert_idx is not None:
        lines.insert(insert_idx + 1, import_line)
        return "\n".join(lines)

    # Fallback: prepend near top after std:: imports
    for i, line in enumerate(lines[:50]):
        if line.strip().startswith("use "):
            lines.insert(i + 1, import_line)
            return "\n".join(lines)

    return import_line + "\n" + builder_text


def replace_size_in_decryption(builder_text: str) -> str:
    # Replace single-line size-based macro invocations with explicit matches
    fixes = [
        (r"SymmetricAlg::Aes\s*=>\s*decryption!\(key,\s*size,\s*data,\s*pass,\s*cipher,\s*AES\s*\),",
         "SymmetricAlg::Aes => match size { 1024 => decryption!(key, 1024, data, pass, cipher, AES), 768 => decryption!(key, 768, data, pass, cipher, AES), 512 => decryption!(key, 512, data, pass, cipher, AES), _ => Err(CryptError::new(\"invalid Kyber size\")), },"),
        (r"SymmetricAlg::AesXts\s*=>\s*decryption!\(key,\s*size,\s*data,\s*pass,\s*cipher,\s*AES_XTS\s*\),",
         "SymmetricAlg::AesXts => match size { 1024 => decryption!(key, 1024, data, pass, cipher, AES_XTS), 768 => decryption!(key, 768, data, pass, cipher, AES_XTS), 512 => decryption!(key, 512, data, pass, cipher, AES_XTS), _ => Err(CryptError::new(\"invalid Kyber size\")), },"),
        (r"SymmetricAlg::AesCbc\s*=>\s*decryption!\(key,\s*size,\s*data,\s*pass,\s*cipher,\s*AES_CBC\s*\),",
         "SymmetricAlg::AesCbc => match size { 1024 => decryption!(key, 1024, data, pass, cipher, AES_CBC), 768 => decryption!(key, 768, data, pass, cipher, AES_CBC), 512 => decryption!(key, 512, data, pass, cipher, AES_CBC), _ => Err(CryptError::new(\"invalid Kyber size\")), },"),
    ]
    new_text = builder_text
    for pat, rep in fixes:
        new_text = re.sub(pat, rep, new_text)
    return new_text


def main():
    if not WARN.exists():
        print("warnings.txt not found; nothing to do.")
        return

    report = WARN.read_text(errors="ignore")
    if not report.strip():
        print("warnings.txt is empty; nothing to fix.")
        return

    if not BUILDER.exists():
        print("src/builder.rs not found; nothing to patch.")
        return

    text = BUILDER.read_text()

    if "no rules expected `size`" in report or re.search(r"decryption!\(key,\s*size,", report):
        patched = replace_size_in_decryption(text)
        text = patched

    # Import-related errors for macro expansions
    if any(s in report for s in ["use of undeclared type `Kyber`", "cannot find type `Encryption`", "cannot find type `Data`"]):
        text = ensure_imports(text)

    if text != BUILDER.read_text():
        BUILDER.write_text(text)
        print("Patched src/builder.rs based on warnings.txt")
    else:
        print("No changes applied to src/builder.rs")


if __name__ == "__main__":
    main()

