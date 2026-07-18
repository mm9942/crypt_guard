# Algorithms

## Core

- ML-KEM-512 / 768 / 1024
- HKDF-SHA256 / HKDF-SHA512
- XChaCha20Poly1305
- AesGcmSiv

## Legacy / Expert

- old `Kyber*` naming
- raw `AES`
- `AesCtr`
- `AesXts`
- raw `XChaCha20`
- tuple-returning macros and manual nonce handling

## Policy

The safe public API only accepts authenticated AEAD algorithms. Non-AEAD and
old compatibility modes stay outside that surface.
