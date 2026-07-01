# Legacy Migration

The modern default uses ML-KEM + ML-DSA. Keep `legacy-pqclean` only for older
integrations that still depend on the macro and tuple APIs.

## Preferred move

Old:

- `kyber_keypair!`
- `encryption!`
- `decryption!`
- manual `cipher` and `nonce` handling

New:

- ML-KEM key generation through backend traits
- `Encryptor::<Kem, Aead>::new()`
- `Decryptor::<Kem, Aead>::new()`
- one CGv2 envelope

For new code, prefer the safe API and the default feature set. Use the legacy
lane only when compatibility is the requirement.

Before publishing the release, confirm whether legacy compatibility is
limited to source compatibility or whether byte-for-byte v1 artifact migration
needs a dedicated regression suite.

## Example

Old:

```rust
let (enc, cipher, nonce) = encryption!(pk, 768, data, passphrase, XChaCha20Poly1305)?;
let dec = decryption!(sk, 768, enc, passphrase, cipher, Some(nonce), XChaCha20Poly1305)?;
```

New:

```rust
let envelope = Encryptor::<MlKem768, XChaCha20Poly1305>::new()
    .recipient(pk)
    .plaintext(data)
    .seal()?;

let plaintext = Decryptor::<MlKem768, XChaCha20Poly1305>::new()
    .secret_key(sk)
    .open(&envelope)?;
```
