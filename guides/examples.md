# Examples

## Safe default sealing

See `examples/encrypt_xchacha.rs`.

## Safe AES-GCM-SIV sealing

See `examples/encrypt_aes.rs`.

## Legacy macros

See `examples/macro_example.rs`. Treat that example as compatibility-oriented,
not as the primary API.

## HPKE-style sealing

Use `crypt_guard::api::hpke::{seal, open}` when the application needs explicit
`info` and `aad` context binding.
