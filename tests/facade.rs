//! The `crypt_guard` facade keeps the pre-workspace public paths, including
//! proc-macro expansions that refer to `crypt_guard::…`.

// `#[activate_log]` expands to a `fn initialize_logger()` calling
// `crypt_guard::log::initialize_logger`; it must resolve through the facade.
// It is only referenced, never called, so no global subscriber is installed.
#[crypt_guard::activate_log("facade-test.log")]
fn annotated() {}

#[test]
fn proc_macro_expansion_resolves_through_facade() {
    annotated();
    let _: fn() = initialize_logger;
}

#[test]
fn core_paths_are_reexported() {
    use crypt_guard::pq_hpke::{generate_recipient_key_pair, HpkeEnvelope, DEFAULT_SUITE};

    let keys = generate_recipient_key_pair(DEFAULT_SUITE.kem()).unwrap();
    let envelope = HpkeEnvelope::seal(
        DEFAULT_SUITE,
        keys.public_key(),
        b"info",
        b"aad",
        b"payload",
    )
    .unwrap();
    let bytes = envelope.to_bytes();
    let decoded = HpkeEnvelope::from_bytes(&bytes).unwrap();
    assert_eq!(
        decoded.open(keys.private_key(), b"info", b"aad").unwrap(),
        b"payload"
    );
    let _: fn(_) = crypt_guard::activate_log::<&str>;
}

#[cfg(feature = "service")]
#[test]
fn service_layer_is_reachable_through_facade() {
    let secret = crypt_guard::service::SecretBytes::copy_from_slice(b"x");
    assert_eq!(secret.len(), 1);
}

#[cfg(feature = "hyper")]
#[test]
fn hyper_layer_is_reachable_through_facade() {
    let config = crypt_guard::hyper::HttpConfig::default();
    assert!(config.hide_forbidden_keys);
}
