//! Consumer-facing coverage for the explicit experimental draft-05 API.
//!
//! This API is in the default build; the consumer compile check deliberately
//! also uses `default-features = false` to prove the HPKE surface is not hidden.

use std::{fs, path::PathBuf, process::Command};

use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05::{
    generate_recipient_key_pair, setup_base_receiver, setup_base_sender, Encapsulation, Error,
    Profile, RecipientPrivateKey, RecipientPublicKey,
};

const PROFILES: [Profile; 2] = [
    Profile::MlKem768HkdfSha256Aes128Gcm,
    Profile::MlKem1024HkdfSha384Aes256Gcm,
];

#[test]
fn each_pinned_profile_round_trips_through_the_public_api() {
    for profile in PROFILES {
        let pair = generate_recipient_key_pair(profile);

        // These parse operations model two independently persisted key stores;
        // neither setup API receives a raw shared secret or a nonce.
        let public_key = RecipientPublicKey::from_bytes(profile, pair.public_key().as_bytes())
            .expect("generated public key must parse");
        let private_key =
            RecipientPrivateKey::from_seed_bytes(profile, pair.private_key().as_seed_bytes())
                .expect("generated private-key seed must parse");

        let (encapsulation, mut sender) =
            setup_base_sender(profile, &public_key, b"consumer setup info")
                .expect("sender setup must succeed");
        let mut recipient = setup_base_receiver(
            profile,
            &private_key,
            &encapsulation,
            b"consumer setup info",
        )
        .expect("recipient setup must succeed");

        assert_eq!(encapsulation.profile(), profile);
        assert_eq!(
            sender.export(b"export context", 32).unwrap(),
            recipient.export(b"export context", 32).unwrap(),
        );

        let ciphertext = sender
            .seal(b"application aad", b"draft HPKE payload")
            .unwrap();
        assert_eq!(
            recipient.open(b"application aad", &ciphertext).unwrap(),
            b"draft HPKE payload",
        );
    }
}

#[test]
fn authentication_failures_are_generic_for_aad_ciphertext_and_same_size_enc() {
    for profile in PROFILES {
        let pair = generate_recipient_key_pair(profile);
        let public_key = pair.public_key().clone();

        // Wrong AAD leaves the recipient sequence untouched, but use a fresh
        // recipient context in each assertion to model independent receives.
        let (encapsulation, mut sender) = setup_base_sender(profile, &public_key, b"info").unwrap();
        let ciphertext = sender.seal(b"good aad", b"plaintext").unwrap();

        let mut wrong_aad =
            setup_base_receiver(profile, pair.private_key(), &encapsulation, b"info").unwrap();
        assert_eq!(
            wrong_aad.open(b"wrong aad", &ciphertext),
            Err(Error::AuthenticationFailed),
        );

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[0] ^= 0x80;
        let mut wrong_ciphertext =
            setup_base_receiver(profile, pair.private_key(), &encapsulation, b"info").unwrap();
        assert_eq!(
            wrong_ciphertext.open(b"good aad", &modified_ciphertext),
            Err(Error::AuthenticationFailed),
        );

        let mut modified_encapsulation = encapsulation.as_bytes().to_vec();
        modified_encapsulation[0] ^= 0x80;
        let modified_encapsulation =
            Encapsulation::from_bytes(profile, &modified_encapsulation).unwrap();
        let mut wrong_encapsulation = setup_base_receiver(
            profile,
            pair.private_key(),
            &modified_encapsulation,
            b"info",
        )
        .unwrap();
        assert_eq!(
            wrong_encapsulation.open(b"good aad", &ciphertext),
            Err(Error::AuthenticationFailed),
        );
    }
}

#[test]
fn consumer_cannot_clone_contexts_or_supply_a_nonce() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = manifest_dir
        .join("target")
        .join("hpke_pq_draft05_public_compile");
    let source_dir = crate_dir.join("src");
    fs::create_dir_all(&source_dir).expect("compile-check source directory must be created");

    fs::write(
        source_dir.join("main.rs"),
        r#"
use crypt_guard::hpke_pq::draft_ietf_hpke_pq_05::{
    generate_recipient_key_pair, setup_base_sender, Profile,
};

fn require_clone<T: Clone>(_: &T) {}

fn main() {
    let pair = generate_recipient_key_pair(Profile::MlKem768HkdfSha256Aes128Gcm);
    let (_, sender) = setup_base_sender(
        Profile::MlKem768HkdfSha256Aes128Gcm,
        pair.public_key(),
        b"info",
    ).unwrap();
    require_clone(&sender);
    let _ = sender.seal_with_nonce(&[0_u8; 12], b"aad", b"plaintext");
}
"#,
    )
    .expect("compile-check source must be written");
    fs::write(
        crate_dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "crypt_guard_hpke_pq_draft05_public_compile"
version = "0.0.0"
edition = "2021"

[dependencies]
crypt_guard = {{ path = "{}", default-features = false }}

[workspace]
"#,
            manifest_dir.display()
        ),
    )
    .expect("compile-check manifest must be written");

    let output = Command::new("cargo")
        .args(["check", "--offline", "--quiet"])
        .env("CARGO_TARGET_DIR", crate_dir.join("target"))
        .current_dir(&crate_dir)
        .output()
        .expect("consumer compile check must run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "consumer misuse unexpectedly compiled successfully"
    );
    assert!(
        stderr.contains("Clone"),
        "contexts must not satisfy a Clone bound:\n{stderr}"
    );
    assert!(
        stderr.contains("seal_with_nonce"),
        "the public API must not expose a manual nonce method:\n{stderr}"
    );
}
