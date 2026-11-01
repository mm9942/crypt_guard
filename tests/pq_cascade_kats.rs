//! Known-answer tests for `pq_cascade` and the cascade variant of `pq_multi`.
//!
//! # Responsibility scope
//! Integration tests (through the `crypt_guard` facade paths
//! `crypt_guard::{pq_cascade, pq_multi, pq_stream, prf, pq_hpke}`) that check the
//! additive 3.2.0 cascade API against an **independent** implementation:
//! - Part A, known answers: every vector in
//!   `crates/core/tests/vectors/pq-cascade-kats.json` was produced by the Python
//!   reference model of Anhang A of the comnet `cipher-suite-contract.md`
//!   (`python3 -I`, `hashlib.shake_256` plus `cryptography`'s `AESGCMSIV` and
//!   `ChaCha20Poly1305`, XChaCha20-Poly1305 checked against
//!   draft-irtf-cfrg-xchacha-03 A.3.1). They cover all four schemes in counter,
//!   derived-nonce (`seal_once`), STREAM and random mode, three input sets
//!   (contract inputs, empty plaintext/AAD, 300-byte plaintext), every sub-key and
//!   derived nonce, and 20 negative vectors (authentic AEAD output of a wrong
//!   construction that must be rejected).
//! - Part A also cross-checks the vector file against `prf` and the STREAM nonce
//!   layout of `pq_stream` (ChaCha20-Poly1305 scheme), and runs every bit flip,
//!   truncation, extension, wrong AAD/domain/root/scheme/nonce against the vectors.
//! - Part B (`multi`, feature `ml-kem-backend`): `seal_multi_cascade`,
//!   `open_multi_cascade`, `dummy_cascade_wrap` for all four schemes: wrap length
//!   1 751 for every scheme and dummy, identical wrap headers, wrap plaintext
//!   layout, an independent assembly from the documented construction, scheme and
//!   wrap-version tampering, the `accept` callback, recipient-set / header / info /
//!   body splices, suite pinning, opaque errors, and domain separation from the
//!   plain `seal_multi` family.
//!
//! The vectors are tied to `SHA256SUMS` in the same directory
//! (`verify_provenance.sh`). No test uses `unwrap`, `expect`, `panic!` or
//! indexing; failures surface through `TestResult`.
//!
//! # Examples
//! ```text
//! cargo test -p crypt_guard --test pq_cascade_kats
//! ```

use std::collections::BTreeMap;

use crypt_guard::error::CryptError;
use crypt_guard::pq_cascade::{
    open_random, seal_random, Cascade, CascadeNonce, Scheme, CASCADE_OVERHEAD, KEY_LEN, NONCE_LEN,
};
use crypt_guard::pq_stream::StreamEncryptor;
use crypt_guard::prf::{prf, prf32};
use serde::Deserialize;

type BoxErr = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxErr>;

/// The generated vectors (Python model of the contract, see the module docs).
const VECTORS: &str = include_str!("../crates/core/tests/vectors/pq-cascade-kats.json");

const L_IN: &[u8] = b"crypt_guard/v3/cascade/inner";
const L_OUT: &[u8] = b"crypt_guard/v3/cascade/outer";
const L_ONE: &[u8] = b"crypt_guard/v3/cascade/single";
const L_NONCE: &[u8] = b"crypt_guard/v3/cascade/nonce";
const L_RANDOM: &[u8] = b"crypt_guard/v3/cascade/random";
const A_IN: &[u8] = b"crypt_guard/v3/cascade/aad/inner";
const A_OUT: &[u8] = b"crypt_guard/v3/cascade/aad/outer";
const A_ONE: &[u8] = b"crypt_guard/v3/cascade/aad/single";

/// The four schemes in ascending order (ids 1 to 4).
const SCHEMES: [Scheme; 4] = [
    Scheme::ChaCha20Poly1305,
    Scheme::Aes256GcmSiv,
    Scheme::XChaCha20Poly1305,
    Scheme::Cascade,
];

// ── Vector file model ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Labels {
    #[serde(rename = "L_IN")]
    l_in: String,
    #[serde(rename = "L_OUT")]
    l_out: String,
    #[serde(rename = "L_ONE")]
    l_one: String,
    #[serde(rename = "L_NONCE")]
    l_nonce: String,
    #[serde(rename = "L_RANDOM")]
    l_random: String,
    #[serde(rename = "A_IN")]
    a_in: String,
    #[serde(rename = "A_OUT")]
    a_out: String,
    #[serde(rename = "A_ONE")]
    a_one: String,
}

#[derive(Deserialize)]
struct SubKeys {
    ctx: String,
    k_in: String,
    k_out: String,
    k_one: String,
    nonce_once: String,
}

#[derive(Deserialize)]
struct Vector {
    id: String,
    scheme: u8,
    mode: String,
    domain_byte: Option<u8>,
    n: Option<String>,
    prefix: Option<String>,
    index: Option<u32>,
    last: Option<bool>,
    n24: String,
    ct: Option<String>,
    sealed: Option<String>,
}

#[derive(Deserialize)]
struct Negative {
    id: String,
    scheme: u8,
    domain_byte: u8,
    n: String,
    why: String,
    ct: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    root: String,
    domain: String,
    aad: String,
    pt: String,
    subkeys: BTreeMap<String, SubKeys>,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Doc {
    labels: Labels,
    negatives: Vec<Negative>,
    cases: Vec<Case>,
}

/// Decoded inputs of one case.
struct Inputs {
    root: [u8; KEY_LEN],
    domain: Vec<u8>,
    aad: Vec<u8>,
    pt: Vec<u8>,
}

impl Inputs {
    fn cascade(&self, scheme: Scheme) -> Result<Cascade, BoxErr> {
        Ok(Cascade::new(scheme, &self.root, &self.domain)?)
    }
}

impl Case {
    fn inputs(&self) -> Result<Inputs, BoxErr> {
        Ok(Inputs {
            root: array(&unhex(&self.root)?)?,
            domain: unhex(&self.domain)?,
            aad: unhex(&self.aad)?,
            pt: unhex(&self.pt)?,
        })
    }
}

impl Vector {
    fn scheme(&self) -> Result<Scheme, BoxErr> {
        Scheme::from_id(self.scheme).ok_or_else(|| BoxErr::from("unknown scheme id in vector"))
    }

    /// The reusable-call nonce of a `counter` or `stream` vector.
    fn nonce(&self) -> Result<CascadeNonce, BoxErr> {
        match self.mode.as_str() {
            "counter" => Ok(CascadeNonce::Counter {
                domain: self.domain_byte.ok_or("counter vector without domain_byte")?,
                n: self.n.as_deref().ok_or("counter vector without n")?.parse()?,
            }),
            "stream" => Ok(CascadeNonce::Stream {
                prefix: array(&unhex(
                    self.prefix.as_deref().ok_or("stream vector without prefix")?,
                )?)?,
                index: self.index.ok_or("stream vector without index")?,
                last: self.last.ok_or("stream vector without last")?,
            }),
            other => Err(BoxErr::from(format!("mode {other} has no CascadeNonce"))),
        }
    }

    fn ciphertext(&self) -> Result<Vec<u8>, BoxErr> {
        unhex(self.ct.as_deref().ok_or("vector without ct")?)
    }

    fn sealed(&self) -> Result<Vec<u8>, BoxErr> {
        unhex(self.sealed.as_deref().ok_or("vector without sealed")?)
    }
}

fn load() -> Result<Doc, BoxErr> {
    Ok(serde_json::from_str(VECTORS)?)
}

fn find_vector<'a>(case: &'a Case, id: &str) -> Result<&'a Vector, BoxErr> {
    case.vectors
        .iter()
        .find(|v| v.id == id)
        .ok_or_else(|| BoxErr::from(format!("vector {id} missing")))
}

fn unhex(text: &str) -> Result<Vec<u8>, BoxErr> {
    Ok(hex::decode(text)?)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], BoxErr> {
    <[u8; N]>::try_from(bytes).map_err(|_| BoxErr::from("unexpected byte length"))
}

fn lp32(bytes: &[u8]) -> Result<Vec<u8>, BoxErr> {
    let mut out = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    Ok(out)
}

/// `scheme_id u8 ‖ lp32(domain)`, the key-derivation and AAD context of the contract.
fn ctx_of(scheme_id: u8, domain: &[u8]) -> Result<Vec<u8>, BoxErr> {
    let mut out = vec![scheme_id];
    out.extend_from_slice(&lp32(domain)?);
    Ok(out)
}

fn flipped(bytes: &[u8], index: usize, mask: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(byte) = out.get_mut(index) {
        *byte ^= mask;
    }
    out
}

fn is_auth_failed<T>(result: &Result<T, CryptError>) -> bool {
    matches!(result, Err(CryptError::AuthenticationFailed))
}

// ── Part A: known answers ────────────────────────────────────────────────────

#[test]
fn vector_file_is_complete_and_lengths_are_plaintext_plus_32() -> TestResult {
    let doc = load()?;
    let names: Vec<&str> = doc.cases.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["main", "empty", "long"]);
    assert_eq!(doc.negatives.len(), 20);
    for case in &doc.cases {
        let inputs = case.inputs()?;
        // 4 schemes x (2 counter + 1 once + 4 stream + 1 random)
        assert_eq!(case.vectors.len(), 32, "case {}", case.name);
        for scheme_id in 1u8..=4 {
            for mode in ["counter", "once", "stream", "random"] {
                assert!(
                    case.vectors
                        .iter()
                        .any(|v| v.scheme == scheme_id && v.mode == mode),
                    "case {} lacks {mode} vectors for scheme {scheme_id}",
                    case.name
                );
            }
        }
        for v in &case.vectors {
            let (got, expected) = if v.mode == "random" {
                let extra = NONCE_LEN.saturating_add(CASCADE_OVERHEAD);
                (v.sealed()?.len(), inputs.pt.len().saturating_add(extra))
            } else {
                (
                    v.ciphertext()?.len(),
                    inputs.pt.len().saturating_add(CASCADE_OVERHEAD),
                )
            };
            assert_eq!(got, expected, "length of {} / {}", case.name, v.id);
        }
    }
    // The contract inputs: |pt| = 20, |ct| = 52.
    let main = doc.cases.first().ok_or("main case missing")?;
    assert_eq!(main.inputs()?.pt, b"cascade known answer");
    assert_eq!(main.inputs()?.aad, b"aad-1");
    assert_eq!(main.inputs()?.domain, b"crypt_guard/test/cascade");
    Ok(())
}

#[test]
fn labels_match_the_contract() -> TestResult {
    let labels = load()?.labels;
    assert_eq!(labels.l_in.as_bytes(), L_IN);
    assert_eq!(labels.l_out.as_bytes(), L_OUT);
    assert_eq!(labels.l_one.as_bytes(), L_ONE);
    assert_eq!(labels.l_nonce.as_bytes(), L_NONCE);
    assert_eq!(labels.l_random.as_bytes(), L_RANDOM);
    assert_eq!(labels.a_in.as_bytes(), A_IN);
    assert_eq!(labels.a_out.as_bytes(), A_OUT);
    assert_eq!(labels.a_one.as_bytes(), A_ONE);
    Ok(())
}

#[test]
fn subkeys_and_derived_nonces_match_the_crate_prf() -> TestResult {
    let doc = load()?;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        assert_eq!(case.subkeys.len(), 4, "case {}", case.name);
        let mut distinct: Vec<Vec<u8>> = Vec::new();
        for (id, sub) in &case.subkeys {
            let scheme_id: u8 = id.parse()?;
            let ctx = ctx_of(scheme_id, &inputs.domain)?;
            assert_eq!(unhex(&sub.ctx)?, ctx, "ctx of {} / {id}", case.name);

            let k_in = prf32(&inputs.root, L_IN, &ctx)?;
            let k_out = prf32(&inputs.root, L_OUT, &ctx)?;
            let k_one = prf32(&inputs.root, L_ONE, &ctx)?;
            assert_eq!(hex::encode(k_in.as_slice()), sub.k_in, "k_in {} / {id}", case.name);
            assert_eq!(hex::encode(k_out.as_slice()), sub.k_out, "k_out {} / {id}", case.name);
            assert_eq!(hex::encode(k_one.as_slice()), sub.k_one, "k_one {} / {id}", case.name);

            let mut nonce = [0u8; NONCE_LEN];
            prf(&inputs.root, L_NONCE, &ctx, &mut nonce)?;
            assert_eq!(hex::encode(nonce), sub.nonce_once, "nonce {} / {id}", case.name);

            // Only the single-layer key of each scheme, plus both Cascade layer keys,
            // are ever used; they must be pairwise distinct.
            distinct.push(k_one.to_vec());
            if scheme_id == 4 {
                distinct.push(k_in.to_vec());
                distinct.push(k_out.to_vec());
            }
        }
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 6, "sub-keys of case {} are not independent", case.name);
    }
    // Contract 2.2.6: the Cascade layer keys of the contract inputs.
    let main = doc.cases.first().ok_or("main case missing")?;
    let cascade_keys = main.subkeys.get("4").ok_or("scheme 4 sub-keys missing")?;
    assert_eq!(
        cascade_keys.k_in,
        "29eecf9a61cb966250a804b1e531c86ace2802ab217d9a1b8800d74a3cef0292"
    );
    assert_eq!(
        cascade_keys.k_out,
        "0b6df53cdb3e6329fe08c6fe5407857f7e29b8d36f26315da007695562b214f9"
    );
    assert_eq!(
        cascade_keys.nonce_once,
        "e0fbac1160eeeec3cdf30d68d18a7586b88e68d6be2858af"
    );
    Ok(())
}

#[test]
fn vectors_seal_and_open_to_the_model_output() -> TestResult {
    let doc = load()?;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        for v in &case.vectors {
            let scheme = v.scheme()?;
            let at = format!("{} / {}", case.name, v.id);
            match v.mode.as_str() {
                "counter" | "stream" => {
                    let ct = v.ciphertext()?;
                    let nonce = v.nonce()?;
                    let cascade = inputs.cascade(scheme)?;
                    assert_eq!(cascade.scheme(), scheme);
                    assert_eq!(cascade.seal(&nonce, &inputs.aad, &inputs.pt)?, ct, "seal {at}");
                    let opened = cascade.open(&nonce, &inputs.aad, &ct)?;
                    assert_eq!(opened.as_slice(), inputs.pt.as_slice(), "open {at}");
                }
                "once" => {
                    let ct = v.ciphertext()?;
                    let sub = case
                        .subkeys
                        .get(&v.scheme.to_string())
                        .ok_or("sub-keys missing")?;
                    assert_eq!(v.n24, sub.nonce_once, "derived nonce {at}");
                    let sealed = inputs.cascade(scheme)?.seal_once(&inputs.aad, &inputs.pt)?;
                    assert_eq!(sealed, ct, "seal_once {at}");
                    let cascade = inputs.cascade(scheme)?;
                    let opened = cascade.open_once(&inputs.aad, &ct)?;
                    assert_eq!(opened.as_slice(), inputs.pt.as_slice(), "open_once {at}");
                    // Opening twice is harmless; only sealing is one-shot.
                    let again = cascade.open_once(&inputs.aad, &ct)?;
                    assert_eq!(again.as_slice(), inputs.pt.as_slice(), "open_once again {at}");
                }
                "random" => {}
                other => return Err(BoxErr::from(format!("unknown mode {other} in {at}"))),
            }
        }
    }
    Ok(())
}

#[test]
fn contract_2_2_6_vectors_are_present_verbatim() -> TestResult {
    // The numbers printed in section 2.2.6 of the contract (contract inputs).
    let doc = load()?;
    let main = doc.cases.first().ok_or("main case missing")?;
    let find = |id: &str| find_vector(main, id);
    let expected = [
        (
            "counter/Cascade/1/5",
            "71b3d7c5e2cc0ec27edec4dd0949e0039d80207ee810c95567adb765640b7c1a79b269fe0bba036e20b52090685895bbe46fc06b",
        ),
        (
            "counter/XChaCha20Poly1305/1/5",
            "432f81fce4584c0be14cc6e5641387f84f21c702fb8ce953256ab62e90e182ff7c3f16972f93fd002116bb28f25953f67e36778c",
        ),
        (
            "counter/Aes256GcmSiv/1/5",
            "b6428725da3ab72ca71605ae5c0e93fd9e8729215eff00d1c88dbd2c03649960632d737c8a28c82812d90adce5a5db899b5fc2f5",
        ),
        (
            "counter/ChaCha20Poly1305/1/5",
            "975ab325c73f69cf5e2633291eb9d7384a7b4893189aa5e581391226b9ed33f89dea2a5784b25164f3e542f1ec3c52d9ef4ecc4c",
        ),
        (
            "once/Cascade",
            "a649da40579f391994babd7f2ebef1217b13efe922f5cf6c61ff6723237ff270c0e65d57be1c5d7107dad7fe419dc59ccc362f10",
        ),
        (
            "stream/Cascade/00000000000001/3/more",
            "1af3e77dec051584db464a63a695e45d63d1eb26835926adca9508b0bfa12878d6d2093f2d80cd13c032e4af8c1b63604010f18b",
        ),
        (
            "stream/Cascade/00000000000001/3/last",
            "1ce90b5ed61e3be892e424ae37b90dca8041e4ccffd3b8b12707a4b6abb1e346a09202e1de2a5ff3452270d8d91de6de73fe0dcf",
        ),
    ];
    for (id, ct) in expected {
        assert_eq!(hex::encode(find(id)?.ciphertext()?), ct, "vector {id}");
    }
    assert_eq!(
        find("counter/Cascade/1/5")?.n24,
        "010000000000000000000005000000000000000000000000"
    );
    assert_eq!(
        find("stream/Cascade/00000000000001/3/more")?.n24,
        "000000000000010000000300000000000000000000000000"
    );
    let random = find("random/Cascade")?;
    assert_eq!(random.n24, "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7");
    assert_eq!(
        hex::encode(random.sealed()?),
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7057f374419c4fdc4aae3e6a494831e67db98e6ef20e3f00f27501fbaf827112c2df118fa802cc302a0f0e41019ab7084def2c80d"
    );
    Ok(())
}

#[test]
fn in_place_variants_reproduce_the_vectors() -> TestResult {
    let doc = load()?;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        let plain_len = inputs.pt.len();
        let mut fresh = inputs.pt.clone();
        fresh.resize(plain_len.saturating_add(CASCADE_OVERHEAD), 0);
        for v in &case.vectors {
            let scheme = v.scheme()?;
            let at = format!("{} / {}", case.name, v.id);
            match v.mode.as_str() {
                "counter" | "stream" => {
                    let ct = v.ciphertext()?;
                    let nonce = v.nonce()?;
                    let cascade = inputs.cascade(scheme)?;
                    let mut buf = fresh.clone();
                    cascade.seal_in_place(&nonce, &inputs.aad, &mut buf, plain_len)?;
                    assert_eq!(buf, ct, "seal_in_place {at}");
                    let plain = cascade.open_in_place(&nonce, &inputs.aad, &mut buf)?;
                    assert_eq!(&*plain, inputs.pt.as_slice(), "open_in_place {at}");
                }
                "once" => {
                    let ct = v.ciphertext()?;
                    let mut buf = fresh.clone();
                    inputs
                        .cascade(scheme)?
                        .seal_once_in_place(&inputs.aad, &mut buf, plain_len)?;
                    assert_eq!(buf, ct, "seal_once_in_place {at}");
                    let plain = inputs
                        .cascade(scheme)?
                        .open_once_in_place(&inputs.aad, &mut buf)?;
                    assert_eq!(&*plain, inputs.pt.as_slice(), "open_once_in_place {at}");
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[test]
fn in_place_open_failure_leaves_no_plaintext_and_wrong_buffer_length_is_rejected() -> TestResult {
    let doc = load()?;
    let main = doc.cases.first().ok_or("main case missing")?;
    let inputs = main.inputs()?;
    let cascade = inputs.cascade(Scheme::Cascade)?;
    let nonce = CascadeNonce::Counter { domain: 1, n: 5 };
    let ct = cascade.seal(&nonce, &inputs.aad, &inputs.pt)?;

    // A failed in-place open (wrong AAD) must not leave the plaintext in the buffer.
    let mut buf = ct.clone();
    let result = cascade.open_in_place(&nonce, b"aad-2", &mut buf);
    assert!(is_auth_failed(&result));
    assert!(
        !buf.windows(inputs.pt.len()).any(|w| w == inputs.pt.as_slice()),
        "plaintext leaked into the buffer of a failed open"
    );

    // Buffer length is a caller contract: plain_len + CASCADE_OVERHEAD, else InvalidParameters.
    let mut short = inputs.pt.clone();
    short.resize(inputs.pt.len().saturating_add(CASCADE_OVERHEAD).saturating_sub(1), 0);
    assert!(matches!(
        cascade.seal_in_place(&nonce, &inputs.aad, &mut short, inputs.pt.len()),
        Err(CryptError::InvalidParameters)
    ));
    let mut long = inputs.pt.clone();
    long.resize(inputs.pt.len().saturating_add(CASCADE_OVERHEAD).saturating_add(1), 0);
    assert!(matches!(
        cascade.seal_in_place(&nonce, &inputs.aad, &mut long, inputs.pt.len()),
        Err(CryptError::InvalidParameters)
    ));
    Ok(())
}

#[test]
fn random_vectors_open_and_seal_random_round_trips() -> TestResult {
    let doc = load()?;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        for v in case.vectors.iter().filter(|v| v.mode == "random") {
            let scheme = v.scheme()?;
            let at = format!("{} / {}", case.name, v.id);
            let sealed = v.sealed()?;
            assert_eq!(
                hex::encode(sealed.iter().copied().take(NONCE_LEN).collect::<Vec<u8>>()),
                v.n24,
                "n24 prefix {at}"
            );
            let opened = open_random(scheme, &inputs.root, &inputs.domain, &inputs.aad, &sealed)?;
            assert_eq!(opened.as_slice(), inputs.pt.as_slice(), "open_random {at}");

            // Fresh random seal: n24 || ct, correct length, opens, never repeats.
            let first = seal_random(scheme, &inputs.root, &inputs.domain, &inputs.aad, &inputs.pt)?;
            let second =
                seal_random(scheme, &inputs.root, &inputs.domain, &inputs.aad, &inputs.pt)?;
            let want = inputs
                .pt
                .len()
                .saturating_add(NONCE_LEN)
                .saturating_add(CASCADE_OVERHEAD);
            assert_eq!(first.len(), want, "seal_random length {at}");
            assert_ne!(first, second, "two random seals were identical ({at})");
            assert_ne!(
                first.iter().take(NONCE_LEN).collect::<Vec<_>>(),
                second.iter().take(NONCE_LEN).collect::<Vec<_>>(),
                "random n24 repeated ({at})"
            );
            for sealed in [&first, &second] {
                let plain =
                    open_random(scheme, &inputs.root, &inputs.domain, &inputs.aad, sealed)?;
                assert_eq!(plain.as_slice(), inputs.pt.as_slice(), "round trip {at}");
            }

            // Every byte, including the n24 prefix, is authenticated.
            for index in 0..sealed.len() {
                let bad = flipped(&sealed, index, 0x01);
                let result =
                    open_random(scheme, &inputs.root, &inputs.domain, &inputs.aad, &bad);
                assert!(is_auth_failed(&result), "flip at {index} accepted ({at})");
            }
            // Wrong AAD / domain / root / scheme.
            let mut other_domain = inputs.domain.clone();
            other_domain.push(b'x');
            let mut other_root = inputs.root;
            if let Some(b) = other_root.first_mut() {
                *b ^= 0x01;
            }
            assert!(is_auth_failed(&open_random(
                scheme,
                &inputs.root,
                &inputs.domain,
                b"other-aad",
                &sealed
            )));
            assert!(is_auth_failed(&open_random(
                scheme,
                &inputs.root,
                &other_domain,
                &inputs.aad,
                &sealed
            )));
            assert!(is_auth_failed(&open_random(
                scheme,
                &other_root,
                &inputs.domain,
                &inputs.aad,
                &sealed
            )));
            for other in SCHEMES.into_iter().filter(|s| *s != scheme) {
                assert!(
                    is_auth_failed(&open_random(
                        other,
                        &inputs.root,
                        &inputs.domain,
                        &inputs.aad,
                        &sealed
                    )),
                    "scheme {scheme:?} sealed value opened as {other:?} ({at})"
                );
            }
            // Truncation and extension.
            let shorter: Vec<u8> = sealed.iter().copied().take(sealed.len().saturating_sub(1)).collect();
            let mut longer = sealed.clone();
            longer.push(0x5a);
            for bad in [shorter, longer, Vec::new()] {
                assert!(
                    open_random(scheme, &inputs.root, &inputs.domain, &inputs.aad, &bad).is_err(),
                    "malformed length {} accepted ({at})",
                    bad.len()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn every_byte_flip_of_every_vector_fails_opaquely() -> TestResult {
    let doc = load()?;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        for v in &case.vectors {
            if v.mode == "random" {
                continue;
            }
            let scheme = v.scheme()?;
            let at = format!("{} / {}", case.name, v.id);
            let ct = v.ciphertext()?;
            let cascade = inputs.cascade(scheme)?;
            for index in 0..ct.len() {
                for mask in [0x01u8, 0x80] {
                    let bad = flipped(&ct, index, mask);
                    let result = if v.mode == "once" {
                        cascade.open_once(&inputs.aad, &bad)
                    } else {
                        cascade.open(&v.nonce()?, &inputs.aad, &bad)
                    };
                    assert!(
                        is_auth_failed(&result),
                        "flip {mask:#04x} at byte {index} accepted ({at})"
                    );
                }
            }
            // Truncated by one byte, extended by one byte, empty.
            let shorter: Vec<u8> = ct.iter().copied().take(ct.len().saturating_sub(1)).collect();
            let mut longer = ct.clone();
            longer.push(0);
            for bad in [shorter, longer, Vec::new()] {
                let result = if v.mode == "once" {
                    cascade.open_once(&inputs.aad, &bad)
                } else {
                    cascade.open(&v.nonce()?, &inputs.aad, &bad)
                };
                assert!(result.is_err(), "length {} accepted ({at})", bad.len());
            }
        }
    }
    Ok(())
}

#[test]
fn wrong_aad_domain_root_scheme_and_nonce_fail() -> TestResult {
    let doc = load()?;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        for v in &case.vectors {
            if v.mode == "random" {
                continue;
            }
            let scheme = v.scheme()?;
            let at = format!("{} / {}", case.name, v.id);
            let ct = v.ciphertext()?;
            let cascade = inputs.cascade(scheme)?;
            let once = v.mode == "once";
            let open_with = |c: &Cascade, nonce: &CascadeNonce, aad: &[u8]| {
                if once {
                    c.open_once(aad, &ct)
                } else {
                    c.open(nonce, aad, &ct)
                }
            };
            let nonce = if once {
                CascadeNonce::Counter { domain: 1, n: 0 } // unused for `once`
            } else {
                v.nonce()?
            };
            // Control: the right inputs open.
            assert!(open_with(&cascade, &nonce, &inputs.aad).is_ok(), "control {at}");

            // Wrong AAD (appended byte, and dropped when there is one).
            let mut longer_aad = inputs.aad.clone();
            longer_aad.push(b'!');
            assert!(is_auth_failed(&open_with(&cascade, &nonce, &longer_aad)), "aad+ {at}");
            if !inputs.aad.is_empty() {
                assert!(is_auth_failed(&open_with(&cascade, &nonce, b"")), "aad- {at}");
            }
            // Wrong domain.
            let mut domain = inputs.domain.clone();
            domain.push(b'x');
            let other = Cascade::new(scheme, &inputs.root, &domain)?;
            assert!(is_auth_failed(&open_with(&other, &nonce, &inputs.aad)), "domain {at}");
            // Wrong root.
            let mut root = inputs.root;
            if let Some(b) = root.last_mut() {
                *b ^= 0x80;
            }
            let other = Cascade::new(scheme, &root, &inputs.domain)?;
            assert!(is_auth_failed(&open_with(&other, &nonce, &inputs.aad)), "root {at}");
            // Wrong scheme.
            for wrong in SCHEMES.into_iter().filter(|s| *s != scheme) {
                let other = inputs.cascade(wrong)?;
                assert!(
                    is_auth_failed(&open_with(&other, &nonce, &inputs.aad)),
                    "scheme {scheme:?} vector opened as {wrong:?} ({at})"
                );
            }
            // Wrong nonce (counter and stream only; `once` has no caller nonce).
            if once {
                continue;
            }
            let wrong_nonces: Vec<CascadeNonce> = match nonce {
                CascadeNonce::Counter { domain, n } => vec![
                    CascadeNonce::Counter { domain, n: n.wrapping_add(1) },
                    CascadeNonce::Counter { domain: domain ^ 0x01, n },
                ],
                CascadeNonce::Stream { prefix, index, last } => {
                    let mut other_prefix = prefix;
                    if let Some(b) = other_prefix.first_mut() {
                        *b ^= 0x10;
                    }
                    vec![
                        CascadeNonce::Stream { prefix, index: index.wrapping_add(1), last },
                        CascadeNonce::Stream { prefix, index, last: !last },
                        CascadeNonce::Stream { prefix: other_prefix, index, last },
                    ]
                }
                _ => return Err(BoxErr::from("unexpected CascadeNonce variant")),
            };
            for wrong in wrong_nonces {
                assert!(
                    is_auth_failed(&open_with(&cascade, &wrong, &inputs.aad)),
                    "wrong nonce {wrong:?} accepted ({at})"
                );
            }
            // A one-shot vector is not a counter vector and vice versa.
            assert!(is_auth_failed(&cascade.open_once(&inputs.aad, &ct)), "once vs {at}");
        }
    }
    Ok(())
}

#[test]
fn negative_vectors_are_rejected() -> TestResult {
    let doc = load()?;
    let main = doc.cases.first().ok_or("main case missing")?;
    let inputs = main.inputs()?;
    let full_len = inputs.pt.len().saturating_add(CASCADE_OVERHEAD);
    for neg in &doc.negatives {
        let scheme = Scheme::from_id(neg.scheme).ok_or("unknown scheme in negative vector")?;
        let nonce = CascadeNonce::Counter { domain: neg.domain_byte, n: neg.n.parse()? };
        let ct = unhex(&neg.ct)?;
        let result = inputs.cascade(scheme)?.open(&nonce, &inputs.aad, &ct);
        assert!(result.is_err(), "negative vector {} was accepted: {}", neg.id, neg.why);
        if ct.len() == full_len {
            assert!(
                is_auth_failed(&result),
                "negative vector {} must fail with the opaque error: {}",
                neg.id,
                neg.why
            );
        }
    }
    Ok(())
}

#[test]
fn stream_vectors_match_the_pq_stream_layout() -> TestResult {
    // For the ChaCha20-Poly1305 scheme the cascade STREAM nonce is exactly the
    // `pq_stream` nonce (`prefix[7] ‖ counter u32 BE ‖ last u8`), so
    // `pq_stream::StreamEncryptor` under the single-layer key and the
    // single-layer AAD must reproduce the model's ciphertext.
    let doc = load()?;
    let mut checked = 0usize;
    for case in &doc.cases {
        let inputs = case.inputs()?;
        let sub = case.subkeys.get("1").ok_or("scheme 1 sub-keys missing")?;
        let key: [u8; KEY_LEN] = array(&unhex(&sub.k_one)?)?;
        let ctx = ctx_of(1, &inputs.domain)?;
        let mut aad = A_ONE.to_vec();
        aad.extend_from_slice(&ctx);
        aad.extend_from_slice(&inputs.aad);
        let mut body = inputs.pt.clone();
        body.extend_from_slice(&[0u8; 16]); // single-layer filler
        for v in case
            .vectors
            .iter()
            .filter(|v| v.mode == "stream" && v.scheme == 1)
        {
            let index = v.index.ok_or("stream vector without index")?;
            if index > 8 {
                continue; // a counter near u32::MAX cannot be reached by sealing chunks
            }
            let prefix: [u8; 7] = array(&unhex(v.prefix.as_deref().ok_or("prefix missing")?)?)?;
            let mut encryptor = StreamEncryptor::new(&key, prefix)?;
            for _ in 0..index {
                encryptor.encrypt_next(b"earlier chunk", b"other aad")?;
            }
            let sealed = if v.last.ok_or("last missing")? {
                encryptor.encrypt_last(&body, &aad)?
            } else {
                encryptor.encrypt_next(&body, &aad)?
            };
            assert_eq!(sealed, v.ciphertext()?, "pq_stream layout {} / {}", case.name, v.id);
            checked = checked.saturating_add(1);
        }
    }
    // 3 cases x ({prefix 1, index 3} non-final + final, {prefix 9.., index 0} non-final).
    assert_eq!(checked, 9);
    Ok(())
}

#[test]
fn programming_errors_are_invalid_parameters() -> TestResult {
    let root = [0x42u8; KEY_LEN];
    for scheme in SCHEMES {
        // All-zero root and empty domain are rejected up front.
        assert!(matches!(
            Cascade::new(scheme, &[0u8; KEY_LEN], b"crypt_guard/test/cascade"),
            Err(CryptError::InvalidParameters)
        ));
        assert!(matches!(
            Cascade::new(scheme, &root, b""),
            Err(CryptError::InvalidParameters)
        ));
        let cascade = Cascade::new(scheme, &root, b"crypt_guard/test/cascade")?;
        // A zero STREAM prefix is rejected like `pq_stream::validate_prefix` does.
        let zero_prefix = CascadeNonce::Stream { prefix: [0u8; 7], index: 0, last: false };
        assert!(matches!(
            cascade.seal(&zero_prefix, b"", b"data"),
            Err(CryptError::InvalidParameters)
        ));
        // Debug output is redacted: no key material, no domain bytes.
        let debug = format!("{cascade:?}");
        assert!(!debug.contains("42"), "Debug leaked key bytes: {debug}");
        assert!(!debug.contains("crypt_guard/test/cascade"), "Debug leaked the domain: {debug}");
    }
    Ok(())
}

// ── Part B: pq_multi cascade variant ─────────────────────────────────────────

#[cfg(feature = "ml-kem-backend")]
mod multi {
    use std::cell::Cell;

    use super::{is_auth_failed, BoxErr, TestResult, SCHEMES};
    use crypt_guard::error::CryptError;
    use crypt_guard::pq_cascade::{
        open_envelope, seal_envelope, Cascade, Scheme, CASCADE_OVERHEAD, MAXIMAL_SUITE,
    };
    use crypt_guard::pq_hpke::{
        derive_recipient_key_pair, Aead, HpkeEnvelope, Kdf, Kem, RecipientKeyPair, Suite,
        DEFAULT_SUITE,
    };
    use crypt_guard::pq_multi::{
        dummy_cascade_wrap, dummy_wrap, open_multi, open_multi_cascade, recipient_set_hash,
        seal_multi, seal_multi_cascade, MultiRecipientCiphertext, WRAP_PAYLOAD_LEN,
    };
    use zeroize::Zeroizing;

    const HEADER: &[u8] = b"group=7;epoch=3;msg=42";
    const INFO: &[u8] = b"comnet/group-message/v1";
    const PAYLOAD: &[u8] = b"hello, cascade group";
    /// `20 (CGH3 header) + 1665 (hybrid enc) + 34 (wrap payload) + 32 (two tags)`.
    const WRAP_LEN: usize = 1751;
    /// `CGH3 ‖ version 1 ‖ kem 0x0051 ‖ kdf 0x0011 ‖ aead 0xff02 ‖ enc_len 1665 ‖ ct_len 66`.
    const WRAP_HEADER: [u8; 20] = [
        b'C', b'G', b'H', b'3', 0x00, 0x01, 0x00, 0x51, 0x00, 0x11, 0xff, 0x02, 0x00, 0x00, 0x06,
        0x81, 0x00, 0x00, 0x00, 0x42,
    ];
    /// `pq_cascade` domain of the body (documented in the `pq_multi` module docs).
    const MULTI_BODY: &[u8] = b"crypt_guard/v3/multi-recipient/body";
    const WRAP_INFO_LABEL: &[u8] = b"crypt_guard/v3/multi-recipient/wrap";
    const CEK: [u8; 32] = [0x42; 32];

    fn member(seed: u8) -> Result<RecipientKeyPair, BoxErr> {
        Ok(derive_recipient_key_pair(MAXIMAL_SUITE.kem(), &[seed; 32])?)
    }

    fn members(count: u8) -> Result<Vec<RecipientKeyPair>, BoxErr> {
        (1..=count).map(member).collect()
    }

    fn fingerprints(keys: &[RecipientKeyPair]) -> Vec<[u8; 32]> {
        keys.iter().map(|k| k.public_key().fingerprint()).collect()
    }

    fn seal(
        scheme: Scheme,
        keys: &[RecipientKeyPair],
        payload: &[u8],
    ) -> Result<MultiRecipientCiphertext, CryptError> {
        let public: Vec<_> = keys.iter().map(RecipientKeyPair::public_key).collect();
        seal_multi_cascade(MAXIMAL_SUITE, scheme, &public, HEADER, INFO, payload)
    }

    fn open_with(
        key: &RecipientKeyPair,
        ct: &MultiRecipientCiphertext,
        index: usize,
        header: &[u8],
        accept: &dyn Fn(Scheme) -> bool,
    ) -> Result<(Scheme, Zeroizing<Vec<u8>>), CryptError> {
        let fp = key.public_key().fingerprint();
        open_multi_cascade(MAXIMAL_SUITE, key.private_key(), &fp, ct, index, header, INFO, accept)
    }

    fn open_ok(
        key: &RecipientKeyPair,
        ct: &MultiRecipientCiphertext,
        index: usize,
    ) -> Result<(Scheme, Zeroizing<Vec<u8>>), CryptError> {
        open_with(key, ct, index, HEADER, &|_| true)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// `WRAP_INFO_LABEL ‖ lp32(info) ‖ set_hash ‖ fp` (documented, unchanged from `seal_multi`).
    fn wrap_info(info: &[u8], set_hash: &[u8; 32], fp: &[u8; 32]) -> Result<Vec<u8>, BoxErr> {
        let mut out = WRAP_INFO_LABEL.to_vec();
        out.extend_from_slice(&u32::try_from(info.len())?.to_be_bytes());
        out.extend_from_slice(info);
        out.extend_from_slice(set_hash);
        out.extend_from_slice(fp);
        Ok(out)
    }

    fn wrap_plaintext(version: u8, scheme_id: u8, cek: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![version, scheme_id];
        out.extend_from_slice(cek);
        out
    }

    /// Assemble a multi-recipient ciphertext from the documented construction with
    /// attacker-chosen pieces: body sealed under `body_scheme` and `cek`, every wrap
    /// carrying `wrap_pt`.
    fn assemble(
        keys: &[RecipientKeyPair],
        body_scheme: Scheme,
        cek: &[u8; 32],
        wrap_pt: &[u8],
    ) -> Result<MultiRecipientCiphertext, BoxErr> {
        let fps = fingerprints(keys);
        let set_hash = recipient_set_hash(&fps)?;
        let mut aad = HEADER.to_vec();
        aad.extend_from_slice(&set_hash);
        let body = Cascade::new(body_scheme, cek, MULTI_BODY)?.seal_once(&aad, PAYLOAD)?;
        let mut wraps = Vec::new();
        for (key, fp) in keys.iter().zip(fps.iter()) {
            let info_i = wrap_info(INFO, &set_hash, fp)?;
            let envelope = seal_envelope(MAXIMAL_SUITE, key.public_key(), &info_i, HEADER, wrap_pt)?;
            wraps.push(envelope.try_to_bytes()?);
        }
        Ok(MultiRecipientCiphertext { body, wraps, recipient_set_hash: set_hash })
    }

    #[test]
    fn multi_wrap_len_is_1751() -> TestResult {
        let keys = members(3)?;
        assert_eq!(WRAP_PAYLOAD_LEN, 34);
        assert_eq!(20 + 1665 + WRAP_PAYLOAD_LEN + CASCADE_OVERHEAD, WRAP_LEN);
        for scheme in SCHEMES {
            let ct = seal(scheme, &keys, PAYLOAD)?;
            assert_eq!(ct.wraps.len(), 3);
            assert_eq!(ct.body.len(), PAYLOAD.len() + CASCADE_OVERHEAD, "{scheme:?}");
            for wrap in &ct.wraps {
                assert_eq!(wrap.len(), WRAP_LEN, "{scheme:?}");
                // Header bytes are identical for every scheme: the level is invisible.
                assert_eq!(wrap.get(..20), Some(WRAP_HEADER.as_slice()), "{scheme:?}");
                let envelope = HpkeEnvelope::from_bytes(wrap)?;
                assert_eq!(envelope.suite(), MAXIMAL_SUITE);
                assert_eq!(envelope.encapsulation().len(), 1665);
                assert_eq!(envelope.ciphertext().len(), WRAP_PAYLOAD_LEN + CASCADE_OVERHEAD);
            }
        }
        Ok(())
    }

    #[test]
    fn dummy_cascade_wrap_len_equals_real() -> TestResult {
        let keys = members(2)?;
        let real = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        let real_wrap = real.wraps.first().ok_or("missing wrap")?;
        let first = dummy_cascade_wrap(MAXIMAL_SUITE)?;
        let second = dummy_cascade_wrap(MAXIMAL_SUITE)?;
        assert_eq!(first.len(), real_wrap.len());
        assert_eq!(first.len(), WRAP_LEN);
        assert_eq!(first.get(..20), Some(WRAP_HEADER.as_slice()));
        assert_eq!(first.get(..20), real_wrap.get(..20));
        assert_ne!(first, second, "dummy wraps must be random");
        let envelope = HpkeEnvelope::from_bytes(&first)?;
        assert_eq!(envelope.suite(), MAXIMAL_SUITE);
        assert_eq!(envelope.ciphertext().len(), WRAP_PAYLOAD_LEN + CASCADE_OVERHEAD);

        // Nobody can open a dummy: put it into a real ciphertext and try every member.
        let mut padded = real.clone();
        padded.wraps.push(first);
        let dummy_index = padded.wraps.len().saturating_sub(1);
        for key in &keys {
            assert!(is_auth_failed(&open_ok(key, &padded, dummy_index)));
        }
        Ok(())
    }

    #[test]
    fn multi_all_schemes_roundtrip() -> TestResult {
        let keys = members(3)?;
        for scheme in SCHEMES {
            let ct = seal(scheme, &keys, PAYLOAD)?;
            assert!(!contains(&ct.body, PAYLOAD), "{scheme:?} body contains the plaintext");
            for (index, key) in keys.iter().enumerate() {
                let (got, plain) = open_ok(key, &ct, index)?;
                assert_eq!(got, scheme, "scheme reported to recipient {index}");
                assert_eq!(plain.as_slice(), PAYLOAD, "{scheme:?} recipient {index}");
            }
            ct.check_recipient_set(&fingerprints(&keys))?;
        }
        Ok(())
    }

    #[test]
    fn multi_payload_sizes_roundtrip() -> TestResult {
        let keys = members(2)?;
        let key = keys.last().ok_or("missing member")?;
        let big = vec![0x37u8; 1000];
        let payloads: [&[u8]; 3] = [b"", b"x", big.as_slice()];
        for scheme in SCHEMES {
            for payload in payloads {
                let ct = seal(scheme, &keys, payload)?;
                assert_eq!(ct.body.len(), payload.len() + CASCADE_OVERHEAD);
                let (got, plain) = open_ok(key, &ct, 1)?;
                assert_eq!(got, scheme);
                assert_eq!(plain.as_slice(), payload);
            }
        }
        Ok(())
    }

    #[test]
    fn wrap_plaintext_layout_is_version_scheme_cek() -> TestResult {
        let keys = members(2)?;
        let fps = fingerprints(&keys);
        for scheme in SCHEMES {
            let ct = seal(scheme, &keys, PAYLOAD)?;
            for (index, key) in keys.iter().enumerate() {
                let wrap = ct.wraps.get(index).ok_or("missing wrap")?;
                let fp = fps.get(index).ok_or("missing fingerprint")?;
                let info_i = wrap_info(INFO, &ct.recipient_set_hash, fp)?;
                let envelope = HpkeEnvelope::from_bytes(wrap)?;
                let wrap_pt =
                    open_envelope(MAXIMAL_SUITE, &envelope, key.private_key(), &info_i, HEADER)?;
                assert_eq!(wrap_pt.len(), WRAP_PAYLOAD_LEN);
                assert_eq!(wrap_pt.first().copied(), Some(1), "WRAP_VERSION");
                assert_eq!(wrap_pt.get(1).copied(), Some(scheme.id()), "scheme id");
                // The CEK in the wrap opens the body under the documented domain and AAD.
                let cek: [u8; 32] = wrap_pt
                    .get(2..)
                    .ok_or("missing CEK")?
                    .try_into()
                    .map_err(|_| BoxErr::from("CEK is not 32 bytes"))?;
                let mut aad = HEADER.to_vec();
                aad.extend_from_slice(&ct.recipient_set_hash);
                let plain = Cascade::new(scheme, &cek, MULTI_BODY)?.open_once(&aad, &ct.body)?;
                assert_eq!(plain.as_slice(), PAYLOAD);
            }
        }
        Ok(())
    }

    #[test]
    fn independent_assembly_opens_via_the_documented_construction() -> TestResult {
        // A ciphertext built only from the documented formulas (pq_cascade primitives)
        // must open with open_multi_cascade and report the scheme from the wrap.
        let keys = members(2)?;
        for scheme in SCHEMES {
            let ct = assemble(&keys, scheme, &CEK, &wrap_plaintext(1, scheme.id(), &CEK))?;
            for (index, key) in keys.iter().enumerate() {
                let (got, plain) = open_ok(key, &ct, index)?;
                assert_eq!(got, scheme);
                assert_eq!(plain.as_slice(), PAYLOAD);
            }
        }
        Ok(())
    }

    #[test]
    fn multi_level_byte_tamper_detected() -> TestResult {
        // The wrap claims one scheme, the body was sealed under another: the scheme id is
        // part of every body key and AAD, so the body can never open under the claim.
        let keys = members(1)?;
        let key = keys.first().ok_or("missing member")?;
        for body_scheme in SCHEMES {
            for claimed in SCHEMES {
                let ct = assemble(&keys, body_scheme, &CEK, &wrap_plaintext(1, claimed.id(), &CEK))?;
                let result = open_ok(key, &ct, 0);
                if claimed == body_scheme {
                    let (got, plain) = result?;
                    assert_eq!(got, body_scheme);
                    assert_eq!(plain.as_slice(), PAYLOAD);
                } else {
                    assert!(
                        is_auth_failed(&result),
                        "body sealed as {body_scheme:?} opened under claimed {claimed:?}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn wrap_version_unknown_scheme_and_wrong_length_are_rejected() -> TestResult {
        let keys = members(1)?;
        let key = keys.first().ok_or("missing member")?;
        let good = wrap_plaintext(1, Scheme::Cascade.id(), &CEK);
        let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
        for version in [0u8, 2, 255] {
            cases.push((
                format!("wrap version {version}"),
                wrap_plaintext(version, Scheme::Cascade.id(), &CEK),
            ));
        }
        for id in [0u8, 5, 15, 255] {
            cases.push((format!("scheme id {id}"), wrap_plaintext(1, id, &CEK)));
        }
        let mut long = good.clone();
        long.push(0x42);
        cases.push(("one byte too long".to_owned(), long));
        cases.push((
            "one byte too short".to_owned(),
            good.iter().copied().take(WRAP_PAYLOAD_LEN - 1).collect(),
        ));
        cases.push(("empty".to_owned(), Vec::new()));
        // Control: the unmodified payload opens.
        let control = assemble(&keys, Scheme::Cascade, &CEK, &good)?;
        assert!(open_ok(key, &control, 0).is_ok());
        for (what, wrap_pt) in cases {
            let ct = assemble(&keys, Scheme::Cascade, &CEK, &wrap_pt)?;
            let calls = Cell::new(0u32);
            let result = open_with(key, &ct, 0, HEADER, &|_| {
                calls.set(calls.get() + 1);
                true
            });
            assert!(is_auth_failed(&result), "{what} was accepted");
            assert_eq!(calls.get(), 0, "accept must not see a defective wrap ({what})");
        }
        Ok(())
    }

    #[test]
    fn multi_accept_false_is_auth_failed() -> TestResult {
        let keys = members(2)?;
        let key = keys.first().ok_or("missing member")?;
        for scheme in SCHEMES {
            let ct = seal(scheme, &keys, PAYLOAD)?;

            // accept sees exactly the wrap's scheme, exactly once.
            let calls = Cell::new(0u32);
            let seen = Cell::new(None);
            let (got, _) = open_with(key, &ct, 0, HEADER, &|s| {
                calls.set(calls.get() + 1);
                seen.set(Some(s));
                true
            })?;
            assert_eq!(got, scheme);
            assert_eq!(calls.get(), 1);
            assert_eq!(seen.get(), Some(scheme));

            // accept == false: the same opaque error, accept called once.
            let calls = Cell::new(0u32);
            let result = open_with(key, &ct, 0, HEADER, &|_| {
                calls.set(calls.get() + 1);
                false
            });
            assert!(is_auth_failed(&result), "{scheme:?}");
            assert_eq!(calls.get(), 1);

            // Tenant minimum "at least AES-256-GCM-SIV".
            let at_least_aes = |s: Scheme| s >= Scheme::Aes256GcmSiv;
            let result = open_with(key, &ct, 0, HEADER, &at_least_aes);
            assert_eq!(result.is_ok(), at_least_aes(scheme), "{scheme:?}");
            if !at_least_aes(scheme) {
                assert!(is_auth_failed(&result));
            }
        }

        // accept runs before the body is touched: a tampered body still reaches accept.
        let mut ct = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        if let Some(b) = ct.body.first_mut() {
            *b ^= 0x01;
        }
        let calls = Cell::new(0u32);
        let result = open_with(key, &ct, 0, HEADER, &|_| {
            calls.set(calls.get() + 1);
            true
        });
        assert!(is_auth_failed(&result));
        assert_eq!(calls.get(), 1);

        // accept is not consulted for a wrap that does not authenticate.
        let ct = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        let outsider = member(99)?;
        let calls = Cell::new(0u32);
        let result = open_with(&outsider, &ct, 0, HEADER, &|_| {
            calls.set(calls.get() + 1);
            true
        });
        assert!(is_auth_failed(&result));
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    #[test]
    fn multi_recipient_set_and_header_splice_rejected() -> TestResult {
        let keys = members(3)?;
        let first = keys.first().ok_or("missing member")?;
        let second = keys.get(1).ok_or("missing member")?;
        let ct = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        assert!(open_ok(first, &ct, 0).is_ok(), "control");

        // Header AAD and info.
        assert!(is_auth_failed(&open_with(first, &ct, 0, b"group=7;epoch=4;msg=42", &|_| true)));
        let fp = first.public_key().fingerprint();
        let result = open_multi_cascade(
            MAXIMAL_SUITE,
            first.private_key(),
            &fp,
            &ct,
            0,
            HEADER,
            b"other/info",
            &|_| true,
        );
        assert!(is_auth_failed(&result));

        // Substituted or modified recipient-set hash (the sender's claim is authenticated).
        let other_set = fingerprints(&members(2)?);
        let mut forged = ct.clone();
        forged.recipient_set_hash = recipient_set_hash(&other_set)?;
        assert!(is_auth_failed(&open_ok(first, &forged, 0)));
        let mut forged = ct.clone();
        if let Some(b) = forged.recipient_set_hash.first_mut() {
            *b ^= 0x01;
        }
        assert!(is_auth_failed(&open_ok(first, &forged, 0)));

        // Wrong fingerprint, another member's wrap, out-of-range index.
        let wrong_fp = second.public_key().fingerprint();
        let result = open_multi_cascade(
            MAXIMAL_SUITE,
            first.private_key(),
            &wrong_fp,
            &ct,
            0,
            HEADER,
            INFO,
            &|_| true,
        );
        assert!(is_auth_failed(&result));
        assert!(is_auth_failed(&open_ok(first, &ct, 1)));
        assert!(is_auth_failed(&open_ok(second, &ct, 0)));
        assert!(is_auth_failed(&open_ok(first, &ct, 3)));
        assert!(is_auth_failed(&open_ok(first, &ct, usize::MAX)));

        // Body of another message under the same recipients and header.
        let other = seal(Scheme::Cascade, &keys, b"another payload")?;
        let mut spliced = ct.clone();
        spliced.body = other.body.clone();
        assert!(is_auth_failed(&open_ok(first, &spliced, 0)));
        // Wraps of another message (other CEK) with this message's body.
        let mut spliced = ct.clone();
        spliced.wraps = other.wraps.clone();
        assert!(is_auth_failed(&open_ok(first, &spliced, 0)));
        // A single foreign wrap in place of mine.
        let mut spliced = ct.clone();
        if let (Some(slot), Some(foreign)) = (spliced.wraps.first_mut(), other.wraps.first()) {
            *slot = foreign.clone();
        }
        assert!(is_auth_failed(&open_ok(first, &spliced, 0)));
        // Truncated and extended body.
        let mut shorter = ct.clone();
        shorter.body.pop();
        assert!(is_auth_failed(&open_ok(first, &shorter, 0)));
        let mut longer = ct.clone();
        longer.body.push(0);
        assert!(is_auth_failed(&open_ok(first, &longer, 0)));
        // Outsider.
        let outsider = member(99)?;
        for index in 0..ct.wraps.len() {
            assert!(is_auth_failed(&open_ok(&outsider, &ct, index)));
        }
        Ok(())
    }

    #[test]
    fn tampering_with_any_part_of_a_wrap_or_the_body_fails_opaquely() -> TestResult {
        let keys = members(1)?;
        let key = keys.first().ok_or("missing member")?;
        let ct = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        let wrap_len = ct.wraps.first().ok_or("missing wrap")?.len();
        assert_eq!(wrap_len, WRAP_LEN);
        // Header fields (magic, version, suite ids, lengths), start/middle/end of `enc`
        // (ML-KEM part and P-384 part), first/last byte of the ciphertext and tag.
        let positions = [
            0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16, 19, 20, 21, 500, 1583, 1584, 1588, 1650,
            1684, 1685, 1700, 1734, 1735, 1750,
        ];
        for position in positions {
            let mut bad = ct.clone();
            if let Some(wrap) = bad.wraps.first_mut() {
                if let Some(b) = wrap.get_mut(position) {
                    *b ^= 0x01;
                }
            }
            assert!(is_auth_failed(&open_ok(key, &bad, 0)), "wrap byte {position} flip accepted");
        }
        for position in 0..ct.body.len() {
            let mut bad = ct.clone();
            if let Some(b) = bad.body.get_mut(position) {
                *b ^= 0x80;
            }
            assert!(is_auth_failed(&open_ok(key, &bad, 0)), "body byte {position} flip accepted");
        }
        // Undecodable wraps: truncated, extended, empty, garbage.
        for bad_wrap in [
            ct.wraps.first().map(|w| w.iter().copied().take(WRAP_LEN - 1).collect::<Vec<u8>>()),
            ct.wraps.first().map(|w| {
                let mut longer = w.clone();
                longer.push(0);
                longer
            }),
            Some(Vec::new()),
            Some(vec![0xA5; WRAP_LEN]),
        ] {
            let mut bad = ct.clone();
            bad.wraps = vec![bad_wrap.ok_or("missing wrap")?];
            assert!(is_auth_failed(&open_ok(key, &bad, 0)));
        }
        Ok(())
    }

    #[test]
    fn suite_is_pinned_to_maximal() -> TestResult {
        let keys = members(2)?;
        let key = keys.first().ok_or("missing member")?;
        let public: Vec<_> = keys.iter().map(RecipientKeyPair::public_key).collect();

        // Sealing and dummies refuse any other suite.
        for other in [
            DEFAULT_SUITE,
            Suite::new(Kem::MlKem1024P384, Kdf::Shake256, Aead::Aes256GcmSiv),
            Suite::new(Kem::MlKem1024, Kdf::Shake256, Aead::XChaCha20Poly1305),
        ] {
            assert!(matches!(
                seal_multi_cascade(other, Scheme::Cascade, &public, HEADER, INFO, PAYLOAD),
                Err(CryptError::UnsupportedAlgorithm)
            ));
            assert!(matches!(dummy_cascade_wrap(other), Err(CryptError::UnsupportedAlgorithm)));
        }

        // Opening: a receiver pinned to another suite refuses a Maximal wrap ...
        let ct = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        let fp = key.public_key().fingerprint();
        let result = open_multi_cascade(
            DEFAULT_SUITE,
            key.private_key(),
            &fp,
            &ct,
            0,
            HEADER,
            INFO,
            &|_| true,
        );
        assert!(is_auth_failed(&result));
        // ... and a Maximal receiver refuses a wrap with another wire suite.
        let legacy = seal_multi(DEFAULT_SUITE, &public, HEADER, INFO, PAYLOAD)?;
        assert!(is_auth_failed(&open_ok(key, &legacy, 0)));
        Ok(())
    }

    #[test]
    fn cascade_and_plain_families_do_not_cross_open() -> TestResult {
        let keys = members(2)?;
        let key = keys.first().ok_or("missing member")?;
        let public: Vec<_> = keys.iter().map(RecipientKeyPair::public_key).collect();
        let fp = key.public_key().fingerprint();

        // Plain seal_multi under the Maximal suite (same envelope suite, other construction).
        let plain = seal_multi(MAXIMAL_SUITE, &public, HEADER, INFO, PAYLOAD)?;
        let opened = open_multi(MAXIMAL_SUITE, key.private_key(), &fp, &plain, 0, HEADER, INFO)?;
        assert_eq!(opened.as_slice(), PAYLOAD, "control: the plain family still works");
        assert!(is_auth_failed(&open_ok(key, &plain, 0)));

        // Cascade ciphertext through the plain opener.
        let cascade = seal(Scheme::ChaCha20Poly1305, &keys, PAYLOAD)?;
        let result = open_multi(MAXIMAL_SUITE, key.private_key(), &fp, &cascade, 0, HEADER, INFO);
        assert!(is_auth_failed(&result));
        Ok(())
    }

    #[test]
    fn empty_and_duplicate_recipients_are_rejected() -> TestResult {
        let keys = members(1)?;
        let key = keys.first().ok_or("missing member")?;
        for scheme in SCHEMES {
            assert!(matches!(
                seal_multi_cascade(MAXIMAL_SUITE, scheme, &[], HEADER, INFO, PAYLOAD),
                Err(CryptError::InvalidParameters)
            ));
            assert!(matches!(
                seal_multi_cascade(
                    MAXIMAL_SUITE,
                    scheme,
                    &[key.public_key(), key.public_key()],
                    HEADER,
                    INFO,
                    PAYLOAD
                ),
                Err(CryptError::InvalidParameters)
            ));
        }
        Ok(())
    }

    #[test]
    fn wraps_can_be_shuffled_and_padded_with_cascade_dummies() -> TestResult {
        let keys = members(3)?;
        let ct = seal(Scheme::XChaCha20Poly1305, &keys, PAYLOAD)?;
        let mut padded = ct.clone();
        padded.wraps.push(dummy_cascade_wrap(MAXIMAL_SUITE)?);
        padded.wraps.push(dummy_cascade_wrap(MAXIMAL_SUITE)?);
        padded.wraps.reverse();
        let total = padded.wraps.len();
        for (member_index, key) in keys.iter().enumerate() {
            let index = total.saturating_sub(1).saturating_sub(member_index);
            let (got, plain) = open_ok(key, &padded, index)?;
            assert_eq!(got, Scheme::XChaCha20Poly1305);
            assert_eq!(plain.as_slice(), PAYLOAD);
        }
        for wrap in &padded.wraps {
            assert_eq!(wrap.len(), WRAP_LEN);
        }
        // Dummies do not enter the recipient-set hash.
        padded.check_recipient_set(&fingerprints(&keys))?;
        Ok(())
    }

    #[test]
    fn every_message_gets_a_fresh_cek_and_fresh_wraps() -> TestResult {
        let keys = members(1)?;
        let first = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        let second = seal(Scheme::Cascade, &keys, PAYLOAD)?;
        assert_ne!(first.body, second.body);
        assert_ne!(first.wraps, second.wraps);
        assert_eq!(first.recipient_set_hash, second.recipient_set_hash);
        Ok(())
    }

    #[test]
    fn legacy_family_is_unchanged() -> TestResult {
        // 20 + 1665 + 32 (CEK) + 16 (tag): the pre-3.2 wrap size, still produced by seal_multi.
        let keys = members(2)?;
        let public: Vec<_> = keys.iter().map(RecipientKeyPair::public_key).collect();
        let ct = seal_multi(DEFAULT_SUITE, &public, HEADER, INFO, PAYLOAD)?;
        for wrap in &ct.wraps {
            assert_eq!(wrap.len(), 1733);
        }
        assert_eq!(ct.body.len(), PAYLOAD.len() + 16);
        assert_eq!(dummy_wrap(DEFAULT_SUITE)?.len(), 1733);
        let key = keys.first().ok_or("missing member")?;
        let fp = key.public_key().fingerprint();
        let plain = open_multi(DEFAULT_SUITE, key.private_key(), &fp, &ct, 0, HEADER, INFO)?;
        assert_eq!(plain.as_slice(), PAYLOAD);
        Ok(())
    }
}
