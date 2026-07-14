use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct CompileFailCase {
    source: &'static str,
    stderr_needles: &'static [&'static str],
}

#[test]
fn staged_safe_api_compile_failures() {
    let mut cases = vec![CompileFailCase {
        source: "tests/ui/legacy_aes_not_safe_aead.rs",
        stderr_needles: &["AuthenticatedAead", "crypt_guard::AES"],
    }];

    // The content-axis typestate cases only apply to the non-legacy safe path.
    // When `legacy-pqclean` is enabled, those legacy methods are present again
    // and the compile-fail assertions would become false positives.
    if !cfg!(feature = "legacy-pqclean") {
        cases.extend([
            CompileFailCase {
                source: "tests/ui/content_encrypt_file_on_message.rs",
                stderr_needles: &["no method named `encrypt_file`"],
            },
            CompileFailCase {
                source: "tests/ui/content_encrypt_data_on_files.rs",
                stderr_needles: &["no method named `encrypt_data`"],
            },
            CompileFailCase {
                source: "tests/ui/content_decrypt_msg_on_files.rs",
                stderr_needles: &["no method named `decrypt_msg`"],
            },
            CompileFailCase {
                source: "tests/ui/sealer_missing_recipient.rs",
                stderr_needles: &["no method named `plaintext`", "MissingRecipient"],
            },
            CompileFailCase {
                source: "tests/ui/sealer_missing_plaintext.rs",
                stderr_needles: &["no method named `seal`", "MissingPlaintext"],
            },
            CompileFailCase {
                source: "tests/ui/opener_missing_secret_key.rs",
                stderr_needles: &["no method named `open`", "MissingSecretKey"],
            },
        ]);
    }

    for case in cases {
        assert_compile_fails(case);
    }
}

fn assert_compile_fails(case: CompileFailCase) {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let work_dir = prepare_case_crate(&manifest_dir, case.source);

    let output = Command::new("cargo")
        .arg("check")
        .arg("--offline")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(work_dir.join("Cargo.toml"))
        .output()
        .expect("failed to run cargo check for compile-fail case");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "{} unexpectedly compiled successfully",
        case.source
    );
    for needle in case.stderr_needles {
        assert!(
            stderr.contains(needle),
            "{} stderr did not contain {:?}\n\nstderr:\n{}",
            case.source,
            needle,
            stderr
        );
    }
}

fn prepare_case_crate(manifest_dir: &Path, source: &str) -> PathBuf {
    let case_name = source
        .rsplit('/')
        .next()
        .expect("source path has a file name")
        .trim_end_matches(".rs");
    let work_dir = manifest_dir
        .join("target")
        .join("typestate_compile")
        .join(case_name);
    let src_dir = work_dir.join("src");
    fs::create_dir_all(&src_dir).expect("failed to create compile-fail test crate");

    fs::write(
        src_dir.join("main.rs"),
        fs::read_to_string(manifest_dir.join(source)).unwrap(),
    )
    .expect("failed to write compile-fail main.rs");

    fs::write(
        work_dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "{case_name}_compile_fail"
version = "0.0.0"
edition = "2021"

[dependencies]
crypt_guard = {{ path = "{path}", default-features = {default_features}, features = {features:?} }}

[workspace]
"#,
            path = manifest_dir.display(),
            default_features = default_features_enabled(),
            features = dependency_features(),
        ),
    )
    .expect("failed to write compile-fail Cargo.toml");

    work_dir
}

fn default_features_enabled() -> bool {
    !cfg!(any(
        feature = "legacy-pqclean",
        all(feature = "ml-kem-backend", feature = "ml-dsa-backend")
    ))
}

fn dependency_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "legacy-pqclean") {
        features.push("legacy-pqclean");
    } else if cfg!(all(feature = "ml-kem-backend", feature = "ml-dsa-backend")) {
        features.push("ml-kem-backend");
        features.push("ml-dsa-backend");
    }
    features
}
