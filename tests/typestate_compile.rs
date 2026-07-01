#[test]
fn staged_safe_api_compile_failures() {
    let t = trybuild::TestCases::new();

    // This case checks the safe API's AEAD marker bounds and stays valid across
    // both feature sets.
    t.compile_fail("tests/ui/legacy_aes_not_safe_aead.rs");

    // The content-axis typestate cases only apply to the non-legacy safe path.
    // When `legacy-pqclean` is enabled, those legacy methods are present again
    // and the compile-fail assertions would become false positives.
    if !cfg!(feature = "legacy-pqclean") {
        t.compile_fail("tests/ui/content_encrypt_file_on_message.rs");
        t.compile_fail("tests/ui/content_encrypt_data_on_files.rs");
        t.compile_fail("tests/ui/content_decrypt_msg_on_files.rs");
        t.compile_fail("tests/ui/sealer_missing_recipient.rs");
        t.compile_fail("tests/ui/sealer_missing_plaintext.rs");
        t.compile_fail("tests/ui/opener_missing_secret_key.rs");
    }
}
