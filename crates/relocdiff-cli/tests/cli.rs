use std::process::Command;

#[test]
fn invalid_input_uses_exit_code_two_and_keeps_json_clean() {
    let missing = std::env::temp_dir().join("relocdiff-missing-input.exe");
    let output = Command::new(env!("CARGO_BIN_EXE_relocdiff"))
        .args([
            "inspect",
            missing.to_str().unwrap(),
            "--address",
            "0x140000000",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("error: "));
}
