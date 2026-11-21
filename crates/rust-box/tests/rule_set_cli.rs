//! `rust-box rule-set` against sing-box v1.14.4: the fixtures in
//! `tests/data/rule-set` were written by the real sing-box binary
//! (`*.sing.srs` by `rule-set compile`/`convert`, `*.decompiled.json` by
//! `decompile`, `*.formatted.json` and `v1.upgraded.json` from the stdout
//! of `format`/`upgrade`, `merged.json` by `merge -c domain.json -c
//! v2.json -c v1.json`, `match.expected.txt` from the stderr of `match`).
//! Binary files are compared after decompression, since the zlib streams
//! of Go and Rust differ.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SOURCES: &[&str] = &["full", "domain", "v1", "v2"];

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/rule-set").join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(data(name)).unwrap()
}

fn rust_box(args: &[&str]) -> Output {
    let binary = std::env::var_os("CARGO_BIN_EXE_rust-box").expect("Cargo supplies the rust-box binary path");
    let output = Command::new(binary).args(args).output().unwrap();
    output
}

fn ok(args: &[&str]) -> Output {
    let output = rust_box(args);
    assert!(output.status.success(), "{args:?}: {}", String::from_utf8_lossy(&output.stderr));
    output
}

fn decompressed(content: &[u8]) -> (u8, Vec<u8>) {
    rb_config::srs::decompress(content).unwrap()
}

#[test]
fn compile_matches_sing_box() {
    let directory = tempfile::tempdir().unwrap();
    for name in SOURCES {
        let output = directory.path().join(format!("{name}.srs"));
        ok(&["rule-set", "compile", data(&format!("{name}.json")).to_str().unwrap(), "-o", output.to_str().unwrap()]);
        let ours = std::fs::read(&output).unwrap();
        assert_eq!(decompressed(&ours), decompressed(&read(&format!("{name}.sing.srs"))), "{name}");
    }
    // Without -o the output goes next to the source, `.json` replaced.
    let source = directory.path().join("x.json");
    std::fs::copy(data("domain.json"), &source).unwrap();
    ok(&["rule-set", "compile", source.to_str().unwrap()]);
    assert!(directory.path().join("x.srs").exists());
}

#[test]
fn decompile_matches_sing_box() {
    let directory = tempfile::tempdir().unwrap();
    for name in SOURCES {
        let output = directory.path().join(format!("{name}.json"));
        ok(&[
            "rule-set",
            "decompile",
            data(&format!("{name}.sing.srs")).to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
        ]);
        let ours = std::fs::read_to_string(&output).unwrap();
        assert_eq!(ours, String::from_utf8(read(&format!("{name}.decompiled.json"))).unwrap(), "{name}");
    }
    let output = rust_box(&["rule-set", "decompile", data("adguard.sing.srs").to_str().unwrap(), "-o", "/dev/null"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unable to decompile binary AdGuard rules to rule-set."));
}

#[test]
fn format_matches_sing_box() {
    for name in SOURCES {
        let output = ok(&["rule-set", "format", data(&format!("{name}.json")).to_str().unwrap()]);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(read(&format!("{name}.formatted.json"))).unwrap(),
            "{name}"
        );
    }
    // -w rewrites the file (without the extra newline) and prints its path.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("f.json");
    std::fs::copy(data("v2.json"), &path).unwrap();
    let output = ok(&["rule-set", "format", "-w", path.to_str().unwrap()]);
    assert_eq!(String::from_utf8_lossy(&output.stderr).trim(), path.to_str().unwrap());
    let formatted = read("v2.formatted.json");
    assert_eq!(std::fs::read(&path).unwrap(), formatted[..formatted.len() - 1]);
    // Unchanged: nothing is printed.
    let output = ok(&["rule-set", "format", "-w", path.to_str().unwrap()]);
    assert!(output.stderr.is_empty());
}

#[test]
fn upgrade_matches_sing_box() {
    let output = ok(&["rule-set", "upgrade", data("v1.json").to_str().unwrap()]);
    assert_eq!(String::from_utf8(output.stdout).unwrap(), String::from_utf8(read("v1.upgraded.json")).unwrap());
    let output = ok(&["rule-set", "upgrade", data("v2.json").to_str().unwrap()]);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already up-to-date"));
}

#[test]
fn merge_matches_sing_box() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("sub/merged.json");
    let (domain, v1, v2) = (data("domain.json"), data("v1.json"), data("v2.json"));
    ok(&[
        "rule-set",
        "merge",
        output.to_str().unwrap(),
        "-c",
        domain.to_str().unwrap(),
        "-c",
        v2.to_str().unwrap(),
        "-c",
        v1.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), String::from_utf8(read("merged.json")).unwrap());
    // A directory contributes its .json files.
    let inputs = directory.path().join("in");
    std::fs::create_dir(&inputs).unwrap();
    for name in ["domain.json", "v1.json", "v2.json"] {
        std::fs::copy(data(name), inputs.join(name)).unwrap();
    }
    std::fs::write(inputs.join("ignored.txt"), "x").unwrap();
    let output = directory.path().join("merged2.json");
    ok(&["rule-set", "merge", output.to_str().unwrap(), "-C", inputs.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), String::from_utf8(read("merged.json")).unwrap());
}

#[test]
fn match_matches_sing_box() {
    let expected = String::from_utf8(read("match.expected.txt")).unwrap();
    let mut ours = String::new();
    for target in ["example.com", "www.google.com", "10.1.2.3", "1.1.1.1", "none.invalid", "logical.test"] {
        ours.push_str(&format!("== {target}\n"));
        let output = ok(&["rule-set", "match", data("full.json").to_str().unwrap(), target]);
        ours.push_str(&String::from_utf8(output.stderr).unwrap());
        let output = ok(&["rule-set", "match", "-f", "binary", data("full.sing.srs").to_str().unwrap(), target]);
        for line in String::from_utf8(output.stderr).unwrap().lines() {
            ours.push_str(&format!("B {line}\n"));
        }
    }
    assert_eq!(ours, expected);
    let output = rust_box(&["rule-set", "match", "-f", "x", data("full.json").to_str().unwrap(), "a"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown rule-set format: x"));
}

#[test]
fn convert_matches_sing_box() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("adguard.srs");
    ok(&[
        "rule-set",
        "convert",
        "-t",
        "adguard",
        data("adguard.txt").to_str().unwrap(),
        "-o",
        output.to_str().unwrap(),
    ]);
    assert_eq!(decompressed(&std::fs::read(&output).unwrap()), decompressed(&read("adguard.sing.srs")));
    let output = rust_box(&["rule-set", "convert", data("adguard.txt").to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("source type is required"));
    let output = rust_box(&["rule-set", "convert", "-t", "x", data("adguard.txt").to_str().unwrap()]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported source type: x"));
}

/// Empty lists as sing-box's decoder sees them (outputs taken from the real
/// binary): `[]` is unset, and a rule list of only empty rules is no list.
#[test]
fn empty_lists_match_sing_box() {
    let cases = [
        (r#"{"version":3,"rules":[{}]}"#, r#"{"version":3}"#, ""),
        (r#"{"version":3,"rules":[{"domain":[]}]}"#, r#"{"version":3}"#, ""),
        (r#"{"version":3,"rules":[{},{}]}"#, r#"{"version":3}"#, ""),
        (r#"{"version":3,"rules":[{"type":"default"}]}"#, r#"{"version":3}"#, ""),
        (
            r#"{"version":3,"rules":[{"domain":[]},{"domain":"a"}]}"#,
            r#"{"version":3,"rules":[{},{"domain":"a"}]}"#,
            "parse rule_set.rules.[0]: missing conditions",
        ),
        (
            r#"{"version":3,"rules":[{"domain":[],"invert":true}]}"#,
            r#"{"version":3,"rules":[{"invert":true}]}"#,
            "parse rule_set.rules.[0]: missing conditions",
        ),
        (
            r#"{"version":3,"rules":[{"type":"logical","mode":"and","rules":[{}]}]}"#,
            r#"{"version":3,"rules":[{"type":"logical","mode":"and"}]}"#,
            "parse rule_set.rules.[0]: missing conditions",
        ),
    ];
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("e.json");
    for (source, formatted, error) in cases {
        std::fs::write(&path, source).unwrap();
        let output = ok(&["rule-set", "format", path.to_str().unwrap()]);
        let compact: String = String::from_utf8(output.stdout).unwrap().split_whitespace().collect();
        assert_eq!(compact, formatted, "{source}");
        let output = rust_box(&["rule-set", "match", path.to_str().unwrap(), "a.com"]);
        let stderr = String::from_utf8(output.stderr).unwrap();
        if error.is_empty() {
            assert!(output.status.success() && stderr.is_empty(), "{source}: {stderr}");
        } else {
            assert!(!output.status.success() && stderr.contains(error), "{source}: {stderr}");
        }
    }
}
