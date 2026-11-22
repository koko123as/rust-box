//! `check` on `tun` inbounds gives the same verdict as sing-box v1.14.4
//! (`SING_BOX_BIN`): what sing-box accepts at `check` time rust-box accepts
//! too, and what it refuses rust-box refuses. Fields rust-box does not
//! implement are refused by rust-box only, and listed apart.

use std::process::Command;

fn check(binary: &str, config: &str) -> (bool, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    std::fs::write(&path, config).unwrap();
    let output = Command::new(binary).args(["check", "-c"]).arg(&path).output().unwrap();
    (output.status.success(), String::from_utf8_lossy(&output.stderr).into_owned())
}

fn tun(fields: &str) -> String {
    format!(
        r#"{{"inbounds":[{{"type":"tun"{fields}}}],"route":{{"rule_set":[{{"type":"inline","tag":"rs","rules":[{{"domain":"a.test"}}]}}]}}}}"#
    )
}

const SAME: &[&str] = &[
    "",
    r#","interface_name":"tun9","mtu":1500,"address":["172.19.0.1/30","fdfe:dcba:9876::1/126"]"#,
    r#","auto_route":true,"strict_route":true,"iproute2_table_index":100,"iproute2_rule_index":100"#,
    r#","route_address":["0.0.0.0/1"],"route_exclude_address":["10.0.0.0/8"]"#,
    r#","include_interface":["eth0"],"exclude_interface":["eth1"]"#,
    r#","include_uid":[0],"include_uid_range":["1000:2000"],"exclude_uid":[1],"exclude_uid_range":["3:4"]"#,
    r#","include_android_user":[0,10],"include_package":["a.b"],"exclude_package":["c.d"]"#,
    r#","udp_timeout":"1m","udp_mapping":"address_dependent","udp_filtering":"address_and_port_dependent","udp_nat_max":10"#,
    r#","stack":"mixed","dns_mode":"hijack","dns_address":["1.1.1.1"]"#,
    r#","stack":"lwip""#,
    r#","dns_mode":"foo""#,
    r#","platform":{"http_proxy":{"enabled":true,"server":"127.0.0.1","server_port":8080}}"#,
    r#","udp_timeout":300"#,
    // Refused by both.
    r#","foo":1"#,
    r#","listen_port":1"#,
    r#","udp_mapping":"x""#,
    r#","include_uid_range":["1"]"#,
    r#","auto_redirect":true"#,
    r#","include_mac_address":["zz"]"#,
    r#","route_address_set":["missing"]"#,
    r#","sniff":true"#,
    r#","gso":true"#,
    r#","inet4_address":"172.19.0.1/30""#,
    r#","endpoint_independent_nat":true"#,
];

/// Accepted by sing-box, refused by rust-box as not implemented.
const NOT_IMPLEMENTED: &[(&str, &str)] = &[
    (r#","netns":"x""#, "inbounds[0].netns: `netns` is not supported by rust-box yet"),
    (
        r#","auto_route":true,"auto_redirect":true"#,
        "inbounds[0].auto_redirect: `auto_redirect` is not supported by rust-box yet",
    ),
    (r#","exclude_mptcp":true"#, "inbounds[0].exclude_mptcp: `exclude_mptcp` is not supported by rust-box yet"),
    (
        r#","loopback_address":["10.7.0.1"]"#,
        "inbounds[0].loopback_address: `loopback_address` is not supported by rust-box yet",
    ),
    (
        r#","include_mac_address":["00:11:22:33:44:55"]"#,
        "inbounds[0].include_mac_address: `include_mac_address` is not supported by rust-box yet",
    ),
    (
        r#","route_address_set":["rs"]"#,
        "inbounds[0].route_address_set: `route_address_set` is not supported by rust-box yet",
    ),
];

#[test]
fn check_verdicts_like_sing_box() {
    let rust_box = env!("CARGO_BIN_EXE_rust-box");
    let sing_box = std::env::var("SING_BOX_BIN").ok().filter(|binary| !binary.is_empty());
    assert!(check(rust_box, &tun("")).0);
    for fields in SAME {
        let config = tun(fields);
        let (ours, our_error) = check(rust_box, &config);
        if let Some(sing_box) = &sing_box {
            let (theirs, their_error) = check(sing_box, &config);
            assert_eq!(ours, theirs, "{fields}\nrust-box: {our_error}\nsing-box: {their_error}");
        }
    }
    for (fields, message) in NOT_IMPLEMENTED {
        let config = tun(fields);
        let (ours, our_error) = check(rust_box, &config);
        assert!(!ours && our_error.contains(message), "{fields}: {our_error}");
        if let Some(sing_box) = &sing_box {
            let (theirs, their_error) = check(sing_box, &config);
            assert!(theirs, "{fields}: {their_error}");
        }
    }
}
