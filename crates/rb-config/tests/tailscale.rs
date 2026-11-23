use rb_config::{parse, Endpoint, TailscaleSshServerOptions};

#[test]
fn endpoint_decodes_v114_options_and_ssh_forms() {
    let options = parse(
        r#"{"endpoints":[{"type":"tailscale","tag":"ts","state_directory":"state","auth_key":"key","control_url":"https://control.example","ephemeral":true,"hostname":"node","accept_routes":true,"exit_node_allow_lan_access":true,"advertise_routes":["10.0.0.0/8"],"advertise_exit_node":false,"advertise_tags":"tag:server","listen_port":41641,"relay_server_port":3478,"relay_server_static_endpoints":["192.0.2.1:3478"],"system_interface":true,"system_interface_name":"tailscale0","system_interface_mtu":1280,"udp_timeout":"5m","ssh_server":{"enabled":true,"disable_pty":true,"disable_sftp":false,"disable_forwarding":true},"taildrop_directory":"Taildrop"}]}"#,
    )
    .unwrap();
    let Endpoint::Tailscale(endpoint) = &options.endpoints[0] else { panic!("expected Tailscale endpoint") };
    assert_eq!(options.endpoints[0].tag(), "ts");
    assert_eq!(options.endpoints[0].kind(), "tailscale");
    assert_eq!(endpoint.state_directory, "state");
    assert_eq!(endpoint.advertise_routes[0].prefix_len, 8);
    assert_eq!(endpoint.advertise_tags.0[0], "tag:server");
    assert_eq!(endpoint.relay_server_port, Some(3478));
    assert_eq!(endpoint.relay_server_static_endpoints[0].to_string(), "192.0.2.1:3478");
    assert!(
        matches!(endpoint.ssh_server.as_ref(), Some(TailscaleSshServerOptions::Settings(settings)) if settings.enabled && settings.disable_pty && settings.disable_forwarding)
    );

    let boolean_form = parse(r#"{"endpoints":[{"type":"tailscale","ssh_server":true}]}"#).unwrap();
    let Endpoint::Tailscale(endpoint) = &boolean_form.endpoints[0] else { panic!("expected Tailscale endpoint") };
    assert!(matches!(endpoint.ssh_server.as_ref(), Some(TailscaleSshServerOptions::Enabled(true))));
}

#[test]
fn endpoint_rejects_conflicts_and_unknown_fields_with_paths() {
    for (config, expected) in [
        (
            r#"{"endpoints":[{"type":"tailscale","advertise_routes":["0.0.0.0/0"]}]}"#,
            "endpoints[0].advertise_routes: `advertise_routes` cannot be default",
        ),
        (
            r#"{"endpoints":[{"type":"tailscale","advertise_exit_node":true,"exit_node":"peer"}]}"#,
            "endpoints[0]: cannot advertise an exit node and use an exit node",
        ),
    ] {
        let error = parse(config).unwrap_err().to_string();
        assert!(error.contains(expected), "{config}: {error}");
    }

    let unknown_endpoint = parse(r#"{"endpoints":[{"type":"tailscale","future":true}]}"#).unwrap_err().to_string();
    assert!(
        unknown_endpoint.contains("endpoints[0]") && unknown_endpoint.contains("unknown field `future`"),
        "{unknown_endpoint}"
    );

    let unknown_ssh = parse(r#"{"endpoints":[{"type":"tailscale","ssh_server":{"enabled":true,"future":true}}]}"#)
        .unwrap_err()
        .to_string();
    assert!(unknown_ssh.contains("endpoints[0]") && unknown_ssh.contains("unknown field `future`"), "{unknown_ssh}");
}
