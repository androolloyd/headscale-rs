fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The gRPC surface (`tonic` + the `proto/*.proto` schemas) is only
    // active under the `full` feature. Wire-layer-only consumers
    // (`default-features = false`) — notably `octravpn-mesh` — don't
    // need `protoc` to be installed in their build environment, so we
    // skip the prost-build step entirely when the feature is off.
    //
    // Without this gate the docker-builder image for the
    // tailscale-interop harness fails the cargo build with:
    //   Error: Could not find `protoc`. If `protoc` is installed, try
    //   setting the `PROTOC` environment variable…
    // The fix is feature-gated so downstream callers of `--features full`
    // (the headscale-cli, the gateway, etc.) keep their generated code.
    if std::env::var_os("CARGO_FEATURE_FULL").is_some() {
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(true)
            .out_dir("src/generated")
            .file_descriptor_set_path("src/generated/headscale_descriptor.bin")
            .compile_protos(
                &[
                    "proto/common.proto",
                    "proto/node.proto",
                    "proto/resources.proto",
                    "proto/payments.proto",
                    "proto/health.proto",
                    "proto/apikey.proto",
                    "proto/policy.proto",
                    "proto/preauthkey.proto",
                    "proto/user.proto",
                    "proto/headscale.proto",
                ],
                &["proto"],
            )?;
    }

    Ok(())
}
