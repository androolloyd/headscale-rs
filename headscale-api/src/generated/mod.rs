// Generated protobuf code
// This module includes the generated code from tonic-build.
// Lints inside the prost-generated file are out of our control and
// re-running the codegen would just regenerate the same shape; suppress
// the stylistic family at the module boundary instead of polluting the
// workspace allow-list.
#[allow(
    clippy::derive_partial_eq_without_eq,
    clippy::default_trait_access,
    clippy::use_self
)]
#[path = "headscale.v1.rs"]
pub mod headscale_v1;

pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!("headscale_descriptor.bin");

// Re-export for convenience
pub use headscale_v1::*;
