//! Native FFI bindings for Flutter mobile apps and biometric support
//!
//! Uses flutter_rust_bridge to expose vault operations to Dart
//! Provides biometric authentication via platform-specific APIs

pub mod api;
pub mod biometric;

pub use api::*;
pub use biometric::*;
