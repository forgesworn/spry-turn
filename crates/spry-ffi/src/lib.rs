//! A supervised Spry relay inside a host application's own process, through
//! a hand-written C ABI (`include/spry_relay.h`) and, with the `jni`
//! feature, a thin JNI shim for Android.
//!
//! Both drive [`spry_service::embedded`]: the same node as
//! `spry-node supervised`, with the same options and lines. No binding
//! generator is involved. Every exported function catches panics, so none
//! crosses into the host; build the library with the `release-ffi` profile,
//! which unwinds, for that to hold in a release build. See
//! `docs/embedding.md`.

#[allow(unsafe_code)]
mod capi;
#[cfg(feature = "jni")]
#[allow(unsafe_code)]
mod jni;

pub use capi::*;
