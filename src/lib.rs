//! Bounded, application-independent packet relaying.
#![forbid(unsafe_code)]

#[cfg(feature = "turn")]
pub mod auth;
pub mod limits;
#[cfg(all(feature = "runtime", feature = "turn"))]
pub mod turn;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub mod wasm;
#[cfg(feature = "turn")]
pub mod wire;
