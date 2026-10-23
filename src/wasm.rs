//! Reusable linear-memory packet arena. Host adapters own networking and time.
//! After construction, framing/parsing uses the same buffer without per-packet
//! Rust allocations or wasm-bindgen slice marshalling of the packet payload.
use crate::{auth, wire};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct PacketArena {
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl PacketArena {
    #[wasm_bindgen(constructor)]
    pub fn new(capacity: usize) -> Result<PacketArena, JsValue> {
        if !(20..=65_536).contains(&capacity) {
            return Err(JsValue::from_str("capacity must be 20..65536"));
        }
        Ok(Self {
            bytes: vec![0; capacity],
        })
    }

    /// Borrow this region with Uint8Array(memory.buffer, arena.ptr(), arena.capacity()).
    /// Recreate the view after any WebAssembly memory growth; do not retain it
    /// beyond the arena's lifetime or call free while the host is using it.
    pub fn ptr(&mut self) -> usize {
        self.bytes.as_mut_ptr() as usize
    }
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    pub fn valid_stun(&self, len: usize) -> bool {
        self.bytes
            .get(..len)
            .and_then(wire::Message::parse)
            .is_some()
    }
    pub fn stun_method(&self, len: usize) -> i32 {
        self.bytes
            .get(..len)
            .and_then(wire::Message::parse)
            .map_or(-1, |m| i32::from(m.method))
    }
    pub fn stun_class(&self, len: usize) -> i32 {
        self.bytes
            .get(..len)
            .and_then(wire::Message::parse)
            .map_or(-1, |m| i32::from(m.class))
    }
    pub fn verify_integrity(&self, len: usize, key: &[u8]) -> bool {
        self.bytes
            .get(..len)
            .and_then(wire::Message::parse)
            .is_some_and(|m| m.verify(key))
    }
    pub fn channel_number(&self, len: usize) -> i32 {
        self.bytes
            .get(..len)
            .and_then(wire::channel)
            .map_or(-1, |(number, _)| i32::from(number))
    }
    pub fn channel_payload_len(&self, len: usize) -> i32 {
        self.bytes
            .get(..len)
            .and_then(wire::channel)
            .map_or(-1, |(_, data)| data.len() as i32)
    }

    /// Payload is already in the arena at offset four. Writes only its header.
    pub fn frame_channel(&mut self, number: u16, payload_len: usize) -> bool {
        if !(0x4000..=0x4fff).contains(&number) || payload_len > self.bytes.len() - 4 {
            return false;
        }
        self.bytes[..2].copy_from_slice(&number.to_be_bytes());
        self.bytes[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        true
    }
}

/// Operator/client control helper; shared secrets must never enter public clients.
#[wasm_bindgen]
pub fn rest_credential(secret: &[u8], username: &str) -> String {
    auth::credential(secret, username)
}
