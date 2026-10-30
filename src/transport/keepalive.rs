//! Zero-overhead keepalive frame (`[kind, nonce_be64]`) shared across transports.
//! Each transport assigns its own `kind` values.

/// Type byte + 8-byte big-endian nonce.
pub const LEN: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keepalive {
    pub kind: u8,
    pub nonce: [u8; 8],
}

impl Keepalive {
    #[inline(always)]
    pub const fn new(kind: u8, nonce: [u8; 8]) -> Self {
        Self { kind, nonce }
    }

    #[inline(always)]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let (&[kind], rest) = payload.split_first_chunk::<1>()?;
        let nonce: [u8; 8] = rest.try_into().ok()?;
        Some(Self { kind, nonce })
    }

    #[inline(always)]
    pub fn encode(self) -> [u8; LEN] {
        let mut out = [0u8; LEN];
        out[0] = self.kind;
        out[1..].copy_from_slice(&self.nonce);
        out
    }
}
