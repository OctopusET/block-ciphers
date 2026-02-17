//! Pure Rust implementation of the [LEA] block cipher ([KS X 3246]).
//!
//! LEA (Lightweight Encryption Algorithm) is a 128-bit block cipher using only
//! 32-bit Addition, Rotation, and XOR (ARX) operations. It supports three key
//! sizes: 128, 192, and 256 bits with 24, 28, and 32 rounds respectively.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate implements only the low-level block cipher function, and is intended
//! for use for implementing higher-level constructions *only*. It is NOT
//! intended for direct use in applications.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Examples
//! ```
//! use lea::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
//! use lea::Lea128;
//!
//! let key = Array::from([0u8; 16]);
//! let mut block = Array::from([0u8; 16]);
//! // Initialize cipher
//! let cipher = Lea128::new(&key);
//!
//! let block_copy = block.clone();
//! // Encrypt block in-place
//! cipher.encrypt_block(&mut block);
//! // And decrypt it back
//! cipher.decrypt_block(&mut block);
//! assert_eq!(block, block_copy);
//! ```
//!
//! [LEA]: https://en.wikipedia.org/wiki/LEA_(cipher)
//! [KS X 3246]: https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/26acc39f/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser,
    Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
    consts::{U1, U16, U24, U32},
    inout::InOut,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Delta constants derived from the fractional part of sqrt(766995),
/// where 76/69/95 = 'L','E','A' in ASCII.
const DELTA: [u32; 8] = [
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957,
];

/// A single round key: 6 words.
type RoundKey = [u32; 6];

/// Generic LEA block cipher.
///
/// `NR` is the number of rounds: 24 (LEA-128), 28 (LEA-192), or 32 (LEA-256).
#[derive(Clone)]
pub struct Lea<const NR: usize> {
    /// Round keys.
    rk: [RoundKey; NR],
}

impl<const NR: usize> BlockSizeUser for Lea<NR> {
    type BlockSize = U16;
}

impl<const NR: usize> ParBlocksSizeUser for Lea<NR> {
    type ParBlocksSize = U1;
}

// -- Encryption --

impl<const NR: usize> BlockCipherEncrypt for Lea<NR> {
    #[inline]
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<const NR: usize> BlockCipherEncBackend for Lea<NR> {
    #[inline]
    fn encrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut x = [
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            u32::from_le_bytes(b[8..12].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
        ];

        for rk in &self.rk {
            let tmp0 = (x[0] ^ rk[0]).wrapping_add(x[1] ^ rk[1]).rotate_left(9);
            let tmp1 = (x[1] ^ rk[2]).wrapping_add(x[2] ^ rk[3]).rotate_right(5);
            let tmp2 = (x[2] ^ rk[4]).wrapping_add(x[3] ^ rk[5]).rotate_right(3);
            x = [tmp0, tmp1, tmp2, x[0]];
        }

        let out = block.get_out();
        out[0..4].copy_from_slice(&x[0].to_le_bytes());
        out[4..8].copy_from_slice(&x[1].to_le_bytes());
        out[8..12].copy_from_slice(&x[2].to_le_bytes());
        out[12..16].copy_from_slice(&x[3].to_le_bytes());
    }
}

// -- Decryption --

impl<const NR: usize> BlockCipherDecrypt for Lea<NR> {
    #[inline]
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        f.call(self)
    }
}

impl<const NR: usize> BlockCipherDecBackend for Lea<NR> {
    #[inline]
    fn decrypt_block(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let b = block.get_in();
        let mut x = [
            u32::from_le_bytes(b[0..4].try_into().unwrap()),
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            u32::from_le_bytes(b[8..12].try_into().unwrap()),
            u32::from_le_bytes(b[12..16].try_into().unwrap()),
        ];

        for rk in self.rk.iter().rev() {
            let tmp0 = x[3];
            let tmp1 = x[0].rotate_right(9).wrapping_sub(tmp0 ^ rk[0]) ^ rk[1];
            let tmp2 = x[1].rotate_left(5).wrapping_sub(tmp1 ^ rk[2]) ^ rk[3];
            let tmp3 = x[2].rotate_left(3).wrapping_sub(tmp2 ^ rk[4]) ^ rk[5];
            x = [tmp0, tmp1, tmp2, tmp3];
        }

        let out = block.get_out();
        out[0..4].copy_from_slice(&x[0].to_le_bytes());
        out[4..8].copy_from_slice(&x[1].to_le_bytes());
        out[8..12].copy_from_slice(&x[2].to_le_bytes());
        out[12..16].copy_from_slice(&x[3].to_le_bytes());
    }
}

// -- Drop / Zeroize --

impl<const NR: usize> Drop for Lea<NR> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.rk.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<const NR: usize> ZeroizeOnDrop for Lea<NR> {}

// -- LEA-128 --

/// LEA-128 block cipher instance.
pub type Lea128 = Lea<24>;

impl KeySizeUser for Lea128 {
    type KeySize = U16;
}

impl KeyInit for Lea128 {
    fn new(key: &Key<Self>) -> Self {
        let mut t = [0u32; 4];
        for i in 0..4 {
            t[i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        let mut rk = [[0u32; 6]; 24];
        for i in 0..24u32 {
            let d = DELTA[(i % 4) as usize];
            t[0] = t[0].wrapping_add(d.rotate_left(i)).rotate_left(1);
            t[1] = t[1].wrapping_add(d.rotate_left(i + 1)).rotate_left(3);
            t[2] = t[2].wrapping_add(d.rotate_left(i + 2)).rotate_left(6);
            t[3] = t[3].wrapping_add(d.rotate_left(i + 3)).rotate_left(11);
            rk[i as usize] = [t[0], t[1], t[2], t[1], t[3], t[1]];
        }

        Self { rk }
    }
}

impl fmt::Debug for Lea128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lea128 { ... }")
    }
}

impl cipher::AlgorithmName for Lea128 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lea128")
    }
}

// -- LEA-192 --

/// LEA-192 block cipher instance.
pub type Lea192 = Lea<28>;

impl KeySizeUser for Lea192 {
    type KeySize = U24;
}

impl KeyInit for Lea192 {
    fn new(key: &Key<Self>) -> Self {
        let mut t = [0u32; 6];
        for i in 0..6 {
            t[i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        let mut rk = [[0u32; 6]; 28];
        for i in 0..28u32 {
            let d = DELTA[(i % 6) as usize];
            t[0] = t[0].wrapping_add(d.rotate_left(i)).rotate_left(1);
            t[1] = t[1].wrapping_add(d.rotate_left(i + 1)).rotate_left(3);
            t[2] = t[2].wrapping_add(d.rotate_left(i + 2)).rotate_left(6);
            t[3] = t[3].wrapping_add(d.rotate_left(i + 3)).rotate_left(11);
            t[4] = t[4].wrapping_add(d.rotate_left(i + 4)).rotate_left(13);
            t[5] = t[5].wrapping_add(d.rotate_left(i + 5)).rotate_left(17);
            rk[i as usize] = [t[0], t[1], t[2], t[3], t[4], t[5]];
        }

        Self { rk }
    }
}

impl fmt::Debug for Lea192 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lea192 { ... }")
    }
}

impl cipher::AlgorithmName for Lea192 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lea192")
    }
}

// -- LEA-256 --

/// LEA-256 block cipher instance.
pub type Lea256 = Lea<32>;

impl KeySizeUser for Lea256 {
    type KeySize = U32;
}

impl KeyInit for Lea256 {
    fn new(key: &Key<Self>) -> Self {
        let mut t = [0u32; 8];
        for i in 0..8 {
            t[i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        let mut rk = [[0u32; 6]; 32];
        for i in 0..32u32 {
            let d = DELTA[(i % 8) as usize];
            let base = (6u32.wrapping_mul(i)) as usize;
            t[base % 8] = t[base % 8].wrapping_add(d.rotate_left(i)).rotate_left(1);
            t[(base + 1) % 8] = t[(base + 1) % 8].wrapping_add(d.rotate_left(i + 1)).rotate_left(3);
            t[(base + 2) % 8] = t[(base + 2) % 8].wrapping_add(d.rotate_left(i + 2)).rotate_left(6);
            t[(base + 3) % 8] = t[(base + 3) % 8].wrapping_add(d.rotate_left(i + 3)).rotate_left(11);
            t[(base + 4) % 8] = t[(base + 4) % 8].wrapping_add(d.rotate_left(i + 4)).rotate_left(13);
            t[(base + 5) % 8] = t[(base + 5) % 8].wrapping_add(d.rotate_left(i + 5)).rotate_left(17);
            rk[i as usize] = [
                t[base % 8],
                t[(base + 1) % 8],
                t[(base + 2) % 8],
                t[(base + 3) % 8],
                t[(base + 4) % 8],
                t[(base + 5) % 8],
            ];
        }

        Self { rk }
    }
}

impl fmt::Debug for Lea256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lea256 { ... }")
    }
}

impl cipher::AlgorithmName for Lea256 {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Lea256")
    }
}
