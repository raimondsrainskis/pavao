//! # types
//!
//! exposes some custom data types for SMB2/£

/**
 * MIT License
 *
 * pavao - Copyright (C) 2021 Christian Visintin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
// mods (put here types which requires implementations)
pub mod guid;
pub mod hash;
// exposes
pub use guid::Guid;
pub use hash::{HashAlgorithm, HashOptions, Salt};

// simple types

/// ## Cipher
///
/// SMB2/3 protocol encryption ciphers
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Cipher {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
}

/// ## SigningAlgorithm
///
/// SMB2/3 protocol signing algorithm
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum SigningAlgorithm {
    HmacSha256 = 0x0000,
    AesCmac = 0x0001,
    AesGmac = 0x0002,
}
