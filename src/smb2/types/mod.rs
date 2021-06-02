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

use std::convert::TryFrom;

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

// Conversions

impl TryFrom<u16> for Cipher {
    type Error = ();
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(Cipher::Aes128Ccm),
            0x0002 => Ok(Cipher::Aes128Gcm),
            0x0003 => Ok(Cipher::Aes256Ccm),
            0x0004 => Ok(Cipher::Aes256Gcm),
            _ => Err(()),
        }
    }
}

impl TryFrom<u16> for SigningAlgorithm {
    type Error = ();
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0000 => Ok(SigningAlgorithm::HmacSha256),
            0x0001 => Ok(SigningAlgorithm::AesCmac),
            0x0002 => Ok(SigningAlgorithm::AesGmac),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_types_cipher() {
        assert_eq!(Cipher::try_from(0x0001).ok().unwrap(), Cipher::Aes128Ccm);
        assert_eq!(Cipher::try_from(0x0002).ok().unwrap(), Cipher::Aes128Gcm);
        assert_eq!(Cipher::try_from(0x0003).ok().unwrap(), Cipher::Aes256Ccm);
        assert_eq!(Cipher::try_from(0x0004).ok().unwrap(), Cipher::Aes256Gcm);
        assert!(Cipher::try_from(0xffff).is_err());
    }

    #[test]
    fn test_smb2_types_signing_algo() {
        assert_eq!(
            SigningAlgorithm::try_from(0x0000).ok().unwrap(),
            SigningAlgorithm::HmacSha256
        );
        assert_eq!(
            SigningAlgorithm::try_from(0x0001).ok().unwrap(),
            SigningAlgorithm::AesCmac
        );
        assert_eq!(
            SigningAlgorithm::try_from(0x0002).ok().unwrap(),
            SigningAlgorithm::AesGmac
        );
        assert!(SigningAlgorithm::try_from(0xffff).is_err());
    }
}
