//! # Guid
//!
//! defines data types for client GUID

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
use rand::distributions::{Distribution, Uniform};
use std::convert::TryFrom;

/// ## Guid
///
/// Client GUID
#[derive(Debug)]
pub struct Guid {
    guid: Vec<u8>, // 16 bytes
}

impl Guid {
    /// ### new
    ///
    /// Generates a new Guid
    pub fn new() -> Self {
        // Generate new 16 random bytes
        let mut rng = rand::thread_rng();
        let uniform: Uniform<u8> = Uniform::from(0..255);
        let guid: Vec<u8> = (0..16).map(|_| uniform.sample(&mut rng)).collect();
        Self { guid }
    }

    /// ### data
    ///
    /// Get guid data
    pub fn data(&self) -> &[u8] {
        self.guid.as_slice()
    }
}

impl TryFrom<Vec<u8>> for Guid {
    type Error = &'static str;

    fn try_from(guid: Vec<u8>) -> Result<Self, Self::Error> {
        match guid.len() {
            16 => Ok(Self { guid }),
            _ => Err("Invalid guid length"),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_types_guid() {
        let guid: Guid = Guid::new();
        assert_eq!(guid.guid.len(), 16);
        let guid: Vec<u8> = vec![
            0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0xa1, 0x1a, 0x10, 0x03, 0xba, 0x71, 0x0f,
            0xed, 0x00,
        ];
        let guid: Guid = Guid::try_from(guid).ok().unwrap();
        assert_eq!(
            guid.data(),
            &[
                0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0xa1, 0x1a, 0x10, 0x03, 0xba, 0x71, 0x0f,
                0xed, 0x00
            ]
        );
        assert!(Guid::try_from(vec![0; 5]).is_err());
    }
}
