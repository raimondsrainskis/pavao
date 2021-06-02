//! # hash
//!
//! exposes hash types for smb

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

/// ## HashOptions
///
/// Hash options for client
#[derive(Debug)]
pub struct HashOptions {
    algorithms: Vec<HashAlgorithm>,
    salt: Salt,
}

impl HashOptions {
    /// ### new
    ///
    /// Instantiates a new `HashOptions`
    pub fn new() -> Self {
        Self {
            algorithms: vec![],
            salt: Salt::new(),
        }
    }

    /// ### add_algorithm
    ///
    /// Add new `HashAlgorithm` to list
    pub fn add_algorithm(&mut self, algo: HashAlgorithm) {
        if !self.algorithms.contains(&algo) {
            self.algorithms.push(algo);
        }
    }

    /// ### algorithms
    ///
    /// Get algorithms
    pub fn algorithms(&self) -> &[HashAlgorithm] {
        self.algorithms.as_slice()
    }

    /// ### salt
    ///
    /// Get salt
    pub fn salt(&self) -> &Salt {
        &self.salt
    }
}

/// ## HashAlgorithm
///
/// hash algorithms supported by SMB2/3
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum HashAlgorithm {
    Sha512 = 0x0001,
}

impl TryFrom<u16> for HashAlgorithm {
    type Error = &'static str;
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(HashAlgorithm::Sha512),
            _ => Err("Invalid hash algorithm"),
        }
    }
}

/// ## Salt
///
/// Hash salt
#[derive(Clone, Debug)]
pub struct Salt {
    salt: Vec<u8>, // 32 bytes
}

impl Salt {
    /// ### new
    ///
    /// Generates a new Salt
    pub fn new() -> Self {
        // Generate new 32 random bytes
        let mut rng = rand::thread_rng();
        let uniform: Uniform<u8> = Uniform::from(0..255);
        let salt: Vec<u8> = (0..32).map(|_| uniform.sample(&mut rng)).collect();
        Self { salt }
    }

    /// ### data
    ///
    /// Get salt data
    pub fn data(&self) -> &[u8] {
        self.salt.as_slice()
    }
}

impl From<Vec<u8>> for Salt {
    fn from(salt: Vec<u8>) -> Self {
        Salt { salt }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn test_smb2_types_salt() {
        let salt: Salt = Salt::new();
        assert_eq!(salt.data().len(), 32);
        let salt: Vec<u8> = vec![0xca, 0xfe];
        let salt: Salt = Salt::from(salt);
        assert_eq!(salt.data().to_vec(), vec![0xca, 0xfe]);
    }

    #[test]
    fn test_smb2_types_hash() {
        let mut opts: HashOptions = HashOptions::new();
        assert_eq!(opts.algorithms().len(), 0);
        assert_eq!(opts.salt().data().len(), 32);
        opts.add_algorithm(HashAlgorithm::Sha512);
        assert_eq!(opts.algorithms().len(), 1);
        // Add double
        opts.add_algorithm(HashAlgorithm::Sha512);
        assert_eq!(opts.algorithms().len(), 1);
        assert_eq!(
            HashAlgorithm::try_from(0x0001).ok().unwrap(),
            HashAlgorithm::Sha512
        );
        assert!(HashAlgorithm::try_from(0xffff).is_err());
    }
}
