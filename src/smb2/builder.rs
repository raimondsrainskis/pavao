//! # builder
//!
//! provides a Client builder to simplify the setup of the client

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
use super::{
    types::{Cipher, Guid, HashAlgorithm, HashOptions, SigningAlgorithm},
    Client, DialectRevision, Error, SmbResult,
};

/// ## ClientBuilder
///
/// A helper struct to use to setup the SMB2 client
#[derive(Debug)]
pub struct ClientBuilder {
    addr: String,
    ciphers: Vec<Cipher>,
    guid: Guid,
    hash: HashOptions,
    signatures: Vec<SigningAlgorithm>,
    versions: Vec<DialectRevision>, // Selected versions
}

// TODO: methods (setters + connect)

// TODO: default

// TODO: connect -> SmbResult<Client>

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            addr: String::from("localhost:445"),
            ciphers: vec![],
            guid: Guid::new(),
            hash: HashOptions::new(),
            signatures: vec![],
            versions: vec![],
        }
    }
}

impl ClientBuilder {
    /// ### with_addr
    ///
    /// Specify remote address for connection
    pub fn with_addr(mut self, addr: String) -> ClientBuilder {
        self.addr = addr;
        self
    }

    /// ### with_hash_sha512
    ///
    /// Add support for hash with sha512
    pub fn with_hash_sha512(mut self) -> ClientBuilder {
        self.hash.add_algorithm(HashAlgorithm::Sha512);
        self
    }

    /// ### with_smb_all
    ///
    /// Enables all SMB2/3 dialects
    pub fn with_smb_all(mut self) -> ClientBuilder {
        self = self.with_smb_v2();
        self = self.with_smb_v3();
        self
    }

    /// ### with_smb_v2
    ///
    /// Enables all SMB2 versions
    pub fn with_smb_v2(mut self) -> ClientBuilder {
        self = self.with_smb_v202();
        self = self.with_smb_v210();
        self
    }

    /// ### with_smb_v3
    ///
    /// Enables all SMB3 versions
    pub fn with_smb_v3(mut self) -> ClientBuilder {
        self = self.with_smb_v300();
        self = self.with_smb_v302();
        self = self.with_smb_v311();
        self
    }

    /// ### with_smb_v202
    ///
    /// Enables smb2.02
    pub fn with_smb_v202(mut self) -> ClientBuilder {
        self.add_version(DialectRevision::V202);
        self
    }

    /// ### with_smb_v202
    ///
    /// Enables smb2.10
    pub fn with_smb_v210(mut self) -> ClientBuilder {
        self.add_version(DialectRevision::V210);
        self
    }

    /// ### with_smb_v300
    ///
    /// Enables smb3.00
    pub fn with_smb_v300(mut self) -> ClientBuilder {
        self.add_version(DialectRevision::V300);
        self
    }

    /// ### with_smb_v302
    ///
    /// Enables smb3.02
    pub fn with_smb_v302(mut self) -> ClientBuilder {
        self.add_version(DialectRevision::V302);
        self
    }

    /// ### with_smb_v311
    ///
    /// Enables smb3.11
    pub fn with_smb_v311(mut self) -> ClientBuilder {
        self.add_version(DialectRevision::V311);
        self
    }

    /// ### connect
    ///
    /// Finalize builder and connect to remote
    pub fn connect(mut self) -> SmbResult<Client> {
        // TODO: complete
        Err(Error::MissingArg(String::from("all")))
    }

    // -- privates

    /// ### add_version
    ///
    /// Push version to supported versions
    fn add_version(&mut self, v: DialectRevision) {
        if !self.versions.contains(&v) {
            self.versions.push(v);
        }
    }
}
