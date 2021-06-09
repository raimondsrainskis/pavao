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
    messages::{
        negotiate::{NegotiateRequest, NegotiateResponse},
        Decode, Decoder, Encoder, Response, ResponseData,
    },
    types::{Cipher, Guid, HashAlgorithm, HashOptions, SigningAlgorithm},
    Client, DialectRevision, Error, SmbResult, Socket,
};
use bytes::BytesMut;

/// ## ClientBuilder
///
/// A helper struct to use to setup the SMB2 client
#[derive(Debug)]
pub struct ClientBuilder {
    addr: String,
    ciphers: Vec<Cipher>,
    hash: HashOptions,
    signatures: Vec<SigningAlgorithm>,
    versions: Vec<DialectRevision>, // Selected versions
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            addr: String::from("localhost:445"),
            ciphers: vec![],
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

    // -- hash

    /// ### with_hash_sha512
    ///
    /// Add support for hash with sha512
    pub fn with_hash_sha512(mut self) -> ClientBuilder {
        self.hash.add_algorithm(HashAlgorithm::Sha512);
        self
    }

    // -- signatures

    /// ### with_sign_hmac_sha256
    ///
    /// Add HMAC/SHA256 to hash algorithms
    pub fn with_sign_hmac_sha256(mut self) -> ClientBuilder {
        self.add_signature(SigningAlgorithm::HmacSha256);
        self
    }
    /// ### with_sign_aes_cmac
    ///
    /// Add AES/CMAC to hash algorithms
    pub fn with_sign_aes_cmac(mut self) -> ClientBuilder {
        self.add_signature(SigningAlgorithm::AesCmac);
        self
    }

    /// ### with_sign_aes_gmac
    ///
    /// Add AES/GMAC to hash algorithms
    pub fn with_sign_aes_gmac(mut self) -> ClientBuilder {
        self.add_signature(SigningAlgorithm::AesGmac);
        self
    }

    // -- dialects

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

    // -- connect

    /// ### connect
    ///
    /// Finalize builder and connect to remote
    pub async fn connect(mut self) -> SmbResult<Client> {
        // Prepare message
        let negotiate: NegotiateRequest = NegotiateRequest::new(
            self.versions,
            Guid::new(),
            self.hash,
            self.ciphers,
            self.signatures,
        );
        let payload = Encoder::default().encode_negotiate(negotiate).await;
        // Create socket and connect
        let mut socket: Socket = Socket::connect(self.addr.as_str())
            .await
            .map_err(|x| Error::IoError(x))?;
        // Write bytes
        socket.send(&payload).await.map_err(|x| Error::IoError(x))?;
        // Wait for response
        let mut response: vec![0; 65536];
        socket
            .recv(&mut response)
            .await
            .map_err(|x| Error::IoError(x))?;
        // Parse response
        let response: Response = Decoder::default()
            .decode(&mut BytesMut::from(response))
            .await?;
        match response.data {
            ResponseData::Ok(buff) => {
                // TODO: build client
                let response: NegotiateResponse = NegotiateResponse::decode(&mut buff)?;
            }
            ResponseData::Err(_) => Err(Error::CommandError(response.header.status)),
        }
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

    /// ### add_signature
    ///
    /// Push signature to supported algorithms
    fn add_signature(&mut self, v: SigningAlgorithm) {
        if !self.signatures.contains(&v) {
            self.signatures.push(v);
        }
    }
}
