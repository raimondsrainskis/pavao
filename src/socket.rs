//! # socket
//!
//! a façade for `async_net::TcpStream`

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
// deps
use async_std::net::{Shutdown, TcpStream};
use async_std::prelude::*;
use std::io::Result as IoResult;

/// ## Socket
///
/// A wrapper around the `TcpStream` struct
#[derive(Debug)]
pub struct Socket {
    stream: TcpStream,
}

impl Socket {
    /// ### connect
    ///
    /// Try to connect to remote
    pub async fn connect(addr: &str) -> IoResult<Self> {
        let stream: TcpStream = TcpStream::connect(addr).await?;
        Ok(Socket { stream })
    }

    /// ### disconnect
    ///
    /// Disconnect from remote
    pub async fn disconnect(&self) -> IoResult<()> {
        self.stream.shutdown(Shutdown::Both)
    }

    /// ### send
    ///
    /// Send data to socket
    pub async fn send(&mut self, data: &[u8]) -> IoResult<()> {
        self.stream.write_all(data).await
    }

    /// ### recv
    ///
    /// Receive from socket
    pub async fn recv(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        self.stream.read(buffer).await
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use async_std::net::TcpListener;
    use pretty_assertions::assert_eq;

    #[async_attributes::test]
    async fn test_socket() {
        // Setup a dummy tcp listener
        let host: &str = "127.0.0.1:8470";
        let listener = TcpListener::bind(host).await.ok().unwrap();
        let mut incoming = listener.incoming();
        // Connect client
        let mut socket: Socket = Socket::connect(host).await.ok().unwrap();
        // Write something
        let expected: &[u8] = &[0xca, 0xfe, 0xba, 0xbe, 0x15, 0xde, 0xad, 0x00];
        assert!(socket.send(expected).await.is_ok());
        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(mut stream) => {
                    // Write data back
                    let mut read = vec![0; 1024];
                    match stream.read(&mut read).await {
                        Ok(n) => {
                            if n == 0 {
                                // connection was closed
                                break;
                            }
                            assert_eq!(stream.write(&read[0..n]).await.ok().unwrap(), 8);
                            // Read
                            let mut incoming = vec![0; 1024];
                            assert_eq!(socket.recv(incoming.as_mut_slice()).await.ok().unwrap(), 8);
                            assert_eq!(incoming[0..8], *expected);
                            // Close
                            assert!(socket.disconnect().await.is_ok());
                            break;
                        }
                        Err(err) => {
                            panic!("socket error: {}", err);
                        }
                    }
                }
                Err(err) => {
                    panic!("Socket error: {}", err);
                }
            }
        }
    }
}
