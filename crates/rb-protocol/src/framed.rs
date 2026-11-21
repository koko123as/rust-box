//! Helpers shared by the protocols that carry UDP packets, or several
//! streams, inside one TCP stream (trojan, vless).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Room read ahead of the current frame, at most, per read.
const READ_CHUNK: usize = 16 * 1024;

/// A reader that keeps bytes read past the current frame, so reading a
/// frame is cancel safe (the router races packet reads against timeouts):
/// bytes are only taken out once a whole frame is there.
pub struct FrameReader<R> {
    reader: R,
    pending: Vec<u8>,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(reader: R) -> Self {
        FrameReader { reader, pending: Vec::new() }
    }

    /// The next frame: `parse` gets the bytes read so far and returns the
    /// frame and how many bytes it took, or `None` while it is incomplete.
    /// The end of the stream before a whole frame is an `UnexpectedEof`.
    pub async fn next<T>(&mut self, mut parse: impl FnMut(&[u8]) -> io::Result<Option<(T, usize)>>) -> io::Result<T> {
        loop {
            if let Some((frame, used)) = parse(&self.pending)? {
                self.pending.drain(..used);
                return Ok(frame);
            }
            self.pending.reserve(READ_CHUNK);
            if self.reader.read_buf(&mut self.pending).await? == 0 {
                return Err(eof());
            }
        }
    }

    /// Exactly `length` bytes (cancel safe as [`FrameReader::next`]).
    pub async fn read_exact(&mut self, length: usize) -> io::Result<Vec<u8>> {
        self.next(|data| Ok((data.len() >= length).then(|| (data[..length].to_vec(), length)))).await
    }
}

/// Go's `io.EOF`, which sing's errors print as "EOF".
pub fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

/// The big-endian `u16` at `offset`, if `data` is long enough.
pub fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2).map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// sing `E.IsClosedOrCanceled` for a handshake: the client went away.
pub fn is_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

/// Prefixes an error with sing's `E.Cause` text.
pub fn cause(error: io::Error, message: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{message}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_survive_partial_reads() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut reader = FrameReader::new(server);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for byte in [3u8, b'a', b'b', b'c', 1, b'x'] {
                client.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let parse = |data: &[u8]| -> io::Result<Option<(Vec<u8>, usize)>> {
            let Some(&length) = data.first() else { return Ok(None) };
            let end = 1 + length as usize;
            Ok((data.len() >= end).then(|| (data[1..end].to_vec(), end)))
        };
        assert_eq!(reader.next(parse).await.unwrap(), b"abc");
        assert_eq!(reader.next(parse).await.unwrap(), b"x");
        assert_eq!(reader.next(parse).await.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }
}
