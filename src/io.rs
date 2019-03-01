use std::io::{self, Read};

/// An iterator over chunks of an instance of `Read`.
///
/// This struct is generally created by calling [`chunks`][chunks] on a
/// type implementing the `Read` trait.
///
/// This iterator is similar to [`slice::chunks`](slice::chunks) but yields chunks from a reader.
pub struct Chunks<R> {
    /// The inner reader to read chunks from.
    reader: R,

    /// The chunk size.
    size: usize,
}

impl<R: Read> Chunks<R> {
    /// Construct a new chunked iterator over the given reader `reader`.
    ///
    /// # Panics
    ///
    /// Panics if the given `size` is zero.
    pub fn from(reader: R, size: usize) -> Self {
        assert_ne!(size, 0, "chunk size cannot be zero");
        Self { reader, size }
    }
}

impl<B: Read> Iterator for Chunks<B> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Allocate a chunk buffer and read index
        let mut chunk = vec![0; self.size];
        let mut read = 0;

        // Attempt to keep reading until stream ends or buffer is full
        while read < self.size {
            match self.reader.read(&mut chunk[read..]) {
                // Yield buffer if nothing could be read
                Ok(0) => break,

                // Increase read counter, continue reading
                Ok(r) => read += r,

                // Yield errors
                Err(e) => return Some(Err(e)),
            }
        }

        // Truncate buffer to read section, return none if nothing was read
        if read > 0 {
            chunk.truncate(read);
            Some(Ok(chunk))
        } else {
            None
        }
    }
}

/// Chunk iterator implementation for readers.
pub trait ChunkRead
where
    Self: Read + Sized,
{
    /// Returns an iterator over chunks of this reader.
    ///
    /// The preferred `size` of the chunks must be specified.
    ///
    /// This behaves similar to [`slice::chunks`](slice::chunks) but yields chunks from a reader.
    fn chunks(self, size: usize) -> Chunks<Self> {
        Chunks::from(self, size)
    }
}

impl<R: Read> ChunkRead for R {}
