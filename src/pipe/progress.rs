use std::cmp::min;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use bytes::{BufMut, BytesMut};

use crate::pipe::{DEFAULT_BUF_SIZE, prelude::*};

pub struct ProgressPipe {
    /// The current progress.
    // TODO: use state types in `reporter`?
    cur: u64,

    /// The total pipe length, being the maximum possible progress.
    // TODO: use state types in `reporter`?
    len: u64,

    /// A reporter, to report the progress status to.
    // TODO: do not make this optional, optionally use this pipe instead
    reporter: Option<Arc<Mutex<ProgressReporter>>>,
}

impl ProgressPipe {
    /// Construct a new progress reporting pipe.
    pub fn new(cur: u64, len: u64, reporter: Option<Arc<Mutex<ProgressReporter>>>) -> Self {
        Self {
            cur,
            len,
            reporter,
        }
    }

    /// Construct a new progress reporting pipe.
    pub fn zero(len: u64, reporter: Option<Arc<Mutex<ProgressReporter>>>) -> Self {
        Self::new(0, len, reporter)
    }
}

impl Pipe for ProgressPipe {
    type Reader = ProgressReader;
    type Writer = ProgressWriter;

    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Transparently pipe the data
        let (len, data) = self.pipe_transparent(input);

        // Update current progress and reporter
        self.cur = min(self.cur + len as u64, self.len);
        if let Some(reporter) = self.reporter.as_mut() {
            let progress = self.cur;
            let _ = reporter.lock().map(|mut r| r.progress(progress));
        }

        (len, data)
    }
}

pub struct ProgressReader {
    pipe: ProgressPipe,
    inner: Box<dyn Read>,
    buf: BytesMut,
}

pub struct ProgressWriter {
    pipe: ProgressPipe,
    inner: Box<dyn Write>,
}

impl PipeRead<ProgressPipe> for ProgressReader {
    fn new(pipe: ProgressPipe, inner: Box<dyn Read>) -> Self {
        Self {
            pipe,
            inner,
            buf: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
        }
    }
}

impl PipeWrite<ProgressPipe> for ProgressWriter {
    fn new(pipe: ProgressPipe, inner: Box<dyn Write>) -> Self {
        Self {
            pipe,
            inner,
        }
    }
}

impl Read for ProgressReader {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        // Attempt to fill input buffer if has capacity upto default buffer size and output length
        let capacity = min(DEFAULT_BUF_SIZE, buf.len()) - self.buf.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf.extend_from_slice(&inner_buf[..read]);

            // If nothing is read, return the same
            if read == 0 {
                return Ok(0);
            }
        }

        // Move input buffer into the pipe
        let (read, out) = self.pipe.pipe(&self.buf);
        self.buf.split_to(read);

        // Number of bytes written to given buffer
        let mut total = 0;

        // Write any pipe output to given buffer and remaining to output buffer
        if let Some(out) = out {
            // Copy as much data as possible from pipe output to read buffer
            let write = min(out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&out[..write]);

            // Assert there are no unwritten output bytes
            assert_eq!(write, out.len(), "failed to write all pipe output bytes to output buffer");

            // TODO: is this still valid?
            // Return if given buffer is full, or slice to unwritten buffer
            if write == buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Try again with remaining given buffer
        self.read(buf).map(|n| n + total)
    }
}

impl Write for ProgressWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Transform input data through crypter, write result to inner writer
        let (read, data) = self.pipe.pipe(buf);
        if let Some(data) = data {
            self.inner.write_all(&data)?;
        }

        Ok(read)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl PipeLen for ProgressReader {
    fn len_in(&self) -> usize {
        self.pipe.len as usize
    }

    fn len_out(&self) -> usize {
        self.pipe.len as usize
    }
}

impl PipeLen for ProgressWriter {
    fn len_in(&self) -> usize {
        self.pipe.len as usize
    }

    fn len_out(&self) -> usize {
        self.pipe.len as usize
    }
}

/// A progress reporter.
pub trait ProgressReporter: Send {
    /// Start the progress with the given total.
    fn start(&mut self, total: u64);

    /// A progress update.
    fn progress(&mut self, progress: u64);

    /// Finish the progress.
    fn finish(&mut self);
}
