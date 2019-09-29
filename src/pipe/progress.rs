use std::cmp::min;
use std::sync::{Arc, Mutex};

use crate::pipe::{prelude::*, PipeReader, PipeWriter};

pub struct ProgressPipe {
    /// The current progress.
    // TODO: use state types in `reporter`?
    cur: u64,

    /// The total pipe length, being the maximum possible progress.
    // TODO: use state types in `reporter`?
    len: u64,

    /// A reporter, to report the progress status to.
    // TODO: do not make this optional, optionally use this pipe instead
    reporter: Option<Arc<Mutex<dyn ProgressReporter>>>,
}

impl ProgressPipe {
    /// Construct a new progress reporting pipe.
    pub fn new(cur: u64, len: u64, reporter: Option<Arc<Mutex<dyn ProgressReporter>>>) -> Self {
        Self { cur, len, reporter }
    }

    /// Construct a new progress reporting pipe.
    pub fn zero(len: u64, reporter: Option<Arc<Mutex<dyn ProgressReporter>>>) -> Self {
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

pub type ProgressReader = PipeReader<ProgressPipe>;
pub type ProgressWriter = PipeWriter<ProgressPipe>;

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
