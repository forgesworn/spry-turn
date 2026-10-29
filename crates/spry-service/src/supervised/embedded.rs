//! Supervised standard mode inside a host application's own process.
//!
//! The same node as `spry-node supervised`, for a host that cannot or should
//! not start a child process (the Android app). It takes the same options,
//! except `--exit-on-stdin-close`, and the same five settings as name and
//! value pairs instead of the process environment. Lines that the child
//! process would print on stdout go to the host's [`Sink`], one JSON object
//! per call, followed by a last `stopped` line. [`Node::stop`] replaces
//! closing stdin: the relay stops, its router mappings are removed and the
//! node ends. No signal handler is installed and the process is never ended.
//! See `docs/embedding.md`.
use super::{Environment, Host, Lifetime, Output, STOP_SECONDS, exit_of, run, runtime};
use serde_json::json;
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};

/// Receives each line the node prints, as one JSON object without a line
/// ending. Called from the node's own threads, one line at a time and in
/// order; it should return quickly and must not call back into the node.
pub type Sink = Arc<dyn Fn(&str) + Send + Sync>;

/// How a node ended: the exit code `spry-node supervised` would have used,
/// and the refusal it would have printed, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    /// `0` after a stop, `1` for a refusal or failure, `3` when the router
    /// could not host (`portmap failed` or `portmap lost` came first).
    pub code: i32,
    /// The refusal, which names a setting and never carries its value.
    pub refusal: Option<String>,
}

/// Seconds [`Node`]'s drop and [`Node::close`] wait by default for an
/// orderly stop: the node's own bound for removing router mappings, and two
/// more for the relay and the control channel to close.
pub const CLOSE_SECONDS: u64 = STOP_SECONDS + 2;

#[derive(Default)]
struct Done {
    exit: Mutex<Option<Exit>>,
    changed: Condvar,
}

/// A running node. Dropping it stops the node and waits up to
/// [`CLOSE_SECONDS`] for it to end.
pub struct Node {
    lifetime: Arc<Lifetime>,
    done: Arc<Done>,
    thread: Option<thread::JoinHandle<()>>,
}

/// Start a node on its own thread. Settings are checked on that thread, so a
/// refusal arrives as the `stopped` line (`code` 1 and `refusal`), exactly
/// as the child process would print it on stderr and exit. An error here
/// means only that the thread could not be started.
pub fn start(
    args: Vec<String>,
    environment: Vec<(String, String)>,
    sink: Sink,
) -> io::Result<Node> {
    let lifetime = Arc::new(Lifetime::default());
    let done = Arc::new(Done::default());
    let (stopping, finished) = (lifetime.clone(), done.clone());
    let thread = thread::Builder::new()
        .name("spry-supervised".into())
        .spawn(move || {
            let out = Output(sink);
            let ran = catch_unwind(AssertUnwindSafe(|| {
                let runtime = runtime()?;
                let result = runtime.block_on(run(
                    &args,
                    Environment::from_pairs(&environment),
                    Host::Embedded,
                    &out,
                    stopping,
                ));
                runtime.shutdown_timeout(Duration::from_secs(1));
                result
            }));
            let (code, refusal) = ran.map_or((1, None), exit_of);
            let mut line = json!({"v":1,"event":"stopped","code":code});
            if let Some(refusal) = &refusal {
                line["refusal"] = refusal.as_str().into();
            }
            let _ = catch_unwind(AssertUnwindSafe(|| out.line(line)));
            if let Ok(mut exit) = finished.exit.lock() {
                *exit = Some(Exit { code, refusal });
            }
            finished.changed.notify_all();
        })?;
    Ok(Node {
        lifetime,
        done,
        thread: Some(thread),
    })
}

impl Node {
    /// Ask for an orderly stop and return at once. The relay stops, then the
    /// node's router mappings are removed (within [`STOP_SECONDS`]), the
    /// last lines arrive and the node ends. Calling it again does nothing.
    pub fn stop(&self) {
        self.lifetime.close();
    }
    /// How the node ended, or `None` while it runs.
    pub fn exit(&self) -> Option<Exit> {
        self.done.exit.lock().ok()?.clone()
    }
    /// Wait up to `timeout` for the node to end.
    pub fn wait(&self, timeout: Duration) -> Option<Exit> {
        let deadline = Instant::now() + timeout;
        let mut exit = self.done.exit.lock().ok()?;
        while exit.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            exit = self.done.changed.wait_timeout(exit, left).ok()?.0;
        }
        exit.clone()
    }
    /// Stop the node and wait up to `timeout` for it to end. `None` means it
    /// had not ended: its thread is left to finish on its own, holding what
    /// it still holds, and nothing it owns is freed early.
    pub fn close(mut self, timeout: Duration) -> Option<Exit> {
        self.finish(timeout)
    }
    fn finish(&mut self, timeout: Duration) -> Option<Exit> {
        self.stop();
        let exit = self.wait(timeout);
        if let Some(thread) = self.thread.take() {
            if exit.is_some() {
                let _ = thread.join();
            }
        }
        exit
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.finish(Duration::from_secs(CLOSE_SECONDS));
        }
    }
}
