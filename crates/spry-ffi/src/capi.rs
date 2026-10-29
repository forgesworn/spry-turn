//! The C ABI. `include/spry_relay.h` is its contract and states the
//! ownership and lifetime of every pointer; keep the two in step.
use spry_service::embedded::{self, CLOSE_SECONDS, Node};
use std::{
    collections::VecDeque,
    ffi::{CStr, c_char},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// `SPRY_RELAY_ABI_VERSION`: raised on any incompatible change.
pub const SPRY_RELAY_ABI_VERSION: u32 = 1;

/// Success; from `spry_relay_next_line`, a line was copied.
pub const SPRY_RELAY_OK: i32 = 0;
/// `spry_relay_next_line`: no line arrived within the timeout.
pub const SPRY_RELAY_NO_LINE: i32 = 1;
/// `spry_relay_next_line`: the node has ended and every line has been read.
pub const SPRY_RELAY_ENDED: i32 = 2;
/// A null pointer, text that is not UTF-8, or too many or too long entries.
pub const SPRY_RELAY_ERR_ARGUMENT: i32 = -1;
/// The buffer is too small for the next line; it stays queued and the
/// length it needs is written to `*length`.
pub const SPRY_RELAY_ERR_BUFFER: i32 = -2;
/// The node's thread could not be started.
pub const SPRY_RELAY_ERR_START: i32 = -3;
/// A panic was caught inside the library. The call had no effect that can
/// be relied on; free the handle.
pub const SPRY_RELAY_ERR_PANIC: i32 = -4;
/// `spry_relay_free`: the node had not ended within its deadline. Its thread
/// finishes on its own; the handle is freed all the same.
pub const SPRY_RELAY_ERR_DETACHED: i32 = -5;
/// `spry_relay_exit_code`: the node is still running.
pub const SPRY_RELAY_RUNNING: i32 = -1;

/// At most this many arguments.
pub const SPRY_RELAY_MAX_ARGS: usize = 256;
/// At most this many `NAME=VALUE` settings.
pub const SPRY_RELAY_MAX_SETTINGS: usize = 16;
/// At most this many bytes in one argument or setting, without its NUL.
pub const SPRY_RELAY_MAX_TEXT: usize = 8192;
/// Unread lines kept for the host. A host that falls this far behind loses
/// the oldest; the last line, `stopped`, is always kept.
pub const SPRY_RELAY_MAX_QUEUED: usize = 1024;

/// A buffer size for `spry_relay_next_line` that comfortably holds the
/// lines the node prints; a longer line is reported with
/// [`SPRY_RELAY_ERR_BUFFER`] and the size it needs.
pub const SPRY_RELAY_LINE_BUFFER: usize = 16384;

/// How often a reader waiting on an empty queue looks to see if the node
/// has ended.
const ENDED_CHECK: Duration = Duration::from_millis(50);

#[derive(Default)]
struct Lines {
    queue: Mutex<VecDeque<String>>,
    arrived: Condvar,
}
impl Lines {
    fn lock(&self) -> MutexGuard<'_, VecDeque<String>> {
        // A panic while the lock was held cannot leave the queue half
        // changed: each operation on it is a single push or pop.
        self.queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn push(&self, line: &str) {
        let mut queue = self.lock();
        if queue.len() >= SPRY_RELAY_MAX_QUEUED {
            queue.pop_front();
        }
        queue.push_back(line.to_owned());
        drop(queue);
        self.arrived.notify_all();
    }
}

/// The opaque handle, `SpryRelay` in C.
pub struct SpryRelay {
    node: Node,
    lines: Arc<Lines>,
}

/// What a reader found.
pub(crate) enum Next {
    /// `take` accepted the line, which has been removed.
    Line,
    /// `take` refused the line, which stays first in the queue.
    Kept,
    NoLine,
    Ended,
}

impl SpryRelay {
    pub(crate) fn start(args: Vec<String>, settings: Vec<String>) -> Result<Box<Self>, i32> {
        if args.len() > SPRY_RELAY_MAX_ARGS || settings.len() > SPRY_RELAY_MAX_SETTINGS {
            return Err(SPRY_RELAY_ERR_ARGUMENT);
        }
        if args
            .iter()
            .chain(&settings)
            .any(|text| text.len() > SPRY_RELAY_MAX_TEXT)
        {
            return Err(SPRY_RELAY_ERR_ARGUMENT);
        }
        let environment = settings
            .into_iter()
            .map(|setting| {
                let (name, value) = setting.split_once('=').ok_or(SPRY_RELAY_ERR_ARGUMENT)?;
                Ok((name.to_owned(), value.to_owned()))
            })
            .collect::<Result<Vec<_>, i32>>()?;
        let lines = Arc::new(Lines::default());
        let sink = lines.clone();
        let node = embedded::start(args, environment, Arc::new(move |line| sink.push(line)))
            .map_err(|_| SPRY_RELAY_ERR_START)?;
        Ok(Box::new(Self { node, lines }))
    }

    /// Hand the oldest unread line to `take`, waiting up to `timeout` for
    /// one. The line is removed only if `take` returns true.
    pub(crate) fn next(&self, timeout: Duration, take: impl FnOnce(&str) -> bool) -> Next {
        let deadline = Instant::now() + timeout;
        let mut queue = self.lines.lock();
        loop {
            if let Some(line) = queue.front() {
                if take(line) {
                    queue.pop_front();
                    return Next::Line;
                }
                return Next::Kept;
            }
            // The `stopped` line is queued before the exit is recorded, so an
            // ended node with an empty queue has nothing more to say.
            if self.node.exit().is_some() {
                return Next::Ended;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Next::NoLine;
            }
            queue = self
                .lines
                .arrived
                .wait_timeout(queue, left.min(ENDED_CHECK))
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }

    pub(crate) fn stop(&self) {
        self.node.stop();
    }

    pub(crate) fn exit_code(&self) -> i32 {
        self.node
            .exit()
            .map_or(SPRY_RELAY_RUNNING, |exit| exit.code)
    }

    pub(crate) fn free(self) -> i32 {
        let Self { node, lines } = self;
        // The node's sink holds its own reference to the queue, so a node
        // left running cannot write into freed memory.
        drop(lines);
        match node.close(Duration::from_secs(CLOSE_SECONDS)) {
            Some(_) => SPRY_RELAY_OK,
            None => SPRY_RELAY_ERR_DETACHED,
        }
    }
}

/// Run `body`, turning a panic into [`SPRY_RELAY_ERR_PANIC`].
pub(crate) fn guard(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(SPRY_RELAY_ERR_PANIC)
}

/// Copy `count` NUL-terminated UTF-8 strings.
///
/// # Safety
///
/// `list` is null with `count` 0, or points to `count` readable pointers,
/// each to a NUL-terminated string that stays valid for this call.
unsafe fn strings(list: *const *const c_char, count: usize) -> Option<Vec<String>> {
    if count == 0 {
        return Some(Vec::new());
    }
    if list.is_null() || count > SPRY_RELAY_MAX_ARGS {
        return None;
    }
    // SAFETY: the caller guarantees `count` readable pointers at `list`;
    // `count` is non-zero and bounded, and `list` is not null.
    let pointers = unsafe { std::slice::from_raw_parts(list, count) };
    pointers
        .iter()
        .map(|&text| {
            if text.is_null() {
                return None;
            }
            // SAFETY: the caller guarantees each pointer is a NUL-terminated
            // string valid for this call; it is not null.
            let text = unsafe { CStr::from_ptr(text) };
            text.to_str().ok().map(str::to_owned)
        })
        .collect()
}

/// Test-only: panics inside the guard and so returns
/// [`SPRY_RELAY_ERR_PANIC`], unless the build aborts on panic.
#[cfg(feature = "panic-probe")]
#[unsafe(no_mangle)]
pub extern "C" fn spry_relay_panic_probe() -> i32 {
    guard(|| panic!("spry_relay_panic_probe"))
}

/// The ABI version this library implements.
#[unsafe(no_mangle)]
pub extern "C" fn spry_relay_abi_version() -> u32 {
    SPRY_RELAY_ABI_VERSION
}

/// Start a node. See `spry_relay.h`.
///
/// # Safety
///
/// `argv` and `envp` follow [`strings`]; `out_relay` is a writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spry_relay_start(
    argv: *const *const c_char,
    argc: usize,
    envp: *const *const c_char,
    envc: usize,
    out_relay: *mut *mut SpryRelay,
) -> i32 {
    guard(|| {
        if out_relay.is_null() {
            return SPRY_RELAY_ERR_ARGUMENT;
        }
        // SAFETY: `out_relay` is writable by contract and not null.
        unsafe { out_relay.write(ptr::null_mut()) };
        if envc > SPRY_RELAY_MAX_SETTINGS {
            return SPRY_RELAY_ERR_ARGUMENT;
        }
        // SAFETY: the caller's lists follow the `strings` contract.
        let (Some(args), Some(settings)) = (unsafe { strings(argv, argc) }, unsafe {
            strings(envp, envc)
        }) else {
            return SPRY_RELAY_ERR_ARGUMENT;
        };
        match SpryRelay::start(args, settings) {
            Ok(relay) => {
                // SAFETY: as above; the caller now owns the handle.
                unsafe { out_relay.write(Box::into_raw(relay)) };
                SPRY_RELAY_OK
            }
            Err(code) => code,
        }
    })
}

/// Copy the next line into `buffer`. See `spry_relay.h`.
///
/// # Safety
///
/// `relay` is a live handle from `spry_relay_start`; `buffer` has
/// `capacity` writable bytes (or is null with `capacity` 0); `length` is a
/// writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spry_relay_next_line(
    relay: *const SpryRelay,
    timeout_ms: u32,
    buffer: *mut u8,
    capacity: usize,
    length: *mut usize,
) -> i32 {
    guard(|| {
        if relay.is_null() || length.is_null() || (buffer.is_null() && capacity != 0) {
            return SPRY_RELAY_ERR_ARGUMENT;
        }
        // SAFETY: a live handle by contract, used only through shared
        // references; the queue and node are internally synchronised.
        let relay = unsafe { &*relay };
        let mut needed = 0;
        let next = relay.next(Duration::from_millis(timeout_ms.into()), |line| {
            needed = line.len();
            if needed > capacity {
                return false;
            }
            // SAFETY: `buffer` has `capacity` writable bytes and the line
            // fits; the two cannot overlap, the line being the library's.
            unsafe { ptr::copy_nonoverlapping(line.as_ptr(), buffer, needed) };
            true
        });
        let (code, written) = match next {
            Next::Line => (SPRY_RELAY_OK, needed),
            Next::Kept => (SPRY_RELAY_ERR_BUFFER, needed),
            Next::NoLine => (SPRY_RELAY_NO_LINE, 0),
            Next::Ended => (SPRY_RELAY_ENDED, 0),
        };
        // SAFETY: `length` is writable by contract and not null.
        unsafe { length.write(written) };
        code
    })
}

/// Ask the node to stop and return at once. See `spry_relay.h`.
///
/// # Safety
///
/// `relay` is a live handle from `spry_relay_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spry_relay_stop(relay: *const SpryRelay) -> i32 {
    guard(|| {
        if relay.is_null() {
            return SPRY_RELAY_ERR_ARGUMENT;
        }
        // SAFETY: a live handle by contract, used through a shared reference.
        unsafe { &*relay }.stop();
        SPRY_RELAY_OK
    })
}

/// The node's exit code, or `SPRY_RELAY_RUNNING`. See `spry_relay.h`.
///
/// # Safety
///
/// `relay` is a live handle from `spry_relay_start`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spry_relay_exit_code(relay: *const SpryRelay) -> i32 {
    guard(|| {
        if relay.is_null() {
            return SPRY_RELAY_ERR_ARGUMENT;
        }
        // SAFETY: a live handle by contract, used through a shared reference.
        unsafe { &*relay }.exit_code()
    })
}

/// Stop the node, wait for it and free the handle. See `spry_relay.h`.
///
/// # Safety
///
/// `relay` is null, or a live handle from `spry_relay_start` that no other
/// call is using or will use; it is invalid afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn spry_relay_free(relay: *mut SpryRelay) -> i32 {
    guard(|| {
        if relay.is_null() {
            return SPRY_RELAY_OK;
        }
        // SAFETY: the handle came from `Box::into_raw` in `spry_relay_start`
        // and, by contract, nothing else uses it now or later.
        unsafe { *Box::from_raw(relay) }.free()
    })
}
