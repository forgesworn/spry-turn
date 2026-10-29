//! A thin JNI shim over the C ABI's internals, for
//! `dev.forgesworn.spry.SpryRelayNative`:
//!
//! ```kotlin
//! package dev.forgesworn.spry
//!
//! object SpryRelayNative {
//!     init { System.loadLibrary("spry_relay") }
//!     @JvmStatic external fun abiVersion(): Int
//!     @JvmStatic external fun start(args: Array<String>, environment: Array<String>): Long
//!     @JvmStatic external fun nextLine(handle: Long, timeoutMillis: Int): ByteArray?
//!     @JvmStatic external fun stop(handle: Long): Int
//!     @JvmStatic external fun exitCode(handle: Long): Int
//!     @JvmStatic external fun free(handle: Long): Int
//! }
//! ```
//!
//! Written by hand against the JNI function table, with no binding crate.
//! Only the table entries below are used; their indices are fixed by the JNI
//! specification and checked against `jni.h` (see `docs/embedding.md`).
//! Each function returns a plain value and never throws; the Kotlin class
//! wraps them. See `docs/embedding.md` for the rules a caller follows.
use crate::capi::{
    Next, SPRY_RELAY_ABI_VERSION, SPRY_RELAY_ERR_ARGUMENT, SPRY_RELAY_MAX_ARGS,
    SPRY_RELAY_MAX_SETTINGS, SPRY_RELAY_OK, SpryRelay, guard,
};
use std::{
    ffi::{c_char, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    time::Duration,
};

/// `JNIEnv *`: a pointer to the pointer to the function table.
type Env = *mut *const *const c_void;
type Object = *mut c_void;
type Jint = i32;
type Jlong = i64;
type Jboolean = u8;

// Indices into `struct JNINativeInterface` (JNI specification, "Interface
// Function Table"; the first four entries are reserved).
const DELETE_LOCAL_REF: usize = 23;
const GET_STRING_UTF_LENGTH: usize = 168;
const GET_STRING_UTF_CHARS: usize = 169;
const RELEASE_STRING_UTF_CHARS: usize = 170;
const GET_ARRAY_LENGTH: usize = 171;
const GET_OBJECT_ARRAY_ELEMENT: usize = 173;
const NEW_BYTE_ARRAY: usize = 176;
const SET_BYTE_ARRAY_REGION: usize = 208;
const EXCEPTION_CHECK: usize = 228;

/// The table entry at `index`, as a raw pointer.
///
/// # Safety
///
/// `env` is the `JNIEnv *` the JVM passed to the current native call, on
/// the thread it was passed on.
unsafe fn entry(env: Env, index: usize) -> *const c_void {
    // SAFETY: `*env` is the JVM's function table, which has more than
    // `EXCEPTION_CHECK` entries in every JNI version since 1.6.
    unsafe { *(*env).add(index) }
}

macro_rules! call {
    ($env:expr, $index:expr, fn($($arg:ty),*) -> $ret:ty, $($value:expr),*) => {{
        let function: unsafe extern "system" fn(Env, $($arg),*) -> $ret =
            // SAFETY: the entry at this index has exactly this signature in
            // `jni.h`, and `$env` is the current call's environment.
            unsafe { std::mem::transmute(entry($env, $index)) };
        // SAFETY: the arguments are valid for this JNI function, as each
        // call site states.
        unsafe { function($env, $($value),*) }
    }};
}

/// Copy a `String[]` into Rust strings. `None` for a null array, a null
/// element, more than `limit` elements, or text the JVM cannot give as
/// UTF-8 (JNI's modified UTF-8 matches UTF-8 except for NUL and characters
/// outside the Basic Multilingual Plane, which are refused here).
///
/// # Safety
///
/// `env` is the current call's environment and `array` a `String[]` local
/// reference or null.
unsafe fn strings(env: Env, array: Object, limit: usize) -> Option<Vec<String>> {
    if array.is_null() {
        return None;
    }
    let count = call!(env, GET_ARRAY_LENGTH, fn(Object) -> Jint, array);
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count <= limit)?;
    let mut found = Vec::with_capacity(count);
    for index in 0..count {
        // In bounds, so no exception; a null element is refused.
        let element = call!(
            env,
            GET_OBJECT_ARRAY_ELEMENT,
            fn(Object, Jint) -> Object,
            array,
            index as Jint
        );
        if element.is_null() {
            return None;
        }
        let text = call!(
            env,
            GET_STRING_UTF_CHARS,
            fn(Object, *mut Jboolean) -> *const c_char,
            element,
            ptr::null_mut()
        );
        let copied = if text.is_null() {
            None
        } else {
            let length = call!(env, GET_STRING_UTF_LENGTH, fn(Object) -> Jint, element);
            let copied = usize::try_from(length).ok().and_then(|length| {
                // SAFETY: the JVM returned `length` bytes of modified UTF-8
                // at `text`, valid until they are released below.
                let bytes = unsafe { std::slice::from_raw_parts(text.cast::<u8>(), length) };
                std::str::from_utf8(bytes).ok().map(str::to_owned)
            });
            call!(
                env,
                RELEASE_STRING_UTF_CHARS,
                fn(Object, *const c_char) -> (),
                element,
                text
            );
            copied
        };
        call!(env, DELETE_LOCAL_REF, fn(Object) -> (), element);
        found.push(copied?);
    }
    Some(found)
}

/// The handle a `Long` carries, or `None` for 0.
fn relay<'a>(handle: Jlong) -> Option<&'a SpryRelay> {
    let pointer = handle as usize as *const SpryRelay;
    // SAFETY: a non-zero handle is one `start` returned and `free` has not
    // yet consumed, by the documented contract; it is used only through a
    // shared reference, the node and queue being internally synchronised.
    unsafe { pointer.as_ref() }
}

/// `abiVersion(): Int`
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_forgesworn_spry_SpryRelayNative_abiVersion(
    _env: Env,
    _class: Object,
) -> Jint {
    SPRY_RELAY_ABI_VERSION as Jint
}

/// `start(args: Array<String>, environment: Array<String>): Long`: the
/// handle, or 0 if an argument was malformed or the node's thread could not
/// start. A refused setting still returns a handle; the refusal arrives as
/// the `stopped` line.
///
/// # Safety
///
/// Called by the JVM, with its environment and two `String[]` references.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_dev_forgesworn_spry_SpryRelayNative_start(
    env: Env,
    _class: Object,
    args: Object,
    environment: Object,
) -> Jlong {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the JVM's environment and references for this call.
        let args = unsafe { strings(env, args, SPRY_RELAY_MAX_ARGS) };
        // SAFETY: as above.
        let settings = unsafe { strings(env, environment, SPRY_RELAY_MAX_SETTINGS) };
        let (Some(args), Some(settings)) = (args, settings) else {
            return 0;
        };
        SpryRelay::start(args, settings).map_or(0, |relay| Box::into_raw(relay) as usize as Jlong)
    }))
    .unwrap_or(0)
}

/// `nextLine(handle: Long, timeoutMillis: Int): ByteArray?`: the next line
/// as UTF-8; null if none arrived within the timeout (or the array could not
/// be allocated, in which case the line stays queued); an empty array once
/// the node has ended and every line has been read. A negative timeout
/// counts as 0.
///
/// # Safety
///
/// Called by the JVM; `handle` follows the documented contract.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_dev_forgesworn_spry_SpryRelayNative_nextLine(
    env: Env,
    _class: Object,
    handle: Jlong,
    timeout_millis: Jint,
) -> Object {
    catch_unwind(AssertUnwindSafe(|| {
        let empty = || call!(env, NEW_BYTE_ARRAY, fn(Jint) -> Object, 0);
        let Some(relay) = relay(handle) else {
            return empty();
        };
        let timeout = Duration::from_millis(u64::try_from(timeout_millis).unwrap_or(0));
        let mut array = ptr::null_mut();
        let next = relay.next(timeout, |line| {
            let Ok(length) = Jint::try_from(line.len()) else {
                return false;
            };
            let created = call!(env, NEW_BYTE_ARRAY, fn(Jint) -> Object, length);
            if created.is_null() {
                // OutOfMemoryError is pending; the line stays for later.
                return false;
            }
            call!(
                env,
                SET_BYTE_ARRAY_REGION,
                fn(Object, Jint, Jint, *const i8) -> (),
                created,
                0,
                length,
                line.as_ptr().cast::<i8>()
            );
            if call!(env, EXCEPTION_CHECK, fn() -> Jboolean,) != 0 {
                call!(env, DELETE_LOCAL_REF, fn(Object) -> (), created);
                return false;
            }
            array = created;
            true
        });
        match next {
            Next::Line => array,
            Next::Ended => empty(),
            Next::Kept | Next::NoLine => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// `stop(handle: Long): Int`: ask for an orderly stop and return at once.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_forgesworn_spry_SpryRelayNative_stop(
    _env: Env,
    _class: Object,
    handle: Jlong,
) -> Jint {
    guard(|| match relay(handle) {
        Some(relay) => {
            relay.stop();
            SPRY_RELAY_OK
        }
        None => SPRY_RELAY_ERR_ARGUMENT,
    })
}

/// `exitCode(handle: Long): Int`: `-1` while running, else the exit code.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_forgesworn_spry_SpryRelayNative_exitCode(
    _env: Env,
    _class: Object,
    handle: Jlong,
) -> Jint {
    guard(|| relay(handle).map_or(SPRY_RELAY_ERR_ARGUMENT, SpryRelay::exit_code))
}

/// `free(handle: Long): Int`: stop, wait up to seven seconds and free. The
/// handle is invalid afterwards. 0 frees nothing.
///
/// # Safety
///
/// Called by the JVM; `handle` follows the documented contract and no other
/// call is using it or will use it.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_dev_forgesworn_spry_SpryRelayNative_free(
    _env: Env,
    _class: Object,
    handle: Jlong,
) -> Jint {
    let pointer = handle as usize as *mut SpryRelay;
    if pointer.is_null() {
        return SPRY_RELAY_OK;
    }
    guard(|| {
        // SAFETY: the handle came from `Box::into_raw` in `start` and, by
        // contract, nothing else uses it now or later.
        unsafe { *Box::from_raw(pointer) }.free()
    })
}
