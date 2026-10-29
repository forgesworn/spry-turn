# Embedding the relay in an app's own process

[Supervised standard mode](supervised-mode.md) normally runs as a child
process, `spry-node supervised`. Android does not suit a bundled executable,
so the same node is also offered as a native library, `libspry_relay`, with a
hand-written C ABI and a thin JNI shim. The node, its options, its rules and
its output lines are those of the child process; only how it starts, how its
lines arrive and how it stops differ.

Desktop hosts should keep using the `spry-node` executable from the release:
a separate process is easier to sign, hash and kill. The library is for a
host that cannot start one.

## What is in a release

From the first release tagged after this change, the release workflow
(`.github/workflows/release.yml`) attaches:

| Artefact | Contents |
|---|---|
| `spry-turn-<tag>-aarch64-apple-darwin.tar.gz` | `bin/spry-turn` and `bin/spry-node` for macOS on Apple silicon. No Intel build. Ad hoc signed by the linker, not Developer ID signed or notarised; a host app that bundles them signs its own copy. |
| `spry-turn-<tag>-x86_64-pc-windows-msvc.zip` | `bin\spry-turn.exe` and `bin\spry-node.exe`. **Unsigned**: there is no Authenticode signature, so SmartScreen and Defender may warn about or block them. |
| `spry-turn-<tag>-x86_64-unknown-linux-gnu.tar.gz` | Both executables for Linux x64 (glibc). |
| `spry-turn-<tag>-aarch64-unknown-linux-gnu.tar.gz` | Both executables for Linux arm64 (glibc), built on a native arm64 runner. |
| `spry-relay-<tag>-android.tar.gz` | `jniLibs/arm64-v8a/libspry_relay.so`, `jniLibs/x86_64/libspry_relay.so`, `include/spry_relay.h`, `consumer-rules.pro` and this guide |
| `spry-turn-<tag>-source.tar.gz` | `git archive` of the tagged commit |
| `release-manifest.json` | Every asset's SHA-256 and size, the commit and the workflow run |
| `SHA256SUMS` | SHA-256 of every asset above |

Every archive also holds its own `SHA256SUMS` and a `provenance.json`
(commit, workflow run, compiler, build command, file hashes and, for Linux,
the minimum glibc). Verify before use:

```sh
sha256sum -c SHA256SUMS            # or: shasum -a 256 -c SHA256SUMS
```

Each build runs on its own platform's runner (macOS arm64, Windows x64,
Linux x64, Linux arm64), starts both executables there and drives the
embedded relay through the C ABI with this crate's tests before packaging.
The Android libraries are checked for machine, 16 KB page alignment, exported
symbols and needed libraries, and the JNI entry points are driven from a JVM
on Linux. The workflow creates a **draft** prerelease on a `v*` tag that
matches `Cargo.toml`; a maintainer reviews and publishes it. It never
replaces the assets of an existing release.

## Building the Android library

```sh
rustup target add aarch64-linux-android x86_64-linux-android
python3 scripts/build-android.py            # or --ndk <path to NDK 28.2>
```

The script uses the NDK's own clang for API 33 as linker and C compiler
(`ring`, under `rustls`, compiles C and assembly) through cargo's standard
`CC_<target>`, `AR_<target>` and `CARGO_TARGET_<TARGET>_LINKER` variables.
No `cargo-ndk` or other wrapper is involved. It builds
`cargo build -p spry-ffi --features jni --profile release-ffi --target <abi>`,
links with 16 KB pages (`-z max-page-size=16384`, needed for apps targeting
API 35 on 16 KB devices) and checks that each `.so` exports every function
below and needs only `libc.so`, `libm.so`, `libdl.so` or `liblog.so`.

The `release-ffi` profile is the release profile with `panic = "unwind"`.
The executables abort on a panic; inside a host's process that would end the
app, so the library unwinds instead and every exported function catches the
panic and returns an error code.

## The C ABI

`crates/spry-ffi/include/spry_relay.h` is the contract; read it for the exact
rules. In short:

```c
uint32_t spry_relay_abi_version(void);
int32_t spry_relay_start(const char *const *argv, size_t argc,
                         const char *const *envp, size_t envc,
                         SpryRelay **out_relay);
int32_t spry_relay_next_line(const SpryRelay *relay, uint32_t timeout_ms,
                             uint8_t *buffer, size_t capacity, size_t *length);
int32_t spry_relay_stop(const SpryRelay *relay);
int32_t spry_relay_exit_code(const SpryRelay *relay);
int32_t spry_relay_free(SpryRelay *relay);
```

- **Options.** `argv` is what follows `spry-node supervised`, without
  `--exit-on-stdin-close` (which is refused: the host's stop request is the
  lifetime). Every other option and rule is the child process's.
- **Settings.** `envp` holds `NAME=VALUE` strings in place of the
  environment: `SPRY_TURN_SECRET` (required), `SPRY_ROOM_SEAL`,
  `SPRY_LOCAL_TEST`, `SPRY_SOCKS_PROXY` and `SPRY_CONTROL_CA_FILE`, each at
  most once. Any other name refuses, `SPRY_` or not. The library never reads
  the process environment, so nothing the host inherited can apply.
- **Lines.** `spry_relay_next_line` copies the next line into the caller's
  buffer: the same single-line JSON objects the child process prints on
  stdout (`portmap`, `ready`, `status`, `control`, `urls`), as UTF-8 without a
  line ending. After them comes one last line, which the child process does
  not print:

  ```json
  {"v":1,"event":"stopped","code":0}
  {"v":1,"event":"stopped","code":1,"refusal":"--bind must be the concrete local IPv4 address of the hosting interface"}
  ```

  `code` is the exit code the child process would have used (0 stopped, 1
  refused or failed, 3 the router could not host; see
  [exit codes](supervised-mode.md#exit-codes)). `refusal` is the text the
  child process prints on stderr; it names a setting and never carries its
  value. After `stopped`, `next_line` returns `SPRY_RELAY_ENDED`.
- **Refusals arrive as lines.** Settings are checked on the node's thread, so
  `spry_relay_start` returns a handle even for a refused setting. It fails
  only for a malformed list (`SPRY_RELAY_ERR_ARGUMENT`) or if the thread
  cannot start.
- **Stop.** `spry_relay_stop` returns at once. The relay stops and frees its
  ports, the node removes the router mappings it made (within five seconds,
  as on stdin close), `portmap released` and `stopped` arrive, and the node
  ends.
- **Free.** `spry_relay_free` stops the node if it runs, waits up to seven
  seconds and frees the handle. If the node has not ended by then it returns
  `SPRY_RELAY_ERR_DETACHED`; the node's thread finishes on its own, holding
  only its own references.

### Pointers and lifetimes

- Every pointer passed in is borrowed for that call only; the library copies
  what it keeps.
- The library never returns memory for the host to free. Lines are copied
  into the host's buffer; too small a buffer returns `SPRY_RELAY_ERR_BUFFER`
  with the size needed in `*length`, and the line stays queued.
- The handle is the host's from a successful start until `spry_relay_free`,
  called exactly once, after every other call on it has returned. It is
  invalid afterwards.
- `next_line`, `stop` and `exit_code` may run on one handle from several
  threads at once.
- Up to 1024 unread lines are kept; a host that falls further behind loses
  the oldest. `stopped` is always the newest, so it is never lost.
- The library calls nothing back in the host, installs no signal handler and
  never ends the process.

A host normally runs one reader thread:

```c
uint8_t line[SPRY_RELAY_LINE_BUFFER];
size_t length;
for (;;) {
    int32_t code = spry_relay_next_line(relay, 1000, line, sizeof line, &length);
    if (code == SPRY_RELAY_OK) handle_line(line, length);
    else if (code == SPRY_RELAY_ENDED) break;
    else if (code != SPRY_RELAY_NO_LINE) break; /* an error */
}
spry_relay_free(relay); /* after the reader is done */
```

and calls `spry_relay_stop` from wherever the person presses Stop.

## The JNI shim (Android)

Built with the `jni` feature, the library also exports
`Java_dev_forgesworn_spry_SpryRelayNative_*` for this Kotlin class, which the
app writes:

```kotlin
package dev.forgesworn.spry

object SpryRelayNative {
    init { System.loadLibrary("spry_relay") }
    @JvmStatic external fun abiVersion(): Int
    @JvmStatic external fun start(args: Array<String>, environment: Array<String>): Long
    @JvmStatic external fun nextLine(handle: Long, timeoutMillis: Int): ByteArray?
    @JvmStatic external fun stop(handle: Long): Int
    @JvmStatic external fun exitCode(handle: Long): Int
    @JvmStatic external fun free(handle: Long): Int
}
```

| Method | Returns |
|---|---|
| `abiVersion()` | `1`; check it before anything else |
| `start(args, environment)` | The handle, or 0 if an argument was malformed (null, more than 256 arguments or 16 settings, a setting without `=`, or text with a NUL or a character outside the Basic Multilingual Plane) or the thread could not start |
| `nextLine(handle, timeoutMillis)` | The next line as UTF-8 bytes (`String(bytes, Charsets.UTF_8)`); `null` if none arrived in time; an empty array once `stopped` has been read |
| `stop(handle)` | `0`; asks for an orderly stop and returns at once |
| `exitCode(handle)` | `-1` while running, else 0, 1 or 3 |
| `free(handle)` | `0`, or `-5` if the node had not ended after seven seconds. Blocks; never call it on the main thread. `free(0)` does nothing. |

The same lifetime rules apply: one reader thread loops on `nextLine` until it
returns an empty array, the person's Stop calls `stop`, and `free` follows
once the reader has finished. Never use a handle after `free`.

The shim is written by hand against the JNI function table (nine entries,
their indices checked against the NDK's `jni.h`), with no binding crate or
generator, following ForgeSworn's ferrule decision. It never calls back into
Java, so no class, method or field is looked up from native code.

**Keep rules.** R8 cannot see JNI names. The release archive carries
`consumer-rules.pro`, which keeps the class name and its native methods:

```
-keepclasseswithmembernames,includedescriptorclasses class dev.forgesworn.spry.SpryRelayNative {
    native <methods>;
}
-keep class dev.forgesworn.spry.SpryRelayNative
```

An app must include these rules and qualify its minified release APK with a
cold-load instrumentation test, then on a physical phone, as its own gate.

**What the app still owns.** The relay runs on the node's own threads inside
the app process; the built-in relay design runs it in a separate
`android:process=":relay"` foreground service so that a native fault (an
abort, a stack overflow, an out-of-memory) ends the relay, not the app. Pass
`--gateway` from `LinkProperties` with `--map-ports`, since an app cannot rely
on reading the system route table. Keep the state file in the app's private
files directory and the secret out of storage in clear. Charging, Wi-Fi,
temperature and data gates belong to the app.

## Safety

The rest of the workspace forbids `unsafe`. A C ABI cannot be written
without it, so `crates/spry-ffi` denies it instead and allows it only on its
two ABI modules (`capi.rs`, `jni.rs`), where every unsafe block states why it
is sound and Clippy's `undocumented_unsafe_blocks` is enforced. The node
itself, in `spry-service`, still forbids `unsafe`.

## Evidence and limits

- `cargo test -p spry-ffi` drives the exported functions from Rust as a C
  host would: malformed calls, a refused setting reported as `stopped`, a
  real node on loopback that reports `ready`, `status` and `control` and
  frees its ports on stop, a too-small buffer, freeing a running node, and a
  `--map-ports` node whose stop removes exactly its mappings from the
  in-house fake router. The header's constants and function names are checked
  against the library.
- `scripts/jni-smoke.py` loads the library into a JVM with `-Xcheck:jni`
  and drives every JNI entry point: a refused start, a malformed setting, and
  a loopback node through `ready`, `status`, stop, `stopped` and free.
- `scripts/build-android.py` proves that both Android libraries link and
  checks their machine, alignment, exports and needed libraries.

No Android device or emulator has loaded the library, no minified APK has
been tested, and no router, NAT or remote guest is involved. Those are the
Android app's gates (the built-in relay plan's A3 to A5), including the
GrapheneOS acceptance in [GOALS](../GOALS.md).
