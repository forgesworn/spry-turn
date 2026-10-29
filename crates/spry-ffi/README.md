# spry-ffi

`libspry_relay`: the supervised Spry relay (`spry-node supervised`) inside a
host app's own process, for Android. A hand-written C ABI
(`include/spry_relay.h`) and, with the `jni` feature, a thin JNI shim for
`dev.forgesworn.spry.SpryRelayNative`. No binding generator. MIT.

Build the Android libraries with `python3 scripts/build-android.py` (NDK
clang, `release-ffi` profile, 16 KB pages). Read
[docs/embedding.md](../../docs/embedding.md) for the ABI, the ownership and
lifetime rules, the JNI class and its keep rules (`android/consumer-rules.pro`).

This is the only crate in the workspace that allows `unsafe`, and only in its
two ABI modules: exporting an unmangled function and reading a caller's
pointer cannot be done without it.
