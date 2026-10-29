package dev.forgesworn.spry;

/**
 * A Java stand-in for the Kotlin {@code object SpryRelayNative} described in
 * docs/embedding.md: the same class name and static native methods, so the
 * same JNI symbols. Used only by the JNI smoke test.
 */
public final class SpryRelayNative {
    private SpryRelayNative() {}

    public static native int abiVersion();
    public static native long start(String[] args, String[] environment);
    public static native byte[] nextLine(long handle, int timeoutMillis);
    public static native int stop(long handle);
    public static native int exitCode(long handle);
    public static native int free(long handle);
}
