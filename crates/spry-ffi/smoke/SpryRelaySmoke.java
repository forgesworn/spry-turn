import dev.forgesworn.spry.SpryRelayNative;
import java.nio.charset.StandardCharsets;

/**
 * Loads libspry_relay through System.load and drives every JNI entry point:
 * a refused start, then a loopback node that reports, stops and is freed.
 * Usage: java -cp <classes> SpryRelaySmoke <library path> <state directory>
 */
public final class SpryRelaySmoke {
    private static final String SECRET = "SPRY_TURN_SECRET=synthetic-supervised-secret-not-for-deployment";
    private static final String HOST = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    /** The next line, or null once the node has ended and been read out. */
    private static String next(long handle) {
        long deadline = System.nanoTime() + 15_000_000_000L;
        while (true) {
            byte[] line = SpryRelayNative.nextLine(handle, 200);
            if (line != null && line.length == 0) {
                return null;
            }
            if (line != null) {
                return new String(line, StandardCharsets.UTF_8);
            }
            check(System.nanoTime() < deadline, "a line in time");
        }
    }

    private static String until(long handle, String event) {
        while (true) {
            String line = next(handle);
            check(line != null, "ended before " + event);
            System.out.println(line);
            if (line.contains("\"event\":\"" + event + "\"")) {
                return line;
            }
        }
    }

    public static void main(String[] arguments) throws Exception {
        System.load(arguments[0]);
        check(SpryRelayNative.abiVersion() == 1, "ABI version 1");

        // No secret: refused on the node's thread, reported as the last line.
        long refused = SpryRelayNative.start(new String[] {"--map-ports"}, new String[0]);
        check(refused != 0, "a handle for a refused setting");
        String stopped = until(refused, "stopped");
        check(stopped.contains("\"code\":1") && stopped.contains("SPRY_TURN_SECRET"), stopped);
        check(next(refused) == null, "ended after stopped");
        check(SpryRelayNative.exitCode(refused) == 1, "exit code 1");
        check(SpryRelayNative.free(refused) == 0, "freed");

        // A malformed setting never starts a thread.
        check(SpryRelayNative.start(new String[0], new String[] {"NO_EQUALS"}) == 0, "malformed refused");

        // A loopback node. Nothing listens on the control relay port; the node
        // keeps trying in the background, which this smoke does not need.
        String[] args = {
            "--pairing-key", HOST,
            "--state-file", arguments[1] + "/state.json",
            "--control-relay", "ws://127.0.0.1:9/",
            "--bind", "127.0.0.1", "--public-ip", "203.0.113.7",
            "--listen-port", arguments[2],
            "--public-udp-port", "51000", "--public-tcp-port", "51001",
            "--relay-port-map", (Integer.parseInt(arguments[2]) + 2) + ":51002",
        };
        long handle = SpryRelayNative.start(args, new String[] {SECRET, "SPRY_LOCAL_TEST=true"});
        check(handle != 0, "a handle");
        check(until(handle, "ready").contains("turn:203.0.113.7:51000?transport=udp"), "ready URLs");
        check(until(handle, "status").contains("\"allocations\":0"), "status counts");
        check(SpryRelayNative.exitCode(handle) == -1, "running");
        check(SpryRelayNative.stop(handle) == 0, "stop asked");
        check(until(handle, "stopped").contains("\"code\":0"), "stopped cleanly");
        check(next(handle) == null, "ended");
        check(SpryRelayNative.exitCode(handle) == 0, "exit code 0");
        check(SpryRelayNative.free(handle) == 0, "freed");
        check(SpryRelayNative.free(0) == 0, "free(0) does nothing");
        System.out.println("JNI smoke passed");
    }
}
