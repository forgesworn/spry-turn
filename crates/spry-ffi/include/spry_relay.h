/*
 * spry_relay.h: a supervised Spry relay inside the host application's own
 * process. MIT licence. See docs/embedding.md in forgesworn/spry-turn.
 *
 * The node is `spry-node supervised` without the child process: the same
 * options (except --exit-on-stdin-close), the same five settings as
 * "NAME=VALUE" strings instead of the process environment, and the same
 * single-line JSON objects, read with spry_relay_next_line instead of
 * stdout. The last line is always
 *
 *     {"v":1,"event":"stopped","code":0}
 *
 * with "refusal" added when a setting was refused. "code" is the exit code
 * the child process would have used: 0 stopped, 1 refused or failed, 3 the
 * router could not host.
 *
 * Pointers and lifetimes
 *
 *   - Every pointer the host passes in is borrowed for that call only. The
 *     library copies what it keeps and never holds a host pointer after the
 *     call returns.
 *   - The library never hands out memory for the host to free. Lines are
 *     copied into the host's own buffer.
 *   - A SpryRelay handle is owned by the host from a successful
 *     spry_relay_start until spry_relay_free, which must be called exactly
 *     once, after every other call on that handle has returned and when no
 *     other will start. The handle is invalid afterwards.
 *   - spry_relay_next_line, spry_relay_stop and spry_relay_exit_code may be
 *     called on one handle from any threads at the same time.
 *   - No function calls back into the host. No function throws, unwinds or
 *     ends the process: a panic inside the library becomes
 *     SPRY_RELAY_ERR_PANIC (when built with the release-ffi profile).
 *   - The library installs no signal handler and never reads the process
 *     environment.
 */
#ifndef SPRY_RELAY_H
#define SPRY_RELAY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPRY_RELAY_ABI_VERSION 1

/* Return codes. */
#define SPRY_RELAY_OK 0            /* success; next_line: a line was copied */
#define SPRY_RELAY_NO_LINE 1       /* next_line: no line within the timeout */
#define SPRY_RELAY_ENDED 2         /* next_line: ended, every line read */
#define SPRY_RELAY_ERR_ARGUMENT -1 /* null pointer, not UTF-8, too many or too long */
#define SPRY_RELAY_ERR_BUFFER -2   /* next_line: buffer too small; *length = size needed */
#define SPRY_RELAY_ERR_START -3    /* start: the node's thread could not start */
#define SPRY_RELAY_ERR_PANIC -4    /* a panic was caught; free the handle */
#define SPRY_RELAY_ERR_DETACHED -5 /* free: not ended in time; its thread finishes alone */
#define SPRY_RELAY_RUNNING -1      /* exit_code: still running */

/* Limits. */
#define SPRY_RELAY_MAX_ARGS 256      /* argc */
#define SPRY_RELAY_MAX_SETTINGS 16   /* envc */
#define SPRY_RELAY_MAX_TEXT 8192     /* bytes in one argument or setting */
#define SPRY_RELAY_MAX_QUEUED 1024   /* unread lines kept; the oldest go first */
#define SPRY_RELAY_LINE_BUFFER 16384 /* recommended buffer; a longer line gets ERR_BUFFER */

typedef struct SpryRelay SpryRelay;

/* The ABI version the library implements. Compare with
 * SPRY_RELAY_ABI_VERSION before any other call. */
uint32_t spry_relay_abi_version(void);

/*
 * Start a node on its own thread and return at once.
 *
 * argv: argc NUL-terminated UTF-8 options, exactly as after
 *       `spry-node supervised` but without --exit-on-stdin-close, for
 *       example "--pairing-key", "<hex>", "--map-ports", ... May be NULL
 *       when argc is 0 (which is then refused as a setting).
 * envp: envc NUL-terminated UTF-8 "NAME=VALUE" settings. Only
 *       SPRY_TURN_SECRET (required), SPRY_ROOM_SEAL, SPRY_LOCAL_TEST,
 *       SPRY_SOCKS_PROXY and SPRY_CONTROL_CA_FILE are accepted, each once.
 * out_relay: receives the handle on SPRY_RELAY_OK, and NULL otherwise.
 *
 * Settings are checked on the node's thread: a refused setting still
 * returns SPRY_RELAY_OK and a handle, and the refusal arrives as the
 * "stopped" line. Returns SPRY_RELAY_ERR_ARGUMENT for a malformed list and
 * SPRY_RELAY_ERR_START if the thread could not start.
 */
int32_t spry_relay_start(const char *const *argv, size_t argc,
                         const char *const *envp, size_t envc,
                         SpryRelay **out_relay);

/*
 * Copy the oldest unread line into buffer, waiting up to timeout_ms for one
 * (0 does not wait). The line is UTF-8 JSON, without a NUL terminator or a
 * line ending; *length receives its size in bytes.
 *
 * buffer: capacity writable bytes, or NULL when capacity is 0.
 * length: always written: the line's size on SPRY_RELAY_OK, the size
 *         needed on SPRY_RELAY_ERR_BUFFER (the line stays queued), else 0.
 *
 * Returns SPRY_RELAY_OK, SPRY_RELAY_NO_LINE, SPRY_RELAY_ENDED (the node has
 * ended and its last line, "stopped", has been read), or an error.
 */
int32_t spry_relay_next_line(const SpryRelay *relay, uint32_t timeout_ms,
                             uint8_t *buffer, size_t capacity,
                             size_t *length);

/*
 * Ask the node for an orderly stop and return at once: the relay stops,
 * the router mappings this node made are removed (bounded to five
 * seconds), the last lines arrive and the node ends. Calling it again, or
 * after the node has ended, does nothing.
 */
int32_t spry_relay_stop(const SpryRelay *relay);

/* The node's exit code (0, 1 or 3) once it has ended, else
 * SPRY_RELAY_RUNNING. */
int32_t spry_relay_exit_code(const SpryRelay *relay);

/*
 * Stop the node if it runs, wait up to seven seconds for it to end, and
 * free the handle. Unread lines are discarded. NULL does nothing. Blocks;
 * do not call it on a thread that must stay responsive.
 *
 * Returns SPRY_RELAY_OK, or SPRY_RELAY_ERR_DETACHED when the node had not
 * ended: its thread finishes on its own, and the handle is freed anyway.
 */
int32_t spry_relay_free(SpryRelay *relay);

#ifdef __cplusplus
}
#endif

#endif /* SPRY_RELAY_H */
