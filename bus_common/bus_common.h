/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    bus_common.h
 * @brief   SOFA bus_common, variant-agnostic bus simulator skeleton.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Owns the accept loop, peer table, select() event loop, CSV trace
 * row primitives, ANSI colour resolver, lifecycle, and Ctrl-C
 * handling. Variants supply only the per-frame parse / route logic
 * via three callbacks:
 *
 *   on_peer_accepted   - allocate variant-specific per-peer state.
 *   on_peer_readable   - read + parse + relay one frame from this peer.
 *                        May call fbsec_bus_relay_bytes / for-each-peer
 *                        helpers and fbsec_bus_emit_trace_row.
 *   on_peer_dropped    - free variant state; optionally emit a "loss"
 *                        trace row.
 *
 * Single-bus-per-process by design (file-static state). Multi-bus
 * support would require minor refactor; not in scope for the demo.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef BUS_COMMON_H
#define BUS_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <winsock2.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default listen backlog. */
#define FBSEC_BUS_LISTEN_BACKLOG 16

/** Maximum simultaneous peer connections (one slot reserved for the listener). */
#define FBSEC_BUS_MAX_PEERS (FD_SETSIZE - 1)

/* ---- Options + callbacks --------------------------------------------- */

typedef enum {
  FBSEC_BUS_COLOR_AUTO   = 0,
  FBSEC_BUS_COLOR_ALWAYS = 1,
  FBSEC_BUS_COLOR_NEVER  = 2
} fbsec_bus_color_pref_t;

typedef struct fbsec_bus_options_t {
  int                    port;        /**< TCP port */
  bool                   quiet;       /**< suppress stdout trace */
  fbsec_bus_color_pref_t color_pref;
  /**
   * Idle wake-up cadence in milliseconds. 0 = block in select() until a
   * socket is readable (legacy behaviour). >0 = wake on socket activity
   * OR every N ms whichever is sooner; on the timeout-only wake the
   * variant's @ref fbsec_bus_callbacks_t::on_idle_tick is fired.
   * Used by the FD bus to poll a PCAN-Basic receive queue without
   * spawning a thread.
   */
  int                    idle_timeout_ms;
} fbsec_bus_options_t;

typedef struct fbsec_bus_callbacks_t {
  /**
   * @brief Called once per accepted peer. Variant returns its own per-peer
   *        state pointer (bus_common stashes it; passes it back to
   *        @c on_peer_readable / @c on_peer_dropped). Return NULL to reject.
   */
  void *(*on_peer_accepted)(SOCKET sock, uint16_t tcp_port, void *vctx);

  /**
   * @brief Called when a peer's socket is readable. Variant should consume
   *        exactly one frame off the socket; may call fbsec_bus_relay_*
   *        and fbsec_bus_emit_trace_row.
   *
   * @retval 0  peer stays connected.
   * @retval -1 peer dropped (graceful EOF or protocol error).
   */
  int  (*on_peer_readable)(SOCKET sock, void *peer_state, void *vctx);

  /**
   * @brief Called once per peer drop, after the bus removed the slot.
   *        Variant frees its per-peer state and optionally emits a
   *        "peer disconnected" / "loss" trace row.
   */
  void (*on_peer_dropped)(SOCKET sock, void *peer_state, void *vctx);

  /**
   * @brief Called when select() returns 0 (timeout, no socket activity).
   *        Only fires when @c fbsec_bus_options_t::idle_timeout_ms > 0.
   *        Variant uses this to poll non-socket sources (e.g. a PCAN
   *        receive queue) and inject frames into the peer mesh via
   *        @ref fbsec_bus_each_peer.
   *
   * Optional. NULL means "no idle work".
   */
  void (*on_idle_tick)(void *vctx);
} fbsec_bus_callbacks_t;

/* ---- Run --------------------------------------------------------------- */

/**
 * @brief Bring up the listening socket, install the Ctrl-C handler, and
 *        run the select() loop until the user interrupts.
 *
 * Banner / "listening on ..." message / CSV trace header are NOT
 * printed by this function; the variant prints them around the call
 * (banner first per ADR-004; header after listen succeeds).
 *
 * @param opts   listen port + colour / quiet preferences.
 * @param cb     variant callbacks.
 * @param vctx   opaque pointer passed to every callback.
 *
 * @retval 0  graceful shutdown (Ctrl-C).
 * @retval 1  fatal error (WSA / bind / listen / accept-fatal).
 */
int fbsec_bus_run(const fbsec_bus_options_t   *opts,
                  const fbsec_bus_callbacks_t *cb,
                  void                         *vctx);

/* ---- Helpers callable from inside callbacks -------------------------- */

/**
 * @brief Send @p bytes to every connected peer except @p origin (NULL =
 *        broadcast to all). Recipients whose send fails are dropped.
 */
void fbsec_bus_relay_bytes(SOCKET origin, const uint8_t *bytes, size_t n);

/**
 * @brief Iterate over connected peers (excluding @p skip if not NULL).
 *        @p fn is called once per slot.
 */
typedef void (*fbsec_bus_peer_visitor_fn)(SOCKET sock, void *peer_state, void *cb_arg);
void fbsec_bus_each_peer(SOCKET                    skip,
                         fbsec_bus_peer_visitor_fn fn,
                         void                     *cb_arg);

/* ---- Trace helpers --------------------------------------------------- */

/** True iff colour is currently enabled (auto-resolved at startup). */
bool fbsec_bus_use_color(void);

/** Format current local wall-clock as "HH:MM:SS.mmm". */
void fbsec_bus_format_timestamp(char *buf, size_t buflen);

/**
 * @brief Emit one CSV trace row on stdout: <frame#>,<ts>,<...>\n,
 *        wrapped with @p col_start / col_end (use ANSI escapes from
 *        bus_common_ansi.h or pass "" to disable). Increments the
 *        frame counter. No-op when --quiet.
 *
 * The @p body is printed verbatim between the timestamp and the
 * trailing newline; variant supplies the comma-separated middle of
 * the row.
 */
void fbsec_bus_emit_trace_row(const char *col_start,
                              const char *col_end,
                              const char *body);

/* ANSI SGR escapes the variant trace formatter may use. Empty when
   colour is off; the variant chooses which to pass to emit_trace_row. */
const char *fbsec_bus_ansi_reset(void);
const char *fbsec_bus_ansi_red(void);
const char *fbsec_bus_ansi_blue(void);
const char *fbsec_bus_ansi_magenta(void);
const char *fbsec_bus_ansi_dim(void);

/* ---- Wire I/O helpers ------------------------------------------------- */

/**
 * @brief recv() the requested byte count, looping over short returns.
 *
 * @retval  1  all @p n bytes received.
 * @retval  0  graceful EOF (peer closed before any byte of this read).
 * @retval -1  socket error or unexpected EOF mid-buffer.
 */
int fbsec_bus_recv_exact(SOCKET s, void *buf, size_t n);

/**
 * @brief send() the requested byte count, looping over short returns.
 *
 * @retval 0  success.
 * @retval -1 socket error.
 */
int fbsec_bus_send_all(SOCKET s, const void *buf, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* BUS_COMMON_H */
/* EOF */
