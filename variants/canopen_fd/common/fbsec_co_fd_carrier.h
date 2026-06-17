/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_carrier.h
 * @brief   SOFA CANopen FD, peer-side TCP-loopback carrier.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 06-MAY-2026
 *
 * "Virtual CAN FD bus" carrier as defined by
 * `doc/fieldbus_sim_canopen_fd_spec.txt §3 / §10`. Provides the peer
 * side of the carrier: WSAStartup, connect to bus, send + recv of
 * one CAN FD frame at a time using @ref fbsec_co_fd_frame_t. The
 * bus simulator implements its own accept-loop and does not link
 * this module.
 *
 * THIS IS THE ONLY MODULE IN `variants/canopen_fd/common/` THAT
 * INCLUDES WINSOCK. Substituting a real CAN-FD driver (PCAN,
 * SocketCAN, Kvaser, ...) is a matter of swapping this single
 * file; the rest of the variant is driver-agnostic.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_CO_FD_CARRIER_H
#define FBSEC_CO_FD_CARRIER_H

#include <stdint.h>
#include <stdbool.h>

#include <winsock2.h>

#include "fbsec_co_fd_frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default carrier port (spec §2). */
#define FBSEC_CO_FD_DEFAULT_PORT 5810u

/** Default carrier host (loopback). */
#define FBSEC_CO_FD_DEFAULT_HOST "127.0.0.1"

/** Status codes returned by the carrier API. */
typedef enum {
  FBSEC_CO_FD_CARRIER_OK      = 0,
  FBSEC_CO_FD_CARRIER_TIMEOUT = 1, /**< deadline elapsed before recv done    */
  FBSEC_CO_FD_CARRIER_CLOSED  = 2, /**< peer (bus) closed the TCP connection */
  FBSEC_CO_FD_CARRIER_FRAME   = 3, /**< malformed CAN FD frame on the wire   */
  FBSEC_CO_FD_CARRIER_NET     = 4  /**< socket / WSA / connect error         */
} fbsec_co_fd_carrier_status_t;

/**
 * @brief Carrier handle.
 *
 * Owned by the caller; the carrier API never allocates. Construct
 * with @ref fbsec_co_fd_carrier_init, use, then release with
 * @ref fbsec_co_fd_carrier_close.
 */
typedef struct fbsec_co_fd_carrier_t {
  SOCKET sock;
} fbsec_co_fd_carrier_t;

/* ---- Process-wide WSA lifecycle --------------------------------------- */

/**
 * @brief WSAStartup wrapper. Call once before any carrier instance.
 *
 * @retval FBSEC_CO_FD_CARRIER_OK   WSAStartup succeeded.
 * @retval FBSEC_CO_FD_CARRIER_NET  WSAStartup failed.
 */
fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_global_init(void);

/** WSACleanup wrapper. Call once on program exit. */
void fbsec_co_fd_carrier_global_shutdown(void);

/* ---- Per-carrier lifecycle -------------------------------------------- */

/** Reset @p c to a known-disconnected state. */
void fbsec_co_fd_carrier_init(fbsec_co_fd_carrier_t *c);

/**
 * @brief Connect to the bus simulator at @p host : @p port.
 *
 * @param c     carrier; must have been initialized with
 *              @ref fbsec_co_fd_carrier_init or be already-closed.
 * @param host  ASCII IPv4 address (e.g. "127.0.0.1").
 * @param port  TCP port number (typically @ref FBSEC_CO_FD_DEFAULT_PORT).
 *
 * @retval FBSEC_CO_FD_CARRIER_OK   connected.
 * @retval FBSEC_CO_FD_CARRIER_NET  socket / connect / address error.
 */
fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_connect(
    fbsec_co_fd_carrier_t *c,
    const char            *host,
    uint16_t               port);

/** Close the carrier's socket if open and mark it disconnected. */
void fbsec_co_fd_carrier_close(fbsec_co_fd_carrier_t *c);

/** @return true when @p c holds an open connection. */
bool fbsec_co_fd_carrier_is_open(const fbsec_co_fd_carrier_t *c);

/* ---- I/O -------------------------------------------------------------- */

/**
 * @brief Serialize @p frame and send it on the carrier (blocking).
 *
 * The frame is validated with @ref fbsec_co_fd_frame_validate
 * before serialization; an invalid frame returns
 * @ref FBSEC_CO_FD_CARRIER_FRAME without any bytes touching the
 * wire.
 *
 * @retval FBSEC_CO_FD_CARRIER_OK     full frame sent.
 * @retval FBSEC_CO_FD_CARRIER_FRAME  frame failed pre-send validation.
 * @retval FBSEC_CO_FD_CARRIER_NET    socket error during send.
 */
fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_send(
    fbsec_co_fd_carrier_t     *c,
    const fbsec_co_fd_frame_t *frame);

/**
 * @brief Receive one CAN FD frame from the carrier with a deadline.
 *
 * @p deadline_ms is an absolute monotonic millisecond timestamp
 * (compatible with @ref fbsec_co_fd_carrier_now_ms). The function
 * keeps reading until the full carrier message has arrived OR the
 * deadline elapses OR the connection is closed by the bus.
 *
 * @retval FBSEC_CO_FD_CARRIER_OK      complete frame received in @p frame.
 * @retval FBSEC_CO_FD_CARRIER_TIMEOUT deadline reached mid-read; @p frame
 *                                      may be partially populated and
 *                                      MUST be discarded.
 * @retval FBSEC_CO_FD_CARRIER_CLOSED  bus closed the TCP connection.
 * @retval FBSEC_CO_FD_CARRIER_FRAME   malformed header / overlong len /
 *                                      reserved bits set.
 * @retval FBSEC_CO_FD_CARRIER_NET     socket error during recv.
 */
fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_recv(
    fbsec_co_fd_carrier_t *c,
    fbsec_co_fd_frame_t   *frame,
    uint32_t               deadline_ms);

/* ---- Time helper ------------------------------------------------------ */

/** Monotonic millisecond timestamp (GetTickCount). Wraps after ~49 days. */
uint32_t fbsec_co_fd_carrier_now_ms(void);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_CO_FD_CARRIER_H */
/* EOF */
