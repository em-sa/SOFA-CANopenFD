/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_carrier.c
 * @brief   SOFA CANopen FD, peer-side TCP-loopback carrier, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 06-MAY-2026
 *
 * Sole winsock-touching file in `variants/canopen_fd/common/`. See
 * the header for the contract; idioms (recv-with-deadline,
 * send_all loop) are standard winsock blocking-with-timeout
 * patterns.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_co_fd_carrier.h"

#include <ws2tcpip.h>
#include <windows.h>

#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* ---- Process-wide WSA lifecycle --------------------------------------- */

fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_global_init(void) {
  WSADATA wsa;
  int rc = WSAStartup(MAKEWORD(2, 2), &wsa);
  if (rc != 0) {
    return FBSEC_CO_FD_CARRIER_NET;
  }
  return FBSEC_CO_FD_CARRIER_OK;
}

void fbsec_co_fd_carrier_global_shutdown(void) {
  WSACleanup();
}

/* ---- Per-carrier lifecycle -------------------------------------------- */

void fbsec_co_fd_carrier_init(fbsec_co_fd_carrier_t *c) {
  c->sock = INVALID_SOCKET;
}

fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_connect(
    fbsec_co_fd_carrier_t *c,
    const char            *host,
    uint16_t               port) {
  c->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (c->sock == INVALID_SOCKET) {
    return FBSEC_CO_FD_CARRIER_NET;
  }

  struct sockaddr_in sa;
  memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port   = htons(port);
  if (InetPtonA(AF_INET, host, &sa.sin_addr) != 1) {
    closesocket(c->sock);
    c->sock = INVALID_SOCKET;
    return FBSEC_CO_FD_CARRIER_NET;
  }

  if (connect(c->sock, (const struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR) {
    closesocket(c->sock);
    c->sock = INVALID_SOCKET;
    return FBSEC_CO_FD_CARRIER_NET;
  }
  return FBSEC_CO_FD_CARRIER_OK;
}

void fbsec_co_fd_carrier_close(fbsec_co_fd_carrier_t *c) {
  if (c->sock != INVALID_SOCKET) {
    closesocket(c->sock);
    c->sock = INVALID_SOCKET;
  }
}

bool fbsec_co_fd_carrier_is_open(const fbsec_co_fd_carrier_t *c) {
  return c->sock != INVALID_SOCKET;
}

/* ---- Time helper ------------------------------------------------------ */

uint32_t fbsec_co_fd_carrier_now_ms(void) {
  return (uint32_t)GetTickCount();
}

/* ---- Send loop -------------------------------------------------------- */

static fbsec_co_fd_carrier_status_t send_all(SOCKET s,
                                             const uint8_t *buf,
                                             size_t n) {
  size_t sent = 0;
  while (sent < n) {
    int r = send(s, (const char *)(buf + sent), (int)(n - sent), 0);
    if (r == SOCKET_ERROR || r <= 0) {
      return FBSEC_CO_FD_CARRIER_NET;
    }
    sent += (size_t)r;
  }
  return FBSEC_CO_FD_CARRIER_OK;
}

fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_send(
    fbsec_co_fd_carrier_t     *c,
    const fbsec_co_fd_frame_t *frame) {
  if (c->sock == INVALID_SOCKET) {
    return FBSEC_CO_FD_CARRIER_NET;
  }
  if (fbsec_co_fd_frame_validate(frame) != FBSEC_CO_FD_VALID_OK) {
    return FBSEC_CO_FD_CARRIER_FRAME;
  }

  uint8_t buf[FBSEC_CO_FD_WIRE_MAX];
  size_t  n = 0;
  if (!fbsec_co_fd_frame_serialize(frame, buf, sizeof buf, &n)) {
    /* Should not happen given validate() succeeded. */
    return FBSEC_CO_FD_CARRIER_FRAME;
  }
  return send_all(c->sock, buf, n);
}

/* ---- Receive loop with deadline --------------------------------------- */

/**
 * @brief Receive exactly @p n bytes into @p buf or fail.
 *
 * Sets SO_RCVTIMEO before each recv() call to the remaining time
 * until @p deadline_ms; on TIMEDOUT or zero remaining returns
 * @ref FBSEC_CO_FD_CARRIER_TIMEOUT.
 */
static fbsec_co_fd_carrier_status_t recv_exact_with_deadline(
    SOCKET    s,
    uint8_t  *buf,
    size_t    n,
    uint32_t  deadline_ms) {
  size_t got = 0;
  while (got < n) {
    uint32_t now = (uint32_t)GetTickCount();
    int32_t  remain = (int32_t)(deadline_ms - now);
    if (remain <= 0) {
      return FBSEC_CO_FD_CARRIER_TIMEOUT;
    }
    DWORD timeout = (DWORD)remain;
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout, sizeof timeout) == SOCKET_ERROR) {
      return FBSEC_CO_FD_CARRIER_NET;
    }
    int r = recv(s, (char *)(buf + got), (int)(n - got), 0);
    if (r == 0) {
      return FBSEC_CO_FD_CARRIER_CLOSED;
    }
    if (r == SOCKET_ERROR) {
      int err = WSAGetLastError();
      if (err == WSAETIMEDOUT) {
        return FBSEC_CO_FD_CARRIER_TIMEOUT;
      }
      return FBSEC_CO_FD_CARRIER_NET;
    }
    got += (size_t)r;
  }
  return FBSEC_CO_FD_CARRIER_OK;
}

fbsec_co_fd_carrier_status_t fbsec_co_fd_carrier_recv(
    fbsec_co_fd_carrier_t *c,
    fbsec_co_fd_frame_t   *frame,
    uint32_t               deadline_ms) {
  if (c->sock == INVALID_SOCKET) {
    return FBSEC_CO_FD_CARRIER_NET;
  }

  uint8_t header[FBSEC_CO_FD_HEADER_SIZE];
  fbsec_co_fd_carrier_status_t st = recv_exact_with_deadline(
      c->sock, header, sizeof header, deadline_ms);
  if (st != FBSEC_CO_FD_CARRIER_OK) {
    return st;
  }

  size_t expected_payload = 0;
  fbsec_co_fd_parse_t pr = fbsec_co_fd_frame_parse_header(
      header, sizeof header, frame, &expected_payload);
  if (pr != FBSEC_CO_FD_PARSE_OK) {
    return FBSEC_CO_FD_CARRIER_FRAME;
  }

  if (expected_payload > 0u) {
    st = recv_exact_with_deadline(c->sock,
                                  frame->payload,
                                  expected_payload,
                                  deadline_ms);
    if (st != FBSEC_CO_FD_CARRIER_OK) {
      return st;
    }
  }
  return FBSEC_CO_FD_CARRIER_OK;
}

/* EOF */
