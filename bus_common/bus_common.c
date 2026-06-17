/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    bus_common.c
 * @brief   SOFA bus_common, variant-agnostic bus simulator, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "bus_common.h"

#include <ws2tcpip.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* ---- ANSI escapes (file-static; only emitted when g_use_color) -------- */

#define ANSI_RESET      "\x1b[0m"
#define ANSI_DIM        "\x1b[2m"
#define ANSI_RED        "\x1b[31m"
#define ANSI_BLUE       "\x1b[94m"
#define ANSI_MAGENTA    "\x1b[35m"

/* ---- File-static state ------------------------------------------------ */

typedef struct {
  SOCKET   sock;
  bool     in_use;
  uint16_t tcp_port;
  void    *user;       /* variant-supplied per-peer state */
} bus_peer_t;

static bus_peer_t    g_peers[FBSEC_BUS_MAX_PEERS];
static SOCKET        g_listen_sock     = INVALID_SOCKET;
static volatile LONG g_shutdown_flag   = 0;
static bool          g_quiet           = false;
static bool          g_use_color       = false;
static uint64_t      g_frame_no        = 0;
static int           g_idle_timeout_ms = 0;

/* ---- Forward decls ---------------------------------------------------- */

static BOOL WINAPI ctrl_handler(DWORD ctrl_type);
static int  start_listening(int port);
static void resolve_color(fbsec_bus_color_pref_t pref);
static void run_event_loop(const fbsec_bus_callbacks_t *cb, void *vctx);
static void shutdown_all(const fbsec_bus_callbacks_t *cb, void *vctx);
static void accept_new_peer(const fbsec_bus_callbacks_t *cb, void *vctx);
static void drop_peer(bus_peer_t *p, const fbsec_bus_callbacks_t *cb, void *vctx);

/* ---- Public ANSI accessors ------------------------------------------- */

bool fbsec_bus_use_color(void)            { return g_use_color; }
const char *fbsec_bus_ansi_reset(void)    { return g_use_color ? ANSI_RESET   : ""; }
const char *fbsec_bus_ansi_red(void)      { return g_use_color ? ANSI_RED     : ""; }
const char *fbsec_bus_ansi_blue(void)     { return g_use_color ? ANSI_BLUE    : ""; }
const char *fbsec_bus_ansi_magenta(void)  { return g_use_color ? ANSI_MAGENTA : ""; }
const char *fbsec_bus_ansi_dim(void)      { return g_use_color ? ANSI_DIM     : ""; }

/* ---- Time / colour --------------------------------------------------- */

void fbsec_bus_format_timestamp(char *buf, size_t buflen) {
  SYSTEMTIME st;
  GetLocalTime(&st);
  snprintf(buf, buflen, "%02u:%02u:%02u.%03u",
           (unsigned)st.wHour, (unsigned)st.wMinute,
           (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
}

static void resolve_color(fbsec_bus_color_pref_t pref) {
  switch (pref) {
    case FBSEC_BUS_COLOR_NEVER:  g_use_color = false; return;
    case FBSEC_BUS_COLOR_ALWAYS: g_use_color = true;  break;
    case FBSEC_BUS_COLOR_AUTO:
    default: {
      HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
      DWORD  mode = 0;
      g_use_color = (h != INVALID_HANDLE_VALUE && h != NULL
                     && GetConsoleMode(h, &mode));
      break;
    }
  }
  if (g_use_color) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (h != INVALID_HANDLE_VALUE && h != NULL && GetConsoleMode(h, &mode)) {
      (void)SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
  }
}

/* ---- Trace emit ------------------------------------------------------ */

void fbsec_bus_emit_trace_row(const char *col_start,
                              const char *col_end,
                              const char *body) {
  if (g_quiet) return;
  ++g_frame_no;
  char ts[16];
  fbsec_bus_format_timestamp(ts, sizeof ts);
  if (g_frame_no < 100000ULL) {
    printf("%s%05llu,%s,%s%s\n",
           col_start, (unsigned long long)g_frame_no, ts, body, col_end);
  } else {
    printf("%s%llu,%s,%s%s\n",
           col_start, (unsigned long long)g_frame_no, ts, body, col_end);
  }
}

/* ---- Wire I/O helpers ------------------------------------------------- */

int fbsec_bus_recv_exact(SOCKET s, void *buf, size_t n) {
  uint8_t *p   = (uint8_t *)buf;
  size_t   got = 0;
  while (got < n) {
    int r = recv(s, (char *)(p + got), (int)(n - got), 0);
    if (r == 0) return (got == 0) ? 0 : -1;
    if (r < 0)  return (got == 0) ? 0 : -1;
    got += (size_t)r;
  }
  return 1;
}

int fbsec_bus_send_all(SOCKET s, const void *buf, size_t n) {
  const uint8_t *p   = (const uint8_t *)buf;
  size_t         sent = 0;
  while (sent < n) {
    int r = send(s, (const char *)(p + sent), (int)(n - sent), 0);
    if (r <= 0) return -1;
    sent += (size_t)r;
  }
  return 0;
}

/* ---- Peer iteration / relay ----------------------------------------- */

void fbsec_bus_each_peer(SOCKET skip, fbsec_bus_peer_visitor_fn fn, void *cb_arg) {
  for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
    bus_peer_t *p = &g_peers[i];
    if (!p->in_use || p->sock == skip) continue;
    fn(p->sock, p->user, cb_arg);
  }
}

void fbsec_bus_relay_bytes(SOCKET origin, const uint8_t *bytes, size_t n) {
  for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
    bus_peer_t *p = &g_peers[i];
    if (!p->in_use || p->sock == origin) continue;
    if (fbsec_bus_send_all(p->sock, bytes, n) != 0) {
      /* On send failure we would ideally drop the peer, but that mid-callback
         requires the variant's on_peer_dropped, and we do not have its
         pointer here. Mark for drop on next select pass via close. */
      closesocket(p->sock);
      p->sock      = INVALID_SOCKET;
      p->in_use    = false;
      /* Variant's per-peer state leaks here in the rare relay-failure
         case; documented limitation. */
      p->user      = NULL;
    }
  }
}

/* ---- Console Ctrl handler -------------------------------------------- */

static BOOL WINAPI ctrl_handler(DWORD ctrl_type) {
  (void)ctrl_type;
  InterlockedExchange(&g_shutdown_flag, 1);
  /* Close listener AND every accepted peer socket so the main thread's
     select() unblocks immediately. Without this the X-button close on
     a console window can leave the process blocked in select() until
     Windows force-kills it ~5 s later, occasionally leaving the listen
     port in a transient kernel-bookkeeping state that breaks the next
     start. */
  SOCKET ls = g_listen_sock;
  if (ls != INVALID_SOCKET) {
    g_listen_sock = INVALID_SOCKET;
    closesocket(ls);
  }
  for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
    bus_peer_t *p = &g_peers[i];
    if (p->in_use && p->sock != INVALID_SOCKET) {
      SOCKET ps = p->sock;
      p->sock = INVALID_SOCKET;
      closesocket(ps);
    }
  }
  return TRUE;
}

/* ---- Listening socket ------------------------------------------------ */

static int start_listening(int port) {
  /* Retry bind on WSAEADDRINUSE up to 5x with 200 ms backoff. Windows
     occasionally keeps the listener port temporarily reserved after a
     hard window-close (CTRL_CLOSE_EVENT cuts off cleanup at 5 s); the
     retry handles that without forcing the user to wait minutes for
     the kernel to time out. */
  SOCKET s = INVALID_SOCKET;
  int    bind_rc = SOCKET_ERROR;
  int    last_err = 0;
  for (int attempt = 0; attempt < 5; ++attempt) {
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
      fprintf(stderr, "bus_common: socket() failed: %d\n", WSAGetLastError());
      return -1;
    }
    BOOL one = TRUE;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    bind_rc = bind(s, (struct sockaddr *)&addr, sizeof addr);
    if (bind_rc == 0) break;

    last_err = WSAGetLastError();
    closesocket(s);
    s = INVALID_SOCKET;
    if (last_err != WSAEADDRINUSE) break;
    Sleep(200);
  }
  if (bind_rc != 0) {
    fprintf(stderr, "bus_common: bind(127.0.0.1:%d) failed after retries: %d%s\n",
            port, last_err,
            (last_err == WSAEADDRINUSE)
              ? " (port still held by a previous instance; check Task Manager)"
              : "");
    if (s != INVALID_SOCKET) closesocket(s);
    return -1;
  }
  if (listen(s, FBSEC_BUS_LISTEN_BACKLOG) == SOCKET_ERROR) {
    fprintf(stderr, "bus_common: listen() failed: %d\n", WSAGetLastError());
    closesocket(s);
    return -1;
  }
  g_listen_sock = s;
  return 0;
}

/* ---- Event loop ------------------------------------------------------ */

static void accept_new_peer(const fbsec_bus_callbacks_t *cb, void *vctx) {
  struct sockaddr_in src;
  int srclen = (int)sizeof src;
  SOCKET s = accept(g_listen_sock, (struct sockaddr *)&src, &srclen);
  if (s == INVALID_SOCKET) {
    int err = WSAGetLastError();
    if (err != WSAEINTR && err != WSAEWOULDBLOCK) {
      fprintf(stderr, "bus_common: accept() failed: %d\n", err);
    }
    return;
  }

  bus_peer_t *slot = NULL;
  for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
    if (!g_peers[i].in_use) {
      slot = &g_peers[i];
      break;
    }
  }
  if (slot == NULL) {
    fprintf(stderr, "bus_common: peer table full, rejecting\n");
    closesocket(s);
    return;
  }

  uint16_t tcp_port = (uint16_t)ntohs(src.sin_port);
  void *user = NULL;
  if (cb->on_peer_accepted != NULL) {
    user = cb->on_peer_accepted(s, tcp_port, vctx);
    if (user == NULL && cb->on_peer_accepted != NULL) {
      /* Variant rejected this peer (or signaled "no per-peer state"). We
         accept either: a NULL user with a still-connected socket means
         "track the slot, no variant state". To distinguish "rejected"
         the variant would close the socket itself before returning;
         we do not probe. */
    }
  }

  slot->sock     = s;
  slot->in_use   = true;
  slot->tcp_port = tcp_port;
  slot->user     = user;
}

static void drop_peer(bus_peer_t *p, const fbsec_bus_callbacks_t *cb, void *vctx) {
  if (!p->in_use) return;
  SOCKET s = p->sock;
  void *user = p->user;
  p->sock   = INVALID_SOCKET;
  p->in_use = false;
  p->user   = NULL;
  if (cb->on_peer_dropped != NULL) {
    cb->on_peer_dropped(s, user, vctx);
  }
  closesocket(s);
}

static void run_event_loop(const fbsec_bus_callbacks_t *cb, void *vctx) {
  while (InterlockedCompareExchange(&g_shutdown_flag, 0, 0) == 0) {
    fd_set rfds;
    FD_ZERO(&rfds);

    SOCKET ls = g_listen_sock;
    if (ls != INVALID_SOCKET) FD_SET(ls, &rfds);
    for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
      if (g_peers[i].in_use) FD_SET(g_peers[i].sock, &rfds);
    }

    /* Use the variant's idle_timeout_ms when it is positive (e.g. PCAN
       polling needs ~5 ms). Otherwise floor at 250 ms so the loop
       wakes up periodically to check the shutdown flag; necessary on
       Windows because closesocket() from the Ctrl-handler thread
       does not always unblock a select() in another thread. */
    int  effective_to = (g_idle_timeout_ms > 0) ? g_idle_timeout_ms : 250;
    struct timeval tv;
    tv.tv_sec  = effective_to / 1000;
    tv.tv_usec = (effective_to % 1000) * 1000;
    int n = select(0, &rfds, NULL, NULL, &tv);
    if (n == SOCKET_ERROR) {
      if (InterlockedCompareExchange(&g_shutdown_flag, 0, 0) != 0) break;
      int err = WSAGetLastError();
      if (err == WSAEINTR) continue;
      fprintf(stderr, "bus_common: select() failed: %d\n", err);
      break;
    }
    if (n == 0) {
      /* Idle timeout: no socket activity. Variant may poll non-socket
         sources here (e.g. PCAN-Basic receive queue). */
      if (cb->on_idle_tick != NULL) cb->on_idle_tick(vctx);
      continue;
    }

    ls = g_listen_sock;
    if (ls != INVALID_SOCKET && FD_ISSET(ls, &rfds)) {
      accept_new_peer(cb, vctx);
    }
    for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
      bus_peer_t *p = &g_peers[i];
      if (!p->in_use) continue;
      if (FD_ISSET(p->sock, &rfds)) {
        int rc = (cb->on_peer_readable != NULL)
                   ? cb->on_peer_readable(p->sock, p->user, vctx)
                   : -1;
        if (rc != 0) {
          drop_peer(p, cb, vctx);
        }
      }
    }
  }
}

static void shutdown_all(const fbsec_bus_callbacks_t *cb, void *vctx) {
  for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
    bus_peer_t *p = &g_peers[i];
    if (!p->in_use) continue;
    drop_peer(p, cb, vctx);
  }
  SOCKET ls = g_listen_sock;
  if (ls != INVALID_SOCKET) {
    g_listen_sock = INVALID_SOCKET;
    closesocket(ls);
  }
}

/* ---- Public run ----------------------------------------------------- */

int fbsec_bus_run(const fbsec_bus_options_t   *opts,
                  const fbsec_bus_callbacks_t *cb,
                  void                         *vctx) {
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    fprintf(stderr, "bus_common: WSAStartup failed\n");
    return 1;
  }

  setvbuf(stdout, NULL, _IONBF, 0);
  for (size_t i = 0; i < (size_t)FBSEC_BUS_MAX_PEERS; ++i) {
    g_peers[i].sock   = INVALID_SOCKET;
    g_peers[i].in_use = false;
    g_peers[i].user   = NULL;
  }
  g_quiet = opts->quiet;
  resolve_color(opts->color_pref);
  g_frame_no = 0;
  g_shutdown_flag = 0;
  g_idle_timeout_ms = opts->idle_timeout_ms;

  if (start_listening(opts->port) != 0) {
    WSACleanup();
    return 1;
  }

  if (!g_quiet) {
    fprintf(stderr, "listening on 127.0.0.1:%d\n", opts->port);
  }

  if (!SetConsoleCtrlHandler(ctrl_handler, TRUE)) {
    fprintf(stderr, "warning: SetConsoleCtrlHandler failed (%lu)\n",
            (unsigned long)GetLastError());
  }

  run_event_loop(cb, vctx);
  shutdown_all(cb, vctx);
  WSACleanup();
  return 0;
}

/* EOF */
