/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_bus.c
 * @brief   SOFA CANopen FD bus simulator main.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 27-MAY-2026
 *
 * Thin variant entry point on top of bus_common. Carries CAN FD
 * frames over the carrier wire format defined by
 * `doc/fieldbus_sim_canopen_fd_spec.txt §3`. The variant supplies
 * only the per-frame parse / route / trace decode + per-peer
 * `SIM_PEER_ANNOUNCE` capture; bus_common owns accept loop, peer
 * table, select loop, CSV trace primitives, ANSI colour resolver,
 * and Ctrl-C lifecycle.
 *
 * Routing is broadcast (every CAN FD frame goes to every other
 * connected peer) via a dumb-relay model. Per-peer filtering by
 * node id / CAN ID happens inside the FD server / client.
 *
 * Optional CAN FD bridge (`--pcan CHANNEL`, or auto-prompt at
 * startup if a PCAN device is present): every USDO frame received
 * on a TCP peer is mirrored to the real bus via PCAN-Basic, and
 * every CAN FD frame received from PCAN is broadcast to all TCP
 * peers, so a hardware CANopen FD server / client can join the
 * simulated mesh on equal footing. Simulator-only frames
 * (SIM_PEER_ANNOUNCE / _LOSS / _FRAME_ERROR) are filtered in both
 * directions because they have no meaning on a real CAN bus.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "bus_common.h"

#include "fbsec_co_fd_frame.h"
#include "fbsec_co_fd_usdo.h"
#include "fbsec_co_fd_pcan.h"

/* ---- Compile-time configuration ---------------------------------------- */

#define DEFAULT_PORT       5810
#define VERSION_STR        "V1.2"
#define VERSION_DATE_STR   "27-MAY-2026"
#define SIM_NAME_MAX       30u
#define PCAN_IDLE_TIMEOUT_MS 5

/* Named mutex used to detect a second hub instance on the same PC.
   "Local\\" namespace -> per-session, which is what we want: each
   interactive login session gets its own hub. */
#define SINGLE_INSTANCE_MUTEX_NAME "Local\\SOFA_CO_FD_Bus_SingleInstance"

/* Action labels for the trace tint. */
#define AC_USDO_REQ      "rq"
#define AC_USDO_RSP      "rp"
#define AC_USDO_ABT      "ab"
#define AC_ANNOUNCE      "an"
#define AC_LOSS          "lo"
#define AC_ERROR         "er"
#define AC_NONE          "--"

/* ---- Per-peer state -------------------------------------------------- */

typedef struct fd_peer_t {
  bool     announced;
  uint8_t  role;          /* FBSEC_CO_FD_SIM_ROLE_SERVER / _CLIENT */
  uint8_t  node_id;
  uint8_t  name_len;
  uint8_t  name[SIM_NAME_MAX];
  uint16_t tcp_port;
} fd_peer_t;

#define MAX_PEERS         (FD_SETSIZE - 1)
static fd_peer_t g_peer_pool[MAX_PEERS];
static bool      g_peer_in_use[MAX_PEERS];

static fd_peer_t *alloc_peer(void) {
  for (size_t i = 0; i < (size_t)MAX_PEERS; ++i) {
    if (!g_peer_in_use[i]) {
      g_peer_in_use[i] = true;
      memset(&g_peer_pool[i], 0, sizeof g_peer_pool[i]);
      return &g_peer_pool[i];
    }
  }
  return NULL;
}

static void free_peer(fd_peer_t *p) {
  if (p == NULL) return;
  size_t idx = (size_t)(p - g_peer_pool);
  if (idx < (size_t)MAX_PEERS) g_peer_in_use[idx] = false;
}

/* ---- Trace formatting ----------------------------------------------- */

static const char *ansi_for_action(const char *ac) {
  if (!fbsec_bus_use_color() || ac == NULL) return "";
  if (strcmp(ac, AC_USDO_REQ) == 0) return fbsec_bus_ansi_blue();
  if (strcmp(ac, AC_USDO_RSP) == 0) return fbsec_bus_ansi_magenta();
  if (strcmp(ac, AC_USDO_ABT) == 0) return fbsec_bus_ansi_red();
  if (strcmp(ac, AC_ERROR)    == 0) return fbsec_bus_ansi_red();
  if (strcmp(ac, AC_ANNOUNCE) == 0) return fbsec_bus_ansi_dim();
  if (strcmp(ac, AC_LOSS)     == 0) return fbsec_bus_ansi_dim();
  if (strcmp(ac, AC_NONE)     == 0) return fbsec_bus_ansi_dim();
  return "";
}

/* Render a 0..255 node id as 2-hex; sentinel <0 or >0xFF renders "--". */
static void render_node(char out[3], int v) {
  if (v < 0 || v > 0xFF) {
    out[0] = '-'; out[1] = '-'; out[2] = '\0';
  } else {
    snprintf(out, 3, "%02X", (unsigned)v);
  }
}

static void format_payload(char *out, size_t outsize,
                           const uint8_t *payload, uint8_t plen) {
  size_t pos = 0;
  for (uint8_t i = 0; i < plen && pos + 4 < outsize; ++i) {
    int n = snprintf(out + pos, outsize - pos,
                     (i == 0) ? "%02X" : " %02X", (unsigned)payload[i]);
    if (n < 0 || (size_t)n >= outsize - pos) break;
    pos += (size_t)n;
  }
  out[pos] = '\0';
}

/* Compute (src, dst) node-id pair to display for this frame.
   @p origin is the TCP peer that delivered the frame (NULL when the
   frame came from PCAN or was synthesised by the bus). */
static void compute_src_dst(const fbsec_co_fd_frame_t *f,
                            const fd_peer_t           *origin,
                            int                       *src_out,
                            int                       *dst_out) {
  *src_out = -1;
  *dst_out = -1;
  uint32_t can_id = fbsec_co_fd_frame_id_value(f);

  /* USDO carries both ends in the wire: sender is the low 7 bits of
     the CAN ID; receiver is BUF[0]. The decode helper does both. */
  uint8_t                 sender = 0u;
  fbsec_co_fd_usdo_kind_t kind   = FBSEC_CO_FD_USDO_KIND_NONE;
  if (fbsec_co_fd_usdo_can_id_split(can_id, &sender, &kind)) {
    *src_out = (int)sender;
    fbsec_co_fd_usdo_pdu_t pdu;
    if (fbsec_co_fd_usdo_decode(f, &pdu) == FBSEC_CO_FD_USDO_DECODE_OK) {
      *dst_out = (int)pdu.dst_node_id;
    }
    (void)origin;
    return;
  }
  if (can_id == FBSEC_CO_FD_CAN_ID_SIM_PEER_ANNOUNCE
      || can_id == FBSEC_CO_FD_CAN_ID_SIM_PEER_LOSS) {
    /* payload[0] = role, payload[1] = announced node id. */
    if (f->len >= 2u) *src_out = (int)f->payload[1];
    return;
  }
  /* SIM_FRAME_ERROR and any other CAN ID: src/dst unknown. */
}

/**
 * @brief Emit one trace row for a CAN FD frame.
 *
 * Body layout: [%02X->%02X],0x%08X,<HH HH ...>
 * (src, dst, full 29-bit CAN ID, then payload as space-separated hex).
 */
static void emit_frame_trace(const fbsec_co_fd_frame_t *f,
                             const char                *ac,
                             const fd_peer_t           *origin) {
  char body[3 * FBSEC_CO_FD_PAYLOAD_MAX + 64];
  char payload_str[3 * FBSEC_CO_FD_PAYLOAD_MAX + 4];
  format_payload(payload_str, sizeof payload_str, f->payload, f->len);

  int src = -1, dst = -1;
  compute_src_dst(f, origin, &src, &dst);
  char src_s[3], dst_s[3];
  render_node(src_s, src);
  render_node(dst_s, dst);

  uint32_t can_id_value = fbsec_co_fd_frame_id_value(f);
  snprintf(body, sizeof body,
           "[%s->%s],0x%08X,%s",
           src_s, dst_s, (unsigned)can_id_value, payload_str);
  (void)ac;
  const char *col_start = ansi_for_action(ac);
  const char *col_end   = (col_start[0] != '\0') ? fbsec_bus_ansi_reset() : "";
  fbsec_bus_emit_trace_row(col_start, col_end, body);
}

static void emit_peer_event_trace(const char *label, uint16_t tcp_port) {
  char body[80];
  snprintf(body, sizeof body, "[--->--],,%s port=%u",
           label, (unsigned)tcp_port);
  const char *col_start = ansi_for_action(AC_NONE);
  const char *col_end   = (col_start[0] != '\0') ? fbsec_bus_ansi_reset() : "";
  fbsec_bus_emit_trace_row(col_start, col_end, body);
}

static void emit_trace_header(void) {
  printf("    #,        time,src->dst,    CAN ID,data\n");
}

/* ---- Frame-error helper --------------------------------------------- */

static void emit_carrier_error(uint8_t err_code) {
  fbsec_co_fd_frame_t f;
  fbsec_co_fd_frame_init(&f, FBSEC_CO_FD_CAN_ID_SIM_FRAME_ERROR, /*extended=*/true);
  f.payload[0] = err_code;
  f.len        = 1u;
  emit_frame_trace(&f, AC_ERROR, NULL);
}

/* ---- Announce capture / loss synthesis ------------------------------ */

static void record_announce(fd_peer_t *p, const fbsec_co_fd_frame_t *f) {
  p->announced = true;
  if (f->len >= 1u) p->role    = f->payload[0];
  if (f->len >= 2u) p->node_id = f->payload[1];

  size_t name_bytes = 0;
  if (f->len > 2u) {
    name_bytes = (size_t)(f->len - 2u);
    if (name_bytes > SIM_NAME_MAX) name_bytes = SIM_NAME_MAX;
    memcpy(p->name, &f->payload[2], name_bytes);
  }
  p->name_len = (uint8_t)name_bytes;
}

static void fill_peer_loss(const fd_peer_t *p, fbsec_co_fd_frame_t *f_out) {
  fbsec_co_fd_frame_init(f_out, FBSEC_CO_FD_CAN_ID_SIM_PEER_LOSS, /*extended=*/true);
  f_out->payload[0] = p->role;
  f_out->payload[1] = p->node_id;
  if (p->name_len > 0u) memcpy(&f_out->payload[2], p->name, p->name_len);
  f_out->len = (uint8_t)(2u + p->name_len);
}

/* ---- Read one carrier frame off a peer socket ----------------------- */

static int read_one_frame(SOCKET sock, fbsec_co_fd_frame_t *f) {
  uint8_t header[FBSEC_CO_FD_HEADER_SIZE];
  int rr = fbsec_bus_recv_exact(sock, header, sizeof header);
  if (rr == 0) return 0;     /* graceful EOF */
  if (rr < 0)  return -1;

  size_t expected_payload = 0;
  fbsec_co_fd_parse_t pr = fbsec_co_fd_frame_parse_header(
      header, sizeof header, f, &expected_payload);
  if (pr != FBSEC_CO_FD_PARSE_OK) {
    /* Map parse errors to carrier error codes. */
    uint8_t err =
        (pr == FBSEC_CO_FD_PARSE_LEN_TOO_BIG)    ? FBSEC_CO_FD_SIM_ERR_LEN_TOO_BIG
      : (pr == FBSEC_CO_FD_PARSE_RESERVED_CANID) ? FBSEC_CO_FD_SIM_ERR_RESERVED_CANID
      : (pr == FBSEC_CO_FD_PARSE_RESERVED_FLAGS) ? FBSEC_CO_FD_SIM_ERR_RESERVED_FLAGS
      :                                            FBSEC_CO_FD_SIM_ERR_SHORT_READ;
    emit_carrier_error(err);
    return -1;
  }
  if (expected_payload > 0u) {
    rr = fbsec_bus_recv_exact(sock, f->payload, expected_payload);
    if (rr == 0) return 0;
    if (rr < 0) {
      emit_carrier_error(FBSEC_CO_FD_SIM_ERR_SHORT_READ);
      return -1;
    }
  }
  return 1;
}

/* ---- PCAN bridge helpers -------------------------------------------- */

/* True for CAN IDs that are simulator-internal control events; never
   forwarded onto a real CAN FD bus. */
static bool can_id_is_sim_only(uint32_t can_id_value) {
  return can_id_value == FBSEC_CO_FD_CAN_ID_SIM_PEER_ANNOUNCE
      || can_id_value == FBSEC_CO_FD_CAN_ID_SIM_PEER_LOSS
      || can_id_value == FBSEC_CO_FD_CAN_ID_SIM_FRAME_ERROR;
}

/* TCP -> PCAN. Called after every frame relayed to TCP peers. */
static void pcan_bridge_send_if_open(const fbsec_co_fd_frame_t *f) {
  if (!fbsec_pcan_is_open()) return;
  uint32_t can_id_value = fbsec_co_fd_frame_id_value(f);
  if (can_id_is_sim_only(can_id_value)) return;
  bool extended = fbsec_co_fd_frame_is_extended(f);
  bool brs      = (f->flags & FBSEC_CO_FD_FLAG_BRS) != 0u;
  (void)fbsec_pcan_write_fd(can_id_value, extended, brs, f->payload, f->len);
}

/* Visitor for fbsec_bus_each_peer: send the serialized frame to one peer. */
typedef struct broadcast_ctx_t {
  const uint8_t *bytes;
  size_t         n;
} broadcast_ctx_t;

static void send_to_peer_visitor(SOCKET sock, void *peer_state, void *cb_arg) {
  (void)peer_state;
  const broadcast_ctx_t *bc = (const broadcast_ctx_t *)cb_arg;
  (void)fbsec_bus_send_all(sock, bc->bytes, bc->n);
}

/* ---- bus_common callbacks ------------------------------------------- */

static void *cb_on_peer_accepted(SOCKET sock, uint16_t tcp_port, void *vctx) {
  (void)sock;
  (void)vctx;
  fd_peer_t *p = alloc_peer();
  if (p == NULL) return NULL;
  p->tcp_port = tcp_port;
  emit_peer_event_trace("Peer connected", tcp_port);
  return p;
}

static int cb_on_peer_readable(SOCKET sock, void *peer_state, void *vctx) {
  (void)vctx;
  fd_peer_t *peer = (fd_peer_t *)peer_state;

  fbsec_co_fd_frame_t f;
  int rr = read_one_frame(sock, &f);
  if (rr <= 0) return -1;

  uint32_t can_id = fbsec_co_fd_frame_id_value(&f);

  /* SIM control events: ANNOUNCE valid from peers; LOSS / FRAME_ERROR
     are simulator-only and rejected if seen on the wire. */
  if (can_id == FBSEC_CO_FD_CAN_ID_SIM_PEER_ANNOUNCE) {
    if (peer != NULL && peer->announced) {
      emit_carrier_error(FBSEC_CO_FD_SIM_ERR_DUP_ANNOUNCE);
      return -1;
    }
    if (peer != NULL) record_announce(peer, &f);
    emit_frame_trace(&f, AC_ANNOUNCE, peer);
    uint8_t buf[FBSEC_CO_FD_WIRE_MAX];
    size_t  n = 0;
    if (fbsec_co_fd_frame_serialize(&f, buf, sizeof buf, &n)) {
      fbsec_bus_relay_bytes(sock, buf, n);
    }
    /* SIM_PEER_ANNOUNCE never goes onto the real bus. */
    return 0;
  }
  if (can_id == FBSEC_CO_FD_CAN_ID_SIM_PEER_LOSS
      || can_id == FBSEC_CO_FD_CAN_ID_SIM_FRAME_ERROR) {
    emit_carrier_error(FBSEC_CO_FD_SIM_ERR_UNKNOWN_CANID);
    return -1;
  }

  /* USDO frames: validate PDU, then trace + relay + bridge. */
  uint8_t                 sender_unused = 0u;
  fbsec_co_fd_usdo_kind_t kind          = FBSEC_CO_FD_USDO_KIND_NONE;
  if (fbsec_co_fd_usdo_can_id_split(can_id, &sender_unused, &kind)) {
    fbsec_co_fd_usdo_pdu_t pdu;
    if (fbsec_co_fd_usdo_decode(&f, &pdu) != FBSEC_CO_FD_USDO_DECODE_OK) {
      emit_carrier_error(FBSEC_CO_FD_SIM_ERR_USDO_MALFORMED);
      return -1;
    }
    /* Direction-specific tint: REQUEST is "rq"; RESPONSE-prefix splits
       into "ab" (cmd 0x80) versus "rp" (other cmd values). */
    const char *ac;
    if (kind == FBSEC_CO_FD_USDO_KIND_REQUEST) {
      ac = AC_USDO_REQ;
    } else if (pdu.cmd == FBSEC_CO_FD_USDO_CMD_ABORT) {
      ac = AC_USDO_ABT;
    } else {
      ac = AC_USDO_RSP;
    }
    emit_frame_trace(&f, ac, peer);
    uint8_t buf[FBSEC_CO_FD_WIRE_MAX];
    size_t  n = 0;
    if (fbsec_co_fd_frame_serialize(&f, buf, sizeof buf, &n)) {
      fbsec_bus_relay_bytes(sock, buf, n);
    }
    pcan_bridge_send_if_open(&f);
    return 0;
  }

  /* Unknown CAN ID. */
  emit_carrier_error(FBSEC_CO_FD_SIM_ERR_UNKNOWN_CANID);
  return -1;
}

static void cb_on_peer_dropped(SOCKET sock, void *peer_state, void *vctx) {
  (void)sock;
  (void)vctx;
  fd_peer_t *peer = (fd_peer_t *)peer_state;
  if (peer == NULL) return;
  emit_peer_event_trace("Peer disconnected", peer->tcp_port);
  if (peer->announced) {
    fbsec_co_fd_frame_t loss;
    fill_peer_loss(peer, &loss);
    /* origin = peer (so the trace shows the dropped peer's node id as src). */
    emit_frame_trace(&loss, AC_LOSS, peer);
    uint8_t buf[FBSEC_CO_FD_WIRE_MAX];
    size_t  n = 0;
    if (fbsec_co_fd_frame_serialize(&loss, buf, sizeof buf, &n)) {
      fbsec_bus_relay_bytes(sock, buf, n);
    }
  }
  free_peer(peer);
}

/* PCAN -> TCP. Drains the PCAN receive queue on idle ticks. */
static void cb_on_idle_tick(void *vctx) {
  (void)vctx;
  if (!fbsec_pcan_is_open()) return;
  for (;;) {
    uint32_t can_id_value = 0;
    bool     extended     = false;
    bool     brs          = false;
    uint8_t  data[FBSEC_CO_FD_PAYLOAD_MAX];
    uint8_t  len          = 0;
    if (!fbsec_pcan_read_fd(&can_id_value, &extended, &brs, data, &len)) {
      break;
    }
    if (can_id_is_sim_only(can_id_value)) continue;
    if (len > FBSEC_CO_FD_PAYLOAD_MAX) continue;

    fbsec_co_fd_frame_t f;
    fbsec_co_fd_frame_init(&f, can_id_value, extended);
    f.flags = brs ? FBSEC_CO_FD_FLAG_BRS : 0u;
    if (len > 0u) memcpy(f.payload, data, len);
    f.len = len;

    if (fbsec_co_fd_frame_validate(&f) != FBSEC_CO_FD_VALID_OK) continue;

    /* Tint per direction. PCAN-side frames do not go through the
       per-peer announce mechanism, so the USDO tag is derived purely
       from CAN ID + cmd byte. */
    const char             *ac     = AC_NONE;
    uint8_t                 sender = 0u;
    fbsec_co_fd_usdo_kind_t kind   = FBSEC_CO_FD_USDO_KIND_NONE;
    if (fbsec_co_fd_usdo_can_id_split(can_id_value, &sender, &kind)) {
      if (kind == FBSEC_CO_FD_USDO_KIND_REQUEST) {
        ac = AC_USDO_REQ;
      } else if (f.len >= 2u && f.payload[1] == FBSEC_CO_FD_USDO_CMD_ABORT) {
        ac = AC_USDO_ABT;
      } else {
        ac = AC_USDO_RSP;
      }
    }

    /* origin = NULL: src column renders from the USDO CAN ID via
       compute_src_dst (PCAN frames have no peer-announce entry). */
    emit_frame_trace(&f, ac, NULL);

    uint8_t buf[FBSEC_CO_FD_WIRE_MAX];
    size_t  n = 0;
    if (!fbsec_co_fd_frame_serialize(&f, buf, sizeof buf, &n)) continue;
    broadcast_ctx_t bc = { .bytes = buf, .n = n };
    fbsec_bus_each_peer(INVALID_SOCKET, send_to_peer_visitor, &bc);
  }
}

/* ---- main ------------------------------------------------------------ */

static void print_banner(void) {
  printf("\n");
  printf("SOFA CANopen FD Bus Simulator, version %s of %s\n",
         VERSION_STR, VERSION_DATE_STR);
  printf("by EmSA (www.Em-SA.com)\n");
  printf("\n");
}

static void print_usage(FILE *f) {
  fprintf(f,
    "usage: fbsec_co_fd_bus [--port N] [--quiet] [--color|--no-color]\n"
    "                       [--pcan CHANNEL | --no-pcan] [--help]\n"
    "\n"
    "  --port N        TCP port to listen on (default %d).\n"
    "  --quiet         Suppress trace on stdout.\n"
    "  --color         Force ANSI colour on (default: auto, on if TTY).\n"
    "  --no-color      Force ANSI colour off.\n"
    "  --pcan CHANNEL  Bridge to PCAN-Basic at the named channel\n"
    "                  (e.g. PCAN_USBBUS1, PCAN_PCIBUS1, or 0xNN).\n"
    "                  Bitrate fixed at 500k arbitration / 2M data.\n"
    "  --no-pcan       Suppress the auto-probe prompt at startup.\n"
    "  --help          Print this and exit 0.\n",
    DEFAULT_PORT);
}

/* Block-read one trimmed line from stdin (max 31 chars + NUL). Returns
   the line or NULL on EOF. */
static char *read_line(char *buf, size_t cap) {
  if (fgets(buf, (int)cap, stdin) == NULL) return NULL;
  size_t n = strlen(buf);
  while (n > 0 && (buf[n-1] == '\r' || buf[n-1] == '\n' ||
                   buf[n-1] == ' '  || buf[n-1] == '\t')) {
    buf[--n] = '\0';
  }
  return buf;
}

/* Single-instance guard. Tries to create a named mutex; if it already
   exists, another hub is running. Prompts the user to abort or
   continue anyway. Returns true to proceed, false to abort.

   The handle is intentionally never closed: it lives for the process
   lifetime and the OS releases it on exit. */
static bool check_single_instance(void) {
  HANDLE h = CreateMutexA(NULL, FALSE, SINGLE_INSTANCE_MUTEX_NAME);
  if (h == NULL) {
    /* Mutex creation failed entirely (very unusual). Don't block
       startup over a diagnostic feature. */
    return true;
  }
  if (GetLastError() != ERROR_ALREADY_EXISTS) {
    return true;
  }
  printf("Another SOFA CANopen FD Bus instance appears to be running on this PC.\n");
  printf("Only one hub is supported per machine; a second instance will fail to\n");
  printf("bind the listen port unless --port is changed.\n");
  printf("Start this instance anyway? (y/n): ");
  fflush(stdout);
  char line[16];
  if (read_line(line, sizeof line) == NULL) {
    return false;
  }
  if (line[0] != 'y' && line[0] != 'Y') {
    return false;
  }
  printf("\n");
  return true;
}

/* Returns a handle to open, or PCAN_NONEBUS if the user declined / no
   device was found / PCAN-Basic is not installed. */
static uint16_t pcan_probe_and_prompt(void) {
  if (!fbsec_pcan_loaded()) return PCAN_NONEBUS;
  uint16_t avail[8];
  size_t found = fbsec_pcan_probe_available(avail, sizeof avail / sizeof avail[0]);
  if (found == 0) return PCAN_NONEBUS;
  uint16_t pick = avail[0];
  printf("PCAN device on %s detected. Connect at 500k/2M? (y/n): ",
         fbsec_pcan_handle_name(pick));
  fflush(stdout);
  char line[16];
  if (read_line(line, sizeof line) == NULL) return PCAN_NONEBUS;
  if (line[0] != 'y' && line[0] != 'Y') return PCAN_NONEBUS;
  return pick;
}

int main(int argc, char **argv) {
  fbsec_bus_options_t opts = {
    .port            = DEFAULT_PORT,
    .quiet           = false,
    .color_pref      = FBSEC_BUS_COLOR_AUTO,
    .idle_timeout_ms = 0
  };

  bool        pcan_explicit = false;   /* --pcan CHANNEL given */
  bool        pcan_disabled = false;   /* --no-pcan given */
  uint16_t    pcan_handle   = PCAN_NONEBUS;

  for (int i = 1; i < argc; ++i) {
    const char *a = argv[i];
    if (strcmp(a, "--help") == 0) {
      print_usage(stdout);
      return 0;
    } else if (strcmp(a, "--quiet") == 0) {
      opts.quiet = true;
    } else if (strcmp(a, "--color") == 0) {
      opts.color_pref = FBSEC_BUS_COLOR_ALWAYS;
    } else if (strcmp(a, "--no-color") == 0) {
      opts.color_pref = FBSEC_BUS_COLOR_NEVER;
    } else if (strcmp(a, "--no-pcan") == 0) {
      pcan_disabled = true;
    } else if (strcmp(a, "--pcan") == 0 && (i + 1) < argc) {
      const char *val = argv[++i];
      uint16_t h = PCAN_NONEBUS;
      if (!fbsec_pcan_parse_channel(val, &h)) {
        fprintf(stderr, "--pcan: unrecognized channel '%s'\n", val);
        return 2;
      }
      pcan_explicit = true;
      pcan_handle   = h;
    } else if (strcmp(a, "--port") == 0 && (i + 1) < argc) {
      const char *val = argv[++i];
      char *endp = NULL;
      long v = strtol(val, &endp, 0);
      if (endp == val || *endp != '\0' || v < 1 || v > 65535) {
        fprintf(stderr, "--port: invalid value '%s'\n", val);
        return 2;
      }
      opts.port = (int)v;
    } else {
      fprintf(stderr, "unknown argument: '%s'\n", a);
      print_usage(stderr);
      return 2;
    }
  }

  print_banner();

  if (!check_single_instance()) {
    fprintf(stderr, "Aborted: another SOFA CANopen FD Bus instance is running.\n");
    return 1;
  }

  for (size_t i = 0; i < (size_t)MAX_PEERS; ++i) g_peer_in_use[i] = false;

  /* PCAN bring-up: explicit --pcan wins; otherwise auto-probe unless
     --no-pcan suppresses the prompt. */
  if (pcan_explicit) {
    if (!fbsec_pcan_load()) {
      fprintf(stderr, "--pcan: PCANBasic.dll not found or missing FD entry points.\n");
      return 1;
    }
    if (!fbsec_pcan_open_500k_2m(pcan_handle)) {
      fprintf(stderr, "--pcan: failed to open %s at 500k/2M.\n",
              fbsec_pcan_handle_name(pcan_handle));
      fbsec_pcan_unload();
      return 1;
    }
    fprintf(stderr, "PCAN bridge: %s @ 500k/2M\n",
            fbsec_pcan_handle_name(pcan_handle));
  } else if (!pcan_disabled) {
    if (fbsec_pcan_load()) {
      fprintf(stderr, "PCAN: PCANBasic.dll loaded; scanning channels...\n");
      uint16_t pick = pcan_probe_and_prompt();
      if (pick != PCAN_NONEBUS) {
        if (fbsec_pcan_open_500k_2m(pick)) {
          fprintf(stderr, "PCAN bridge: %s @ 500k/2M\n",
                  fbsec_pcan_handle_name(pick));
        }
      }
    } else {
      fprintf(stderr, "PCAN: PCANBasic.dll not present; skipping bridge.\n");
    }
  }

  if (fbsec_pcan_is_open()) {
    opts.idle_timeout_ms = PCAN_IDLE_TIMEOUT_MS;
  }

  fbsec_bus_callbacks_t cb = {
    .on_peer_accepted = cb_on_peer_accepted,
    .on_peer_readable = cb_on_peer_readable,
    .on_peer_dropped  = cb_on_peer_dropped,
    .on_idle_tick     = cb_on_idle_tick
  };

  if (!opts.quiet) emit_trace_header();

  int rc = fbsec_bus_run(&opts, &cb, NULL);

  fbsec_pcan_close();
  fbsec_pcan_unload();
  return rc;
}

/* EOF */
