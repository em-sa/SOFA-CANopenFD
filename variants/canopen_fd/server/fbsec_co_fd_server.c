/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_server.c
 * @brief   SOFA CANopen FD, USDO-responder server main.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 20-JUL-2026
 *
 * Thin variant entry point: connect to the CAN FD bus simulator via
 * `fbsec_co_fd_carrier`, send `SIM_PEER_ANNOUNCE` (role server),
 * pull CAN FD frames in a blocking recv loop, decode the USDO PDU,
 * filter by dst_node_id, hand the expedited data block to
 * @ref fbsec_server_dispatch_request, and let the send_reply
 * callback wrap the dispatch result back into a USDO response (or
 * abort) frame on the bus.
 *
 * All variant-agnostic logic (OD setup, port hooks, key store,
 * dispatch glue, trace formatter, CLI helpers) lives in
 * `server_common/`. The variant supplies only:
 *
 *   - the CAN FD carrier connect / send_announce sequence,
 *   - the recv loop that pulls one CAN FD frame and routes by CAN ID,
 *   - the send_reply callback that picks the right USDO response cmd
 *     based on the request cmd captured at recv time.
 *
 * See doc/fieldbus_sim_canopen_fd_spec.txt for the wire contract.
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

#include "fbsec_secure_od.h"

#include "server_common_cfg.h"
#include "server_common_cli.h"
#include "server_common_const_od.h"
#include "server_common_dispatch.h"
#include "server_common_hooks.h"
#include "server_common_keys.h"
#include "server_common_lifecycle.h"
#include "server_common_od.h"
#include "server_common_trace.h"

#include "fbsec_descriptor.h"

#if FBSEC_FEATURE_ASYM
#include "server_common_asym.h"
#endif

#include "fbsec_co_fd_addr.h"
#include "fbsec_co_fd_carrier.h"
#include "fbsec_co_fd_frame.h"
#include "fbsec_co_fd_usdo.h"

/* ---- Compile-time configuration ---------------------------------------- */

#define DEFAULT_BUS_HOST     "127.0.0.1"
#define DEFAULT_BUS_PORT     5810
#define DEFAULT_NODE_ID      0x05u
#define DEFAULT_NAME         "fbsec_co_fd_server"
#define VERSION_STR          "V1.1"
#define VERSION_DATE_STR     "22-JUL-2026"
#define EXEC_NAME            "fbsec_co_fd_server"
#define BANNER_NAME          "SOFA CANopen FD Server"

/* SIM_PEER_ANNOUNCE name buffer cap. */
#define SIM_NAME_MAX 30u

/* The CANopen FD USDO codec carries the requester's node id in the CAN
   ID's low 7 bits (see doc/fieldbus_sim_canopen_fd_spec.txt §4); the
   server uses that as fbsec_sod_dispatch's @c client_dev parameter so
   the per-client armed-slot bookkeeping discriminates real per-client
   sessions on a multi-client bus. */

/* ---- Variant-local config + state ------------------------------------- */

typedef struct {
  fbsec_server_cfg_t common;
  uint8_t  node_id;            /* CANopen node id 1..127, mirrored into device_id */
  char     bus_host[64];
  int      bus_port;
  char     name[SIM_NAME_MAX + 1];
} server_variant_cfg_t;

static fbsec_co_fd_carrier_t g_carrier;
static volatile LONG         g_shutdown = 0;
static server_variant_cfg_t  g_cfg;

/**
 * @brief Per-request context the recv loop hands to send_reply via
 *        the dispatch's @c user pointer.
 *
 * The reply USDO command depends on the request command:
 *   - download_req (0x01) -> download_resp (0x21) on success / DEFER
 *   - upload_req   (0x11) -> upload_resp   (0x31) on success
 *   - either                -> abort (7Fh) on non-zero status
 *
 * The recv loop captures requester / session / index / sub / cmd from
 * the inbound USDO PDU before invoking dispatch; send_reply uses them
 * to address the response back to the requester.
 */
typedef struct {
  uint8_t  src_node_id;   /**< requester (from request CAN ID low 7 bits) */
  uint8_t  req_cmd;
  uint8_t  session;
  uint16_t index;
  uint8_t  subindex;
} request_ctx_t;

/* ---- Forward declarations --------------------------------------------- */

static int  parse_args(int argc, char **argv);
static void print_usage(FILE *f);
static int  parse_bus_arg(const char *s);

static int  bus_connect(void);
static int  send_announce(void);

static BOOL WINAPI ctrl_handler(DWORD ctrl_type);

static void run_dispatch_loop(void);

static int  send_reply_cb(void *user, uint16_t to_dev, uint32_t data_id,
                          fbsec_abort_t status, const uint8_t *data,
                          uint16_t data_len);

/* ---- main -------------------------------------------------------------- */

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);

  /* Defaults. */
  memset(&g_cfg, 0, sizeof g_cfg);
  g_cfg.common.color_pref = FBSEC_SERVER_COLOR_AUTO;
  g_cfg.node_id           = (uint8_t)DEFAULT_NODE_ID;
  memcpy(g_cfg.bus_host, DEFAULT_BUS_HOST, sizeof DEFAULT_BUS_HOST);
  g_cfg.bus_port = DEFAULT_BUS_PORT;
  memcpy(g_cfg.name, DEFAULT_NAME, sizeof DEFAULT_NAME);

  int rc = parse_args(argc, argv);
  if (rc == -1) return 0;
  if (rc != 0)  return 1;

  /* Mirror node id into the SOFA AAD device_id field per the
     "OD Entry Placement" section of the Integration Guide chapter in
     doc/EmSA-UM-105-COP FBsec CANopen V01.docx. */
  g_cfg.common.my_dev = (uint16_t)g_cfg.node_id;

  bool use_color = fbsec_server_cli_resolve_color(g_cfg.common.color_pref);
  fbsec_server_trace_set_quiet(g_cfg.common.quiet);
  fbsec_server_trace_set_use_color(use_color);

  fbsec_server_cli_print_banner(BANNER_NAME, VERSION_STR, VERSION_DATE_STR);

  if (fbsec_co_fd_carrier_global_init() != FBSEC_CO_FD_CARRIER_OK) {
    fprintf(stderr, EXEC_NAME ": WSAStartup failed\n");
    return 1;
  }

  fbsec_co_fd_carrier_init(&g_carrier);
  if (bus_connect() != 0) {
    fbsec_co_fd_carrier_global_shutdown();
    return 1;
  }
  if (send_announce() != 0) {
    fbsec_co_fd_carrier_close(&g_carrier);
    fbsec_co_fd_carrier_global_shutdown();
    return 1;
  }

  if (fbsec_server_od_init(g_cfg.common.my_dev, g_cfg.common.key_file_path,
                           g_cfg.common.od_file_path,
                           g_cfg.common.demo_keys) != 0) {
    fbsec_co_fd_carrier_close(&g_carrier);
    fbsec_co_fd_carrier_global_shutdown();
    return 1;
  }

  fprintf(stderr, "Object Dictionary (USDO mapped):\n");
  fprintf(stderr,
          "  application data:\n"
          "    idx 0x%04X sub 0x00  SRD 32-bit u_int (auto-increments)\n"
          "    idx 0x%04X sub 0x00  SWR 32-bit u_int (mirrors into SRD)\n"
          "    idx 0x%04X sub 0x00  SWR 16-byte array (last write)\n",
          (unsigned)(FBSEC_SERVER_ENTRY_RD_DATA_ID >> 16),
          (unsigned)(FBSEC_SERVER_ENTRY_WR_DATA_ID >> 16),
          (unsigned)(FBSEC_SERVER_ENTRY_SWR_DATA_ID >> 16));
  {
    uint8_t n = fbsec_const_od_count();
    if (n > 0u) {
      uint8_t p;
      fprintf(stderr, "  constant unsecured data (--od-file):\n");
      for (p = 0u; p < n; ++p) {
        uint16_t idx = 0u;
        uint16_t len = 0u;
        uint8_t  sub = 0u;
        uint8_t  b;
        const uint8_t *d = fbsec_const_od_at(p, &idx, &sub, &len);
        fprintf(stderr, "    idx 0x%04X sub 0x%02X  %u bytes:",
                (unsigned)idx, (unsigned)sub, (unsigned)len);
        for (b = 0u; (d != NULL) && (b < len); ++b) {
          fprintf(stderr, " %02X", d[b]);
        }
        fprintf(stderr, "\n");
      }
    }
  }
  fprintf(stderr,
          "  AEAD security objects (CiA 720):\n"
          "    idx 0xC000/0xC001    capability / status descriptors\n"
          "    idx 0xC010 sub 0x00  session salt (present, NOT_IMPLEMENTED)\n"
          "    idx 0xC011 sub 0x00  AEAD key ids (slot count + per-slot id)\n");
  if (fbsec_sod_find_entry(FBSEC_SERVER_ENTRY_SRD_DATA_ID) != NULL) {
    fprintf(stderr,
          "    idx 0xC018 sub 0x00  SRD 16-byte 1018h identity (AEAD)\n");
  } else {
    fprintf(stderr,
          "    idx 0xC018 (identity) absent: pass --od-file with a 1018h quad\n");
  }
  fprintf(stderr,
          "    idx 0xC01F sub 0x00  SECURE_WO key set: rolling-key install "
          "ladder (token->Prov->Integrator->Operator)\n");
#if FBSEC_FEATURE_ASYM
  fprintf(stderr,
          "  RPK security objects (CiA 720, Ed25519 signed):\n"
          "    idx 0xC020 sub 1..3  ownership: epoch / voucher / LDevID export\n"
          "    idx 0xC021 sub 0x00  public keys (manufacturer, integrator)\n"
          "    idx 0xC022 sub 0x00  public key types\n"
          "    idx 0xC028 sub 0x00  signed identity read\n"
          "    idx 0xC02F sub 0x00  provisioning key install (signed)\n"
          "    idx 0xC042 sub 1..2  generic secure access (signed read/write)\n"
          "    idx 0xC049 sub 0x00  secure function command (signed)\n"
          "    idx 0x%04X sub 0x00  RPK read twin  (reached via C042h:01)\n"
          "    idx 0x%04X sub 0x00  RPK write twin (reached via C042h:02)\n",
          (unsigned)(FBSEC_SERVER_ENTRY_RPK_RD_DATA_ID >> 16),
          (unsigned)(FBSEC_SERVER_ENTRY_RPK_WR_DATA_ID >> 16));
#endif
  fprintf(stderr,
          "key store: keyid 1 (Provisioning Session Key) %s, "
          "keyid 2 (Integrator Session Key) %s, "
          "keyid 3 (Operator Session Key) %s\n",
          fbsec_sod_has_key(FBSEC_DEMO_KEYID_PROVISIONING) ? "loaded" : "absent",
          fbsec_sod_has_key(FBSEC_DEMO_KEYID_INTEGRATOR)   ? "loaded" : "absent",
          fbsec_sod_has_key(FBSEC_DEMO_KEYID_OPERATOR)     ? "loaded" : "absent");

  /* Live commissioning state: how this node presents on the bus right now,
     and, when uncommissioned, how it can be claimed. */
  {
    uint8_t      comm = fbsec_server_lifecycle_commissioning();
    fbsec_caps_t caps;
    fbsec_descriptor_build_caps(0u, &caps);
    fprintf(stderr, "commissioning (C001h:01h): %s\n",
            (comm == FBSEC_STAT_COMMISSIONED) ? "commissioned / owned"
                                              : "uncommissioned");
    fprintf(stderr, "handover gate (C000h:06h):%s%s%s\n",
            ((caps.handover_model & FBSEC_DESC_HANDOVER_TOFU) != 0u)    ? " TOFU" : "",
            ((caps.handover_model & FBSEC_DESC_HANDOVER_TOKEN) != 0u)   ? " token" : "",
            ((caps.handover_model & FBSEC_DESC_HANDOVER_VOUCHER) != 0u) ? " voucher" : "");
#if FBSEC_FEATURE_ASYM
    fprintf(stderr, "RPK identity: IDevID %s, owner epoch %lu, %s\n",
            fbsec_server_asym_idevid_present() ? "present" : "absent",
            (unsigned long)fbsec_server_asym_owner_epoch(),
            fbsec_server_asym_is_uncommissioned() ? "not yet claimed" : "owned");
    if (comm != FBSEC_STAT_COMMISSIONED) {
      fprintf(stderr,
              "  -> uncommissioned: from the client, use the L) lifecycle submenu\n"
              "     to claim ownership (voucher) and install the Provisioning key\n");
    }
#endif
  }
  fbsec_server_trace_print_legend();

  if (!SetConsoleCtrlHandler(ctrl_handler, TRUE)) {
    fprintf(stderr, "warning: SetConsoleCtrlHandler failed (%lu)\n",
            (unsigned long)GetLastError());
  }

  run_dispatch_loop();

  fbsec_co_fd_carrier_close(&g_carrier);
  fbsec_co_fd_carrier_global_shutdown();
  return 0;
}

/* ---- Argv & banner ----------------------------------------------------- */

static int parse_args(int argc, char **argv) {
  int i = 1;
  while (i < argc) {
    fbsec_server_cli_result_t cr = fbsec_server_cli_try_common_flag(
        &i, argc, argv, &g_cfg.common, EXEC_NAME);
    if (cr == FBSEC_SERVER_CLI_HELP)  { print_usage(stdout); return -1; }
    if (cr == FBSEC_SERVER_CLI_ERROR) { return 1; }
    if (cr == FBSEC_SERVER_CLI_HANDLED) { continue; }

    const char *a = argv[i];
    if (strcmp(a, "--bus") == 0 && (i + 1) < argc) {
      if (parse_bus_arg(argv[i + 1]) != 0) {
        fprintf(stderr, EXEC_NAME ": invalid --bus value\n");
        return 1;
      }
      i += 2;
    } else if (strcmp(a, "--node") == 0 && (i + 1) < argc) {
      uint32_t v;
      if (fbsec_server_cli_parse_u32(argv[i + 1], &v) != 0
          || v == 0u || v > FBSEC_CO_FD_NODE_ID_MAX) {
        fprintf(stderr, EXEC_NAME ": invalid --node (1..%u)\n",
                (unsigned)FBSEC_CO_FD_NODE_ID_MAX);
        return 1;
      }
      g_cfg.node_id = (uint8_t)v;
      i += 2;
    } else if (strcmp(a, "--name") == 0 && (i + 1) < argc) {
      const char *n = argv[i + 1];
      size_t nl = strlen(n);
      if (nl > SIM_NAME_MAX) {
        fprintf(stderr, EXEC_NAME ": --name longer than %u bytes\n",
                (unsigned)SIM_NAME_MAX);
        return 1;
      }
      memcpy(g_cfg.name, n, nl);
      g_cfg.name[nl] = '\0';
      i += 2;
    } else {
      fprintf(stderr, EXEC_NAME ": unknown option '%s'\n", a);
      print_usage(stderr);
      return 1;
    }
  }
  return 0;
}

static void print_usage(FILE *f) {
  fprintf(f,
    "usage: " EXEC_NAME " [options]\n"
    "\n"
    "  --bus HOST:PORT     CAN FD bus simulator address "
                          "(default %s:%d)\n"
    "  --node N            CANopen node id 1..127 "
                          "(default 0x%02X);\n"
    "                      mirrored into SOFA device_id AAD field\n"
    "  --name STR          peer-announce name "
                          "(default \"%s\", max %u bytes)\n"
    "  --verbose           extra stderr informational lines\n"
    "  --quiet             suppress per-request log on stdout\n"
    "  --color             force ANSI colour on (default: auto-on if TTY)\n"
    "  --no-color          force ANSI colour off (e.g. when piping to a file)\n"
    "  --key-file FILE     load session keys from FILE and boot Operational\n"
    "                      (one row: '<keyid> <label> <hex> [<u32-id>]')\n"
    "  --demo-keys         fill any unset key slots with the built-in demo\n"
    "                      keys and boot Operational; without keys the device\n"
    "                      boots Uncommissioned (new-from-manufacturer)\n"
    "  --od-file FILE      load constant unsecured OD entries from FILE\n"
    "                      (rows '<index> <sub> <len> <data...>'; supplies\n"
    "                      the 1018h identity that C018h serves)\n"
    "  --help              print this and exit 0\n"
    "\n"
    "Object table (USDO mapped):\n"
    "  application data:\n"
    "    idx 0x2020 sub 0x00  SECURE_RO  4 bytes\n"
    "    idx 0x2010 sub 0x00  SECURE_WO  4 bytes  (shadows into 0x2020)\n"
    "    idx 0x2016 sub 0x00  SECURE_WO 16 bytes\n"
    "  AEAD security objects (CiA 720):\n"
    "    idx 0xC000/0xC001    capability / status descriptors\n"
    "    idx 0xC010 sub 0x00  session salt (present, NOT_IMPLEMENTED)\n"
    "    idx 0xC011 sub 0x00  AEAD key ids\n"
    "    idx 0xC018 sub 0x00  SECURE_RO 16 bytes  1018h identity (needs --od-file)\n"
    "    idx 0xC01F sub 0x00  SECURE_WO key set (rolling-key install ladder)\n"
#if FBSEC_FEATURE_ASYM
    "  RPK security objects (CiA 720, Ed25519 signed):\n"
    "    idx 0xC020 sub 1..3  ownership: epoch / voucher / LDevID export\n"
    "    idx 0xC021 sub 0x00  public keys (manufacturer, integrator)\n"
    "    idx 0xC022 sub 0x00  public key types\n"
    "    idx 0xC028 sub 0x00  signed identity read\n"
    "    idx 0xC02F sub 0x00  provisioning key install (signed)\n"
    "    idx 0xC042 sub 1..2  generic secure access (signed read/write)\n"
    "    idx 0xC049 sub 0x00  secure function command (signed)\n"
    "    idx 0x2021 sub 0x00  RPK read twin  (reached via C042h:01)\n"
    "    idx 0x2017 sub 0x00  RPK write twin (reached via C042h:02)\n"
#endif
    ,
    DEFAULT_BUS_HOST, DEFAULT_BUS_PORT,
    (unsigned)DEFAULT_NODE_ID, DEFAULT_NAME,
    (unsigned)SIM_NAME_MAX);
}

static int parse_bus_arg(const char *s) {
  if (s == NULL || *s == '\0') return -1;
  const char *colon = strchr(s, ':');
  if (colon == NULL) {
    uint32_t v;
    if (fbsec_server_cli_parse_u32(s, &v) == 0 && v >= 1u && v <= 65535u) {
      g_cfg.bus_port = (int)v;
      return 0;
    }
    size_t hl = strlen(s);
    if (hl >= sizeof g_cfg.bus_host) return -1;
    memcpy(g_cfg.bus_host, s, hl + 1);
    return 0;
  }
  size_t hl = (size_t)(colon - s);
  if (hl == 0 || hl >= sizeof g_cfg.bus_host) return -1;
  memcpy(g_cfg.bus_host, s, hl);
  g_cfg.bus_host[hl] = '\0';
  uint32_t v;
  if (fbsec_server_cli_parse_u32(colon + 1, &v) != 0 || v < 1u || v > 65535u) return -1;
  g_cfg.bus_port = (int)v;
  return 0;
}

/* ---- Console Ctrl handler --------------------------------------------- */

static BOOL WINAPI ctrl_handler(DWORD ctrl_type) {
  (void)ctrl_type;
  InterlockedExchange(&g_shutdown, 1);
  fbsec_co_fd_carrier_close(&g_carrier);
  return TRUE;
}

/* ---- Bus connection & announce ---------------------------------------- */

static int bus_connect(void) {
  fbsec_co_fd_carrier_status_t st = fbsec_co_fd_carrier_connect(
      &g_carrier, g_cfg.bus_host, (uint16_t)g_cfg.bus_port);
  if (st != FBSEC_CO_FD_CARRIER_OK) {
    fprintf(stderr, EXEC_NAME ": connect(%s:%d) failed\n",
            g_cfg.bus_host, g_cfg.bus_port);
    return -1;
  }
  return 0;
}

/**
 * @brief Build and send SIM_PEER_ANNOUNCE: payload = role || node_id || name.
 *
 * Wire layout matches doc/fieldbus_sim_canopen_fd_spec.txt §7.1.
 */
static int send_announce(void) {
  fbsec_co_fd_frame_t f;
  fbsec_co_fd_frame_init(&f, FBSEC_CO_FD_CAN_ID_SIM_PEER_ANNOUNCE,
                         /*extended=*/true);
  size_t name_len = strlen(g_cfg.name);
  if (name_len > SIM_NAME_MAX) name_len = SIM_NAME_MAX;
  f.payload[0] = FBSEC_CO_FD_SIM_ROLE_SERVER;
  f.payload[1] = g_cfg.node_id;
  if (name_len > 0u) memcpy(&f.payload[2], g_cfg.name, name_len);
  f.len = (uint8_t)(2u + name_len);
  fbsec_co_fd_carrier_status_t st = fbsec_co_fd_carrier_send(&g_carrier, &f);
  if (st != FBSEC_CO_FD_CARRIER_OK) {
    fprintf(stderr, EXEC_NAME ": send_announce failed\n");
    return -1;
  }
  return 0;
}

/* ---- USDO segmented transfer (optional asymmetric layer) -------------- */
#if FBSEC_FEATURE_ASYM

/* Single-slot segmented-download reassembly and segmented-upload source.
   Sufficient for the single-client demo; a multi-client bus would key
   these by (peer, session). */
static struct {
  bool     active;
  uint8_t  src;
  uint8_t  session;
  uint8_t  sub;
  uint16_t index;
  uint8_t  counter;
  uint16_t total;
  uint16_t have;
  uint8_t  buf[FBSEC_CO_FD_USDO_SEG_BODY_MAX];
} g_segdl;

static struct {
  bool     active;
  uint8_t  dst;
  uint8_t  session;
  uint16_t total;
  uint16_t sent;
  uint8_t  counter;
  uint8_t  buf[FBSEC_CO_FD_USDO_SEG_BODY_MAX];
} g_segul;

/* Lowest index the USDO codec will encode. Used as the abort multiplexor
   when the offending frame was a segment, which carries none. */
#define SERVER_SEG_ABORT_INDEX 0x1000u

/* Send a USDO abort and drop both segmented-transfer contexts. The code
   is a CiA 1301 Table 31 value describing the segmented-transfer fault
   (see shared/fbsec_abort.h). */
static void server_seg_abort(uint8_t peer, uint8_t session,
                             uint16_t index, uint8_t subindex,
                             fbsec_abort_t code) {
  fbsec_co_fd_frame_t f;
  g_segdl.active = false;
  g_segul.active = false;
  if (fbsec_co_fd_usdo_encode_abort(&f, g_cfg.node_id, peer, session,
                                    index, subindex, code)) {
    (void)fbsec_co_fd_carrier_send(&g_carrier, &f);
  }
}

/**
 * @brief Handle a USDO download-initiate request (cmd 0x02).
 *
 * Opens the single reassembly slot and acknowledges with cmd 0x22.
 *
 * @param pdu  decoded initiate request. Must not be NULL.
 */
static void server_seg_download_init(const fbsec_co_fd_usdo_pdu_t *pdu) {
  fbsec_co_fd_frame_t f;

  if (pdu->total_size > (uint32_t)sizeof g_segdl.buf) {
    server_seg_abort(pdu->src_node_id, pdu->session, pdu->index, pdu->subindex,
                     FBSEC_ABORT_LEN_TOO_HIGH);
    return;
  }
  g_segdl.active  = true;
  g_segdl.src     = pdu->src_node_id;
  g_segdl.session = pdu->session;
  g_segdl.index   = pdu->index;
  g_segdl.sub     = pdu->subindex;
  g_segdl.counter = 0u;
  g_segdl.total   = (uint16_t)pdu->total_size;
  g_segdl.have    = 0u;

  if (fbsec_co_fd_usdo_encode_download_init_resp(&f, g_cfg.node_id,
                                                 pdu->src_node_id, pdu->session,
                                                 pdu->index, pdu->subindex)) {
    (void)fbsec_co_fd_carrier_send(&g_carrier, &f);
  }
}

/* True when @p pdu belongs to the open reassembly slot. */
static bool server_seg_download_matches(const fbsec_co_fd_usdo_pdu_t *pdu) {
  return g_segdl.active
      && (pdu->src_node_id == g_segdl.src)
      && (pdu->session     == g_segdl.session);
}

/**
 * @brief Append one download segment to the reassembly slot.
 *
 * @param pdu  decoded segment / end request. Must not be NULL.
 * @return true when this was the end segment and the body is complete in
 *         @c g_segdl.buf; false when more segments are expected or the
 *         transfer was aborted.
 */
static bool server_seg_download_feed(const fbsec_co_fd_usdo_pdu_t *pdu) {
  fbsec_co_fd_frame_t f;
  bool last = (pdu->cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ);

  if (!server_seg_download_matches(pdu)) {
    server_seg_abort(pdu->src_node_id, pdu->session, SERVER_SEG_ABORT_INDEX, 0u,
                     FBSEC_ABORT_SESSION_ID);
    return false;
  }
  if (!last && (pdu->counter != g_segdl.counter)) {
    server_seg_abort(pdu->src_node_id, pdu->session, g_segdl.index, g_segdl.sub,
                     FBSEC_ABORT_SEG_COUNTER);
    return false;
  }
  if (((uint32_t)g_segdl.have + pdu->data_len) > (uint32_t)g_segdl.total) {
    server_seg_abort(pdu->src_node_id, pdu->session, g_segdl.index, g_segdl.sub,
                     FBSEC_ABORT_DATA_SIZE);
    return false;
  }
  if (pdu->data_len > 0u) {
    memcpy(&g_segdl.buf[g_segdl.have], pdu->data, pdu->data_len);
  }
  g_segdl.have = (uint16_t)(g_segdl.have + pdu->data_len);

  if (!last) {
    if (fbsec_co_fd_usdo_encode_download_seg_resp(&f, g_cfg.node_id,
                                                  pdu->src_node_id, pdu->session,
                                                  g_segdl.counter)) {
      (void)fbsec_co_fd_carrier_send(&g_carrier, &f);
    }
    g_segdl.counter++;
    return false;
  }

  if (g_segdl.have != g_segdl.total) {
    server_seg_abort(pdu->src_node_id, pdu->session, g_segdl.index, g_segdl.sub,
                     FBSEC_ABORT_DATA_SIZE);
    return false;
  }
  return true;
}

/**
 * @brief Serve one upload-segment request (cmd 0x13) from the pending
 *        segmented-upload body.
 *
 * @param pdu  decoded upload-segment request. Must not be NULL.
 */
static void server_seg_upload_serve(const fbsec_co_fd_usdo_pdu_t *pdu) {
  fbsec_co_fd_frame_t f;
  uint16_t remaining;
  bool     ok;

  if ((!g_segul.active) || (pdu->src_node_id != g_segul.dst)
      || (pdu->session != g_segul.session)) {
    server_seg_abort(pdu->src_node_id, pdu->session, SERVER_SEG_ABORT_INDEX, 0u,
                     FBSEC_ABORT_SESSION_ID);
    return;
  }
  if (pdu->counter != g_segul.counter) {
    server_seg_abort(pdu->src_node_id, pdu->session, SERVER_SEG_ABORT_INDEX, 0u,
                     FBSEC_ABORT_SEG_COUNTER);
    return;
  }

  remaining = (uint16_t)(g_segul.total - g_segul.sent);
  if (remaining > FBSEC_CO_FD_USDO_SEG_DATA_MAX) {
    ok = fbsec_co_fd_usdo_encode_upload_seg_resp(&f, g_cfg.node_id, g_segul.dst,
                                                 g_segul.session, g_segul.counter,
                                                 &g_segul.buf[g_segul.sent]);
    if (ok) {
      (void)fbsec_co_fd_carrier_send(&g_carrier, &f);
    }
    g_segul.sent = (uint16_t)(g_segul.sent + FBSEC_CO_FD_USDO_SEG_DATA_MAX);
    g_segul.counter++;
    return;
  }

  ok = fbsec_co_fd_usdo_encode_upload_end_resp(&f, g_cfg.node_id, g_segul.dst,
                                               g_segul.session,
                                               &g_segul.buf[g_segul.sent],
                                               remaining);
  if (ok) {
    (void)fbsec_co_fd_carrier_send(&g_carrier, &f);
  }
  g_segul.active = false;
}
#endif /* FBSEC_FEATURE_ASYM */

/* ---- Dispatch loop ---------------------------------------------------- */

/**
 * @brief Pull one CAN FD frame from the carrier and route by CAN ID.
 *
 * Recv timeout is short (250 ms) so the Ctrl-C close-socket path can
 * unblock the loop within a quarter second; in production the caller
 * would use a longer deadline.
 */
static void run_dispatch_loop(void) {
  for (;;) {
    if (InterlockedCompareExchange(&g_shutdown, 0, 0) != 0) {
      break;
    }
    fbsec_co_fd_frame_t f;
    uint32_t deadline = fbsec_co_fd_carrier_now_ms() + 250u;
    fbsec_co_fd_carrier_status_t st =
        fbsec_co_fd_carrier_recv(&g_carrier, &f, deadline);
    if (st == FBSEC_CO_FD_CARRIER_TIMEOUT) {
      continue;
    }
    if (st == FBSEC_CO_FD_CARRIER_CLOSED) {
      if (InterlockedCompareExchange(&g_shutdown, 0, 0) == 0) {
        fprintf(stderr, EXEC_NAME ": bus closed connection\n");
      }
      break;
    }
    if (st != FBSEC_CO_FD_CARRIER_OK) {
      fprintf(stderr, EXEC_NAME ": carrier recv failed\n");
      break;
    }

    /* Decode USDO PDU. The decoder verifies the CAN ID is in the USDO
       family; non-USDO frames (other peers' responses, SIM_* events)
       short-circuit out as DECODE_NOT_USDO. */
    fbsec_co_fd_usdo_pdu_t pdu;
    fbsec_co_fd_usdo_decode_t dr = fbsec_co_fd_usdo_decode(&f, &pdu);
    if (dr != FBSEC_CO_FD_USDO_DECODE_OK) {
      if (g_cfg.common.verbose && dr != FBSEC_CO_FD_USDO_DECODE_NOT_USDO) {
        fprintf(stderr, EXEC_NAME ": USDO decode rc=%d, dropping\n", (int)dr);
      }
      continue;
    }

    /* Only act on requests addressed to our own node id. */
    uint8_t                 sender = 0u;
    fbsec_co_fd_usdo_kind_t kind   = FBSEC_CO_FD_USDO_KIND_NONE;
    (void)fbsec_co_fd_usdo_can_id_split(fbsec_co_fd_frame_id_value(&f),
                                        &sender, &kind);
    if (kind != FBSEC_CO_FD_USDO_KIND_REQUEST) continue;
    if (pdu.dst_node_id != g_cfg.node_id) continue;

#if FBSEC_FEATURE_ASYM
    /* USDO segmented transfers: reassemble large downloads and serve the
       segments of a large upload before the normal single-frame dispatch. */
    if (pdu.cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_INIT_REQ) {
      server_seg_download_init(&pdu);
      continue;
    }
    if ((pdu.cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_SEG_REQ)
        || (pdu.cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ)) {
      if (!server_seg_download_feed(&pdu)) {
        continue;   /* ack / abort already sent, or more segments expected */
      }
      request_ctx_t sctx = {
        .src_node_id = g_segdl.src,
        .req_cmd     = FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ,
        .session     = g_segdl.session,
        .index       = g_segdl.index,
        .subindex    = g_segdl.sub
      };
      uint32_t seg_data_id =
        fbsec_co_fd_data_id_from_index_sub(g_segdl.index, g_segdl.sub);
      fbsec_server_dispatch_request((uint16_t)g_segdl.src, seg_data_id,
                                    g_segdl.buf, g_segdl.total,
                                    send_reply_cb, &sctx);
      g_segdl.active = false;
      continue;
    }
    if (pdu.cmd == FBSEC_CO_FD_USDO_CMD_UPLOAD_SEG_REQ) {
      server_seg_upload_serve(&pdu);
      continue;
    }
#endif

    /* Compute data_id from (index, sub) per doc/fieldbus_sim_canopen_fd_spec.txt §2. */
    uint32_t data_id = fbsec_co_fd_data_id_from_index_sub(pdu.index, pdu.subindex);

    /* Stash everything send_reply needs to address the response. */
    request_ctx_t rctx = {
      .src_node_id = pdu.src_node_id,
      .req_cmd     = pdu.cmd,
      .session     = pdu.session,
      .index       = pdu.index,
      .subindex    = pdu.subindex
    };

    /* Use the requester's node id as the dispatch's client_dev so
       per-client armed-slot bookkeeping is keyed correctly even when
       multiple clients share the bus. */
    fbsec_server_dispatch_request((uint16_t)pdu.src_node_id, data_id,
                                  pdu.data, pdu.data_len,
                                  send_reply_cb, &rctx);
  }
}

/**
 * @brief Variant's send_reply: wrap dispatch reply in the matching
 *        USDO response cmd (or USDO abort on non-zero status).
 */
static int send_reply_cb(void *user, uint16_t to_dev, uint32_t data_id,
                         fbsec_abort_t status, const uint8_t *data,
                         uint16_t data_len) {
  (void)to_dev;
  const request_ctx_t *rctx = (const request_ctx_t *)user;

  fbsec_co_fd_frame_t f;
  bool ok = false;

#if FBSEC_FEATURE_ASYM
  /* A reply larger than one expedited data block is parked and announced
     with an upload-initiate response (cmd 0x32); the client then pulls it
     with the standard upload-segment exchange. */
  if (status == FBSEC_ABORT_NONE && data_len > FBSEC_CO_FD_USDO_DATA_MAX) {
    if (data_len > (uint16_t)sizeof g_segul.buf) {
      fprintf(stderr, EXEC_NAME ": reply too large for a segmented upload\n");
      return -1;
    }
    memcpy(g_segul.buf, data, data_len);
    g_segul.total   = data_len;
    g_segul.sent    = 0u;
    g_segul.counter = 0u;
    g_segul.session = rctx->session;
    g_segul.dst     = rctx->src_node_id;
    g_segul.active  = true;
    ok = fbsec_co_fd_usdo_encode_upload_init_resp(&f, g_cfg.node_id,
                                                  rctx->src_node_id, rctx->session,
                                                  rctx->index, rctx->subindex,
                                                  data_len);
    if (!ok) {
      fprintf(stderr, EXEC_NAME ": USDO upload-initiate encode failed\n");
      return -1;
    }
    if (fbsec_co_fd_carrier_send(&g_carrier, &f) != FBSEC_CO_FD_CARRIER_OK) {
      fprintf(stderr, EXEC_NAME ": carrier send failed\n");
      return -1;
    }
    (void)data_id;
    return 0;
  }
#endif

  if (status != FBSEC_ABORT_NONE) {
    /* Abort: cmd 7Fh, 7-byte CiA 1301 Table 32 frame, 1-byte ac. */
    ok = fbsec_co_fd_usdo_encode_abort(&f, g_cfg.node_id, rctx->src_node_id,
                                       rctx->session,
                                       rctx->index, rctx->subindex, status);
  } else if (rctx->req_cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_REQ) {
    /* SRD Pass-1 DEFER ACK or SWR Pass-2 commit ACK -> download_resp.
       Optional data carries the 2-byte session_id when the matching
       request asked to arm a cyclic session via bit-6 in the keyid. */
    ok = fbsec_co_fd_usdo_encode_download_resp(&f, g_cfg.node_id, rctx->src_node_id,
                                               rctx->session,
                                               rctx->index, rctx->subindex,
                                               data, data_len);
#if FBSEC_FEATURE_ASYM
  } else if (rctx->req_cmd == FBSEC_CO_FD_USDO_CMD_DOWNLOAD_END_REQ) {
    /* Segmented download completed -> download-end response (cmd 0x24).
       Any reply body a segmented write produced is dropped: the CiA 1301
       end response carries none, and no SOFA write verb returns one. */
    ok = fbsec_co_fd_usdo_encode_download_end_resp(&f, g_cfg.node_id,
                                                   rctx->src_node_id,
                                                   rctx->session);
#endif
  } else if (rctx->req_cmd == FBSEC_CO_FD_USDO_CMD_UPLOAD_REQ) {
    /* SRD Pass-2 data fetch or SWR Pass-1 server_random -> upload_resp. */
    ok = fbsec_co_fd_usdo_encode_upload_resp(&f, g_cfg.node_id, rctx->src_node_id,
                                             rctx->session,
                                             rctx->index, rctx->subindex,
                                             data, data_len);
  } else {
    /* Unknown request cmd -> CiA 1301 Table 31 13h. */
    ok = fbsec_co_fd_usdo_encode_abort(&f, g_cfg.node_id, rctx->src_node_id,
                                       rctx->session,
                                       rctx->index, rctx->subindex,
                                       FBSEC_ABORT_BAD_CMD);
  }

  if (!ok) {
    fprintf(stderr, EXEC_NAME ": USDO encode failed\n");
    return -1;
  }
  fbsec_co_fd_carrier_status_t st = fbsec_co_fd_carrier_send(&g_carrier, &f);
  if (st != FBSEC_CO_FD_CARRIER_OK) {
    fprintf(stderr, EXEC_NAME ": carrier send failed\n");
    return -1;
  }
  (void)data_id;
  return 0;
}

/* EOF */
