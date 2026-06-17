/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_client.c
 * @brief   SOFA CANopen FD, USDO-initiator client main.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Thin variant entry point: connect to the CAN FD bus simulator via
 * `fbsec_co_fd_carrier`, send `SIM_PEER_ANNOUNCE` (role client),
 * dispatch single-shot or menu mode through `client_common`. The
 * variant supplies only the transport-vtable callbacks that wrap
 * USDO encoding around the secure-tunnel byte exchange:
 *
 *   transport_read   USDO download_req (req_body) or upload_req (empty);
 *                    expect download_resp (empty) or upload_resp (data).
 *   transport_write  USDO download_req (buf); expect download_resp ACK.
 *
 * No plain rd/wr (the demo OD entries are SECURE_RO/SECURE_WO only)
 * and no batch mode in this initial cut. Menu mode is fully wired
 * via `fbsec_client_run_menu`.
 *
 * See doc/fieldbus_sim_canopen_fd_spec.txt §6 for the secure-tunnel
 * flow mapping onto USDO.
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

#include "fbsec_aead.h"
#include "fbsec_secure_proto.h"

#include "client_common_cfg.h"
#include "client_common_cli.h"
#include "client_common_keys.h"
#include "client_common_menu.h"
#include "client_common_platform.h"
#include "client_common_trace.h"
#include "client_common_verbs.h"

#include "fbsec_co_fd_addr.h"
#include "fbsec_co_fd_carrier.h"
#include "fbsec_co_fd_frame.h"
#include "fbsec_co_fd_usdo.h"

/* ---- Compile-time configuration ---------------------------------------- */

#define DEFAULT_BUS_HOST     "127.0.0.1"
#define DEFAULT_BUS_PORT     5810
#define DEFAULT_NODE_ID      0x7Fu        /* announced; demo client convention */
#define DEFAULT_NAME         "fbsec_co_fd_client"
#define VERSION_STR          "V1.0"
#define VERSION_DATE_STR     "07-MAY-2026"
#define EXEC_NAME            "fbsec_co_fd_client"
#define BANNER_NAME          "SOFA CANopen FD Client"

#define SIM_NAME_MAX 30u

/* ---- Variant-local state ---------------------------------------------- */

typedef struct {
  fbsec_client_cfg_t common;
  uint8_t  node_id;             /* this client's announced node id (1..127) */
  uint8_t  target_node;         /* default target server node id (1..127) for --menu */
  char     bus_host[64];
  int      bus_port;
  char     name[SIM_NAME_MAX + 1];
} client_variant_cfg_t;

static fbsec_co_fd_carrier_t g_carrier;
static client_variant_cfg_t  g_cfg;

/* Variant's "my_dev" mapped from --node into the SOFA AAD device_id space. */
static uint16_t              g_my_dev = (uint16_t)DEFAULT_NODE_ID;

/* USDO session counter. Bumped per outgoing request; wraps 0xFF -> 1
   (skipping 0). Used to pair responses with requests on a real bus
   where multiple transfers may be in flight; the SOFA demo only
   drives one at a time but we still vary the value for trace clarity
   and CiA-compliance. */
static uint8_t               g_usdo_session = 0u;
static uint8_t next_session(void) {
  g_usdo_session = (g_usdo_session == 0xFFu) ? 1u : (uint8_t)(g_usdo_session + 1u);
  if (g_usdo_session == 0u) g_usdo_session = 1u;
  return g_usdo_session;
}

/* Setter handed to the menu's prompt_node_id; updates both the variant's
   own canonical node id storage and the trace's my_dev mirror. */
static void on_menu_set_node_id(uint8_t new_node_id) {
  g_cfg.node_id = new_node_id;
  g_my_dev      = (uint16_t)new_node_id;
}

/* ---- Forward declarations -------------------------------------------- */

static int parse_args(int argc, char **argv,
                      fbsec_client_verb_t *verb_out,
                      uint32_t *target_out, uint32_t *data_id_out,
                      uint8_t *write_buf, size_t write_buf_size,
                      size_t *write_len_out);
static void print_usage(FILE *f);
static int  parse_bus_arg(const char *s);

static int  bus_connect(void);
static int  send_announce(void);

static fbsec_secure_status_t transport_read(
  void *ctx, uint16_t device_id, uint32_t data_id,
  const uint8_t *req_body, uint16_t req_len,
  uint8_t *buf, uint32_t buf_size,
  uint32_t timeout_ms,
  uint32_t *len_out, uint32_t *abort_out);
static fbsec_secure_status_t transport_write(
  void *ctx, uint16_t device_id, uint32_t data_id,
  const uint8_t *buf, uint32_t len,
  uint32_t timeout_ms,
  uint32_t *abort_out);

static const fbsec_secure_transport_t g_transport = {
  transport_read,
  transport_write,
  NULL
};

/* ---- Port hook: client_id ------------------------------------------- */

/* AAD client_device_id. On CANopen FD this is the local node_id (1..127);
   we hold it in g_my_dev as uint16, the AAD-build code truncates to one
   byte when FBSEC_AEAD_DEV_ID_SIZE == 1. */
uint16_t fbsec_secure_port_get_client_id(void) {
  return g_my_dev;
}

/* ---- main -------------------------------------------------------------- */

int main(int argc, char **argv) {
  fbsec_client_verb_t verb;
  uint32_t target_arg  = 0;
  uint32_t data_id_arg = 0;
  uint8_t  write_buf[FBSEC_AEAD_MAX_PROTECTED];
  size_t   write_len   = 0;

  setvbuf(stdout, NULL, _IONBF, 0);

  /* Defaults. */
  memset(&g_cfg, 0, sizeof g_cfg);
  g_cfg.common.timeout_ms = 1000u;
  g_cfg.common.count      = 1u;
  g_cfg.common.color_pref = FBSEC_CLIENT_COLOR_AUTO;
  g_cfg.common.ts_state   = FBSEC_CLIENT_TS_DEFAULT;
  g_cfg.node_id           = (uint8_t)DEFAULT_NODE_ID;
  g_cfg.target_node       = 0x05u;
  memcpy(g_cfg.bus_host, DEFAULT_BUS_HOST, sizeof DEFAULT_BUS_HOST);
  g_cfg.bus_port = DEFAULT_BUS_PORT;
  memcpy(g_cfg.name, DEFAULT_NAME, sizeof DEFAULT_NAME);

  int rc = parse_args(argc, argv, &verb, &target_arg, &data_id_arg,
                      write_buf, sizeof write_buf, &write_len);
  if (rc == -1) return 0;
  if (rc != 0)  return 1;

  /* Mirror node id into SOFA device_id field. */
  g_my_dev = (uint16_t)g_cfg.node_id;

  bool use_color = fbsec_client_cli_resolve_color(g_cfg.common.color_pref);
  bool show_ts   = fbsec_client_cli_resolve_show_ts(g_cfg.common.ts_state, false);
  fbsec_client_trace_set_quiet(g_cfg.common.quiet);
  fbsec_client_trace_set_use_color(use_color);
  fbsec_client_trace_set_show_ts(show_ts);

  fbsec_client_cli_print_banner(BANNER_NAME, VERSION_STR, VERSION_DATE_STR);

  if (fbsec_co_fd_carrier_global_init() != FBSEC_CO_FD_CARRIER_OK) {
    fprintf(stderr, EXEC_NAME ": WSAStartup failed\n");
    return 1;
  }

  fbsec_co_fd_carrier_init(&g_carrier);
  if (bus_connect() != 0) {
    fbsec_co_fd_carrier_global_shutdown();
    return 1;
  }
  if (g_cfg.common.verbose) {
    fprintf(stderr, "connected to %s:%d as node 0x%02X\n",
            g_cfg.bus_host, g_cfg.bus_port, (unsigned)g_cfg.node_id);
  }
  if (send_announce() != 0) {
    fbsec_co_fd_carrier_close(&g_carrier);
    fbsec_co_fd_carrier_global_shutdown();
    return 1;
  }

  fbsec_secure_set_salt_callback(fbsec_client_keys_on_observed_salt, NULL);

  /* If --main-key + --salt + --keyid were given, populate the active
     slot via HKDF (a no-op when --key-file or --key already populated
     it). */
  if (fbsec_client_keys_derive_session_if_needed() != 0) {
    fbsec_co_fd_carrier_close(&g_carrier);
    fbsec_co_fd_carrier_global_shutdown();
    return 1;
  }
  /* Backfill any of slots 1/2/3 still empty with their demo session
     keys, so every menu / --keyid choice in 1..3 has a key resident
     when the user picks it. Slots populated by --key-file, --key, or
     the HKDF derivation above are left alone. */
  fbsec_client_keys_load_demo_all();

  int exit_code = 1;
  if (g_cfg.common.menu_mode) {
    char bus_label[80];
    snprintf(bus_label, sizeof bus_label, "%s:%d", g_cfg.bus_host, g_cfg.bus_port);
    fbsec_client_menu_cfg_t mcfg = {
      .my_dev      = g_my_dev,
      .timeout_ms  = g_cfg.common.timeout_ms,
      .bus_label   = bus_label,
      .set_node_id = on_menu_set_node_id
    };
    exit_code = fbsec_client_run_menu(&g_transport, &mcfg);
  } else {
    fbsec_client_trace_print_legend();
    switch (verb) {
      case FBSEC_CLIENT_VERB_SRD: {
        uint8_t  buf[FBSEC_AEAD_MAX_PROTECTED];
        uint32_t got = 0u;
        exit_code = fbsec_client_run_secure_read(&g_transport,
                                                 (uint16_t)target_arg, data_id_arg,
                                                 g_cfg.common.timeout_ms,
                                                 buf, sizeof buf, &got);
        break;
      }
      case FBSEC_CLIENT_VERB_SWR:
        exit_code = fbsec_client_run_secure_write(&g_transport,
                                                  (uint16_t)target_arg, data_id_arg,
                                                  write_buf, (uint16_t)write_len,
                                                  g_cfg.common.timeout_ms);
        break;
      case FBSEC_CLIENT_VERB_SRD_POLL:
        exit_code = fbsec_client_run_secure_read_poll(&g_transport,
                                                      (uint16_t)target_arg, data_id_arg,
                                                      g_cfg.common.count,
                                                      g_cfg.common.timeout_ms);
        break;
      case FBSEC_CLIENT_VERB_SWR_POLL:
        exit_code = fbsec_client_run_secure_write_poll(&g_transport,
                                                       (uint16_t)target_arg, data_id_arg,
                                                       write_buf, (uint16_t)write_len,
                                                       g_cfg.common.count,
                                                       g_cfg.common.timeout_ms);
        break;
      case FBSEC_CLIENT_VERB_RD:
      case FBSEC_CLIENT_VERB_WR:
      default:
        fprintf(stderr, EXEC_NAME ": plain rd/wr not supported in this variant "
                "(demo entries are SECURE_RO/SECURE_WO only)\n");
        exit_code = 1;
        break;
    }
  }

  fbsec_client_keys_wipe();
  fbsec_co_fd_carrier_close(&g_carrier);
  fbsec_co_fd_carrier_global_shutdown();
  return exit_code;
}

/* ---- Argv parsing ----------------------------------------------------- */

static int parse_args(int argc, char **argv,
                      fbsec_client_verb_t *verb_out,
                      uint32_t *target_out, uint32_t *data_id_out,
                      uint8_t *write_buf, size_t write_buf_size,
                      size_t *write_len_out) {
  *write_len_out = 0;

  if (argc < 2) {
    print_usage(stderr);
    return 1;
  }

  /* First pass: detect --help / --menu. */
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--help") == 0) {
      print_usage(stdout);
      return -1;
    }
    if (strcmp(argv[i], "--menu") == 0) {
      g_cfg.common.menu_mode = true;
    }
  }

  const char *data_hex  = NULL;
  int positional_start  = 1;

  if (g_cfg.common.menu_mode) {
    positional_start = 1;
  } else {
    if (argc < 4) {
      fprintf(stderr, EXEC_NAME ": missing positional arguments\n");
      print_usage(stderr);
      return 1;
    }
    if (strcmp(argv[1], "srd") == 0) {
      *verb_out = FBSEC_CLIENT_VERB_SRD;
    } else if (strcmp(argv[1], "swr") == 0) {
      *verb_out = FBSEC_CLIENT_VERB_SWR;
    } else if (strcmp(argv[1], "srdpoll") == 0) {
      *verb_out = FBSEC_CLIENT_VERB_SRD_POLL;
    } else if (strcmp(argv[1], "swrpoll") == 0) {
      *verb_out = FBSEC_CLIENT_VERB_SWR_POLL;
    } else {
      fprintf(stderr, EXEC_NAME
              ": unknown verb '%s' (srd|swr|srdpoll|swrpoll)\n", argv[1]);
      print_usage(stderr);
      return 1;
    }
    if (fbsec_client_cli_parse_u32(argv[2], target_out) != 0
        || *target_out == 0u || *target_out > FBSEC_CO_FD_NODE_ID_MAX) {
      fprintf(stderr, EXEC_NAME ": invalid target node '%s' (1..%u)\n",
              argv[2], (unsigned)FBSEC_CO_FD_NODE_ID_MAX);
      return 1;
    }
    if (fbsec_client_cli_parse_u32(argv[3], data_id_out) != 0
        || !fbsec_co_fd_data_id_is_canopen_form(*data_id_out)) {
      fprintf(stderr, EXEC_NAME ": invalid CANopen-form data_id '%s'\n", argv[3]);
      return 1;
    }
    positional_start = 4;
  }

  int i = positional_start;
  while (i < argc) {
    if (strcmp(argv[i], "--menu") == 0) { i += 1; continue; }

    fbsec_client_cli_result_t cr = fbsec_client_cli_try_common_flag(
        &i, argc, argv, &g_cfg.common, NULL, EXEC_NAME);
    if (cr == FBSEC_CLIENT_CLI_HELP) {
      print_usage(stdout);
      return -1;
    }
    if (cr == FBSEC_CLIENT_CLI_ERROR)   return 1;
    if (cr == FBSEC_CLIENT_CLI_HANDLED) continue;

    const char *a = argv[i];
    if (strcmp(a, "--bus") == 0 && (i + 1) < argc) {
      if (parse_bus_arg(argv[i + 1]) != 0) {
        fprintf(stderr, EXEC_NAME ": invalid --bus value\n");
        return 1;
      }
      i += 2;
    } else if (strcmp(a, "--node") == 0 && (i + 1) < argc) {
      uint32_t v;
      if (fbsec_client_cli_parse_u32(argv[i + 1], &v) != 0
          || v == 0u || v > FBSEC_CO_FD_NODE_ID_MAX) {
        fprintf(stderr, EXEC_NAME ": invalid --node (1..%u)\n",
                (unsigned)FBSEC_CO_FD_NODE_ID_MAX);
        return 1;
      }
      g_cfg.node_id = (uint8_t)v;
      i += 2;
    } else if (strcmp(a, "--target-node") == 0 && (i + 1) < argc) {
      uint32_t v;
      if (fbsec_client_cli_parse_u32(argv[i + 1], &v) != 0
          || v == 0u || v > FBSEC_CO_FD_NODE_ID_MAX) {
        fprintf(stderr, EXEC_NAME ": invalid --target-node (1..%u)\n",
                (unsigned)FBSEC_CO_FD_NODE_ID_MAX);
        return 1;
      }
      g_cfg.target_node = (uint8_t)v;
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
    } else if (strcmp(a, "--data") == 0 && (i + 1) < argc) {
      data_hex = argv[i + 1];
      i += 2;
    } else {
      fprintf(stderr, EXEC_NAME ": unknown option '%s'\n", a);
      print_usage(stderr);
      return 1;
    }
  }

  /* Cross-flag validation. */
  if (!g_cfg.common.menu_mode) {
    bool needs_payload = (*verb_out == FBSEC_CLIENT_VERB_SWR)
                      || (*verb_out == FBSEC_CLIENT_VERB_SWR_POLL);
    if (needs_payload) {
      if (data_hex == NULL) {
        fprintf(stderr, EXEC_NAME ": %s needs --data HEX\n",
                (*verb_out == FBSEC_CLIENT_VERB_SWR) ? "swr" : "swrpoll");
        return 1;
      }
      if (fbsec_client_cli_parse_hex(data_hex, write_buf, write_buf_size, write_len_out) != 0) {
        fprintf(stderr, EXEC_NAME ": invalid --data hex string\n");
        return 1;
      }
      if (*write_len_out == 0 || *write_len_out > FBSEC_AEAD_MAX_PROTECTED) {
        fprintf(stderr, EXEC_NAME ": payload must be 1..%u bytes\n",
                (unsigned)FBSEC_AEAD_MAX_PROTECTED);
        return 1;
      }
    }
    if ((uint32_t)g_cfg.node_id == *target_out) {
      fprintf(stderr, EXEC_NAME ": --node collides with target node\n");
      return 1;
    }
  }

  /* Secure-verb credential validation. In --menu mode the interactive
     prompt_key() loads a demo key on entry, so bare --menu is valid;
     only enforce the cmdline credentials if the user actually passed
     a key flag (catches partial --keyid / --key combinations). For
     single-shot mode every FD verb is secure, so validation always
     runs. */
  bool any_secure;
  if (g_cfg.common.menu_mode) {
    any_secure = (fbsec_client_keys_session_set() || fbsec_client_keys_main_set());
  } else {
    any_secure = FBSEC_CLIENT_VERB_IS_SECURE(*verb_out);
  }
  if (any_secure || fbsec_client_keys_session_set() || fbsec_client_keys_main_set()
      || fbsec_client_keys_keyid() != 0u) {
    if (fbsec_client_keys_keyid() == 0u) {
      fprintf(stderr, EXEC_NAME ": secure verbs require --keyid N\n");
      return 1;
    }
    if (!fbsec_client_keys_session_set() && !fbsec_client_keys_main_set()) {
      fprintf(stderr,
              EXEC_NAME ": secure verbs require --key HEX or --main-key + --salt\n");
      return 1;
    }
    if (fbsec_client_keys_main_set() && fbsec_client_keys_salt_len() == 0) {
      fprintf(stderr, EXEC_NAME ": --main-key requires --salt\n");
      return 1;
    }
    if (fbsec_client_keys_session_set() && fbsec_client_keys_main_set()) {
      fprintf(stderr,
              EXEC_NAME ": --key and --main-key are mutually exclusive\n");
      return 1;
    }
  }
  return 0;
}

static void print_usage(FILE *f) {
  fprintf(f,
    "usage:\n"
    "  " EXEC_NAME " (srd|swr|srdpoll|swrpoll) <target_node> <data_id> [options]\n"
    "  " EXEC_NAME " --menu [options]\n"
    "  " EXEC_NAME " --help\n"
    "\n"
    "Single-shot positional:\n"
    "  <target_node>  CANopen node id 1..%u (decimal or 0xHEX)\n"
    "  <data_id>      0xIIIISSnn where II=index (>= 0x1000), SS=subindex,\n"
    "                 nn=0x00 (reserved low byte; see doc/fieldbus_sim_canopen_fd_spec.txt §2)\n"
    "\n"
    "Common options:\n"
    "  --bus HOST:PORT     CAN FD bus simulator (default %s:%d)\n"
    "  --node N            this client's announced node id (default 0x%02X)\n"
    "  --target-node N     default target node for --menu (default 0x05)\n"
    "  --name STR          peer-announce name\n"
    "  --timeout MS        per-response timeout (default 1000)\n"
    "  --count N           poll burst length for srdpoll/swrpoll (default 1)\n"
    "  --verbose           extra stderr informational lines\n"
    "  --quiet             suppress per-row trace on stdout\n"
    "  --color / --no-color\n"
    "  --encrypt / --no-encrypt\n"
    "  --help              print this and exit 0\n"
    "\n"
    "swr / swrpoll payload:\n"
    "  --data HEX\n"
    "\n"
    "Secure verb credentials (one of):\n"
    "  --key HEX --keyid N\n"
    "  --main-key HEX --salt HEX --keyid N [--kdf FBSEC-SK-v1]\n"
    "  --key-file FILE --keyid N\n"
    "\n"
    "Menu mode:  --menu\n",
    (unsigned)FBSEC_CO_FD_NODE_ID_MAX,
    DEFAULT_BUS_HOST, DEFAULT_BUS_PORT,
    (unsigned)DEFAULT_NODE_ID);
}

static int parse_bus_arg(const char *s) {
  if (s == NULL || *s == '\0') return -1;
  const char *colon = strchr(s, ':');
  if (colon == NULL) {
    uint32_t v;
    if (fbsec_client_cli_parse_u32(s, &v) == 0 && v >= 1u && v <= 65535u) {
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
  if (fbsec_client_cli_parse_u32(colon + 1, &v) != 0 || v < 1u || v > 65535u) return -1;
  g_cfg.bus_port = (int)v;
  return 0;
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

static int send_announce(void) {
  fbsec_co_fd_frame_t f;
  fbsec_co_fd_frame_init(&f, FBSEC_CO_FD_CAN_ID_SIM_PEER_ANNOUNCE, /*extended=*/true);
  size_t name_len = strlen(g_cfg.name);
  if (name_len > SIM_NAME_MAX) name_len = SIM_NAME_MAX;
  f.payload[0] = FBSEC_CO_FD_SIM_ROLE_CLIENT;
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

/* ---- Transport vtable: USDO over CAN FD carrier --------------------- */

/**
 * @brief Round-trip one USDO request and decode the matching USDO
 *        response.
 *
 * @param req_frame     pre-encoded request frame (just send + trace).
 * @param target_node   target server node id (also expected in response BUF[0]).
 * @param data_id       used only for trace.
 * @param req_body      optional request payload (for TX trace).
 * @param req_len       length of @p req_body.
 * @param expected_cmd  USDO_CMD_DOWNLOAD_RESP or _UPLOAD_RESP; abort frames
 *                      are also accepted regardless.
 * @param resp_data_out (optional) on success, pointer into the recv frame's
 *                      USDO data block; lifetime bounded by this call.
 * @param resp_len_out  (optional) length of resp_data_out.
 * @param abort_out     receives the abort code on FBSEC_SECP_ABORT.
 */
static fbsec_secure_status_t round_trip(const fbsec_co_fd_frame_t *req_frame,
                                        uint16_t target_node_for_trace,
                                        uint32_t data_id,
                                        const uint8_t *req_body,
                                        uint16_t req_len,
                                        uint8_t expected_cmd,
                                        uint8_t expected_node,
                                        uint8_t expected_session,
                                        uint8_t *out_buf, uint32_t out_buf_size,
                                        uint32_t *len_out,
                                        uint32_t timeout_ms,
                                        uint32_t *abort_out) {
  fbsec_client_trace_inc_round();
  fbsec_client_trace_secure_frame(true, g_my_dev, target_node_for_trace,
                                  data_id, req_body, req_len, 0u);
  fbsec_co_fd_carrier_status_t st = fbsec_co_fd_carrier_send(&g_carrier, req_frame);
  if (st != FBSEC_CO_FD_CARRIER_OK) {
    return FBSEC_SECP_TX;
  }

  uint32_t deadline = fbsec_co_fd_carrier_now_ms() + timeout_ms;
  for (;;) {
    fbsec_co_fd_frame_t resp;
    st = fbsec_co_fd_carrier_recv(&g_carrier, &resp, deadline);
    if (st == FBSEC_CO_FD_CARRIER_TIMEOUT) return FBSEC_SECP_TIMEOUT;
    if (st == FBSEC_CO_FD_CARRIER_CLOSED)  return FBSEC_SECP_TX;
    if (st != FBSEC_CO_FD_CARRIER_OK)      return FBSEC_SECP_PROTOCOL;

    /* Filter: only USDO response/abort frames addressed back to us.
       Decode pulls src from the CAN ID and dst from BUF[0]. */
    fbsec_co_fd_usdo_pdu_t pdu;
    if (fbsec_co_fd_usdo_decode(&resp, &pdu) != FBSEC_CO_FD_USDO_DECODE_OK) {
      continue;
    }
    uint8_t                 sender = 0u;
    fbsec_co_fd_usdo_kind_t kind   = FBSEC_CO_FD_USDO_KIND_NONE;
    (void)fbsec_co_fd_usdo_can_id_split(fbsec_co_fd_frame_id_value(&resp),
                                        &sender, &kind);
    if (kind != FBSEC_CO_FD_USDO_KIND_RESPONSE) continue;
    /* Sender must be the targeted server, dst (BUF[0]) must be us. */
    if (pdu.src_node_id != expected_node) continue;
    if (pdu.dst_node_id != (uint8_t)g_cfg.node_id) continue;
    /* Session must match what we sent (catches cross-talk). */
    if (pdu.session != expected_session) continue;
    /* Filter by index/sub matching our request. */
    uint16_t want_index = (uint16_t)((data_id >> 16) & 0xFFFFu);
    uint8_t  want_sub   = (uint8_t) ((data_id >>  8) & 0xFFu);
    if (pdu.index != want_index || pdu.subindex != want_sub) continue;

    if (pdu.cmd == FBSEC_CO_FD_USDO_CMD_ABORT) {
      uint32_t abort_code = 0u;
      if (pdu.data_len == 4u && pdu.data != NULL) {
        abort_code = (uint32_t)pdu.data[0]
                  | ((uint32_t)pdu.data[1] <<  8)
                  | ((uint32_t)pdu.data[2] << 16)
                  | ((uint32_t)pdu.data[3] << 24);
      }
      fbsec_client_trace_secure_frame(false, target_node_for_trace, g_my_dev,
                                      data_id, NULL, 0u, abort_code);
      if (abort_out != NULL) *abort_out = abort_code;
      return FBSEC_SECP_ABORT;
    }
    if (pdu.cmd != expected_cmd) {
      /* Wrong response type (e.g. download_resp when we expected upload_resp). */
      return FBSEC_SECP_PROTOCOL;
    }

    fbsec_client_trace_secure_frame(false, target_node_for_trace, g_my_dev,
                                    data_id, pdu.data, pdu.data_len, 0u);
    if (pdu.data_len > out_buf_size) return FBSEC_SECP_BUFSIZE;
    if (pdu.data_len > 0u) memcpy(out_buf, pdu.data, pdu.data_len);
    if (len_out != NULL) *len_out = pdu.data_len;
    return FBSEC_SECP_OK;
  }
}

/**
 * @brief transport_read: secure-tunnel read-pattern half-round-trip.
 *
 * If req_len > 0 (Pass-1 challenge / cyclic-arm pre-data): build a
 * USDO download_req carrying the body; expect download_resp (empty
 * ACK).
 *
 * If req_len == 0 (Pass-2 fetch / cyclic poll): build a USDO
 * upload_req; expect upload_resp with data.
 */
static fbsec_secure_status_t transport_read(
  void    *ctx,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t *req_body,
  uint16_t       req_len,
  uint8_t *buf,
  uint32_t buf_size,
  uint32_t timeout_ms,
  uint32_t *len_out,
  uint32_t *abort_out)
{
  (void)ctx;

  uint16_t want_index = (uint16_t)((data_id >> 16) & 0xFFFFu);
  uint8_t  want_sub   = (uint8_t) ((data_id >>  8) & 0xFFu);
  uint8_t  target_node = (uint8_t)(device_id & 0xFFu);

  if (target_node == 0u || target_node > FBSEC_CO_FD_NODE_ID_MAX) {
    return FBSEC_SECP_PROTOCOL;
  }

  fbsec_co_fd_frame_t req;
  bool ok;
  uint8_t expected_cmd;
  uint8_t session = next_session();

  if (req_len > 0u) {
    ok = fbsec_co_fd_usdo_encode_download_req(&req, g_cfg.node_id, target_node,
                                              session, want_index, want_sub,
                                              req_body, req_len);
    expected_cmd = FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP;
  } else {
    ok = fbsec_co_fd_usdo_encode_upload_req(&req, g_cfg.node_id, target_node,
                                            session, want_index, want_sub,
                                            NULL, 0u);
    expected_cmd = FBSEC_CO_FD_USDO_CMD_UPLOAD_RESP;
  }
  if (!ok) return FBSEC_SECP_PROTOCOL;

  return round_trip(&req, device_id, data_id,
                    req_body, req_len,
                    expected_cmd, target_node, session,
                    buf, buf_size, len_out,
                    timeout_ms, abort_out);
}

/**
 * @brief transport_write: secure-tunnel write-pattern half-round-trip.
 *
 * Build a USDO download_req carrying buf; expect download_resp ACK.
 * Used by SWR Pass-2 (key+random+cipher+tag).
 */
static fbsec_secure_status_t transport_write(
  void    *ctx,
  uint16_t device_id,
  uint32_t data_id,
  const uint8_t *buf,
  uint32_t len,
  uint32_t timeout_ms,
  uint32_t *abort_out)
{
  (void)ctx;
  if (len > FBSEC_CO_FD_USDO_DATA_MAX) return FBSEC_SECP_BUFSIZE;

  uint16_t want_index = (uint16_t)((data_id >> 16) & 0xFFFFu);
  uint8_t  want_sub   = (uint8_t) ((data_id >>  8) & 0xFFu);
  uint8_t  target_node = (uint8_t)(device_id & 0xFFu);

  if (target_node == 0u || target_node > FBSEC_CO_FD_NODE_ID_MAX) {
    return FBSEC_SECP_PROTOCOL;
  }

  fbsec_co_fd_frame_t req;
  uint8_t session = next_session();
  if (!fbsec_co_fd_usdo_encode_download_req(&req, g_cfg.node_id, target_node,
                                            session, want_index, want_sub,
                                            buf, (uint16_t)len)) {
    return FBSEC_SECP_PROTOCOL;
  }

  /* The dispatch reply for a download_req carrying a Pass-2 SWR is empty. */
  uint8_t  scratch[1];
  uint32_t scratch_len = 0u;
  return round_trip(&req, device_id, data_id,
                    buf, (uint16_t)len,
                    FBSEC_CO_FD_USDO_CMD_DOWNLOAD_RESP, target_node, session,
                    scratch, sizeof scratch, &scratch_len,
                    timeout_ms, abort_out);
}

/* EOF */
