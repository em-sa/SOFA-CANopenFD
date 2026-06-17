/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_pcan.c
 * @brief   SOFA FD bus, PCAN-Basic dynamic-load wrapper, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 08-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_co_fd_pcan.h"

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- PCAN-Basic ABI typedefs ------------------------------------------ */

typedef WORD   tpcan_handle_t;
typedef DWORD  tpcan_status_t;
typedef UINT64 tpcan_timestamp_fd_t;
typedef DWORD  tpcan_parameter_t;

/* On-wire layout matches fbsec_pcan_msg_fd_t (same field order/sizes). */
typedef struct {
  DWORD ID;
  BYTE  MSGTYPE;
  BYTE  DLC;
  BYTE  DATA[FBSEC_PCAN_MSG_DATA_MAX];
} tpcan_msg_fd_t;

typedef tpcan_status_t (WINAPI *pcan_initialize_fd_fn)(tpcan_handle_t, char *);
typedef tpcan_status_t (WINAPI *pcan_uninitialize_fn)(tpcan_handle_t);
typedef tpcan_status_t (WINAPI *pcan_get_value_fn)(tpcan_handle_t, tpcan_parameter_t,
                                                  void *, DWORD);
typedef tpcan_status_t (WINAPI *pcan_read_fd_fn)(tpcan_handle_t, tpcan_msg_fd_t *,
                                                tpcan_timestamp_fd_t *);
typedef tpcan_status_t (WINAPI *pcan_write_fd_fn)(tpcan_handle_t,
                                                 const tpcan_msg_fd_t *);
typedef tpcan_status_t (WINAPI *pcan_reset_fn)(tpcan_handle_t);

/* ---- File-static state ------------------------------------------------ */

static HMODULE              g_dll          = NULL;
static pcan_initialize_fd_fn fp_init       = NULL;
static pcan_uninitialize_fn  fp_uninit     = NULL;
static pcan_get_value_fn     fp_getval     = NULL;
static pcan_read_fd_fn       fp_read       = NULL;
static pcan_write_fd_fn      fp_write      = NULL;
static pcan_reset_fn         fp_reset      = NULL;

static uint16_t g_open_handle = PCAN_NONEBUS;
static bool     g_open        = false;

/* PCAN_InitializeFD takes a non-const char *. Keep a writable copy
   instead of relying on string-literal mutability. */
static char g_bitrate_500k_2m[256] =
  "f_clock=80000000,nom_brp=2,nom_tseg1=63,nom_tseg2=16,nom_sjw=16,"
  "data_brp=2,data_tseg1=15,data_tseg2=4,data_sjw=4";

/* ---- Symbol resolution ------------------------------------------------- */

static FARPROC resolve(HMODULE m, const char *name) {
  FARPROC p = GetProcAddress(m, name);
  if (p == NULL) {
    fprintf(stderr, "PCAN: GetProcAddress(\"%s\") failed\n", name);
  }
  return p;
}

bool fbsec_pcan_load(void) {
  if (g_dll != NULL) return true;
  g_dll = LoadLibraryA("PCANBasic.dll");
  if (g_dll == NULL) {
    return false;
  }
  fp_init   = (pcan_initialize_fd_fn)resolve(g_dll, "CAN_InitializeFD");
  fp_uninit = (pcan_uninitialize_fn) resolve(g_dll, "CAN_Uninitialize");
  fp_getval = (pcan_get_value_fn)    resolve(g_dll, "CAN_GetValue");
  fp_read   = (pcan_read_fd_fn)      resolve(g_dll, "CAN_ReadFD");
  fp_write  = (pcan_write_fd_fn)     resolve(g_dll, "CAN_WriteFD");
  fp_reset  = (pcan_reset_fn)        resolve(g_dll, "CAN_Reset");
  if (fp_init == NULL || fp_uninit == NULL || fp_getval == NULL
      || fp_read == NULL || fp_write == NULL || fp_reset == NULL) {
    fbsec_pcan_unload();
    return false;
  }
  return true;
}

void fbsec_pcan_unload(void) {
  if (g_open) fbsec_pcan_close();
  if (g_dll != NULL) {
    FreeLibrary(g_dll);
    g_dll = NULL;
  }
  fp_init = NULL; fp_uninit = NULL; fp_getval = NULL;
  fp_read = NULL; fp_write = NULL; fp_reset = NULL;
}

bool fbsec_pcan_loaded(void) {
  return g_dll != NULL && fp_init != NULL;
}

bool fbsec_pcan_is_open(void) {
  return g_open;
}

/* ---- Channel probing --------------------------------------------------- */

/* PCAN-Basic exposes USBBUS1..8 in 0x51..0x58 and USBBUS9..16 in
   0x509..0x510 (non-contiguous). Same applies to PCIBUS9..16 etc.
   For probe-time we cover the common low-numbered ranges; users with
   higher-numbered devices can still use --pcan CHANNEL explicitly. */
static const uint16_t k_probe_handles[] = {
  PCAN_USBBUS1, PCAN_USBBUS2, PCAN_USBBUS3, PCAN_USBBUS4,
  PCAN_USBBUS5, PCAN_USBBUS6, PCAN_USBBUS7, PCAN_USBBUS8,
  PCAN_PCIBUS1, PCAN_PCIBUS2, PCAN_PCIBUS3, PCAN_PCIBUS4,
  PCAN_PCIBUS5, PCAN_PCIBUS6, PCAN_PCIBUS7, PCAN_PCIBUS8
};

/* Decode one PCAN_CHANNEL_CONDITION value to a short label for the
   stderr probe report. Older PCAN-Basic versions use bitmask values
   (0x01=AVAILABLE, 0x02=OCCUPIED, 0x04=PCANVIEW), newer versions
   sometimes return the same values as enum-style codes; either way
   "any non-UNAVAILABLE state" means the device is physically present. */
static const char *condition_label(DWORD c) {
  switch (c) {
    case PCAN_CHANNEL_UNAVAILABLE: return "unavailable";
    case PCAN_CHANNEL_AVAILABLE:   return "available";
    case PCAN_CHANNEL_OCCUPIED:    return "occupied";
    case PCAN_CHANNEL_PCANVIEW:    return "pcanview";
    default:                       return "?";
  }
}

/* Query CAN FD capability. Returns true if the channel reports
   PCAN_FEATURE_FD_CAPABLE. Older drivers may not implement
   PCAN_CHANNEL_FEATURES; on PCAN_ERROR_ILLPARAMTYPE we conservatively
   return false (best to be honest and not offer a bridge that would
   fail at CAN_InitializeFD). */
static bool channel_supports_fd(uint16_t handle) {
  if (fp_getval == NULL) return false;
  DWORD features = 0;
  tpcan_status_t st = fp_getval((tpcan_handle_t)handle,
                                PCAN_CHANNEL_FEATURES,
                                &features, (DWORD)sizeof features);
  if (st != PCAN_ERROR_OK) return false;
  return (features & PCAN_FEATURE_FD_CAPABLE) != 0u;
}

size_t fbsec_pcan_probe_available(uint16_t *handles_out, size_t cap) {
  if (!fbsec_pcan_loaded()) return 0;
  size_t found        = 0;
  size_t classical_seen = 0;   /* present but non-FD-capable */
  size_t occupied_seen  = 0;
  for (size_t i = 0; i < sizeof k_probe_handles / sizeof k_probe_handles[0]; ++i) {
    DWORD condition = 0;
    tpcan_status_t st = fp_getval((tpcan_handle_t)k_probe_handles[i],
                                  PCAN_CHANNEL_CONDITION,
                                  &condition, (DWORD)sizeof condition);
    if (st != PCAN_ERROR_OK) continue;
    if (condition == PCAN_CHANNEL_UNAVAILABLE) continue;

    bool fd_capable = channel_supports_fd(k_probe_handles[i]);

    fprintf(stderr, "PCAN: %s -> condition=0x%02lX (%s), %s\n",
            fbsec_pcan_handle_name(k_probe_handles[i]),
            (unsigned long)condition, condition_label(condition),
            fd_capable ? "CAN FD capable" : "classical CAN only");

    if (condition == PCAN_CHANNEL_OCCUPIED) {
      ++occupied_seen;
      continue;
    }
    if (!fd_capable) {
      ++classical_seen;
      continue;
    }

    /* AVAILABLE or PCANVIEW + FD-capable: offer it. */
    if (handles_out != NULL && found < cap) {
      handles_out[found] = k_probe_handles[i];
    }
    ++found;
  }
  if (found == 0u && classical_seen > 0u) {
    fprintf(stderr,
            "PCAN: device(s) detected but none support CAN FD; the SOFA FD "
            "bridge needs an FD-capable interface (e.g. PCAN-USB FD or "
            "PCAN-USB Pro FD).\n");
  }
  if (found == 0u && occupied_seen > 0u) {
    fprintf(stderr,
            "PCAN: device(s) detected but channels are OCCUPIED, close "
            "PCAN-View / other PCAN clients to bridge from here.\n");
  }
  return found;
}

const char *fbsec_pcan_handle_name(uint16_t handle) {
  switch (handle) {
    case PCAN_USBBUS1: return "PCAN_USBBUS1";
    case PCAN_USBBUS2: return "PCAN_USBBUS2";
    case PCAN_USBBUS3: return "PCAN_USBBUS3";
    case PCAN_USBBUS4: return "PCAN_USBBUS4";
    case PCAN_USBBUS5: return "PCAN_USBBUS5";
    case PCAN_USBBUS6: return "PCAN_USBBUS6";
    case PCAN_USBBUS7: return "PCAN_USBBUS7";
    case PCAN_USBBUS8: return "PCAN_USBBUS8";
    case PCAN_PCIBUS1: return "PCAN_PCIBUS1";
    case PCAN_PCIBUS2: return "PCAN_PCIBUS2";
    case PCAN_PCIBUS3: return "PCAN_PCIBUS3";
    case PCAN_PCIBUS4: return "PCAN_PCIBUS4";
    case PCAN_PCIBUS5: return "PCAN_PCIBUS5";
    case PCAN_PCIBUS6: return "PCAN_PCIBUS6";
    case PCAN_PCIBUS7: return "PCAN_PCIBUS7";
    case PCAN_PCIBUS8: return "PCAN_PCIBUS8";
    default:           return "?";
  }
}

bool fbsec_pcan_parse_channel(const char *s, uint16_t *out) {
  if (s == NULL || out == NULL || *s == '\0') return false;
  /* Symbolic match (case-sensitive: matches the names we emit). */
  for (size_t i = 0; i < sizeof k_probe_handles / sizeof k_probe_handles[0]; ++i) {
    if (strcmp(s, fbsec_pcan_handle_name(k_probe_handles[i])) == 0) {
      *out = k_probe_handles[i];
      return true;
    }
  }
  /* Numeric (decimal or 0x-hex). */
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 0);
  if (end == s || *end != '\0' || v == 0u || v > 0xFFFFu) return false;
  *out = (uint16_t)v;
  return true;
}

/* ---- Open / close ------------------------------------------------------ */

bool fbsec_pcan_open_500k_2m(uint16_t handle) {
  if (!fbsec_pcan_loaded()) return false;
  if (g_open) return false;
  tpcan_status_t st = fp_init((tpcan_handle_t)handle, g_bitrate_500k_2m);
  if (st != PCAN_ERROR_OK) {
    fprintf(stderr, "PCAN: CAN_InitializeFD(%s) failed: 0x%08lX\n",
            fbsec_pcan_handle_name(handle), (unsigned long)st);
    return false;
  }
  g_open_handle = handle;
  g_open = true;
  return true;
}

void fbsec_pcan_close(void) {
  if (!g_open) return;
  if (fp_uninit != NULL) {
    (void)fp_uninit((tpcan_handle_t)g_open_handle);
  }
  g_open = false;
  g_open_handle = PCAN_NONEBUS;
}

/* ---- DLC mapping ------------------------------------------------------- */

/* Round @p len up to the nearest legal CAN FD length (0..8, 12, 16, 20,
   24, 32, 48, 64) and return the corresponding DLC code (0..15). */
static uint8_t len_to_dlc(uint8_t len, uint8_t *padded_len_out) {
  uint8_t plen, dlc;
  if      (len <=  8u) { plen = len;  dlc = len;       }
  else if (len <= 12u) { plen = 12u;  dlc = 9u;        }
  else if (len <= 16u) { plen = 16u;  dlc = 10u;       }
  else if (len <= 20u) { plen = 20u;  dlc = 11u;       }
  else if (len <= 24u) { plen = 24u;  dlc = 12u;       }
  else if (len <= 32u) { plen = 32u;  dlc = 13u;       }
  else if (len <= 48u) { plen = 48u;  dlc = 14u;       }
  else                 { plen = 64u;  dlc = 15u;       }
  if (padded_len_out != NULL) *padded_len_out = plen;
  return dlc;
}

static uint8_t dlc_to_len(uint8_t dlc) {
  static const uint8_t k_dlc_map[16] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64
  };
  return k_dlc_map[dlc & 0x0Fu];
}

/* ---- Read / write ------------------------------------------------------ */

bool fbsec_pcan_write_fd(uint32_t can_id, bool extended, bool brs,
                         const uint8_t *data, uint8_t len) {
  if (!g_open || fp_write == NULL) return false;
  if (len > FBSEC_PCAN_MSG_DATA_MAX) return false;

  tpcan_msg_fd_t m;
  memset(&m, 0, sizeof m);
  m.ID = can_id;
  m.MSGTYPE = (BYTE)PCAN_MESSAGE_FD;
  if (extended) m.MSGTYPE |= (BYTE)PCAN_MESSAGE_EXTENDED;
  if (brs)      m.MSGTYPE |= (BYTE)PCAN_MESSAGE_BRS;

  uint8_t padded = 0u;
  m.DLC = len_to_dlc(len, &padded);
  if (data != NULL && len > 0u) memcpy(m.DATA, data, len);
  /* tail bytes m.DATA[len..padded-1] stay zero from memset. */
  (void)padded;

  tpcan_status_t st = fp_write((tpcan_handle_t)g_open_handle, &m);
  if (st != PCAN_ERROR_OK) {
    fprintf(stderr, "PCAN: CAN_WriteFD failed: 0x%08lX\n", (unsigned long)st);
    return false;
  }
  return true;
}

bool fbsec_pcan_read_fd(uint32_t *can_id_out, bool *extended_out, bool *brs_out,
                        uint8_t *data_out, uint8_t *len_out) {
  if (!g_open || fp_read == NULL) return false;
  tpcan_msg_fd_t m;
  tpcan_timestamp_fd_t ts = 0;
  tpcan_status_t st = fp_read((tpcan_handle_t)g_open_handle, &m, &ts);
  if (st == PCAN_ERROR_QRCVEMPTY) return false;
  if (st != PCAN_ERROR_OK) {
    /* Do not spam on transient errors (bus-off, etc.); a single line per
       drain pass is enough for diagnosis without flooding. */
    fprintf(stderr, "PCAN: CAN_ReadFD failed: 0x%08lX\n", (unsigned long)st);
    return false;
  }
  if (can_id_out  != NULL) *can_id_out  = m.ID;
  if (extended_out != NULL) *extended_out = (m.MSGTYPE & PCAN_MESSAGE_EXTENDED) != 0u;
  if (brs_out     != NULL) *brs_out     = (m.MSGTYPE & PCAN_MESSAGE_BRS) != 0u;
  uint8_t L = dlc_to_len(m.DLC);
  if (L > FBSEC_PCAN_MSG_DATA_MAX) L = FBSEC_PCAN_MSG_DATA_MAX;
  if (data_out != NULL && L > 0u) memcpy(data_out, m.DATA, L);
  if (len_out  != NULL) *len_out = L;
  return true;
}

/* EOF */
