/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_hooks.c
 * @brief   SOFA server_common, port hooks + demo buffers, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_hooks.h"
#include "server_common_keys.h"
#include "server_common_const_od.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include "fbsec_secure_od.h"

/* ---- File-static state ----------------------------------------------- */

static uint16_t g_my_dev = 0u;

/* Shadow buffer for the 4-byte secure pair: 0x20200000 reads return this;
   0x20100000 writes overwrite it. Initial value mirrors fbsec_server_spec
   section 11. */
static uint8_t g_value[FBSEC_SERVER_ENTRY_VALUE_LEN] = {
  0x00u, 0x11u, 0x22u, 0x33u
};

/* C018h (0xC0180000) backing store. Filled by
   @ref fbsec_server_hooks_load_identity with the 1018h identity quad. */
static uint8_t g_secure_ro[FBSEC_SERVER_ENTRY_SECURE_LEN];

/* SECURE_WO 0x20160000 backing store (16-byte demo write target). */
static uint8_t g_secure_wo[FBSEC_SERVER_ENTRY_SECURE_LEN];

#if FBSEC_FEATURE_ASYM
/* RPK read twin 0x20210000: 4-byte value that auto-bumps on read, mirror of
   g_value but reached only through C042h signed read. */
static uint8_t g_rpk_ro[FBSEC_SERVER_ENTRY_VALUE_LEN] = {
  0xA0u, 0xA1u, 0xA2u, 0xA3u
};

/* RPK write twin 0x20170000: 16-byte C042h signed-write target. */
static uint8_t g_rpk_wo[FBSEC_SERVER_ENTRY_SECURE_LEN];
#endif

/* ---- Setup / accessors ----------------------------------------------- */

void fbsec_server_hooks_set_my_dev(uint16_t my_dev) {
  g_my_dev = my_dev;
}

bool fbsec_server_hooks_load_identity(void) {
  return fbsec_const_od_get_identity(g_secure_ro);
}

const uint8_t *fbsec_server_hooks_value(void) {
  return g_value;
}

const uint8_t *fbsec_server_hooks_secure_ro(void) {
  return g_secure_ro;
}

const uint8_t *fbsec_server_hooks_secure_wo(void) {
  return g_secure_wo;
}

#if FBSEC_FEATURE_ASYM
const uint8_t *fbsec_server_hooks_rpk_wo(void) {
  return g_rpk_wo;
}
#endif

/* ---- Port hook: device id -------------------------------------------- */

uint16_t fbsec_sod_port_get_device_id(void) {
  return g_my_dev;
}

/* ---- Port hook: time --------------------------------------------------- */

uint16_t fbsec_sod_port_get_time_ms(void) {
#ifdef _WIN32
  return (uint16_t)GetTickCount();
#else
  /* Linux: clock_gettime(CLOCK_MONOTONIC) milliseconds. */
  return 0u;
#endif
}

/* ---- Port hook: random ------------------------------------------------- */

bool fbsec_sod_port_random(uint8_t *buf, uint16_t len) {
  if (buf == NULL || len == 0u) {
    return false;
  }
#ifdef _WIN32
  HCRYPTPROV hProv = 0;
  if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT)) {
    return false;
  }
  bool ok = (CryptGenRandom(hProv, (DWORD)len, (BYTE *)buf) != FALSE);
  (void)CryptReleaseContext(hProv, 0);
  return ok;
#else
  /* Linux: getrandom(2) or /dev/urandom. */
  return false;
#endif
}

/* ---- Port hook: access policy (default-allow) ------------------------ */

bool fbsec_sod_port_access_allowed(fbsec_sod_op_t op, uint32_t data_id) {
  (void)op;
  (void)data_id;
  return true;        /* default-allow; host overrides for lock policy */
}

/*
 * Role policy for the reference demo:
 *   keyid 1 (Provisioning Session Key) -> read + write
 *   keyid 2 (Integrator   Session Key) -> read + write
 *   keyid 3 (Operator     Session Key) -> read only
 * Any other provisioned keyid is treated as Operator-level (read-
 * only) until the host installs a real role mapping.
 */
bool fbsec_sod_port_role_allowed(fbsec_sod_op_t op,
                                 uint8_t        key_id_base,
                                 uint32_t       data_id) {
  (void)data_id;
  if (op == FBSEC_SOD_OP_READ) {
    return true;
  }
  /* Write: only Provisioning Session Key and Integrator Session Key. */
  return (key_id_base == FBSEC_DEMO_KEYID_PROVISIONING)
      || (key_id_base == FBSEC_DEMO_KEYID_INTEGRATOR);
}

/* ---- Port hook: read-before ------------------------------------------ */

fbsec_abort_t fbsec_sod_port_read_before(uint32_t data_id,
                                         uint8_t *dst,
                                         uint16_t *len) {
  if (data_id == FBSEC_SERVER_ENTRY_SRD_DATA_ID) {
    memcpy(dst, g_secure_ro, FBSEC_SERVER_ENTRY_SECURE_LEN);
    *len = FBSEC_SERVER_ENTRY_SECURE_LEN;
    return FBSEC_ABORT_NONE;
  }
  if (data_id == FBSEC_SERVER_ENTRY_RD_DATA_ID) {
    /* Return current value, then bump (big-endian +1) so successive
       polls visibly tick. Writes via fbsec_sod_port_write_after still
       overwrite g_value normally. */
    memcpy(dst, g_value, FBSEC_SERVER_ENTRY_VALUE_LEN);
    *len = FBSEC_SERVER_ENTRY_VALUE_LEN;
    uint32_t v = ((uint32_t)g_value[0] << 24)
               | ((uint32_t)g_value[1] << 16)
               | ((uint32_t)g_value[2] <<  8)
               |  (uint32_t)g_value[3];
    v++;
    g_value[0] = (uint8_t)((v >> 24) & 0xFFu);
    g_value[1] = (uint8_t)((v >> 16) & 0xFFu);
    g_value[2] = (uint8_t)((v >>  8) & 0xFFu);
    g_value[3] = (uint8_t)( v        & 0xFFu);
    return FBSEC_ABORT_NONE;
  }
#if FBSEC_FEATURE_ASYM
  if (data_id == FBSEC_SERVER_ENTRY_RPK_RD_DATA_ID) {
    /* RPK read twin: return current value, then bump (big-endian +1) so
       successive signed reads visibly tick, mirroring 0x20200000. */
    memcpy(dst, g_rpk_ro, FBSEC_SERVER_ENTRY_VALUE_LEN);
    *len = FBSEC_SERVER_ENTRY_VALUE_LEN;
    uint32_t rv = ((uint32_t)g_rpk_ro[0] << 24)
                | ((uint32_t)g_rpk_ro[1] << 16)
                | ((uint32_t)g_rpk_ro[2] <<  8)
                |  (uint32_t)g_rpk_ro[3];
    rv++;
    g_rpk_ro[0] = (uint8_t)((rv >> 24) & 0xFFu);
    g_rpk_ro[1] = (uint8_t)((rv >> 16) & 0xFFu);
    g_rpk_ro[2] = (uint8_t)((rv >>  8) & 0xFFu);
    g_rpk_ro[3] = (uint8_t)( rv        & 0xFFu);
    return FBSEC_ABORT_NONE;
  }
#endif
  *len = 0u;
  return FBSEC_ABORT_NO_OBJECT;
}

/* ---- Port hook: write-after ------------------------------------------ */

fbsec_abort_t fbsec_sod_port_write_after(uint32_t       data_id,
                                         const uint8_t *src,
                                         uint16_t       len) {
  if (data_id == FBSEC_SERVER_ENTRY_SWR_DATA_ID) {
    if (len != FBSEC_SERVER_ENTRY_SECURE_LEN) {
      return FBSEC_ABORT_TYPE_MISMATCH;
    }
    memcpy(g_secure_wo, src, FBSEC_SERVER_ENTRY_SECURE_LEN);
    return FBSEC_ABORT_NONE;
  }
  if (data_id == FBSEC_SERVER_ENTRY_WR_DATA_ID) {
    if (len != FBSEC_SERVER_ENTRY_VALUE_LEN) {
      return FBSEC_ABORT_TYPE_MISMATCH;
    }
    memcpy(g_value, src, FBSEC_SERVER_ENTRY_VALUE_LEN);
    return FBSEC_ABORT_NONE;
  }
#if FBSEC_FEATURE_ASYM
  if (data_id == FBSEC_SERVER_ENTRY_RPK_WR_DATA_ID) {
    if (len != FBSEC_SERVER_ENTRY_SECURE_LEN) {
      return FBSEC_ABORT_TYPE_MISMATCH;
    }
    memcpy(g_rpk_wo, src, FBSEC_SERVER_ENTRY_SECURE_LEN);
    return FBSEC_ABORT_NONE;
  }
#endif
  return FBSEC_ABORT_NO_OBJECT;
}

/* EOF */
