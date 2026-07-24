/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_od.c
 * @brief   SOFA server_common, secure OD setup, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.1 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_od.h"
#include "server_common_hooks.h"
#include "server_common_keys.h"
#include "server_common_const_od.h"
#include "server_common_lifecycle.h"

#include <stdio.h>
#include <string.h>

#include "fbsec_secure_od.h"

#if FBSEC_FEATURE_ASYM
#include "server_common_asym.h"
#include "fbsec_asym.h"
#include "fbsec_asym_demo.h"
#endif

int fbsec_server_od_init(uint16_t my_dev, const char *key_file_path,
                         const char *od_file_path, bool install_demo_keys) {
  bool identity_ok;
  bool have_session_keys;

  fbsec_sod_init();
  fbsec_server_lifecycle_init();      /* Factory until keys settle below */
  fbsec_server_hooks_set_my_dev(my_dev);

#if FBSEC_FEATURE_ASYM
  fbsec_server_asym_init();   /* device identity store (IDevID, anchor, ...) */

  /* Pre-install the demo integrator public key as the authorizing peer for
     C042h signed writes and C049h signed commands. A real device installs
     this at commissioning; the demo derives it from the shared demo seed so
     the client's integrator signature verifies out of the box. */
  {
    const uint8_t integ_seed[FBSEC_ASYM_SEED_SIZE] = FBSEC_DEMO_INTEGRATOR_SEED_BYTES;
    fbsec_keypair_t integ;
    fbsec_pubkey_t  integ_pub;
    if (fbsec_asym_keygen(integ_seed, &integ)) {
      memcpy(integ_pub.pub, integ.pub, FBSEC_ASYM_PUBKEY_SIZE);
      (void)fbsec_server_asym_set_peer(1u, &integ_pub);
    }
  }
#endif

  /* Load the constant, unsecured OD entries (object 1018h etc.) before
     anything reads them. C018h is served from the 1018h identity quad,
     so it is only registered when that identity is present. */
  fbsec_const_od_init();
  if (od_file_path != NULL) {
    if (fbsec_const_od_load_file(od_file_path) != 0) {
      return -1;
    }
  }
  identity_ok = fbsec_server_hooks_load_identity();

  /* The demo entries leave .key_id = FBSEC_SOD_KEY_NONE so any provisioned
     key passes the AEAD step; the actual role policy (Provisioning Session
     Key + Integrator Session Key can read/write; Operator Session Key can
     read but not write) lives in fbsec_sod_port_role_allowed. value_type
     stays at the default (BIN) so trace renders as hex. */
  fbsec_sod_entry_t e_sro = {
    .data_id      = FBSEC_SERVER_ENTRY_SRD_DATA_ID,   /* C018h identity */
    .key_id       = FBSEC_SOD_KEY_NONE,
    .access_flags = FBSEC_SOD_ACCESS_SECURE_RO,
    .data_len     = FBSEC_SERVER_ENTRY_SECURE_LEN
  };
  fbsec_sod_entry_t e_swo = {
    .data_id      = FBSEC_SERVER_ENTRY_SWR_DATA_ID,   /* 2016h demo write */
    .key_id       = FBSEC_SOD_KEY_NONE,
    .access_flags = FBSEC_SOD_ACCESS_SECURE_WO,
    .data_len     = FBSEC_SERVER_ENTRY_SECURE_LEN
  };
  fbsec_sod_entry_t e_pro = {
    .data_id      = FBSEC_SERVER_ENTRY_RD_DATA_ID,
    .key_id       = FBSEC_SOD_KEY_NONE,
    .access_flags = FBSEC_SOD_ACCESS_SECURE_RO,
    .data_len     = FBSEC_SERVER_ENTRY_VALUE_LEN
  };
  fbsec_sod_entry_t e_pwo = {
    .data_id      = FBSEC_SERVER_ENTRY_WR_DATA_ID,
    .key_id       = FBSEC_SOD_KEY_NONE,
    .access_flags = FBSEC_SOD_ACCESS_SECURE_WO,
    .data_len     = FBSEC_SERVER_ENTRY_VALUE_LEN
  };
  /* C018h is registered only when its 1018h identity is loaded. */
  if ((identity_ok && !fbsec_sod_register_entry(&e_sro))
      || !fbsec_sod_register_entry(&e_swo)
      || !fbsec_sod_register_entry(&e_pro)
      || !fbsec_sod_register_entry(&e_pwo)) {
    fprintf(stderr, "server_common: failed to register secure entries\n");
    return -1;
  }

  /* Load --key-file (if any) first; demo keys fill any unset slots only
     when explicitly requested (--demo-keys). Neither path present means
     the device boots with no session keys, i.e. Uncommissioned. */
  if (key_file_path != NULL) {
    if (fbsec_server_load_key_file(key_file_path) != 0) {
      return -1;
    }
  }
  if (install_demo_keys) {
    fbsec_server_install_demo_keys_if_unset();
  }

  /* Drive the commissioning stage from whether a session key is present.
     A key ladder or a persisted owner would refine this in later phases;
     for now the honest split is keys => Operational, none => Uncommissioned. */
  have_session_keys = fbsec_sod_has_key(FBSEC_DEMO_KEYID_PROVISIONING)
                   || fbsec_sod_has_key(FBSEC_DEMO_KEYID_INTEGRATOR)
                   || fbsec_sod_has_key(FBSEC_DEMO_KEYID_OPERATOR);
  fbsec_server_lifecycle_set(have_session_keys ? FBSEC_STAGE_OPERATIONAL
                                               : FBSEC_STAGE_UNCOMMISSIONED);
  return 0;
}

/* EOF */
