/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_caps.c
 * @brief   SOFA client_common, capability/status descriptor reader.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.2 of 22-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_caps.h"

#include <stdio.h>
#include <string.h>

/* Read one C000h sub-index and decode it into @p caps. */
static int read_one_sub(const fbsec_secure_transport_t *transport,
                        uint16_t target, uint8_t sub,
                        uint32_t timeout_ms, fbsec_caps_t *caps) {
  uint8_t  buf[8];
  uint32_t len   = 0u;
  fbsec_abort_t abrt = FBSEC_ABORT_NONE;
  uint32_t data_id = (uint32_t)(((uint32_t)FBSEC_DESC_CAP_INDEX << 16) |
                                ((uint32_t)sub << 8));
  fbsec_secure_status_t rc;

  rc = transport->read(transport->ctx, target, data_id, NULL, 0u,
                       buf, (uint32_t)sizeof(buf), timeout_ms, &len, &abrt);
  if (rc == FBSEC_SECP_ABORT) {
    return 2;
  }
  if (rc != FBSEC_SECP_OK) {
    return 1;
  }
  if (!fbsec_caps_deserialize_sub(caps, sub, buf, (uint16_t)len)) {
    return 1;
  }
  return 0;
}

int fbsec_client_read_caps(const fbsec_secure_transport_t *transport,
                           uint16_t target, uint32_t timeout_ms,
                           fbsec_caps_t *out) {
  uint8_t sub;
  int     rc;

  if ((transport == NULL) || (transport->read == NULL) || (out == NULL)) {
    return 1;
  }

  /* Sub 0x00 carries the highest sub-index, so it bounds the loop. */
  rc = read_one_sub(transport, target, 0x00u, timeout_ms, out);
  if (rc != 0) {
    return rc;
  }
  if (out->highest_sub > FBSEC_DESC_CAP_SUB_MAX) {
    return 1;
  }

  for (sub = 0x01u; sub <= out->highest_sub; sub++) {
    rc = read_one_sub(transport, target, sub, timeout_ms, out);
    if (rc != 0) {
      return rc;
    }
  }
  return 0;
}

bool fbsec_client_caps_meets_min(const fbsec_caps_t *caps,
                                 fbsec_client_min_sec_t floor) {
  if (floor == FBSEC_CLIENT_SEC_ANY) {
    return true;
  }
  if (caps == NULL) {
    return false;
  }
  /* Mechanisms live in the sub 08h bitmap; an absent sub 08h leaves the
     field zero, which fails any non-ANY floor - the intended fail-closed. */
  uint16_t mech = caps->mechanisms;
  if (floor == FBSEC_CLIENT_SEC_AEAD) {
    return (mech & FBSEC_MECH_AEAD) != 0u;
  }
  if (floor == FBSEC_CLIENT_SEC_SIGNED) {
    return (mech & FBSEC_MECH_RPK) != 0u;
  }
  if (floor == FBSEC_CLIENT_SEC_X509) {
    return (mech & FBSEC_MECH_X509) != 0u;
  }
  return false;
}

int fbsec_client_enforce_min_security(const fbsec_secure_transport_t *transport,
                                      uint16_t target, uint32_t timeout_ms,
                                      fbsec_client_min_sec_t floor, bool quiet) {
  fbsec_caps_t caps;
  int          rc;
  const char  *want = (floor == FBSEC_CLIENT_SEC_SIGNED) ? "signed (RPK)"
                    : (floor == FBSEC_CLIENT_SEC_X509)   ? "X.509"
                    : "AEAD";

  if (floor == FBSEC_CLIENT_SEC_ANY) {
    return 0;
  }

  memset(&caps, 0, sizeof caps);
  rc = fbsec_client_read_caps(transport, target, timeout_ms, &caps);
  if (rc != 0) {
    fprintf(stderr,
            "policy: cannot read the capability descriptor (rc=%d); "
            "refusing to proceed rather than assume a security level.\n", rc);
    return 1;
  }
  if (!fbsec_client_caps_meets_min(&caps, floor)) {
    fprintf(stderr,
            "policy: device 0x%02X does not advertise the required %s mechanism; "
            "refusing rather than downgrading (the cold descriptor may be spoofed).\n",
            (unsigned)target, want);
    return 1;
  }
  if (!quiet) {
    printf("policy: minimum security satisfied (device advertises %s).\n", want);
  }
  return 0;
}

/* EOF */
