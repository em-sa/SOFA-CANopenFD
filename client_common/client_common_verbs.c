/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_verbs.c
 * @brief   SOFA client_common, secure verb runners, implementation.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_verbs.h"
#include "client_common_keys.h"
#include "client_common_trace.h"

#include <stdio.h>
#include <string.h>

#include "fbsec_aead.h"
#include "fbsec_secure_proto.h"

/* ---- Status -> human-readable ------------------------------------- */

const char *fbsec_client_secp_strerror(fbsec_secure_status_t rc) {
  switch (rc) {
    case FBSEC_SECP_OK:       return "ok";
    case FBSEC_SECP_TIMEOUT:  return "timeout";
    case FBSEC_SECP_TX:       return "transmit failed";
    case FBSEC_SECP_PROTOCOL: return "protocol error";
    case FBSEC_SECP_BUFSIZE:  return "buffer size";
    case FBSEC_SECP_ABORT:    return "server abort";
    case FBSEC_SECP_TAG:      return "tag verify failed";
    case FBSEC_SECP_RANDOM:   return "random source failed";
    default:                  return "unknown";
  }
}

/* ---- Internal: emit per-call summary ----------------------------- */

/**
 * @brief   Emit the per-call result line and close the deferred RX row.
 * @param   success    true when the verb completed successfully.
 * @param   data_id    Object data id for the plain-text close.
 * @param   plain      Decrypted payload to print, or NULL.
 * @param   plen       Length of @p plain in bytes.
 * @param   abort_code Server abort code, used when @p fail_text is NULL.
 * @param   fail_text  Failure message, or NULL to render @p abort_code.
 */
static void emit_summary(bool success,
                         uint32_t data_id,
                         const uint8_t *plain, size_t plen,
                         uint32_t abort_code, const char *fail_text) {
  if (fbsec_client_trace_get_quiet()) {
    return;
  }
  if (success) {
    if (plain != NULL && plen > 0) {
      fbsec_client_trace_close_with_plain(data_id, plain, (uint16_t)plen);
    } else {
      fbsec_client_trace_close_no_plain();
    }
    return;
  }
  fbsec_client_trace_close_no_plain();
  if (fail_text != NULL) {
    printf("%sFAIL  %s%s\n",
           fbsec_client_trace_col_abort(), fail_text,
           fbsec_client_trace_col_end());
  } else {
    printf("%sFAIL  abort 0x%08X%s\n",
           fbsec_client_trace_col_abort(), (unsigned)abort_code,
           fbsec_client_trace_col_end());
  }
}

/* ---- Single-shot ------------------------------------------------- */

#if FBSEC_FEATURE_READ
int fbsec_client_run_secure_read(const fbsec_secure_transport_t *transport,
                                 uint16_t target,
                                 uint32_t data_id,
                                 uint32_t timeout_ms,
                                 uint8_t *out_buf, uint32_t out_buf_size,
                                 uint32_t *out_len) {
  uint32_t abort_code = 0u;
  uint32_t got = 0u;
  fbsec_client_keys_clear_observed_salt();
  fbsec_client_trace_set_verb("srd");
  fbsec_client_trace_reset_round();

  fbsec_secure_status_t rc = fbsec_secure_read(transport,
                                           target, data_id,
                                           fbsec_client_keys_session(),
                                           fbsec_client_keys_effective_keyid(),
                                           out_buf, out_buf_size,
                                           timeout_ms,
                                           &got, &abort_code);
  fbsec_client_trace_set_verb("");
  if (out_len != NULL) {
    *out_len = got;
  }

  if (rc == FBSEC_SECP_OK) {
    emit_summary(true, data_id, out_buf, (size_t)got, 0, NULL);
    return 0;
  }
  if (rc == FBSEC_SECP_ABORT) {
    emit_summary(false, data_id, NULL, 0, abort_code, NULL);
    return 2;
  }
  if (rc == FBSEC_SECP_TAG) {
    emit_summary(false, data_id, NULL, 0, 0, "tag verify failed");
    return 3;
  }
  emit_summary(false, data_id, NULL, 0, 0, fbsec_client_secp_strerror(rc));
  return 1;
}
#endif

#if FBSEC_FEATURE_WRITE
int fbsec_client_run_secure_write(const fbsec_secure_transport_t *transport,
                                  uint16_t target,
                                  uint32_t data_id,
                                  const uint8_t *payload, uint16_t plen,
                                  uint32_t timeout_ms) {
  uint32_t abort_code = 0u;
  fbsec_client_keys_clear_observed_salt();
  fbsec_client_trace_set_verb("swr");
  fbsec_client_trace_reset_round();

  fbsec_secure_status_t rc = fbsec_secure_write(transport,
                                            target, data_id,
                                            fbsec_client_keys_session(),
                                            fbsec_client_keys_effective_keyid(),
                                            payload, plen,
                                            timeout_ms,
                                            &abort_code);
  fbsec_client_trace_set_verb("");

  if (rc == FBSEC_SECP_OK) {
    emit_summary(true, data_id, NULL, 0, 0, NULL);
    return 0;
  }
  if (rc == FBSEC_SECP_ABORT) {
    emit_summary(false, data_id, NULL, 0, abort_code, NULL);
    return 2;
  }
  if (rc == FBSEC_SECP_TAG) {
    emit_summary(false, data_id, NULL, 0, 0, "tag verify failed");
    return 3;
  }
  emit_summary(false, data_id, NULL, 0, 0, fbsec_client_secp_strerror(rc));
  return 1;
}
#endif

/* ---- Cyclic-mode --------------------------------------------------- */

#if FBSEC_FEATURE_CYCLIC && FBSEC_FEATURE_READ
int fbsec_client_run_secure_read_poll(const fbsec_secure_transport_t *transport,
                                      uint16_t target,
                                      uint32_t data_id,
                                      uint32_t count,
                                      uint32_t timeout_ms) {
  fbsec_secure_session_t sess;
  memset(&sess, 0, sizeof sess);

  uint32_t abort_code = 0u;
  fbsec_client_keys_clear_observed_salt();
  /* Iteration 1 is a cyclic-capable single SRD: full Pass-1 + Pass-2,
     returns the data AND a session_id we use for follow-up polls.
     Iterations 2..count use the streamlined poll path. */
  fbsec_client_trace_set_verb("srd");
  fbsec_client_trace_reset_round();
  uint8_t  buf[FBSEC_AEAD_MAX_PROTECTED];
  uint32_t armed_len = 0u;
  fbsec_secure_status_t rc = fbsec_secure_read_armed(transport,
                                               target, data_id,
                                               fbsec_client_keys_session(),
                                               fbsec_client_keys_effective_keyid(),
                                               buf, sizeof buf,
                                               timeout_ms,
                                               &armed_len,
                                               &abort_code, &sess);
  fbsec_client_trace_set_verb("");
  if (rc != FBSEC_SECP_OK) {
    if (rc == FBSEC_SECP_ABORT) {
      emit_summary(false, data_id, NULL, 0, abort_code, NULL);
      return 2;
    }
    if (rc == FBSEC_SECP_TAG) {
      emit_summary(false, data_id, NULL, 0, 0, "tag verify failed");
      return 3;
    }
    emit_summary(false, data_id, NULL, 0, 0, fbsec_client_secp_strerror(rc));
    return 1;
  }
  emit_summary(true, data_id, buf, (size_t)armed_len, 0, NULL);

  uint16_t got = 0u;
  int      worst_exit = 0;
  for (uint32_t n = 2u; n <= count; ++n) {
    fbsec_client_trace_set_verb("pollrd");
    fbsec_client_trace_reset_round();
    rc = fbsec_secure_poll_read(transport,
                              target, fbsec_client_keys_session(),
                              timeout_ms, &abort_code,
                              &sess, buf, sizeof buf, &got, NULL);
    fbsec_client_trace_set_verb("");
    if (rc == FBSEC_SECP_OK) {
      emit_summary(true, data_id, buf, (size_t)got, 0, NULL);
    } else if (rc == FBSEC_SECP_ABORT) {
      emit_summary(false, data_id, NULL, 0, abort_code, NULL);
      if (worst_exit < 2) {
        worst_exit = 2;
      }
      break;
    } else if (rc == FBSEC_SECP_TAG) {
      emit_summary(false, data_id, NULL, 0, 0, "tag verify failed");
      if (worst_exit < 3) {
        worst_exit = 3;
      }
      break;
    } else {
      emit_summary(false, data_id, NULL, 0, 0, fbsec_client_secp_strerror(rc));
      if (worst_exit < 1) {
        worst_exit = 1;
      }
      break;
    }
  }
  memset(&sess, 0, sizeof sess);
  return worst_exit;
}
#endif

#if FBSEC_FEATURE_CYCLIC && FBSEC_FEATURE_WRITE
int fbsec_client_run_secure_write_poll(const fbsec_secure_transport_t *transport,
                                       uint16_t target,
                                       uint32_t data_id,
                                       const uint8_t *payload, uint16_t plen,
                                       uint32_t count,
                                       uint32_t timeout_ms) {
  fbsec_secure_session_t sess;
  memset(&sess, 0, sizeof sess);

  uint32_t abort_code = 0u;
  fbsec_client_keys_clear_observed_salt();
  /* Iteration 1 is a cyclic-capable single SWR: full Pass-1 + Pass-2,
     commits the data AND establishes a session for follow-up polls. */
  fbsec_client_trace_set_verb("swr");
  fbsec_client_trace_reset_round();
  fbsec_secure_status_t rc = fbsec_secure_write_armed(transport,
                                                target, data_id,
                                                fbsec_client_keys_session(),
                                                fbsec_client_keys_effective_keyid(),
                                                payload, plen,
                                                timeout_ms,
                                                &abort_code, &sess);
  fbsec_client_trace_set_verb("");
  if (rc != FBSEC_SECP_OK) {
    if (rc == FBSEC_SECP_ABORT) {
      emit_summary(false, data_id, NULL, 0, abort_code, NULL);
      return 2;
    }
    if (rc == FBSEC_SECP_TAG) {
      emit_summary(false, data_id, NULL, 0, 0, "tag verify failed");
      return 3;
    }
    emit_summary(false, data_id, NULL, 0, 0, fbsec_client_secp_strerror(rc));
    return 1;
  }
  emit_summary(true, data_id, NULL, 0, 0, NULL);

  int worst_exit = 0;
  for (uint32_t n = 2u; n <= count; ++n) {
    fbsec_client_trace_set_verb("pollwr");
    fbsec_client_trace_reset_round();
    rc = fbsec_secure_poll_write(transport,
                               target, fbsec_client_keys_session(),
                               timeout_ms, &abort_code,
                               &sess, payload, plen, NULL);
    fbsec_client_trace_set_verb("");
    if (rc == FBSEC_SECP_OK) {
      emit_summary(true, data_id, NULL, 0, 0, NULL);
    } else if (rc == FBSEC_SECP_ABORT) {
      emit_summary(false, data_id, NULL, 0, abort_code, NULL);
      if (worst_exit < 2) {
        worst_exit = 2;
      }
      break;
    } else if (rc == FBSEC_SECP_TAG) {
      emit_summary(false, data_id, NULL, 0, 0, "tag verify failed");
      if (worst_exit < 3) {
        worst_exit = 3;
      }
      break;
    } else {
      emit_summary(false, data_id, NULL, 0, 0, fbsec_client_secp_strerror(rc));
      if (worst_exit < 1) {
        worst_exit = 1;
      }
      break;
    }
  }
  memset(&sess, 0, sizeof sess);
  return worst_exit;
}
#endif

/* EOF */
