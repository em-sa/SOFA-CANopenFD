/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_addr.c
 * @brief   SOFA CANopen FD, data_id <-> (index, sub) helpers, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 06-MAY-2026
 *
 * Three trivial bit-shift helpers; no dependencies beyond the public
 * header. See the header for the encoding rationale and the
 * canonical references in `doc/`.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "fbsec_co_fd_addr.h"

uint32_t fbsec_co_fd_data_id_from_index_sub(uint16_t index, uint8_t subindex) {
  return ((uint32_t)index << 16) | ((uint32_t)subindex << 8);
}

void fbsec_co_fd_index_sub_from_data_id(uint32_t  data_id,
                                        uint16_t *index_out,
                                        uint8_t  *subindex_out) {
  *index_out    = (uint16_t)((data_id >> 16) & 0xFFFFu);
  *subindex_out = (uint8_t) ((data_id >>  8) & 0xFFu);
}

bool fbsec_co_fd_data_id_is_canopen_form(uint32_t data_id) {
  if ((data_id & 0xFFu) != 0u) {
    return false;
  }
  if (((data_id >> 16) & 0xFFFFu) < 0x1000u) {
    return false;
  }
  return true;
}

/* EOF */
