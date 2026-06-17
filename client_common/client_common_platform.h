/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_platform.h
 * @brief   SOFA client_common, endian + time + console helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Tiny utility surface used by every other client_common_*.c. The
 * Windows-specific bits (`fbsec_client_format_timestamp`,
 * `fbsec_client_console_enable_ansi`, `fbsec_client_monotonic_ms`)
 * are implemented behind `#ifdef _WIN32`; a Linux port is later work.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef CLIENT_COMMON_PLATFORM_H
#define CLIENT_COMMON_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Little-endian helpers --------------------------------------------- */

uint16_t fbsec_client_read_u16le(const uint8_t *p);
uint32_t fbsec_client_read_u32le(const uint8_t *p);
void     fbsec_client_write_u16le(uint8_t *p, uint16_t v);
void     fbsec_client_write_u32le(uint8_t *p, uint32_t v);

/* ---- Time -------------------------------------------------------------- */

/** Monotonic millisecond timestamp (GetTickCount). Wraps after ~49 days. */
uint32_t fbsec_client_monotonic_ms(void);

/** Format current local wall-clock as "HH:MM:SS.mmm". */
void fbsec_client_format_timestamp(char *buf, size_t buflen);

/* ---- Console ---------------------------------------------------------- */

bool fbsec_client_stdout_is_console(void);
void fbsec_client_console_enable_ansi(void);

#ifdef __cplusplus
}
#endif

#endif /* CLIENT_COMMON_PLATFORM_H */
/* EOF */
