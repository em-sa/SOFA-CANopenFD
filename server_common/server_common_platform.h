/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_platform.h
 * @brief   SOFA server_common, endian + time + console helpers.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Tiny utility surface used by every other server_common_*.c. The
 * Windows-specific bits (`fbsec_server_format_timestamp`,
 * `fbsec_server_console_enable_ansi`) are implemented behind
 * `#ifdef _WIN32`; a Linux port is later work.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef SERVER_COMMON_PLATFORM_H
#define SERVER_COMMON_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Little-endian helpers --------------------------------------------- */

/**
 * @brief Read a little-endian unsigned 16-bit value from a byte buffer.
 *
 * @param p  source buffer; at least 2 bytes must be readable.
 * @return   the decoded 16-bit value.
 */
uint16_t fbsec_server_read_u16le(const uint8_t *p);

/**
 * @brief Read a little-endian unsigned 32-bit value from a byte buffer.
 *
 * @param p  source buffer; at least 4 bytes must be readable.
 * @return   the decoded 32-bit value.
 */
uint32_t fbsec_server_read_u32le(const uint8_t *p);

/**
 * @brief Write an unsigned 16-bit value to a byte buffer, little-endian.
 *
 * @param p  destination buffer; at least 2 bytes must be writable.
 * @param v  value to encode.
 */
void     fbsec_server_write_u16le(uint8_t *p, uint16_t v);

/**
 * @brief Write an unsigned 32-bit value to a byte buffer, little-endian.
 *
 * @param p  destination buffer; at least 4 bytes must be writable.
 * @param v  value to encode.
 */
void     fbsec_server_write_u32le(uint8_t *p, uint32_t v);

/* ---- Time -------------------------------------------------------------- */

/**
 * @brief Format the current local wall-clock time as "HH:MM:SS.mmm".
 *
 * @param buf     destination buffer.
 * @param buflen  capacity in bytes (>= 13 for full output).
 */
void fbsec_server_format_timestamp(char *buf, size_t buflen);

/* ---- Console ---------------------------------------------------------- */

/**
 * @brief Auto-detect whether stdout is attached to a console.
 *
 * @retval true   colour rendering is sensible (TTY detected).
 * @retval false  output is being piped or redirected.
 */
bool fbsec_server_stdout_is_console(void);

/**
 * @brief Enable ANSI virtual-terminal processing on the stdout console
 *        (Windows only). No-op when ANSI is already in effect or
 *        when stdout is not a console.
 */
void fbsec_server_console_enable_ansi(void);

#ifdef __cplusplus
}
#endif

#endif /* SERVER_COMMON_PLATFORM_H */
/* EOF */
