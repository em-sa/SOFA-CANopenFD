/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_platform.c
 * @brief   SOFA server_common, endian + time + console helpers, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_platform.h"

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

/* ---- Little-endian helpers --------------------------------------------- */

uint16_t fbsec_server_read_u16le(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

uint32_t fbsec_server_read_u32le(const uint8_t *p) {
  return  (uint32_t)p[0]
       | ((uint32_t)p[1] <<  8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

void fbsec_server_write_u16le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)( v        & 0xFFu);
  p[1] = (uint8_t)((v >>  8) & 0xFFu);
}

void fbsec_server_write_u32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)( v        & 0xFFu);
  p[1] = (uint8_t)((v >>  8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* ---- Time -------------------------------------------------------------- */

void fbsec_server_format_timestamp(char *buf, size_t buflen) {
#ifdef _WIN32
  SYSTEMTIME st;
  GetLocalTime(&st);
  snprintf(buf, buflen, "%02u:%02u:%02u.%03u",
           (unsigned)st.wHour,
           (unsigned)st.wMinute,
           (unsigned)st.wSecond,
           (unsigned)st.wMilliseconds);
#else
  /* Linux/macOS port: clock_gettime(CLOCK_REALTIME) + localtime_r. */
  if (buflen > 0) {
    buf[0] = '\0';
  }
#endif
}

/* ---- Console ---------------------------------------------------------- */

bool fbsec_server_stdout_is_console(void) {
#ifdef _WIN32
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD  mode = 0;
  return (h != INVALID_HANDLE_VALUE) && (h != NULL) && (GetConsoleMode(h, &mode) != 0);
#else
  return false;
#endif
}

void fbsec_server_console_enable_ansi(void) {
#ifdef _WIN32
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD  mode = 0;
  if ((h != INVALID_HANDLE_VALUE) && (h != NULL) && (GetConsoleMode(h, &mode) != 0)) {
    (void)SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
#endif
}

/* EOF */
