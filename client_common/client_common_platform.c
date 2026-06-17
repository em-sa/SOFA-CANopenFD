/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    client_common_platform.c
 * @brief   SOFA client_common, endian + time + console helpers, impl.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 07-MAY-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "client_common_platform.h"

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

uint16_t fbsec_client_read_u16le(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

uint32_t fbsec_client_read_u32le(const uint8_t *p) {
  return  (uint32_t)p[0]
       | ((uint32_t)p[1] <<  8)
       | ((uint32_t)p[2] << 16)
       | ((uint32_t)p[3] << 24);
}

void fbsec_client_write_u16le(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)( v        & 0xFFu);
  p[1] = (uint8_t)((v >>  8) & 0xFFu);
}

void fbsec_client_write_u32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)( v        & 0xFFu);
  p[1] = (uint8_t)((v >>  8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

uint32_t fbsec_client_monotonic_ms(void) {
#ifdef _WIN32
  return (uint32_t)GetTickCount();
#else
  return 0u;
#endif
}

void fbsec_client_format_timestamp(char *buf, size_t buflen) {
#ifdef _WIN32
  SYSTEMTIME st;
  GetLocalTime(&st);
  snprintf(buf, buflen, "%02u:%02u:%02u.%03u",
           (unsigned)st.wHour,
           (unsigned)st.wMinute,
           (unsigned)st.wSecond,
           (unsigned)st.wMilliseconds);
#else
  if (buflen > 0) {
    buf[0] = '\0';
  }
#endif
}

bool fbsec_client_stdout_is_console(void) {
#ifdef _WIN32
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD  mode = 0;
  return (h != INVALID_HANDLE_VALUE) && (h != NULL) && (GetConsoleMode(h, &mode) != 0);
#else
  return false;
#endif
}

void fbsec_client_console_enable_ansi(void) {
#ifdef _WIN32
  HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD  mode = 0;
  if ((h != INVALID_HANDLE_VALUE) && (h != NULL) && (GetConsoleMode(h, &mode) != 0)) {
    (void)SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
#endif
}

/* EOF */
