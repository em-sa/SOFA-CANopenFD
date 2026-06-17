/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    fbsec_co_fd_pcan.h
 * @brief   SOFA FD bus, optional PCAN-Basic CAN FD bridge.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 08-MAY-2026
 *
 * Self-contained, dynamic-load wrapper around PEAK PCAN-Basic for the
 * subset of calls the FD bus simulator needs. PCAN-Basic is loaded at
 * runtime via LoadLibrary("PCANBasic.dll"); the project still builds
 * and runs on machines without the SDK / driver. When the DLL is
 * absent or fails to resolve any required symbol,
 * @ref fbsec_pcan_loaded returns false and every other entry point
 * becomes a benign no-op.
 *
 * Vendors a small subset of PCAN-Basic constants and types (the
 * official PCAN-Basic header is freely distributable; only the
 * declarations actually referenced are reproduced).
 *
 * Single channel per process (the FD bus only ever connects to one
 * physical bus). Bitrate is fixed at 500k arbitration / 2M data; that
 * is the only mode the demo currently exercises.
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#ifndef FBSEC_CO_FD_PCAN_H
#define FBSEC_CO_FD_PCAN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Vendored PCAN-Basic subset --------------------------------------- */

/* Channel handles. Only the USB and PCI families are probed; that covers
   every PCAN FD device shipped today (PCAN-USB FD, PCAN-USB Pro FD,
   PCAN-PCI Express FD, etc.). */
#define PCAN_NONEBUS    0x00u
#define PCAN_USBBUS1    0x51u
#define PCAN_USBBUS2    0x52u
#define PCAN_USBBUS3    0x53u
#define PCAN_USBBUS4    0x54u
#define PCAN_USBBUS5    0x55u
#define PCAN_USBBUS6    0x56u
#define PCAN_USBBUS7    0x57u
#define PCAN_USBBUS8    0x58u
#define PCAN_PCIBUS1    0x41u
#define PCAN_PCIBUS2    0x42u
#define PCAN_PCIBUS3    0x43u
#define PCAN_PCIBUS4    0x44u
#define PCAN_PCIBUS5    0x45u
#define PCAN_PCIBUS6    0x46u
#define PCAN_PCIBUS7    0x47u
#define PCAN_PCIBUS8    0x48u

/* Status codes used by the wrapper. */
#define PCAN_ERROR_OK           0x00000000u
#define PCAN_ERROR_QRCVEMPTY    0x00000020u   /* normal: read queue empty */
#define PCAN_ERROR_INITIALIZED  0x00000400u

/* CAN_GetValue parameter constants (PCAN-Basic, all 8-bit TPCANParameter). */
#define PCAN_CHANNEL_CONDITION  0x0Du   /* availability of a channel        */
#define PCAN_CHANNEL_FEATURES   0x16u   /* feature bitmask (FD_CAPABLE etc.)*/

/* Channel-condition return bits. */
#define PCAN_CHANNEL_UNAVAILABLE 0x00u
#define PCAN_CHANNEL_AVAILABLE   0x01u
#define PCAN_CHANNEL_OCCUPIED    0x02u
#define PCAN_CHANNEL_PCANVIEW    0x04u  /* also-shareable with PCAN-View    */

/* PCAN_CHANNEL_FEATURES bits. */
#define PCAN_FEATURE_FD_CAPABLE  0x01u  /* channel supports CAN FD          */

/* MSGTYPE flags. */
#define PCAN_MESSAGE_STANDARD   0x00u
#define PCAN_MESSAGE_RTR        0x01u
#define PCAN_MESSAGE_EXTENDED   0x02u
#define PCAN_MESSAGE_FD         0x04u
#define PCAN_MESSAGE_BRS        0x08u
#define PCAN_MESSAGE_ESI        0x10u

#define FBSEC_PCAN_MSG_DATA_MAX 64u

/* CAN FD message struct (matches PCAN-Basic TPCANMsgFD layout). */
typedef struct fbsec_pcan_msg_fd_t {
  uint32_t id;       /* 11- or 29-bit identifier value (no flag bits)        */
  uint8_t  msgtype;  /* PCAN_MESSAGE_* bits OR-ed                            */
  uint8_t  dlc;      /* 0..15 - DLC code (0..8 => 0..8 bytes; 9..15 => FD)   */
  uint8_t  data[FBSEC_PCAN_MSG_DATA_MAX];
} fbsec_pcan_msg_fd_t;

/* ---- Wrapper API ------------------------------------------------------- */

/** Load PCANBasic.dll and resolve every required entry point. Idempotent. */
bool fbsec_pcan_load(void);

/** Free the DLL. Calls @ref fbsec_pcan_close first if a channel is open. */
void fbsec_pcan_unload(void);

/** True after a successful @ref fbsec_pcan_load. */
bool fbsec_pcan_loaded(void);

/**
 * @brief Probe USB1..8 and PCI1..8 for channels reporting AVAILABLE.
 *
 * @param handles_out  buffer receiving available handle values.
 * @param cap          capacity of @p handles_out.
 * @return Number of available channels found (may exceed @p cap, in which
 *         case only the first @p cap values were stored).
 */
size_t fbsec_pcan_probe_available(uint16_t *handles_out, size_t cap);

/** "PCAN_USBBUS1" / "PCAN_PCIBUS3" / "?" for unknown handles. */
const char *fbsec_pcan_handle_name(uint16_t handle);

/** Parse a channel string. Accepts symbolic ("PCAN_USBBUS1") or hex ("0x51"). */
bool fbsec_pcan_parse_channel(const char *s, uint16_t *out);

/**
 * @brief CAN_InitializeFD on @p handle with the canonical 500k/2M bitrate
 *        string for an 80 MHz clock.
 *
 * @retval true on success.
 * @retval false if PCAN is not loaded, the channel rejects init, or any
 *         status other than OK is returned.
 */
bool fbsec_pcan_open_500k_2m(uint16_t handle);

/** CAN_Uninitialize the open channel. Safe to call when nothing is open. */
void fbsec_pcan_close(void);

/** True between successful open and close. */
bool fbsec_pcan_is_open(void);

/**
 * @brief Send one CAN FD frame.
 *
 * @p len is the actual byte count 0..64; the wrapper rounds up to the
 * next legal CAN FD length and zero-pads as needed. Caller does NOT need
 * to compute the DLC code.
 *
 * @retval true   CAN_WriteFD returned PCAN_ERROR_OK.
 * @retval false  PCAN not loaded / not open, or write returned non-OK.
 */
bool fbsec_pcan_write_fd(uint32_t can_id, bool extended, bool brs,
                         const uint8_t *data, uint8_t len);

/**
 * @brief Drain one frame from the PCAN receive queue.
 *
 * @retval true   one frame returned in *_out parameters.
 * @retval false  queue empty (PCAN_ERROR_QRCVEMPTY) or any other error.
 *                Callers loop until this returns false.
 */
bool fbsec_pcan_read_fd(uint32_t *can_id_out, bool *extended_out, bool *brs_out,
                        uint8_t *data_out, uint8_t *len_out);

#ifdef __cplusplus
}
#endif

#endif /* FBSEC_CO_FD_PCAN_H */
/* EOF */
