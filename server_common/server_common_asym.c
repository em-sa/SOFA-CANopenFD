/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Embedded Systems Academy (EmSA). All rights reserved. */
/**
 * @file    server_common_asym.c
 * @brief   SOFA server_common, device-side asymmetric identity store.
 *          aka FBsec - FieldBus Security
 * @author  Embedded Systems Academy (EmSA), opensource@em-sa.com
 * @version V1.0 of 19-JUL-2026
 *
 * Copyright (c) 2026 Embedded Systems Academy.
 * Licensed under the Apache License, Version 2.0
 * (https://www.apache.org/licenses/LICENSE-2.0).
 */

#include "server_common_asym.h"

#if FBSEC_FEATURE_ASYM

#include <string.h>

#include "fbsec_asym_demo.h"

/* ---- Device identity store (file-static) ----------------------------- */

typedef struct
{
  fbsec_keypair_t idevid;                            /* factory identity     */
  uint8_t         idevid_cert[FBSEC_ASYM_SIG_SIZE];  /* mfg cert over blob   */
  fbsec_keypair_t ldevid;                            /* local identity       */
  bool            ldevid_present;
  fbsec_pubkey_t  anchor;                            /* mfg trust anchor     */
  fbsec_pubkey_t  owner;                             /* owner public key     */
  bool            owner_set;
  uint32_t        owner_epoch;
  bool            uncommissioned;
  uint8_t         serial[FBSEC_ASYM_SERIAL_LEN];
  uint8_t         provisioning_key[FBSEC_AEAD_KEY_SIZE];
  bool            provisioning_set;
  fbsec_pubkey_t  peer[FBSEC_SERVER_ASYM_PEER_SLOTS + 1u]; /* 1-based slots  */
  bool            peer_set[FBSEC_SERVER_ASYM_PEER_SLOTS + 1u];
  bool            ready;
} server_asym_store_t;

static server_asym_store_t g_st;

/* Build the identity blob (serial || IDevID public key) into @p out. */
static void build_identity_blob(uint8_t out[FBSEC_ASYM_IDENTITY_BLOB_LEN])
{
  memcpy(out, g_st.serial, FBSEC_ASYM_SERIAL_LEN);
  memcpy(&out[FBSEC_ASYM_SERIAL_LEN], g_st.idevid.pub, FBSEC_ASYM_PUBKEY_SIZE);
}

void fbsec_server_asym_init(void)
{
  static const uint8_t idevid_seed[FBSEC_ASYM_SEED_SIZE] = FBSEC_DEMO_IDEVID_SEED_BYTES;
  static const uint8_t mfg_seed[FBSEC_ASYM_SEED_SIZE]    = FBSEC_DEMO_MFG_SEED_BYTES;
  static const uint8_t serial[FBSEC_ASYM_SERIAL_LEN]     = FBSEC_DEMO_DEVICE_SERIAL_BYTES;

  fbsec_keypair_t mfg;
  uint8_t blob[FBSEC_ASYM_IDENTITY_BLOB_LEN];
  uint8_t transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_ASYM_IDENTITY_BLOB_LEN];
  uint16_t tlen;

  memset(&g_st, 0, sizeof(g_st));
  memcpy(g_st.serial, serial, FBSEC_ASYM_SERIAL_LEN);

  /* Device factory identity. */
  (void)fbsec_asym_keygen(idevid_seed, &g_st.idevid);

  /* The simulator plays factory: derive the manufacturer keypair, publish
   * its public half as the trust anchor, and certify the IDevID. The
   * manufacturer private key is not retained on the device. */
  (void)fbsec_asym_keygen(mfg_seed, &mfg);
  memcpy(g_st.anchor.pub, mfg.pub, FBSEC_ASYM_PUBKEY_SIZE);

  build_identity_blob(blob);
  tlen = fbsec_asym_transcript(FBSEC_ASYM_RD_IDEVID_CERT, blob, (uint16_t)sizeof(blob),
                               transcript, (uint16_t)sizeof(transcript));
  (void)fbsec_asym_sign(&mfg, transcript, tlen, g_st.idevid_cert);
  memset(&mfg, 0, sizeof(mfg));

  g_st.ldevid_present = false;
  g_st.owner_set      = false;
  g_st.owner_epoch    = (uint32_t)FBSEC_DEMO_OWNER_EPOCH_START;
  g_st.uncommissioned = true;
  g_st.ready          = true;
}

bool fbsec_server_asym_idevid_present(void)   { return g_st.ready; }
bool fbsec_server_asym_ldevid_present(void)   { return g_st.ldevid_present; }
bool fbsec_server_asym_is_uncommissioned(void){ return g_st.uncommissioned; }
uint32_t fbsec_server_asym_owner_epoch(void)  { return g_st.owner_epoch; }

const fbsec_keypair_t *fbsec_server_asym_idevid(void) { return &g_st.idevid; }

const fbsec_keypair_t *fbsec_server_asym_ldevid(void)
{
  return g_st.ldevid_present ? &g_st.ldevid : NULL;
}

const uint8_t *fbsec_server_asym_idevid_cert(void) { return g_st.idevid_cert; }
const fbsec_pubkey_t *fbsec_server_asym_anchor(void) { return &g_st.anchor; }
const fbsec_pubkey_t *fbsec_server_asym_owner(void)
{
  return g_st.owner_set ? &g_st.owner : NULL;
}
const uint8_t *fbsec_server_asym_serial(void) { return g_st.serial; }

/* ---- Handover mutators ----------------------------------------------- */

bool fbsec_server_asym_generate_ldevid(fbsec_pubkey_t *out_pub)
{
  static const uint8_t ldevid_seed[FBSEC_ASYM_SEED_SIZE] = FBSEC_DEMO_LDEVID_SEED_BYTES;

  if (!g_st.ready)
  {
    return false;
  }
  if (!fbsec_asym_keygen(ldevid_seed, &g_st.ldevid))
  {
    return false;
  }
  g_st.ldevid_present = true;
  if (out_pub != NULL)
  {
    memcpy(out_pub->pub, g_st.ldevid.pub, FBSEC_ASYM_PUBKEY_SIZE);
  }
  return true;
}

#if FBSEC_HANDOVER_AUTHORIZED
bool fbsec_server_asym_claim(const uint8_t *voucher, uint16_t len)
{
  /* voucher = serial[8] || integrator_pub[32] || epoch[4 LE] || SIG_MFG[64] */
  const uint8_t *serial;
  const uint8_t *integ_pub;
  const uint8_t *sig;
  uint32_t epoch;
  uint8_t  body[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 4u];
  uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + sizeof body];
  uint16_t tlen;
  uint16_t body_len = (uint16_t)(FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 4u);

  if ((voucher == NULL) || (len != FBSEC_HO_VOUCHER_LEN) || (!g_st.ready))
  {
    return false;
  }
  serial    = &voucher[0];
  integ_pub = &voucher[FBSEC_ASYM_SERIAL_LEN];
  epoch     = (uint32_t)voucher[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE]
            | ((uint32_t)voucher[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 1u] << 8)
            | ((uint32_t)voucher[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 2u] << 16)
            | ((uint32_t)voucher[FBSEC_ASYM_SERIAL_LEN + FBSEC_ASYM_PUBKEY_SIZE + 3u] << 24);
  sig       = &voucher[body_len];

  /* Anchor signature over serial || integrator_pub || epoch. */
  memcpy(body, voucher, body_len);
  tlen = fbsec_asym_transcript(FBSEC_ASYM_RD_VOUCHER, body, body_len,
                               transcript, (uint16_t)sizeof transcript);
  if ((tlen == 0u) || !fbsec_asym_verify(&g_st.anchor, transcript, tlen, sig))
  {
    return false;
  }
  /* Serial must name this device, it must be uncommissioned, and the epoch
     must strictly advance (no rollback to a prior owner). */
  if ((memcmp(serial, g_st.serial, FBSEC_ASYM_SERIAL_LEN) != 0) ||
      (!g_st.uncommissioned) || (epoch <= g_st.owner_epoch))
  {
    return false;
  }

  memcpy(g_st.owner.pub, integ_pub, FBSEC_ASYM_PUBKEY_SIZE);
  g_st.owner_set      = true;
  g_st.owner_epoch    = epoch;
  g_st.uncommissioned = false;
  return true;
}
#endif /* FBSEC_HANDOVER_AUTHORIZED */

bool fbsec_server_asym_install_provisioning(const uint8_t *payload, uint16_t len)
{
  /* payload = key[FBSEC_AEAD_KEY_SIZE] || SIG_integrator[64] */
  const uint8_t *key;
  const uint8_t *sig;

  if ((payload == NULL) || (len != FBSEC_HO_PROVISION_LEN) || (!g_st.ready))
  {
    return false;
  }
  key = &payload[0];
  sig = &payload[FBSEC_AEAD_KEY_SIZE];
  (void)sig;

#if FBSEC_HANDOVER_AUTHORIZED
  {
    /* Authorized: the install must be signed by the owner established at
       claim; a device with no owner refuses. */
    uint8_t  transcript[FBSEC_ASYM_TRANSCRIPT_OVERHEAD + FBSEC_AEAD_KEY_SIZE];
    uint16_t tlen = fbsec_asym_transcript(FBSEC_ASYM_RD_PKINSTALL_ACK,
                                          key, (uint16_t)FBSEC_AEAD_KEY_SIZE,
                                          transcript, (uint16_t)sizeof transcript);
    if ((!g_st.owner_set) || (tlen == 0u) ||
        !fbsec_asym_verify(&g_st.owner, transcript, tlen, sig))
    {
      return false;
    }
  }
#endif
  /* Basic model: trust on first use (the genuineness check in step 1 is the
     only gate); store the key. */
  memcpy(g_st.provisioning_key, key, FBSEC_AEAD_KEY_SIZE);
  g_st.provisioning_set = true;
  return true;
}

const uint8_t *fbsec_server_asym_provisioning_key(void)
{
  return g_st.provisioning_set ? g_st.provisioning_key : NULL;
}

void fbsec_server_asym_decommission(void)
{
  /* Clear ownership + installed material; keep identity, anchor and peers. */
  memset(&g_st.owner, 0, sizeof g_st.owner);
  g_st.owner_set = false;
  memset(g_st.provisioning_key, 0, sizeof g_st.provisioning_key);
  g_st.provisioning_set = false;
  memset(&g_st.ldevid, 0, sizeof g_st.ldevid);
  g_st.ldevid_present = false;
  /* Demo: reset the epoch so the same demo voucher re-claims the device. */
  g_st.owner_epoch    = (uint32_t)FBSEC_DEMO_OWNER_EPOCH_START;
  g_st.uncommissioned = true;
}

bool fbsec_server_asym_set_peer(uint8_t slot, const fbsec_pubkey_t *pk)
{
  if ((slot == 0u) || (slot > FBSEC_SERVER_ASYM_PEER_SLOTS) || (pk == NULL))
  {
    return false;
  }
  g_st.peer[slot]     = *pk;
  g_st.peer_set[slot] = true;
  return true;
}

bool fbsec_server_asym_get_peer(uint8_t slot, fbsec_pubkey_t *out)
{
  if ((slot == 0u) || (slot > FBSEC_SERVER_ASYM_PEER_SLOTS) || (out == NULL) ||
      (!g_st.peer_set[slot]))
  {
    return false;
  }
  *out = g_st.peer[slot];
  return true;
}

#endif /* FBSEC_FEATURE_ASYM */

/* EOF */
