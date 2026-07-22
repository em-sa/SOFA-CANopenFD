================================================================================
  SOFA Documentation Index
================================================================================


PROJECT SUMMARY

  SOFA ("Secure Object Fieldbus Access") is a Windows demonstrator of
  a unilateral secure-access tunnel for industrial fieldbuses.

  A tunnel is a server-side single data object: clients send requests
  to it, the server emits responses from it. The secure-tunnel layer
  makes those exchanges confidential (when encryption is enabled),
  authenticated, and replay-resistant, without changing the host
  fieldbus's framing or addressing.

  "Unilateral" means client-driven: the client picks the data object,
  the verb (read / write, single / cyclic), and the encryption mode;
  the server validates, applies role policy, and answers. There is no
  separate session-establishment handshake. Every request carries the
  keying inputs it needs, and the AEAD tag binds device id, data id,
  and direction.

  The codebase isolates the AEAD behind a small interface
  (`shared/fbsec_aead.h`) so the construction can be swapped for
  another AEAD (ChaCha20-Poly1305, AES-CCM, AES-256-GCM) without
  touching the secure-tunnel logic above it.

  The demo ships today as a CANopen FD variant on a TCP-loopback
  bus simulator (port 5810), optionally bridged to a real CAN FD
  network via PEAK PCAN-Basic. Future variants (generic, CANopen CC,
  EtherCAT) will plug into the same secure-tunnel core and reuse the
  same four secure verbs and the same secure-only object-dictionary
  entries.


PUBLISHED DOWNLOADS

  EmSA publishes the following SOFA materials for direct download in the
  EmSA security whitepaper library:

    https://www.esacademy.com/en/library/security-white-papers.html

    - EmSA-WP-105   the secure-access protocol whitepaper (the ISO/IEC
                    9798-2 alignment referenced below).
    - User manual   EmSA-UM-105 COP FBsec CANopen, bundled in this
                    distribution as doc/SOFA-UM-105.pdf.
    - Executable    ready-to-run binaries with launcher batches, for
      demo          direct execution without building from source.

  EmSA-WP-104 (key provisioning / layer key model) is available from the
  same library.


STANDARDS ALIGNMENT

  Cryptographic primitives, standards-conforming building blocks
  chosen for portability across embedded crypto libraries (mbedTLS,
  wolfSSL, Mbed PSA, Windows BCrypt, etc.):

    - HKDF-SHA-256
        RFC 5869, NIST SP 800-56C Rev. 2.

    - AES-128-GCM (AEAD interface)
        NIST FIPS 197 (AES) + NIST SP 800-38D (GCM);
        equivalent to ISO/IEC 19772:2020 mechanism #5.

  Entity-authentication pattern, aligned with ISO/IEC 9798-2
  (entity authentication using symmetric encipherment), in the
  following sense:

    Each SOFA single-shot access (SRD or SWR) follows the shape
    of ISO/IEC 9798-2 Mechanism 4 (three-pass mutual
    authentication using random challenges), truncated to two
    passes so that authentication is unilateral by construction.
    Both peers still contribute a random time-variant parameter
    (client_random and server_random); both randoms are bound
    into the AEAD's Associated Data and feed the GCM nonce by
    XOR. EmSA-WP-105 section 9.1 lists the five named deviations
    from strict 9798-2 (dropped third pass, AEAD replacing bare
    MAC, explicit nonce construction, AAD-carried entity
    identifiers, counter extension for cyclic continuations).

      SRD authenticates the SERVER to the client. The server
        proves possession of the role key by producing a valid
        AEAD tag over the client's random and over both peer
        identifiers in the AAD prefix.
      SWR authenticates the CLIENT to the server. Mirror role:
        the client's tag covers the server's random and both
        peer identifiers.

    The AAD also covers a direction byte and the full wire
    keyid byte (encryption flag, cyclic flag, base id), so
    downgrade attempts on any AAD-prefix field fail tag
    verification.

    Cyclic-mode follow-up polls use the same nonce construction
    as the single-shot case (the canonical example from EmSA-WP-105
    section 4.2.6): both peers retain `nonce_base = client_random
    XOR server_random` for the lifetime of the session and increment
    a 32-bit counter per poll. The cyclic nonce is therefore
    `nonce_base XOR (0^64 || counter_be32)`. Both peers contribute
    randomness to every nonce in the stream; the counter extension
    is the only cyclic-specific addition (deviation (v) from WP-105
    section 9.1).

  What SOFA does NOT claim:

    - Full conformance to any specific ISO/IEC 9798 standard.

    - Mutual entity authentication per ISO/IEC 9798-2 mechanism.

    - A standalone authenticated-session protocol. Entity
      authentication is achieved as a side-effect of
      authenticated data access; there is no session-establishment
      handshake independent of a specific data object.


SECURITY OBJECT DICTIONARY (CiA 720 C0xxh)

  The implemented entries in the reserved security range. The full
  per-subindex reference is in the user manual, chapter 5.

  AEAD (symmetric) objects:

    - C000h   Security profile and capabilities. Unauthenticated;
              a tool learns the device class in one cold read.
    - C001h   Security status. Non-secret operational state, no
              key material.
    - C010h   Session pre-requisites. Write-only session salt that
              arms a session for key derivation.
    - C011h   AEAD key identifiers. Non-secret key ids for slot
              discovery.
    - C018h   Authenticated identification. AEAD-tagged read of the
              device identity (object 1018h quadruple).
    - C01Fh   Key set. Write-only symmetric key install and rotation.

  RPK (Ed25519 raw-public-key) objects, built when the RPK layer is
  enabled:

    - C020h   Ownership control. Voucher claim, owner epoch, and
              LDevID generate and export.
    - C021h   Public keys. Verification public keys the device holds.
    - C022h   Public key types. Algorithm id and length for the keys
              in C021h.
    - C028h   Authenticated identification, signed. The Ed25519
              flavor of the identity read in C018h.
    - C02Fh   Provisioning key install, signed. Bootstraps the
              symmetric provisioning key on an identity-only device.
    - C042h   Generic secure access, RPK. The signed sibling of the
              AEAD generic access.
    - C049h   Secure function command, RPK. A signed function code
              for high-value commands.

  Protection is by replacement, not addition: a secure entry is
  guarded by the AEAD tag or by an Ed25519 signature, never by both.
  On a signed entry the signature replaces the tag, and freshness
  comes from the two-pass challenge, so the signature always covers
  randomness the verifier contributed.


--------------------------------------------------------------------------------

  The user manual is the single reference and ships beside this file:

    SOFA-UM-105.pdf
                                      User manual. Chapters 4 and 5 are the
                                      normative reference: every implemented
                                      object dictionary entry (the CiA 720
                                      C000h-C04Fh security range) and every
                                      wire byte (AAD, AEAD, nonce, keyid byte,
                                      USDO PDU, CAN IDs, and the single and
                                      cyclic SRD/SWR flows). Chapters 6-8 cover
                                      building, running and the command line.
                                      Chapters 9-11 are the porting guide
                                      (port hooks, OD/USDO wiring, key handling,
                                      MCU storage, Ed25519 layer). The
                                      appendices give the abort codes, the
                                      configuration macros and the demo keys.

/* EOF */
