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
  same four secure verbs and the same four secure-only object-
  dictionary entries.


PUBLISHED DOWNLOADS

  EmSA publishes the following SOFA materials for direct download in the
  EmSA security whitepaper library:

    https://www.esacademy.com/en/library/security-white-papers.html

    - EmSA-WP-105   the secure-access protocol whitepaper (the ISO/IEC
                    9798-2 alignment referenced below).
    - User manual   EmSA-UM-105 COP FBsec CANopen (also bundled as a PDF
                    in this doc/ folder).
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


--------------------------------------------------------------------------------

  Start here:

    EmSA-UM-105-COP FBsec CANopen V01.pdf
                                      User manual. "Running the Examples"
                                      walks through hub/server/client launch,
                                      the optional PCAN bridge, and the trace
                                      output. "Integration Guide" at the end
                                      is the porting reference (key handling,
                                      MCU storage, OD/USDO wiring, abort-code
                                      mapping, threat model).

  Cryptographic protocol (variant-neutral; applies to every current and
  future variant):

    fieldbus_sim_secure_tunnel_spec.txt   AAD, AEAD, nonce, keyid byte,
                                          single + cyclic flows.
                                          Authoritative for the byte
                                          sequences each variant transports.

  CANopen FD variant (TCP-loopback bus on port 5810; optional PCAN bridge):

    fieldbus_sim_canopen_fd_spec.txt      device_id <-> node id and
                                          data_id <-> (index, sub) mappings;
                                          USDO PDU + reserved CAN IDs.
    flow_diagrams.txt                     sequencediagram.org source for the
                                          four protocol flows (single SRD/SWR
                                          + cyclic SRD/SWR).

/* EOF */
