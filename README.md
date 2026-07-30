# SOFA — Secure Object Fieldbus Access

A small, transport-agnostic AEAD-protected secure-tunnel demonstrator
for fieldbus traffic. The transport-agnostic crypto + state-machine
lib lives in `shared/`, and each fieldbus variant plugs in a thin
client / server / bus simulator on top of it. Today only the
**CANopen FD** variant is shipped; future variants (generic,
CANopen CC, EtherCAT) will plug in alongside under `variants/<name>/`.

The CANopen FD variant exercises the secure verbs (`srd`, `swr`,
`srdpoll`, `swrpoll`) over an unsegmented SDO (USDO) expedited carrier
with an AES-128-GCM secure tunnel whose AAD covers addressing
(server / client node IDs, the object multiplexor) and the key-selector byte. See
`doc/` for the wire spec and the integration guides.

> ⚠️ **Demonstrator — not for production.** SOFA is a teaching and
> porting reference. It ships with **publicly known demo keys**
> (`run/keys-demo.txt`), simulates the key-provisioning/derivation
> lifecycle out, and has **not been independently security-audited**.
> Do not deploy it as-is or reuse any key material from this repository
> on a real device. See [`SECURITY.md`](SECURITY.md). The software is
> provided "AS IS" under the Apache-2.0 warranty disclaimer (§7) and
> limitation of liability (§8).

## Self-contained build

This repository is **source-only** — no binaries are committed. It builds
and runs without any sibling projects, system libraries, or
redistributables. Everything required is in-tree:

- The mbedtls subset (AES, GCM, SHA-256, plus glue) ships under
  `third_party/mbedtls/`.
- The Monocypher Ed25519 subset (for the optional RPK layer) ships under
  `third_party/monocypher/`.
- All produced `.exe` files statically link the MSVC C runtime
  (`/MT` Release), so the binaries you build copy to any Windows 10+
  machine and run without the Visual C++ Redistributable installed.
  `dumpbin /dependents` on every binary shows only system DLLs
  (`KERNEL32`, `WS2_32`, `ADVAPI32`).
- Optional: `fbsec_co_fd_bus` resolves `PCANBasic.dll` at runtime via
  `LoadLibrary`. Machines without the PEAK driver still build and
  run; only the optional PCAN bridge is skipped.

Build from source with the steps under [Building](#building). If you just
want to try the demo without a toolchain, a **ready-to-run executable
demo** (binaries + launcher batches + docs) is published for direct
download in the EmSA security whitepaper library
(<https://www.esacademy.com/en/library/security-white-papers.html>) —
download, unzip, and run the batches in `run/`. See also
[References](#references).

## Keys and the simulation boundary

SOFA is a simulator. On a real embedded target, WP-104 §3.4 specifies
that each layer (Provisioning, Integrator, Operator) has a *master*
key, and for each communication a per-session key is derived via
HKDF(layer_master, salt, info). SOFA simulates both the masters and
the derivation step out — what gets installed and what the wire
keyid byte selects are the already-derived **session keys**. The
three slots are therefore labelled *Provisioning Key*,
*Integrator Key*, *Operator Key*. See the "Key Model"
and "Master Keys vs Session Keys" sections of the Integration Guide
chapter in `doc/SOFA-UM-105.pdf` for the full discussion.
The full key-provisioning lifecycle SOFA simulates out is specified in
the EmSA WP-104 whitepaper (see [References](#references)).

## Building

Requirements:

- CMake 3.20+
- MSVC 14.50 (Visual Studio 2026), `/W4 /WX /permissive-` clean

```
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
```

This produces three executables for the CANopen FD variant under
`build/variants/canopen_fd/.../Release/`:

- `fbsec_co_fd_bus.exe`
- `fbsec_co_fd_server.exe`
- `fbsec_co_fd_client.exe`

plus the static libraries they share (`fbsec_crypto.lib`,
`fbsec_client_common.lib`, `fbsec_server_common.lib`,
`fbsec_bus_common.lib`, `fbsec_canopen_fd.lib`).

## Running the demo

In three terminals:

```
build\variants\canopen_fd\bus\Release\fbsec_co_fd_bus.exe
build\variants\canopen_fd\server\Release\fbsec_co_fd_server.exe --hub 127.0.0.1:5810 --node-id 0x05
build\variants\canopen_fd\client\Release\fbsec_co_fd_client.exe --menu --hub 127.0.0.1:5810
```

Or use the launcher batches in `run/`:

```
run\start_fd_hub.bat
run\start_fd_server.bat
run\start_fd_client.bat
```

## Compile-time feature flags

The library can be stripped to read-only / write-only and/or
single-shot-only at build time. Defaults in `shared/fbsec_config.h`:

```
FBSEC_FEATURE_READ    1
FBSEC_FEATURE_WRITE   1
FBSEC_FEATURE_CYCLIC  1
```

Override via CMake cache, e.g. write-only single-shot:

```
cmake -S . -B build -DFBSEC_FEATURE_READ=0 \
                    -DFBSEC_FEATURE_WRITE=1 \
                    -DFBSEC_FEATURE_CYCLIC=0
```

At least one of `READ` / `WRITE` must be `1` (enforced by `#error`).
With `CYCLIC=0` the server additionally rejects bit 6 of the wire
keyid byte as reserved. This is fail-closed against a downgrade.

`FBSEC_AEAD_DEV_ID_SIZE` defaults to `1` (CANopen FD node_id). Future
variants with a uint16 device_id will set it to `2`; peers compiled
with mismatched values fail-closed at AEAD verify on the first
secure verb.

## RPK identity layer (Ed25519)

On top of the symmetric AEAD core, SOFA can build an optional raw-public-key
(RPK) identity layer that uses Ed25519 signatures. It is controlled by a
single CMake knob and now defaults on:

```
cmake -S . -B build -DFBSEC_FEATURE_ASYM=ON
```

Build with `-DFBSEC_FEATURE_ASYM=OFF` for a minimal, AEAD-only device that
carries no signature code or public-key state. The Ed25519 primitives come
from a vendored subset of Monocypher under `third_party/monocypher/`; see
[`NOTICE`](NOTICE) for the attribution.

The RPK layer adds the following CiA 720 object-dictionary entries:

- `C020h`: ownership control (owner epoch, voucher claim, LDevID generate and export).
- `C021h`: public keys the device holds for verification.
- `C022h`: public-key types and lengths for the keys in `C021h`.
- `C028h`: authenticated identification, signed (the RPK flavor of the AEAD identity read).
- `C02Fh`: provisioning key install, signed.
- `C042h`: generic secure access, RPK (the RPK sibling of the AEAD generic access).
- `C049h`: secure function command, RPK.

The protection model is replacement, not addition: a secure entry is
guarded by the AEAD tag or by an Ed25519 signature, never by both. On a
signed entry the signature replaces the tag, and freshness comes from the
two-pass challenge, so the signature always covers randomness the verifier
contributed.

## Repository layout

```
SOFA/
├── CMakeLists.txt
├── LICENSE                         # Apache 2.0
├── NOTICE                          # third-party attributions (mbedtls, monocypher)
├── SECURITY.md                     # security status + vuln reporting
├── CONTRIBUTING.md                 # maintenance model + how to send feedback
├── README.md                       # this file
├── bus_common/                     # variant-agnostic bus / socket helpers
├── client_common/                  # variant-agnostic client lib (CLI, verbs, trace)
├── server_common/                  # variant-agnostic server lib (dispatch, hooks, OD)
├── doc/                            # wire specs + integration guides + history
├── run/                            # launcher batches
│   └── start_fd_*.bat              # CANopen FD launchers
├── shared/                         # transport-agnostic crypto + state machine
│   ├── fbsec_aead.{c,h}            # AES-GCM + AAD construction
│   ├── fbsec_config.h              # AEAD / KDF / tag / feature knobs
│   ├── fbsec_hkdf.{c,h}            # HKDF-SHA256 (info "FBSEC-SK-v1")
│   ├── fbsec_secure_od.{c,h}       # server-side dispatch + secure OD
│   ├── fbsec_secure_proto.{c,h}    # client-side state machine
│   └── mbedtls_fbsec_config.h      # mbedtls subset config
├── variants/
│   └── canopen_fd/                 # CANopen FD variant (only one shipped today)
│       ├── bus/                    # CAN FD bus simulator + optional PCAN bridge
│       ├── client/                 # FD client main
│       ├── server/                 # FD server main
│       └── common/                 # FD-specific: addressing, USDO carrier, framing
└── third_party/
    ├── mbedtls/                    # vendored mbedtls subset (AES/GCM/SHA-256)
    │   ├── include/
    │   ├── library/
    │   └── LICENSE                 # Apache 2.0 (Arm/mbedtls)
    └── monocypher/                 # vendored Monocypher Ed25519 subset (RPK layer)
        └── LICENSE                 # BSD-2-Clause OR CC-0 (Monocypher)
```

## Documentation

Start with the user manual `doc/SOFA-UM-105.pdf`;
its "Running the Examples" chapter is the step-by-step demo guide, and
the "Integration Guide" chapter at the end is the porting reference
(key handling, MCU storage, OD/USDO wiring, abort-code mapping, threat
model). Chapters 4 and 5 are the normative wire and object-dictionary
reference. Full index in `doc/README.txt`.

| File                  | What it covers                                              |
|-----------------------|------------------------------------------------------------|
| `doc/SOFA-UM-105.pdf` | user manual: demo walkthrough, wire and OD reference, Integration Guide |
| `doc/README.txt`      | this documentation index                                   |

## References

EmSA publishes the following SOFA materials for direct download in the
EmSA security whitepaper library:

<https://www.esacademy.com/en/library/security-white-papers.html>

- **EmSA-WP-105**: the secure-access protocol and its relationship to
  ISO/IEC 9798-2 (referenced by `doc/README.txt` and the user manual).
- **User manual**: *EmSA-UM-105 COP FBsec CANopen*, bundled in this
  distribution as `doc/SOFA-UM-105.pdf`.
- **Executable demo**: ready-to-run binaries with launcher batches, for
  direct execution without building from source.

The design also draws on **EmSA-WP-104** (key provisioning and the
Provisioning / Integrator / Operator layer key model — the lifecycle SOFA
simulates out), available from the same library.

For offline / archival completeness you may also keep local copies of the
whitepaper PDFs alongside the other documents in `doc/`.

## License

Licensed under the Apache License, Version 2.0; see [`LICENSE`](LICENSE).
Third-party attributions are in [`NOTICE`](NOTICE); security status and
vulnerability reporting are in [`SECURITY.md`](SECURITY.md).

Copyright © 2026 Embedded Systems Academy (EmSA) — opensource@em-sa.com
