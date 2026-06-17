# Security Policy

## Status of this project

SOFA is a **demonstrator**. It exists to show the shape of an AEAD-protected
secure-access tunnel for industrial fieldbuses and to serve as a porting
reference. It is **not a hardened, independently audited product** and is
**not intended for production deployment as-is**. In particular:

- The demo ships with **hardcoded, publicly known demo keys**
  (`run/keys-demo.txt`). These are test vectors, not secrets. Never reuse
  them, or any key material from this repository, on a real device.
- The simulator omits the key-provisioning and key-derivation lifecycle
  that a real target requires (see WP-104 and the Integration Guide).
- Platform concerns such as secure key storage, entropy sourcing, and
  side-channel resistance are out of scope for the demonstrator and are
  the integrator's responsibility.

See also the warranty disclaimer and limitation of liability in the
Apache License, Version 2.0 (sections 7 and 8), under which this software
is provided.

## Reporting a vulnerability

If you believe you have found a security issue in the SOFA code — for
example a flaw in the AEAD construction, the AAD/nonce handling, the state
machine, or the wire protocol — please report it **privately** rather than
opening a public issue.

- Email: **opensource@em-sa.com**
- Please include a description, affected files or wire sequences, and a
  reproduction or proof-of-concept where possible.

We aim to acknowledge reports within a reasonable period and will keep you
informed as we assess and address the issue. Because SOFA is a
demonstrator maintained on a best-effort basis, we cannot commit to a
fixed remediation timeline, but well-founded reports are taken seriously.

Please give us a reasonable opportunity to respond before any public
disclosure.
