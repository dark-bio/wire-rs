# Security policy

This crate is the encrypted wire between an Ark and the host it is plugged
into, the transport every other protocol of the Dark Bio ecosystem runs over.
Reports are taken seriously and handled quickly.

## Reporting a vulnerability

Please do not open a public issue for anything that looks like a security
problem. Send a private email to peter@dark.bio instead, with a description of
the issue, the affected version and, if you have one, a way to reproduce it.
You will get an acknowledgement within a few days, and updates as the fix
progresses.

Findings in the cryptography underneath belong with the crypto crate, and
findings in its dependencies with their maintainers, but a report here is
still welcome. We track the RustSec advisory database daily and ship
dependency fixes as new releases.

## Supported versions

Only the latest release on crates.io receives fixes. Versions are 0.x and every
minor bump may change the API and the protocol, so fixes ship as new versions
rather than backports. Consumers should track the latest release, which the
Ark firmware and the Dark Bio tools do.

## Disclosure

Fixes are released first and disclosed afterwards. Once a fixed version is on
crates.io, an advisory is filed with the RustSec database so that `cargo audit`
users learn about it, and the report is credited unless you prefer otherwise.
