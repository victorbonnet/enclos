---
status: accepted
---

# Threat model: accidental damage by mostly trusted agents

enclos primarily prevents accidental damage by agents the user mostly trusts: a misled or buggy agent that deletes the wrong files, reads credentials it has no business with, reaches hosts nobody expected, or leaves something running outside its sandbox. It is not designed to contain deliberately malicious code that exploits the kernel or works hard to evade the sandbox; that needs a VM backend.

## Consequences

- Shared-kernel backends (Seatbelt, bubblewrap) are acceptable defaults, and the honest limits are stated in the design.
- Broad host reads with a sensitive-path deny list are acceptable (see [0015](0015-broad-reads-narrow-writes.md)).
- Exfiltration through an allowed destination is reduced by a narrow allowlist and logging, not prevented.
- Known routes out of the sandbox are still blocked and probed (see [0016](0016-seatbelt-blocks-host-service-delegation.md)), because a trusted agent uses them innocently, for example by opening a URL with `open`.
- enclos still never claims isolation that is not enforced and tested ([0009](0009-refuse-what-cannot-be-enforced.md)).
