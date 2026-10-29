---
status: accepted
---

# A service reads its secrets from a file its sandbox alone reads

Amends [0022](0022-secrets-granted-per-sandbox.md) for runtime services.

On macOS any process of the user can read another's start-up environment through `sysctl` `kern.procargs2`, Apple's own signed programs aside, and Seatbelt has no rule for it: on macOS 26.5.2, a program in one sandbox read the environment of another sandbox's Hermes gateway, its bot token among it (the check printed only the names; the values come in the same read), and the same under a hand-written Seatbelt policy of `(deny default)` that allowed only `kern.argmax`. A secret in a long-running service's environment is therefore readable by every other sandbox for as long as the service runs.

So a runtime whose services can read their secrets from a file gets them there instead. Its adapter names the variable that points to the folder (Hermes: `HERMES_MANAGED_DIR`, whose `.env` Hermes loads into its own process, last and with override). When a service starts, `enclos launch` writes the secrets its policy grants to `secrets/.env` in the sandbox's folder (the folder `0700`, the file `0600`, values double-quoted with `\` and `"` escaped, as both python-dotenv and Hermes's own reader take them back, a value holding a line break or `${` refused since the two would read it differently), sets only that variable; `sandbox stop` and `sandbox rm` remove the folder. The sandbox reads its own folder and never writes it; no other sandbox reads it (design §5). Sessions (`connect`, `exec`) still get their secrets as variables, which other sandboxes can read while they run; the design states that gap.

Considered: denying the read in Seatbelt (no rule covers it: `sysctl-read`, `process-info*` and the rest leave it open), and keeping variables and stating the gap (the bot token of a service running all day is the secret most worth taking). The file is written to enclos's own folder while the services run, which ADR 0022's "never written" did not foresee; it is readable by the user's other processes, as the Keychain item is to `security`.
