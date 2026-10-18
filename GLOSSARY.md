# enclos

enclos runs AI agents, or any other command, inside a sandbox the user controls, with a policy deciding what the command may do and an audit log recording what happened.

## Language

**Agent**:
Any program run under enclos. enclos does not distinguish AI agents from other commands.
_Avoid_: bot, assistant, tool

**Session**:
One run of a command under enclos, from start until the command and everything it started have exited.
_Avoid_: run, job, execution

**Sandbox**:
The boundary the operating system enforces around a session's processes.
_Avoid_: jail, container, enclave, profile

**Policy**:
The list of what a session may do: which paths it may read or write, which domains it may reach, which environment variables it receives. Anything not listed is denied.
_Avoid_: rules, permissions, config, profile

**Audit log**:
The append-only, tamper-evident record of sessions and what they did, kept outside the reach of every sandbox.
_Avoid_: history, trace, journal
