# Fail closed when the sandbox cannot be set up

If any part of the sandbox cannot be set up (for example, Landlock is missing from the kernel or the network namespace cannot be created), enclos refuses to run the command and explains how to fix it. There is no flag to run unsandboxed anyway: a user who wants that can run the command without enclos, and nobody can mistake an unprotected session for a protected one.
