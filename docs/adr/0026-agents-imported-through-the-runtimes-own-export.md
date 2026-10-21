---
status: accepted
---

# Agents come from the host only through the runtime's own export

People already run agents on their own computer and want to test them in a sandbox (issue #34). enclos could define its own archive of an agent, or read the host runtime's files itself, or let the runtime do both ends. Reading the host runtime's files means reading where its secrets live (`~/.hermes` is on the read deny list), and an archive format of enclos's own would have to track every runtime's layout and drift with it.

So an agent comes in only from an export the user made with the runtime's own command (`hermes profile export`), named with `enclos agent add <sandbox>/<agent> --from <archive>`. enclos never runs the host's runtime or reads its files on its own. It copies the archive beside the sandbox home, where the sandbox reads and cannot write, audits the copy with its SHA-256, and runs the runtime's own import inside the sandbox, under its policy, so the runtime extracts it there and the host never does. What the export holds is the runtime's to decide; enclos copies no login and no secret in ([0022](0022-secrets-granted-per-sandbox.md)), and nothing in the archive widens the policy.

This narrows [0001](0001-manage-only-created-sandboxes.md): enclos still never looks for agents on the host; it imports one only from an archive the user names.

## Considered options

- **An archive format of enclos's own:** one format across runtimes, but enclos would have to know what each runtime keeps and leaves out, including its secrets.
- **Copy the host runtime's agent folder:** no export step, but enclos would read the host runtime's home, which holds its login and secrets, and extract on the host what the sandbox then runs.

## Consequences

- A runtime whose adapter has no import command cannot import, and `--from` says so.
- The archive is checked on the host before it is copied: a link, anything but a plain file, and a file under a sandbox's folder are refused, so the host never copies what a sandbox put or pointed at into a sandbox.
- Whether the runtime's export leaves out its secrets, and whether its import stays within the agent's folder, is the runtime's code; for Hermes it is to verify (design §14).
