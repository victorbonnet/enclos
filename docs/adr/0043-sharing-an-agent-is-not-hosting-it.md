---
status: proposed
---

# Sharing an agent with named people is not hosting it for them

Amends §2's non-goal "Hosting agents for other people (multi-tenant)".

With the mobile app ([0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md), proposed), a user may want a person of their household to talk to some of their agents. That is close to hosting agents for others, which §2 rules out.

Decision (proposed): the user may **share** a sandbox, or one agent of it, with a named **person** (a login of the tailnet), with the abilities `read`, `chat` or `approve`, through the bridge. Each conversation belongs to the person who started it, the bridge shows a person only what is shared with them and sends notifications only to the devices of a conversation's owner, and the runtime is told who speaks. enclos does not isolate people from each other: the sandbox stays the boundary ([0003](0003-sandbox-is-the-permission-boundary.md)), an agent's memory and files are the same whoever talks to it, the host's user can read every conversation, and guests use the sandbox's runtime login. Sharing one agent is for routing, not for keeping secrets; isolation is a sandbox of its own.

Reason: the household case needs no tenancy, only a list of who may talk to what. Saying plainly what it does not protect keeps it from being taken for isolation (§1, principle 6).

## Consequences

- The data model holds a person on every message and an owner on every conversation from the first version, with only the host's user as a person, so sharing later changes no stored history.
- §2's non-goal stays for everything else: no tenants, no isolation between people, no agents run on behalf of someone who is not the host's user.
