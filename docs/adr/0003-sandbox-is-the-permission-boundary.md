---
status: accepted
---

# The sandbox is the permission boundary, the profile is not

Each sandbox holds one agent runtime and any number of its profiles. All profiles in a sandbox share its policy, proxy, secrets and home folder, so they can read each other's files. Profiles that need different permissions go in different sandboxes. Enforcing permissions per profile inside one sandbox would mean a separate sandbox per profile anyway, so enclos makes that explicit instead of offering a boundary it cannot hold.

## Consequences

- The proxy gives each profile its own listener so the network log is per profile, but that attribution is informative, not a security boundary.
- Secrets are granted per sandbox for now; per-profile grants are still an open decision in the design. They would only limit which variables each profile's service receives, since every profile can still read the shared home.
