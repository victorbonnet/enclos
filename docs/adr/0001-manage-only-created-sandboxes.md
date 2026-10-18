---
status: accepted
---

# enclos manages only the sandboxes it creates

enclos creates named, persistent sandboxes, installs an agent in each, and governs them through a policy, a state and an audit log. It never discovers, scans or collects agents it did not start, and it never routes work between agents. This keeps the state complete (everything enclos manages, it created) and keeps the product a control tool rather than an orchestrator.

## Considered options

- **Wrap any command (`enclos run -- <cmd>`):** simpler, but it gives enclos nothing persistent to hold a policy, a state or a network log against. `enclos exec <sandbox> -- <cmd>` covers one-off commands inside an existing sandbox.
