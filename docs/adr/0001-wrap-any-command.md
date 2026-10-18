# Wrap any command, not specific agents

enclos runs any command (`enclos run -- <command>`) inside a sandbox, instead of integrating with specific agents such as Claude Code or Codex. The boundary is enforced by the operating system, so it holds whatever the agent does, and it works the same for every agent and for plain scripts. Agent-specific integrations (for example, richer audit records from an agent's hooks) can be added on top later, but they never replace the sandbox.
