# Design documents

The design and the Phase 1 build plan live in the "DevOps and RunOps" Claude project:

- `claude/log-watcher-design.md`
- `claude/log-watcher-plan-phase1.md`

Decisions taken after the design draft:

- Tier 2 model: `claude-haiku-5-5`. Phase 2 investigator model: `claude-sonnet-5-5`.
- Model endpoint, model name, and the name of the key's environment variable are config per tier.
