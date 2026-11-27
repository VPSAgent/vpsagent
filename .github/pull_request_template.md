## Summary
<!-- Briefly describe what changed and why. -->

## Verification
- [ ] `pnpm build` passes
- [ ] `pnpm typecheck` passes
- [ ] `pnpm test` passes

## Security & Scope Checklist
- [ ] No `/var/run/docker.sock` exposure in core containers
- [ ] No secrets, tokens (`vpsmcp_*`), or `.env` values committed or logged
- [ ] Keeps VPSAgent lean (no built-in AI chat UI or LLM provider settings)
