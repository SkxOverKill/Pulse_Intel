# Contributing to Pulse Intelligence

Thanks for helping make Pulse Intelligence useful for analysts and teams that need an
open CTI platform.

## Development setup

```bash
npm install
npm run db:migrate
npm run db:seed
npm run db:seed:demo
npm run dev
```

Use `.env.example` as the environment template. Never commit `.env`, API keys, database dumps,
or exported production intelligence.

## Before opening a pull request

Run the fast checks:

```bash
npm run lint
npm run typecheck
npm run test
npm run build
```

For changes that touch enrichment, feeds, hunting, API keys, or reports, also run the relevant
verify script from `package.json`.

## Project rules worth preserving

- Relations that express analyst judgement must carry confidence and attribution.
- Whitelisted indicators must never be enriched, exported, alerted on, or matched by hunts.
- Report bodies must stay plain/preformatted text unless a safe renderer is added.
- ATT&CK imports are version-pinned; upgrades should be deliberate and reviewed.
- Feed and enrichment work should surface quotas honestly instead of implying instant completion.

## Pull request style

Keep pull requests focused. Include:

- What changed.
- How you verified it.
- Any migrations or operator steps.
- Screenshots for UI changes.
