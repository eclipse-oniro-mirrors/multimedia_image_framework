# OpenCode Knowledge Builder

OpenCode workflow plugin for building OpenHarmony repository knowledge docs through code reading and owner interviews.

## Install

After publishing this package to npm:

```sh
npx @ohos-graphics/opencode-knowledge-builder install
```

The installer updates the global OpenCode config, installs a global command, and installs a dedicated agent:

- `~/.config/opencode/opencode.json`
- `~/.config/opencode/commands/knowledge.md`
- `~/.config/opencode/agents/knowledge-builder.md`

It does not write `.opencode/` files into product repositories.

## Use

Open an OpenHarmony repository in OpenCode and run:

```text
/knowledge <module>
```

The module name is an input. The plugin reads the current repository's `AGENTS.md` knowledge routing and code evidence to decide what to inspect and ask; it does not include module-specific interview questions.

The workflow follows a superpowers-style gated process:

1. `Discover` reads `AGENTS.md`, scans code anchors, and writes an evidence map.
2. `Interview Plan` prepares owner questions from the evidence map.
3. `Owner Interview` asks the module owner for design background, history, constraints, and verification knowledge.
4. `Draft` writes a process draft, not the final document.
5. `Review Gate` checks the draft against evidence, API compatibility, XTS, real-device validation, and unanswered questions.
6. `Finalize` writes the final knowledge doc only after the user confirms.

For a module named `<module>`, process artifacts are written under:

```text
docs/knowledge/.drafts/<module>/evidence.md
docs/knowledge/.drafts/<module>/interview.md
docs/knowledge/.drafts/<module>/draft.md
docs/knowledge/.drafts/<module>/review.md
```

The final document path prefers the path found in `AGENTS.md`; otherwise it falls back to:

```text
docs/knowledge/<module>.md
```

## Local Trial

From this package directory:

```sh
node bin/opencode-knowledge-builder.mjs install --dry-run
node bin/opencode-knowledge-builder.mjs install --config-dir /tmp/opencode-config
```

## Publish

```sh
npm publish --access public
```
