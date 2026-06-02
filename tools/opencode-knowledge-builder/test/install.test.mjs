import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PACKAGE_NAME,
  buildAgentTemplate,
  buildCommandTemplate,
  buildRecipe,
  installKnowledgeBuilder,
  updateOpenCodeConfigText,
} from "../src/install.mjs";

test("updateOpenCodeConfigText adds the package plugin and preserves existing plugins", () => {
  const input = `{
  // keep comments
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["existing-plugin"]
}`;

  const output = updateOpenCodeConfigText(input, PACKAGE_NAME);

  assert.match(output, /keep comments/);
  assert.match(output, /"existing-plugin"/);
  assert.match(output, new RegExp(`"${PACKAGE_NAME.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"`));
});

test("updateOpenCodeConfigText is idempotent", () => {
  const input = `{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["${PACKAGE_NAME}"]
}`;

  const output = updateOpenCodeConfigText(input, PACKAGE_NAME);

  assert.equal((output.match(new RegExp(PACKAGE_NAME, "g")) ?? []).length, 1);
});

test("buildCommandTemplate starts the interactive knowledge workflow", () => {
  const command = buildCommandTemplate();

  assert.match(command, /^---\ndescription:/);
  assert.match(command, /agent: knowledge-builder/);
  assert.match(command, /knowledge_recipe/);
  assert.match(command, /\/knowledge <module>/);
  assert.match(command, /Discover/);
  assert.match(command, /Review Gate/);
  assert.match(command, /processArtifacts/);
  assert.doesNotMatch(command, /image-knowledge/);
});

test("buildAgentTemplate limits permissions and requires owner interview before finalizing", () => {
  const agent = buildAgentTemplate();

  assert.match(agent, /description: Builds repository module knowledge docs/);
  assert.match(agent, /edit: ask/);
  assert.match(agent, /docs\/knowledge\/.drafts/);
  assert.match(agent, /每轮最多问/);
  assert.match(agent, /Review Gate/);
  assert.match(agent, /不要把推测写成事实/);
});

test("buildRecipe returns generic process artifacts for any module", () => {
  const recipe = buildRecipe("sample module");

  assert.equal(recipe.module, "sample module");
  assert.equal(recipe.moduleSlug, "sample-module");
  assert.equal(recipe.outputPath, "docs/knowledge/sample-module.md");
  assert.equal(recipe.processArtifacts.evidence, "docs/knowledge/.drafts/sample-module/evidence.md");
  assert.equal(recipe.processArtifacts.interview, "docs/knowledge/.drafts/sample-module/interview.md");
  assert.equal(recipe.processArtifacts.draft, "docs/knowledge/.drafts/sample-module/draft.md");
  assert.equal(recipe.processArtifacts.review, "docs/knowledge/.drafts/sample-module/review.md");
  assert.deepEqual(recipe.workflowPhases, ["Discover", "Interview Plan", "Owner Interview", "Draft", "Review Gate", "Finalize"]);
  assert.ok(recipe.routeSources.includes("AGENTS.md"));
  assert.ok(recipe.discoveryQuestions.some((question) => question.includes("代码锚点")));
  assert.ok(recipe.reviewChecklist.some((item) => item.includes("代码锚点")));
});

test("package templates do not hardcode a pilot module name", async () => {
  const packageRoot = new URL("..", import.meta.url);
  const files = [
    "README.md",
    "src/install.mjs",
    "src/plugin.mjs",
    "bin/opencode-knowledge-builder.mjs",
  ];

  for (const file of files) {
    const text = await readFile(new URL(file, packageRoot), "utf8");
    assert.doesNotMatch(text, /pixelmap/i, `${file} should not hardcode pilot module names`);
  }
});

test("installKnowledgeBuilder writes global command, agent, and config without clobbering", async () => {
  const tempHome = await mkdtemp(path.join(os.tmpdir(), "opencode-knowledge-builder-"));
  try {
    const configDir = path.join(tempHome, ".config", "opencode");

    const first = await installKnowledgeBuilder({ configDir });
    const second = await installKnowledgeBuilder({ configDir });

    assert.equal(first.changed.length, 3);
    assert.equal(second.changed.length, 0);
    await stat(path.join(configDir, "commands", "knowledge.md"));
    await stat(path.join(configDir, "agents", "knowledge-builder.md"));

    const config = await readFile(path.join(configDir, "opencode.json"), "utf8");
    assert.match(config, new RegExp(PACKAGE_NAME.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  } finally {
    await rm(tempHome, { recursive: true, force: true });
  }
});

test("installKnowledgeBuilder refuses to overwrite changed templates unless forced", async () => {
  const tempHome = await mkdtemp(path.join(os.tmpdir(), "opencode-knowledge-builder-"));
  try {
    const configDir = path.join(tempHome, ".config", "opencode");
    await installKnowledgeBuilder({ configDir });
    await writeFile(path.join(configDir, "commands", "knowledge.md"), "custom command", "utf8");

    await assert.rejects(
      installKnowledgeBuilder({ configDir }),
      /Refusing to overwrite/,
    );

    const forced = await installKnowledgeBuilder({ configDir, force: true });
    assert.ok(forced.changed.includes("commands/knowledge.md"));
  } finally {
    await rm(tempHome, { recursive: true, force: true });
  }
});
