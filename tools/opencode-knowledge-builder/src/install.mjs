import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const PACKAGE_NAME = "@ohos-graphics/opencode-knowledge-builder";
export const COMMAND_RELATIVE_PATH = "commands/knowledge.md";
export const AGENT_RELATIVE_PATH = "agents/knowledge-builder.md";

const MODULE_PLACEHOLDER = "<module>";

function normalizeModuleName(moduleName) {
  const value = String(moduleName || MODULE_PLACEHOLDER).trim();
  return value || MODULE_PLACEHOLDER;
}

function escapeForRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function slugifyModule(moduleName) {
  const slug = normalizeModuleName(moduleName)
    .toLowerCase()
    .replace(/^<|>$/g, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "module";
}

export function buildRecipe(moduleName = MODULE_PLACEHOLDER) {
  const module = normalizeModuleName(moduleName);
  const moduleSlug = slugifyModule(module);

  return {
    module,
    moduleSlug,
    outputPath: `docs/knowledge/${moduleSlug}.md`,
    outputPathPolicy: "Prefer an explicit knowledge document path from AGENTS.md knowledge routing; fallback to outputPath.",
    processArtifacts: {
      evidence: `docs/knowledge/.drafts/${moduleSlug}/evidence.md`,
      interview: `docs/knowledge/.drafts/${moduleSlug}/interview.md`,
      draft: `docs/knowledge/.drafts/${moduleSlug}/draft.md`,
      review: `docs/knowledge/.drafts/${moduleSlug}/review.md`,
    },
    workflowPhases: ["Discover", "Interview Plan", "Owner Interview", "Draft", "Review Gate", "Finalize"],
    goal: "通过仓内知识路由、代码证据和模块责任人访谈，沉淀模块职责、接口行为、验证路径和常见风险。",
    routeSources: [
      "AGENTS.md",
      "README.md",
      "docs/knowledge/",
      "BUILD.gn",
    ],
    routeDiscovery: [
      "先从 AGENTS.md 的知识路由表查找目标模块对应的文档路径、代码锚点和验证重点。",
      "如果 AGENTS.md 没有目标模块路由，先根据模块名在仓内搜索候选目录、接口文件、测试目标和构建目标。",
      "如果候选范围仍不清楚，先询问用户模块边界，不要套用任何内置示例。",
    ],
    evidenceCommands: [
      `rg -n "${escapeForRegex(module)}" AGENTS.md README.md docs interfaces frameworks services plugins test 2>/dev/null || true`,
      `rg --files | rg -i "${escapeForRegex(moduleSlug)}|${escapeForRegex(module)}" || true`,
      "rg -n \"ERR_|ERROR|SUCCESS|Result|Status|Exception|Parcel|IPC|NAPI|NDK|XTS|fuzz|unittest|BUILD.gn\" . 2>/dev/null || true",
    ],
    discoveryQuestions: [
      "AGENTS.md 是否已经给出目标模块的知识路由、代码锚点和验证重点？",
      "代码锚点里哪些是公开接口，哪些是内部实现，哪些是测试或 mock？",
      "从代码证据看，哪些行为缺少设计背景、历史约束或责任人确认？",
      "哪些接口、错误码、跨仓依赖、兼容性或验证要求需要进一步追问？",
    ],
    interviewPrinciples: [
      "问题必须来自代码证据缺口，不使用插件内置模块示例替代当前模块事实。",
      "每轮最多问 3 个问题，说明问题关联的代码锚点或不确定点。",
      "优先追问责任边界、接口行为、数据/资源生命周期、跨仓依赖、验证方式和典型故障。",
      "未被代码或责任人确认的信息进入待补充，不写成确定事实。",
    ],
    documentSections: [
      "范围和读者",
      "代码证据地图",
      "模块职责和边界",
      "公开接口和内部实现边界",
      "核心数据结构、状态和生命周期",
      "依赖和跨仓接口",
      "错误码、兼容性和外部行为",
      "验证建议",
      "常见问题和排查路径",
      "待补充和待确认",
    ],
    completionCriteria: [
      "每个关键结论都能追溯到代码锚点或责任人口述背景。",
      "未被代码或责任人确认的信息写入待补充，不写成确定事实。",
      "涉及接口行为时明确需要同步检查的语言绑定、调用方或跨仓依赖。",
      "涉及设备、硬件能力、跨进程、异步或资源生命周期时明确真实环境验证项。",
    ],
    reviewChecklist: [
      "关键结论是否都有代码锚点或责任人回答支撑。",
      "代码证据地图是否覆盖接口、实现、测试、构建目标、错误码和外部绑定。",
      "是否存在未证实断言；如果存在，是否已放入待补充和待真机确认。",
      "涉及 API 行为时是否写明调用方、兼容性、错误码映射和 XTS/接口测试要求。",
      "涉及设备、硬件能力、异步、跨进程或资源生命周期时是否写明真实环境验证项和缺失原因。",
      "最终文档是否能被 AGENTS.md 知识路由直接消费。",
    ],
  };
}

export function buildKnowledgeDocTemplate(moduleName = MODULE_PLACEHOLDER) {
  const recipe = buildRecipe(moduleName);

  return `# ${recipe.module} 模块知识文档

## 范围和读者

说明本文覆盖的模块场景、适合阅读的人，以及不覆盖的边界。

## 代码证据地图

列出代码锚点、关键类/函数、它们分别回答什么问题。

## 模块职责和边界

说明模块负责什么、不负责什么、和相邻模块如何分工。

## 公开接口和内部实现边界

说明公开接口、内部实现、语言绑定或跨仓接口边界。

## 核心数据结构、状态和生命周期

说明核心对象、状态流转、资源创建和释放责任。

## 依赖和跨仓接口

说明依赖方、被依赖方、能力查询、配置和跨仓协调方式。

## 错误码、兼容性和外部行为

说明错误码映射、兼容性约束、外部可观测行为和接口测试要求。

## 验证建议

列出本地构建、单元测试、fuzz、接口测试、XTS 和真实环境验证建议。

## 常见问题和排查路径

记录常见编译错误、运行时故障、能力差异、资源生命周期或兼容性问题。

## 待补充和待确认

只放尚未被代码或责任人确认的信息，不把推测写成事实。
`;
}

export function buildCommandTemplate() {
  return `---
description: Build a module knowledge doc through code reading and owner interview
agent: knowledge-builder
---

目标模块：$ARGUMENTS

你要启动仓库知识库访谈流程。模块名由用户输入决定，不要使用插件内置示例替代当前模块事实。若目标模块为空，先根据 AGENTS.md 的知识路由判断；仍无法判断时先询问用户模块名和范围：

\`\`\`text
/knowledge <module>
\`\`\`

执行要求：

1. 先调用 \`knowledge_recipe\`，参数 module 取目标模块，读取其中的 \`routeDiscovery\`、\`workflowPhases\`、\`processArtifacts\`、\`outputPath\` 和 \`reviewChecklist\`；如果工具暂时不可用，按本命令和 AGENTS.md 里的知识路由继续。
2. 按 superpowers-style 阶段推进，不要跳阶段：
   - Discover：读取当前仓的 \`AGENTS.md\`，按知识路由和 recipe 的 routeDiscovery/evidenceCommands 发现代码锚点、验证重点和缺失信息，写入 \`processArtifacts.evidence\`。
   - Interview Plan：基于证据地图形成访谈计划，写入 \`processArtifacts.interview\`，然后向责任人提问。
   - Owner Interview：每轮最多问 3 个问题，并说明问题对应的代码证据或不确定点。
   - Draft：用户回答足够后，先写 \`processArtifacts.draft\`，不要直接写最终文档。
   - Review Gate：按 \`reviewChecklist\` 检视草稿，结果写入 \`processArtifacts.review\`，有遗留问题时继续追问或标为待补充。
   - Finalize：用户明确确认“生成最终文档”后，才写入 \`outputPath\`。
3. 过程件允许生成；最终文档必须等用户确认后生成。
4. 不要把推测写成事实；未确认的信息放入“待补充和待真机确认”。
`;
}

export function buildAgentTemplate() {
  return `---
description: Builds repository module knowledge docs by reading code and interviewing owners
mode: primary
permission:
  read: allow
  list: allow
  grep: allow
  edit: ask
  question: allow
  webfetch: deny
  websearch: deny
  bash:
    "*": ask
    "rg *": allow
    "git status*": allow
    "git diff*": allow
---

你是 OpenHarmony 仓库知识库访谈 agent。你的目标不是一次性编故事，而是结合代码证据和模块责任人的背景知识，按 superpowers-style 阶段门禁生成可被后续 agent 路由和复用的模块知识文档。

工作方式：

1. 先读当前仓的 AGENTS.md，理解仓级规则、提交约束和知识路由。
2. 对目标模块调用 knowledge_recipe，拿到 routeDiscovery、输出路径、processArtifacts、workflowPhases、reviewChecklist 和验收条件。
3. 按 Discover → Interview Plan → Owner Interview → Draft → Review Gate → Finalize 推进，不要跳阶段。
4. Discover 阶段先从 AGENTS.md 知识路由发现模块对应的代码锚点、验证重点和候选知识文档路径；如果 AGENTS.md 没有该模块路由，先通过 read/list/grep/rg 搜索候选目录、接口文件、实现文件、测试、构建目标、错误码和外部绑定，仍不清楚时询问用户模块边界，并写入 docs/knowledge/.drafts/<module>/evidence.md。
5. Interview Plan 和 Owner Interview 阶段先访谈，再落最终文档。每轮最多问 3 个问题，并把问题和已看到的代码证据关联起来；访谈记录写入 docs/knowledge/.drafts/<module>/interview.md。
6. Draft 阶段只写过程草稿 docs/knowledge/.drafts/<module>/draft.md。
7. Review Gate 阶段按 reviewChecklist 检视草稿，把结果写入 docs/knowledge/.drafts/<module>/review.md；存在遗留问题时继续追问或标为待补充。
8. 用户明确确认“生成最终文档”后，才写入 recipe 的 outputPath。

写作约束：

- 不要把推测写成事实；未确认信息进入“待补充和待真机确认”。
- 每个关键结论要能追溯到代码锚点或责任人回答。
- 模块专属问题必须来自当前仓的 AGENTS.md、代码证据或用户回答，不要套用插件里的固定模块例子。
- 过程件可以生成；最终知识文档必须经过 Review Gate 和用户确认。
- 接口行为变更要覆盖 Native、JS/NAPI、NDK/C API、CJ、ANI/Taihe 等同步检查点。
- 涉及资源生命周期、跨进程、异步、硬件能力、协议/格式、接口兼容或外部可观测行为时，要写明验证路径。
- 文档语言使用中文，面向不熟悉该模块但需要改代码的工程师。
`;
}

function escapeForJson(value) {
  return JSON.stringify(value);
}

function stripJsonComments(text) {
  let result = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const next = text[i + 1];
    if (inString) {
      result += char;
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === "\"") {
        inString = false;
      }
      continue;
    }
    if (char === "\"") {
      inString = true;
      result += char;
      continue;
    }
    if (char === "/" && next === "/") {
      while (i < text.length && text[i] !== "\n") {
        i += 1;
      }
      result += "\n";
      continue;
    }
    if (char === "/" && next === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) {
        i += 1;
      }
      i += 1;
      continue;
    }
    result += char;
  }
  return result.replace(/,\s*([}\]])/g, "$1");
}

function parseJsonc(text) {
  return JSON.parse(stripJsonComments(text));
}

function findStringProperty(text, propertyName) {
  const pattern = new RegExp(`"${propertyName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\s*:\\s*`, "g");
  const match = pattern.exec(text);
  return match ? { start: match.index, valueStart: pattern.lastIndex } : null;
}

function findMatchingBracket(text, openIndex, openChar, closeChar) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = openIndex; i < text.length; i += 1) {
    const char = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === "\"") {
        inString = false;
      }
      continue;
    }
    if (char === "\"") {
      inString = true;
      continue;
    }
    if (char === openChar) {
      depth += 1;
    } else if (char === closeChar) {
      depth -= 1;
      if (depth === 0) {
        return i;
      }
    }
  }
  return -1;
}

function lineIndentBefore(text, index) {
  const lineStart = text.lastIndexOf("\n", index - 1) + 1;
  const prefix = text.slice(lineStart, index);
  return prefix.match(/^\s*/)?.[0] ?? "";
}

export function updateOpenCodeConfigText(text, pluginName = PACKAGE_NAME) {
  const parsed = parseJsonc(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("OpenCode config must be a JSON object.");
  }

  const pluginProperty = findStringProperty(text, "plugin");
  if (!pluginProperty) {
    const closeIndex = findMatchingBracket(text, text.indexOf("{"), "{", "}");
    if (closeIndex < 0) {
      throw new Error("OpenCode config is missing the root closing brace.");
    }
    const hasProperties = Object.keys(parsed).length > 0;
    const closeIndent = lineIndentBefore(text, closeIndex);
    const itemIndent = `${closeIndent}  `;
    const insertion = `${hasProperties ? "," : ""}\n${itemIndent}"plugin": [${escapeForJson(pluginName)}]\n${closeIndent}`;
    return `${text.slice(0, closeIndex)}${insertion}${text.slice(closeIndex)}`;
  }

  if (!Array.isArray(parsed.plugin)) {
    throw new Error("OpenCode config field \"plugin\" must be an array.");
  }
  if (parsed.plugin.includes(pluginName)) {
    return text;
  }

  const arrayStart = text.indexOf("[", pluginProperty.valueStart);
  const arrayEnd = findMatchingBracket(text, arrayStart, "[", "]");
  if (arrayStart < 0 || arrayEnd < 0) {
    throw new Error("OpenCode config field \"plugin\" must be an array.");
  }

  const closeIndent = lineIndentBefore(text, arrayEnd);
  const itemIndent = closeIndent ? `${closeIndent}  ` : "  ";
  const arrayText = text.slice(arrayStart, arrayEnd + 1);
  const isEmpty = parseJsonc(arrayText).length === 0;
  const insertion = isEmpty
    ? `\n${itemIndent}${escapeForJson(pluginName)}\n${closeIndent}`
    : `,\n${itemIndent}${escapeForJson(pluginName)}\n${closeIndent}`;
  return `${text.slice(0, arrayEnd)}${insertion}${text.slice(arrayEnd)}`;
}

export function defaultConfigDir(env = process.env) {
  if (env.OPENCODE_CONFIG_DIR) {
    return env.OPENCODE_CONFIG_DIR;
  }
  if (env.XDG_CONFIG_HOME) {
    return path.join(env.XDG_CONFIG_HOME, "opencode");
  }
  return path.join(os.homedir(), ".config", "opencode");
}

async function readTextIfExists(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

async function writeManagedFile(configDir, relativePath, content, options) {
  const target = path.join(configDir, relativePath);
  const previous = await readTextIfExists(target);
  if (previous === content) {
    return false;
  }
  if (previous !== null && !options.force) {
    throw new Error(`Refusing to overwrite ${relativePath}. Re-run with --force if this is expected.`);
  }
  if (!options.dryRun) {
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content, "utf8");
  }
  return true;
}

async function writeConfig(configDir, packageName, options) {
  const target = path.join(configDir, "opencode.json");
  const previous = await readTextIfExists(target);
  const next = previous === null
    ? `{\n  "$schema": "https://opencode.ai/config.json",\n  "plugin": [${escapeForJson(packageName)}]\n}\n`
    : updateOpenCodeConfigText(previous, packageName);
  if (previous === next) {
    return false;
  }
  if (!options.dryRun) {
    await mkdir(configDir, { recursive: true });
    await writeFile(target, next, "utf8");
  }
  return true;
}

export async function installKnowledgeBuilder({
  configDir = defaultConfigDir(),
  packageName = PACKAGE_NAME,
  dryRun = false,
  force = false,
} = {}) {
  const changed = [];
  const options = { dryRun, force };

  if (await writeConfig(configDir, packageName, options)) {
    changed.push("opencode.json");
  }
  if (await writeManagedFile(configDir, COMMAND_RELATIVE_PATH, buildCommandTemplate(), options)) {
    changed.push(COMMAND_RELATIVE_PATH);
  }
  if (await writeManagedFile(configDir, AGENT_RELATIVE_PATH, buildAgentTemplate(), options)) {
    changed.push(AGENT_RELATIVE_PATH);
  }

  return {
    configDir,
    packageName,
    changed,
    command: "/knowledge <module>",
  };
}
