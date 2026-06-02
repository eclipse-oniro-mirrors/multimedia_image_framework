import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export const PACKAGE_NAME = "@ohos-graphics/opencode-knowledge-builder";
export const COMMAND_RELATIVE_PATH = "commands/knowledge.md";
export const AGENT_RELATIVE_PATH = "agents/knowledge-builder.md";

const DEFAULT_MODULE = "pixelmap";

export function buildRecipe(moduleName = DEFAULT_MODULE) {
  const normalized = String(moduleName || DEFAULT_MODULE).trim().toLowerCase();
  if (normalized !== DEFAULT_MODULE) {
    return {
      module: normalized,
      supported: false,
      message: "当前试点只内置 pixelmap recipe。请先用 /knowledge pixelmap；后续模块可通过扩展 recipe 接入同一入口。",
    };
  }

  return {
    module: DEFAULT_MODULE,
    outputPath: "docs/knowledge/pixelmap-memory-model.md",
    processArtifacts: {
      evidence: "docs/knowledge/.drafts/pixelmap/evidence.md",
      interview: "docs/knowledge/.drafts/pixelmap/interview.md",
      draft: "docs/knowledge/.drafts/pixelmap/draft.md",
      review: "docs/knowledge/.drafts/pixelmap/review.md",
    },
    workflowPhases: ["Discover", "Interview Plan", "Owner Interview", "Draft", "Review Gate", "Finalize"],
    goal: "通过代码证据和模块责任人访谈，沉淀 PixelMap 内存模型、接口行为、验证路径和常见风险。",
    codeAnchors: [
      "AGENTS.md",
      "interfaces/innerkits/include/pixel_map.h",
      "interfaces/innerkits/include/pixel_astc.h",
      "interfaces/innerkits/include/media_errors.h",
      "interfaces/kits/native/include/image/image_common.h",
      "frameworks/innerkitsimpl/common/",
      "frameworks/innerkitsimpl/converter/",
      "frameworks/innerkitsimpl/egl_image/",
      "frameworks/kits/js/common/image_error_convert.cpp",
      "frameworks/kits/js/common/pixelmap_ndk/",
      "frameworks/kits/cj/src/pixel_map_impl.cpp",
      "plugins/common/libs/image/libextplugin/src/texture_encode/",
      "frameworks/innerkitsimpl/test/",
      "frameworks/innerkitsimpl/test/fuzztest/",
    ],
    evidenceCommands: [
      "rg -n \"class PixelMap|PixelMap::Create|DMA_ALLOC|SHARE_MEM_ALLOC|CUSTOM_ALLOC|HEAP_ALLOC\" interfaces frameworks plugins",
      "rg -n \"ASTC|texture_encode|pixel_astc|CreatePixelMapForASTC|CompressToAstc\" interfaces frameworks plugins",
      "rg -n \"YCBCR_P010|YCRCB_P010|YUV|ConvertPixelMapFormat\" interfaces frameworks plugins",
      "rg -n \"Marshalling|Unmarshalling|Parcel|Surface|NativeBuffer|DMA\" interfaces frameworks plugins",
      "rg -n \"ERR_IMAGE_|SUCCESS|ImageError|Media::\" interfaces frameworks plugins",
    ],
    interviewTopics: [
      "PixelMap 创建入口、复用入口和各语言接口之间的真实边界",
      "HEAP_ALLOC、SHARE_MEM_ALLOC、CUSTOM_ALLOC、DMA_ALLOC 的选择规则、释放责任和跨进程限制",
      "surface、NativeBuffer、DMA buffer、GL 后处理相关生命周期，以及哪些场景必须真机验证",
      "YUV、P010、RGB、ASTC 的转换链路、限制条件和性能敏感点",
      "ASTC 编码场景、输入输出约束、texture encode 插件边界和测试资源来源",
      "Parcel/TLV/IPC 兼容性：哪些字段不能随意改，历史兼容包袱是什么",
      "错误码、JS/NDK/CJ/NAPI 映射和 XTS 验证要求",
      "典型故障：DMA 生命周期、stride/size 不一致、插件加载失败、硬解能力差异、HDR/色彩空间表现异常",
    ],
    documentSections: [
      "范围和读者",
      "代码证据地图",
      "公开接口和语言绑定边界",
      "PixelMap 创建和内存承载",
      "allocator 语义和生命周期",
      "YUV/P010/RGB/ASTC 转换",
      "ASTC 编码场景",
      "surface、DMA、GL 和跨进程传输",
      "错误码、API 兼容和 XTS",
      "验证建议",
      "常见问题和排查路径",
      "待补充和待真机确认",
    ],
    completionCriteria: [
      "每个关键结论都能追溯到代码锚点或责任人口述背景。",
      "未被代码或责任人确认的信息写入待补充，不写成确定事实。",
      "涉及接口行为时明确 JS/NDK/CJ/NAPI/Native 的同步检查点。",
      "涉及硬件、surface、DMA、HDR 或 codec 能力时明确真机验证项。",
    ],
    reviewChecklist: [
      "关键结论是否都有代码锚点或责任人回答支撑。",
      "代码证据地图是否覆盖接口、实现、测试、fuzz、错误码和语言绑定。",
      "是否存在未证实断言；如果存在，是否已放入待补充和待真机确认。",
      "涉及 API 行为时是否写明 JS/NDK/CJ/NAPI/Native 同步检查点和 XTS 验证。",
      "涉及硬件、surface、DMA、HDR、codec 能力时是否写明真实设备验证项和缺失原因。",
      "最终文档是否能被 AGENTS.md 知识路由直接消费。",
    ],
  };
}

export function buildKnowledgeDocTemplate(moduleName = DEFAULT_MODULE) {
  const recipe = buildRecipe(moduleName);
  if (recipe.supported === false) {
    return recipe.message;
  }

  return `# PixelMap 内存模型和接口行为

## 范围和读者

说明本文覆盖的 PixelMap 场景、适合阅读的人，以及不覆盖的边界。

## 代码证据地图

列出代码锚点、关键类/函数、它们分别回答什么问题。

## 公开接口和语言绑定边界

说明 Native inner API、JS/NAPI、NDK/C API、CJ、ANI/Taihe 等接口边界。

## PixelMap 创建和内存承载

说明创建入口、复用入口、尺寸/stride/format 校验和默认内存承载方式。

## allocator 语义和生命周期

分别说明 HEAP_ALLOC、SHARE_MEM_ALLOC、CUSTOM_ALLOC、DMA_ALLOC 的使用条件、释放责任和跨进程限制。

## YUV/P010/RGB/ASTC 转换

说明转换入口、格式约束、性能敏感点和失败路径。

## ASTC 编码场景

说明 ASTC 编码触发条件、texture encode 插件边界、输入输出约束和验证资源。

## surface、DMA、GL 和跨进程传输

说明 surface/native buffer、DMA buffer、GL 后处理、Parcel/TLV/IPC 的生命周期和兼容性要求。

## 错误码、API 兼容和 XTS

说明错误码映射、JS/NDK/CJ/NAPI 同步点、接口改动需要验证的 XTS 用例。

## 验证建议

列出本地构建、单元测试、fuzz、XTS 和真实设备验证建议。

## 常见问题和排查路径

记录 DMA 生命周期、stride/size、插件加载、硬解能力、HDR/色彩空间等典型问题。

## 待补充和待真机确认

只放尚未被代码或责任人确认的信息，不把推测写成事实。
`;
}

export function buildCommandTemplate() {
  return `---
description: Build a module knowledge doc through code reading and owner interview
agent: knowledge-builder
---

目标模块：$ARGUMENTS

你要启动仓库知识库访谈流程。若目标模块为空，先根据 AGENTS.md 的知识路由判断；当前试点内置 pixelmap recipe：

\`\`\`text
/knowledge pixelmap
\`\`\`

执行要求：

1. 先调用 \`knowledge_recipe\`，参数 module 取目标模块，读取其中的 \`workflowPhases\`、\`processArtifacts\`、\`outputPath\` 和 \`reviewChecklist\`；如果工具暂时不可用，按本命令和 AGENTS.md 里的知识路由继续。
2. 按 superpowers-style 阶段推进，不要跳阶段：
   - Discover：读取当前仓的 \`AGENTS.md\`，按 recipe 代码锚点和命令整理代码证据地图，写入 \`processArtifacts.evidence\`。
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
2. 对目标模块调用 knowledge_recipe，拿到代码锚点、访谈主题、输出路径、processArtifacts、workflowPhases、reviewChecklist 和验收条件。
3. 按 Discover → Interview Plan → Owner Interview → Draft → Review Gate → Finalize 推进，不要跳阶段。
4. Discover 阶段使用 read/list/grep/rg 梳理代码证据地图：接口文件、实现文件、测试、fuzz、插件边界、错误码映射都要分清，并写入 docs/knowledge/.drafts/<module>/evidence.md。
5. Interview Plan 和 Owner Interview 阶段先访谈，再落最终文档。每轮最多问 3 个问题，并把问题和已看到的代码证据关联起来；访谈记录写入 docs/knowledge/.drafts/<module>/interview.md。
6. Draft 阶段只写过程草稿 docs/knowledge/.drafts/<module>/draft.md。
7. Review Gate 阶段按 reviewChecklist 检视草稿，把结果写入 docs/knowledge/.drafts/<module>/review.md；存在遗留问题时继续追问或标为待补充。
8. 用户明确确认“生成最终文档”后，才写入 recipe 的 outputPath。

写作约束：

- 不要把推测写成事实；未确认信息进入“待补充和待真机确认”。
- 每个关键结论要能追溯到代码锚点或责任人回答。
- 过程件可以生成；最终知识文档必须经过 Review Gate 和用户确认。
- 接口行为变更要覆盖 Native、JS/NAPI、NDK/C API、CJ、ANI/Taihe 等同步检查点。
- 涉及 PixelMap、allocator、DMA、surface、HDR、色彩空间、ASTC、YUV/P010、IPC/Parcel 时，要写明验证路径。
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
    command: "/knowledge pixelmap",
  };
}
