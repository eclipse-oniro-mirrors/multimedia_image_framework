import { tool } from "@opencode-ai/plugin";

import {
  buildKnowledgeDocTemplate,
  buildRecipe,
} from "./install.mjs";

function asPrettyJson(value) {
  return JSON.stringify(value, null, 2);
}

export const KnowledgeBuilderPlugin = async () => ({
  tool: {
    knowledge_recipe: tool({
      description: "Return the code-reading recipe and interview plan for a repository module knowledge document.",
      args: {
        module: tool.schema.string().optional(),
      },
      async execute(args) {
        return asPrettyJson(buildRecipe(args.module));
      },
    }),

    knowledge_template: tool({
      description: "Return the Markdown document template for a repository module knowledge document.",
      args: {
        module: tool.schema.string().optional(),
      },
      async execute(args) {
        return buildKnowledgeDocTemplate(args.module);
      },
    }),
  },
});

export default KnowledgeBuilderPlugin;
