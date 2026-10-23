import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "AICodeAuditor",
  version: packageJson.version,
  copyright: `© ${currentYear}, AICodeAuditor.`,
  meta: {
    title: "AICodeAuditor — 代码审计平台",
    description: "LLM 驱动的源代码安全审计平台控制台",
  },
};
