// ── Config barrel — re-exports all config concerns ──

export { ABORT_REMEMBER_MS, PROMPT_WARNING_THRESHOLD } from "./thresholds";
export { allowedBashPatterns, pathAwareCommands, dangerousFindFlags } from "./bash-patterns";
export { allowedReadPaths, deniedPaths } from "./path-rules";
export { dangerousPatterns } from "./dangerous-patterns";
