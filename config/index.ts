// ── Config barrel — re-exports all config concerns ──

export { ABORT_REMEMBER_MS, PROMPT_WARNING_THRESHOLD } from "./thresholds";
export { allowedBashPatterns, pathAwareCommands, dangerousFindFlags, dangerousSedFlags, dangerousPerlFlags, wrapperCommands, writeCapableCommands, isWriteOperation, SHELL_INTERPRETERS } from "./bash-patterns";
export { allowedReadPaths, allowedWritePaths, deniedPaths } from "./path-rules";
export { dangerousCommandPatterns, dangerousContextPatterns } from "./dangerous-patterns";
export { isTrustedScriptPath, isTrustedScriptCommand } from "./trusted-scripts";
