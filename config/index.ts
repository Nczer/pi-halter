// ── Config barrel — re-exports all config concerns ──

export { ABORT_REMEMBER_MS, PROMPT_WARNING_THRESHOLD } from "./thresholds";
export { unconditionallySafeCommands, isAllowedCommand, isSafeSubcommand, pathAwareCommands, dangerousFindFlags, dangerousSedFlags, dangerousPerlFlags, wrapperCommands, isWriteOperation, SHELL_INTERPRETERS } from "./bash-patterns";
export { PACKAGE_MANAGERS } from "../segment-helpers";
export { allowedReadPaths, allowedWritePaths, deniedPaths, warnPaths } from "./path-rules";
export { dangerousCommandPatterns, dangerousContextPatterns } from "./dangerous-patterns";
export { isTrustedScriptPath, isTrustedScriptCommand } from "./trusted-scripts";
