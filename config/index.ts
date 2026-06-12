// ── Config barrel — re-exports all config concerns ──

// Time and count thresholds
/** How long (ms) to remember a recently-aborted command before allowing retry. */
export const ABORT_REMEMBER_MS = 60_000;
/** Number of prompts before showing high-frequency warning. */
export const PROMPT_WARNING_THRESHOLD = 20;

export { unconditionallySafeCommands, isAllowedCommand, isSafeSubcommand, pathAwareCommands, dangerousFindFlags, dangerousSedFlags, dangerousPerlFlags, wrapperCommands, isWriteOperation, SHELL_INTERPRETERS } from "./bash-patterns";
export { PACKAGE_MANAGERS } from "../analysis/segment-helpers";
export { allowedReadPaths, allowedWritePaths, deniedPaths, warnPaths } from "./path-rules";
export { dangerousCommandPatterns, dangerousContextPatterns } from "./dangerous-patterns";
export { isTrustedScriptPath, isTrustedScriptCommand } from "./trusted-scripts";
