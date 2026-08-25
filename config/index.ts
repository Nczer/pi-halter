// ── Config barrel — re-exports all config concerns ──

// Time and count thresholds
/** How long (ms) to remember a recently-aborted command before allowing retry. */
export const ABORT_REMEMBER_MS = 60_000;
/** Number of prompts before showing high-frequency warning. */
export const PROMPT_WARNING_THRESHOLD = 20;

export { unconditionallySafeCommands, isAllowedCommand, isSafeSubcommand, pathAwareCommands, wrapperCommands, isWriteOperation, SHELL_INTERPRETERS, SCRIPT_INTERPRETERS, PACKAGE_MANAGERS, NETWORK_COMMANDS, GIT_NETWORK_SUBCOMMANDS, GIT_GLOBAL_FLAGS, NETWORK_URL_RE, findNetworkEgress, FETCH_PKG_FORMS, fetchFormPackage, gitNetworkSubcommand, skipEnvPrefixes } from "./bash-patterns";
export { allowedReadPaths, allowedWritePaths, deniedPaths, warnPaths } from "./path-rules";
export { dangerousCommandPatterns, dangerousContextPatterns } from "./dangerous-patterns";
export { isTrustedScriptPath, isTrustedScriptCommand } from "./trusted-scripts";
export { DECISION_LOG_ENABLED } from "./logging";
