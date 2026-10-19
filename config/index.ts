// ── Config barrel — re-exports all config concerns ──

// Time and count thresholds
/** How long (ms) to remember a recently-aborted command before allowing retry. */
export const ABORT_REMEMBER_MS = 60_000;
/** Number of prompts before showing high-frequency warning. */
export const PROMPT_WARNING_THRESHOLD = 20;

export { unconditionallySafeCommands, isAllowedCommand, isSafeSubcommand, pathAwareCommands, wrapperCommands, isWriteOperation, codeBodiesWrite, codeWriteCapable, type CodeBody, SHELL_INTERPRETERS, SCRIPT_INTERPRETERS, PACKAGE_MANAGERS, NETWORK_COMMANDS, GIT_NETWORK_SUBCOMMANDS, GIT_FETCH_SUBCOMMANDS, GIT_GLOBAL_FLAGS, NETWORK_URL_RE, NETWORK_URL_RE_GLOBAL, UPLOAD_BODY_FLAGS, UPLOAD_COPY_COMMANDS, HTTP_METHOD_FLAGS, findNetworkEgress, FETCH_PKG_FORMS, fetchFormScan, type FetchFormScan, gitNetworkSubcommand, goCargoFetchForm, skipEnvPrefixes } from "./bash-patterns";
export { allowedReadPaths, allowedWritePaths, warnPaths } from "./path-rules";
export { dangerousCommandPatterns, dangerousContextPatterns } from "./dangerous-patterns";
export { isTrustedScriptPath, isTrustedScriptCommand, registryRunDeps, resolveDepSource, uvRunFlags, uvFetchFormOk, type RegistryDep, type UvRunDep, type UvRunOption, type UvRunFlags, type UvDepFlag } from "./trusted-scripts";
export { findScriptOperand, type ScriptOperand, type ScriptCandidate } from "./script-operand";
export { DECISION_LOG_ENABLED } from "./logging";
