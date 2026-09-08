/**
 * dspa conversions — the two D3/D11 auto-allow → prompt probes (docs/
 * dspa-redesign.md). A manual auto-allow means the LOCATION/command form
 * is trusted; under /dspa the CONTENT of reviewable operations is still
 * judged (two stages, same policy as a prompt). The conversion re-shapes
 * the auto-allow into the manual-shaped prompt so the shared dspa block
 * in gate() handles gate → judge → auto-allow / prompt-with-verdict
 * uniformly.
 *
 * Session grants convert too (D3): the grant trusts the LOCATION, the
 * content is still judged. Every manual write auto-allow (project .pi
 * paths, session-granted dirs/files, static config paths) becomes a judged
 * prompt; in-cwd writes need no probe — they prompt in manual already and
 * take the normal dspa prompt → judge path.
 *
 * Payload-less commands, reads, and non-dspa modes are never converted.
 * Judge off/invalid → no conversion (the manual auto-allow stands — dspa
 * never adds a prompt on its own; a runtime judge failure still falls
 * toward the prompt, D6).
 */
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import type {Decision, PermissionRequest} from "../decide/types";
import { synthesizeManualBashPrompt } from "../decide/bash-rules";
import { findExecutedScript } from "../analysis/script-payload";
import { judgeStatus } from "../judge/verdict";
import { isDspaActive } from "../modes/dspa-mode";
import { gateDecide } from "./gate";
import type { Store } from "./store";

/**
 * Run both dspa content-judgment probes over a manual auto-allow:
 *
 *  1. D3 file-write probe: a WRITE that manual mode would auto-allow is
 *     re-decided with judgeWriteAutoAllows — every manual write auto-allow
 *     converts to a prompt, session grants included (the grant trusts the
 *     location, the content is judged, D3; reads are never judged).
 *  2. D11 bash conversion: an auto-allow that runs a reviewable script
 *     payload (granted interpreter execution) is judged — the grant
 *     trusts the command form, the content is still reviewed. The
 *     deterministic floor is moot on a manual auto-allow: it already
 *     passed every danger check (canBeAutoAllowed, credential paths,
 *     network, D10 trust).
 *
 * Returns the (possibly converted) decision.
 */
export async function applyDspaConversions(
  request: PermissionRequest,
  decision: Decision,
  store: Store,
  ctx: ExtensionContext,
): Promise<Decision> {
  if (decision.kind !== "auto-allow" || !isDspaActive() || !ctx.hasUI
      || judgeStatus(ctx).state !== "ok") {
    return decision;
  }
  // D3: file-write probe.
  if (request.type === "file" && request.toolName !== "read") {
    const probed = await gateDecide(request, store, ctx, { judgeWriteAutoAllows: true });
    if (probed.kind === "prompt") return probed;
  }
  // D11: bash script-payload conversion.
  if (request.type === "bash") {
    const analysis = decision.analysis;
    if (analysis && findExecutedScript(analysis, request.cwd) !== null) {
      const synthetic = synthesizeManualBashPrompt(request, store, analysis);
      if (synthetic?.kind === "prompt") return synthetic;
    }
  }
  return decision;
}
