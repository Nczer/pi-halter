/**
 * The credential accreditation at the floor (docs/dspa-credential-vouch.md).
 *
 * The operator answered a credential stop once for a directory: "the
 * credential material under here is mine to work on, this session." This module
 * is the whole policy decision — the three floor doors ask it the same question
 * and get the same answer:
 *
 *   cleared   — may this command's credential floor stop be lifted, letting the
 *               judge decide (V-e: the floor stands down, it does not approve;
 *               guard G6: an accredited stop still needs approve + risk ≤
 *               medium, or the prompt appears as it did before)?
 *   offerDir  — otherwise, the deepest common ancestor directory of the
 *               credential paths this command wanted and has not been granted
 *               yet, i.e. exactly what the prompt may offer to accredit
 *               (§4.2: no concrete dir, no offer).
 *
 * Fail closed in every uncertain case, and the uncertainty is enumerated in the
 * early returns below rather than assumed away.
 */
import path from "node:path";
import { under } from "../analysis/path-util";
import { isAccreditableCredentialPath, type CredentialFindings } from "../analysis/credentials";
import type { PromptData } from "../decide/types";
import type { Store } from "./store";

export interface CredentialGrant {
  cleared: boolean;
  offerDir: string | null;
}

const NO_GRANT: CredentialGrant = { cleared: false, offerDir: null };

/** The deepest directory every one of these paths sits under; null when they
 *  share nothing but the root (nothing nameable, so nothing to accredit). */
function commonAncestorDir(paths: string[]): string | null {
  let common: string[] | null = null;
  for (const p of paths) {
    const parts = path.dirname(p).split("/").filter(Boolean);
    if (common === null) {
      common = parts;
      continue;
    }
    let i = 0;
    while (i < common.length && i < parts.length && common[i] === parts[i]) i++;
    common = common.slice(0, i);
    if (common.length === 0) return null;
  }
  return common && common.length > 0 ? `/${common.join("/")}` : null;
}

/**
 * One credential stop, one answer.
 *
 * `findings` is what the credential scan matched (analysis/credentials.ts). A
 * door that already knows a single path — the file branch — synthesizes one
 * entry for it, so the ceiling and the fail-closed rules live here only once.
 *
 * `written` is every resolved path the command writes. A write to a credential
 * path is never covered (V-d/G2): the accreditation is a statement about
 * reading the operator's own material, and it grants no write authority — not
 * even inside the accredited dir. Such a command gets no clearance AND no
 * offer, because a grant would not have changed this command's outcome.
 */
export function credentialAccreditation(
  findings: CredentialFindings | undefined,
  store: Store,
  written: string[] = [],
): CredentialGrant {
  // Nothing nameable matched (the scan's finding is text-only — a bare-name
  // glob, a cwd symlink escape, a substitution body's operand): no clearance,
  // and no directory to offer (G4).
  if (!findings || findings.paths.length === 0) return NO_GRANT;
  if (findings.pathless.length > 0) return NO_GRANT;

  const pending: string[] = [];
  for (const f of findings.paths) {
    // V-c / G1: one name-shaped path (a store, a standalone keyfile, an env
    // file) keeps the whole stop absolute — an accreditation is not a keyring.
    if (!isAccreditableCredentialPath(f.path)) return NO_GRANT;
    if (written.some((w) => w === f.path || under(w, f.path))) return NO_GRANT;
    if (!store.isInsideAccreditedDir(f.path)) pending.push(f.path);
  }

  if (pending.length === 0) return { cleared: true, offerDir: null };
  const dir = commonAncestorDir(pending);
  return dir ? { cleared: false, offerDir: dir } : NO_GRANT;
}

/**
 * Is this operation the credential class, standing down on an accreditation?
 *
 * The judge cascade asks it (gate/fallthrough.ts): an accredited credential
 * stop has a stage-1 packet that says only "credential file", against a rule
 * that denies on that fact alone — while the operator's whole act was to say
 * the judge may rule. So stage 1 would add a call and nothing else
 * (docs/dspa-credential-vouch.md V-e).
 *
 * The floor doors do not use this: they also need `offerDir`, and the bash door
 * asks with the analysis it resolved for the decision rather than one riding on
 * the prompt data. Drift between the two is safe in one direction only: the
 * cascade either ran stage 1 for nothing, or skipped it while stage 2 — the
 * final verdict, and the only stage that sees the grants — still ruled.
 */
export function credentialClassCleared(pd: PromptData, store: Store): boolean {
  if (pd.type === "bash") {
    const a = pd.analysis;
    if (!a || !pd.credentialRule) return false;
    return credentialAccreditation(a.credentialFindings, store, [
      ...a.writePaths,
      ...a.bodyWritePaths,
    ]).cleared;
  }
  // The file branch's one path is the whole finding; a write target never
  // clears (V-d/G2) — same synthesis as the file door.
  if (pd.type === "file" && pd.warnedRule) {
    return credentialAccreditation(
      { paths: [{ path: pd.resolved, rule: pd.warnedRule }], pathless: [] },
      store,
      pd.isWriteOp ? [pd.resolved] : [],
    ).cleared;
  }
  return false;
}
