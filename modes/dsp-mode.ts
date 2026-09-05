// ── DSP (Dangerously Skip Permissions) state ──

let dspActive = false;

export function isDspActive(): boolean {
  return dspActive;
}

export function setDspActive(value: boolean): void {
  dspActive = value;
}
