import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  Editor,
  type EditorTheme,
  Key,
  matchesKey,
  truncateToWidth,
  wrapTextWithAnsi,
} from "@earendil-works/pi-tui";

interface Theme {
  fg(color: string, text: string): string;
}

/**
 * Create an editor theme matching the selection UI.
 */
function createEditorTheme(theme: Theme): EditorTheme {
  return {
    borderColor: (s) => theme.fg("accent", s),
    selectList: {
      selectedPrefix: (t) => theme.fg("accent", t),
      selectedText: (t) => theme.fg("accent", t),
      description: (t) => theme.fg("muted", t),
      scrollInfo: (t) => theme.fg("dim", t),
      noMatch: (t) => theme.fg("warning", t),
    },
  };
}

/**
 * Add wrapped text lines to an array, respecting width and indent.
 */
function addWrapped(lines: string[], text: string, width: number, indent = ""): void {
  const contentWidth = Math.max(1, width - indent.length);
  for (const line of wrapTextWithAnsi(text, contentWidth)) {
    lines.push(truncateToWidth(`${indent}${line}`, width));
  }
}

/**
 * Show a selection prompt with cyclic navigation (up from first wraps to last, down from last wraps to first).
 *
 * Returns the selected choice or null if cancelled.
 */
export async function showSelectIndex(
  ctx: ExtensionContext,
  title: string,
  choices: string[],
): Promise<number | null> {
  return ctx.ui.custom<number | null>((tui, theme, _kb, done) => {
    let selectedIndex = 0;
    let cachedLines: string[] | undefined;

    function refresh() {
      cachedLines = undefined;
      tui.requestRender();
    }

    function handleInput(data: string) {
      if (matchesKey(data, Key.up)) {
        selectedIndex = (selectedIndex - 1 + choices.length) % choices.length;
        refresh();
        return;
      }
      if (matchesKey(data, Key.down)) {
        selectedIndex = (selectedIndex + 1) % choices.length;
        refresh();
        return;
      }
      if (matchesKey(data, Key.enter)) {
        done(selectedIndex);
        return;
      }
      if (matchesKey(data, Key.escape)) {
        done(null);
      }
    }

    function render(width: number): string[] {
      if (cachedLines) return cachedLines;

      const lines: string[] = [];
      const add = (text: string) => lines.push(truncateToWidth(text, width));

      add(theme.fg("accent", "─".repeat(width)));
      addWrapped(lines, theme.fg("text", ` ${title}`), width);
      lines.push("");

      for (let i = 0; i < choices.length; i++) {
        const selected = i === selectedIndex;
        const prefix = selected ? theme.fg("accent", "> ") : "  ";
        const label = selected ? theme.fg("accent", choices[i]) : theme.fg("text", choices[i]);
        add(`${prefix}${label}`);
      }

      lines.push("");
      add(theme.fg("dim", " ↑↓ navigate (cyclic) • Enter select • Esc cancel"));
      add(theme.fg("accent", "─".repeat(width)));
      cachedLines = lines;
      return lines;
    }

    return {
      render,
      invalidate: () => { cachedLines = undefined; },
      handleInput,
    };
  });
}

/**
 * Show a text editor prompt for entering a reason.
 *
 * Returns the entered text or null if cancelled.
 */
export async function showReasonEditor(
  ctx: ExtensionContext,
  title: string,
): Promise<string | null> {
  return ctx.ui.custom<string | null>((tui, theme, _kb, done) => {
    let cachedLines: string[] | undefined;
    // pi-coding-agent bundles its own copy of pi-tui, so the TUI instance passed to
    // ctx.ui.custom() is a structurally-identical but nominally-different type than
    // the one Editor's constructor expects (private-field clash). Safe to cast: same API.
    const editor = new Editor(tui as unknown as ConstructorParameters<typeof Editor>[0], createEditorTheme(theme));

    editor.onSubmit = (value) => {
      const trimmed = value.trim();
      done(trimmed || null);
    };

    function refresh() {
      cachedLines = undefined;
      tui.requestRender();
    }

    function handleInput(data: string) {
      if (matchesKey(data, Key.escape)) {
        done(null);
        return;
      }
      editor.handleInput(data);
      refresh();
    }

    function render(width: number): string[] {
      if (cachedLines) return cachedLines;

      const lines: string[] = [];
      const add = (text: string) => lines.push(truncateToWidth(text, width));

      add(theme.fg("accent", "─".repeat(width)));
      addWrapped(lines, theme.fg("text", ` ${title}`), width);
      lines.push("");

      for (const line of editor.render(Math.max(1, width - 2))) {
        add(` ${line}`);
      }

      lines.push("");
      add(theme.fg("dim", " Enter to submit • Esc cancel"));
      add(theme.fg("accent", "─".repeat(width)));
      cachedLines = lines;
      return lines;
    }

    return {
      render,
      invalidate: () => {
        cachedLines = undefined;
        editor.invalidate();
      },
      handleInput,
    };
  });
}
