import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";

export interface UserRule {
  pattern: string;
  action: "allow" | "deny";
}

export interface UserPermissions {
  bash: UserRule[];
  read: UserRule[];
  write: UserRule[];
}

let CONFIG_PATH = path.join(os.homedir(), ".config", "pi", "permissions.json");

export function setPersistencePath(newPath: string) {
  CONFIG_PATH = newPath;
}

export async function loadUserPermissions(): Promise<UserPermissions> {
  try {
    const data = await fs.readFile(CONFIG_PATH, "utf8");
    return JSON.parse(data);
  } catch (e) {
    return { bash: [], read: [], write: [] };
  }
}

export async function saveUserPermissions(permissions: UserPermissions): Promise<void> {
  try {
    await fs.mkdir(path.dirname(CONFIG_PATH), { recursive: true });
    await fs.writeFile(CONFIG_PATH, JSON.stringify(permissions, null, 2), "utf8");
  } catch (e) {
    console.error(`Failed to save permissions to ${CONFIG_PATH}:`, e);
  }
}
