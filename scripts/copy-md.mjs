// tsc only emits .js — copy markdown tool specs (src/services/**/*.md) into dist/.
import { cpSync, statSync } from "node:fs";

cpSync("src/services", "dist/services", {
  recursive: true,
  filter: (src) => statSync(src).isDirectory() || src.endsWith(".md"),
});
