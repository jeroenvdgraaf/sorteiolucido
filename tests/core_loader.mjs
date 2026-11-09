// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// Extrai o bloco CORE-BEGIN/CORE-END de SorteioLucido.html e o carrega como módulo no Node.
// Assim os testes exercitam exatamente o código que a página executa (sem passo de build).
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { pathToFileURL } from "node:url";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const HTML_PATH = join(ROOT, "SorteioLucido.html");

export function extractCore(html = readFileSync(HTML_PATH, "utf8")) {
  const b = html.indexOf("// ---------------------------------------------------------------- CORE-BEGIN");
  const e = html.indexOf("// ---------------------------------------------------------------- CORE-END");
  if (b < 0 || e < 0 || e < b) throw new Error("marcadores CORE-BEGIN/CORE-END não encontrados");
  return html.slice(b, e);
}

export async function loadCore() {
  const src = extractCore() + "\nexport default CORE;\n";
  const file = join(mkdtempSync(join(tmpdir(), "sorteiolucido-core-")), "core.mjs");
  writeFileSync(file, src);
  return (await import(pathToFileURL(file).href)).default;
}
