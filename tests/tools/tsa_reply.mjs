// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
// Responde a um TimeStampReq com a TSA de TESTE (openssl ts -reply). Usado por testes e geradores.
import { readFileSync, writeFileSync, mkdtempSync, copyFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const TSA = join(dirname(fileURLToPath(import.meta.url)), "..", "fixtures", "tsa");
export function tsaReply(tsq) {
  const dir = mkdtempSync(join(tmpdir(), "tsa-"));
  for (const f of ["tsa.crt", "tsa.key"]) copyFileSync(join(TSA, f), join(dir, f));
  writeFileSync(join(dir, "serial.txt"), "01\n");
  writeFileSync(join(dir, "q.tsq"), tsq);
  execFileSync("openssl", ["ts", "-reply", "-config", join(TSA, "tsa.cnf"), "-queryfile", join(dir, "q.tsq"), "-out", join(dir, "r.tsr")], { env: { ...process.env, TSA_DIR: dir }, stdio: "ignore" });
  return readFileSync(join(dir, "r.tsr"));
}
