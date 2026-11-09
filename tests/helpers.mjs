// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Jeroen van de Graaf
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "./core_loader.mjs";

export const FIX = join(ROOT, "tests", "fixtures");
export const readJson = (p) => JSON.parse(readFileSync(join(FIX, p), "utf8"));
export const cert = (name) => readJson(join("certificates", name + ".json"));
export const WORLD = readJson("world.json");
export const clone = (x) => JSON.parse(JSON.stringify(x));

// deps de verifyCertificate a partir da rede simulada (o BLS é testado à parte, com a biblioteca real).
export function depsFor(world = WORLD, { unreachable = [] } = {}) {
  return {
    eth: async (n) => {
      if (unreachable.includes("eth")) throw new Error("simulado: sem rede");
      return { block: world.eth.blocks[n] || null, parent: world.eth.blocks[n - 1] || null, head: world.eth.head };
    },
    drand: async (r) => {
      if (unreachable.includes("drand")) throw new Error("simulado: sem rede");
      const b = world.drand[r]; if (!b) throw new Error("rodada não encontrada"); return { ...b };
    },
    lottery: async (g, c) => {
      if (unreachable.includes(g)) throw new Error("simulado: Caixa bloqueada");
      return world.lottery[g + "/" + c] || null;
    },
  };
}
export const statusOf = (rep) => Object.fromEntries(rep.checks.map((c) => [c.id, c.status]));
export const failing = (rep) => rep.checks.filter((c) => c.status === "falhou").map((c) => c.id).sort();
// Troca um dígito hexadecimal por outro (sempre diferente).
export const flipHex = (h, i = 10) => h.slice(0, i) + (h[i] === "0" ? "1" : "0") + h.slice(i + 1);
