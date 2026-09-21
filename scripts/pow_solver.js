"use strict";

const BE = 512;
const LT = 511;
const DR = 2;
const LR = 2654435761;
const HR = 2246822519;

function add(a, b) {
  return (a + b) >>> 0;
}

function rotl(value, bits) {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function powHash(data) {
  let e0 = 1779033703;
  let e1 = 3144134277;
  let e2 = 1013904242;
  let e3 = 2773480762;

  for (const byte of data) {
    e0 = rotl(add(e0, byte), 7);
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 16);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 12);
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 8);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 7);
  }

  for (let round = 0; round < 8; round += 1) {
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 16);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 12);
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 8);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 7);
  }

  const r = new Uint32Array(BE);
  for (let i = 0; i < BE; i += 1) {
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 16);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 12);
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 8);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 7);
    r[i] = (e0 ^ e2) >>> 0;
  }

  for (let round = 0; round < DR; round += 1) {
    for (let s = 0; s < BE; s += 1) {
      const a = r[s] & LT;
      let c = add(r[s], r[a]);
      c = rotl(c, 13);
      c = (c ^ Math.imul(r[(s + 1) & LT], LR)) >>> 0;
      r[s] = c;
      e0 = (e0 ^ c) >>> 0;
      e0 = add(e0, e1);
      e3 = rotl((e3 ^ e0) >>> 0, 16);
      e2 = add(e2, e3);
      e1 = rotl((e1 ^ e2) >>> 0, 12);
      e0 = add(e0, e1);
      e3 = rotl((e3 ^ e0) >>> 0, 8);
      e2 = add(e2, e3);
      e1 = rotl((e1 ^ e2) >>> 0, 7);
    }
  }

  const output = new Uint32Array(8);
  const blockSize = BE / 8;
  for (let i = 0; i < 8; i += 1) {
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 16);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 12);
    e0 = add(e0, e1);
    e3 = rotl((e3 ^ e0) >>> 0, 8);
    e2 = add(e2, e3);
    e1 = rotl((e1 ^ e2) >>> 0, 7);

    let value = e0;
    const start = i * blockSize;
    for (let c = 0; c < blockSize; c += 1) {
      const d = r[start + c];
      value = add(value, d);
      value = rotl(value, 5);
      value = (value ^ Math.imul(d, HR)) >>> 0;
    }
    output[i] = (value ^ e2) >>> 0;
  }
  return output;
}

function hasDifficulty(words, difficulty) {
  let bits = 0;
  for (const word of words) {
    if (word === 0) {
      bits += 32;
      continue;
    }
    return bits + Math.clz32(word) >= difficulty;
  }
  return bits >= difficulty;
}

function solve(nonce, difficulty, timeoutMs) {
  const prefix = `${nonce}:`;
  const started = Date.now();
  let counter = 0;
  while (Date.now() - started < timeoutMs) {
    if (hasDifficulty(powHash(Buffer.from(prefix + counter)), difficulty)) {
      return String(counter);
    }
    counter += 1;
  }
  return null;
}

const [, , nonce, difficultyText, timeoutText] = process.argv;
const difficulty = Number(difficultyText);
const timeoutMs = Number(timeoutText || 120000);
const solution = solve(nonce, difficulty, timeoutMs);
if (solution === null) {
  process.exitCode = 2;
} else {
  process.stdout.write(solution);
}
