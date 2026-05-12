const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BIN = path.join(__dirname, '..', 'crypt_tools.js');
const NODE = process.execPath;

function stripAnsi(value) {
  return value.replace(/\x1b\[[0-9;]*m/g, '');
}

function runCLI(args) {
  const result = spawnSync(NODE, [BIN, ...args], {
    encoding: 'utf8',
    cwd: path.join(__dirname, '..'),
    windowsHide: true,
  });

  if (result.error) {
    throw result.error;
  }

  return {
    code: result.status,
    stdout: stripAnsi(result.stdout || ''),
    stderr: stripAnsi(result.stderr || ''),
  };
}

test('smoke: node cli text roundtrip', () => {
  const enc = runCLI(['-t', 'smoke test', '-p', 'pw']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);

  const match = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
  assert.ok(match, enc.stdout);

  const dec = runCLI(['-d', '-t', match[1], '-p', 'pw']);
  assert.equal(dec.code, 0, dec.stdout + dec.stderr);
  assert.match(dec.stdout, /Decrypted:\s*smoke test/);
});
