const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BIN = path.join(__dirname, '..', 'crypt_tools.js');
const NODE = process.execPath;

function stripAnsi(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function runCLI(args, opts = {}) {
  const result = spawnSync(NODE, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd,
    env: { ...process.env, ...opts.env },
    input: opts.input || '',
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

test('generates key file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-key-'));
    const keyPath = path.join(tmp, 'my.key');
    const res = runCLI(['--generate-keyfile', keyPath]);
    assert.equal(res.code, 0);
    assert.match(res.stdout, /Key file generated/);
    assert.ok(fs.existsSync(keyPath));
    const recoveryKey = fs.readFileSync(keyPath, 'utf8').trim();
    assert.match(recoveryKey, /^[A-Za-z0-9_-]+$/);
    assert.equal(recoveryKey.length, 22);
});

test('encrypts and decrypts text with key file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-key-'));
    const keyPath = path.join(tmp, 'my.key');
    runCLI(['--generate-keyfile', keyPath]);

    const enc = runCLI(['-t', 'secret message', '-p', 'mypass', '--keyfile', keyPath]);
    assert.equal(enc.code, 0);
    const m = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
    assert.ok(m, 'expected encrypted base64 output');
    const b64 = m[1];

    const dec = runCLI(['-d', '-t', b64, '-p', 'mypass', '--keyfile', keyPath]);
    assert.equal(dec.code, 0);
    assert.match(dec.stdout, /Decrypted:\s*secret message/);
});

test('fails to decrypt with wrong key file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-key-'));
    const key1 = path.join(tmp, 'key1.key');
    const key2 = path.join(tmp, 'key2.key');
    runCLI(['--generate-keyfile', key1]);
    runCLI(['--generate-keyfile', key2]);

    const enc = runCLI(['-t', 'secret text', '-p', 'pass', '--keyfile', key1]);
    const m = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
    const b64 = m[1];

    const dec = runCLI(['-d', '-t', b64, '-p', 'pass', '--keyfile', key2]);
    assert.equal(dec.code, 1);
    assert.match(dec.stdout + dec.stderr, /Decryption failed/);
});

test('encrypts and decrypts file with key file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-key-'));
    const keyPath = path.join(tmp, 'my.key');
    runCLI(['--generate-keyfile', keyPath]);

    const infile = path.join(tmp, 'a.txt');
    fs.writeFileSync(infile, 'file content', 'utf8');

    const enc = runCLI(['-f', infile, '-p', 'pass', '--keyfile', keyPath]);
    assert.equal(enc.code, 0);
    const encFile = path.join(tmp, 'a.txt.enc');
    assert.ok(fs.existsSync(encFile));

    const dec = runCLI(['-d', '-f', encFile, '-p', 'pass', '--keyfile', keyPath]);
    assert.equal(dec.code, 0);
    const decFile = path.join(tmp, 'a.txt.dec');
    assert.ok(fs.existsSync(decFile));
    assert.equal(fs.readFileSync(decFile, 'utf8'), 'file content');
});

test('inspects metadata of file encrypted with key file', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-key-'));
    const keyPath = path.join(tmp, 'my.key');
    runCLI(['--generate-keyfile', keyPath]);

    const infile = path.join(tmp, 'data.txt');
    fs.writeFileSync(infile, 'data', 'utf8');

    runCLI(['-f', infile, '-p', 'pass', '--keyfile', keyPath]);
    const encFile = path.join(tmp, 'data.txt.enc');

    const res = runCLI(['--inspect', '-f', encFile]);
    assert.equal(res.code, 0);
    assert.match(res.stdout, /Keyfile:\s*enabled/);
});
