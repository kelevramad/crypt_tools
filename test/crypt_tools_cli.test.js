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

test('errors when no args provided', () => {
  const res = runCLI([]);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Either --text or --file is required/);
});

test('encrypts and decrypts text', () => {
  const enc = runCLI(['-t', 'hello', '-p', 'pw']);
  assert.equal(enc.code, 0);
  const m = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
  assert.ok(m, 'expected encrypted base64 output');
  const b64 = m[1];

  const dec = runCLI(['-d', '-t', b64, '-p', 'pw']);
  assert.equal(dec.code, 0);
  assert.match(dec.stdout, /Decrypted:\s*hello/);
});
test('decrypts text with wrong password fails', () => {
  const enc = runCLI(['-t', 'hello', '-p', 'pw']);
  assert.equal(enc.code, 0);
  const m = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
  assert.ok(m, 'expected encrypted base64 output');
  const b64 = m[1];

  const dec = runCLI(['-d', '-t', b64, '-p', 'wrong']);
  assert.equal(dec.code, 1);
  assert.match(dec.stdout + dec.stderr, /Decryption failed/);
});
test('decrypts text with invalid base64 fails', () => {
  const dec = runCLI(['-d', '-t', '!!!notbase64!!!', '-p', 'pw']);
  assert.equal(dec.code, 1);
  assert.match(dec.stdout + dec.stderr, /Decryption failed/);
});

test('encrypts and decrypts file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(enc.code, 0);
  const encFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'pw']);
  assert.equal(dec.code, 0);
  const decFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'content');
});
test('file not found exits with error', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'missing.txt');
  const res = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /File not found/);
});

test('decrypt file with wrong password does not create output', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(enc.code, 0);
  const encFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'wrong']);
  assert.equal(dec.code, 1);
  const decFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.dec');
  assert.ok(!fs.existsSync(decFile));
});
test('decrypt file too small fails', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'tiny.enc');
  fs.writeFileSync(infile, Buffer.alloc(10));

  const dec = runCLI(['-d', '-f', infile, '-p', 'pw']);
  assert.match(dec.stdout + dec.stderr, /File too small/);
  const decFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.dec');
  assert.ok(!fs.existsSync(decFile));
});

test('wildcard no match exits with error', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const res = runCLI(['-f', '*.nomatch', '-p', 'pw'], { cwd: tmp });
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /No files matched pattern/);
});

test('wildcard in base dir yields no match', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const sub = path.join(tmp, 'sub1');
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(sub, 'a.txt'), 'a', 'utf8');

  const pattern = path.join(tmp, 'sub*', '*.txt');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /No files matched pattern/);
});
test('single-match wildcard logs processing file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'one.txt');
  fs.writeFileSync(infile, 'one', 'utf8');

  const pattern = path.join(tmp, '*.txt');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 0);
  assert.match(res.stdout + res.stderr, /Processing file: .*one\.txt/);
});

test('wildcard supports character class and question mark', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  fs.writeFileSync(path.join(tmp, 'a1.tx'), 'a1', 'utf8');
  fs.writeFileSync(path.join(tmp, 'a2.tt'), 'a2', 'utf8');
  fs.writeFileSync(path.join(tmp, 'b1.tx'), 'b1', 'utf8');

  const pattern = path.join(tmp, 'a?.t[xt]');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'a1.enc')));
  assert.ok(fs.existsSync(path.join(tmp, 'a2.enc')));
  assert.ok(!fs.existsSync(path.join(tmp, 'b1.enc')));
});

test('wildcard skips file paths with brackets', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  fs.writeFileSync(path.join(tmp, 'a[1].txt'), 'a', 'utf8');
  fs.writeFileSync(path.join(tmp, 'b.txt'), 'b', 'utf8');

  const pattern = path.join(tmp, '*.txt');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 0);
  assert.ok(!fs.existsSync(path.join(tmp, 'a[1].enc')));
  assert.ok(fs.existsSync(path.join(tmp, 'b.enc')));
});

test('wildcard on missing directory reports unexpected error', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const missingDir = path.join(tmp, 'missing');
  const pattern = path.join(missingDir, '*.txt');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Unexpected error/);
});




test('non-recursive wildcard processes multiple files', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  fs.writeFileSync(path.join(tmp, 'a.txt'), 'a', 'utf8');
  fs.writeFileSync(path.join(tmp, 'b.txt'), 'b', 'utf8');

  const pattern = path.join(tmp, '*.txt');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'a.enc')));
  assert.ok(fs.existsSync(path.join(tmp, 'b.enc')));
});
test('compress flag produces smaller encrypted file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'big.txt');
  fs.writeFileSync(infile, 'A'.repeat(20000), 'utf8');

  const encNoComp = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(encNoComp.code, 0);
  const encNoCompFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.enc');
  const sizeNoComp = fs.statSync(encNoCompFile).size;

  const encComp = runCLI(['-f', infile, '-p', 'pw', '-c']);
  assert.equal(encComp.code, 0);
  const encCompFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.enc');
  const sizeComp = fs.statSync(encCompFile).size;

  assert.ok(sizeComp < sizeNoComp);
});
test('compress flag decrypts back original file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'A'.repeat(5000), 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw', '-c']);
  assert.equal(enc.code, 0);
  const encFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'pw', '-c']);
  assert.equal(dec.code, 0);
  const decFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'A'.repeat(5000));
});
test('non-recursive decrypt exits 1 when any file fails', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const good = path.join(tmp, 'good.txt');
  fs.writeFileSync(good, 'ok', 'utf8');

  const enc = runCLI(['-f', good, '-p', 'pw']);
  assert.equal(enc.code, 0);

  const badEnc = path.join(tmp, 'bad.enc');
  fs.writeFileSync(badEnc, Buffer.alloc(10));

  const pattern = path.join(tmp, '*.enc');
  const dec = runCLI(['-d', '-f', pattern, '-p', 'pw']);
  assert.equal(dec.code, 1);
  assert.match(dec.stdout + dec.stderr, /Failed to decrypt|File too small/);
});

test('recursive encrypt/decrypt for directory', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const sub = path.join(tmp, 'sub');
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(tmp, 'a.txt'), 'a', 'utf8');
  fs.writeFileSync(path.join(sub, 'b.txt'), 'b', 'utf8');

  const enc = runCLI(['-r', '-f', tmp, '-p', 'pw']);
  assert.equal(enc.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'a.txt.enc')));
  assert.ok(fs.existsSync(path.join(sub, 'b.txt.enc')));

  const dec = runCLI(['-r', '-d', '-f', tmp, '-p', 'pw']);
  assert.equal(dec.code, 0);
  assert.equal(fs.readFileSync(path.join(tmp, 'a.txt'), 'utf8'), 'a');
  assert.equal(fs.readFileSync(path.join(sub, 'b.txt'), 'utf8'), 'b');
});
test('recursive decrypt uses .dec for files without extension', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'secret');
  fs.writeFileSync(infile, 'secret', 'utf8');

  const enc = runCLI(['-r', '-f', tmp, '-p', 'pw']);
  assert.equal(enc.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'secret.enc')));

  const dec = runCLI(['-r', '-d', '-f', tmp, '-p', 'pw']);
  assert.equal(dec.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'secret.enc.dec')));
});
test('recursive decrypt reports failures but continues', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const good = path.join(tmp, 'good.txt');
  fs.writeFileSync(good, 'ok', 'utf8');

  const enc = runCLI(['-f', good, '-p', 'pw']);
  assert.equal(enc.code, 0);

  const badEnc = path.join(tmp, 'bad.enc');
  fs.writeFileSync(badEnc, Buffer.alloc(10));

  const dec = runCLI(['-r', '-d', '-f', tmp, '-p', 'pw']);
  assert.equal(dec.code, 0);
  assert.match(dec.stdout + dec.stderr, /Some files failed/);
});
test('output flag ignored for recursive directory', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const sub = path.join(tmp, 'sub');
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(tmp, 'a.txt'), 'a', 'utf8');
  fs.writeFileSync(path.join(sub, 'b.txt'), 'b', 'utf8');

  const out = path.join(tmp, 'out.bin');
  const enc = runCLI(['-r', '-f', tmp, '-o', out, '-p', 'pw']);
  assert.equal(enc.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'a.txt.enc')));
  assert.ok(fs.existsSync(path.join(sub, 'b.txt.enc')));
  assert.ok(!fs.existsSync(out));
});

test('log flag creates crypt_tools.log', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');

  const res = runCLI(['-f', infile, '-p', 'pw', '--log'], { cwd: tmp });
  assert.equal(res.code, 0);
  assert.ok(fs.existsSync(path.join(tmp, 'crypt_tools.log')));
});

test('debug flag prints debug enabled', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');

  const res = runCLI(['-f', infile, '-p', 'pw', '--debug']);
  assert.equal(res.code, 0);
  assert.match(res.stdout + res.stderr, /Debug mode: Enabled/);
});

test('recursive wildcard expands and encrypts', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const sub = path.join(tmp, 'sub');
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(tmp, 'a.txt'), 'a', 'utf8');
  fs.writeFileSync(path.join(sub, 'b.txt'), 'b', 'utf8');

  const pattern = path.join(tmp, '*.txt');
  const res = runCLI(['-r', '-f', pattern, '-p', 'pw']);
  if (res.code !== 0) {
    throw new Error(`exit ${res.code}: ${res.stdout} ${res.stderr}`);
  }
  assert.ok(fs.existsSync(path.join(tmp, 'a.enc')));
  assert.ok(fs.existsSync(path.join(sub, 'b.enc')));
});

test('output flag writes to custom path', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  const outfile = path.join(tmp, 'custom.out');
  fs.writeFileSync(infile, 'content', 'utf8');

  const res = runCLI(['-f', infile, '-o', outfile, '-p', 'pw']);
  assert.equal(res.code, 0);
  assert.ok(fs.existsSync(outfile));
});
test('output flag works for decrypt', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(enc.code, 0);
  const encFile = path.join(path.dirname(infile), path.basename(infile, path.extname(infile)) + '.enc');

  const decOut = path.join(tmp, 'out.txt');
  const dec = runCLI(['-d', '-f', encFile, '-o', decOut, '-p', 'pw']);
  assert.equal(dec.code, 0);
  assert.ok(fs.existsSync(decOut));
  assert.equal(fs.readFileSync(decOut, 'utf8'), 'content');
});

test('directory without -r exits with error', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const res = runCLI(['-f', tmp, '-p', 'pw']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Use -r\/--recursive/);
});






















