const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const BIN = path.join(__dirname, '..', 'crypt_tools.js');
const NODE = process.execPath;
const cryptTools = require('../crypt_tools.js');

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

test('loads config defaults for password and kdf', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-config-'));
  const configPath = path.join(tmp, '.crypt_tools.json');
  fs.writeFileSync(configPath, JSON.stringify({
    password: 'config-pass',
    kdf: 'argon2',
    iterations: 3,
  }), 'utf8');

  const res = runCLI(['-t', 'hello'], { cwd: tmp, env: { HOME: tmp, USERPROFILE: tmp } });
  assert.equal(res.code, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /Config file:/);
  assert.match(res.stdout, /KDF: argon2 \(3 iterations\)/);
  assert.match(res.stdout, /Encrypted \(Base64\):/);
});

test('uses password from CRYPT_TOOLS_PASSWORD', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-env-'));
  const res = runCLI(['-t', 'hello'], {
    cwd: tmp,
    env: {
      HOME: tmp,
      USERPROFILE: tmp,
      CRYPT_TOOLS_PASSWORD: 'env-pass',
    },
  });

  assert.equal(res.code, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /Encrypted \(Base64\):/);
});

test('encrypt text with --qr prints a QR code', () => {
  const res = runCLI(['-t', 'hello', '-p', 'pw', '--qr']);
  assert.equal(res.code, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /Encrypted \(Base64\):/);
  assert.match(res.stdout, /QR Code Output:/);
});

test('--qr rejects decrypt mode', () => {
  const res = runCLI(['-d', '-t', 'hello', '-p', 'pw', '--qr']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /--qr is only supported with text encryption/);
});

test('--select requires an interactive terminal', () => {
  const res = runCLI(['--encrypt', '--select', '-p', 'pw']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Interactive file selection requires an interactive terminal/);
});

test('renderQrCode helper returns rendered output', async () => {
  let printed = '';
  const originalWrite = process.stdout.write;
  process.stdout.write = (chunk, encoding, callback) => {
    printed += String(chunk);
    if (typeof encoding === 'function') encoding();
    if (typeof callback === 'function') callback();
    return true;
  };

  try {
    const qr = await cryptTools.UIHelpers.renderQrCode('hello');
    assert.ok(qr.length > 0);
    assert.match(printed, /QR Code Output:/);
  } finally {
    process.stdout.write = originalWrite;
  }
});

test('rejects multiple passwords without threshold', () => {
  const res = runCLI(['-t', 'hello', '-p', 'pass1', '-p', 'pass2']);
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /Multiple -p\/--password values require --threshold/);
});

test('allows multiple passwords without threshold in decrypt mode', () => {
  const res = runCLI(['-d', '-t', '!!!notbase64!!!', '-p', 'pass1', '-p', 'pass2']);
  assert.equal(res.code, 1);
  assert.doesNotMatch(res.stdout + res.stderr, /Multiple -p\/--password values require --threshold/);
});

test('threshold text encrypt/decrypt roundtrip with 2 of 3 passwords', () => {
  const enc = runCLI(['-t', 'text threshold roundtrip', '-p', 'alpha', '-p', 'beta', '-p', 'gamma', '--threshold', '2']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);
  const m = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
  assert.ok(m, 'expected base64 output');
  const b64 = m[1];

  const dec = runCLI(['-d', '-t', b64, '-p', 'alpha', '-p', 'gamma']);
  assert.equal(dec.code, 0, dec.stdout + dec.stderr);
  assert.match(dec.stdout, /Threshold encrypted text: 3 passwords, 2 required to decrypt/);
  assert.match(dec.stdout, /Decrypted:\s*text threshold roundtrip/);
});

test('threshold text decrypt fails when fewer than threshold passwords are valid', () => {
  const enc = runCLI(['-t', 'text threshold fail', '-p', 'alpha', '-p', 'beta', '-p', 'gamma', '--threshold', '2']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);
  const b64 = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/)[1];

  const dec = runCLI(['-d', '-t', b64, '-p', 'alpha', '-p', 'WRONG', '-p', 'ALSOWRONG']);
  assert.equal(dec.code, 1);
  assert.match(dec.stdout + dec.stderr, /Not enough valid passwords provided\. Need 2, got 1/);
});

test('threshold decrypt accepts repeated password when distinct shares use the same secret', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-threshold-dup-'));
  const infile = path.join(tmp, 'README.md');
  fs.writeFileSync(infile, 'threshold duplicate password content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', '1', '-p', '1', '-p', '1', '--threshold', '2']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);

  const encFile = infile + '.enc';
  const dec = runCLI(['-d', '-f', encFile, '-p', '1', '-p', '1']);
  assert.equal(dec.code, 0, dec.stdout + dec.stderr);

  const decFile = path.join(tmp, 'README.md.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'threshold duplicate password content');
});

test('threshold decrypt without -p prompts for the required number of passwords', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-threshold-prompt-'));
  const infile = path.join(tmp, 'README.md');
  fs.writeFileSync(infile, 'threshold prompt content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'alpha', '-p', 'beta', '-p', 'gamma', '--threshold', '2']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);

  const encFile = infile + '.enc';
  const dec = runCLI(['-d', '-f', encFile], { input: 'alpha\nbeta\n' });
  assert.equal(dec.code, 0, dec.stdout + dec.stderr);
  assert.match(dec.stdout, /Threshold-encrypted file detected: 2 password\(s\) required/);
  assert.match(dec.stdout, /Enter password 1\/2:/);
  assert.match(dec.stdout, /Enter password 2\/2:/);

  const decFile = path.join(tmp, 'README.md.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'threshold prompt content');
});

test('threshold decrypt auto-detects compression from the file header', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-threshold-compress-'));
  const infile = path.join(tmp, 'README.md');
  fs.writeFileSync(infile, 'A'.repeat(5000), 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'alpha', '-p', 'beta', '-p', 'gamma', '--threshold', '2', '-c']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);

  const encFile = infile + '.enc';
  const dec = runCLI(['-d', '-f', encFile, '-p', 'alpha', '-p', 'beta']);
  assert.equal(dec.code, 0, dec.stdout + dec.stderr);

  const decFile = path.join(tmp, 'README.md.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'A'.repeat(5000));
});

test('decrypt banner reports compression from the file header', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-banner-compress-'));
  const infile = path.join(tmp, 'README.md');
  fs.writeFileSync(infile, 'A'.repeat(5000), 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw', '-c']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);

  const encFile = infile + '.enc';
  const dec = runCLI(['-d', '-f', encFile, '-p', 'wrong']);
  assert.equal(dec.code, 1);
  assert.match(dec.stdout, /Compression: enabled/);
});

test('encrypts and decrypts file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(enc.code, 0);
  const encFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'pw']);
  assert.equal(enc.code, 0);
  const decFile = path.join(path.dirname(infile), path.basename(infile) + '.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'content');
});

test('encrypts hidden container and decrypts outer and inner', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-hv-'));
  const decoy = path.join(tmp, 'decoy.txt');
  const secret = path.join(tmp, 'secret.bin');
  fs.writeFileSync(decoy, 'benign', 'utf8');
  fs.writeFileSync(secret, 'topsecret', 'utf8');

  const enc = runCLI([
    '-f', decoy,
    '--hidden-vol',
    '--hidden-file', secret,
    '--password-outer', 'outerpw',
    '--password-hidden', 'hiddenpw',
  ]);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);
  const container = decoy + '.enc';
  assert.ok(fs.existsSync(container), 'container should exist');

  const outDecoy = path.join(tmp, 'out_decoy.txt');
  const d1 = runCLI(['-d', '-f', container, '-p', 'outerpw', '-o', outDecoy]);
  assert.equal(d1.code, 0, d1.stdout + d1.stderr);
  assert.equal(fs.readFileSync(outDecoy, 'utf8'), 'benign');

  const outSecret = path.join(tmp, 'out_secret.bin');
  const d2 = runCLI(['-d', '--hidden', '-f', container, '-p', 'hiddenpw', '-o', outSecret]);
  assert.equal(d2.code, 0, d2.stdout + d2.stderr);
  assert.equal(fs.readFileSync(outSecret, 'utf8'), 'topsecret');
});

test('inspect reports hidden container', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-hv-inspect-'));
  const decoy = path.join(tmp, 'decoy.txt');
  const secret = path.join(tmp, 'secret.bin');
  fs.writeFileSync(decoy, 'x', 'utf8');
  fs.writeFileSync(secret, 'y', 'utf8');
  const enc = runCLI([
    '-f', decoy,
    '--hidden-vol',
    '--hidden-file', secret,
    '--password-outer', 'a',
    '--password-hidden', 'b',
  ]);
  assert.equal(enc.code, 0);
  const container = decoy + '.enc';
  const ins = runCLI(['--inspect', '-f', container]);
  assert.equal(ins.code, 0);
  const out = ins.stdout + ins.stderr;
  assert.match(out, /hidden/i);
  assert.match(out, /Outer blob size/i);
  assert.match(out, /Hidden blob metadata/i);
  assert.match(out, /Inner compression:/i);
});

test('inspect reports threshold metadata', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-threshold-inspect-'));
  const infile = path.join(tmp, 'README.md');
  fs.writeFileSync(infile, 'threshold inspect content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'alpha', '-p', 'beta', '-p', 'gamma', '--threshold', '2', '-c']);
  assert.equal(enc.code, 0, enc.stdout + enc.stderr);

  const ins = runCLI(['--inspect', '-f', infile + '.enc']);
  assert.equal(ins.code, 0, ins.stdout + ins.stderr);
  const out = ins.stdout + ins.stderr;
  assert.match(out, /Threshold mode: enabled/);
  assert.match(out, /Shares: 3/);
  assert.match(out, /Threshold required: 2/);
  assert.match(out, /Compression: enabled/);
});

test('--hidden on standard encrypt file fails', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-h-std-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'content', 'utf8');
  const enc = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(enc.code, 0);
  const encFile = infile + '.enc';
  const dec = runCLI(['-d', '--hidden', '-f', encFile, '-p', 'pw']);
  assert.equal(dec.code, 1);
  assert.match(dec.stdout + dec.stderr, /CTHV|hidden-volume/i);
});

test('hidden-vol rejects wildcards', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-hv-wc-'));
  fs.writeFileSync(path.join(tmp, 'a.txt'), 'a', 'utf8');
  const res = runCLI([
    '-f', path.join(tmp, '*.txt'),
    '--hidden-vol',
    '--hidden-file', path.join(tmp, 'a.txt'),
    '--password-outer', 'o',
    '--password-hidden', 'h',
  ], { cwd: tmp });
  assert.equal(res.code, 1);
  assert.match(res.stdout + res.stderr, /single decoy/i);
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
  const encFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'wrong']);
  assert.equal(dec.code, 1);
  const decFile = path.join(path.dirname(infile), path.basename(infile) + '.dec');
  assert.ok(!fs.existsSync(decFile));
  assert.match(dec.stdout, /Decryption failed for:/);
  assert.doesNotMatch(dec.stdout, /\[❌\] Decryption failed\s*$/m);
  assert.match(dec.stdout, /Session ended at /);
});

test('missing keyfile avoids duplicate read error line', () => {
  const res = runCLI(['--encrypt', '-t', 'hello', '-p', 'pw', '--keyfile', '.\\missing-key.txt']);
  assert.equal(res.code, 1);
  assert.match(res.stdout, /Failed to read key file: Key file not found:/);
  assert.doesNotMatch(res.stdout, /\[❌\] Failed to read key file\s*$/m);
  assert.match(res.stdout, /Operation aborted: Could not load key file/);
  assert.match(res.stdout, /Session ended at /);
});

test('decrypt without required keyfile still shows session end', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-key-required-'));

  try {
    const keyPath = path.join(tmp, 'key.txt');
    const infile = path.join(tmp, 'plain.txt');
    fs.writeFileSync(infile, 'needs keyfile', 'utf8');

    let res = runCLI(['--generate-keyfile', keyPath], { cwd: tmp });
    assert.equal(res.code, 0);

    res = runCLI(['-f', infile, '-p', 'pw', '--keyfile', keyPath], { cwd: tmp });
    assert.equal(res.code, 0, res.stdout + res.stderr);

    const dec = runCLI(['-d', '-f', infile + '.enc', '-p', 'pw'], { cwd: tmp });
    assert.equal(dec.code, 1);
    assert.match(dec.stdout, /Encrypted with key file but none provided/);
    assert.match(dec.stdout, /Decryption failed for:/);
    assert.match(dec.stdout, /Session ended at /);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
test('decrypt file too small fails', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'tiny.enc');
  fs.writeFileSync(infile, Buffer.alloc(10));

  const dec = runCLI(['-d', '-f', infile, '-p', 'pw']);
  assert.match(dec.stdout + dec.stderr, /File too small/);
  const decFile = path.join(path.dirname(infile), path.basename(infile) + '.dec');
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
  assert.ok(fs.existsSync(path.join(tmp, 'a1.tx.enc')));
  assert.ok(fs.existsSync(path.join(tmp, 'a2.tt.enc')));
  assert.ok(!fs.existsSync(path.join(tmp, 'b1.tx.enc')));
});

test('wildcard skips file paths with brackets', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  fs.writeFileSync(path.join(tmp, 'a[1].txt'), 'a', 'utf8');
  fs.writeFileSync(path.join(tmp, 'b.txt'), 'b', 'utf8');

  const pattern = path.join(tmp, '*.txt');
  const res = runCLI(['-f', pattern, '-p', 'pw']);
  assert.equal(res.code, 0);
  assert.ok(!fs.existsSync(path.join(tmp, 'a[1].txt.enc')));
  assert.ok(fs.existsSync(path.join(tmp, 'b.txt.enc')));
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
  assert.ok(fs.existsSync(path.join(tmp, 'a.txt.enc')));
  assert.ok(fs.existsSync(path.join(tmp, 'b.txt.enc')));
});
test('compress flag produces smaller encrypted file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'big.txt');
  fs.writeFileSync(infile, 'A'.repeat(20000), 'utf8');

  const encNoComp = runCLI(['-f', infile, '-p', 'pw']);
  assert.equal(encNoComp.code, 0);
  const encNoCompFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');
  const sizeNoComp = fs.statSync(encNoCompFile).size;

  const encComp = runCLI(['-f', infile, '-p', 'pw', '-c']);
  assert.equal(encComp.code, 0);
  const encCompFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');
  const sizeComp = fs.statSync(encCompFile).size;

  assert.ok(sizeComp < sizeNoComp);
});
test('compress flag decrypts back original file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'A'.repeat(5000), 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw', '-c']);
  assert.equal(enc.code, 0);
  const encFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'pw', '-c']);
  assert.equal(dec.code, 0);
  const decFile = path.join(path.dirname(infile), path.basename(infile) + '.dec');
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
  assert.ok(fs.existsSync(path.join(tmp, 'secret')), 'decrypted file should be named "secret" (original name restored)');
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
  assert.ok(fs.existsSync(path.join(tmp, 'a.txt.enc')));
  assert.ok(fs.existsSync(path.join(sub, 'b.txt.enc')));
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
  const encFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');

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

test('generate-keyfile creates key file', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));
  const keyfilePath = path.join(tmpDir, 'test_key.txt');

  const result = runCLI(['--generate-keyfile', keyfilePath], { cwd: tmpDir });

  try {
    assert.strictEqual(result.code, 0, 'should exit with code 0');
    assert.ok(fs.existsSync(keyfilePath), 'key file should exist');
    const recoveryKey = fs.readFileSync(keyfilePath, 'utf8').trim();
    assert.match(recoveryKey, /^[A-Za-z0-9_-]+$/);
    assert.strictEqual(recoveryKey.length, 22, 'recovery key should be 22 chars for 16 bytes');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('generate-keyfile uses default name key.txt when no path provided', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));
  const defaultKeyfilePath = path.join(tmpDir, 'key.txt');

  try {
    const result = runCLI(['--generate-keyfile'], { cwd: tmpDir });
    assert.strictEqual(result.code, 0, 'should exit with code 0');
    assert.ok(fs.existsSync(defaultKeyfilePath), 'key.txt should exist in cwd');
    const recoveryKey = fs.readFileSync(defaultKeyfilePath, 'utf8').trim();
    assert.match(recoveryKey, /^[A-Za-z0-9_-]+$/);
    assert.strictEqual(recoveryKey.length, 22, 'recovery key should be 22 chars for 16 bytes');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('encrypts and decrypts file with keyfile', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));

  try {
    // Generate keyfile (relative path)
    let res = runCLI(['--generate-keyfile', 'key.bin'], { cwd: tmpDir });
    assert.strictEqual(res.code, 0);

    // Create input file
    fs.writeFileSync(path.join(tmpDir, 'plain.txt'), 'Secret message for keyfile test');

    // Encrypt with keyfile (relative paths)
    res = runCLI([
      '--encrypt',
      '-f', 'plain.txt',
      '--keyfile', 'key.bin',
      '-p', 'testpassword',
    ], { cwd: tmpDir });

    assert.strictEqual(res.code, 0, 'encryption should succeed: ' + res.stderr);
    assert.ok(fs.existsSync(path.join(tmpDir, 'plain.txt.enc')), 'encrypted file should exist');

    // Decrypt with keyfile
    res = runCLI([
      '--decrypt',
      '-f', 'plain.txt.enc',
      '--keyfile', 'key.bin',
      '-p', 'testpassword',
    ], { cwd: tmpDir });

    assert.strictEqual(res.code, 0, 'decryption should succeed: ' + res.stderr);
    assert.ok(fs.existsSync(path.join(tmpDir, 'plain.txt.dec')), 'decrypted file should exist');
    assert.strictEqual(
      fs.readFileSync(path.join(tmpDir, 'plain.txt.dec'), 'utf8'),
      'Secret message for keyfile test'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('encrypts file with keyfile only (no password)', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));

  try {
    // Generate keyfile
    runCLI(['--generate-keyfile', 'key.bin'], { cwd: tmpDir });

    // Create input file
    fs.writeFileSync(path.join(tmpDir, 'plain.txt'), 'Message with keyfile only');

    // Encrypt with keyfile only (empty password)
    let res = runCLI([
      '--encrypt',
      '-f', 'plain.txt',
      '--keyfile', 'key.bin',
      '-p', '',
    ], { cwd: tmpDir });

    assert.strictEqual(res.code, 0, 'encryption should succeed: ' + res.stderr);

    // Decrypt with keyfile only
    res = runCLI([
      '--decrypt',
      '-f', 'plain.txt.enc',
      '--keyfile', 'key.bin',
      '-p', '',
    ], { cwd: tmpDir });

    assert.strictEqual(res.code, 0, 'decryption should succeed: ' + res.stderr);
    assert.strictEqual(
      fs.readFileSync(path.join(tmpDir, 'plain.txt.dec'), 'utf8'),
      'Message with keyfile only'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('inspect shows keyfile enabled', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));

  try {
    // Generate keyfile
    runCLI(['--generate-keyfile', 'key.bin'], { cwd: tmpDir });

    // Create and encrypt file
    fs.writeFileSync(path.join(tmpDir, 'plain.txt'), 'Test content');
    runCLI([
      '--encrypt',
      '-f', 'plain.txt',
      '--keyfile', 'key.bin',
      '-p', 'testpass',
    ], { cwd: tmpDir });

    // Inspect the file
    const inspectResult = runCLI(['--inspect', '-f', 'plain.txt.enc'], { cwd: tmpDir });

    assert.strictEqual(inspectResult.code, 0, 'inspect should succeed: ' + inspectResult.stderr);
    assert.ok(inspectResult.stdout.includes('Keyfile: enabled'), 'should show keyfile enabled');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('encrypts text with argon2', () => {
  const enc = runCLI(['-t', 'hello', '-p', 'pw', '--kdf', 'argon2', '--iterations', '3']);
  assert.equal(enc.code, 0, 'argon2 encrypt should succeed: ' + enc.stderr);
  assert.match(enc.stdout, /KDF: argon2 \(3 iterations\)/);
  const m = enc.stdout.match(/Encrypted \(Base64\):\s*([A-Za-z0-9+/=]+)/);
  assert.ok(m, 'expected encrypted base64 output');
  const b64 = m[1];

  const dec = runCLI(['-d', '-t', b64, '-p', 'pw']);
  assert.equal(dec.code, 0);
  assert.match(dec.stdout, /Decrypted:\s*hello/);
});

test('encrypts and decrypts file with argon2', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-'));
  const infile = path.join(tmp, 'a.txt');
  fs.writeFileSync(infile, 'argon2 content', 'utf8');

  const enc = runCLI(['-f', infile, '-p', 'pw', '--kdf', 'argon2', '--iterations', '3']);
  assert.equal(enc.code, 0, 'argon2 encrypt should succeed: ' + enc.stderr);
  assert.match(enc.stdout, /KDF: argon2 \(3 iterations\)/);
  const encFile = path.join(path.dirname(infile), path.basename(infile) + '.enc');
  assert.ok(fs.existsSync(encFile));

  const dec = runCLI(['-d', '-f', encFile, '-p', 'pw']);
  assert.equal(dec.code, 0);
  const decFile = path.join(path.dirname(infile), path.basename(infile) + '.dec');
  assert.ok(fs.existsSync(decFile));
  assert.equal(fs.readFileSync(decFile, 'utf8'), 'argon2 content');
});

test('default kdf is pbkdf2', () => {
  const enc = runCLI(['-t', 'hello', '-p', 'pw']);
  assert.equal(enc.code, 0);
  assert.match(enc.stdout, /KDF: pbkdf2 \(100000 iterations\)/);
});

test('inspect shows argon2 kdf', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));

  try {
    fs.writeFileSync(path.join(tmpDir, 'argon2.txt'), 'test content');
    runCLI([
      '--encrypt',
      '-f', 'argon2.txt',
      '-p', 'testpass',
      '--kdf', 'argon2',
      '--iterations', '3',
    ], { cwd: tmpDir });

    const inspectResult = runCLI(['--inspect', '-f', 'argon2.txt.enc'], { cwd: tmpDir });
    assert.strictEqual(inspectResult.code, 0, 'inspect should succeed: ' + inspectResult.stderr);
    assert.ok(inspectResult.stdout.includes('KDF: Argon2id'), 'should show Argon2id');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('shred securely deletes file', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));

  try {
    const testFile = path.join(tmpDir, 'sensitive.txt');
    fs.writeFileSync(testFile, Buffer.alloc(1024));

    assert.ok(fs.existsSync(testFile), 'file should exist before shred');

    const result = runCLI(['--shred', '-f', testFile], { cwd: tmpDir });
    assert.strictEqual(result.code, 0, 'shred should succeed: ' + result.stderr);

    assert.ok(!fs.existsSync(testFile), 'file should be deleted after shred');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('shred with custom passes', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-test-'));

  try {
    const testFile = path.join(tmpDir, 'to_delete.txt');
    fs.writeFileSync(testFile, Buffer.alloc(256));

    assert.ok(fs.existsSync(testFile), 'file should exist before shred');

    const result = runCLI(['--shred', '-f', testFile, '--passes', '1'], { cwd: tmpDir });
    assert.strictEqual(result.code, 0, 'shred should succeed: ' + result.stderr);

    assert.ok(!fs.existsSync(testFile), 'file should be deleted after shred with 1 pass');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('shred requires --file argument', () => {
  const result = runCLI(['--shred']);
  assert.strictEqual(result.code, 1, 'shred without file should fail');
});






