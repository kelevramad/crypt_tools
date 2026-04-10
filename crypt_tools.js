#!/usr/bin/env node
/**
 * Cryptographic Tool for File and Text Encryption/Decryption.
 * Refactored version with AES-GCM and Streaming I/O.
 * Node.js Edition
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const zlib = require('zlib');
const { finished, pipeline } = require('stream/promises');
const { program } = require('commander');
const ProgressBar = require('progress');

let blessed;
let BLESSED_AVAILABLE = false;
try {
    blessed = require('blessed');
    BLESSED_AVAILABLE = true;
} catch (e) {
    // blessed not available
}

let qrcodeTerminal;
let QRCODE_AVAILABLE = false;
try {
    qrcodeTerminal = require('qrcode-terminal');
    QRCODE_AVAILABLE = true;
} catch (e) {
    // qrcode-terminal not available
}

let argon2;
let ARGON2_AVAILABLE = false;
try {
    argon2 = require('argon2');
    ARGON2_AVAILABLE = true;
} catch (e) {
    // Argon2 not available
}

// =========================
// Shamir's Secret Sharing
// =========================

class GaloisField {
    static mul(a, b) {
        let result = 0;
        while (b > 0) {
            if (b & 1) result ^= a;
            const highBit = a & 0x80;
            a = (a << 1) & 0xff;
            if (highBit) a ^= 0x1b;
            b >>= 1;
        }
        return result;
    }

    static exp(base, exp) {
        let result = 1;
        for (let i = 0; i < exp; i++) {
            result = GaloisField.mul(result, base);
        }
        return result;
    }

    static inv(a) {
        if (a === 0) return 0;
        return GaloisField.exp(a, 254);
    }

    static div(a, b) {
        if (b === 0) throw new Error('Division by zero');
        return GaloisField.mul(a, GaloisField.inv(b));
    }
}

class ShamirSecretSharing {
    static generateShares(secret, numShares, threshold) {
        if (threshold > numShares) {
            throw new Error('Threshold cannot exceed number of shares');
        }
        if (threshold < 2) {
            throw new Error('Threshold must be at least 2');
        }
        if (secret.length === 0) {
            throw new Error('Secret cannot be empty');
        }

        const coeffs = [];
        for (let k = 0; k < threshold - 1; k++) {
            coeffs.push(crypto.randomBytes(1)[0]);
        }

        const shares = [];
        for (let i = 0; i < numShares; i++) {
            const share = Buffer.alloc(secret.length + 1);
            share[0] = i + 1;
            const x = i + 1;

            for (let j = 0; j < secret.length; j++) {
                let y = secret[j];
                for (let deg = 1; deg < threshold; deg++) {
                    y ^= GaloisField.mul(coeffs[deg - 1], GaloisField.exp(x, deg));
                }
                share[j + 1] = y;
            }

            shares.push(share);
        }

        return shares;
    }

    static recoverSecret(shares) {
        if (shares.length < 2) {
            throw new Error('At least 2 shares required for recovery');
        }
        if (new Set(shares.map((share) => share[0])).size !== shares.length) {
            throw new Error('Duplicate shares are not allowed for recovery');
        }

        const secretLength = shares[0].length - 1;
        const secret = Buffer.alloc(secretLength);

        for (let j = 0; j < secretLength; j++) {
            const xVals = shares.map((s) => s[0]);
            const yVals = shares.map((s) => s[j + 1]);

            let result = 0;
            for (let i = 0; i < shares.length; i++) {
                let num = 1;
                let den = 1;
                for (let m = 0; m < shares.length; m++) {
                    if (m !== i) {
                        num = GaloisField.mul(num, xVals[m]);
                        den = GaloisField.mul(den, xVals[m] ^ xVals[i]);
                    }
                }
                const li = GaloisField.div(num, den);
                result ^= GaloisField.mul(yVals[i], li);
            }

            secret[j] = result;
        }

        return secret;
    }
}

// =========================
// Configuration
// =========================

class Config {
    static AUTHOR = 'Center For Cyber Intelligence';
    static DESCRIPTION = 'Crypt Tools (AES-GCM Edition)';
    static VERSION = '2.6.1';

    // File format
    static MAGIC = Buffer.from('CT02');
    static FORMAT_VERSION = 2;
    static FLAG_COMPRESS = 0x01;
    static FLAG_TEXT = 0x02;
    static FLAG_KEYFILE = 0x04;
    static FLAG_THRESHOLD = 0x08;
    static THRESHOLD_MAGIC = Buffer.from('CTTH');
    static KDF_PBKDF2 = 0x01;
    static KDF_ARGON2 = 0x02;
    static FIXED_HEADER_SIZE = 16;

    /** Hidden-volume container: [CT02_outer][CT02_hidden][FOOTER_MAGIC][uint64_be outer_total_len] */
    static CONTAINER_FOOTER_MAGIC = Buffer.from('CTHV');
    static CONTAINER_FOOTER_SIZE = 12;

    // Argon2id defaults (recommended for password hashing)
    static ARGON2_MEMORY_COST = 65536;  // 64 MB
    static ARGON2_TIME_COST = 3;        // iterations
    static ARGON2_PARALLELISM = 4;

    // AES-GCM Constants
    static KEY_SIZE = 32;           // 256 bits
    static SALT_SIZE = 16;          // 128 bits
    static NONCE_SIZE = 12;         // 96 bits (Standard for GCM)
    static TAG_SIZE = 16;           // 128 bits (Standard for GCM)

    // Streaming
    static CHUNK_SIZE = 64 * 1024;  // 64KB chunks
    static PBKDF2_ITERATIONS = 100000;
}

// =========================
// Logging & UI
// =========================

class TerminalColors {
    static RESET = '\x1b[0m';
    static GREEN = '\x1b[92m';
    static RED = '\x1b[91m';
    static YELLOW = '\x1b[93m';
    static BLUE = '\x1b[94m';
    static CYAN = '\x1b[96m';
    static MAGENTA = '\x1b[95m';
    static WHITE = '\x1b[97m';
}

class UIHelpers {
    static shouldUseColor() {
        return Boolean(process.stdout.isTTY);
    }

    static style(text, color) {
        if (!UIHelpers.shouldUseColor()) {
            return text;
        }
        return `${color}${text}${TerminalColors.RESET}`;
    }

    static heading(icon, title, color = TerminalColors.CYAN) {
        return UIHelpers.style(`${icon} ${title}`, color);
    }

    static renderHelpSection(title, options) {
        const width = options.reduce((max, option) => Math.max(max, option.flags.length), 0);
        const lines = [UIHelpers.heading(...title)];
        for (const option of options) {
            const flags = UIHelpers.style(option.flags.padEnd(width), TerminalColors.WHITE);
            lines.push(`  ${flags}  ${option.description}`);
        }
        return lines.join('\n');
    }

    static renderNodeHelp(cmd) {
        const sections = [
            [
                ['🎯', 'Modes'],
                ['-e, --encrypt', 'Encrypt mode (default)'],
                ['-d, --decrypt', 'Decrypt mode'],
                ['--inspect', 'Inspect encrypted file metadata'],
            ],
            [
                ['📥', 'Input & Output'],
                ['-t, --text <text>', 'Text to process'],
                ['-f, --file <path>', 'File path, directory, or wildcard pattern'],
                ['-o, --output <path>', 'Output file path'],
                ['--config <path>', 'Path to a config file; defaults are auto-discovered'],
                ['--select', 'Browse and choose a file or directory interactively'],
            ],
            [
                ['🔑', 'Passwords & Secrets'],
                ['-p, --password <password>', 'Password (repeat for threshold mode)'],
                ['--threshold <number>', 'Threshold for multi-signature mode'],
                ['--keyfile <path>', 'Key file path for encryption/decryption'],
                ['--password-outer <password>', 'Decoy password for --hidden-vol'],
                ['--password-hidden <password>', 'Hidden password for --hidden-vol / --hidden'],
            ],
            [
                ['📦', 'File & Container Behavior'],
                ['-c, --compress', 'Enable compression'],
                ['-r, --recursive', 'Recursively process directories or wildcard patterns'],
                ['--hidden-vol', 'Encrypt decoy and hidden payload into one container'],
                ['--hidden-file <path>', 'Hidden payload path (requires --hidden-vol)'],
                ['--hidden', 'Decrypt inner/hidden volume in decrypt mode'],
            ],
            [
                ['🧬', 'Crypto Tuning'],
                ['--kdf <type>', 'Key derivation function: pbkdf2 or argon2'],
                ['--iterations <count>', 'Number of KDF iterations'],
                ['--qr', 'Render encrypted text output as a QR code'],
            ],
            [
                ['🛠️', 'Utility'],
                ['--generate-keyfile [path]', 'Generate a random key file and exit (default: key.txt)'],
                ['--debug', 'Enable debug mode'],
                ['--log', 'Enable logging to file'],
                ['-V, --version', 'Show version'],
                ['-h, --help', 'Show help'],
            ],
        ];

        const renderedSections = sections.map(([title, ...options]) =>
            UIHelpers.renderHelpSection(title, options.map(([flags, description]) => ({ flags, description })))
        );

        return [
            UIHelpers.heading('🔐', 'Crypt Tools Help'),
            UIHelpers.style('Beautiful, secure AES-GCM encryption for files and text.', TerminalColors.WHITE),
            '',
            UIHelpers.heading('🚀', 'Usage'),
            '  crypt_tools.js [options]',
            '',
            renderedSections.join('\n\n'),
            '',
            UIHelpers.heading('✨', 'Tips'),
            '  - Wildcards are supported; with -r, patterns like .\\temp\\*.txt are expanded recursively',
            '    (equivalent to .\\temp\\**\\*.txt).',
            '  - Password prompts show a live strength indicator.',
            '  - Key file support: combine password + keyfile for two-factor encryption.',
            '  - Use --select to browse for a file or directory in an interactive terminal UI.',
            '  - Use --qr with text encryption to print the encrypted Base64 payload as a QR code.',
            '  - Hidden volumes use two CT02 blobs plus a visible CTHV footer.',
            '',
            UIHelpers.heading('🌍', 'Environment Variables'),
            '  CRYPT_TOOLS_PASSWORD, CRYPT_TOOLS_KDF, CRYPT_TOOLS_ITERATIONS,',
            '  CRYPT_TOOLS_COMPRESS, CRYPT_TOOLS_COMPRESSION, CRYPT_TOOLS_LOG,',
            '  CRYPT_TOOLS_LOG_ENABLED, CRYPT_TOOLS_DEBUG, CRYPT_TOOLS_DEBUG_ENABLED,',
            '  CRYPT_TOOLS_KEYFILE, CRYPT_TOOLS_THRESHOLD,',
            '  CRYPT_TOOLS_PASSWORD_OUTER, CRYPT_TOOLS_PASSWORD_HIDDEN',
            '',
            UIHelpers.heading('⚙️', 'Config Keys'),
            '  compress, compression, default_compression, kdf, default_kdf,',
            '  iterations, default_iterations, log, logging, log_enabled,',
            '  debug, debug_enabled, password, default_password,',
            '  password_outer, default_password_outer,',
            '  password_hidden, default_password_hidden,',
            '  keyfile, default_keyfile, threshold',
            '',
        ].join('\n');
    }

    static renderQrCode(data) {
        if (!QRCODE_AVAILABLE) {
            throw new Error('QR code support is not available. Please install qrcode-terminal.');
        }

        return new Promise((resolve) => {
            qrcodeTerminal.generate(data, { small: true }, (qrText) => {
                ConsoleLogger.show('info', 'QR Code Output:', '🔳', true, false);
                process.stdout.write(`${qrText}\n`);
                resolve(qrText);
            });
        });
    }

    static selectPathInteractive(startPath = '.') {
        if (!BLESSED_AVAILABLE) {
            return Promise.reject(
                new Error('Interactive file selection is not available. Please install blessed.')
            );
        }
        if (!process.stdin.isTTY || !process.stdout.isTTY) {
            return Promise.reject(new Error('Interactive file selection requires an interactive terminal.'));
        }

        const initialPath = fs.existsSync(startPath) && fs.statSync(startPath).isDirectory()
            ? startPath
            : path.dirname(startPath || '.') || '.';

        return new Promise((resolve) => {
            const screen = blessed.screen({
                smartCSR: true,
                title: 'Crypt Tools Interactive File Selection',
            });

            const header = blessed.box({
                parent: screen,
                top: 0,
                left: 0,
                width: '100%',
                height: 3,
                tags: false,
                style: {
                    fg: 'white',
                    bg: 'blue',
                },
                content: ' Crypt Tools Interactive File Selection\n Use arrows to move, Enter to open/select, Backspace for parent, q to cancel',
            });

            const pathBox = blessed.box({
                parent: screen,
                top: 3,
                left: 0,
                width: '100%',
                height: 2,
                style: { fg: 'cyan' },
            });

            const list = blessed.list({
                parent: screen,
                top: 5,
                left: 0,
                width: '100%',
                height: '100%-5',
                keys: true,
                vi: true,
                mouse: true,
                style: {
                    selected: {
                        bg: 'cyan',
                        fg: 'black',
                        bold: true,
                    },
                },
                border: 'line',
                label: ' Paths ',
            });

            let currentDir = path.resolve(initialPath);
            let currentEntries = [];

            function close(result) {
                screen.destroy();
                resolve(result);
            }

            function buildEntries(directory) {
                const entries = [
                    { label: `📁 [.] Select current directory: ${directory}`, path: directory, action: 'select' },
                    { label: '⬆️  [..] Go to parent directory', path: path.dirname(directory), action: 'up' },
                ];

                const names = fs.readdirSync(directory).sort((a, b) => {
                    const aPath = path.join(directory, a);
                    const bPath = path.join(directory, b);
                    const aDir = fs.statSync(aPath).isDirectory();
                    const bDir = fs.statSync(bPath).isDirectory();
                    if (aDir !== bDir) {
                        return aDir ? -1 : 1;
                    }
                    return a.localeCompare(b, undefined, { sensitivity: 'base' });
                });

                for (const name of names) {
                    const fullPath = path.join(directory, name);
                    const isDir = fs.statSync(fullPath).isDirectory();
                    entries.push({
                        label: `${isDir ? '📁' : '📄'} ${name}`,
                        path: fullPath,
                        action: isDir ? 'enter' : 'select',
                    });
                }
                return entries;
            }

            function refresh(directory) {
                currentDir = path.resolve(directory);
                currentEntries = buildEntries(currentDir);
                pathBox.setContent(` Current directory: ${currentDir}`);
                list.setItems(currentEntries.map((entry) => entry.label));
                list.select(0);
                screen.render();
            }

            list.on('select', (_, index) => {
                const entry = currentEntries[index];
                if (!entry) {
                    return;
                }
                if (entry.action === 'up' || entry.action === 'enter') {
                    refresh(entry.path);
                } else {
                    close(entry.path);
                }
            });

            screen.key(['backspace', 'left'], () => refresh(path.dirname(currentDir)));
            screen.key(['q', 'escape', 'C-c'], () => close(null));

            refresh(currentDir);
            list.focus();
        });
    }
}

class ConsoleLogger {
    static DEBUG_ENABLED = false;
    static LOG_ENABLED = false;
    static LOG_FILE = 'crypt_tools.log';

    // Output style definitions: icon + color for each level
    static STYLES = {
        'info': { icon: 'ℹ️', color: TerminalColors.BLUE },
        'success': { icon: '✅', color: TerminalColors.GREEN },
        'error': { icon: '❌', color: TerminalColors.RED },
        'warning': { icon: '⚠️', color: TerminalColors.YELLOW },
        'debug': { icon: '🐞', color: TerminalColors.MAGENTA },
        'important': { icon: '📌', color: TerminalColors.MAGENTA },
    };

    static show(level, message, icon = null, showConsole = true, logFile = true) {
        // Skip debug if not enabled
        if (level === 'debug' && !ConsoleLogger.DEBUG_ENABLED) {
            return;
        }

        // Get style for this level
        const style = ConsoleLogger.STYLES[level] || ConsoleLogger.STYLES['info'];
        // Use custom icon if provided, otherwise use default from style
        const usedIcon = icon !== null ? icon : style.icon;
        const color = style.color;

        // Write to log file if enabled (with emoji)
        if (logFile && ConsoleLogger.LOG_ENABLED) {
            ConsoleLogger._writeToFile(level, usedIcon, message);
        }

        // Print to console if enabled (with emoji and colors)
        if (showConsole) {
            ConsoleLogger._printToConsole(usedIcon, message, color);
        }
    }

    static _printToConsole(icon, message, color) {
        const white = TerminalColors.WHITE;
        const reset = TerminalColors.RESET;
        console.log(`${white}[${reset}${icon}${white}]${reset} ${color}${message}${reset}`);
    }

    static _writeToFile(level, icon, message) {
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const logEntry = `[${timestamp}] [${level.toUpperCase()}] [${icon}] ${message}\n`;
        fs.appendFileSync(ConsoleLogger.LOG_FILE, logEntry, { encoding: 'utf-8' });
    }

    static logCompletionSummary(isDecrypt, successCount, totalOps, elapsedSec) {
        const action = isDecrypt ? 'Decryption' : 'Encryption';
        if (totalOps > 0 && successCount === totalOps) {
            ConsoleLogger.show('success', `${action} completed successfully`, '✅');
        } else if (successCount === 0) {
            // Specific per-file errors are already shown, so avoid duplicating a generic failure line.
        } else {
            ConsoleLogger.show('warning', `${action} completed with failures`, '⚠️');
        }
        ConsoleLogger.show('info', `Operations completed: ${successCount}/${totalOps}`, '✔️');
        ConsoleLogger.show('info', `Total time: ${elapsedSec.toFixed(2)}s`, '⏱️');
    }
}

// =========================
// Progress Bar (tqdm-like)
// =========================

class ProgressBarUtils {
    static formatSize(bytes) {
        const units = ['B', 'k', 'M', 'G', 'T'];
        let value = bytes;
        let unitIndex = 0;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }
        if (unitIndex === 0) {
            return `${Math.round(value)}B`;
        }
        return `${value.toFixed(2)}${units[unitIndex]}`;
    }

    static formatRate(bytesPerSec) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let value = bytesPerSec;
        let unitIndex = 0;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }
        if (unitIndex === 0) {
            return `${Math.round(value)}B/s`;
        }
        return `${value.toFixed(1)}${units[unitIndex]}/s`;
    }

    static formatTime(seconds) {
        const totalSeconds = Math.max(0, Math.floor(seconds));
        const s = totalSeconds % 60;
        const m = Math.floor(totalSeconds / 60) % 60;
        const h = Math.floor(totalSeconds / 3600);
        const pad2 = (n) => String(n).padStart(2, '0');
        if (h > 0) {
            return `${pad2(h)}:${pad2(m)}:${pad2(s)}`;
        }
        return `${pad2(m)}:${pad2(s)}`;
    }

    static getTokens(bar, startTime, nextCurr = null) {
        const elapsedSec = (Date.now() - startTime) / 1000;
        const curr = nextCurr !== null ? nextCurr : bar.curr;
        const total = bar.total;
        const rate = elapsedSec > 0 ? (curr / elapsedSec) : 0;
        const remainingSec = rate > 0 ? (total - curr) / rate : 0;
        return {
            sizes: `${ProgressBarUtils.formatSize(curr)}/${ProgressBarUtils.formatSize(total)}`,
            telapsed: ProgressBarUtils.formatTime(elapsedSec),
            teta: ProgressBarUtils.formatTime(remainingSec),
            trate: ProgressBarUtils.formatRate(rate)
        };
    }

    static calcBarWidth(label, tokens) {
        const columns = (process.stderr && process.stderr.columns) ? process.stderr.columns : 120;
        const fixedLen = `${label} 100%|| ${tokens.sizes} [${tokens.telapsed}<${tokens.teta}, ${tokens.trate}]`.length;
        const width = columns - fixedLen;
        return Math.max(10, Math.min(80, width));
    }

    static create(label, total) {
        const initialTokens = {
            sizes: '0B/0B',
            telapsed: '00:00',
            teta: '00:00',
            trate: '0B/s'
        };
        const bar = new ProgressBar(`${label} :percent|:bar| :sizes [:telapsed<:teta, :trate]`, {
            total,
            width: ProgressBarUtils.calcBarWidth(label, initialTokens),
            complete: '▓',
            incomplete: '░',
            head: '▓',
            clear: false
        });
        const startTime = Date.now();
        return {
            bar,
            render: () => {
                const tokens = ProgressBarUtils.getTokens(bar, startTime);
                bar.width = ProgressBarUtils.calcBarWidth(label, tokens);
                bar.render(tokens);
            },
            tick: (len) => {
                const nextCurr = bar.curr + len;
                const tokens = ProgressBarUtils.getTokens(bar, startTime, nextCurr);
                bar.width = ProgressBarUtils.calcBarWidth(label, tokens);
                bar.tick(len, tokens);
            }
        };
    }
}

// =========================
// ConfigParser
// =========================

class ConfigParser {
    static FILENAMES = [
        '.crypt_tools.conf',
        '.crypt_tools.json',
        '.crypt_tools.yml',
        '.crypt_tools.yaml',
    ];

    static KEY_ALIASES = {
        compress: 'compress',
        compression: 'compress',
        default_compression: 'compress',
        kdf: 'kdf',
        default_kdf: 'kdf',
        iterations: 'iterations',
        default_iterations: 'iterations',
        log: 'log',
        logging: 'log',
        log_enabled: 'log',
        debug: 'debug',
        debug_enabled: 'debug',
        password: 'password',
        default_password: 'password',
        password_outer: 'passwordOuter',
        default_password_outer: 'passwordOuter',
        password_hidden: 'passwordHidden',
        default_password_hidden: 'passwordHidden',
        keyfile: 'keyfile',
        default_keyfile: 'keyfile',
        threshold: 'threshold',
    };

    static ENV_KEY_ALIASES = {
        CRYPT_TOOLS_COMPRESS: 'compress',
        CRYPT_TOOLS_COMPRESSION: 'compress',
        CRYPT_TOOLS_KDF: 'kdf',
        CRYPT_TOOLS_ITERATIONS: 'iterations',
        CRYPT_TOOLS_LOG: 'log',
        CRYPT_TOOLS_LOG_ENABLED: 'log',
        CRYPT_TOOLS_DEBUG: 'debug',
        CRYPT_TOOLS_DEBUG_ENABLED: 'debug',
        CRYPT_TOOLS_PASSWORD: 'password',
        CRYPT_TOOLS_PASSWORD_OUTER: 'passwordOuter',
        CRYPT_TOOLS_PASSWORD_HIDDEN: 'passwordHidden',
        CRYPT_TOOLS_KEYFILE: 'keyfile',
        CRYPT_TOOLS_THRESHOLD: 'threshold',
    };

    static CLI_OPTION_ALIASES = {
        '--compress': 'compress',
        '-c': 'compress',
        '--kdf': 'kdf',
        '--iterations': 'iterations',
        '--log': 'log',
        '--debug': 'debug',
        '-p': 'password',
        '--password': 'password',
        '--password-outer': 'passwordOuter',
        '--password-hidden': 'passwordHidden',
        '--keyfile': 'keyfile',
        '--threshold': 'threshold',
        '--config': 'config',
    };

    static normalizeKey(rawKey) {
        return ConfigParser.KEY_ALIASES[String(rawKey).trim().toLowerCase().replace(/-/g, '_')];
    }

    static parseBool(value) {
        if (typeof value === 'boolean') {
            return value;
        }
        if (typeof value === 'number') {
            return value !== 0;
        }
        const normalized = String(value).trim().toLowerCase();
        if (['1', 'true', 'yes', 'on'].includes(normalized)) {
            return true;
        }
        if (['0', 'false', 'no', 'off'].includes(normalized)) {
            return false;
        }
        throw new Error(`Invalid boolean value: ${value}`);
    }

    static coerceValue(key, value) {
        if (['compress', 'log', 'debug'].includes(key)) {
            return ConfigParser.parseBool(value);
        }
        if (['iterations', 'threshold'].includes(key)) {
            return Number.parseInt(value, 10);
        }
        if (key === 'kdf') {
            return String(value).trim().toLowerCase();
        }
        if (['password', 'passwordOuter', 'passwordHidden', 'keyfile'].includes(key)) {
            return String(value);
        }
        return value;
    }

    static parseYaml(content) {
        const data = {};
        for (const line of content.split(/\r?\n/)) {
            const stripped = line.trim();
            if (!stripped || stripped.startsWith('#')) {
                continue;
            }
            const separator = stripped.indexOf(':');
            if (separator === -1) {
                throw new Error(`Invalid YAML line: ${line}`);
            }
            const key = stripped.slice(0, separator).trim();
            const rawValue = stripped.slice(separator + 1).trim();
            data[key] = rawValue;
        }
        return data;
    }

    static parseConf(content) {
        const data = {};
        for (const line of content.split(/\r?\n/)) {
            const stripped = line.trim();
            if (!stripped || stripped.startsWith('#') || stripped.startsWith(';')) {
                continue;
            }
            const eqIndex = stripped.indexOf('=');
            const colonIndex = stripped.indexOf(':');
            const separatorIndex = eqIndex >= 0 ? eqIndex : colonIndex;
            if (separatorIndex === -1) {
                throw new Error(`Invalid config line: ${line}`);
            }
            const key = stripped.slice(0, separatorIndex).trim();
            const rawValue = stripped.slice(separatorIndex + 1).trim();
            data[key] = rawValue;
        }
        return data;
    }

    static readFile(configPath) {
        const ext = path.extname(configPath).toLowerCase();
        const content = fs.readFileSync(configPath, 'utf8');
        let parsed;
        if (ext === '.json') {
            parsed = JSON.parse(content);
        } else if (ext === '.yml' || ext === '.yaml') {
            parsed = ConfigParser.parseYaml(content);
        } else {
            parsed = ConfigParser.parseConf(content);
        }

        if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
            throw new Error('Configuration file must contain a top-level object');
        }

        const normalized = {};
        for (const [rawKey, rawValue] of Object.entries(parsed)) {
            const key = ConfigParser.normalizeKey(rawKey);
            if (!key) {
                continue;
            }
            normalized[key] = ConfigParser.coerceValue(key, rawValue);
        }
        return normalized;
    }

    static discoverPath(explicitPath) {
        if (explicitPath) {
            return { path: explicitPath, explicit: true };
        }

        for (const filename of ConfigParser.FILENAMES) {
            const candidate = path.join(process.cwd(), filename);
            if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
                return { path: candidate, explicit: false };
            }
        }
        return { path: null, explicit: false };
    }

    static loadDefaults(explicitConfigPath) {
        const configInfo = ConfigParser.discoverPath(explicitConfigPath);
        const configDefaults = {};
        if (configInfo.path) {
            try {
                Object.assign(configDefaults, ConfigParser.readFile(configInfo.path));
            } catch (err) {
                throw new Error(`Failed to load config file ${configInfo.path}: ${err.message}`);
            }
        } else if (configInfo.explicit) {
            throw new Error(`Config file not found: ${explicitConfigPath}`);
        }

        const envDefaults = {};
        for (const [envKey, normalizedKey] of Object.entries(ConfigParser.ENV_KEY_ALIASES)) {
            const rawValue = process.env[envKey];
            if (rawValue === undefined || rawValue === '') {
                continue;
            }
            envDefaults[normalizedKey] = ConfigParser.coerceValue(normalizedKey, rawValue);
        }

        return { configPath: configInfo.path, configDefaults, envDefaults };
    }

    static detectCliOverrides(argv) {
        const overrides = new Set();
        for (const token of argv) {
            if (token.startsWith('--')) {
                const flag = token.split('=', 1)[0];
                const normalized = ConfigParser.CLI_OPTION_ALIASES[flag];
                if (normalized) {
                    overrides.add(normalized);
                }
            } else if (ConfigParser.CLI_OPTION_ALIASES[token]) {
                overrides.add(ConfigParser.CLI_OPTION_ALIASES[token]);
            }
        }
        return overrides;
    }

    static applyDefaults(options, cliOverrides, configDefaults, envDefaults) {
        const mergedDefaults = { ...configDefaults, ...envDefaults };

        if (!cliOverrides.has('password') && (!options.password || options.password.length === 0) && 'password' in mergedDefaults) {
            const passwordValue = mergedDefaults.password;
            options.password = Array.isArray(passwordValue) ? passwordValue : [passwordValue];
        }

        for (const attr of ['passwordOuter', 'passwordHidden', 'keyfile', 'threshold']) {
            if (cliOverrides.has(attr)) {
                continue;
            }
            if (options[attr] === undefined && attr in mergedDefaults) {
                options[attr] = mergedDefaults[attr];
            }
        }

        for (const attr of ['compress', 'log', 'debug']) {
            if (cliOverrides.has(attr)) {
                continue;
            }
            if (attr in mergedDefaults) {
                options[attr] = Boolean(mergedDefaults[attr]);
            }
        }

        if (!cliOverrides.has('kdf') && options.kdf === undefined && 'kdf' in mergedDefaults) {
            options.kdf = mergedDefaults.kdf;
        }

        if (!cliOverrides.has('iterations') && options.iterations === undefined && 'iterations' in mergedDefaults) {
            options.iterations = mergedDefaults.iterations;
        }

        return options;
    }
}

class Banner {
    static BANNERS = [
        String.raw`
      /$$$$$$                                  /$$           /$$$$$$$$                  /$$
     /$$__  $$                                | $$          |__  $$__/                 | $$
    | $$  \__/  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$           | $$  /$$$$$$   /$$$$$$ | $$  /$$$$$$$
    | $$       /$$__  $$| $$  | $$ /$$__  $$|_  $$_/           | $$ /$$__  $$ /$$__  $$| $$ /$$_____/
    | $$      | $$  \__/| $$  | $$| $$  \ $$  | $$             | $$| $$  \ $$| $$  \ $$| $$|  $$$$$$
    | $$    $$| $$      | $$  | $$| $$  | $$  | $$ /$$         | $$| $$  | $$| $$  | $$| $$ \____  $$
    |  $$$$$$/| $$      |  $$$$$$$| $$$$$$$/  |  $$$$/         | $$|  $$$$$$/|  $$$$$$/| $$ /$$$$$$$/
     \______/ |__/       \____  $$| $$____/    \___/           |__/ \______/  \______/ |__/|_______/
                         /$$  | $$| $$
                        |  $$$$$$/| $$
                         \______/ |__/
    `,
        String.raw`
      ÛÛÛÛÛÛÛÛÛ                                  ÛÛÛÛÛ       ÛÛÛÛÛÛÛÛÛÛÛ                   ÛÛÛÛ
      ÛÛÛ°°°°°ÛÛÛ                                °°ÛÛÛ       °Û°°°ÛÛÛ°°°Û                  °°ÛÛÛ
     ÛÛÛ     °°°  ÛÛÛÛÛÛÛÛ  ÛÛÛÛÛ ÛÛÛÛ ÛÛÛÛÛÛÛÛ  ÛÛÛÛÛÛÛ     °   °ÛÛÛ  °   ÛÛÛÛÛÛ   ÛÛÛÛÛÛ  °ÛÛÛ   ÛÛÛÛÛ
    °ÛÛÛ         °°ÛÛÛ°°ÛÛÛ°°ÛÛÛ °ÛÛÛ °°ÛÛÛ°°ÛÛÛ°°°ÛÛÛ°          °ÛÛÛ     ÛÛÛ°°ÛÛÛ ÛÛÛ°°ÛÛÛ °ÛÛÛ  ÛÛÛ°°
    °ÛÛÛ          °ÛÛÛ °°°  °ÛÛÛ °ÛÛÛ  °ÛÛÛ °ÛÛÛ  °ÛÛÛ           °ÛÛÛ    °ÛÛÛ °ÛÛÛ°ÛÛÛ °ÛÛÛ °ÛÛÛ °°ÛÛÛÛÛ
    °°ÛÛÛ     ÛÛÛ °ÛÛÛ      °ÛÛÛ °ÛÛÛ  °ÛÛÛ °ÛÛÛ  °ÛÛÛ ÛÛÛ       °ÛÛÛ    °ÛÛÛ °ÛÛÛ°ÛÛÛ °ÛÛÛ °ÛÛÛ  °°°°ÛÛÛ
     °°ÛÛÛÛÛÛÛÛÛ  ÛÛÛÛÛ     °°ÛÛÛÛÛÛÛ  °ÛÛÛÛÛÛÛ   °°ÛÛÛÛÛ        ÛÛÛÛÛ   °°ÛÛÛÛÛÛ °°ÛÛÛÛÛÛ  ÛÛÛÛÛ ÛÛÛÛÛÛ
      °°°°°°°°°  °°°°°       °°°°°ÛÛÛ  °ÛÛÛ°°°     °°°°°        °°°°°     °°°°°°   °°°°°°  °°°°° °°°°°°
                             ÛÛÛ °ÛÛÛ  °ÛÛÛ
                            °°ÛÛÛÛÛÛ   ÛÛÛÛÛ
                             °°°°°°   °°°°°
    `,
        String.raw`
      ,ad8888ba,                                               888888888888                    88
     d8"'    '"8b                                     ,d            88                         88
    d8'                                               88            88                         88
    88            8b,dPPYba, 8b       d8 8b,dPPYba, MM88MMM         88  ,adPPYba,   ,adPPYba,  88 ,adPPYba,
    88            88P'   "Y8 '8b     d8' 88P'    "8a  88            88 a8"     "8a a8"     "8a 88 I8[    ""
    Y8,           88          '8b,  d8'  88       d8  88            88 8b       d8 8b       d8 88  '"Y8ba,
     Y8a.    .a8P 88           '8b,d8'   88b,   ,a8"  88,           88 "8a,   ,a8" "8a,   ,a8" 88 aa    ]8I
      '"Y8888Y"'  88             Y88'    88'YbbdP"'   "Y888         88  '"YbbdP"'   '"YbbdP"'  88 '"YbbdP"'
                                 d8'     88
                                d8'      88
    `,
        String.raw`
     ██████╗██████╗ ██╗   ██╗██████╗ ████████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║          ██║   ██║   ██║██║   ██║██║     ███████╗
    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║          ██║   ██║   ██║██║   ██║██║     ╚════██║
    ╚██████╗██║  ██║   ██║   ██║        ██║          ██║   ╚██████╔╝╚██████╔╝███████╗███████║
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
    `
    ];

    static show() {
        const banner = this.BANNERS[Math.floor(Math.random() * this.BANNERS.length)];
        const cyan = TerminalColors.CYAN;
        const reset = TerminalColors.RESET;
        console.log(`${cyan}${banner}${reset}`);
        console.log(`${cyan}${Config.DESCRIPTION} v${Config.VERSION}${reset}`);
        console.log(`${cyan}Author: ${Config.AUTHOR}${reset}\n`);
    }
}

// =========================
// HeaderParser
// =========================

class HeaderParser {
    static uint32ToBuffer(value) {
        const buf = Buffer.alloc(4);
        buf.writeUInt32BE(value >>> 0, 0);
        return buf;
    }

    static bufferToUint32(buf) {
        return buf.readUInt32BE(0);
    }

    static buildHeader({ compress = false, isText = false, useKeyfile = false, kdfId = Config.KDF_PBKDF2, iterations = Config.PBKDF2_ITERATIONS } = {}) {
        let flags = 0;
        if (compress) flags |= Config.FLAG_COMPRESS;
        if (isText) flags |= Config.FLAG_TEXT;
        if (useKeyfile) flags |= Config.FLAG_KEYFILE;

        const kdfParams = HeaderParser.uint32ToBuffer(iterations);
        return Buffer.concat([
            Config.MAGIC,
            Buffer.from([Config.FORMAT_VERSION, flags, kdfId, 0x00, Config.SALT_SIZE, Config.NONCE_SIZE, Config.TAG_SIZE, kdfParams.length]),
            kdfParams
        ]);
    }

    static parseCT02(buffer) {
        if (buffer.length < 12) {
            throw new Error('CT02 header too short');
        }
        if (!buffer.subarray(0, 4).equals(Config.MAGIC)) {
            throw new Error('Invalid CT02 magic');
        }

        const version = buffer[4];
        const flags = buffer[5];
        const kdfId = buffer[6];
        const saltLen = buffer[8];
        const nonceLen = buffer[9];
        const tagLen = buffer[10];
        const kdfParamLen = buffer[11];
        const headerLen = 12 + kdfParamLen;

        if (buffer.length < headerLen) {
            throw new Error('Incomplete CT02 header');
        }

        const kdfParams = buffer.subarray(12, headerLen);
        const iterations = kdfParamLen === 4 ? HeaderParser.bufferToUint32(kdfParams) : Config.PBKDF2_ITERATIONS;

        return {
            format: Config.MAGIC.toString('ascii'),
            version,
            flags,
            compress: Boolean(flags & Config.FLAG_COMPRESS),
            isText: Boolean(flags & Config.FLAG_TEXT),
            useKeyfile: Boolean(flags & Config.FLAG_KEYFILE),
            kdfId,
            iterations,
            saltLen,
            nonceLen,
            tagLen,
            kdfParamLen,
            headerLen,
            isLegacy: false
        };
    }

    static parseLegacy({ textPayload = false } = {}) {
        return {
            format: 'legacy-v2.1',
            version: 'legacy',
            flags: 0,
            compress: null,
            isText: textPayload,
            useKeyfile: false,
            kdfId: Config.KDF_PBKDF2,
            iterations: Config.PBKDF2_ITERATIONS,
            saltLen: Config.SALT_SIZE,
            nonceLen: Config.NONCE_SIZE,
            tagLen: Config.TAG_SIZE,
            kdfParamLen: 4,
            headerLen: 0,
            isLegacy: true
        };
    }

    static parseFormat(buffer, { textPayload = false } = {}) {
        if (buffer.length >= 4 && buffer.subarray(0, 4).equals(Config.MAGIC)) {
            return HeaderParser.parseCT02(buffer);
        }
        return HeaderParser.parseLegacy({ textPayload });
    }

    static parseHiddenFooter(inputPath) {
        let fileSize;
        try {
            fileSize = fs.statSync(inputPath).size;
        } catch {
            return null;
        }

        const minBlob = Config.FIXED_HEADER_SIZE + Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE;
        if (fileSize < minBlob * 2 + Config.CONTAINER_FOOTER_SIZE) {
            return null;
        }

        const fd = fs.openSync(inputPath, 'r');
        const footer = Buffer.alloc(Config.CONTAINER_FOOTER_SIZE);
        fs.readSync(fd, footer, 0, footer.length, fileSize - Config.CONTAINER_FOOTER_SIZE);
        fs.closeSync(fd);

        if (!footer.subarray(0, 4).equals(Config.CONTAINER_FOOTER_MAGIC)) {
            return null;
        }

        const outerTotalLen = footer.readBigUInt64BE(4);
        if (outerTotalLen <= 0n || outerTotalLen >= BigInt(fileSize - Config.CONTAINER_FOOTER_SIZE)) {
            return null;
        }
        const outerNum = Number(outerTotalLen);
        const hiddenStart = outerNum;
        const hiddenLen = fileSize - Config.CONTAINER_FOOTER_SIZE - outerNum;
        if (hiddenLen < minBlob) {
            return null;
        }

        const magicCheck = Buffer.alloc(4);
        const fd2 = fs.openSync(inputPath, 'r');
        fs.readSync(fd2, magicCheck, 0, 4, hiddenStart);
        fs.closeSync(fd2);
        if (!magicCheck.equals(Config.MAGIC)) {
            return null;
        }

        return {
            outerTotalLen: outerNum,
            hiddenStart,
            hiddenLen,
            fileSize
        };
    }

    static inspectThreshold(inputPath) {
        if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isFile()) {
            return null;
        }

        const fd = fs.openSync(inputPath, 'r');
        try {
            const prefix = Buffer.alloc(Config.FIXED_HEADER_SIZE);
            const bytesRead = fs.readSync(fd, prefix, 0, prefix.length, 0);
            if (bytesRead < Config.FIXED_HEADER_SIZE || !prefix.subarray(0, 4).equals(Config.MAGIC)) {
                return null;
            }

            const metadata = HeaderParser.parseFormat(prefix, { textPayload: false });
            if (metadata.isLegacy || !(metadata.flags & Config.FLAG_THRESHOLD)) {
                return null;
            }

            const shareCountsOffset = metadata.headerLen + metadata.saltLen + metadata.nonceLen;
            const shareCounts = Buffer.alloc(2);
            const shareBytesRead = fs.readSync(fd, shareCounts, 0, 2, shareCountsOffset);
            if (shareBytesRead !== 2) {
                throw new Error('Threshold metadata is incomplete');
            }

            return {
                numPasswords: shareCounts[0],
                threshold: shareCounts[1]
            };
        } finally {
            fs.closeSync(fd);
        }
    }

    static inspectBlob(inputPath, { blobStart = 0, blobSpan = null } = {}) {
        const fileSize = fs.statSync(inputPath).size;
        const span = blobSpan == null ? fileSize - blobStart : blobSpan;
        if (span <= 0) {
            throw new Error('Invalid encrypted file structure');
        }

        const fd = fs.openSync(inputPath, 'r');
        try {
            let prefix = Buffer.alloc(Math.min(Config.FIXED_HEADER_SIZE, span));
            const bytesRead = fs.readSync(fd, prefix, 0, prefix.length, blobStart);
            prefix = prefix.subarray(0, bytesRead);

            if (prefix.length < Config.FIXED_HEADER_SIZE) {
                throw new Error('File is too small to inspect');
            }
            if (!prefix.subarray(0, 4).equals(Config.MAGIC)) {
                throw new Error('Unrecognized file format. Only CT02 encrypted files can be inspected reliably.');
            }

            let metadata = HeaderParser.parseFormat(prefix, { textPayload: false });
            if (!metadata.isLegacy && prefix.length < metadata.headerLen) {
                prefix = Buffer.alloc(metadata.headerLen);
                fs.readSync(fd, prefix, 0, metadata.headerLen, blobStart);
                metadata = HeaderParser.parseCT02(prefix);
            }

            const result = {
                format: metadata.format,
                version: metadata.version,
                legacy: metadata.isLegacy,
                compression: metadata.compress ? 'enabled' : 'disabled',
                keyfile: metadata.useKeyfile ? 'enabled' : 'disabled',
                kdf: metadata.kdfId === Config.KDF_PBKDF2 ? 'PBKDF2-SHA256' : (metadata.kdfId === Config.KDF_ARGON2 ? 'Argon2id' : `unknown(${metadata.kdfId})`),
                iterations: metadata.iterations,
                saltLength: metadata.saltLen,
                nonceLength: metadata.nonceLen,
                tagLength: metadata.tagLen,
                headerLength: metadata.headerLen,
                blobSize: span,
                thresholdMode: (metadata.flags & Config.FLAG_THRESHOLD) ? 'enabled' : 'disabled'
            };

            let metadataBytes = metadata.headerLen + metadata.saltLen + metadata.nonceLen + metadata.tagLen;
            if (metadata.flags & Config.FLAG_THRESHOLD) {
                const numSharesAndThreshold = Buffer.alloc(2);
                const shareBytesRead = fs.readSync(fd, numSharesAndThreshold, 0, 2, blobStart + metadata.headerLen + metadata.saltLen + metadata.nonceLen);
                if (shareBytesRead !== 2) {
                    throw new Error('Threshold metadata is incomplete');
                }
                const numPasswords = numSharesAndThreshold[0];
                const thresholdRequired = numSharesAndThreshold[1];
                const shareSize = Config.SALT_SIZE + Config.NONCE_SIZE + Config.KEY_SIZE + 1 + Config.TAG_SIZE;
                const shareMetadataSize = 2 + (numPasswords * shareSize);
                metadataBytes += shareMetadataSize;
                result.numPasswords = numPasswords;
                result.thresholdRequired = thresholdRequired;
                result.shareMetadataSize = shareMetadataSize;
            }

            const ciphertextSize = span - metadataBytes;
            if (ciphertextSize < 0) {
                throw new Error('Invalid encrypted file structure');
            }
            result.ciphertextSize = ciphertextSize;
            return result;
        } finally {
            fs.closeSync(fd);
        }
    }
}

// =========================
// KeyFileUtils
// =========================

class KeyFileUtils {
    static generate(outputPath, keySize = 16) {
        try {
            const key = crypto.randomBytes(keySize);
            const recoveryKey = key.toString('base64url');
            fs.writeFileSync(outputPath, `${recoveryKey}\n`, 'utf8');
            ConsoleLogger.show('success', `Recovery key file generated: ${outputPath}`);
            ConsoleLogger.show('info', `Key size: ${keySize} bytes (${keySize * 8} bits)`);
            return true;
        } catch (err) {
            ConsoleLogger.show('error', `Failed to generate key file: ${err.message}`);
            return false;
        }
    }

    static read(keyfilePath) {
        try {
            if (!fs.existsSync(keyfilePath)) {
                throw new Error(`Key file not found: ${keyfilePath}`);
            }

            const rawData = fs.readFileSync(keyfilePath);
            if (rawData.length > 4096) {
                throw new Error(`Key file too large: ${rawData.length} bytes (maximum 4096)`);
            }

            let keyData = rawData;
            const textData = rawData.toString('utf8').trim();
            if (textData.length > 0) {
                if (!/^[A-Za-z0-9_-]+$/.test(textData)) {
                    throw new Error('Recovery key contains invalid characters');
                }
                keyData = Buffer.from(textData, 'base64url');
            }

            if (keyData.length < 16) {
                throw new Error(`Key file too small: ${keyData.length} bytes (minimum 16)`);
            }

            if (keyData.length > 1024) {
                throw new Error(`Key file too large: ${keyData.length} bytes (maximum 1024)`);
            }

            ConsoleLogger.show('debug', `Read key file: ${keyfilePath} (${keyData.length} bytes)`);
            return keyData;
        } catch (err) {
            ConsoleLogger.show('error', `Failed to read key file: ${err.message}`);
            return null;
        }
    }

    static combinePasswordAndKeyfile(password, keyfileData) {
        const passwordBuffer = Buffer.from(password, 'utf-8');
        const combined = Buffer.concat([passwordBuffer, keyfileData]);
        const hashed = crypto.createHash('sha256').update(combined).digest();
        return hashed.toString('hex');
    }
}

// =========================
// Core Logic (Engine)
// =========================

class CryptoEngine {
    async _deriveKey(password, salt, keyfileData = null, kdfType = Config.KDF_PBKDF2, iterations = Config.PBKDF2_ITERATIONS) {
        let derivedFrom;
        if (keyfileData) {
            ConsoleLogger.show('debug', 'Using key file for key derivation');
            derivedFrom = KeyFileUtils.combinePasswordAndKeyfile(password, keyfileData);
        } else {
            derivedFrom = password;
        }

        if (kdfType === Config.KDF_ARGON2) {
            if (!ARGON2_AVAILABLE) {
                ConsoleLogger.show('error', 'Argon2 is not available. Please install argon2: npm install argon2');
                throw new Error('Argon2 support not installed');
            }
            ConsoleLogger.show('debug', `Deriving key with Argon2id (${iterations} iterations)`);

            const hash = await argon2.hash(derivedFrom, {
                salt: salt,
                type: argon2.argon2id,
                timeCost: iterations,
                memoryCost: Config.ARGON2_MEMORY_COST,
                parallelism: Config.ARGON2_PARALLELISM,
                hashLength: Config.KEY_SIZE,
                raw: true
            });
            return hash;
        }

        ConsoleLogger.show('debug', `Deriving key with PBKDF2 (${iterations} iterations)`);

        return crypto.pbkdf2Sync(
            derivedFrom,
            salt,
            iterations,
            Config.KEY_SIZE,
            'sha256'
        );
    }

    _formatSize(size) {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let unitIndex = 0;
        let sizeNum = size;
        while (sizeNum >= 1024 && unitIndex < units.length - 1) {
            sizeNum /= 1024;
            unitIndex++;
        }
        return `${sizeNum.toFixed(2)}${units[unitIndex]}`;
    }

    async encryptData(data, password, keyfileData = null, kdfType = Config.KDF_PBKDF2, iterations = Config.PBKDF2_ITERATIONS) {
        ConsoleLogger.show('debug', `Starting in-memory data encryption (${data.length} bytes input)`);
        const salt = crypto.randomBytes(Config.SALT_SIZE);
        const nonce = crypto.randomBytes(Config.NONCE_SIZE);
        const useKeyfile = keyfileData !== null;
        const header = HeaderParser.buildHeader({ isText: true, useKeyfile, kdfId: kdfType, iterations });
        ConsoleLogger.show('debug', `Generated salt (${Config.SALT_SIZE} bytes) and nonce (${Config.NONCE_SIZE} bytes)`);
        const key = await this._deriveKey(password, salt, keyfileData, kdfType, iterations);

        ConsoleLogger.show('debug', 'Initializing AES-GCM cipher');
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        ConsoleLogger.show('debug', `Encryption complete. Ciphertext size: ${encrypted.length} bytes, Tag size: ${tag.length} bytes`);

        return Buffer.concat([header, salt, nonce, encrypted, tag]);
    }

    async decryptData(encData, password, keyfileData = null) {
        try {
            ConsoleLogger.show('debug', `Starting in-memory data decryption. Total input size: ${encData.length} bytes`);
            const metadata = HeaderParser.parseFormat(encData, { textPayload: true });
            const overhead = metadata.headerLen + metadata.saltLen + metadata.nonceLen + metadata.tagLen;
            if (encData.length < overhead) {
                ConsoleLogger.show('debug', 'Input data is smaller than minimum overhead');
                throw new Error('Data too short');
            }

            let salt;
            let nonce;
            let tag;
            let ciphertext;
            if (metadata.isLegacy) {
                salt = encData.subarray(0, metadata.saltLen);
                nonce = encData.subarray(metadata.saltLen, metadata.saltLen + metadata.nonceLen);
                tag = encData.subarray(metadata.saltLen + metadata.nonceLen, overhead);
                ciphertext = encData.subarray(overhead);
            } else {
                const saltStart = metadata.headerLen;
                const nonceStart = saltStart + metadata.saltLen;
                const nonceEnd = nonceStart + metadata.nonceLen;
                salt = encData.subarray(saltStart, nonceStart);
                nonce = encData.subarray(nonceStart, nonceEnd);
                tag = encData.subarray(encData.length - metadata.tagLen);
                ciphertext = encData.subarray(nonceEnd, encData.length - metadata.tagLen);
            }
            ConsoleLogger.show('debug', `Extracted salt, nonce, tag, and ciphertext (${ciphertext.length} bytes)`);

            const useKeyfile = metadata.useKeyfile || false;
            const kdfType = metadata.kdfId || Config.KDF_PBKDF2;
            const iterations = metadata.iterations || Config.PBKDF2_ITERATIONS;
            if (useKeyfile && !keyfileData) {
                ConsoleLogger.show('warning', 'Encrypted with key file but none provided. Attempting password-only decryption.');
            }

            const key = await this._deriveKey(password, salt, keyfileData || null, kdfType, iterations);
            ConsoleLogger.show('debug', 'Initializing AES-GCM cipher for decryption');
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(tag);

            ConsoleLogger.show('debug', 'Verifying tag and decrypting ciphertext');
            const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            ConsoleLogger.show('debug', `Decryption successful. Plaintext size: ${decrypted.length} bytes`);
            return decrypted;

        } catch (err) {
            ConsoleLogger.show('error', 'Decryption failed!');
            return null;
        }
    }

    async encryptFile(inputPath, outputPath, password, compress = false, keyfileData = null, kdfType = Config.KDF_PBKDF2, iterations = Config.PBKDF2_ITERATIONS) {
        try {
            ConsoleLogger.show('debug', `Starting file encryption: ${inputPath} -> ${outputPath}`);
            const stats = fs.statSync(inputPath);
            const fileSize = stats.size;

            ConsoleLogger.show('debug', `Generating ${Config.SALT_SIZE} bytes salt and ${Config.NONCE_SIZE} bytes nonce`);
            const salt = crypto.randomBytes(Config.SALT_SIZE);
            const nonce = crypto.randomBytes(Config.NONCE_SIZE);
            const useKeyfile = keyfileData !== null;
            const key = await this._deriveKey(password, salt, keyfileData, kdfType, iterations);
            ConsoleLogger.show('debug', 'Initializing AES-GCM cipher');
            const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
            const header = HeaderParser.buildHeader({ compress, useKeyfile, kdfId: kdfType, iterations });

            const desc = compress ? '[🔒] Compressing & Encrypting' : '[🔒] Encrypting';
            const label = compress ? '[🔒] Compressing & Encrypting:' : '[🔒] Encrypting:';
            if (compress) {
                ConsoleLogger.show('debug', 'Compression enabled (zlib level 9)');
            }
            const progress = ProgressBarUtils.create(label, fileSize);
            progress.render();

            const outputStream = fs.createWriteStream(outputPath);
            outputStream.write(header);
            outputStream.write(salt);
            outputStream.write(nonce);

            const readStream = fs.createReadStream(inputPath, { highWaterMark: Config.CHUNK_SIZE });
            readStream.on('data', (chunk) => progress.tick(chunk.length));

            let sourceStream = readStream;
            if (compress) {
                const deflater = zlib.createDeflate({ level: 9 });
                sourceStream = sourceStream.pipe(deflater);
            }

            sourceStream.pipe(cipher).pipe(outputStream, { end: false });
            await finished(cipher);

            const tag = cipher.getAuthTag();
            ConsoleLogger.show('debug', `Generated authentication tag (${tag.length} bytes)`);
            outputStream.write(tag);
            outputStream.end();
            await finished(outputStream);
            return true;

        } catch (err) {
            ConsoleLogger.show('error', `File encryption error: ${err.message}`);
            ConsoleLogger.show('error', `Failed to encrypt: ${inputPath}`);
            if (fs.existsSync(outputPath)) {
                fs.unlinkSync(outputPath);
            }
            return false;
        }
    }

    async decryptFile(inputPath, outputPath, password, compress = false, keyfileData = null, sliceStart = 0, sliceEnd = null) {
        try {
            const fileSizeOnDisk = fs.statSync(inputPath).size;
            const end = sliceEnd == null ? fileSizeOnDisk : sliceEnd;
            if (sliceStart < 0 || end > fileSizeOnDisk || sliceStart >= end) {
                throw new Error('Invalid decrypt byte range');
            }
            const fileSize = end - sliceStart;
            ConsoleLogger.show('debug', `Starting file decryption: ${inputPath} (blob size: ${this._formatSize(fileSize)}) -> ${outputPath}`);
            const minimumOverhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE;

            if (fileSize < minimumOverhead) {
                ConsoleLogger.show('debug', 'File size is smaller than required header + footer overhead');
                throw new Error('File too small');
            }

            const fd = fs.openSync(inputPath, 'r');
            let prefix = Buffer.alloc(Math.min(Config.FIXED_HEADER_SIZE, fileSize));
            fs.readSync(fd, prefix, 0, prefix.length, sliceStart);
            let metadata = HeaderParser.parseFormat(prefix, { textPayload: false });
            if (metadata.isLegacy && sliceStart !== 0) {
                fs.closeSync(fd);
                throw new Error('Legacy format does not support container slices');
            }
            if (!metadata.isLegacy && prefix.length < metadata.headerLen) {
                prefix = Buffer.alloc(metadata.headerLen);
                fs.readSync(fd, prefix, 0, metadata.headerLen, sliceStart);
                metadata = HeaderParser.parseCT02(prefix);
            }

            const useKeyfile = metadata.useKeyfile || false;
            const kdfType = metadata.kdfId || Config.KDF_PBKDF2;
            const iterations = metadata.iterations || Config.PBKDF2_ITERATIONS;

            const salt = Buffer.alloc(metadata.saltLen);
            const nonce = Buffer.alloc(metadata.nonceLen);
            const tag = Buffer.alloc(metadata.tagLen);
            const hdrOff = sliceStart + metadata.headerLen;
            fs.readSync(fd, salt, 0, metadata.saltLen, hdrOff);
            fs.readSync(fd, nonce, 0, metadata.nonceLen, hdrOff + metadata.saltLen);
            fs.readSync(fd, tag, 0, metadata.tagLen, sliceStart + fileSize - metadata.tagLen);
            fs.closeSync(fd);

            const ciphertextLen = fileSize - metadata.headerLen - metadata.saltLen - metadata.nonceLen - metadata.tagLen;
            ConsoleLogger.show('debug', `Read salt (${salt.length} bytes), nonce (${nonce.length} bytes), ciphertext (${ciphertextLen} bytes), and tag (${tag.length} bytes)`);

            if (useKeyfile && !keyfileData) {
                ConsoleLogger.show('warning', 'Encrypted with key file but none provided. Attempting password-only decryption.');
            }

            const key = await this._deriveKey(password, salt, keyfileData || null, kdfType, iterations);
            ConsoleLogger.show('debug', 'Initializing AES-GCM cipher for decryption');

            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(tag);
            ConsoleLogger.show('debug', `Ciphertext length to decrypt: ${this._formatSize(ciphertextLen)}`);

            const effectiveCompress = metadata.isLegacy ? compress : metadata.compress;
            const desc = effectiveCompress ? '[🔓] Decrypting & Decompressing' : '[🔓] Decrypting';
            const label = effectiveCompress ? '[🔓] Decrypting & Decompressing:' : '[🔓] Decrypting:';
            if (effectiveCompress) {
                ConsoleLogger.show('debug', 'Decompression enabled (zlib inflate)');
            }
            const progress = ProgressBarUtils.create(label, ciphertextLen);
            progress.render();

            const cipherStart = sliceStart + metadata.headerLen + metadata.saltLen + metadata.nonceLen;
            const cipherEnd = sliceStart + fileSize - metadata.tagLen - 1;
            const readStream = fs.createReadStream(inputPath, {
                start: cipherStart,
                end: cipherEnd,
                highWaterMark: Config.CHUNK_SIZE
            });
            readStream.on('data', (chunk) => progress.tick(chunk.length));

            try {
                const outputStream = fs.createWriteStream(outputPath);
                if (effectiveCompress) {
                    const inflater = zlib.createInflate();
                    await pipeline(readStream, decipher, inflater, outputStream);
                } else {
                    await pipeline(readStream, decipher, outputStream);
                }
            } catch (err) {
                if (progress && progress.bar && typeof progress.bar.terminate === 'function') {
                    if (!progress.bar.complete) {
                        progress.bar.terminate();
                    }
                } else if (process && process.stderr && process.stderr.write) {
                    process.stderr.write('\n');
                }
                ConsoleLogger.show('error', 'INTEGRITY CHECK FAILED! Password wrong or file corrupted.');
                ConsoleLogger.show('error', `Decryption failed for: ${inputPath}`);
                if (fs.existsSync(outputPath)) {
                    try { fs.unlinkSync(outputPath); } catch (e) { }
                }
                return false;
            }
            ConsoleLogger.show('success', 'Integrity Verified. Decryption successful.');
            return true;

        } catch (err) {
            ConsoleLogger.show('error', `File decryption error: ${err.message}`);
            ConsoleLogger.show('error', `Failed to decrypt: ${inputPath}`);
            if (fs.existsSync(outputPath)) {
                try { fs.unlinkSync(outputPath); } catch (e) { }
            }
            return false;
        }
    }

    async encryptHiddenContainer(decoyPath, hiddenPath, outputPath, passwordOuter, passwordHidden, compress = false, keyfileData = null, kdfType = Config.KDF_PBKDF2, iterations = Config.PBKDF2_ITERATIONS) {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'crypt-tools-hv-'));
        const tmpOuter = path.join(tmpDir, 'outer.enc');
        const tmpHidden = path.join(tmpDir, 'hidden.enc');
        try {
            const okO = await this.encryptFile(decoyPath, tmpOuter, passwordOuter, compress, keyfileData, kdfType, iterations);
            if (!okO) return false;
            const okH = await this.encryptFile(hiddenPath, tmpHidden, passwordHidden, compress, keyfileData, kdfType, iterations);
            if (!okH) return false;

            const outerLen = fs.statSync(tmpOuter).size;
            await pipeline(fs.createReadStream(tmpOuter, { highWaterMark: Config.CHUNK_SIZE }), fs.createWriteStream(outputPath));
            await pipeline(fs.createReadStream(tmpHidden, { highWaterMark: Config.CHUNK_SIZE }), fs.createWriteStream(outputPath, { flags: 'a' }));
            const foot = Buffer.alloc(Config.CONTAINER_FOOTER_SIZE);
            Config.CONTAINER_FOOTER_MAGIC.copy(foot, 0);
            foot.writeBigUInt64BE(BigInt(outerLen), 4);
            await fs.promises.appendFile(outputPath, foot);

            const total = outerLen + fs.statSync(tmpHidden).size + Config.CONTAINER_FOOTER_SIZE;
            ConsoleLogger.show('success', `Hidden container written (${this._formatSize(total)})`);
            return true;
        } catch (err) {
            ConsoleLogger.show('error', `Hidden container encryption error: ${err.message}`);
            if (fs.existsSync(outputPath)) {
                try { fs.unlinkSync(outputPath); } catch (e) { }
            }
            return false;
        } finally {
            try {
                fs.rmSync(tmpDir, { recursive: true, force: true });
            } catch (e) { }
        }
    }

    async decryptHiddenContainer(inputPath, outputPath, password, { hidden = false, compress = false, keyfileData = null } = {}) {
        const info = HeaderParser.parseHiddenFooter(inputPath);
        if (!info) {
            ConsoleLogger.show('error', 'Not a hidden-volume container (missing or invalid CTHV footer).');
            return false;
        }
        if (hidden) {
            return this.decryptFile(
                inputPath,
                outputPath,
                password,
                compress,
                keyfileData,
                info.hiddenStart,
                info.fileSize - Config.CONTAINER_FOOTER_SIZE
            );
        }
        return this.decryptFile(
            inputPath,
            outputPath,
            password,
            compress,
            keyfileData,
            0,
            info.outerTotalLen
        );
    }

    inspectFile(inputPath) {
        if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isFile()) {
            const err = new Error(`ENOENT: no such file or directory, stat '${inputPath}'`);
            err.code = 'ENOENT';
            throw err;
        }

        const fileSize = fs.statSync(inputPath).size;
        const footerInfo = HeaderParser.parseHiddenFooter(inputPath);
        const outerSpan = footerInfo ? footerInfo.outerTotalLen : fileSize;
        const result = HeaderParser.inspectBlob(inputPath, { blobStart: 0, blobSpan: outerSpan });
        result.fileSize = fileSize;
        result.container = footerInfo ? 'hidden' : 'standard';

        if (footerInfo) {
            result.outerBlobSize = footerInfo.outerTotalLen;
            result.hiddenBlobSize = footerInfo.hiddenLen;
            result.hiddenMetadata = HeaderParser.inspectBlob(inputPath, {
                blobStart: footerInfo.hiddenStart,
                blobSpan: footerInfo.hiddenLen
            });
            result.footerNote = 'CTHV/Ciphertext. This file embeds a second encrypted blob; deniability vs forensic analysis is limited versus full-disk hidden volumes.';
        }

        return result;
    }

    async encryptWithThreshold(inputPath, outputPath, passwords, threshold, compress = false, keyfileData = null, kdfType = Config.KDF_PBKDF2, iterations = Config.PBKDF2_ITERATIONS) {
        try {
            const numPasswords = passwords.length;
            if (threshold > numPasswords) {
                throw new Error('Threshold cannot exceed number of passwords');
            }
            if (threshold < 2) {
                throw new Error('Threshold must be at least 2');
            }

            ConsoleLogger.show('debug', `Starting threshold file encryption: ${numPasswords} passwords, threshold ${threshold}`);

            const masterKey = crypto.randomBytes(Config.KEY_SIZE);
            ConsoleLogger.show('debug', 'Generated master key for threshold encryption');

            const shares = ShamirSecretSharing.generateShares(masterKey, numPasswords, threshold);
            ConsoleLogger.show('debug', `Generated ${numPasswords} shares using Shamir's Secret Sharing`);

            const fileSize = fs.statSync(inputPath).size;
            const salt = crypto.randomBytes(Config.SALT_SIZE);
            const nonce = crypto.randomBytes(Config.NONCE_SIZE);
            const key = await this._deriveKey('threshold-dummy', salt, null, kdfType, iterations);

            const header = HeaderParser.buildHeader({ compress, useKeyfile: keyfileData !== null, kdfId: kdfType, iterations });
            header[5] |= Config.FLAG_THRESHOLD;

            const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

            const label = compress ? '[🔒] Compressing & Encrypting:' : '[🔒] Encrypting:';
            const progress = ProgressBarUtils.create(label, fileSize);
            progress.render();

            const outputStream = fs.createWriteStream(outputPath);
            outputStream.write(header);
            outputStream.write(salt);
            outputStream.write(nonce);

            outputStream.write(Buffer.from([numPasswords, threshold]));

            for (let i = 0; i < numPasswords; i++) {
                const passwordSalt = crypto.randomBytes(Config.SALT_SIZE);
                const passwordKey = await this._deriveKey(passwords[i], passwordSalt, keyfileData, kdfType, iterations);
                const encryptedShare = this._encryptShareWithPassword(shares[i], passwordKey);
                outputStream.write(passwordSalt);
                outputStream.write(encryptedShare);
            }

            const readStream = fs.createReadStream(inputPath, { highWaterMark: Config.CHUNK_SIZE });
            readStream.on('data', (chunk) => progress.tick(chunk.length));

            let sourceStream = readStream;
            if (compress) {
                const deflater = zlib.createDeflate({ level: 9 });
                sourceStream = sourceStream.pipe(deflater);
            }

            sourceStream.pipe(cipher).pipe(outputStream, { end: false });
            await finished(cipher);

            const tag = cipher.getAuthTag();
            outputStream.write(tag);
            outputStream.end();
            await finished(outputStream);

            ConsoleLogger.show('success', `Threshold encryption complete (${numPasswords} passwords, ${threshold} required)`);
            return true;

        } catch (err) {
            ConsoleLogger.show('error', `Threshold encryption error: ${err.message}`);
            if (fs.existsSync(outputPath)) {
                fs.unlinkSync(outputPath);
            }
            return false;
        }
    }

    _encryptShareWithPassword(share, passwordKey) {
        const nonce = crypto.randomBytes(Config.NONCE_SIZE);
        const cipher = crypto.createCipheriv('aes-256-gcm', passwordKey, nonce);
        const encrypted = Buffer.concat([cipher.update(share), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([nonce, encrypted, tag]);
    }

    _decryptShareWithPassword(encryptedData, passwordKey) {
        const nonce = encryptedData.subarray(0, Config.NONCE_SIZE);
        const ciphertext = encryptedData.subarray(Config.NONCE_SIZE, -Config.TAG_SIZE);
        const tag = encryptedData.subarray(-Config.TAG_SIZE);

        const decipher = crypto.createDecipheriv('aes-256-gcm', passwordKey, nonce);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    async decryptWithThreshold(inputPath, outputPath, passwords, compress = false, keyfileData = null, sliceStart = 0, sliceEnd = null) {
        try {
            const fileSizeOnDisk = fs.statSync(inputPath).size;
            const end = sliceEnd == null ? fileSizeOnDisk : sliceEnd;
            if (sliceStart < 0 || end > fileSizeOnDisk || sliceStart >= end) {
                throw new Error('Invalid decrypt byte range');
            }

            const fileSize = end - sliceStart;
            ConsoleLogger.show('debug', `Starting threshold file decryption: ${inputPath}`);

            const fd = fs.openSync(inputPath, 'r');
            let prefix = Buffer.alloc(Math.min(Config.FIXED_HEADER_SIZE, fileSize));
            fs.readSync(fd, prefix, 0, prefix.length, sliceStart);

            const metadata = HeaderParser.parseFormat(prefix, { textPayload: false });
            if (!(metadata.flags & Config.FLAG_THRESHOLD)) {
                throw new Error('File is not encrypted with threshold mode');
            }

            if (prefix.length < metadata.headerLen) {
                prefix = Buffer.alloc(metadata.headerLen);
                fs.readSync(fd, prefix, 0, metadata.headerLen, sliceStart);
            }

            const salt = Buffer.alloc(metadata.saltLen);
            const nonce = Buffer.alloc(metadata.nonceLen);
            fs.readSync(fd, salt, 0, metadata.saltLen, sliceStart + metadata.headerLen);
            fs.readSync(fd, nonce, 0, metadata.nonceLen, sliceStart + metadata.headerLen + metadata.saltLen);

            const numSharesAndThreshold = Buffer.alloc(2);
            fs.readSync(fd, numSharesAndThreshold, 0, 2, sliceStart + metadata.headerLen + metadata.saltLen + metadata.nonceLen);
            const numPasswords = numSharesAndThreshold[0];
            const threshold = numSharesAndThreshold[1];

            ConsoleLogger.show('info', `Threshold encrypted: ${numPasswords} passwords, ${threshold} required to decrypt`);

            let shareDataOffset = sliceStart + metadata.headerLen + metadata.saltLen + metadata.nonceLen + 2;
            const encryptedShares = [];

            for (let i = 0; i < numPasswords; i++) {
                const passwordSalt = Buffer.alloc(Config.SALT_SIZE);
                fs.readSync(fd, passwordSalt, 0, Config.SALT_SIZE, shareDataOffset);
                shareDataOffset += Config.SALT_SIZE;

                const encryptedShareLen = Config.NONCE_SIZE + Config.KEY_SIZE + 1 + Config.TAG_SIZE;
                const encryptedShare = Buffer.alloc(encryptedShareLen);
                fs.readSync(fd, encryptedShare, 0, encryptedShareLen, shareDataOffset);
                shareDataOffset += encryptedShareLen;

                encryptedShares.push({ salt: passwordSalt, data: encryptedShare });
            }

            fs.closeSync(fd);

            const masterKey = await this._tryReconstructMasterKey(inputPath, outputPath, encryptedShares, passwords, threshold, keyfileData, metadata);
            if (!masterKey) {
                throw new Error('Failed to decrypt with provided passwords');
            }

            const key = await this._deriveKey('threshold-dummy', salt, null, metadata.kdfId || Config.KDF_PBKDF2, metadata.iterations || Config.PBKDF2_ITERATIONS);

            const fileData = fs.readFileSync(inputPath);
            const ciphertextLen = fileSize - metadata.headerLen - metadata.saltLen - metadata.nonceLen - metadata.tagLen - 2 - (numPasswords * (Config.SALT_SIZE + Config.NONCE_SIZE + Config.KEY_SIZE + 1 + Config.TAG_SIZE));
            const cipherStart = shareDataOffset;
            const ciphertext = fileData.subarray(cipherStart, cipherStart + ciphertextLen);
            const tag = fileData.subarray(-metadata.tagLen);
            ConsoleLogger.show('debug', `cipherStart=${cipherStart}, ciphertextLen=${ciphertextLen}`);
            
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(tag);

            const effectiveCompress = metadata.compress;
            const label = effectiveCompress ? '[🔓] Decrypting & Decompressing:' : '[🔓] Decrypting:';
            const progress = ProgressBarUtils.create(label, ciphertextLen);
            progress.render();
            
            progress.tick(ciphertextLen);
            
            const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
            
            if (effectiveCompress) {
                const decompressed = zlib.inflateSync(decrypted);
                fs.writeFileSync(outputPath, decompressed);
            } else {
                fs.writeFileSync(outputPath, decrypted);
            }

            ConsoleLogger.show('success', 'Threshold decryption successful');
            return true;

        } catch (err) {
            ConsoleLogger.show('error', `Threshold decryption error: ${err.message}`);
            if (fs.existsSync(outputPath)) {
                try { fs.unlinkSync(outputPath); } catch (e) { }
            }
            return false;
        }
    }

    async _tryReconstructMasterKey(inputPath, outputPath, encryptedShares, passwords, threshold, keyfileData, metadata) {
        const kdfType = metadata.kdfId || Config.KDF_PBKDF2;
        const iterations = metadata.iterations || Config.PBKDF2_ITERATIONS;

        const shareDataList = [];
        const usedShareIndexes = new Set();
        const recoveredShareIds = new Set();
        for (const pw of passwords) {
            for (let idx = 0; idx < encryptedShares.length; idx++) {
                if (usedShareIndexes.has(idx)) {
                    continue;
                }

                const encShare = encryptedShares[idx];
                try {
                    const passwordKey = await this._deriveKey(pw, encShare.salt, keyfileData, kdfType, iterations);
                    const share = this._decryptShareWithPassword(encShare.data, passwordKey);
                    const shareId = share[0];
                    if (recoveredShareIds.has(shareId)) {
                        break;
                    }

                    recoveredShareIds.add(shareId);
                    usedShareIndexes.add(idx);
                    shareDataList.push(share);
                    ConsoleLogger.show('debug', 'Successfully decrypted a share with password');
                    break;
                } catch (e) {
                    continue;
                }
            }
        }

        if (shareDataList.length < threshold) {
            ConsoleLogger.show('error', `Not enough valid passwords provided. Need ${threshold}, got ${shareDataList.length}`);
            return null;
        }

        try {
            const masterKey = ShamirSecretSharing.recoverSecret(shareDataList.slice(0, threshold));
            ConsoleLogger.show('debug', 'Successfully reconstructed master key');
            return masterKey;
        } catch (err) {
            ConsoleLogger.show('error', `Failed to reconstruct master key: ${err.message}`);
            return null;
        }
    }
}

// =========================
// Password Strength Validator
// =========================

class PasswordStrength {
    static STRENGTHS = {
        'VERY_WEAK': { label: 'Very Weak', color: '\x1b[91m\x1b[1m', reset: '\x1b[0m', icon: '❌' },
        'WEAK': { label: 'Weak', color: '\x1b[91m', reset: '\x1b[0m', icon: '⚠️' },
        'MEDIUM': { label: 'Medium', color: '\x1b[93m', reset: '\x1b[0m', icon: '⚡' },
        'STRONG': { label: 'Strong', color: '\x1b[92m', reset: '\x1b[0m', icon: '✅' },
        'VERY_STRONG': { label: 'Very Strong', color: '\x1b[92m\x1b[1m', reset: '\x1b[0m', icon: '🔒' }
    };

    static check(password) {
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);
        const length = password.length;

        let score = 0;

        // Length scoring
        if (length >= 8) score += 1;
        if (length >= 12) score += 1;
        if (length >= 16) score += 1;

        // Character type scoring
        if (hasLower) score += 1;
        if (hasUpper) score += 1;
        if (hasNumber) score += 1;
        if (hasSymbol) score += 1;

        // Determine strength
        let strength;
        if (score <= 2 || length < 6) {
            strength = 'VERY_WEAK';
        } else if (score <= 3 || length < 8) {
            strength = 'WEAK';
        } else if (score <= 5) {
            strength = 'MEDIUM';
        } else if (score <= 6) {
            strength = 'STRONG';
        } else {
            strength = 'VERY_STRONG';
        }

        return {
            score,
            strength,
            hasLower,
            hasUpper,
            hasNumber,
            hasSymbol,
            length
        };
    }

    static getIndicator(password) {
        const result = this.check(password);
        const strength = this.STRENGTHS[result.strength];
        return `${strength.color}${strength.icon} ${strength.label}${strength.reset}`;
    }

    static getCharTypes(password) {
        const result = this.check(password);
        const types = [];
        const checkIcon = '✓';
        const crossIcon = '✗';
        const green = TerminalColors.GREEN;
        const red = TerminalColors.RED;
        const reset = TerminalColors.RESET;

        if (result.hasLower) {
            types.push(`${green}${checkIcon} Lower${reset}`);
        } else {
            types.push(`${red}${crossIcon} Lower${reset}`);
        }

        if (result.hasUpper) {
            types.push(`${green}${checkIcon} Upper${reset}`);
        } else {
            types.push(`${red}${crossIcon} Upper${reset}`);
        }

        if (result.hasNumber) {
            types.push(`${green}${checkIcon} Number${reset}`);
        } else {
            types.push(`${red}${crossIcon} Number${reset}`);
        }

        if (result.hasSymbol) {
            types.push(`${green}${checkIcon} Symbol${reset}`);
        } else {
            types.push(`${red}${crossIcon} Symbol${reset}`);
        }

        return types.join(' ');
    }
}

// =========================
// =========================
// PasswordUtils
// =========================

class PasswordUtils {
    static #nonTtyPasswordLinesPromise = null;
    static #nonTtyPasswordLineIndex = 0;

    static _readNonTtyPasswordLine() {
        if (!PasswordUtils.#nonTtyPasswordLinesPromise) {
            PasswordUtils.#nonTtyPasswordLinesPromise = new Promise((resolve, reject) => {
                let data = '';
                process.stdin.setEncoding('utf8');
                process.stdin.on('data', (chunk) => {
                    data += chunk;
                });
                process.stdin.on('end', () => {
                    resolve(data.split(/\r?\n/));
                });
                process.stdin.on('error', reject);
            });
        }

        return PasswordUtils.#nonTtyPasswordLinesPromise.then((lines) => {
            if (PasswordUtils.#nonTtyPasswordLineIndex >= lines.length) {
                return '';
            }
            const line = lines[PasswordUtils.#nonTtyPasswordLineIndex];
            PasswordUtils.#nonTtyPasswordLineIndex += 1;
            return line.trim();
        });
    }

    static normalize(passwordValue) {
        if (Array.isArray(passwordValue)) {
            return passwordValue[0] || '';
        }
        return passwordValue || '';
    }

    static async prompt(prompt = 'Enter Password: ') {
        const white = TerminalColors.WHITE;
        const reset = TerminalColors.RESET;
        process.stdout.write(`${white}[${reset}🔑${white}]${reset} ${prompt}`);

        // Hide cursor
        process.stdout.write('\x1b[?25l');

        let password = '';

        // Check if stdin supports raw mode (TTY)
        if (!process.stdin.isTTY) {
            return PasswordUtils._readNonTtyPasswordLine().then((line) => {
                process.stdout.write('\x1b[?25h\n');
                return line;
            });
        }

        // TTY: use raw mode for interactive password input
        return new Promise((resolve) => {
            process.stdin.setRawMode(true);
            process.stdin.resume();

            function updateDisplay() {
                const strengthIndicator = PasswordStrength.getIndicator(password);
                const charTypes = PasswordStrength.getCharTypes(password);
                const asterisks = '*'.repeat(password.length);
                process.stdout.write(`\r${white}[${reset}🔑${white}]${reset} ${prompt}${asterisks}  ${strengthIndicator}  ${charTypes}\x1b[K`);
            }

            process.stdin.on('data', (char) => {
                char = char.toString('utf-8');

                if (char === '\r' || char === '\n' || char.charCodeAt(0) === 13) {
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\x1b[?25h\n');
                    process.stdin.removeAllListeners('data');
                    resolve(password);
                } else if (char.charCodeAt(0) === 3) {
                    // Ctrl+C
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\x1b[?25h\n');
                    process.stdin.removeAllListeners('data');
                    process.exit(0);
                } else if (char.charCodeAt(0) === 4) {
                    // Ctrl+D
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\x1b[?25h\n');
                    process.stdin.removeAllListeners('data');
                    resolve(password);
                } else if (char.charCodeAt(0) === 127 || char.charCodeAt(0) === 8) {
                    // Backspace
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                        updateDisplay();
                    }
                } else if (char >= ' ' && char.length === 1) {
                    password += char;
                    updateDisplay();
                }
            });
        });
    }

    static async verify(prompt1 = 'Enter Password: ', prompt2 = 'Verify Password: ') {
        const white = TerminalColors.WHITE;
        const reset = TerminalColors.RESET;

        const password = await PasswordUtils.prompt(prompt1);

        if (!password) {
            ConsoleLogger.show('error', 'Password cannot be empty.');
            ConsoleLogger.show('error', 'Operation aborted: No password provided');
            process.exit(1);
        }

        ConsoleLogger.show('info', 'Password entered by user', '🔑');

        process.stdout.write(`${white}[${reset}🔄${white}]${reset} ${prompt2}`);
        process.stdout.write('\x1b[?25l');

        let password2 = '';

        // Check if stdin supports raw mode (TTY)
        if (!process.stdin.isTTY) {
            // Non-TTY: fall back to simple line input
            return new Promise((resolve) => {
                const rl = readline.createInterface({
                    input: process.stdin,
                    terminal: false
                });

                rl.on('line', (line) => {
                    process.stdout.write('\x1b[?25h\n');
                    rl.close();
                    password2 = line.trim();

                    if (password !== password2) {
                        ConsoleLogger.show('error', 'Passwords do not match!');
                        ConsoleLogger.show('error', 'Operation aborted due to password mismatch');
                        process.exit(1);
                    }
                    resolve(password2);
                });

                rl.on('close', () => {
                    // If stream closed without input, use the first password (for single-line input)
                    if (!password2) {
                        password2 = password;
                    }
                    if (password !== password2) {
                        ConsoleLogger.show('error', 'Passwords do not match!');
                        ConsoleLogger.show('error', 'Operation aborted due to password mismatch');
                        process.exit(1);
                    }
                    resolve(password2);
                });
            });
        }

        // TTY: use raw mode for interactive password input
        return new Promise((resolve) => {
            process.stdin.setRawMode(true);
            process.stdin.resume();

            function updateDisplay() {
                const strengthIndicator = PasswordStrength.getIndicator(password2);
                const charTypes = PasswordStrength.getCharTypes(password2);
                const asterisks = '*'.repeat(password2.length);
                process.stdout.write(`\r${white}[${reset}🔄${white}]${reset} ${prompt2}${asterisks}  ${strengthIndicator}  ${charTypes}\x1b[K`);
            }

            process.stdin.on('data', (char) => {
                char = char.toString('utf-8');

                if (char === '\r' || char === '\n' || char.charCodeAt(0) === 13) {
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\x1b[?25h\n');
                    process.stdin.removeAllListeners('data');

                    if (password !== password2) {
                        ConsoleLogger.show('error', 'Passwords do not match!');
                        ConsoleLogger.show('error', 'Operation aborted due to password mismatch');
                        process.exit(1);
                    }
                    resolve(password2);
                } else if (char.charCodeAt(0) === 3) {
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\x1b[?25h\n');
                    process.stdin.removeAllListeners('data');
                    process.exit(0);
                } else if (char.charCodeAt(0) === 4) {
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\x1b[?25h\n');
                    process.stdin.removeAllListeners('data');
                    resolve(password2);
                } else if (char.charCodeAt(0) === 127 || char.charCodeAt(0) === 8) {
                    if (password2.length > 0) {
                        password2 = password2.slice(0, -1);
                        updateDisplay();
                    }
                } else if (char >= ' ' && char.length === 1) {
                    password2 += char;
                    updateDisplay();
                }
            });
        });
    }

    static async getThresholdPasswords(numPasswords, threshold, providedPasswords) {
        const passwords = providedPasswords ? [...providedPasswords] : [];
        for (let i = passwords.length; i < numPasswords; i++) {
            const pw = await PasswordUtils.prompt(`Enter password ${i + 1}/${numPasswords}: `);
            if (!pw) {
                ConsoleLogger.show('error', 'Password cannot be empty');
                process.exit(1);
            }
            passwords.push(pw);
        }
        return passwords;
    }
}

// =========================
// CLI Logic
// =========================

async function main() {
    program
        .description(Config.DESCRIPTION)
        .version(Config.VERSION)
        .configureHelp({
            formatHelp: (cmd) => UIHelpers.renderNodeHelp(cmd),
        })
        .option('-e, --encrypt', 'Encrypt mode (default)', true)
        .option('-d, --decrypt', 'Decrypt mode', false)
        .option('--inspect', 'Inspect encrypted file metadata', false)
        .option('--generate-keyfile [path]', 'Generate a random key file and exit (default: key.txt)')
        .option('-t, --text <text>', 'Text to process')
        .option('-f, --file <path>', 'File path, directory, or wildcard pattern (e.g., "*.md", "temp\\*.txt")')
        .option('-o, --output <path>', 'Output file path')
        .option('--config <path>', 'Path to a config file (.conf, .json, .yml, .yaml); defaults are auto-discovered')
        .option('--select', 'Browse and choose a file or directory interactively', false)
        .option('-p, --password <password>', 'Password (can be specified multiple times for threshold mode)', (val, arr) => [...arr, val], [])
        .option('--threshold <number>', 'Threshold for multi-signature mode (e.g., 2 for 2 of 3)', parseInt)
        .option('--keyfile <path>', 'Key file path for encryption/decryption (use with or without password)')
        .option('-c, --compress', 'Enable compression', false)
        .option('--hidden-vol', 'Encrypt decoy (-f) and hidden (--hidden-file) into one container (single file only)', false)
        .option('--hidden-file <path>', 'Hidden payload path (requires --hidden-vol on encrypt)')
        .option('--hidden', 'With -d -f, decrypt inner/hidden volume (password is the hidden password)', false)
        .option('--password-outer <password>', 'Decoy password for --hidden-vol (optional; exposing via CLI is insecure)')
        .option('--password-hidden <password>', 'Hidden password for --hidden-vol; with -d --hidden can be used instead of -p')
        .option('-r, --recursive', 'Recursively process directories or wildcard patterns (uses ** for subfolders)', false)
        .option('--kdf <type>', 'Key derivation function: pbkdf2 (default) or argon2 (more secure)')
        .option('--iterations <count>', 'Number of iterations for KDF (default: 100000 for PBKDF2, 3 for Argon2)', parseInt)
        .option('--qr', 'Render encrypted text output as a QR code (text encrypt mode only)', false)
        .option('--debug', 'Enable debug mode', false)
        .option('--log', 'Enable logging to file', false);

    // Show banner for help/version
    const helpOrVersion = process.argv.includes('-h') || process.argv.includes('--help') || process.argv.includes('-V') || process.argv.includes('--version');
    if (helpOrVersion) {
        Banner.show();
    }

    const rawArgv = process.argv.slice(2);
    const cliOverrides = ConfigParser.detectCliOverrides(rawArgv);
    program.parse(process.argv);
    const options = program.opts();
    let configPath;
    try {
        const defaults = ConfigParser.loadDefaults(options.config);
        configPath = defaults.configPath;
        ConfigParser.applyDefaults(options, cliOverrides, defaults.configDefaults, defaults.envDefaults);
    } catch (err) {
        Banner.show();
        ConsoleLogger.show('error', err.message);
        process.exit(1);
    }

    // Handle key file generation
    if (options.generateKeyfile) {
        const keyfilePath = options.generateKeyfile === true ? 'key.txt' : options.generateKeyfile;
        if (KeyFileUtils.generate(keyfilePath)) {
            process.exit(0);
        } else {
            process.exit(1);
        }
    }

    // Show banner first
    Banner.show();

    if (options.select && options.text) {
        ConsoleLogger.show('error', '--select cannot be used with --text');
        process.exit(1);
    }
    if (options.qr && (options.decrypt || !options.text)) {
        ConsoleLogger.show('error', '--qr is only supported with text encryption');
        process.exit(1);
    }
    if (options.select) {
        const shouldRedrawBanner = Boolean(process.stdin.isTTY && process.stdout.isTTY);
        try {
            const selectedPath = await UIHelpers.selectPathInteractive(options.file || '.');
            if (!selectedPath) {
                if (shouldRedrawBanner) {
                    Banner.show();
                }
                ConsoleLogger.show('error', 'Interactive file selection cancelled');
                process.exit(1);
            }
            if (shouldRedrawBanner) {
                Banner.show();
            }
            options.file = selectedPath;
            ConsoleLogger.show('info', `Selected path: ${selectedPath}`, '🧭');
        } catch (err) {
            if (shouldRedrawBanner) {
                Banner.show();
            }
            ConsoleLogger.show('error', err.message);
            process.exit(1);
        }
    }

    // Require either text or file (skip for --generate-keyfile)
    if (!options.generateKeyfile) {
        if (!options.text && !options.file) {
            ConsoleLogger.show('error', 'Either --text or --file is required');
            process.exit(1);
        }
        if (options.inspect && options.text) {
            ConsoleLogger.show('error', '--inspect only supports --file input');
            process.exit(1);
        }
        if (options.hiddenVol && options.text) {
            ConsoleLogger.show('error', '--hidden-vol applies only to file encryption');
            process.exit(1);
        }
        if (options.hiddenVol && options.decrypt) {
            ConsoleLogger.show('error', '--hidden-vol is for encryption only');
            process.exit(1);
        }
        if (options.hiddenVol && options.inspect) {
            ConsoleLogger.show('error', '--hidden-vol cannot be used with --inspect');
            process.exit(1);
        }
        if (options.hiddenFile && !options.hiddenVol) {
            ConsoleLogger.show('error', '--hidden-file requires --hidden-vol');
            process.exit(1);
        }
        if (options.hiddenVol && !options.hiddenFile) {
            ConsoleLogger.show('error', '--hidden-vol requires --hidden-file');
            process.exit(1);
        }
        if (options.hidden && !options.decrypt) {
            ConsoleLogger.show('error', '--hidden requires decrypt mode (-d)');
            process.exit(1);
        }
        if (options.hidden && options.text) {
            ConsoleLogger.show('error', '--hidden applies only to file decryption');
            process.exit(1);
        }
        if ((options.password ? options.password.length : 0) > 1 && !options.threshold && !options.decrypt) {
            ConsoleLogger.show('error', 'Multiple -p/--password values require --threshold');
            process.exit(1);
        }
        if (options.threshold) {
            if (options.threshold < 2) {
                ConsoleLogger.show('error', '--threshold must be at least 2');
                process.exit(1);
            }
            if (options.threshold > (options.password ? options.password.length : 0)) {
                ConsoleLogger.show('warning', `--threshold is ${options.threshold} but only ${options.password ? options.password.length : 0} passwords provided via -p`);
            }
            if (options.text) {
                ConsoleLogger.show('error', '--threshold applies only to file encryption/decryption');
                process.exit(1);
            }
            if (options.hiddenVol) {
                ConsoleLogger.show('error', '--threshold cannot be used with --hidden-vol');
                process.exit(1);
            }
        }
    }

    // Enable logging FIRST if --log flag is set
    if (options.log) {
        ConsoleLogger.LOG_ENABLED = true;
    }

    // Record start time
    const startTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    ConsoleLogger.show('info', `Session started at ${startTimestamp}`, '🕐');
    if (configPath) {
        ConsoleLogger.show('info', `Config file: ${configPath}`, '⚙️');
    }
    let sessionEnded = false;
    function finishSession() {
        if (sessionEnded) {
            return;
        }
        sessionEnded = true;
        const endTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        ConsoleLogger.show('info', `Session ended at ${endTimestamp}`, '🏁');
        if (ConsoleLogger.LOG_ENABLED) {
            ConsoleLogger.show('info', '='.repeat(80), null, false, true);
        }
    }
    function abort(code = 1) {
        finishSession();
        process.exit(code);
    }

    // Enable debug mode if --debug flag is set
    if (options.debug) {
        ConsoleLogger.DEBUG_ENABLED = true;
        ConsoleLogger.show('debug', 'Debug Mode Enabled. Verbose logging activated.');
        ConsoleLogger.show('info', 'Debug mode: Enabled');
    }

    // Show log file info (after LOG_ENABLED is set)
    if (options.log) {
        ConsoleLogger.show('debug', `Logging enabled. Writing to: ${ConsoleLogger.LOG_FILE}`);
        ConsoleLogger.show('info', `Log file: ${ConsoleLogger.LOG_FILE}`);
        ConsoleLogger.show('info', 'Logging to file: Enabled');
    }

    const engine = new CryptoEngine();

    let fileList = null;
    if (options.file) {
        const expanded = FileUtils.expandFilePattern(options.file, options.recursive);
        if (expanded.length === 0 && FileUtils.hasWildcard(options.file)) {
            ConsoleLogger.show('error', `No files matched pattern: ${options.file}`);
            ConsoleLogger.show('error', 'Operation failed: No matching files');
            abort(1);
        }
        fileList = expanded;
    }

    if (options.hiddenVol) {
        if (!options.file) {
            ConsoleLogger.show('error', '--hidden-vol requires -f/--file (decoy path)');
            abort(1);
        }
        if (options.recursive) {
            ConsoleLogger.show('error', '--hidden-vol cannot be used with --recursive');
            abort(1);
        }
        const wc = FileUtils.hasWildcard(options.file);
        if (wc || (fileList && fileList.length !== 1)) {
            ConsoleLogger.show('error', '--hidden-vol requires a single decoy file (no wildcards or multi-file batch)');
            abort(1);
        }
        const decoyP = fileList[0];
        if (!fs.existsSync(decoyP)) {
            ConsoleLogger.show('error', `Decoy file not found: ${decoyP}`);
            abort(1);
        }
        if (!fs.statSync(decoyP).isFile()) {
            ConsoleLogger.show('error', 'Decoy path must be a regular file for --hidden-vol');
            abort(1);
        }
        if (!fs.existsSync(options.hiddenFile) || !fs.statSync(options.hiddenFile).isFile()) {
            ConsoleLogger.show('error', `Hidden file not found or not a file: ${options.hiddenFile}`);
            abort(1);
        }
    }

    if (options.inspect && options.file) {
        const target = (fileList && fileList.length > 0) ? fileList[0] : options.file;
        let details;
        try {
            details = engine.inspectFile(target);
        } catch (err) {
            if (err.code === 'ENOENT') {
                ConsoleLogger.show('error', `File not found: ${target}`);
                ConsoleLogger.show('error', 'Operation failed: File does not exist');
            } else {
                ConsoleLogger.show('error', `Inspect failed: ${err.message}`);
                ConsoleLogger.show('error', `File is not a supported encrypted file: ${target}`);
            }
            abort(1);
        }

        ConsoleLogger.show('info', `Format: ${details.format}`, '🔍');
        ConsoleLogger.show('info', `Version: ${details.version}`, '📜');
        ConsoleLogger.show('info', `Legacy: ${details.legacy ? 'yes' : 'no'}`, '🕰️');
        ConsoleLogger.show('info', `Compression: ${details.compression}`, '🗜️');
        ConsoleLogger.show('info', `Keyfile: ${details.keyfile || 'disabled'}`, '🔑');
        ConsoleLogger.show('info', `KDF: ${details.kdf}`, '🧬');
        ConsoleLogger.show('info', `Iterations: ${details.iterations}`, '🔁');
        ConsoleLogger.show('info', `Threshold mode: ${details.thresholdMode}`, '🧩');
        if (details.numPasswords !== undefined) {
            ConsoleLogger.show('info', `Shares: ${details.numPasswords}`, '🔢');
            ConsoleLogger.show('info', `Threshold required: ${details.thresholdRequired}`, '🎯');
        }
        ConsoleLogger.show('info', `Salt length: ${details.saltLength}`, '🧂');
        ConsoleLogger.show('info', `Nonce length: ${details.nonceLength}`, '🎲');
        ConsoleLogger.show('info', `Tag length: ${details.tagLength}`, '🏷️');
        ConsoleLogger.show('info', `Header length: ${details.headerLength}`, '🧱');
        ConsoleLogger.show('info', `File size: ${details.fileSize} bytes`, '📦');
        ConsoleLogger.show('info', `Ciphertext size: ${details.ciphertextSize} bytes`, '🔐');
        if (details.container === 'hidden') {
            ConsoleLogger.show('info', 'Container: hidden (outer CT02 + inner CT02 + CTHV footer)', '🫥');
            ConsoleLogger.show('info', `Outer blob size: ${details.outerBlobSize} bytes`, '📦');
            ConsoleLogger.show('info', `Hidden blob size: ${details.hiddenBlobSize} bytes`, '📦');
            if (details.hiddenMetadata) {
                ConsoleLogger.show('info', 'Hidden blob metadata:', '🫥');
                ConsoleLogger.show('info', `Inner compression: ${details.hiddenMetadata.compression}`, '🗜️');
                ConsoleLogger.show('info', `Inner keyfile: ${details.hiddenMetadata.keyfile}`, '🔑');
                ConsoleLogger.show('info', `Inner KDF: ${details.hiddenMetadata.kdf}`, '🧬');
                ConsoleLogger.show('info', `Inner iterations: ${details.hiddenMetadata.iterations}`, '🔁');
                ConsoleLogger.show('info', `Inner threshold mode: ${details.hiddenMetadata.thresholdMode}`, '🧩');
                if (details.hiddenMetadata.numPasswords !== undefined) {
                    ConsoleLogger.show('info', `Inner shares: ${details.hiddenMetadata.numPasswords}`, '🔢');
                    ConsoleLogger.show('info', `Inner threshold required: ${details.hiddenMetadata.thresholdRequired}`, '🎯');
                }
            }
            if (details.footerNote) {
                ConsoleLogger.show('warning', details.footerNote);
            }
        }
        const endTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        ConsoleLogger.show('info', `Session ended at ${endTimestamp}`, '🏁');
        if (ConsoleLogger.LOG_ENABLED) {
            ConsoleLogger.show('info', '='.repeat(80), null, false, true);
        }
        return;
    }

    if (options.text) {
        const modeStr = options.decrypt ? 'decrypt' : 'encrypt';
        const compressionStr = 'disabled';
        ConsoleLogger.show('info', `Mode: ${modeStr}`, options.decrypt ? '🔓' : '🔐');
        ConsoleLogger.show('info', `Compression: ${compressionStr}`, '📦');
    } else if (options.file) {
        ConsoleLogger.show('debug', `File specified: ${options.file}`);
        if (!fs.existsSync(options.file) && !FileUtils.hasWildcard(options.file)) {
            ConsoleLogger.show('error', `File not found: ${options.file}`);
            ConsoleLogger.show('error', 'Operation failed: File does not exist');
            ConsoleLogger.show('error', 'Please check the file path and try again');
            abort(1);
        }

        let isDir = false;
        if (!FileUtils.hasWildcard(options.file) && fs.existsSync(options.file)) {
            isDir = fs.statSync(options.file).isDirectory();
        }
        if (isDir && !options.recursive) {
            ConsoleLogger.show('error', 'Path is a directory. Use -r/--recursive to process directories.');
            ConsoleLogger.show('error', 'Operation aborted: Directory specified without --recursive flag');
            abort(1);
        }

        const modeStr = options.decrypt ? 'decrypt' : 'encrypt';
        const compressionStr = options.compress ? 'enabled' : 'disabled';
        let displayCompression = compressionStr;
        if (options.decrypt && !isDir && !FileUtils.hasWildcard(options.file) && fs.existsSync(options.file) && fs.statSync(options.file).isFile()) {
            try {
                const details = engine.inspectFile(options.file);
                displayCompression = details.compression;
            } catch (err) {
                ConsoleLogger.show('debug', `Could not inspect compression metadata: ${err.message}`);
            }
        }
        ConsoleLogger.show('info', `Mode: ${modeStr}`, options.decrypt ? '🔓' : '🔐');
        ConsoleLogger.show('info', `Compression: ${displayCompression}`, '📦');

        if (isDir && options.recursive) {
            ConsoleLogger.show('info', `Processing directory: ${options.file}`, '📁');
            ConsoleLogger.show('info', `${options.decrypt ? 'Decrypting' : 'Encrypting'} directory: ${options.file}`, options.decrypt ? '🔓' : '🔒');
            ConsoleLogger.show('info', 'Recursive mode: enabled', '🔄');
        } else if (!isDir) {
            if (fileList && fileList.length > 1) {
                ConsoleLogger.show('info', `Processing files: ${fileList.length}`, '📄');
            } else if (!FileUtils.hasWildcard(options.file) && fs.existsSync(options.file)) {
                const inputSize = fs.statSync(options.file).size;
                ConsoleLogger.show('info', `Processing file: ${options.file} (${engine._formatSize(inputSize)})`, '📄');
            } else if (fileList && fileList.length === 1) {
                const inputSize = fs.statSync(fileList[0]).size;
                ConsoleLogger.show('info', `Processing file: ${fileList[0]} (${engine._formatSize(inputSize)})`, '📄');
            }
        }
    }

    // Show text info
    if (options.text) {
        ConsoleLogger.show('info', 'Processing text...', '💬');
        ConsoleLogger.show('info', `Input text length: ${options.text.length} characters`);
    }

    // Handle key file
    let keyfileData = null;
    if (options.keyfile) {
        ConsoleLogger.show('info', `Using key file: ${options.keyfile}`, '🔐');
        keyfileData = KeyFileUtils.read(options.keyfile);
        if (!keyfileData) {
            ConsoleLogger.show('error', 'Operation aborted: Could not load key file');
            abort(1);
        }
        ConsoleLogger.show('success', 'Key file loaded successfully');
    } else {
        ConsoleLogger.show('debug', 'No key file provided');
    }

    // Handle KDF selection
    options.kdf = options.kdf || 'pbkdf2';
    if (options.kdf && !['pbkdf2', 'argon2'].includes(options.kdf)) {
        ConsoleLogger.show('error', 'Invalid --kdf value. Must be "pbkdf2" or "argon2"');
        abort(1);
    }

    // Handle KDF selection - show info before password prompt
    const kdfType = options.kdf === 'argon2' ? Config.KDF_ARGON2 : Config.KDF_PBKDF2;
    if (options.kdf === 'argon2' && !ARGON2_AVAILABLE) {
        ConsoleLogger.show('error', 'Argon2 is not available. Please install argon2: npm install argon2');
        abort(1);
    }
    let iterations = options.iterations;
    if (iterations === undefined || isNaN(iterations)) {
        iterations = options.kdf === 'argon2' ? Config.ARGON2_TIME_COST : Config.PBKDF2_ITERATIONS;
    }
    ConsoleLogger.show('important', `KDF: ${options.kdf} (${iterations} iterations)`, '🧬');

    let pwOuter = options.passwordOuter;
    let pwHidden = options.passwordHidden;
    let thresholdRequirements = null;

    if (
        options.decrypt &&
        options.file &&
        !options.inspect &&
        !options.hidden &&
        !options.hiddenVol &&
        !FileUtils.hasWildcard(options.file) &&
        fs.existsSync(options.file) &&
        fs.statSync(options.file).isFile()
    ) {
        try {
            thresholdRequirements = HeaderParser.inspectThreshold(options.file);
        } catch (err) {
            ConsoleLogger.show('debug', `Could not inspect threshold requirements: ${err.message}`);
        }
    }

    // Secure Password Input with Strength Indicator
    if (!options.inspect && options.hiddenVol) {
        if (pwOuter === undefined) {
            pwOuter = await PasswordUtils.verify(
                'Enter decoy (outer) password: ',
                'Verify decoy (outer) password: '
            );
            ConsoleLogger.show('info', 'Decoy password entered', '🔑');
        } else {
            ConsoleLogger.show('debug', 'Decoy password provided via command line');
        }
        if (pwHidden === undefined) {
            pwHidden = await PasswordUtils.verify(
                'Enter hidden volume password: ',
                'Verify hidden volume password: '
            );
            ConsoleLogger.show('info', 'Hidden volume password entered', '🔑');
        } else {
            ConsoleLogger.show('debug', 'Hidden password provided via command line');
        }
    } else if (!options.inspect && thresholdRequirements && (!options.password || options.password.length < thresholdRequirements.threshold)) {
        const providedPasswords = options.password || [];
        ConsoleLogger.show('info', `Threshold-encrypted file detected: ${thresholdRequirements.threshold} password(s) required`);
        options.password = await PasswordUtils.getThresholdPasswords(
            thresholdRequirements.threshold,
            thresholdRequirements.threshold,
            providedPasswords
        );
    } else if (!options.inspect && (!options.password || options.password.length === 0)) {
        if (options.decrypt && options.hidden && options.passwordHidden !== undefined) {
            options.password = options.passwordHidden;
            ConsoleLogger.show('debug', 'Using --password-hidden for inner decrypt');
        } else if (!options.decrypt) {
            options.password = await PasswordUtils.verify();
            ConsoleLogger.show('info', 'Password verification entered', '🔄');
        } else {
            options.password = await PasswordUtils.prompt();
            ConsoleLogger.show('info', 'Password entered by user', '🔑');
        }
    } else if (!options.inspect && options.threshold) {
        const numPasswords = options.password ? options.password.length : 0;
        if (numPasswords < options.threshold) {
            ConsoleLogger.show('info', `Threshold mode: need ${options.threshold} passwords`);
            const providedPasswords = options.password || [];
            options.password = await PasswordUtils.getThresholdPasswords(options.threshold, options.threshold, providedPasswords);
        } else {
            ConsoleLogger.show('debug', `Using all ${numPasswords} provided passwords for threshold encryption`);
        }
    } else if (!options.inspect) {
        if (options.password && options.password.length === 1) {
            options.password = options.password[0];
            ConsoleLogger.show('debug', 'Password provided via command line');
        }
    }

    if (options.text) {
        const startTime = Date.now();

        // Default to encrypt if decrypt is not explicitly set
        if (!options.decrypt) {
            ConsoleLogger.show('info', 'Encrypting text...');
            const result = await engine.encryptData(Buffer.from(options.text, 'utf-8'), options.password, keyfileData, kdfType, iterations);
            const b64Result = result.toString('base64');
            ConsoleLogger.show('success', `Encrypted (Base64): ${b64Result}`);
            if (options.qr) {
                await UIHelpers.renderQrCode(b64Result);
            }
            const elapsed = (Date.now() - startTime) / 1000;
            ConsoleLogger.show('info', `Output encrypted text length: ${b64Result.length} characters`);
            ConsoleLogger.show('success', 'Encryption completed successfully', '✅');
            ConsoleLogger.show('info', 'Operations completed: 1/1', '✔️');
            ConsoleLogger.show('info', `Total time: ${elapsed.toFixed(2)}s`, '⏱️');
        } else {
            ConsoleLogger.show('info', 'Decrypting text...');
            ConsoleLogger.show('debug', 'Decoding Base64 text input');
            const rawData = Buffer.from(options.text, 'base64');
            const result = await engine.decryptData(rawData, options.password, keyfileData);
            if (result) {
                ConsoleLogger.show('success', `Decrypted: ${result.toString('utf-8')}`);
                const elapsed = (Date.now() - startTime) / 1000;
                ConsoleLogger.show('info', `Output decrypted text length: ${result.length} characters`);
                ConsoleLogger.show('success', 'Decryption completed successfully', '✅');
                ConsoleLogger.show('info', 'Operations completed: 1/1', '✔️');
                ConsoleLogger.show('info', `Total time: ${elapsed.toFixed(2)}s`, '⏱️');
            } else {
                ConsoleLogger.show('error', 'Decryption failed');
                abort(1);
            }
        }

    } else if (options.file) {
        // Recursive Directory Processing
        if (options.recursive && !FileUtils.hasWildcard(options.file) && fs.existsSync(options.file) && fs.statSync(options.file).isDirectory()) {
            const inputDir = options.file;
            const modeStr = options.decrypt ? 'decrypt' : 'encrypt';
            const compressionStr = options.compress ? 'enabled' : 'disabled';
            const lockEmoji = options.decrypt ? '🔓' : '🔐';

            ConsoleLogger.show('debug', 'Recursive mode enabled');

            let successCount = 0;
            let failCount = 0;
            const startTime = Date.now();

            const files = FileUtils.walkDir(inputDir);
            for (const filePath of files) {
                if (!options.decrypt) {
                    // Skip already encrypted files if in encrypt mode
                    if (filePath.endsWith('.enc')) continue;

                    const outPath = filePath + '.enc';
                    ConsoleLogger.show('info', `Processing: ${filePath}`, '📄');
                    const result = await engine.encryptFile(filePath, outPath, options.password, options.compress, keyfileData, kdfType, iterations);
                    if (result) {
                        successCount++;
                        const size = fs.statSync(outPath).size;
                        ConsoleLogger.show('success', `File encrypted: ${outPath} (${engine._formatSize(size)})`, '📄');
                    } else {
                        failCount++;
                    }
                } else {
                    // Decrypt mode: Only process .enc files
                    if (!filePath.endsWith('.enc')) continue;

                    let outPath = filePath.slice(0, -4); // Strip .enc
                    if (outPath === filePath.slice(0, -4) && path.extname(outPath) === '') {
                        outPath = filePath + '.dec';
                    }

                    ConsoleLogger.show('info', `Processing: ${filePath}`, '📄');
                    const foot = HeaderParser.parseHiddenFooter(filePath);
                    let result;
                    if (foot) {
                        result = await engine.decryptHiddenContainer(filePath, outPath, options.password, {
                            hidden: options.hidden,
                            compress: options.compress,
                            keyfileData
                        });
                    } else if (options.hidden) {
                        ConsoleLogger.show('error', `--hidden only applies to CTHV containers: ${filePath}`, '❌');
                        result = false;
                    } else {
                        result = await engine.decryptFile(filePath, outPath, options.password, options.compress, keyfileData);
                    }
                    if (result) {
                        successCount++;
                        const size = fs.statSync(outPath).size;
                        ConsoleLogger.show('success', `File decrypted: ${outPath} (${engine._formatSize(size)})`, '📄');
                    } else {
                        failCount++;
                    }
                }
            }

            const elapsed = (Date.now() - startTime) / 1000;
            const totalOps = successCount + failCount;

            ConsoleLogger.show('info', `Batch complete. Success: ${successCount}, Failed: ${failCount}`);
            if (failCount > 0) {
                ConsoleLogger.show('warning', `Some files failed to process: ${failCount} failed`);
            }
            ConsoleLogger.show('info', `Total files processed: ${totalOps}`);
            ConsoleLogger.show('info', `Successful: ${successCount}`);
            ConsoleLogger.show('info', `Failed: ${failCount}`);

            // Display completion summary
            ConsoleLogger.logCompletionSummary(options.decrypt, successCount, totalOps, elapsed);

        } else if (fs.existsSync(options.file) || (fileList && fileList.length > 0)) {
            const targets = (fileList && fileList.length > 0) ? fileList : [options.file];
            let successCount = 0;
            let failCount = 0;
            const startTime = Date.now();

            for (const target of targets) {
                if (FileUtils.hasWildcard(target)) {
                    continue;
                }
                let stat;
                try {
                    stat = fs.statSync(target);
                } catch (e) {
                    continue;
                }
                if (stat.isDirectory()) {
                    continue;
                }
                const outputFile = options.output && targets.length === 1
                    ? options.output
                    : (options.decrypt
                        ? path.join(path.dirname(target), path.basename(target, '.enc') + '.dec')
                        : target + '.enc');

                let ok;
                if (!options.decrypt) {
                    if (options.hiddenVol) {
                        ok = await engine.encryptHiddenContainer(
                            target,
                            options.hiddenFile,
                            outputFile,
                            pwOuter,
                            pwHidden,
                            options.compress,
                            keyfileData,
                            kdfType,
                            iterations
                        );
                    } else if (options.threshold) {
                        ok = await engine.encryptWithThreshold(
                            target,
                            outputFile,
                            options.password,
                            options.threshold,
                            options.compress,
                            keyfileData,
                            kdfType,
                            iterations
                        );
                    } else {
                        // For non-threshold encryption, extract single password from array
                        const singlePassword = PasswordUtils.normalize(options.password);
                        ok = await engine.encryptFile(target, outputFile, singlePassword, options.compress, keyfileData, kdfType, iterations);
                    }
                } else {
                    const foot = HeaderParser.parseHiddenFooter(target);
                    if (foot) {
                        ok = await engine.decryptHiddenContainer(target, outputFile, options.password, {
                            hidden: options.hidden,
                            compress: options.compress,
                            keyfileData
                        });
                    } else if (options.hidden) {
                        ConsoleLogger.show('error', '--hidden only applies to files with a CTHV hidden-volume footer.');
                        ok = false;
                    } else {
                        // Check if file is threshold-encrypted by reading its header
                        let isThresholdFile = false;
                        try {
                            const fd = fs.openSync(target, 'r');
                            const headerBuf = Buffer.alloc(16);
                            fs.readSync(fd, headerBuf, 0, 16, 0);
                            fs.closeSync(fd);
                            if (headerBuf[0] === 0x43 && headerBuf[1] === 0x54 && headerBuf[2] === 0x30 && headerBuf[3] === 0x32) {
                                const flags = headerBuf[5];
                                isThresholdFile = Boolean(flags & Config.FLAG_THRESHOLD);
                            }
                        } catch (e) {
                            // Ignore and use default decrypt
                        }

                        if (isThresholdFile || options.threshold) {
                            ok = await engine.decryptWithThreshold(
                                target,
                                outputFile,
                                options.password,
                                options.compress,
                                keyfileData
                            );
                        } else {
                            // For non-threshold files, extract single password from array
                            const singlePassword = PasswordUtils.normalize(options.password);
                            ok = await engine.decryptFile(target, outputFile, singlePassword, options.compress, keyfileData);
                        }
                    }
                }

                if (ok) {
                    successCount++;
                    const outputSize = fs.statSync(outputFile).size;
                    ConsoleLogger.show('success', `File ${options.decrypt ? 'decrypted' : 'encrypted'}: ${outputFile} (${engine._formatSize(outputSize)})`, '📄');
                } else {
                    failCount++;
                }
            }

            const elapsed = (Date.now() - startTime) / 1000;
            const totalOps = successCount + failCount;

            ConsoleLogger.logCompletionSummary(options.decrypt, successCount, totalOps, elapsed);

            if (failCount > 0) {
                abort(1);
            }
        }
    }

    // Record end time
    finishSession();
}

// =========================
// FileUtils
// =========================

class FileUtils {
    static walkDir(dir) {
        const results = [];
        const list = fs.readdirSync(dir);

        for (const file of list) {
            const filePath = path.join(dir, file);
            let stat;
            try {
                stat = fs.statSync(filePath);
            } catch (err) {
                continue;
            }

            if (stat && stat.isDirectory()) {
                results.push(...FileUtils.walkDir(filePath));
            } else {
                results.push(filePath);
            }
        }

        return results;
    }

    static hasWildcard(p) {
        return /[*?[\]]/.test(p);
    }

    static globToRegex(globPattern) {
        let regex = '^';
        let inClass = false;
        for (let i = 0; i < globPattern.length; i++) {
            const ch = globPattern[i];
            if (ch === '\\') {
                regex += '\\\\';
            } else if (ch === '[') {
                inClass = true;
                regex += ch;
            } else if (ch === ']') {
                inClass = false;
                regex += ch;
            } else if (ch === '*' && !inClass) {
                regex += '.*';
            } else if (ch === '?' && !inClass) {
                regex += '.';
            } else {
                regex += ch.replace(/[.+^${}()|]/g, '\\$&');
            }
        }
        regex += '$';
        return new RegExp(regex, 'i');
    }

    static expandFilePattern(pattern, recursive) {
        if (!FileUtils.hasWildcard(pattern)) {
            return [pattern];
        }

        const baseDir = path.dirname(pattern);
        const namePattern = path.basename(pattern);

        if (FileUtils.hasWildcard(baseDir)) {
            return [];
        }

        const targetDir = baseDir === '.' ? process.cwd() : baseDir;
        const matcher = FileUtils.globToRegex(namePattern);
        let candidates = [];

        if (recursive) {
            candidates = FileUtils.walkDir(targetDir);
        } else {
            const entries = fs.readdirSync(targetDir);
            candidates = entries.map((e) => path.join(targetDir, e));
        }

        const matches = [];
        for (const filePath of candidates) {
            if (FileUtils.hasWildcard(filePath)) {
                continue;
            }
            let stat;
            try {
                stat = fs.statSync(filePath);
            } catch (err) {
                continue;
            }
            if (!stat.isFile()) continue;
            const name = path.basename(filePath);
            if (matcher.test(name)) {
                matches.push(filePath);
            }
        }
        return matches;
    }
}

if (require.main === module) {
    main().catch((err) => {
        ConsoleLogger.show('error', `Unexpected error: ${err.message}`);
        process.exit(1);
    });
} else {
    module.exports = {
        main,
        UIHelpers,
        ConsoleLogger,
        ConfigParser,
        HeaderParser,
        KeyFileUtils,
        PasswordUtils,
        CryptoEngine,
        Config,
        ShamirSecretSharing,
        Banner,
        FileUtils,
        ProgressBarUtils,
    };
}
