#!/usr/bin/env node
/**
 * Cryptographic Tool for File and Text Encryption/Decryption.
 * Refactored version with AES-GCM and Streaming I/O.
 * Node.js Edition
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const zlib = require('zlib');
const { finished, pipeline } = require('stream/promises');
const { program } = require('commander');
const ProgressBar = require('progress');

// =========================
// Configuration
// =========================

class Config {
    static AUTHOR = 'Center For Cyber Intelligence';
    static DESCRIPTION = 'Crypt Tools (AES-GCM Edition)';
    static VERSION = '2.1.0';

    // File format
    static MAGIC = Buffer.from('CT02');
    static FORMAT_VERSION = 2;
    static FLAG_COMPRESS = 0x01;
    static FLAG_TEXT = 0x02;
    static FLAG_KEYFILE = 0x04;
    static KDF_PBKDF2 = 0x01;
    static FIXED_HEADER_SIZE = 16;

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
}

// =========================
// Progress Bar (tqdm-like)
// =========================

function formatTqdmSize(bytes) {
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

function formatTqdmRate(bytesPerSec) {
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

function formatTqdmTime(seconds) {
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

function getTqdmTokens(bar, startTime, nextCurr = null) {
    const elapsedSec = (Date.now() - startTime) / 1000;
    const curr = nextCurr !== null ? nextCurr : bar.curr;
    const total = bar.total;
    const rate = elapsedSec > 0 ? (curr / elapsedSec) : 0;
    const remainingSec = rate > 0 ? (total - curr) / rate : 0;
    return {
        sizes: `${formatTqdmSize(curr)}/${formatTqdmSize(total)}`,
        telapsed: formatTqdmTime(elapsedSec),
        teta: formatTqdmTime(remainingSec),
        trate: formatTqdmRate(rate)
    };
}

function calcTqdmBarWidth(label, tokens) {
    const columns = (process.stderr && process.stderr.columns) ? process.stderr.columns : 120;
    const fixedLen = `${label} 100%|| ${tokens.sizes} [${tokens.telapsed}<${tokens.teta}, ${tokens.trate}]`.length;
    const width = columns - fixedLen;
    return Math.max(10, Math.min(80, width));
}

function createTqdmBar(label, total) {
    const initialTokens = {
        sizes: '0B/0B',
        telapsed: '00:00',
        teta: '00:00',
        trate: '0B/s'
    };
    const bar = new ProgressBar(`${label} :percent|:bar| :sizes [:telapsed<:teta, :trate]`, {
        total,
        width: calcTqdmBarWidth(label, initialTokens),
        complete: '▓',
        incomplete: '░',
        head: '▓',
        clear: false
    });
    const startTime = Date.now();
    return {
        bar,
        render: () => {
            const tokens = getTqdmTokens(bar, startTime);
            bar.width = calcTqdmBarWidth(label, tokens);
            bar.render(tokens);
        },
        tick: (len) => {
            const nextCurr = bar.curr + len;
            const tokens = getTqdmTokens(bar, startTime, nextCurr);
            bar.width = calcTqdmBarWidth(label, tokens);
            bar.tick(len, tokens);
        }
    };
}

function bufferToUint32(buf) {
    return buf.readUInt32BE(0);
}

function parseCT02HeaderFromBuffer(buffer) {
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
    const iterations = kdfParamLen === 4 ? bufferToUint32(kdfParams) : Config.PBKDF2_ITERATIONS;

    return {
        format: Config.MAGIC.toString('ascii'),
        version,
        flags,
        compress: Boolean(flags & Config.FLAG_COMPRESS),
        isText: Boolean(flags & Config.FLAG_TEXT),
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

function parseFormatFromBuffer(buffer) {
    if (buffer.length >= 4 && buffer.subarray(0, 4).equals(Config.MAGIC)) {
        return parseCT02HeaderFromBuffer(buffer);
    }
    throw new Error('Unrecognized file format. Only CT02 encrypted files can be inspected reliably.');
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
      ██████╗██████╗ ██╗   ██╗██████╗ ████████╗    ████████╗ ██████╗  ██████╗ ██╗     ███████╗
     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║          ██║   ██║   ██║██║   ██║██║     ███████╗
     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║          ██║   ██║   ██║██║   ██║██║     ╚════██║
     ╚██████╗██║  ██║   ██║   ██║        ██║          ██║   ╚██████╔╝╚██████╔╝███████╗███████║
      ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
    `,
        String.raw`
     ██████╗ ██████╗ ██╗   ██╗██████╗ ███████╗███████╗███████╗
    ██╔════╝██╔═══██╗██║   ██║██╔══██╗██╔════╝██╔════╝██╔════╝
    ██║     ██║   ██║██║   ██║██████╔╝█████╗  █████╗  ███████╗
    ██║     ██║   ██║██║   ██║██╔══██╗██╔══╝  ██╔══╝  ╚════██║
    ╚██████╗╚██████╔╝╚██████╔╝██║  ██║███████╗███████╗███████║
     ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
    `,
        String.raw`
     ██████╗ ███████╗ █████╗ ██████╗ 
    ██╔════╝ ██╔════╝██╔══██╗██╔══██╗
    ██║  ███╗█████╗  ███████║██║  ██║
    ██║   ██║██╔══╝  ██╔══██║██║  ██║
    ╚██████╔╝███████╗██║  ██║██████╔╝
     ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ 
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
// Core Logic (Engine)
// =========================

class CryptoEngine {
    _deriveKey(password, salt) {
        ConsoleLogger.show('debug', `Deriving key with PBKDF2 (${Config.PBKDF2_ITERATIONS} iterations)`);
        return crypto.pbkdf2Sync(
            password,
            salt,
            Config.PBKDF2_ITERATIONS,
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

    encryptData(data, password) {
        ConsoleLogger.show('debug', `Starting in-memory data encryption (${data.length} bytes input)`);
        const salt = crypto.randomBytes(Config.SALT_SIZE);
        const nonce = crypto.randomBytes(Config.NONCE_SIZE);
        ConsoleLogger.show('debug', `Generated salt (${Config.SALT_SIZE} bytes) and nonce (${Config.NONCE_SIZE} bytes)`);
        const key = this._deriveKey(password, salt);

        ConsoleLogger.show('debug', 'Initializing AES-GCM cipher');
        const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
        const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
        const tag = cipher.getAuthTag();
        ConsoleLogger.show('debug', `Encryption complete. Ciphertext size: ${encrypted.length} bytes, Tag size: ${tag.length} bytes`);

        return Buffer.concat([salt, nonce, tag, encrypted]);
    }

    decryptData(encData, password) {
        try {
            ConsoleLogger.show('debug', `Starting in-memory data decryption. Total input size: ${encData.length} bytes`);
            const overhead = Config.SALT_SIZE + Config.NONCE_SIZE + Config.TAG_SIZE;
            if (encData.length < overhead) {
                ConsoleLogger.show('debug', 'Input data is smaller than minimum overhead');
                throw new Error('Data too short');
            }

            const salt = encData.subarray(0, Config.SALT_SIZE);
            const nonce = encData.subarray(Config.SALT_SIZE, Config.SALT_SIZE + Config.NONCE_SIZE);
            const tag = encData.subarray(Config.SALT_SIZE + Config.NONCE_SIZE, overhead);
            const ciphertext = encData.subarray(overhead);
            ConsoleLogger.show('debug', `Extracted salt, nonce, tag, and ciphertext (${ciphertext.length} bytes)`);

            const key = this._deriveKey(password, salt);
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

    async encryptFile(inputPath, outputPath, password, compress = false) {
        try {
            ConsoleLogger.show('debug', `Starting file encryption: ${inputPath} -> ${outputPath}`);
            const stats = fs.statSync(inputPath);
            const fileSize = stats.size;

            ConsoleLogger.show('debug', `Generating ${Config.SALT_SIZE} bytes salt and ${Config.NONCE_SIZE} bytes nonce`);
            const salt = crypto.randomBytes(Config.SALT_SIZE);
            const nonce = crypto.randomBytes(Config.NONCE_SIZE);
            const key = this._deriveKey(password, salt);
            ConsoleLogger.show('debug', 'Initializing AES-GCM cipher');
            const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);

            const desc = compress ? '[🔒] Compressing & Encrypting' : '[🔒] Encrypting';
            const label = compress ? '[🔒] Compressing & Encrypting:' : '[🔒] Encrypting:';
            if (compress) {
                ConsoleLogger.show('debug', 'Compression enabled (zlib level 9)');
            }
            const progress = createTqdmBar(label, fileSize);
            progress.render();

            const outputStream = fs.createWriteStream(outputPath);
            const header = Buffer.concat([salt, nonce]);
            outputStream.write(header);

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

    async decryptFile(inputPath, outputPath, password, compress = false) {
        try {
            const stats = fs.statSync(inputPath);
            const fileSize = stats.size;
            ConsoleLogger.show('debug', `Starting file decryption: ${inputPath} (size: ${this._formatSize(fileSize)}) -> ${outputPath}`);
            const headerSize = Config.SALT_SIZE + Config.NONCE_SIZE;
            const footerSize = Config.TAG_SIZE;

            if (fileSize < headerSize + footerSize) {
                ConsoleLogger.show('debug', 'File size is smaller than required header + footer overhead');
                throw new Error('File too small');
            }

            const fd = fs.openSync(inputPath, 'r');
            const salt = Buffer.alloc(Config.SALT_SIZE);
            const nonce = Buffer.alloc(Config.NONCE_SIZE);
            const tag = Buffer.alloc(Config.TAG_SIZE);
            fs.readSync(fd, salt, 0, Config.SALT_SIZE, 0);
            fs.readSync(fd, nonce, 0, Config.NONCE_SIZE, Config.SALT_SIZE);
            fs.readSync(fd, tag, 0, Config.TAG_SIZE, fileSize - footerSize);
            fs.closeSync(fd);

            const ciphertextLen = fileSize - headerSize - footerSize;
            ConsoleLogger.show('debug', `Read salt (${salt.length} bytes), nonce (${nonce.length} bytes), ciphertext (${ciphertextLen} bytes), and tag (${tag.length} bytes)`);
            const key = this._deriveKey(password, salt);
            ConsoleLogger.show('debug', 'Initializing AES-GCM cipher for decryption');

            const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
            decipher.setAuthTag(tag);
            ConsoleLogger.show('debug', `Ciphertext length to decrypt: ${this._formatSize(ciphertextLen)}`);

            const desc = compress ? '[🔓] Decrypting & Decompressing' : '[🔓] Decrypting';
            const label = compress ? '[🔓] Decrypting & Decompressing:' : '[🔓] Decrypting:';
            if (compress) {
                ConsoleLogger.show('debug', 'Decompression enabled (zlib inflate)');
            }
            const progress = createTqdmBar(label, ciphertextLen);
            progress.render();

            const readStream = fs.createReadStream(inputPath, {
                start: headerSize,
                end: fileSize - footerSize - 1,
                highWaterMark: Config.CHUNK_SIZE
            });
            readStream.on('data', (chunk) => progress.tick(chunk.length));

            try {
                const outputStream = fs.createWriteStream(outputPath);
                if (compress) {
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

    inspectFile(inputPath) {
        if (!fs.existsSync(inputPath) || !fs.statSync(inputPath).isFile()) {
            const err = new Error(`ENOENT: no such file or directory, stat '${inputPath}'`);
            err.code = 'ENOENT';
            throw err;
        }

        const fileSize = fs.statSync(inputPath).size;
        let prefix = fs.readFileSync(inputPath).subarray(0, Math.min(fileSize, Config.FIXED_HEADER_SIZE));

        if (prefix.length < Config.FIXED_HEADER_SIZE) {
            throw new Error('File is too small to inspect');
        }

        let metadata = parseFormatFromBuffer(prefix);
        if (prefix.length < metadata.headerLen) {
            prefix = fs.readFileSync(inputPath).subarray(0, metadata.headerLen);
            metadata = parseCT02HeaderFromBuffer(prefix);
        }

        const ciphertextSize = fileSize - metadata.headerLen - metadata.saltLen - metadata.nonceLen - metadata.tagLen;
        if (ciphertextSize < 0) {
            throw new Error('Invalid encrypted file structure');
        }

        return {
            format: metadata.format,
            version: metadata.version,
            legacy: metadata.isLegacy,
            compression: metadata.compress ? 'enabled' : 'disabled',
            kdf: metadata.kdfId === Config.KDF_PBKDF2 ? 'PBKDF2-SHA256' : `unknown(${metadata.kdfId})`,
            iterations: metadata.iterations,
            saltLength: metadata.saltLen,
            nonceLength: metadata.nonceLen,
            tagLength: metadata.tagLen,
            headerLength: metadata.headerLen,
            fileSize,
            ciphertextSize
        };
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
// Password Input Functions
// =========================

function getpassWithStrength(prompt = 'Enter Password: ') {
    const white = TerminalColors.WHITE;
    const reset = TerminalColors.RESET;
    process.stdout.write(`${white}[${reset}🔑${white}]${reset} ${prompt}`);

    // Hide cursor
    process.stdout.write('\x1b[?25l');

    let password = '';

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
                resolve(line.trim());
            });
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

async function getpassVerifyWithStrength(prompt1 = 'Enter Password: ', prompt2 = 'Verify Password: ') {
    const white = TerminalColors.WHITE;
    const reset = TerminalColors.RESET;

    const password = await getpassWithStrength(prompt1);

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

// =========================
// CLI Logic
// =========================

async function main() {
    program
        .description(Config.DESCRIPTION)
        .version(Config.VERSION)
        .option('-e, --encrypt', 'Encrypt mode (default)', true)
        .option('-d, --decrypt', 'Decrypt mode', false)
        .option('--inspect', 'Inspect encrypted file metadata', false)
        .option('-t, --text <text>', 'Text to process')
        .option('-f, --file <path>', 'File path, directory, or wildcard pattern (e.g., "*.md", "temp\\*.txt")')
        .option('-o, --output <path>', 'Output file path')
        .option('-p, --password <password>', 'Password (optional; prompt includes strength indicator)')
        .option('-c, --compress', 'Enable compression', false)
        .option('-r, --recursive', 'Recursively process directories or wildcard patterns (uses ** for subfolders)', false)
        .option('--debug', 'Enable debug mode', false)
        .option('--log', 'Enable logging to file', false)
        .addHelpText('after',
            '\nNotes:\n' +
            '  - Wildcards are supported; with -r, patterns like .\\temp\\*.txt are expanded recursively\n' +
            '    (equivalent to .\\temp\\**\\*.txt).\n' +
            '  - Password prompts show a live strength indicator.\n'
        );

    program.parse(process.argv);
    const options = program.opts();

    // Require either text or file
    if (!options.text && !options.file) {
        ConsoleLogger.show('error', 'Either --text or --file is required');
        process.exit(1);
    }
    if (options.inspect && options.text) {
        ConsoleLogger.show('error', '--inspect only supports --file input');
        process.exit(1);
    }

    Banner.show();

    // Enable logging FIRST if --log flag is set
    if (options.log) {
        ConsoleLogger.LOG_ENABLED = true;
    }

    // Record start time
    const startTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    ConsoleLogger.show('info', `Session started at ${startTimestamp}`, '🕐');

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
        const expanded = expandFilePattern(options.file, options.recursive);
        if (expanded.length === 0 && hasWildcard(options.file)) {
            ConsoleLogger.show('error', `No files matched pattern: ${options.file}`);
            ConsoleLogger.show('error', 'Operation failed: No matching files');
            process.exit(1);
        }
        fileList = expanded;
    }

    if (options.inspect && options.file) {
        const target = (fileList && fileList.length > 0) ? fileList[0] : options.file;
        try {
            const details = engine.inspectFile(target);
            ConsoleLogger.show('info', `Format: ${details.format}`, '🔍');
            ConsoleLogger.show('info', `Version: ${details.version}`, '📜');
            ConsoleLogger.show('info', `Legacy: ${details.legacy ? 'yes' : 'no'}`, '🕰️');
            ConsoleLogger.show('info', `Compression: ${details.compression}`, '🗜️');
            ConsoleLogger.show('info', `KDF: ${details.kdf}`, '🧬');
            ConsoleLogger.show('info', `Iterations: ${details.iterations}`, '🔁');
            ConsoleLogger.show('info', `Salt length: ${details.saltLength}`, '🧂');
            ConsoleLogger.show('info', `Nonce length: ${details.nonceLength}`, '🎲');
            ConsoleLogger.show('info', `Tag length: ${details.tagLength}`, '🏷️');
            ConsoleLogger.show('info', `Header length: ${details.headerLength}`, '🧱');
            ConsoleLogger.show('info', `File size: ${details.fileSize} bytes`, '📦');
            ConsoleLogger.show('info', `Ciphertext size: ${details.ciphertextSize} bytes`, '🔐');
            const endTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
            ConsoleLogger.show('info', `Session ended at ${endTimestamp}`, '🏁');
            if (ConsoleLogger.LOG_ENABLED) {
                ConsoleLogger.show('info', '='.repeat(80), null, false, true);
            }
            return;
        } catch (err) {
            if (err.code === 'ENOENT') {
                ConsoleLogger.show('error', `File not found: ${target}`);
                ConsoleLogger.show('error', 'Operation failed: File does not exist');
            } else {
                ConsoleLogger.show('error', `Inspect failed: ${err.message}`);
                ConsoleLogger.show('error', `File is not a supported encrypted file: ${target}`);
            }
            process.exit(1);
        }
    }

    if (options.text) {
        const modeStr = options.decrypt ? 'decrypt' : 'encrypt';
        const compressionStr = 'disabled';
        ConsoleLogger.show('info', `Mode: ${modeStr}`, options.decrypt ? '🔓' : '🔐');
        ConsoleLogger.show('info', `Compression: ${compressionStr}`, '📦');
        ConsoleLogger.show('info', 'Processing text...', '💬');
        ConsoleLogger.show('info', `Input text length: ${options.text.length} characters`);
    } else if (options.file) {
        ConsoleLogger.show('debug', `File specified: ${options.file}`);
        if (!fs.existsSync(options.file) && !hasWildcard(options.file)) {
            ConsoleLogger.show('error', `File not found: ${options.file}`);
            ConsoleLogger.show('error', 'Operation failed: File does not exist');
            ConsoleLogger.show('error', 'Please check the file path and try again');
            process.exit(1);
        }

        let isDir = false;
        if (!hasWildcard(options.file) && fs.existsSync(options.file)) {
            isDir = fs.statSync(options.file).isDirectory();
        }
        if (isDir && !options.recursive) {
            ConsoleLogger.show('error', 'Path is a directory. Use -r/--recursive to process directories.');
            ConsoleLogger.show('error', 'Operation aborted: Directory specified without --recursive flag');
            process.exit(1);
        }

        const modeStr = options.decrypt ? 'decrypt' : 'encrypt';
        const compressionStr = options.compress ? 'enabled' : 'disabled';
        ConsoleLogger.show('info', `Mode: ${modeStr}`, options.decrypt ? '🔓' : '🔐');
        ConsoleLogger.show('info', `Compression: ${compressionStr}`, '📦');
        if (isDir && options.recursive) {
            ConsoleLogger.show('info', `Processing directory: ${options.file}`, '📁');
            ConsoleLogger.show('info', `${options.decrypt ? 'Decrypting' : 'Encrypting'} directory: ${options.file}`, options.decrypt ? '🔓' : '🔒');
            ConsoleLogger.show('info', 'Recursive mode: enabled', '🔄');
        } else if (!isDir) {
            if (fileList && fileList.length > 1) {
                ConsoleLogger.show('info', `Processing files: ${fileList.length}`, '📄');
            } else if (!hasWildcard(options.file) && fs.existsSync(options.file)) {
                const inputSize = fs.statSync(options.file).size;
                ConsoleLogger.show('info', `Processing file: ${options.file} (${engine._formatSize(inputSize)})`, '📄');
            } else if (fileList && fileList.length === 1) {
                const inputSize = fs.statSync(fileList[0]).size;
                ConsoleLogger.show('info', `Processing file: ${fileList[0]} (${engine._formatSize(inputSize)})`, '📄');
            }
        }
    }

    // Secure Password Input with Strength Indicator
    if (!options.inspect && !options.password) {
        // Only verify password when encrypting (not needed for decrypting)
        if (!options.decrypt) {
            options.password = await getpassVerifyWithStrength();
            ConsoleLogger.show('info', 'Password verification entered', '🔄');
        } else {
            options.password = await getpassWithStrength();
            ConsoleLogger.show('info', 'Password entered by user', '🔑');
        }
    } else if (!options.inspect) {
        ConsoleLogger.show('debug', 'Password provided via command line');
    }

    if (options.text) {
        const startTime = Date.now();

        // Default to encrypt if decrypt is not explicitly set
        if (!options.decrypt) {
            ConsoleLogger.show('info', 'Encrypting text...');
            const result = engine.encryptData(Buffer.from(options.text, 'utf-8'), options.password);
            const b64Result = result.toString('base64');
            ConsoleLogger.show('success', `Encrypted (Base64): ${b64Result}`);
            const elapsed = (Date.now() - startTime) / 1000;
            ConsoleLogger.show('info', `Output encrypted text length: ${b64Result.length} characters`);
            ConsoleLogger.show('success', 'Encryption completed successfully', '✅');
            ConsoleLogger.show('info', 'Operations completed: 1/1', '✔️');
            ConsoleLogger.show('info', `Total time: ${elapsed.toFixed(2)}s`, '⏱️');
        } else {
            ConsoleLogger.show('info', 'Decrypting text...');
            ConsoleLogger.show('debug', 'Decoding Base64 text input');
            const rawData = Buffer.from(options.text, 'base64');
            const result = engine.decryptData(rawData, options.password);
            if (result) {
                ConsoleLogger.show('success', `Decrypted: ${result.toString('utf-8')}`);
                const elapsed = (Date.now() - startTime) / 1000;
                ConsoleLogger.show('info', `Output decrypted text length: ${result.length} characters`);
                ConsoleLogger.show('success', 'Decryption completed successfully', '✅');
                ConsoleLogger.show('info', 'Operations completed: 1/1', '✔️');
                ConsoleLogger.show('info', `Total time: ${elapsed.toFixed(2)}s`, '⏱️');
            } else {
                ConsoleLogger.show('error', 'Decryption failed');
                process.exit(1);
            }
        }

    } else if (options.file) {
        // Recursive Directory Processing
        if (options.recursive && !hasWildcard(options.file) && fs.existsSync(options.file) && fs.statSync(options.file).isDirectory()) {
            const inputDir = options.file;
            const modeStr = options.decrypt ? 'decrypt' : 'encrypt';
            const compressionStr = options.compress ? 'enabled' : 'disabled';
            const lockEmoji = options.decrypt ? '🔓' : '🔐';

            ConsoleLogger.show('debug', 'Recursive mode enabled');

            let successCount = 0;
            let failCount = 0;
            const startTime = Date.now();

            const files = walkDir(inputDir);
            for (const filePath of files) {
                if (!options.decrypt) {
                    // Skip already encrypted files if in encrypt mode
                    if (filePath.endsWith('.enc')) continue;

                    const outPath = filePath + '.enc';
                    ConsoleLogger.show('info', `Processing: ${filePath}`, '📄');
                    const result = await engine.encryptFile(filePath, outPath, options.password, options.compress);
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
                    const result = await engine.decryptFile(filePath, outPath, options.password, options.compress);
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
            ConsoleLogger.show('success', `${options.decrypt ? 'Decryption' : 'Encryption'} completed successfully`, '✅');
            ConsoleLogger.show('info', `Operations completed: ${successCount}/${totalOps}`, '✔️');
            ConsoleLogger.show('info', `Total time: ${elapsed.toFixed(2)}s`, '⏱️');

        } else if (fs.existsSync(options.file) || (fileList && fileList.length > 0)) {
            const targets = (fileList && fileList.length > 0) ? fileList : [options.file];
            let successCount = 0;
            let failCount = 0;
            const startTime = Date.now();

            for (const target of targets) {
                if (hasWildcard(target)) {
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
                const defaultExt = options.decrypt ? '.dec' : '.enc';
                const outputFile = options.output && targets.length === 1
                    ? options.output
                    : (path.join(path.dirname(target), path.basename(target, path.extname(target))) + defaultExt);

                const ok = !options.decrypt
                    ? await engine.encryptFile(target, outputFile, options.password, options.compress)
                    : await engine.decryptFile(target, outputFile, options.password, options.compress);

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

            if (totalOps === 1 && successCount === 1) {
                ConsoleLogger.show('success', `${options.decrypt ? 'Decryption' : 'Encryption'} completed successfully`, '✅');
                ConsoleLogger.show('info', 'Operations completed: 1/1', '✔️');
            } else {
                ConsoleLogger.show('success', `${options.decrypt ? 'Decryption' : 'Encryption'} completed successfully`, '✅');
                ConsoleLogger.show('info', `Operations completed: ${successCount}/${totalOps}`, '✔️');
            }
            ConsoleLogger.show('info', `Total time: ${elapsed.toFixed(2)}s`, '⏱️');

            if (failCount > 0) {
                process.exit(1);
            }
        }
    }

    // Record end time
    const endTimestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    ConsoleLogger.show('info', `Session ended at ${endTimestamp}`, '🏁');

    // Write separator line and end timestamp to log file at the end of session
    if (ConsoleLogger.LOG_ENABLED) {
        ConsoleLogger.show('info', '='.repeat(80), null, false, true);
    }
}

// Helper function to walk directory recursively
function walkDir(dir) {
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
            results.push(...walkDir(filePath));
        } else {
            results.push(filePath);
        }
    }

    return results;
}

function hasWildcard(p) {
    return /[*?[\]]/.test(p);
}

function globToRegex(globPattern) {
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

function expandFilePattern(pattern, recursive) {
    if (!hasWildcard(pattern)) {
        return [pattern];
    }

    const baseDir = path.dirname(pattern);
    const namePattern = path.basename(pattern);

    if (hasWildcard(baseDir)) {
        return [];
    }

    const targetDir = baseDir === '.' ? process.cwd() : baseDir;
    const matcher = globToRegex(namePattern);
    let candidates = [];

    if (recursive) {
        candidates = walkDir(targetDir);
    } else {
        const entries = fs.readdirSync(targetDir);
        candidates = entries.map((e) => path.join(targetDir, e));
    }

    const matches = [];
    for (const filePath of candidates) {
        if (hasWildcard(filePath)) {
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

// Run main
main().catch((err) => {
    ConsoleLogger.show('error', `Unexpected error: ${err.message}`);
    process.exit(1);
});
