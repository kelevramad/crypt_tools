#!/usr/bin/env node
/**
 * Shamir's Secret Sharing Implementation
 */

const crypto = require('crypto');

class ShamirSecretSharing {
    static gfmul(a, b) {
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

    static gfexp(base, exp) {
        let result = 1;
        for (let i = 0; i < exp; i++) {
            result = this.gfmul(result, base);
        }
        return result;
    }

    static gfinv(a) {
        if (a === 0) return 0;
        return this.gfexp(a, 254);
    }

    static gfdiv(a, b) {
        if (b === 0) throw new Error('Division by zero');
        return this.gfmul(a, this.gfinv(b));
    }

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

        // Generate random coefficients ONCE for the polynomial (same for all shares!)
        const coeffs = [];
        for (let k = 0; k < threshold - 1; k++) {
            coeffs.push(crypto.randomBytes(1)[0]);
        }

        const shares = [];

        for (let i = 0; i < numShares; i++) {
            const share = Buffer.alloc(secret.length + 1);
            share[0] = i + 1;  // x-coordinate

            const x = i + 1;

            // Evaluate the SAME polynomial at different x values
            for (let j = 0; j < secret.length; j++) {
                let y = secret[j];
                for (let deg = 1; deg < threshold; deg++) {
                    y ^= this.gfmul(coeffs[deg - 1], this.gfexp(x, deg));
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
            const xVals = shares.map(s => s[0]);
            const yVals = shares.map(s => s[j + 1]);

            let result = 0;
            for (let i = 0; i < shares.length; i++) {
                let num = 1, den = 1;
                for (let m = 0; m < shares.length; m++) {
                    if (m !== i) {
                        num = this.gfmul(num, xVals[m]);
                        den = this.gfmul(den, xVals[m] ^ xVals[i]);
                    }
                }
                const li = this.gfdiv(num, den);
                result ^= this.gfmul(yVals[i], li);
            }

            secret[j] = result;
        }

        return secret;
    }
}

module.exports = ShamirSecretSharing;

if (require.main === module) {
    const secret = Buffer.from('my-secret-key-12345678901234', 'utf-8');
    console.log('Original secret:', secret.toString('hex'));
    
    const shares = ShamirSecretSharing.generateShares(secret, 3, 2);
    console.log('\nGenerated 3 shares (threshold 2):');
    shares.forEach((share, i) => {
        console.log(`Share ${i + 1}:`, share.toString('hex'));
    });

    const recovered = ShamirSecretSharing.recoverSecret([shares[0], shares[1]]);
    console.log('\nRecovered with shares 1 & 2:', recovered.toString('hex'));

    const recovered2 = ShamirSecretSharing.recoverSecret([shares[0], shares[2]]);
    console.log('Recovered with shares 1 & 3:', recovered2.toString('hex'));

    console.log('\nTest passed:', secret.equals(recovered) && secret.equals(recovered2));
}
