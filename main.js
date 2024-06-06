const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const hyperspaceKey = {
    generateKeyPair: () => {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        return { publicKey, privateKey };
    },
    encrypt: (text, publicKey) => {
        const buffer = Buffer.from(text, 'utf8');
        const encrypted = crypto.publicEncrypt(publicKey, buffer);
        return encrypted.toString('hex');
    },
    decrypt: (encryptedText, privateKey) => {
        const buffer = Buffer.from(encryptedText, 'hex');
        const decrypted = crypto.privateDecrypt(privateKey, buffer);
        return decrypted.toString('utf8');
    },
    hashPassword: (password) => {
        return crypto.createHash('sha256').update(password).digest('hex');
    },
    saveKey: (filePath, key) => {
        const fullPath = path.resolve(filePath);
        fs.writeFileSync(fullPath, key, 'utf8');
    },
    loadKey: (filePath) => {
        const fullPath = path.resolve(filePath);
        return fs.readFileSync(fullPath, 'utf8');
    }
};

module.exports = hyperspaceKey;
