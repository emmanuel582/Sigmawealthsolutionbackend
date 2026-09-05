import crypto from 'crypto';
import bcrypt from 'bcryptjs';
export function hashPassword(password) {
    return bcrypt.hashSync(String(password), 10);
}
export function verifyPassword(password, storedHash) {
    if (!storedHash)
        return false;
    // Legacy sha256 from earlier local builds
    if (storedHash.length === 64 && /^[a-f0-9]+$/i.test(storedHash)) {
        const legacy = crypto.createHash('sha256').update(`sigma:${password}`).digest('hex');
        return legacy === storedHash;
    }
    try {
        return bcrypt.compareSync(String(password), storedHash);
    }
    catch {
        return false;
    }
}
