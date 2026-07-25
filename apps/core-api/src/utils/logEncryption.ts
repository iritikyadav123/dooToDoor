import crypto from "crypto";
import { LOG_CRYPTO } from "../config/constants";   


export function encryptionLogLine(plaintext: string, key: Buffer): string {
    const iv = crypto.randomBytes(LOG_CRYPTO.IV_LENGTH);
    const ciper = crypto.createCipheriv(LOG_CRYPTO.ALGORITHM, key, iv);
    const ciperText = Buffer.concat([ciper.update(plaintext, "utf8"), ciper.final()]);
    const authTag = ciper.getAuthTag();


    return Buffer.concat([iv, authTag, ciperText]).toString("base64");
} 


/** Decrypt a single log line product by encryptLogLine(). */
export function decrptLogLine(encoded: string, key: Buffer): string{
    const row = Buffer.from(encoded, "base64");

    if(row.length <= LOG_CRYPTO.IV_LENGTH + LOG_CRYPTO.AUTH_TAG_LENGTH) {
        throw new Error("Encypted log line too short");
    }

    const iv = row.subarray(0, LOG_CRYPTO.IV_LENGTH);
    const authTag = row.subarray(LOG_CRYPTO.IV_LENGTH, LOG_CRYPTO.IV_LENGTH + LOG_CRYPTO.AUTH_TAG_LENGTH);
    const ciphertext = row.subarray(LOG_CRYPTO.IV_LENGTH + LOG_CRYPTO.AUTH_TAG_LENGTH);

    const decipher = crypto.createDecipheriv(LOG_CRYPTO.ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
}


/**Parse LOG_ENCryPTioN_KEy (64 hex chars) into a 32-byte key buffer */

export function loadLogKey(keyHex: string): Buffer {
    const key = Buffer.from(keyHex, "hex");
    if(key.length !== 32) {
        throw new Error(`LOG_ENCRYPTION_KEY must decode to 32 bytes, got ${key.length}`);
    }
    return key;
}