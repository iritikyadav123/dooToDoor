import {pino} from "pino";
import {env, isProd} from "../config/env.js";
import { loadLogKey } from "./logEncryption.js";
import { createEncyptedLogStream } from "./encryptedLogStream.js";

/**
 * Standalone pino instance.
 * Shared with fastify via `loggerInstance` in app.ts so service and 
 * the HTTP layer write to the same logger with the same config.
 * 
 * - development: pretty-printed, unencrypted, stdout only (local, dummy secrets).
 * - staging/production: encrypted at rest, wrtten to LOG_FILE_PATH.
 *    Requires LOG_ENCYPTION_KEY (enfored at boot in in rnv.ts.)
 */

function buildLogger() {
    const redact = {
        paths: [
            "req.headers.authorization",
            "req.headers.cookie",
            "headers.authorization",
            "headers.cookie",
            "*.authorization",
            "*.aeskey",
            "*.hmackey",
            "*AES_KEY_SECRET",
            "*.key",
            "*.payload",
        ],
        censor: "[REDACTED]",
    };

    if(env.NODE_ENV = "development") {
        return pino({
            level: env.LOG_LEVEL,
            base: {service: "doorToDoor"},
            redact, 
            transport : {
                target: "pino-pretty",
                options: {colorize: true, translateTime: "HH:MM:ss"},
            }
        })
    }

    //Staging/production encrypted file stream. env.ts already guarnatees
    //LOG_ENCRPTION_KEY is present outside developemnt.

    const key = loadLogKey(env.LOG_ENCRPTION_KEY!);
    const stream = createEncyptedLogStream(env.LOG_FILE_PATH, key);

    return pino(
        {
            level: env.LOG_LEVEL,
            base: {service: "dooToDoor"},
            redact,
        },
        stream
    );
}

export const logger = buildLogger();