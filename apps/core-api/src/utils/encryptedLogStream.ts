import { Writable } from "stream";
import fs from 'fs';
import path from "path";
import { encryptionLogLine } from "./logEncryption";

export function createEncyptedLogStream(filePath: string, key: Buffer) : Writable {
    const dir = path.dirname(filePath);
    fs.mkdirSync(dir, {recursive: true});

    const fileStream = fs.createWriteStream(filePath, {flags : "a"});

    return new Writable({
        write(chunk: Buffer, _encoding, callback) {
            try {
                const line = chunk.toString("utf8").replace(/\n$/, "");
                if(line.length ===0 ) return callback();
                const encrypted = encryptionLogLine(line, key);
                fileStream.write(encrypted + "\n", callback);
            }catch(err) {
                callback(err instanceof Error ? err: new Error("Log encyption failed"));
            }
        }
    })
}