"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const argon2 = require("argon2themax");
const rp = require("request-promise");
const _ = require("lodash");
const pwhaasDefaultApiKey = "[Your API Key Here]";
const pwhaasDefaultApiRootUri = "https://api.pwhaas.com";
exports.defaultClientOptions = () => {
    return {
        apiKey: process.env.PWHAAS_API_KEY || pwhaasDefaultApiKey,
        maxtime: process.env.PWHAAS_MAX_TIME ? parseInt(process.env.PWHAAS_MAX_TIME) : 500,
        serviceRootUri: process.env.PWHAAS_ROOT_URI || pwhaasDefaultApiRootUri,
        request: {
            method: "POST",
            json: true,
            timeout: process.env.PWHAAS_API_TIMEOUT ? parseInt(process.env.PWHAAS_API_TIMEOUT) : 5000
        },
        disableLocalHashingFallback: !!process.env.PWHAAS_DISABLE_LOCAL_HASHING_FALLBACK,
        disablePreHash: !!process.env.PWHAAS_DISABLE_PRE_HASH
    };
};
// These are the same defaults as argon2 lib.
// But we set them here for consistency across versions.
let hashOptions = {
    hashLength: 32,
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    type: argon2.argon2i
};
class HashRequest {
    constructor(plain, maxtime) {
        this.plain = plain;
        this.maxtime = maxtime;
    }
}
class VerifyRequest {
    constructor(hash, plain) {
        this.hash = hash;
        this.plain = plain;
    }
}
class PwhaasClient {
    constructor(options = exports.defaultClientOptions()) {
        this.setOptions(options);
    }
    setOptions(options) {
        this.options = _.assignIn({}, exports.defaultClientOptions(), options);
    }
    hash(plain, maxtime = this.options.maxtime) {
        return __awaiter(this, void 0, void 0, function* () {
            const req = new HashRequest(plain, maxtime);
            return yield this.postJson("hash", req);
        });
    }
    verify(hash, plain) {
        return __awaiter(this, void 0, void 0, function* () {
            const req = new VerifyRequest(hash, plain);
            return yield this.postJson("verify", req);
        });
    }
    postJson(relativeUri, body) {
        return __awaiter(this, void 0, void 0, function* () {
            const requestOptions = _.cloneDeep(this.options.request);
            requestOptions.body = body;
            requestOptions.auth = {
                user: this.options.apiKey,
                sendImmediately: true
            };
            const uri = `${this.options.serviceRootUri}/${relativeUri}`;
            let result = yield rp(uri, requestOptions);
            return result;
        });
    }
}
exports.PwhaasClient = PwhaasClient;
class LocalHash {
    constructor(remoteHash, localSalt, preHashDisabled) {
        this.remoteHash = remoteHash;
        this.localSalt = localSalt;
        this.preHashDisabled = preHashDisabled;
    }
    static from(encodedHash) {
        const parts = encodedHash.split(":", 4);
        if (parts.length !== 4 || parts[0] !== "pwhaas") {
            throw new Error("Unrecognized hash. Was it created with pwhaas?");
        }
        const hashVersion = parts[1];
        if (!LocalHash.supportedHashVersions[hashVersion]) {
            throw new Error("Unsupported hash version. Maybe you need to update pwhaas?");
        }
        // Version 0 required a salt
        if (hashVersion === "0") {
            const localSalt = Buffer.from(parts[2], "base64");
            return new LocalHash(parts[3], localSalt);
        }
        // Version 1 no longer requires salt
        // If salt is not included, we assume local hash was disabled
        if (hashVersion === "1") {
            const encodedSalt = parts[2];
            const localSalt = encodedSalt ? Buffer.from(encodedSalt, "base64") : null;
            return new LocalHash(parts[3], localSalt, !localSalt);
        }
        // This is unreachable
        // Leaving it here as a reminder to add in parsing code when the version changes
        throw new Error(`Parser not implemented for hash version "${parts[1]}". Implement one.`);
    }
    toString() {
        const saltStr = this.localSalt ? this.localSalt.toString("base64") : "";
        // Tag this so we know it is our hash, including a version field.
        // Colons are a reasonable/simple separator since salt is base64 encoded.
        // TODO: Include the local argon2 options to support using non-defaults
        return `pwhaas:${LocalHash.hashVersion}:${saltStr}:${this.remoteHash}`;
    }
}
LocalHash.supportedHashVersions = {
    "0": true,
    "1": true // Supports no pre-hashing
};
LocalHash.hashVersion = "1";
class Pwhaas {
    constructor(clientOptions = exports.defaultClientOptions()) {
        this.logOutput = console.log;
        this.client = new PwhaasClient(clientOptions);
    }
    get options() {
        return this.client.options;
    }
    setOptions(options) {
        this.client.setOptions(options);
    }
    init(options) {
        return __awaiter(this, void 0, void 0, function* () {
            if (options) {
                this.setOptions(options);
            }
            ;
            // Don't need to get max options if we do not do hash locally
            if (!this.options.disableLocalHashingFallback) {
                this.maxLocalOptions = yield argon2.getMaxOptions();
            }
            return this.maxLocalOptions;
        });
    }
    generateSalt(length) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield argon2.generateSalt(length);
        });
    }
    static hrTimeToMs(hrTime) {
        return hrTime[0] * 1e3 + hrTime[1] / 1e6;
    }
    hash(plain, maxtime = this.options.maxtime) {
        return __awaiter(this, void 0, void 0, function* () {
            // A little marketing... More security for little cost is better, right?
            if (this.options.apiKey === pwhaasDefaultApiKey &&
                this.options.serviceRootUri === pwhaasDefaultApiRootUri) {
                this.logOutput(`pwhaas: Using free trial account. Sign up at pwhaas.com for a more secure hash. Plans starting at only $10/mo.`);
            }
            const startHrTime = process.hrtime();
            let secretPlain = plain;
            let saltElapsedHr = startHrTime;
            let salt = null;
            if (!this.options.disablePreHash) {
                salt = yield this.generateSalt();
                saltElapsedHr = process.hrtime(startHrTime);
                secretPlain = yield argon2.hash(plain, Object.assign({}, hashOptions, { salt }));
            }
            let hashResult;
            try {
                hashResult = yield this.client.hash(secretPlain, maxtime);
            }
            catch (error) {
                // We may be configured to not hash locally -- just throw the error
                if (this.options.disableLocalHashingFallback) {
                    throw error;
                }
                if (!this.maxLocalOptions) {
                    yield this.init();
                }
                const salt = yield this.generateSalt();
                const hashStartHrTime = process.hrtime();
                const hash = yield argon2.hash(secretPlain, salt, this.maxLocalOptions);
                const hashElapsedHrTime = process.hrtime(hashStartHrTime);
                hashResult = {
                    local: true,
                    error,
                    options: this.maxLocalOptions,
                    hash,
                    timing: {
                        salt: Pwhaas.hrTimeToMs(saltElapsedHr),
                        hash: Pwhaas.hrTimeToMs(hashElapsedHrTime)
                    }
                };
            }
            // Replace the remote hash with our encoded hash.
            // This is so we can reproduce the operations used to recreate 
            // the hashed password during the verify step, without having to 
            // store the weaker intermediate hash anywhere.
            const localhash = new LocalHash(hashResult.hash, salt, this.options.disablePreHash);
            hashResult.hash = localhash.toString();
            const elapsedHrTime = process.hrtime(startHrTime);
            const overallDesc = hashResult.local
                ? `pwhaas: API UNAVAILABLE. Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`
                : `pwhaas: Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`;
            const hashDesc = `Hash: ${hashResult.timing.hash}ms.`;
            const threadsDesc = `Threads: ${hashResult.options.parallelism}`;
            const memoryDesc = `Memory: ${Math.pow(2, hashResult.options.memoryCost) / 1024}MB`;
            const iterationsDesc = `Iterations: ${hashResult.options.timeCost}`;
            this.logOutput(`${overallDesc} ${hashDesc} ${threadsDesc} ${memoryDesc} ${iterationsDesc}`);
            return hashResult;
        });
    }
    verify(hash, plain) {
        return __awaiter(this, void 0, void 0, function* () {
            // A little marketing... More security for little cost is better, right?
            if (this.options.apiKey === pwhaasDefaultApiKey &&
                this.options.serviceRootUri === pwhaasDefaultApiRootUri) {
                this.logOutput(`pwhaas: Using free trial account. Sign up at pwhaas.com for a more secure hash. Plans starting at only $10/mo.`);
            }
            const startHrTime = process.hrtime();
            // Use the same salt we used when hashing locally before.
            const localHash = LocalHash.from(hash);
            let secretPlain = plain;
            if (!localHash.preHashDisabled) {
                secretPlain = yield argon2.hash(plain, Object.assign({}, hashOptions, { salt: localHash.localSalt }));
            }
            // Try to do the verify remotely. If fail, do it locally (bummer).
            let verifyResp;
            try {
                verifyResp = yield this.client.verify(localHash.remoteHash, secretPlain);
            }
            catch (error) {
                if (this.options.disableLocalHashingFallback) {
                    throw error;
                }
                const verifyStart = process.hrtime();
                const localMatch = yield argon2.verify(localHash.remoteHash, secretPlain);
                const verifyElapsed = process.hrtime(verifyStart);
                verifyResp = {
                    local: true,
                    error,
                    match: localMatch,
                    timing: {
                        verify: Pwhaas.hrTimeToMs(verifyElapsed)
                    }
                };
            }
            const elapsedHrTime = process.hrtime(startHrTime);
            const overallDesc = verifyResp.local
                ? `pwhaas: API UNAVAILABLE. Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`
                : `pwhaas: Operation took ${Pwhaas.hrTimeToMs(elapsedHrTime)}ms.`;
            const hashDesc = `Verify: ${verifyResp.timing.verify}ms.`;
            this.logOutput(`${overallDesc} ${hashDesc}`);
            return verifyResp;
        });
    }
}
exports.Pwhaas = Pwhaas;
exports.pwhaas = new Pwhaas();
