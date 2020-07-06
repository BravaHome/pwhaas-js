import * as argon2 from "argon2themax";
import * as rp from "request-promise";
export interface ClientOptions {
    apiKey?: string;
    serviceRootUri?: string;
    maxtime?: number;
    request?: rp.RequestPromiseOptions;
    disableLocalHashingFallback?: boolean;
    disablePreHash?: boolean;
}
export declare const defaultClientOptions: () => ClientOptions;
export interface PwhaasService {
    init(options?: ClientOptions): Promise<argon2.Options>;
    hash(plain: string | Buffer, maxtime?: number): Promise<HashResponse>;
    verify(hash: string, plain: string | Buffer): Promise<VerifyResponse>;
    generateSalt(length?: number): Promise<Buffer>;
    setOptions(options: ClientOptions): void;
    readonly options: ClientOptions;
}
export interface HashTiming {
    salt: number;
    hash: number;
}
export interface VerifyTiming {
    verify: number;
}
export interface HashResponse {
    local: boolean;
    options: argon2.Options;
    hash: string;
    timing: HashTiming;
    error: any;
}
export interface VerifyResponse {
    local: boolean;
    match: boolean;
    timing: VerifyTiming;
    error: any;
}
export declare class PwhaasClient {
    options: ClientOptions;
    constructor(options?: ClientOptions);
    setOptions(options: ClientOptions): void;
    hash(plain: string, maxtime?: number): Promise<HashResponse>;
    verify(hash: string, plain: string): Promise<VerifyResponse>;
    private postJson;
}
export declare class Pwhaas implements PwhaasService {
    client: PwhaasClient;
    maxLocalOptions: argon2.Options;
    logOutput: (output: any) => void;
    constructor(clientOptions?: ClientOptions);
    readonly options: ClientOptions;
    setOptions(options: ClientOptions): void;
    init(options?: ClientOptions): Promise<argon2.Options>;
    generateSalt(length?: number): Promise<Buffer>;
    private static hrTimeToMs;
    hash(plain: string, maxtime?: number): Promise<HashResponse>;
    verify(hash: string, plain: string): Promise<VerifyResponse>;
}
export declare const pwhaas: PwhaasService;
