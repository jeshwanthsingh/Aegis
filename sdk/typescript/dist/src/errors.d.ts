export declare class AegisError extends Error {
    constructor(message: string);
}
export declare class AegisConnectionError extends AegisError {
}
export declare class AegisConfigurationError extends AegisError {
}
export declare class AegisAPIError extends AegisError {
    readonly statusCode: number;
    readonly code: string;
    readonly details?: Record<string, unknown>;
    constructor(statusCode: number, code: string, message: string, details?: Record<string, unknown>);
}
export declare class AegisAuthError extends AegisAPIError {
}
export declare class AegisValidationError extends AegisAPIError {
}
export declare class AegisExecutionError extends AegisError {
    readonly executionId?: string;
    readonly exitCode?: number;
    readonly exitReason?: string;
    readonly rawResponse?: Record<string, unknown>;
    constructor(message: string, options?: {
        executionId?: string;
        exitCode?: number;
        exitReason?: string;
        rawResponse?: Record<string, unknown>;
    });
}
export declare class AegisVerificationError extends AegisError {
}
export declare class AegisStreamError extends AegisError {
}
export declare function mapApiError(statusCode: number, code: string, message: string, details?: Record<string, unknown>): AegisAPIError;
