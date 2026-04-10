export class AegisError extends Error {
    constructor(message) {
        super(message);
        this.name = new.target.name;
    }
}
export class AegisConnectionError extends AegisError {
}
export class AegisConfigurationError extends AegisError {
}
export class AegisAPIError extends AegisError {
    statusCode;
    code;
    details;
    constructor(statusCode, code, message, details) {
        super(`HTTP ${statusCode}${code ? ` (${code})` : ""}: ${message}`);
        this.statusCode = statusCode;
        this.code = code;
        this.details = details;
    }
}
export class AegisAuthError extends AegisAPIError {
}
export class AegisValidationError extends AegisAPIError {
}
export class AegisExecutionError extends AegisError {
    executionId;
    exitCode;
    exitReason;
    rawResponse;
    constructor(message, options = {}) {
        const parts = [message];
        if (options.executionId)
            parts.push(`executionId=${options.executionId}`);
        if (options.exitCode !== undefined)
            parts.push(`exitCode=${options.exitCode}`);
        if (options.exitReason)
            parts.push(`exitReason=${options.exitReason}`);
        super(parts.join(" "));
        this.executionId = options.executionId;
        this.exitCode = options.exitCode;
        this.exitReason = options.exitReason;
        this.rawResponse = options.rawResponse;
    }
}
export class AegisVerificationError extends AegisError {
}
export class AegisStreamError extends AegisError {
}
export function mapApiError(statusCode, code, message, details) {
    if (statusCode === 401 || code.startsWith("auth_")) {
        return new AegisAuthError(statusCode, code, message, details);
    }
    if (statusCode === 400 || ["invalid_request", "invalid_intent_contract", "invalid_profile", "validation_error"].includes(code)) {
        return new AegisValidationError(statusCode, code, message, details);
    }
    return new AegisAPIError(statusCode, code, message, details);
}
