import { coerceIntentPayload } from "./intent.js";
export class ExecutionRequest {
    language;
    code;
    timeoutMs;
    intent;
    profile;
    workspaceId;
    executionId;
    constructor(init) {
        this.language = init.language;
        this.code = init.code;
        this.timeoutMs = init.timeoutMs;
        this.intent = init.intent;
        this.profile = init.profile;
        this.workspaceId = init.workspaceId;
        this.executionId = init.executionId;
    }
    toPayload() {
        const payload = { lang: this.language, code: this.code };
        if (this.timeoutMs !== undefined)
            payload.timeout_ms = this.timeoutMs;
        if (this.profile)
            payload.profile = this.profile;
        if (this.workspaceId)
            payload.workspace_id = this.workspaceId;
        if (this.executionId)
            payload.execution_id = this.executionId;
        const intentPayload = coerceIntentPayload(this.intent);
        if (intentPayload)
            payload.intent = intentPayload;
        return payload;
    }
}
