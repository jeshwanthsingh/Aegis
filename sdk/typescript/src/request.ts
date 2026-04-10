import { IntentContract, coerceIntentPayload } from "./intent.js";

export interface ExecutionRequestInit {
  language: string;
  code: string;
  timeoutMs?: number;
  intent?: IntentContract | Record<string, unknown>;
  profile?: string;
  workspaceId?: string;
  executionId?: string;
}

export class ExecutionRequest {
  readonly language: string;
  readonly code: string;
  readonly timeoutMs?: number;
  readonly intent?: IntentContract | Record<string, unknown>;
  readonly profile?: string;
  readonly workspaceId?: string;
  readonly executionId?: string;

  constructor(init: ExecutionRequestInit) {
    this.language = init.language;
    this.code = init.code;
    this.timeoutMs = init.timeoutMs;
    this.intent = init.intent;
    this.profile = init.profile;
    this.workspaceId = init.workspaceId;
    this.executionId = init.executionId;
  }

  toPayload(): Record<string, unknown> {
    const payload: Record<string, unknown> = { lang: this.language, code: this.code };
    if (this.timeoutMs !== undefined) payload.timeout_ms = this.timeoutMs;
    if (this.profile) payload.profile = this.profile;
    if (this.workspaceId) payload.workspace_id = this.workspaceId;
    if (this.executionId) payload.execution_id = this.executionId;
    const intentPayload = coerceIntentPayload(this.intent);
    if (intentPayload) payload.intent = intentPayload;
    return payload;
  }
}
