import { ProofBundle } from "./types.js";
export declare class StreamEvent {
    readonly type: string;
    readonly raw: Record<string, unknown>;
    constructor(type: string, raw: Record<string, unknown>);
}
export declare class StdoutEvent extends StreamEvent {
    readonly chunk: string;
    constructor(raw: Record<string, unknown>);
}
export declare class StderrEvent extends StreamEvent {
    readonly chunk: string;
    constructor(raw: Record<string, unknown>);
}
export declare class ProofEvent extends StreamEvent {
    readonly executionId?: string;
    readonly proofBundle: ProofBundle;
    readonly artifactCount: number;
    readonly divergenceVerdict?: string;
    constructor(raw: Record<string, unknown>);
}
export declare class ErrorEvent extends StreamEvent {
    readonly error: string;
    constructor(raw: Record<string, unknown>);
}
export declare class DoneEvent extends StreamEvent {
    readonly exitCode: number;
    readonly reason?: string;
    readonly durationMs: number;
    constructor(raw: Record<string, unknown>);
    get ok(): boolean;
}
export type ParsedStreamEvent = StreamEvent | StdoutEvent | StderrEvent | ProofEvent | ErrorEvent | DoneEvent;
export declare function parseStreamEvent(raw: Record<string, unknown>): ParsedStreamEvent;
