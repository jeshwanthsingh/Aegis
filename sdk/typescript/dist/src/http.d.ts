export declare class HTTPTransport {
    private readonly baseUrl;
    private readonly apiKey?;
    private readonly timeoutMs;
    constructor(options: {
        baseUrl: string;
        apiKey?: string;
        timeoutMs: number;
    });
    requestJson(method: string, path: string, options?: {
        payload?: Record<string, unknown>;
        authenticated?: boolean;
    }): Promise<Record<string, unknown>>;
    streamSse(path: string, options: {
        payload: Record<string, unknown>;
        authenticated?: boolean;
    }): AsyncIterable<Record<string, unknown>>;
    private buildRequest;
    private mapHttpError;
}
