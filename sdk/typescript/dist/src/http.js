import { AegisConnectionError, AegisStreamError, mapApiError } from "./errors.js";
export class HTTPTransport {
    baseUrl;
    apiKey;
    timeoutMs;
    constructor(options) {
        this.baseUrl = options.baseUrl.replace(/\/$/, "");
        this.apiKey = options.apiKey;
        this.timeoutMs = options.timeoutMs;
    }
    async requestJson(method, path, options = {}) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const response = await fetch(this.baseUrl + path, this.buildRequest(method, options.payload, options.authenticated ?? true, controller.signal));
            if (!response.ok)
                throw await this.mapHttpError(response);
            const text = await response.text();
            try {
                return JSON.parse(text);
            }
            catch (error) {
                throw new AegisConnectionError(`server returned invalid JSON: ${String(error)}`);
            }
        }
        catch (error) {
            if (error instanceof Error && error.name === "AbortError") {
                throw new AegisConnectionError("request timed out");
            }
            if (error instanceof Error && error.name.startsWith("Aegis")) {
                throw error;
            }
            throw new AegisConnectionError(String(error));
        }
        finally {
            clearTimeout(timer);
        }
    }
    async *streamSse(path, options) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        let response;
        try {
            response = await fetch(this.baseUrl + path, this.buildRequest("POST", options.payload, options.authenticated ?? true, controller.signal, true));
        }
        catch (error) {
            clearTimeout(timer);
            if (error instanceof Error && error.name === "AbortError") {
                throw new AegisConnectionError("request timed out");
            }
            throw new AegisConnectionError(String(error));
        }
        if (!response.ok) {
            clearTimeout(timer);
            throw await this.mapHttpError(response);
        }
        const contentType = response.headers.get("content-type") ?? "";
        if (!contentType.includes("text/event-stream")) {
            clearTimeout(timer);
            const body = await response.text();
            throw new AegisStreamError(`expected text/event-stream, got ${contentType || "unknown"}: ${body}`);
        }
        const reader = response.body?.getReader();
        if (!reader) {
            clearTimeout(timer);
            throw new AegisStreamError("streaming response did not expose a readable body");
        }
        const decoder = new TextDecoder();
        let buffer = "";
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done)
                    break;
                buffer += decoder.decode(value, { stream: true });
                let separator = buffer.indexOf("\n\n");
                while (separator !== -1) {
                    const chunk = buffer.slice(0, separator);
                    buffer = buffer.slice(separator + 2);
                    const parsed = parseSseChunk(chunk);
                    if (parsed)
                        yield parsed;
                    separator = buffer.indexOf("\n\n");
                }
            }
            buffer += decoder.decode();
            const finalChunk = parseSseChunk(buffer.trim());
            if (finalChunk)
                yield finalChunk;
        }
        finally {
            clearTimeout(timer);
            reader.releaseLock();
        }
    }
    buildRequest(method, payload, authenticated, signal, stream = false) {
        const headers = { Accept: stream ? "text/event-stream" : "application/json" };
        if (payload)
            headers["Content-Type"] = "application/json";
        if (authenticated && this.apiKey)
            headers.Authorization = `Bearer ${this.apiKey}`;
        return {
            method,
            headers,
            body: payload ? JSON.stringify(payload) : undefined,
            signal,
        };
    }
    async mapHttpError(response) {
        const body = await response.text();
        let code = "http_error";
        let message = body.trim() || response.statusText || `HTTP ${response.status}`;
        let details;
        try {
            const payload = JSON.parse(body);
            if (payload.error && typeof payload.error === "object") {
                if (typeof payload.error.code === "string")
                    code = payload.error.code;
                if (typeof payload.error.message === "string")
                    message = payload.error.message;
                if (payload.error.details && typeof payload.error.details === "object")
                    details = payload.error.details;
            }
        }
        catch {
            // keep fallback body message
        }
        return mapApiError(response.status, code, message, details);
    }
}
function parseSseChunk(chunk) {
    if (!chunk)
        return undefined;
    const dataLines = [];
    for (const rawLine of chunk.split(/\r?\n/)) {
        if (!rawLine || rawLine.startsWith(":"))
            continue;
        if (rawLine.startsWith("data: "))
            dataLines.push(rawLine.slice(6));
    }
    if (dataLines.length === 0)
        return undefined;
    try {
        return JSON.parse(dataLines.join("\n"));
    }
    catch (error) {
        throw new AegisStreamError(`invalid SSE payload: ${String(error)}`);
    }
}
