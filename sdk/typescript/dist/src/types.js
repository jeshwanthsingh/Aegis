export class ConnectionPosture {
    baseUrl;
    baseUrlSource;
    apiKeySource;
    apiKeyConfigured;
    constructor(input) {
        this.baseUrl = input.baseUrl;
        this.baseUrlSource = input.baseUrlSource;
        this.apiKeySource = input.apiKeySource;
        this.apiKeyConfigured = input.apiKeyConfigured;
    }
    get authenticated() {
        return this.apiKeyConfigured;
    }
}
export class HealthStatus {
    status;
    workerSlotsAvailable;
    workerSlotsTotal;
    constructor(input) {
        this.status = input.status;
        this.workerSlotsAvailable = input.workerSlotsAvailable;
        this.workerSlotsTotal = input.workerSlotsTotal;
    }
    get ok() {
        return this.status === "ok";
    }
}
export class ProofBundle {
    proofDir;
    receiptPath;
    receiptPublicKeyPath;
    receiptSummaryPath;
    constructor(input) {
        this.proofDir = input.proofDir;
        this.receiptPath = input.receiptPath;
        this.receiptPublicKeyPath = input.receiptPublicKeyPath;
        this.receiptSummaryPath = input.receiptSummaryPath;
    }
}
