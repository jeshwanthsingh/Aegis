export class ConnectionPosture {
  readonly baseUrl: string;
  readonly baseUrlSource: string;
  readonly apiKeySource: string;
  readonly apiKeyConfigured: boolean;

  constructor(input: { baseUrl: string; baseUrlSource: string; apiKeySource: string; apiKeyConfigured: boolean }) {
    this.baseUrl = input.baseUrl;
    this.baseUrlSource = input.baseUrlSource;
    this.apiKeySource = input.apiKeySource;
    this.apiKeyConfigured = input.apiKeyConfigured;
  }

  get authenticated(): boolean {
    return this.apiKeyConfigured;
  }
}

export class HealthStatus {
  readonly status: string;
  readonly workerSlotsAvailable: number;
  readonly workerSlotsTotal: number;

  constructor(input: { status: string; workerSlotsAvailable: number; workerSlotsTotal: number }) {
    this.status = input.status;
    this.workerSlotsAvailable = input.workerSlotsAvailable;
    this.workerSlotsTotal = input.workerSlotsTotal;
  }

  get ok(): boolean {
    return this.status === "ok";
  }
}

export class ProofBundle {
  readonly proofDir?: string;
  readonly receiptPath?: string;
  readonly receiptPublicKeyPath?: string;
  readonly receiptSummaryPath?: string;

  constructor(input: { proofDir?: string; receiptPath?: string; receiptPublicKeyPath?: string; receiptSummaryPath?: string }) {
    this.proofDir = input.proofDir;
    this.receiptPath = input.receiptPath;
    this.receiptPublicKeyPath = input.receiptPublicKeyPath;
    this.receiptSummaryPath = input.receiptSummaryPath;
  }
}
