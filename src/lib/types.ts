export type Category = "All files" | "Photos" | "Videos" | "Audio" | "Documents" | "Archives" | "Applications" | "Other";
export type TransferState = "queued" | "preparing" | "uploading" | "downloading" | "paused" | "waiting" | "complete" | "failed";

export interface VaultFile {
  id: string;
  name: string;
  folderPath?: string;
  category: Exclude<Category, "All files">;
  size: number;
  mimeType: string;
  encrypted: boolean;
  cached: boolean;
  chunkCount: number;
  accountId: string;
  accountName: string;
  createdAt: string;
  status: "ready" | "uploading" | "missing" | "trashed";
  thumbnail?: string;
  favorite: boolean;
  tags: string[];
  lastOpenedAt?: string;
  deletedAt?: string;
  purgeAt?: string;
}

export interface VaultFolderRecord {
  id: string;
  path: string;
  name: string;
  createdAt: string;
}

export interface Transfer {
  id: string;
  fileId?: string;
  fileName: string;
  direction: "upload" | "download" | "share";
  state: TransferState;
  progress: number;
  transferred: number;
  total: number;
  speed: number;
  etaSeconds?: number;
  message?: string;
  encrypted: boolean;
}

export interface Account {
  id: string;
  name: string;
  phone: string;
  connected: boolean;
  color: string;
  initials: string;
  fileCount: number;
  storedBytes: number;
}

export interface WatchFolder {
  id: string;
  path: string;
  enabled: boolean;
  encrypt: boolean;
  accountId: string;
  uploadedCount: number;
}

export type NewWatchFolder = Pick<WatchFolder, "path" | "enabled" | "encrypt" | "accountId">;

export interface Dashboard {
  files: VaultFile[];
  folders: VaultFolderRecord[];
  transfers: Transfer[];
  accounts: Account[];
  watchFolders: WatchFolder[];
  cacheUsed: number;
  cacheLimit: number;
  previewCacheLimit: number;
  previewCacheTtlMinutes: number;
  storedBytes: number;
  encryptionReady: boolean;
  keychainBacked: boolean;
  appLockEnabled: boolean;
  appLockTimeoutMinutes: number;
  speedProfile: "low-impact" | "balanced" | "maximum";
  recycleRetentionDays: number;
  automaticRetryCount: number;
  notificationsEnabled: boolean;
  healthChecksEnabled: boolean;
  healthCheckIntervalDays: number;
  latestHealthReport?: HealthReport;
  automaticUpdatesConfigured: boolean;
}

export interface LockStatus {
  enabled: boolean;
  locked: boolean;
  keychainBacked: boolean;
}

export interface RecoveryReport {
  scannedMessages: number;
  manifestsFound: number;
  restored: number;
  skipped: number;
  warnings: string[];
}

export interface RecoveryTestReport {
  checkedAt: string;
  keyValid: boolean;
  filesSampled: number;
  manifestsValid: number;
  chunksAvailable: number;
  warnings: string[];
}

export interface HealthReport {
  checkedAt: string;
  accountId: string;
  filesSampled: number;
  chunksChecked: number;
  hashesVerified: number;
  missing: number;
  corrupted: number;
  healthy: boolean;
  warnings: string[];
}

export interface PreviewInfo {
  token: string;
  url: string;
  kind: "image" | "video" | "audio" | "pdf" | "text" | "document" | "unsupported";
  mimeType: string;
  size: number;
  cacheLimit: number;
  expiresAt: string;
  message?: string;
}

export interface PreviewText {
  content: string;
  truncated: boolean;
}

export interface ShareRecipient {
  token: string;
  username: string;
  displayName: string;
  initials: string;
  kind: "user" | "bot";
  verified: boolean;
  expiresAt: string;
}

export interface UploadOptions {
  paths: string[];
  folderRoot?: string;
  destinationFolder?: string;
  encrypt: boolean;
  accountId: string;
  duplicatePolicy: "skip" | "keep";
}

export interface LoginRequest {
  accountId?: string;
  name: string;
  phone: string;
  apiId: number;
  apiHash: string;
}

export interface LoginResult {
  flowId: string;
  status: "code_sent" | "qr_pending" | "password_required" | "connected";
  hint?: string;
  qrUrl?: string;
  expiresAt?: number;
}
