export type NavId =
  | 'overview'
  | 'inbox'
  | 'spaces'
  | 'lenses'
  | 'agents'
  | 'sessions'
  | 'receipts'
  | 'evaluation'
  | 'diagnostics'

export type InboxStatus = 'ready' | 'processing' | 'attention' | 'restricted'

export interface InboxItem {
  id: string
  name: string
  kind: string
  source: string
  imported: string
  size: string
  status: InboxStatus
  summary: string
  excerpt: string
  spaces: string[]
  lenses: string[]
}

export interface SessionRecord {
  id: string
  agent: string
  lens: string
  purpose: string
  remaining: string
  state: 'active' | 'closed'
}

export interface ToastMessage {
  id: number
  tone: 'success' | 'info' | 'warning'
  text: string
}

export type VaultUiState = 'locked' | 'unlocking' | 'unlocked'

export type ReceiptChainStatus = 'verified' | 'invalid'
export type DiagnosticStatus = 'healthy' | 'attention' | 'fatal'

export interface SanitizedOverview {
  schema: 'tessera.desktop.overview.v1'
  state: 'unlocked'
  formatVersion: number
  spaceCount: number
  pendingReviewCount: number
  activeSessionCount: number
  receiptChain: ReceiptChainStatus
  receiptCount: number
  diagnosticStatus: DiagnosticStatus
}

export type OwnerErrorCode =
  | 'invalid_credentials'
  | 'unsupported_format'
  | 'migration_required'
  | 'invalid_bundle'
  | 'unsafe_path'
  | 'already_unlocked'
  | 'native_state_unavailable'
  | 'internal_failure'

export interface OwnerSafeError {
  code: OwnerErrorCode
  message: string
}

export interface LockResult {
  schema: 'tessera.desktop.lock.v1'
  state: 'locked'
}
