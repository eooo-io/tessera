import { invoke } from '@tauri-apps/api/core'
import type {
  DiagnosticStatus,
  LockResult,
  OwnerErrorCode,
  OwnerSafeError,
  ReceiptChainStatus,
  SanitizedOverview,
} from '../types'

export interface OwnerClient {
  openVault: (vaultPath: string, passphrase: string) => Promise<SanitizedOverview>
  lockVault: () => Promise<LockResult>
}

const safeMessages: Record<OwnerErrorCode, string> = {
  invalid_credentials: 'The vault could not be unlocked. Check the passphrase and try again.',
  unsupported_format: 'This vault format is not supported by this version of Tessera.',
  migration_required: 'This vault requires an owner-approved migration before the desktop can open it.',
  invalid_bundle: 'The selected bundle could not be validated as a current Tessera vault.',
  unsafe_path: 'The selected bundle contains an unsafe filesystem entry and was refused.',
  already_unlocked: 'Lock the current vault before opening another one.',
  native_state_unavailable: 'The native vault state is unavailable. Restart Tessera before trying again.',
  internal_failure: 'The native vault operation failed safely. The vault remains locked.',
}

const errorCodes = new Set<OwnerErrorCode>(Object.keys(safeMessages) as OwnerErrorCode[])
const receiptStatuses = new Set<ReceiptChainStatus>(['verified', 'invalid'])
const diagnosticStatuses = new Set<DiagnosticStatus>(['healthy', 'attention', 'fatal'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

export function normalizeOwnerError(value: unknown): OwnerSafeError {
  const candidate = isRecord(value) ? value.code : undefined
  const code = typeof candidate === 'string' && errorCodes.has(candidate as OwnerErrorCode)
    ? candidate as OwnerErrorCode
    : 'internal_failure'
  return { code, message: safeMessages[code] }
}

function projectOverview(value: unknown): SanitizedOverview {
  if (!isRecord(value)
    || value.schema !== 'tessera.desktop.overview.v1'
    || value.state !== 'unlocked'
    || !isCount(value.formatVersion)
    || !isCount(value.spaceCount)
    || !isCount(value.pendingReviewCount)
    || !isCount(value.activeSessionCount)
    || typeof value.receiptChain !== 'string'
    || !receiptStatuses.has(value.receiptChain as ReceiptChainStatus)
    || !isCount(value.receiptCount)
    || typeof value.diagnosticStatus !== 'string'
    || !diagnosticStatuses.has(value.diagnosticStatus as DiagnosticStatus)) {
    throw normalizeOwnerError(undefined)
  }

  return {
    schema: 'tessera.desktop.overview.v1',
    state: 'unlocked',
    formatVersion: value.formatVersion,
    spaceCount: value.spaceCount,
    pendingReviewCount: value.pendingReviewCount,
    activeSessionCount: value.activeSessionCount,
    receiptChain: value.receiptChain as ReceiptChainStatus,
    receiptCount: value.receiptCount,
    diagnosticStatus: value.diagnosticStatus as DiagnosticStatus,
  }
}

export async function openVault(vaultPath: string, passphrase: string): Promise<SanitizedOverview> {
  return invoke('open_vault', { vaultPath, passphrase })
    .then(projectOverview)
    .catch((error: unknown) => Promise.reject(normalizeOwnerError(error)))
}

export async function lockVault(): Promise<LockResult> {
  try {
    const result = await invoke('lock_vault')
    if (!isRecord(result) || result.schema !== 'tessera.desktop.lock.v1' || result.state !== 'locked') {
      throw normalizeOwnerError(undefined)
    }
    return { schema: 'tessera.desktop.lock.v1', state: 'locked' }
  } catch (error) {
    throw normalizeOwnerError(error)
  }
}

export const nativeOwnerClient: OwnerClient = { openVault, lockVault }
