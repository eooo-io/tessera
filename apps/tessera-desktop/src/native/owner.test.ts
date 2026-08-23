import { invoke } from '@tauri-apps/api/core'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { lockVault, normalizeOwnerError, openVault } from './owner'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))

const invokeMock = vi.mocked(invoke)

describe('native owner adapter', () => {
  beforeEach(() => invokeMock.mockReset())

  it('projects a successful result onto the closed overview contract', async () => {
    invokeMock.mockResolvedValue({
      schema: 'tessera.desktop.overview.v1',
      state: 'unlocked',
      formatVersion: 3,
      spaceCount: 2,
      pendingReviewCount: 1,
      activeSessionCount: 0,
      receiptChain: 'verified',
      receiptCount: 3,
      diagnosticStatus: 'healthy',
      rawPath: '/must/not/pass/through',
    })

    const result = await openVault('/synthetic/V.tessera', 'TRANSIENT-SECRET')
    expect(invokeMock).toHaveBeenCalledWith('open_vault', {
      vaultPath: '/synthetic/V.tessera',
      passphrase: 'TRANSIENT-SECRET',
    })
    expect(Object.keys(result).sort()).toEqual([
      'activeSessionCount',
      'diagnosticStatus',
      'formatVersion',
      'pendingReviewCount',
      'receiptChain',
      'receiptCount',
      'schema',
      'spaceCount',
      'state',
    ])
    expect(JSON.stringify(result)).not.toContain('/must/not/pass/through')
  })

  it('normalizes malformed native failures without echoing their payload', () => {
    expect(normalizeOwnerError({ detail: 'TRANSIENT-SECRET /private/path sqlite hash' })).toEqual({
      code: 'internal_failure',
      message: 'The native vault operation failed safely. The vault remains locked.',
    })
  })

  it('invokes the idempotent lock command without arguments', async () => {
    invokeMock.mockResolvedValue({ schema: 'tessera.desktop.lock.v1', state: 'locked' })
    await expect(lockVault()).resolves.toEqual({ schema: 'tessera.desktop.lock.v1', state: 'locked' })
    expect(invokeMock).toHaveBeenCalledWith('lock_vault')
  })
})
