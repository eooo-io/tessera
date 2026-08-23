import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import App from './App'
import type { OwnerClient } from './native/owner'
import type { SanitizedOverview } from './types'

const overview: SanitizedOverview = {
  schema: 'tessera.desktop.overview.v1',
  state: 'unlocked',
  formatVersion: 3,
  spaceCount: 4,
  pendingReviewCount: 2,
  activeSessionCount: 1,
  receiptChain: 'verified',
  receiptCount: 7,
  diagnosticStatus: 'healthy',
}

function client(overrides: Partial<OwnerClient> = {}): OwnerClient {
  return {
    openVault: vi.fn().mockResolvedValue(overview),
    lockVault: vi.fn().mockResolvedValue({ schema: 'tessera.desktop.lock.v1', state: 'locked' }),
    ...overrides,
  }
}

async function fillUnlock(user: ReturnType<typeof userEvent.setup>, path = '/synthetic/V.tessera', passphrase = 'TRANSIENT-PASSPHRASE') {
  await user.type(screen.getByLabelText('Vault bundle'), path)
  await user.type(screen.getByLabelText('Passphrase'), passphrase)
  await user.click(screen.getByRole('button', { name: 'Unlock vault' }))
}

describe('Tessera owner workbench', () => {
  it('starts locked on the live overview with no fixture aggregate', () => {
    render(<App ownerClient={client()} />)
    expect(screen.getByRole('heading', { name: 'Open your vault' })).toBeInTheDocument()
    expect(screen.getAllByText('Locked').length).toBeGreaterThan(0)
    expect(screen.queryByText('1,284')).not.toBeInTheDocument()
  })

  it('unlocks through the typed owner client and clears the passphrase', async () => {
    const user = userEvent.setup()
    const ownerClient = client()
    render(<App ownerClient={ownerClient} />)
    await fillUnlock(user)

    await waitFor(() => expect(ownerClient.openVault).toHaveBeenCalledWith('/synthetic/V.tessera', 'TRANSIENT-PASSPHRASE'))
    expect(screen.queryByLabelText('Passphrase')).not.toBeInTheDocument()
    expect(screen.getByText('Format v3')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.queryByText('/synthetic/V.tessera')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Lock vault' }))
    expect(screen.getByLabelText('Passphrase')).toHaveValue('')
  })

  it('remains locked after failure, shows bounded guidance, and clears the passphrase', async () => {
    const user = userEvent.setup()
    const ownerClient = client({
      openVault: vi.fn().mockRejectedValue({
        code: 'invalid_credentials',
        message: 'The vault could not be unlocked. Check the passphrase and try again.',
      }),
    })
    render(<App ownerClient={ownerClient} />)
    await fillUnlock(user)

    expect(await screen.findByRole('alert')).toHaveTextContent('could not be unlocked')
    expect(screen.getByLabelText('Passphrase')).toHaveValue('')
    expect(screen.getAllByText('Locked').length).toBeGreaterThan(0)
    expect(screen.queryByText('Format v3')).not.toBeInTheDocument()
  })

  it('clears the live overview immediately when explicitly locked', async () => {
    const user = userEvent.setup()
    const releaseLock: { resolve?: (value: { schema: 'tessera.desktop.lock.v1'; state: 'locked' }) => void } = {}
    const ownerClient = client({
      lockVault: vi.fn().mockImplementation(() => new Promise((resolve) => { releaseLock.resolve = resolve })),
    })
    render(<App ownerClient={ownerClient} />)
    await fillUnlock(user)
    expect(await screen.findByText('Format v3')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Lock vault' }))
    expect(screen.queryByText('Format v3')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Open your vault' })).toBeInTheDocument()
    releaseLock.resolve?.({ schema: 'tessera.desktop.lock.v1', state: 'locked' })
  })

  it('labels every non-overview screen as preview-only and disables its actions', async () => {
    const user = userEvent.setup()
    render(<App ownerClient={client()} />)
    await user.click(screen.getByRole('button', { name: /Inbox/ }))
    expect(screen.getByRole('status')).toHaveTextContent('Preview fixtures')
    expect(screen.getByRole('button', { name: 'Import more' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Accept' })).toBeDisabled()
  })

  it('switches between the packaged light and dark themes', async () => {
    const user = userEvent.setup()
    render(<App ownerClient={client()} />)
    await user.click(screen.getByRole('button', { name: 'Use light theme' }))
    expect(document.documentElement.dataset.theme).toBe('eooo-light')
    await user.click(screen.getByRole('button', { name: 'Use dark theme' }))
    expect(document.documentElement.dataset.theme).toBe('eooo-dark')
  })

  it('provides keyboard-reachable lifecycle controls and a compact navigation drawer', async () => {
    const user = userEvent.setup()
    render(<App ownerClient={client()} />)
    await user.tab()
    expect(document.activeElement).toHaveAccessibleName(/Overview/)
    await user.click(screen.getByRole('button', { name: 'Open navigation' }))
    expect(screen.getAllByRole('button', { name: 'Close navigation' })).toHaveLength(2)
    await user.click(screen.getAllByRole('button', { name: 'Close navigation' })[1])
    expect(screen.queryByRole('button', { name: 'Close navigation' })).not.toBeInTheDocument()
  })
})
