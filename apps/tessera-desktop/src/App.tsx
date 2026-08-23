import { useState } from 'react'
import { Info } from 'lucide-react'
import { AppShell } from './components/AppShell'
import { inboxItems, sessions } from './data/demo'
import { nativeOwnerClient, normalizeOwnerError } from './native/owner'
import type { OwnerClient } from './native/owner'
import type { NavId, SanitizedOverview, VaultUiState } from './types'
import {
  AgentsView,
  DiagnosticsView,
  EvaluationView,
  InboxView,
  LensesView,
  OverviewView,
  ReceiptsView,
  SessionsView,
  SpacesView,
} from './views/WorkbenchViews'

interface AppProps {
  ownerClient?: OwnerClient
}

function App({ ownerClient = nativeOwnerClient }: AppProps) {
  const [active, setActive] = useState<NavId>('overview')
  const [dark, setDark] = useState(true)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [vaultState, setVaultState] = useState<VaultUiState>('locked')
  const [vaultPath, setVaultPath] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [overview, setOverview] = useState<SanitizedOverview | null>(null)
  const [ownerError, setOwnerError] = useState<string | null>(null)

  const toggleTheme = () => {
    const next = !dark
    setDark(next)
    document.documentElement.dataset.theme = next ? 'eooo-dark' : 'eooo-light'
  }

  const unlock = async () => {
    if (vaultState !== 'locked' || !vaultPath.trim() || !passphrase) return
    const invocationPath = vaultPath.trim()
    const invocationPassphrase = passphrase
    setVaultState('unlocking')
    setOwnerError(null)
    try {
      const result = await ownerClient.openVault(invocationPath, invocationPassphrase)
      setOverview(result)
      setVaultPath('')
      setVaultState('unlocked')
    } catch (error) {
      setOverview(null)
      setVaultState('locked')
      setOwnerError(normalizeOwnerError(error).message)
    } finally {
      setPassphrase('')
    }
  }

  const lock = async () => {
    if (vaultState !== 'unlocked') return
    setOverview(null)
    setVaultState('locked')
    setOwnerError(null)
    try {
      await ownerClient.lockVault()
    } catch (error) {
      setOwnerError(normalizeOwnerError(error).message)
    }
  }

  const previewContent = (() => {
    switch (active) {
      case 'inbox':
        return <InboxView items={inboxItems} selected={inboxItems[0]} onSelect={() => undefined} onDecision={() => undefined} />
      case 'spaces': return <SpacesView />
      case 'lenses': return <LensesView />
      case 'agents': return <AgentsView />
      case 'sessions': return <SessionsView sessions={sessions} onRevoke={() => undefined} />
      case 'receipts': return <ReceiptsView />
      case 'evaluation': return <EvaluationView />
      case 'diagnostics': return <DiagnosticsView />
      case 'overview': return null
    }
  })()

  const content = active === 'overview' ? (
    <OverviewView
      error={ownerError}
      overview={overview}
      passphrase={passphrase}
      vaultPath={vaultPath}
      vaultState={vaultState}
      onPassphraseChange={setPassphrase}
      onPathChange={setVaultPath}
      onUnlock={unlock}
    />
  ) : (
    <PreviewBoundary>{previewContent}</PreviewBoundary>
  )

  return (
    <AppShell
      active={active}
      dark={dark}
      drawerOpen={drawerOpen}
      vaultState={vaultState}
      onDrawerChange={setDrawerOpen}
      onLock={lock}
      onNavigate={setActive}
      onToggleTheme={toggleTheme}
    >
      {content}
    </AppShell>
  )
}

function PreviewBoundary({ children }: { children: React.ReactNode }) {
  return (
    <div>
      <div className="alert mb-4 border-info/35 bg-info/8 text-sm" role="status">
        <Info className="size-4 shrink-0 text-info" aria-hidden="true" />
        <span><strong>Preview fixtures.</strong> This screen is not connected to the open vault, and its actions are disabled.</span>
      </div>
      <fieldset disabled className="contents" aria-label="Preview-only controls">
        {children}
      </fieldset>
    </div>
  )
}

export default App
