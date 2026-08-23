import {
  Activity,
  Aperture,
  Bot,
  Boxes,
  FileCheck2,
  Gauge,
  Inbox,
  KeyRound,
  Layers3,
} from 'lucide-react'
import type { ComponentType } from 'react'
import type { NavId, VaultUiState } from '../types'
import { BrandMark } from './BrandMark'

const navItems: Array<{ id: NavId; label: string; icon: ComponentType<{ className?: string }> }> = [
  { id: 'overview', label: 'Overview', icon: Gauge },
  { id: 'inbox', label: 'Inbox', icon: Inbox },
  { id: 'spaces', label: 'Spaces', icon: Boxes },
  { id: 'lenses', label: 'Lenses', icon: Aperture },
  { id: 'agents', label: 'Agents', icon: Bot },
  { id: 'sessions', label: 'Sessions', icon: Activity },
  { id: 'receipts', label: 'Receipts', icon: FileCheck2 },
  { id: 'evaluation', label: 'Evaluation', icon: Layers3 },
  { id: 'diagnostics', label: 'Diagnostics', icon: KeyRound },
]

interface NavigationProps {
  active: NavId
  vaultState: VaultUiState
  onSelect: (id: NavId) => void
  mobile?: boolean
}

export function Navigation({ active, vaultState, onSelect, mobile = false }: NavigationProps) {
  return (
    <aside
      className={
        mobile
          ? 'flex h-full w-[min(19rem,88vw)] flex-col bg-base-200 p-4'
          : 'hidden h-screen w-60 shrink-0 flex-col border-r border-base-300 bg-base-200 p-4 lg:flex'
      }
    >
      <div className="flex items-center gap-3 px-2 py-3 text-primary">
        <BrandMark className="size-9" />
        <div>
          <div className="text-base font-semibold tracking-tight text-base-content">Tessera</div>
          <div className="meta-label">Owner workbench</div>
        </div>
      </div>

      <nav className="mt-6 flex-1" aria-label="Primary navigation">
        <ul className="menu w-full gap-1 p-0">
          {navItems.map((item) => {
            const Icon = item.icon
            return (
              <li key={item.id}>
                <button
                  type="button"
                  className={`min-h-11 gap-3 rounded-box border-l-2 ${
                    active === item.id
                      ? 'border-primary bg-primary/12 font-medium text-primary'
                      : 'border-transparent text-base-content/72 hover:bg-base-300/60 hover:text-base-content'
                  }`}
                  aria-current={active === item.id ? 'page' : undefined}
                  onClick={() => onSelect(item.id)}
                >
                  <Icon className="size-[1.1rem]" aria-hidden="true" />
                  {item.label}
                  {item.id !== 'overview' && <span className="badge badge-ghost badge-xs ml-auto">Preview</span>}
                </button>
              </li>
            )
          })}
        </ul>
      </nav>

      <div className="surface-muted p-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">My Vault</p>
            <p className="mt-1 text-xs text-base-content/55">Local · {vaultState.replace('_', ' ')}</p>
          </div>
          <span
            className={`status ${vaultState === 'unlocked' ? 'status-success' : 'status-neutral'}`}
            aria-label={`Vault ${vaultState}`}
          />
        </div>
      </div>
    </aside>
  )
}
