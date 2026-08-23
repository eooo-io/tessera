import {
  LockKeyhole,
  Menu,
  Moon,
  Search,
  ShieldCheck,
  Sun,
  X,
} from 'lucide-react'
import { useEffect, useRef } from 'react'
import type { ReactNode } from 'react'
import type { NavId, VaultUiState } from '../types'
import { BrandMark } from './BrandMark'
import { Navigation } from './Navigation'

interface AppShellProps {
  active: NavId
  children: ReactNode
  dark: boolean
  drawerOpen: boolean
  vaultState: VaultUiState
  onDrawerChange: (open: boolean) => void
  onLock: () => void
  onNavigate: (id: NavId) => void
  onToggleTheme: () => void
}

export function AppShell({
  active,
  children,
  dark,
  drawerOpen,
  vaultState,
  onDrawerChange,
  onLock,
  onNavigate,
  onToggleTheme,
}: AppShellProps) {
  const drawerRef = useRef<HTMLDivElement>(null)
  const drawerTriggerRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!drawerOpen) return
    const previouslyFocused = document.activeElement as HTMLElement | null
    const focusable = () => Array.from(
      drawerRef.current?.querySelectorAll<HTMLElement>(
        'button:not([disabled]):not([tabindex="-1"]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ) ?? [],
    )
    const frame = window.requestAnimationFrame(() => focusable()[0]?.focus())
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onDrawerChange(false)
        return
      }
      if (event.key !== 'Tab') return
      const controls = focusable()
      if (controls.length === 0) return
      const first = controls[0]
      const last = controls[controls.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      window.cancelAnimationFrame(frame)
      document.removeEventListener('keydown', onKeyDown)
      previouslyFocused?.focus()
    }
  }, [drawerOpen, onDrawerChange])

  const navigate = (id: NavId) => {
    onNavigate(id)
    onDrawerChange(false)
  }

  return (
    <div className="flex min-h-screen bg-base-200 text-base-content">
      <Navigation active={active} vaultState={vaultState} onSelect={navigate} />

      {drawerOpen && (
        <div
          ref={drawerRef}
          className="fixed inset-0 z-50 lg:hidden"
          role="dialog"
          aria-modal="true"
          aria-label="Mobile navigation"
        >
          <button
            type="button"
            tabIndex={-1}
            className="absolute inset-0 cursor-default bg-neutral/65"
            aria-label="Close navigation"
            onClick={() => onDrawerChange(false)}
          />
          <div className="relative h-full w-fit shadow-2xl">
            <Navigation active={active} vaultState={vaultState} onSelect={navigate} mobile />
            <button
              type="button"
              className="btn btn-ghost btn-square absolute right-2 top-2"
              aria-label="Close navigation"
              onClick={() => onDrawerChange(false)}
            >
              <X className="size-5" />
            </button>
          </div>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex min-h-16 items-center gap-2 border-b border-base-300 bg-base-100/95 px-3 backdrop-blur-sm sm:gap-3 sm:px-5">
          <button
            ref={drawerTriggerRef}
            type="button"
            className="btn btn-ghost btn-square lg:hidden"
            aria-label="Open navigation"
            onClick={() => onDrawerChange(true)}
          >
            <Menu className="size-5" />
          </button>
          <BrandMark className="size-7 text-primary lg:hidden" />

          <div className="hidden items-center gap-2 lg:flex">
            <span className="font-medium">My Vault</span>
            <span className={`badge badge-outline gap-1 ${vaultState === 'unlocked' ? 'badge-success' : vaultState === 'restart_required' ? 'badge-warning' : 'badge-neutral'}`}>
              <LockKeyhole className="size-3" /> {vaultLabel(vaultState)}
            </span>
            <span className="badge badge-info badge-outline gap-1">
              <ShieldCheck className="size-3" /> Local only
            </span>
          </div>

          <label className="input input-sm ml-auto hidden w-full max-w-md items-center gap-2 bg-base-200 md:flex">
            <Search className="size-4 text-base-content/50" aria-hidden="true" />
            <input type="search" className="grow" placeholder="Search is not connected" aria-label="Search vault preview" disabled />
            <kbd className="kbd kbd-xs hidden xl:inline-flex">⌘K</kbd>
          </label>

          <button
            type="button"
            className="btn btn-ghost btn-square btn-sm ml-auto md:ml-0"
            aria-label={dark ? 'Use light theme' : 'Use dark theme'}
            onClick={onToggleTheme}
          >
            {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </button>
          <button
            type="button"
            className="btn btn-neutral btn-sm gap-2"
            aria-label="Lock vault"
            disabled={vaultState !== 'unlocked'}
            onClick={onLock}
          >
            <LockKeyhole className="size-4" />
            <span className="hidden sm:inline">Lock</span>
          </button>
        </header>

        <main className="scrollbar-thin min-w-0 flex-1 overflow-y-auto p-3 sm:p-5 xl:p-6">
          <div className="mx-auto w-full max-w-[100rem]">{children}</div>
        </main>
      </div>
    </div>
  )
}

function vaultLabel(state: VaultUiState): string {
  switch (state) {
    case 'locked': return 'Locked'
    case 'unlocking': return 'Unlocking'
    case 'unlocked': return 'Unlocked'
    case 'locking': return 'Locking'
    case 'restart_required': return 'Restart required'
  }
}
