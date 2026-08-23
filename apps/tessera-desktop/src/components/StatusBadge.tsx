import { AlertTriangle, Check, LoaderCircle, LockKeyhole } from 'lucide-react'
import type { InboxStatus } from '../types'

const badgeConfig = {
  ready: { label: 'Ready to review', tone: 'badge-warning', icon: Check },
  processing: { label: 'Processing', tone: 'badge-info', icon: LoaderCircle },
  attention: { label: 'Needs attention', tone: 'badge-error', icon: AlertTriangle },
  restricted: { label: 'Restricted', tone: 'badge-neutral', icon: LockKeyhole },
} satisfies Record<InboxStatus, { label: string; tone: string; icon: typeof Check }>

export function StatusBadge({ status }: { status: InboxStatus }) {
  const config = badgeConfig[status]
  const Icon = config.icon
  return (
    <span className={`badge badge-sm gap-1 whitespace-nowrap ${config.tone}`}>
      <Icon className={`size-3 ${status === 'processing' ? 'animate-spin' : ''}`} aria-hidden="true" />
      {config.label}
    </span>
  )
}
