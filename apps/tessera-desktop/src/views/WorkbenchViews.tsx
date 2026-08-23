import {
  Activity,
  AlertTriangle,
  Bot,
  Boxes,
  Check,
  CheckCircle2,
  ChevronRight,
  Cloud,
  Database,
  Eye,
  FileArchive,
  FileCheck2,
  FileText,
  Fingerprint,
  HardDrive,
  Link2,
  LockKeyhole,
  MoreHorizontal,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Upload,
  UserCheck,
  X,
} from 'lucide-react'
import { gateRows, receiptRows } from '../data/demo'
import type { InboxItem, SanitizedOverview, SessionRecord, VaultUiState } from '../types'
import { StatusBadge } from '../components/StatusBadge'

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string
  title: string
  description: string
  action?: React.ReactNode
}) {
  return (
    <header className="mb-5 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
      <div>
        <p className="meta-label mb-1">{eyebrow}</p>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-base-content/62 sm:text-base">{description}</p>
      </div>
      {action}
    </header>
  )
}

function MetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = 'text-primary',
}: {
  label: string
  value: string
  detail: string
  icon: typeof Database
  tone?: string
}) {
  return (
    <article className="surface-panel min-w-0 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="meta-label">{label}</p>
          <p className="mt-2 text-2xl font-semibold tracking-tight">{value}</p>
        </div>
        <div className={`grid size-9 place-items-center rounded-box bg-base-200 ${tone}`}>
          <Icon className="size-[1.1rem]" aria-hidden="true" />
        </div>
      </div>
      <p className="mt-3 text-sm text-base-content/58">{detail}</p>
    </article>
  )
}

interface OverviewViewProps {
  error: string | null
  overview: SanitizedOverview | null
  passphrase: string
  vaultPath: string
  vaultState: VaultUiState
  onPassphraseChange: (value: string) => void
  onPathChange: (value: string) => void
  onUnlock: () => Promise<void>
}

export function OverviewView({
  error,
  overview,
  passphrase,
  vaultPath,
  vaultState,
  onPassphraseChange,
  onPathChange,
  onUnlock,
}: OverviewViewProps) {
  if (!overview) {
    return (
      <>
        <PageHeader
          eyebrow="Live owner workflow"
          title="Open your vault"
          description="Unlock one current format-v3 bundle through Tessera's native core boundary. No vault records are sent to this interface."
        />
        <section className="surface-panel mx-auto max-w-2xl p-5 sm:p-7">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="meta-label">Native vault lifecycle</p>
              <h2 className="mt-1 text-lg font-semibold">Owner unlock</h2>
            </div>
            <span className="badge badge-neutral badge-outline gap-2">
              <LockKeyhole className="size-3.5" aria-hidden="true" />
              {vaultState === 'unlocking' ? 'Unlocking' : 'Locked'}
            </span>
          </div>
          <form
            className="mt-6 space-y-4"
            onSubmit={(event) => {
              event.preventDefault()
              void onUnlock()
            }}
          >
            <label className="form-control block">
              <span className="label-text text-sm font-medium">Vault bundle</span>
              <input
                className="input input-bordered mt-2 w-full font-mono text-sm"
                value={vaultPath}
                onChange={(event) => onPathChange(event.currentTarget.value)}
                placeholder="/path/to/Vault.tessera"
                autoComplete="off"
                spellCheck={false}
                disabled={vaultState === 'unlocking'}
              />
            </label>
            <label className="form-control block">
              <span className="label-text text-sm font-medium">Passphrase</span>
              <input
                className="input input-bordered mt-2 w-full"
                type="password"
                value={passphrase}
                onChange={(event) => onPassphraseChange(event.currentTarget.value)}
                autoComplete="off"
                disabled={vaultState === 'unlocking'}
              />
            </label>
            {error && <div className="alert alert-warning text-sm" role="alert">{error}</div>}
            <button
              className="btn btn-primary w-full sm:w-auto"
              type="submit"
              disabled={vaultState === 'unlocking' || !vaultPath.trim() || !passphrase}
            >
              <LockKeyhole className="size-4" aria-hidden="true" />
              {vaultState === 'unlocking' ? 'Unlocking…' : 'Unlock vault'}
            </button>
          </form>
          <p className="mt-5 text-xs leading-relaxed text-base-content/58">
            The passphrase exists transiently in this owner window, Tauri IPC, and native process memory for this call. It is cleared from the form when the call completes and is never stored or logged by Tessera Desktop.
          </p>
        </section>
      </>
    )
  }

  const receiptDetail = overview.receiptChain === 'verified'
    ? 'Protected chain verified through the current head'
    : 'Protected chain requires owner attention'

  return (
    <>
      <PageHeader
        eyebrow="Live owner workflow"
        title="Overview"
        description="A sanitized aggregate computed by tessera-core. No records, paths, hashes, or receipt payloads cross into the WebView."
        action={<span className="badge badge-success badge-outline">Live vault aggregate</span>}
      />

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 2xl:grid-cols-4" aria-label="Live vault summary">
        <MetricCard label="Pending review" value={String(overview.pendingReviewCount)} detail="Aggregate quarantine count" icon={Database} />
        <MetricCard label="Spaces" value={String(overview.spaceCount)} detail="Aggregate owner space count" icon={Boxes} tone="text-accent" />
        <MetricCard label="Active sessions" value={String(overview.activeSessionCount)} detail="Effective, non-expired sessions" icon={Activity} tone="text-success" />
        <MetricCard label="Receipts" value={String(overview.receiptCount)} detail={receiptDetail} icon={Fingerprint} tone={overview.receiptChain === 'verified' ? 'text-success' : 'text-warning'} />
      </section>

      <section className="surface-panel mt-4 grid gap-4 p-4 sm:grid-cols-2 sm:p-5" aria-label="Bounded vault status">
        <div className="surface-muted p-4">
          <p className="meta-label">Vault format</p>
          <p className="mt-2 text-lg font-semibold">Format v{overview.formatVersion}</p>
          <p className="mt-1 text-sm text-base-content/58">Current protected metadata format</p>
        </div>
        <div className="surface-muted p-4">
          <p className="meta-label">Diagnostics</p>
          <p className="mt-2 text-lg font-semibold capitalize">{overview.diagnosticStatus}</p>
          <p className="mt-1 text-sm text-base-content/58">Bounded aggregate status only</p>
        </div>
      </section>
    </>
  )
}

function ItemIcon({ kind }: { kind: string }) {
  const Icon = kind.includes('archive') ? FileArchive : kind === 'Image' ? Eye : FileText
  return (
    <div className="grid size-9 shrink-0 place-items-center rounded-box bg-base-300 text-base-content/68">
      <Icon className="size-[1.1rem]" />
    </div>
  )
}

interface InboxViewProps {
  items: InboxItem[]
  selected: InboxItem
  onSelect: (item: InboxItem) => void
  onDecision: (action: 'accept' | 'restrict' | 'retry' | 'reject') => void
}

export function InboxView({ items, selected, onSelect, onDecision }: InboxViewProps) {
  return (
    <>
      <PageHeader
        eyebrow="Quarantine boundary"
        title="Inbox review"
        description="Review exactly what enters the vault. Pending material remains unreachable through every lens."
        action={<button className="btn btn-primary btn-sm"><Upload className="size-4" /> Import more</button>}
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(17rem,.72fr)_minmax(28rem,1.28fr)] 2xl:grid-cols-[minmax(17rem,.72fr)_minmax(30rem,1.28fr)_20rem]">
        <section className="surface-panel min-w-0 overflow-hidden" aria-label="Inbox items">
          <div className="border-b border-base-300 p-3">
            <label className="input input-sm flex w-full items-center gap-2 bg-base-200">
              <Search className="size-4 text-base-content/45" />
              <input className="grow" placeholder="Filter inbox" aria-label="Filter inbox" />
              <SlidersHorizontal className="size-4 text-base-content/45" />
            </label>
            <div className="mt-3 flex gap-2 overflow-x-auto pb-1 text-xs">
              <button className="btn btn-primary btn-xs">All 12</button>
              <button className="btn btn-ghost btn-xs">Ready 7</button>
              <button className="btn btn-ghost btn-xs">Attention 3</button>
            </div>
          </div>
          <div className="scrollbar-thin max-h-[32rem] overflow-y-auto xl:max-h-[calc(100vh-18rem)]">
            {items.map((item) => (
              <button
                key={item.id}
                type="button"
                className={`flex w-full gap-3 border-b border-base-300/70 p-3 text-left transition-colors last:border-0 hover:bg-base-200 ${
                  selected.id === item.id ? 'bg-primary/10 shadow-[inset_3px_0_var(--color-primary)]' : ''
                }`}
                aria-pressed={selected.id === item.id}
                onClick={() => onSelect(item)}
              >
                <ItemIcon kind={item.kind} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-start justify-between gap-2">
                    <p className="truncate text-sm font-medium">{item.name}</p>
                    <time className="shrink-0 font-mono text-[0.65rem] text-base-content/42">{item.imported}</time>
                  </div>
                  <p className="mt-0.5 truncate text-xs text-base-content/52">{item.source} · {item.kind}</p>
                  <div className="mt-2"><StatusBadge status={item.status} /></div>
                </div>
              </button>
            ))}
          </div>
        </section>

        <article className="surface-panel min-w-0 overflow-hidden">
          <div className="flex items-start gap-3 border-b border-base-300 p-4">
            <ItemIcon kind={selected.kind} />
            <div className="min-w-0 flex-1">
              <h2 className="truncate text-lg font-semibold">{selected.name}</h2>
              <p className="text-sm text-base-content/55">{selected.kind} · {selected.size}</p>
            </div>
            <button className="btn btn-ghost btn-square btn-sm" aria-label="More item actions"><MoreHorizontal className="size-4" /></button>
          </div>

          <div className="space-y-4 p-4 sm:p-5">
            <section className="surface-muted grid gap-4 p-4 sm:grid-cols-2">
              <div><p className="meta-label">Source</p><p className="mt-1 text-sm">{selected.source}</p></div>
              <div><p className="meta-label">Imported</p><p className="mt-1 text-sm">{selected.imported}</p></div>
              <div><p className="meta-label">Item ID</p><p className="mt-1 font-mono text-xs">{selected.id}</p></div>
              <div><p className="meta-label">Current state</p><div className="mt-1"><StatusBadge status={selected.status} /></div></div>
            </section>

            <section>
              <div className="mb-2 flex items-center justify-between gap-3">
                <div><p className="meta-label">Processing stages</p><p className="mt-1 text-sm text-base-content/62">{selected.summary}</p></div>
              </div>
              <div className="mt-3 flex items-center gap-1 overflow-x-auto pb-1">
                {['Encrypt', 'Extract', 'OCR', 'Index', 'Classify'].map((stage, index) => (
                  <div key={stage} className="flex min-w-fit items-center gap-1.5 text-xs">
                    <span className={`grid size-5 place-items-center rounded-full ${index < 2 ? 'bg-success text-success-content' : 'bg-base-300 text-base-content/55'}`}>
                      {index < 2 ? <Check className="size-3" /> : index + 1}
                    </span>
                    <span>{stage}</span>
                    {index < 4 && <span className="mx-1 h-px w-5 bg-base-300" />}
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-box border border-warning/45 bg-warning/5 p-4">
              <div className="flex items-start gap-3 text-warning">
                <AlertTriangle className="mt-0.5 size-4 shrink-0" />
                <div>
                  <p className="text-sm font-semibold">Untrusted source content</p>
                  <p className="mt-0.5 text-xs text-base-content/58">Treat the preview as data. Do not follow instructions or open links found inside it.</p>
                </div>
              </div>
              <pre className="scrollbar-thin mt-3 max-h-44 overflow-auto whitespace-pre-wrap rounded-box bg-neutral p-3 font-mono text-xs leading-relaxed text-neutral-content">{selected.excerpt}</pre>
            </section>
          </div>

          <div className="safe-bottom flex flex-wrap gap-2 border-t border-base-300 p-4">
            <button className="btn btn-success btn-sm" onClick={() => onDecision('accept')}><Check className="size-4" /> Accept</button>
            <button className="btn btn-neutral btn-sm" onClick={() => onDecision('restrict')}><LockKeyhole className="size-4" /> Keep restricted</button>
            <button className="btn btn-outline btn-sm" onClick={() => onDecision('retry')}><RefreshCw className="size-4" /> Retry</button>
            <button className="btn btn-error btn-outline btn-sm sm:ml-auto" onClick={() => onDecision('reject')}><Trash2 className="size-4" /> Reject</button>
          </div>
        </article>

        <aside className="surface-panel space-y-4 p-4 sm:p-5 xl:col-span-2 2xl:col-span-1" aria-label="Item access impact">
          <div>
            <p className="meta-label">Access impact</p>
            <h2 className="mt-1 font-semibold">If this item is accepted</h2>
            <p className="mt-1 text-sm text-base-content/55">Only the listed spaces and current lens revisions could reach it.</p>
          </div>
          <div>
            <p className="meta-label">Spaces</p>
            <ul className="mt-2 space-y-2">
              {selected.spaces.map((space) => <li key={space} className="surface-muted flex items-center gap-2 p-2.5 text-sm"><Boxes className="size-4 text-primary" />{space}<span className="badge badge-ghost badge-xs ml-auto">Read</span></li>)}
            </ul>
          </div>
          <div>
            <p className="meta-label">Lenses</p>
            <ul className="mt-2 space-y-2">
              {selected.lenses.length ? selected.lenses.map((lens) => <li key={lens} className="surface-muted flex items-center gap-2 p-2.5 text-sm"><ApertureIcon />{lens}</li>) : <li className="text-sm text-base-content/52">No lens currently reaches this item.</li>}
            </ul>
          </div>
          <div className="border-t border-base-300 pt-4">
            <div className="flex items-center justify-between gap-3">
              <div><p className="text-sm font-medium">Allow cloud for this item</p><p className="mt-0.5 text-xs text-base-content/52">Off · local processing only</p></div>
              <input type="checkbox" className="toggle toggle-accent" aria-label="Allow cloud for this item" />
            </div>
          </div>
          <div className="surface-muted p-3">
            <p className="meta-label">Local provenance</p>
            <dl className="mt-3 grid grid-cols-[1fr_auto] gap-x-3 gap-y-2 text-xs">
              <dt className="text-base-content/55">OCR engine</dt><dd className="font-mono">Tesseract 5.3.1</dd>
              <dt className="text-base-content/55">Embedding</dt><dd className="font-mono">MiniLM v1</dd>
              <dt className="text-base-content/55">Device</dt><dd>This machine</dd>
            </dl>
          </div>
        </aside>
      </div>
    </>
  )
}

function ApertureIcon() {
  return <span className="grid size-4 place-items-center rounded-full border border-accent text-[0.55rem] text-accent">◎</span>
}

function CollectionCard({ title, detail, meta, icon: Icon }: { title: string; detail: string; meta: string; icon: typeof Boxes }) {
  return (
    <article className="surface-panel p-4 transition-colors hover:border-primary/45">
      <div className="flex items-start gap-3">
        <div className="grid size-9 shrink-0 place-items-center rounded-box bg-primary/12 text-primary"><Icon className="size-[1.1rem]" /></div>
        <div className="min-w-0 flex-1"><h2 className="font-semibold">{title}</h2><p className="mt-1 text-sm text-base-content/58">{detail}</p><p className="mt-3 font-mono text-xs text-base-content/45">{meta}</p></div>
        <ChevronRight className="size-4 text-base-content/35" />
      </div>
    </article>
  )
}

export function SpacesView() {
  return (
    <>
      <PageHeader eyebrow="Vault organization" title="Spaces" description="Hierarchical owner-controlled containers. Space membership is evaluated before retrieval." action={<button className="btn btn-primary btn-sm">New space</button>} />
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <CollectionCard title="Factor-E Projects" detail="Active project doctrine, implementation evidence, and research." meta="482 items · 3 child spaces" icon={Boxes} />
        <CollectionCard title="Personal Knowledge" detail="Owner-curated notes and long-term reference material." meta="364 items · restricted" icon={LockKeyhole} />
        <CollectionCard title="Research" detail="Market, technical, and product research sources." meta="219 items · 2 lenses" icon={Search} />
        <CollectionCard title="Product Support" detail="Reviewed support transcripts and product signals." meta="96 items · sensitive" icon={UserCheck} />
      </section>
    </>
  )
}

export function LensesView() {
  return (
    <>
      <PageHeader eyebrow="Default-deny policy" title="Lenses" description="Reusable, revision-bound access policies. An agent cannot broaden a lens during a session." action={<button className="btn btn-primary btn-sm">Create lens</button>} />
      <section className="grid gap-3 lg:grid-cols-2">
        {[
          ['Factor-E PM Lens', 'Factor-E Projects', 'Excerpt', 'Revision 7'],
          ['Research Lens', 'Research + selected projects', 'Summary', 'Revision 3'],
          ['Support Lens', 'Product Support', 'Excerpt', 'Revision 2'],
        ].map(([name, scope, mode, revision]) => (
          <article key={name} className="surface-panel p-4 sm:p-5">
            <div className="flex items-start justify-between gap-3"><div><p className="meta-label">{revision}</p><h2 className="mt-1 text-lg font-semibold">{name}</h2></div><span className="badge badge-success badge-outline">Active</span></div>
            <dl className="mt-5 grid grid-cols-2 gap-4 text-sm"><div><dt className="meta-label">Scope</dt><dd className="mt-1">{scope}</dd></div><div><dt className="meta-label">Disclosure</dt><dd className="mt-1">{mode}</dd></div></dl>
            <div className="mt-5 flex gap-2"><button className="btn btn-outline btn-sm">Inspect policy</button><button className="btn btn-ghost btn-sm">Duplicate</button></div>
          </article>
        ))}
      </section>
    </>
  )
}

export function AgentsView() {
  return (
    <>
      <PageHeader eyebrow="Approved consumers" title="Agents" description="Pairings bind one named client to one exact lens revision. Display names are audit context, not attestation." action={<button className="btn btn-primary btn-sm"><Link2 className="size-4" /> Pair agent</button>} />
      <section className="surface-panel overflow-x-auto">
        <table className="table">
          <thead><tr><th>Agent</th><th>Transport</th><th>Lens</th><th>Last access</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {[
              ['Super Skippy', 'stdio', 'Factor-E PM Lens r7', '2m ago', 'Approved'],
              ['Research Assistant', 'HTTP/OAuth', 'Research Lens r3', '18m ago', 'Approved'],
              ['Archive Reviewer', 'stdio', 'Support Lens r2', 'Never', 'Revoked'],
            ].map((row) => <tr key={row[0]}><td className="font-medium">{row[0]}</td><td className="font-mono text-xs">{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td><span className={`badge badge-sm ${row[4] === 'Approved' ? 'badge-success badge-outline' : 'badge-neutral'}`}>{row[4]}</span></td><td><button className="btn btn-ghost btn-square btn-sm" aria-label={`Actions for ${row[0]}`}><MoreHorizontal className="size-4" /></button></td></tr>)}
          </tbody>
        </table>
      </section>
    </>
  )
}

export function SessionsView({ sessions, onRevoke }: { sessions: SessionRecord[]; onRevoke: (id: string) => void }) {
  return (
    <>
      <PageHeader eyebrow="Live disclosure" title="Sessions" description="Every session is time-bound to one immutable pairing, lens revision, purpose, and receipt lifecycle." action={<button className="btn btn-neutral btn-sm"><LockKeyhole className="size-4" /> Lock Guardian</button>} />
      <div className="space-y-3">
        {sessions.map((session) => (
          <article key={session.id} className="surface-panel grid gap-4 p-4 sm:grid-cols-[auto_1fr_auto] sm:items-center sm:p-5">
            <div className={`grid size-10 place-items-center rounded-box ${session.state === 'active' ? 'bg-success/15 text-success' : 'bg-base-300 text-base-content/45'}`}><Bot className="size-5" /></div>
            <div><div className="flex flex-wrap items-center gap-2"><h2 className="font-semibold">{session.agent}</h2><span className={`badge badge-sm ${session.state === 'active' ? 'badge-success' : 'badge-ghost'}`}>{session.state}</span></div><p className="mt-1 text-sm text-base-content/58">{session.lens} · {session.purpose} · {session.remaining}</p></div>
            {session.state === 'active' && <button className="btn btn-error btn-outline btn-sm" onClick={() => onRevoke(session.id)}><X className="size-4" /> Revoke</button>}
          </article>
        ))}
      </div>
    </>
  )
}

export function ReceiptsView() {
  return (
    <>
      <PageHeader eyebrow="Disclosure evidence" title="Receipts" description="Review exact disclosures and verify the append-only receipt chain. Receipts are evidence, not magic immutability dust." action={<button className="btn btn-outline btn-sm"><FileCheck2 className="size-4" /> Verify chain</button>} />
      <section className="surface-panel overflow-x-auto">
        <table className="table">
          <thead><tr><th>Receipt</th><th>Agent</th><th>Operation</th><th>Disclosure</th><th>Integrity</th></tr></thead>
          <tbody>{receiptRows.map((row) => <tr key={row[0]}><td className="font-mono text-xs">{row[0]}</td><td>{row[1]}</td><td className="font-mono text-xs">{row[2]}</td><td>{row[3]}</td><td><span className="badge badge-success badge-outline badge-sm"><CheckCircle2 className="size-3" />{row[4]}</span></td></tr>)}</tbody>
        </table>
      </section>
    </>
  )
}

export function EvaluationView() {
  return (
    <>
      <PageHeader eyebrow="Private release gate" title="Evaluation" description="Prepare and review the local 30–50-question corpus gate. Raw questions, sources, and results remain outside Git." action={<button className="btn btn-primary btn-sm" disabled><Play className="size-4" /> Run evaluation</button>} />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(18rem,.75fr)]">
        <section className="surface-panel p-4 sm:p-5">
          <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="meta-label">Implementation freeze</p><h2 className="mt-1 text-lg font-semibold">Private evaluation not started</h2></div><span className="badge badge-warning">Blocked by implementation</span></div>
          <progress className="progress progress-warning mt-5 w-full" value="82" max="100" />
          <p className="mt-2 text-sm text-base-content/58">The runner is ready. The owner-reviewed corpus is intentionally deferred until the implementation reaches a stable freeze.</p>
          <div className="mt-6 overflow-x-auto"><table className="table table-sm"><thead><tr><th>Gate</th><th>Threshold</th><th>Status</th></tr></thead><tbody>{gateRows.map((row) => <tr key={row[0]}><td>{row[0]}</td><td className="font-mono text-xs">{row[1]}</td><td><span className={`badge badge-sm ${row[2] === 'Ready' ? 'badge-success badge-outline' : 'badge-warning badge-outline'}`}>{row[2]}</span></td></tr>)}</tbody></table></div>
        </section>
        <aside className="space-y-4">
          <section className="surface-panel p-4 sm:p-5"><p className="meta-label">Evaluation plan</p><h2 className="mt-1 font-semibold">No private plan selected</h2><p className="mt-2 text-sm text-base-content/58">Select a local plan only after the implementation freeze. The plan is never copied into the repository.</p><button className="btn btn-outline btn-sm mt-4 w-full"><HardDrive className="size-4" /> Select local plan</button></section>
          <section className="surface-muted p-4"><div className="flex items-start gap-3"><ShieldCheck className="size-5 shrink-0 text-success" /><div><h3 className="text-sm font-semibold">Privacy boundary</h3><p className="mt-1 text-xs leading-relaxed text-base-content/58">Only a reviewed, sanitized aggregate may enter release evidence. Raw queries and identifiers remain local.</p></div></div></section>
        </aside>
      </div>
    </>
  )
}

const diagnosticCards = [
  { title: 'Vault integrity', state: 'Healthy', detail: 'Database, manifests, and 1,284 blobs verified', icon: Database, tone: 'success' },
  { title: 'Receipt chain', state: 'Verified', detail: '128 contiguous receipts through latest head', icon: Fingerprint, tone: 'success' },
  { title: 'Model assets', state: 'Pinned', detail: 'MiniLM manifest and checksum match', icon: HardDrive, tone: 'success' },
  { title: 'Guardian', state: 'Running', detail: 'Loopback only · one active session', icon: ShieldCheck, tone: 'info' },
  { title: 'Recovery snapshot', state: '6h old', detail: 'Last portable backup completed cleanly', icon: RefreshCw, tone: 'warning' },
  { title: 'Cloud processing', state: 'Disabled', detail: 'No item has cloud opt-in', icon: Cloud, tone: 'success' },
] as const

const diagnosticTone = {
  success: { icon: 'bg-success/12 text-success', badge: 'badge-success' },
  info: { icon: 'bg-info/12 text-info', badge: 'badge-info' },
  warning: { icon: 'bg-warning/12 text-warning', badge: 'badge-warning' },
} as const

export function DiagnosticsView() {
  return (
    <>
      <PageHeader eyebrow="Integrity and portability" title="Diagnostics" description="Run bounded checks without exposing vault contents or inventing repairs that cannot be proven." action={<button className="btn btn-primary btn-sm"><Play className="size-4" /> Run diagnostics</button>} />
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {diagnosticCards.map(({ title, state, detail, icon: DiagnosticIcon, tone }) => {
          const styles = diagnosticTone[tone]
          return <article key={title} className="surface-panel p-4"><div className="flex items-start justify-between gap-3"><div className={`grid size-9 place-items-center rounded-box ${styles.icon}`}><DiagnosticIcon className="size-[1.1rem]" /></div><span className={`badge badge-outline badge-sm ${styles.badge}`}>{state}</span></div><h2 className="mt-4 font-semibold">{title}</h2><p className="mt-1 text-sm text-base-content/58">{detail}</p></article>
        })}
      </section>
    </>
  )
}
