import type { InboxItem, SessionRecord } from '../types'

export const inboxItems: InboxItem[] = [
  {
    id: 'inbox-01',
    name: 'Product research — July',
    kind: 'Claude archive',
    source: 'Local import',
    imported: 'Today, 10:42',
    size: '4.2 MB',
    status: 'ready',
    summary: 'Branch-preserving conversation archive with 43 messages and 8 tool events.',
    excerpt:
      'User: What are the unmet needs in developer tools for AI-assisted coding?\n\nAssistant: Based on the supplied research, the recurring needs include durable context across long sessions…',
    spaces: ['Factor-E Projects', 'Personal Knowledge'],
    lenses: ['Factor-E PM Lens', 'Research Lens'],
  },
  {
    id: 'inbox-02',
    name: 'Market landscape 2026.pdf',
    kind: 'PDF document',
    source: 'Mail attachment',
    imported: 'Today, 09:18',
    size: '11.8 MB',
    status: 'processing',
    summary: 'Extraction complete. Local embedding index is processing page 31 of 48.',
    excerpt: 'Preview becomes available after local extraction completes.',
    spaces: ['Research'],
    lenses: ['Research Lens'],
  },
  {
    id: 'inbox-03',
    name: 'PRD draft v3.docx',
    kind: 'Word document',
    source: 'Google Drive export',
    imported: 'Yesterday',
    size: '806 KB',
    status: 'ready',
    summary: 'Product requirements document with 18 sections and 4 embedded images.',
    excerpt: 'Goals: provide an owner-controlled context layer with narrow, reviewable agent access…',
    spaces: ['Factor-E Projects'],
    lenses: ['Factor-E PM Lens'],
  },
  {
    id: 'inbox-04',
    name: 'User interviews.csv',
    kind: 'Delimited data',
    source: 'Dropbox export',
    imported: 'Yesterday',
    size: '218 KB',
    status: 'attention',
    summary: 'Three rows contain malformed quoting. The original is preserved and encrypted.',
    excerpt: 'Narrow quarantine: rows 17, 44, and 45 require review before processing can continue.',
    spaces: ['Research'],
    lenses: [],
  },
  {
    id: 'inbox-05',
    name: 'Whiteboard photo 1.png',
    kind: 'Image',
    source: 'Local import',
    imported: 'Yesterday',
    size: '3.1 MB',
    status: 'processing',
    summary: 'Thumbnail encrypted. Waiting for local OCR and caption provider.',
    excerpt: 'No derived text is available yet.',
    spaces: ['Factor-E Projects'],
    lenses: ['Factor-E PM Lens'],
  },
  {
    id: 'inbox-06',
    name: 'Support thread — 8421.txt',
    kind: 'Plain text',
    source: 'Local import',
    imported: '2 days ago',
    size: '64 KB',
    status: 'ready',
    summary: 'Support transcript detected as 26 ordered speaker turns.',
    excerpt: 'Customer: The workspace loses context when switching between long-running projects…',
    spaces: ['Product Support'],
    lenses: ['Support Lens'],
  },
]

export const sessions: SessionRecord[] = [
  {
    id: 'session-01',
    agent: 'Super Skippy',
    lens: 'Factor-E Projects',
    purpose: 'Implementation support',
    remaining: '01:42:37',
    state: 'active',
  },
  {
    id: 'session-02',
    agent: 'Research Assistant',
    lens: 'Research Lens',
    purpose: 'Landscape synthesis',
    remaining: 'Closed 18m ago',
    state: 'closed',
  },
]

export const activity = [
  ['10:42', 'Product research — July imported and encrypted'],
  ['10:38', 'Super Skippy queried Factor-E Projects'],
  ['10:21', 'Receipt chain verified: 128 receipts'],
  ['09:52', 'Research Lens revision 7 approved'],
]

export const receiptRows = [
  ['rcpt_01JZ…K8Q', 'Super Skippy', 'vault_query', '2 excerpts', 'Verified'],
  ['rcpt_01JZ…H7M', 'Super Skippy', 'vault_get_item', '1 excerpt', 'Verified'],
  ['rcpt_01JZ…D2A', 'Research Assistant', 'vault_query', 'No result', 'Verified'],
  ['rcpt_01JZ…98F', 'Research Assistant', 'vault_list_spaces', '3 spaces', 'Verified'],
]

export const gateRows = [
  ['Policy leakage', 'Exactly 0', 'Ready'],
  ['Exact citation reconstruction', '100%', 'Ready'],
  ['Receipt chain verification', 'Required', 'Ready'],
  ['Recall@10', '≥ 0.80', 'Awaiting corpus'],
  ['No-answer precision', '≥ 0.80', 'Awaiting corpus'],
]
