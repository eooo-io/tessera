export function BrandMark({ className = 'size-8' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 40 40" fill="none" aria-hidden="true">
      <path d="M20 3 35 11.5v17L20 37 5 28.5v-17L20 3Z" stroke="currentColor" strokeWidth="1.6" />
      <path d="m20 3 7.5 13L20 20 12.5 16 20 3Z" fill="currentColor" opacity=".82" />
      <path d="m35 11.5-7.5 13L20 20l7.5-4L35 11.5Z" fill="currentColor" opacity=".58" />
      <path d="m35 28.5-15-8.5 7.5 4L35 11.5v17Z" fill="currentColor" opacity=".35" />
      <path d="M20 37V20l7.5 4L35 28.5 20 37Z" fill="currentColor" opacity=".68" />
      <path d="M5 28.5 20 20v17L5 28.5Z" fill="currentColor" opacity=".42" />
      <path d="m5 11.5 7.5 4.5L20 20 5 28.5v-17Z" fill="currentColor" opacity=".25" />
    </svg>
  )
}
