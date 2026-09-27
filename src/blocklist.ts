// Domains blocked by this DoH resolver.
// A blocked domain also blocks every subdomain beneath it.
// Example: adding "example.com" blocks example.com and www.example.com.
export const BLOCKED_DOMAINS = new Set<string>([
  // 'example.com',
])

export function isBlockedDomain(qname: string): boolean {
  const name = qname.replace(/\\.$/, '').toLowerCase()

  for (const blocked of BLOCKED_DOMAINS) {
    const domain = blocked.replace(/\\.$/, '').toLowerCase()
    if (name === domain || name.endsWith('.' + domain)) return true
  }

  return false
}
