// Domains blocked by this DoH resolver.
// A blocked domain also blocks every subdomain beneath it.
// Example: adding "example.com" blocks example.com and www.example.com.

export const BLOCKED_DOMAINS = new Set<string>([
  // 'example.com',
])

export const BLOCKLIST_PREFIX = 'blocklist:'

function normalizeDomain(domain: string): string {
  return domain.replace(/\.$/, '').trim().toLowerCase()
}

export async function isBlockedDomain(
  qname: string,
  kv?: KVNamespace,
): Promise<boolean> {
  const name = normalizeDomain(qname)

  for (const blocked of BLOCKED_DOMAINS) {
    const domain = normalizeDomain(blocked)
    if (name === domain || name.endsWith('.' + domain)) return true
  }

  if (!kv) return false

  // Check the exact name first, then each parent domain.
  const labels = name.split('.')
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.')
    if (!candidate) continue
    if (await kv.get(BLOCKLIST_PREFIX + candidate)) return true
  }

  return false
}

export async function listBlockedDomains(kv: KVNamespace): Promise<string[]> {
  const domains = new Set<string>()

  for (const blocked of BLOCKED_DOMAINS) {
    const domain = normalizeDomain(blocked)
    if (domain) domains.add(domain)
  }

  let cursor: string | undefined

  do {
    const page = await kv.list({ prefix: BLOCKLIST_PREFIX, cursor })
    for (const key of page.keys) {
      const domain = normalizeDomain(key.name.slice(BLOCKLIST_PREFIX.length))
      if (domain) domains.add(domain)
    }
    cursor = page.list_complete ? undefined : page.cursor
  } while (cursor)

  return [...domains].sort()
}

export function normalizeBlockedDomain(domain: string): string {
  return normalizeDomain(domain)
}
