import { Hono } from 'hono'
import * as dns from '@dnsquery/dns-packet'

type Bindings = {
  ALFIS_KV: KVNamespace
}

type AlfisRecord = {
  type: string
  domain: string
  addr?: string
  ttl?: number
  value?: string
  port?: number
  priority?: number
  weight?: number
  target?: string
}

type AlfisData = {
  zone: string
  records: AlfisRecord[]
}

const app = new Hono<{ Bindings: Bindings }>()

const DOH_CONTENT_TYPE = 'application/dns-message'
const VIEWER = 'https://viewer.alfis.name/domain/'
const DNS1111 = 'https://cloudflare-dns.com/dns-query'

app.get('/', (c) => c.text('DoH Alfis PoC'))

app.get('/dns-query', async (c) => {
  const encoded = c.req.query('dns')
  if (!encoded) return c.text('missing dns query', 400)

  try {
    return await resolveDoH(c.env, base64UrlDecode(encoded))
  } catch (err) {
    console.error(err)
    return c.text('invalid DNS query', 400)
  }
})

app.post('/dns-query', async (c) => {
  const contentType = c.req.header('content-type') ?? ''
  if (!contentType.toLowerCase().startsWith(DOH_CONTENT_TYPE)) {
    return c.text('Content-Type must be application/dns-message', 415)
  }

  try {
    return await resolveDoH(c.env, new Uint8Array(await c.req.arrayBuffer()))
  } catch (err) {
    console.error(err)
    return c.text('invalid DNS query', 400)
  }
})

async function resolveDoH(env: Bindings, packet: Uint8Array): Promise<Response> {
  const query = dns.decode(packet)
  const question = query.questions?.[0]

  if (!question?.name || question.class !== 'IN') {
    return dnsResponse(makeErrorResponse(query, 1))
  }

  const qname = normalizeName(question.name)
  const qtype = question.type
  const cacheKey = `v1:${qname}:${qtype}`

  // KV is only for Alfis-derived answers. 1.1.1.1 is never cached.
  const cached = await env.ALFIS_KV.get(cacheKey, 'arrayBuffer')
  if (cached) return dnsResponse(new Uint8Array(cached))

  // Ordinary DNS first.
  const normal = await queryCloudflare(packet)
  if (normal.ok) {
    const normalBytes = new Uint8Array(await normal.clone().arrayBuffer())
    const decoded = dns.decode(normalBytes)

    // Only a successful answer bypasses Alfis. NXDOMAIN and NODATA continue to Alfis.
    if (decoded.rcode === 0 && (decoded.answers?.length ?? 0) > 0) {
      return dnsResponse(normalBytes)
    }
  }

  // If this is a subdomain, search its parents only. The subdomain itself is
  // never expected to be a solved Alfis entry.
  const alfis = await resolveFromAlfis(qname, qtype)
  if (!alfis) {
    if (normal.ok) return dnsResponse(new Uint8Array(await normal.arrayBuffer()))
    return dnsResponse(makeErrorResponse(query, 3))
  }

  const response = makeAlfisResponse(query, qname, qtype, alfis)
  const encoded = dns.encode(response)

  // Cache only the Alfis result.
  await env.ALFIS_KV.put(cacheKey, encoded.buffer as ArrayBuffer, {
    expirationTtl: Math.max(30, minTtl(alfis.records)),
  })

  return dnsResponse(encoded)
}

async function queryCloudflare(packet: Uint8Array): Promise<Response> {
  return fetch(DNS1111, {
    method: 'POST',
    headers: {
      'content-type': DOH_CONTENT_TYPE,
      accept: DOH_CONTENT_TYPE,
    },
    body: packet,
  })
}

async function resolveFromAlfis(qname: string, qtype: string): Promise<AlfisData | null> {
  const labels = qname.split('.').filter(Boolean)
  if (labels.length < 2) return null

  // foo.bar.send.ygg -> bar.send.ygg -> send.ygg
  for (let i = 0; i <= labels.length - 2; i++) {
    const candidate = labels.slice(i).join('.')
    const data = await fetchAlfis(candidate)

    if (!data) continue

    if (selectRecords(data.records, qname, candidate, qtype).length > 0) {
      return data
    }

    // Exact Alfis domain exists, but requested type is absent.
    if (candidate === qname) return data
  }

  return null
}

async function fetchAlfis(domain: string): Promise<AlfisData | null> {
  const zone = domain.split('.').at(-1)!
  const hash = await doubleSha256Hex(domain)

  // send.ygg and hash.ygg both use this same hash-form Viewer lookup.
  const response = await fetch(`${VIEWER}${hash}.${zone}`, {
    headers: { accept: 'text/html' },
  })

  if (!response.ok) return null

  const html = await response.text()
  const match = html.match(/<pre[^>]*>\s*<code[^>]*>([\s\S]*?)<\/code>\s*<\/pre>/i)
  if (!match) return null

  try {
    const data = JSON.parse(decodeHtml(match[1])) as AlfisData
    if (!data.zone || !Array.isArray(data.records)) return null
    return data
  } catch {
    return null
  }
}

function selectRecords(
  records: AlfisRecord[],
  qname: string,
  ownerDomain: string,
  qtype: string,
): AlfisRecord[] {
  const relative =
    qname === ownerDomain
      ? '@'
      : qname.endsWith(`.${ownerDomain}`)
        ? qname.slice(0, -(ownerDomain.length + 1))
        : null

  if (relative === null) return []

  return records.filter((record) => {
    const owner = normalizeName(record.domain || '@')
    return (owner === '@' || owner === relative) && record.type === qtype
  })
}

function makeAlfisResponse(query: any, qname: string, qtype: string, data: AlfisData): any {
  const ownerDomain = findOwnerDomain(qname, data.zone)
  const records = selectRecords(data.records, qname, ownerDomain, qtype)
  const answers = records.map((record) => toDnsAnswer(record, qname))

  return {
    type: 'response',
    id: query.id,
    flags: dns.AUTHORITATIVE_ANSWER | dns.RECURSION_AVAILABLE,
    questions: query.questions,
    answers,
    authorities: [],
    additionals: [],
    rcode: 0,
  }
}

function toDnsAnswer(record: AlfisRecord, qname: string): any {
  const ttl = record.ttl ?? 300

  switch (record.type) {
    case 'A':
    case 'AAAA':
      return { name: qname, type: record.type, class: 'IN', ttl, data: record.addr }
    case 'CNAME':
      return { name: qname, type: 'CNAME', class: 'IN', ttl, data: record.addr ?? record.value }
    case 'NS':
      return { name: qname, type: 'NS', class: 'IN', ttl, data: record.addr ?? record.value }
    case 'PTR':
      return { name: qname, type: 'PTR', class: 'IN', ttl, data: record.addr ?? record.value }
    case 'MX':
      return {
        name: qname,
        type: 'MX',
        class: 'IN',
        ttl,
        preference: record.priority ?? 10,
        exchange: record.addr ?? record.value,
      }
    case 'TXT':
      return { name: qname, type: 'TXT', class: 'IN', ttl, data: record.value ?? record.addr ?? '' }
    case 'SRV':
      return {
        name: qname,
        type: 'SRV',
        class: 'IN',
        ttl,
        data: {
          priority: record.priority ?? 0,
          weight: record.weight ?? 0,
          port: record.port ?? 0,
          target: record.target ?? record.addr ?? record.value ?? '.',
        },
      }
    default:
      throw new Error(`Unsupported Alfis record type: ${record.type}`)
  }
}

function findOwnerDomain(qname: string, zone: string): string {
  const labels = qname.split('.')
  const zoneIndex = labels.lastIndexOf(zone)
  if (zoneIndex <= 0) return qname
  return labels.slice(zoneIndex - 1).join('.')
}

function minTtl(records: AlfisRecord[]): number {
  return records.reduce((min, r) => Math.min(min, r.ttl ?? 300), 3600)
}

function makeErrorResponse(query: any, rcode: number): Uint8Array {
  return dns.encode({
    type: 'response',
    id: query.id,
    flags: dns.RECURSION_AVAILABLE,
    questions: query.questions ?? [],
    answers: [],
    authorities: [],
    additionals: [],
    rcode,
  })
}

function dnsResponse(body: ArrayBuffer | Uint8Array): Response {
  return new Response(body, {
    headers: {
      'content-type': DOH_CONTENT_TYPE,
      'cache-control': 'no-store',
    },
  })
}

function normalizeName(name: string): string {
  return name.replace(/\.$/, '').toLowerCase()
}

async function doubleSha256Hex(value: string): Promise<string> {
  const encoder = new TextEncoder()
  const first = await crypto.subtle.digest('SHA-256', encoder.encode(value))
  const second = await crypto.subtle.digest('SHA-256', first)

  return [...new Uint8Array(second)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized =
    value.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - (value.length % 4)) % 4)

  const binary = atob(normalized)
  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

function decodeHtml(value: string): string {
  return value
    .replace(/&quot;/g, '"')
    .replace(/&#34;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#39;|&apos;/g, "'")
}

export default app
