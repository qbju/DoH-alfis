import { Hono } from 'hono'
import * as dns from '@dnsquery/dns-packet'
import { isBlockedDomain, listBlockedDomains, normalizeBlockedDomain, BLOCKLIST_PREFIX } from './blocklist'

type Bindings = {
  ALFIS_KV?: KVNamespace
  ADMIN_TOKEN?: string
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
  host?: string
}

type AlfisData = {
  zone: string
  records: AlfisRecord[]
}

const app = new Hono<{ Bindings: Bindings }>()

const DOH_CONTENT_TYPE = 'application/dns-message'
const VIEWER = 'https://viewer.alfis.name/domain/'
const DNS1111 = 'https://cloudflare-dns.com/dns-query'

const ALFIS_ZONES = new Set(['anon','btn','conf','index','merch','mirror','mob','screen','srv','ygg'])

app.get('/', (c) => c.text('DoH Alfis PoC'))

app.get('/admin', (c) => c.html(ADMIN_HTML))

app.get('/api/blocklist', async (c) => {
  if (!isAdminAuthorized(c.req.header('authorization'), c.env.ADMIN_TOKEN)) {
    return c.json({ error: 'unauthorized' }, 401)
  }
  if (!c.env.ALFIS_KV) return c.json({ error: 'ALFIS_KV is not configured' }, 503)
  return c.json({ domains: await listBlockedDomains(c.env.ALFIS_KV) })
})

app.post('/api/blocklist', async (c) => {
  if (!isAdminAuthorized(c.req.header('authorization'), c.env.ADMIN_TOKEN)) {
    return c.json({ error: 'unauthorized' }, 401)
  }
  if (!c.env.ALFIS_KV) return c.json({ error: 'ALFIS_KV is not configured' }, 503)

  const body = await c.req.json<{ domain?: string }>().catch(() => null)
  const domain = body?.domain ? normalizeBlockedDomain(body.domain) : ''
  if (!isValidDomain(domain)) return c.json({ error: 'invalid domain' }, 400)

  await c.env.ALFIS_KV.put(BLOCKLIST_PREFIX + domain, '1')
  return c.json({ ok: true, domain })
})

app.delete('/api/blocklist', async (c) => {
  if (!isAdminAuthorized(c.req.header('authorization'), c.env.ADMIN_TOKEN)) {
    return c.json({ error: 'unauthorized' }, 401)
  }
  if (!c.env.ALFIS_KV) return c.json({ error: 'ALFIS_KV is not configured' }, 503)

  const body = await c.req.json<{ domain?: string }>().catch(() => null)
  const domain = body?.domain ? normalizeBlockedDomain(body.domain) : ''
  if (!isValidDomain(domain)) return c.json({ error: 'invalid domain' }, 400)

  await c.env.ALFIS_KV.delete(BLOCKLIST_PREFIX + domain)
  return c.json({ ok: true, domain })
})

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
  if (!question?.name || question.class !== 'IN') return dnsResponse(makeErrorResponse(query, 1))
  const qname = normalizeName(question.name)
  const qtype = question.type
  const tld = qname.split('.').at(-1) ?? ''
  console.log('[DoH] query', { qname, qtype, tld, isAlfis: ALFIS_ZONES.has(tld) })

  // Apply the blocklist before either Alfis or upstream resolution.
  // This makes the policy consistent for both Alfis and normal DNS names.
  if (await isBlockedDomain(qname, env.ALFIS_KV)) {
    console.log('[DoH] blocked', { qname, qtype })
    return dnsResponse(makeErrorResponse(query, 3))
  }

  if (ALFIS_ZONES.has(tld)) return resolveAlfisQuery(env, query, qname, qtype)
  return resolveNormalQuery(packet)
}

async function resolveAlfisQuery(env: Bindings, query: any, qname: string, qtype: string): Promise<Response> {
  console.log('[Alfis] start', { qname, qtype })
  const cacheKey = 'alfis:v2:' + qname + ':' + qtype
  const cached = env.ALFIS_KV ? await env.ALFIS_KV.get(cacheKey, 'arrayBuffer') : null
  console.log('[Alfis] KV', env.ALFIS_KV ? (cached ? 'HIT' : 'MISS') : 'UNBOUND', cacheKey)
  if (cached) return dnsResponse(new Uint8Array(cached))
  try {
    const alfis = await resolveFromAlfis(qname, qtype)
    console.log('[Alfis] resolve result', alfis)
    if (!alfis) return dnsResponse(makeErrorResponse(query, 3))

    const response = await makeAlfisResponse(query, qname, qtype, alfis.data, alfis.ownerDomain)
    const encoded = dns.encode(response)
    if (env.ALFIS_KV) {
      await env.ALFIS_KV.put(cacheKey, encoded.buffer as ArrayBuffer, {
        expirationTtl: Math.max(30, minTtl(alfis.records)),
      })
    }
    return dnsResponse(encoded)
  } catch (err) {
    console.error('Alfis lookup failed:', err)
    return dnsResponse(makeErrorResponse(query, 2))
  }
}

async function queryCloudflare(packet: Uint8Array): Promise<Response> {
  return fetch(DNS1111, {
    method: 'POST',
    headers: {
      'content-type': DOH_CONTENT_TYPE,
      'accept': DOH_CONTENT_TYPE,
    },
    body: packet,
  })
}

async function resolveNormalQuery(packet: Uint8Array): Promise<Response> {
  try {
    const normal = await queryCloudflare(packet)
    if (normal.ok) return dnsResponse(new Uint8Array(await normal.arrayBuffer()))
    console.error('Cloudflare DoH returned HTTP', normal.status)
  } catch (err) {
    console.error('Cloudflare DoH query failed:', err)
  }
  return new Response(null, { status: 502 })
}
async function resolveFromAlfis(qname: string, qtype: string): Promise<{ data: AlfisData; ownerDomain: string } | null> {
  const labels = qname.split('.').filter(Boolean)
  console.log('[Alfis] labels', labels)
  if (labels.length < 2) return null

  // foo.bar.send.ygg -> foo.bar.send.ygg -> bar.send.ygg -> send.ygg
  // Try the exact domain first, then walk up through its parents.
  for (let i = 0; i <= labels.length - 2; i++) {
    const candidate = labels.slice(i).join('.')
    const candidateTld = candidate.split('.').at(-1) ?? ''
    console.log('[Alfis] candidate', { candidate, candidateTld })
    if (!ALFIS_ZONES.has(candidateTld)) continue
    const data = await fetchAlfis(candidate)
    console.log('[Alfis] viewer data', data)

    if (!data) continue

    const selected = selectRecords(data.records, qname, candidate, qtype, true)
    console.log('[Alfis] selected', { candidate, qname, qtype, selected })
    if (selected.length > 0) return { data, ownerDomain: candidate }
  }

  return null
}

async function fetchAlfis(domain: string): Promise<AlfisData | null> {
  const zone = domain.split('.').at(-1)!
  const hash = await doubleSha256Hex(domain)

  // Alfis Viewer lookup uses literal angle brackets around the hash:
  // <HASH>.ygg
  const lookup = `<${hash}>.${zone}`
  const url = `${VIEWER}${encodeURIComponent(lookup)}`
  console.log('[Viewer] request', { domain, zone, hash, url })
  const response = await fetch(`${VIEWER}${encodeURIComponent(lookup)}`, {
    headers: { accept: 'text/html' },
  })

  console.log('[Viewer] HTTP', response.status)
  if (!response.ok) return null

  const html = await response.text()
  const match = html.match(/<pre[^>]*>([\\s\\S]*?)<\\/pre>/i)
  if (!match) return null

  try {
    const raw = match[1]
      .replace(/<code[^>]*>/gi, '')
      .replace(/<\\/code>/gi, '')
      .trim()
      .replace(/^\`|\`$/g, '')
      .trim()
    const data = JSON.parse(decodeHtml(raw)) as AlfisData
    console.log('[Viewer] parsed', { zone: data.zone, recordCount: data.records?.length, records: data.records })
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
  allowCnameForAddressQuery = false,
): AlfisRecord[] {
  const relative =
    qname === ownerDomain
      ? '@'
      : qname.endsWith(`.${ownerDomain}`)
        ? qname.slice(0, -(ownerDomain.length + 1))
        : null

  console.log('[Select] input', { qname, ownerDomain, qtype, relative, records })
  if (relative === null) return []

  return records.filter((record) => {
    const owner = normalizeName(record.domain || '@')
    const typeMatches =
      record.type === qtype ||
      (allowCnameForAddressQuery &&
        (qtype === 'A' || qtype === 'AAAA') &&
        record.type === 'CNAME')
    const ownerMatches = owner === '@' ? qname === ownerDomain : owner === relative
    return ownerMatches && typeMatches
  })
}

async function makeAlfisResponse(
  query: any,
  qname: string,
  qtype: string,
  data: AlfisData,
  ownerDomain: string,
): Promise<any> {
  const records = selectRecords(data.records, qname, ownerDomain, qtype, true)
  const answers = records.map((record) => toDnsAnswer(record, qname))

  // A/AAAA queries that hit an Alfis CNAME are resolved through 1.1.1.1
  // and returned together with the original CNAME, as required by normal
  // DNS CNAME processing.
  if ((qtype === 'A' || qtype === 'AAAA') && records.some((r) => r.type === 'CNAME')) {
    const cname = records.find((r) => r.type === 'CNAME')!
    const target = normalizeName(cname.addr ?? cname.value ?? cname.host ?? '')
    if (!target) throw new Error('Alfis CNAME has no target')

    const targetAnswers = await resolveCnameTarget(query, target, qtype, [qname])
    answers.push(...targetAnswers)
  }

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

async function resolveCnameTarget(
  originalQuery: any,
  target: string,
  qtype: string,
  chain: string[],
): Promise<any[]> {
  if (chain.includes(target)) throw new Error('CNAME loop detected')
  if (chain.length >= 16) throw new Error('CNAME chain too long')

  const targetQuery = {
    type: 'query',
    id: originalQuery.id,
    flags: originalQuery.flags ?? 0,
    questions: [{ name: target, type: qtype, class: 'IN' }],
    answers: [],
    authorities: [],
    additionals: [],
  }

  const upstream = await queryCloudflare(dns.encode(targetQuery))
  if (!upstream.ok) {
    throw new Error(`Cloudflare DoH returned HTTP ${upstream.status}`)
  }

  const upstreamPacket = new Uint8Array(await upstream.arrayBuffer())
  const upstreamResponse = dns.decode(upstreamPacket)
  const upstreamAnswers = upstreamResponse.answers ?? []

  const cnameAnswers = upstreamAnswers.filter((answer: any) => answer.type === 'CNAME')
  const addressAnswers = upstreamAnswers.filter(
    (answer: any) => answer.type === qtype && answer.class === 'IN',
  )

  if (addressAnswers.length > 0) {
    return [...cnameAnswers, ...addressAnswers]
  }

  const nextCname = cnameAnswers.at(-1)
  if (!nextCname?.data) return []

  const nextTarget = normalizeName(String(nextCname.data))
  const chained = await resolveCnameTarget(originalQuery, nextTarget, qtype, [...chain, target])
  return [...cnameAnswers, ...chained]
}

function toDnsAnswer(record: AlfisRecord, qname: string): any {
  const ttl = record.ttl ?? 300

  switch (record.type) {
    case 'A':
    case 'AAAA':
      return { name: qname, type: record.type, class: 'IN', ttl, data: record.addr }
    case 'CNAME':
      return { name: qname, type: 'CNAME', class: 'IN', ttl, data: record.addr ?? record.value ?? record.host }
    case 'NS':
      return { name: qname, type: 'NS', class: 'IN', ttl, data: record.addr ?? record.value ?? record.host }
    case 'PTR':
      return { name: qname, type: 'PTR', class: 'IN', ttl, data: record.addr ?? record.value }
    case 'MX':
      return {
        name: qname,
        type: 'MX',
        class: 'IN',
        ttl,
        preference: record.priority ?? 10,
        exchange: record.addr ?? record.value ?? record.host,
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
          target: record.target ?? record.addr ?? record.value ?? record.host ?? '.',
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

function isAdminAuthorized(header: string | undefined, token: string | undefined): boolean {
  if (!token || !header) return false
  return header === `Bearer ${token}`
}

function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253 || domain.includes('..')) return false
  const labels = domain.split('.')
  return labels.length >= 2 && labels.every((label) =>
    label.length >= 1 &&
    label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  )
}

const ADMIN_HTML = `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DoH Alfis - Blocklist</title>
<style>
body{font-family:system-ui,sans-serif;max-width:720px;margin:40px auto;padding:0 16px}
input,button{font:inherit;padding:10px} input{width:70%} button{cursor:pointer}
li{display:flex;justify-content:space-between;gap:12px;margin:8px 0}
#login{margin-bottom:24px}.muted{color:#666}
</style>
</head>
<body>
<h1>Blocklist</h1>
<p class="muted">ドメインを追加すると、その配下のサブドメインもNXDOMAINになります。</p>
<div id="login">
<input id="token" type="password" placeholder="ADMIN_TOKEN">
<button onclick="load()">接続</button>
</div>
<form id="add" style="display:none" onsubmit="add(event)">
<input id="domain" placeholder="example.com" autocomplete="off">
<button>ブロック</button>
</form>
<ul id="list"></ul>
<script>
let token='';
async function api(path, options={}){
  options.headers=Object.assign({'Authorization':'Bearer '+token,'Content-Type':'application/json'},options.headers||{});
  const r=await fetch(path,options);
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}
async function load(){
  token=document.getElementById('token').value;
  try{
    await refresh();
    document.getElementById('add').style.display='block';
  }catch(e){alert('認証失敗 / '+e.message)}
}
async function refresh(){
  const data=await api('/api/blocklist');
  document.getElementById('list').innerHTML=data.domains.map(d =>
    '<li><code>'+escapeHtml(d)+'</code><button onclick="removeDomain(\\''+escapeJs(d)+'\\')">削除</button></li>'
  ).join('');
}
async function add(e){
  e.preventDefault();
  const domain=document.getElementById('domain').value.trim();
  try{await api('/api/blocklist',{method:'POST',body:JSON.stringify({domain})});document.getElementById('domain').value='';await refresh()}
  catch(e){alert(e.message)}
}
async function removeDomain(domain){
  if(!confirm(domain+' をブロック解除？')) return;
  try{await api('/api/blocklist',{method:'DELETE',body:JSON.stringify({domain})});await refresh()}
  catch(e){alert(e.message)}
}
function escapeHtml(s){return s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function escapeJs(s){return s.replace(/\\\\/g,'\\\\\\\\').replace(/'/g,"\\\\'")}
</script>
</body>
</html>`

export default app
