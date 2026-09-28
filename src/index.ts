import { Hono } from 'hono'
import * as dns from '@dnsquery/dns-packet'
import { BLOCKED_DOMAINS, isBlockedDomain, listBlockedDomains, normalizeBlockedDomain, BLOCKLIST_PREFIX } from './blocklist'

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

  const domains = await listBlockedDomains(c.env.ALFIS_KV)
  return c.json({
    domains: domains.map((domain) => ({
      domain,
      editable: !isConfiguredDomain(domain),
      source: isConfiguredDomain(domain) ? 'config' : 'kv',
    })),
  })
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

app.put('/api/blocklist', async (c) => {
  if (!isAdminAuthorized(c.req.header('authorization'), c.env.ADMIN_TOKEN)) {
    return c.json({ error: 'unauthorized' }, 401)
  }
  if (!c.env.ALFIS_KV) return c.json({ error: 'ALFIS_KV is not configured' }, 503)

  const body = await c.req.json<{ from?: string; domain?: string }>().catch(() => null)
  const from = body?.from ? normalizeBlockedDomain(body.from) : ''
  const domain = body?.domain ? normalizeBlockedDomain(body.domain) : ''

  if (!isValidDomain(from) || !isValidDomain(domain)) {
    return c.json({ error: 'invalid domain' }, 400)
  }
  if (isConfiguredDomain(from)) {
    return c.json({ error: 'config domain cannot be edited' }, 400)
  }
  if (from === domain) return c.json({ ok: true, domain })

  await c.env.ALFIS_KV.delete(BLOCKLIST_PREFIX + from)
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
  if (isConfiguredDomain(domain)) {
    return c.json({ error: 'config domain cannot be deleted' }, 400)
  }

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
  const lookup = `<${hash}>.${zone}`
  const url = `${VIEWER}${encodeURIComponent(lookup)}`
  console.log('[Viewer] request', { domain, zone, hash, url })

  try {
    const response = await fetch(url, {
      headers: {
        accept: 'application/json, text/html;q=0.9, */*;q=0.8',
      },
      signal: AbortSignal.timeout(8000),
    })

    console.log('[Viewer] HTTP', response.status, response.headers.get('content-type'))
    if (!response.ok) return null

    const body = await response.text()
    const data = parseAlfisData(body, response.headers.get('content-type') ?? '')
    if (!data) {
      console.error('[Viewer] could not parse Alfis data')
      return null
    }

    console.log('[Viewer] parsed', {
      zone: data.zone,
      recordCount: data.records?.length,
      records: data.records,
    })
    return data
  } catch (err) {
    console.error('[Viewer] request failed', err)
    return null
  }
}

function parseAlfisData(body: string, contentType: string): AlfisData | null {
  const candidates: string[] = []

  if (contentType.toLowerCase().includes('application/json')) {
    candidates.push(body)
  }

  const htmlMatches = [
    body.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i)?.[1],
    body.match(/<textarea[^>]*>([\s\S]*?)<\/textarea>/i)?.[1],
    body.match(/<script[^>]*type=["']application\/json["'][^>]*>([\s\S]*?)<\/script>/i)?.[1],
  ]

  for (const match of htmlMatches) {
    if (match) candidates.push(match)
  }

  candidates.push(body)

  for (const candidate of candidates) {
    try {
      const raw = decodeHtml(candidate)
        .replace(/<code[^>]*>/gi, '')
        .replace(/<\/code>/gi, '')
        .trim()
        .replace(/^\`|\`$/g, '')
        .trim()
      const data = JSON.parse(raw) as AlfisData
      if (data && typeof data.zone === 'string' && Array.isArray(data.records)) {
        return data
      }
    } catch {
      // Try the next representation.
    }
  }

  return null
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
    const ownerMatches =
      owner === '@'
        ? qname === ownerDomain
        : owner === relative || (owner === '*' && relative !== '@')
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

function isConfiguredDomain(domain: string): boolean {
  for (const blocked of BLOCKED_DOMAINS) {
    if (normalizeBlockedDomain(blocked) === domain) return true
  }
  return false
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
:root{color-scheme:dark light}
body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px}
input,button{font:inherit;padding:10px} input{box-sizing:border-box}
button{cursor:pointer}
#token{width:min(100%,520px)}
#domain{width:min(100%,520px)}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
.list{list-style:none;padding:0;margin:16px 0}
.item{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:10px 0;border-bottom:1px solid #ddd}
.actions{display:flex;gap:6px}
code{overflow-wrap:anywhere}
.muted{color:#666}
#status{min-height:1.4em}
</style>
</head>
<body>
<h1>Blocklist</h1>
<p class="muted">登録されたドメインと、配下でブロックされる範囲を管理します。</p>

<div id="login">
<input id="token" type="password" placeholder="ADMIN_TOKEN" autocomplete="current-password">
<button onclick="load()">接続</button>
</div>

<div id="panel" style="display:none">
<form id="add" onsubmit="add(event)">
<div class="toolbar">
<input id="domain" placeholder="example.com" autocomplete="off" required>
<button type="submit">追加</button>
<button type="button" onclick="refresh()">再読み込み</button>
</div>
</form>
<p id="status" class="muted"></p>
<ul id="list" class="list"></ul>
</div>

<script>
let token='';

async function api(path, options={}){
  options.headers=Object.assign({
    'Authorization':'Bearer '+token,
    'Content-Type':'application/json'
  },options.headers||{});
  const r=await fetch(path,options);
  if(!r.ok) throw new Error(await r.text());
  return r.json();
}

async function load(){
  token=document.getElementById('token').value;
  try{
    await refresh();
    document.getElementById('panel').style.display='block';
    setStatus('接続しました');
  }catch(e){
    setStatus('接続失敗: '+e.message);
  }
}

async function refresh(){
  const data=await api('/api/blocklist');
  render(data.domains);
}

function render(domains){
  const list=document.getElementById('list');
  list.replaceChildren();

  if(!domains.length){
    const empty=document.createElement('li');
    empty.className='muted';
    empty.textContent='現在ブロックされているドメインはありません。';
    list.appendChild(empty);
    return;
  }

  for(const item of domains){
    const li=document.createElement('li');
    li.className='item';

    const left=document.createElement('div');
    const code=document.createElement('code');
    code.textContent=item.domain;
    left.appendChild(code);

    const meta=document.createElement('span');
    meta.className='muted';
    meta.textContent=item.source==='config'?' 設定ファイル':' KV';
    left.appendChild(meta);

    const actions=document.createElement('div');
    actions.className='actions';

    if(item.editable){
      const edit=document.createElement('button');
      edit.textContent='編集';
      edit.onclick=()=>editDomain(item.domain);
      actions.appendChild(edit);

      const remove=document.createElement('button');
      remove.textContent='削除';
      remove.onclick=()=>removeDomain(item.domain);
      actions.appendChild(remove);
    }else{
      const locked=document.createElement('span');
      locked.className='muted';
      locked.textContent='設定ファイルで管理';
      actions.appendChild(locked);
    }

    li.append(left,actions);
    list.appendChild(li);
  }
}

async function add(e){
  e.preventDefault();
  const domain=document.getElementById('domain').value.trim();
  try{
    const result=await api('/api/blocklist',{
      method:'POST',
      body:JSON.stringify({domain})
    });
    document.getElementById('domain').value='';
    await refresh();
    setStatus(result.domain+' を追加しました');
  }catch(e){
    setStatus('追加失敗: '+e.message);
  }
}

async function editDomain(oldDomain){
  const newDomain=prompt('変更後のドメイン',oldDomain);
  if(newDomain===null || !newDomain.trim() || newDomain.trim()===oldDomain) return;

  try{
    const result=await api('/api/blocklist',{
      method:'PUT',
      body:JSON.stringify({from:oldDomain,domain:newDomain.trim()})
    });
    await refresh();
    setStatus(oldDomain+' → '+result.domain+' に変更しました');
  }catch(e){
    setStatus('編集失敗: '+e.message);
  }
}

async function removeDomain(domain){
  if(!confirm(domain+' をブロック解除しますか？')) return;

  try{
    await api('/api/blocklist',{
      method:'DELETE',
      body:JSON.stringify({domain})
    });
    await refresh();
    setStatus(domain+' を削除しました');
  }catch(e){
    setStatus('削除失敗: '+e.message);
  }
}

function setStatus(message){
  document.getElementById('status').textContent=message;
}
</script>
</body>
</html>`

export default app
