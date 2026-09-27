# DoH-alfis

Hono + Cloudflare Workers PoC for DNS-over-HTTPS with Alfis fallback.

## Resolution order

1. Workers KV lookup (Alfis answers only)
2. Cloudflare 1.1.1.1 DoH
3. Alfis Viewer lookup using double-SHA256 hash form
4. For subdomains, climb to the nearest solved parent domain
5. Return the upstream DNS result when Alfis has no matching record

Normal 1.1.1.1 responses are **never written to KV**.

## Endpoints

- GET /dns-query?dns=<base64url DNS packet>
- POST /dns-query with Content-Type: application/dns-message

## Cloudflare setup

Create/bind a KV namespace named `ALFIS_KV` and deploy with Wrangler.

The current `wrangler.jsonc` leaves the namespace ID empty so Wrangler can provision it during deployment according to the current Workers configuration flow.

Hono's Cloudflare Workers integration and Workers KV bindings are documented by Hono and Cloudflare.
