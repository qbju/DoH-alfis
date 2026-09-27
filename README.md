[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https%3A%2F%2Fgithub.com%2Fqbju%2FDoH-alfis)

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

This project intentionally does not define a KV namespace in `wrangler.jsonc`.

The Worker expects a KV binding named `ALFIS_KV`. The actual KV namespace is chosen by the deployer, so each user can attach their own namespace from the Cloudflare dashboard or add their own Wrangler KV binding configuration.

The application never uses a normal environment variable for the KV namespace ID because Cloudflare Workers KV is exposed through bindings.

Normal 1.1.1.1 responses are **never written to KV**.


Create/bind a KV namespace named `ALFIS_KV` and deploy with Wrangler.

The current `wrangler.jsonc` leaves the namespace ID empty so Wrangler can provision it during deployment according to the current Workers configuration flow.

Hono's Cloudflare Workers integration and Workers KV bindings are documented by Hono and Cloudflare.
