[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https%3A%2F%2Fgithub.com%2Fqbju%2FDoH-alfis)

# DoH-alfis

Hono + Cloudflare Workers で動く、Alfis 対応 DNS-over-HTTPS リゾルバの PoC。

## Deploy

上の **Deploy to Cloudflare** ボタンからデプロイできます。

デプロイ後、Cloudflare Workers の KV binding に自分の KV namespace を `ALFIS_KV` という名前で設定してください。

## Endpoints

- `GET /dns-query?dns=<base64url DNS packet>`
- `POST /dns-query` with `Content-Type: application/dns-message`

## License

MIT
