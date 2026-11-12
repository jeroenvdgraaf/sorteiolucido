# Relay de carimbo de tempo (Lucent Sorteios)

Servidor mínimo da SPEC 6.2, escrito como Cloudflare Worker. Navegadores não conseguem falar
diretamente com servidores RFC 3161 nem com as agendas do OpenTimestamps; o relay só repassa
os pedidos. Ele recebe apenas o lacre (um hash SHA-256), nunca a lista de participantes, e não
guarda estado além dos logs da plataforma.

| Rota | Entrada | Saída |
|---|---|---|
| `POST /v1/timestamp` | `{ "hash": "<64 hex>" }` | `{ "rfc3161": [{ "tsa", "token" }], "ots": "<base64>", "errors"?: [...] }` |
| `POST /v1/ots/upgrade` | `{ "ots": "<base64>" }` | `{ "ots": "<base64>", "complete": true \| false }` |
| `GET /v1/lottery/<megasena\|federal>/<concurso>` | | resultado normalizado, ou 404 |

- `token` é o `TimeStampResp` DER completo, em base64. O relay confere que a TSA carimbou o hash pedido
  antes de devolver o token; a página e o `verify_draw.py` conferem de novo.
- O `.ots` é montado como o cliente oficial: `append(nonce aleatório)`, `sha256`, e então as respostas
  das agendas. O `upgrade` só consulta agendas da lista `OTS_CALENDARS` (proteção contra SSRF) e
  marca `complete: true` quando há um atestado Bitcoin.
- `errors` (opcional) lista serviços que falharam; a resposta é 200 se pelo menos um serviço respondeu.
- O resultado de loteria é `{ game, contest, numbers | prizes, drawDate }`, a partir do endpoint
  não oficial da Caixa (a confirmar; ver `DECISIONS.md`).

## Configuração (`wrangler.toml`, seção `[vars]`)

- `TSAS`: lista JSON de TSAs `{ name, url, enabled }`. Padrão: freetsa.org e DigiCert ligadas;
  **ICP-Brasil presente e desligada**. Para ligar a ICP-Brasil numa implantação, preencha `url`
  com o endereço da Autoridade de Carimbo do Tempo contratada e mude `enabled` para `true`.
  Se a ACT exigir autenticação (certificado de cliente ou credenciais), isso ainda precisa ser
  implementado nesta implantação; nenhum caminho de código depende dela.
- `OTS_CALENDARS`: agendas OpenTimestamps (também usadas como lista permitida no upgrade).
- `CAIXA_API`: base do endpoint da Caixa.
- `ALLOWED_ORIGINS`: origens CORS permitidas, `["*"]` por padrão (necessário para abrir o HTML como
  arquivo local, cuja origem é `null`). Para restringir: `'["https://sorteio.exemplo.org"]'`.
- `TIMEOUT_MS`: tempo máximo de cada pedido repassado.

## Implantação

Requer uma conta Cloudflare (o plano gratuito basta) e Node.js 18 ou mais novo.

```sh
cd relay
npx wrangler@3 login          # abre o navegador para autorizar
npx wrangler@3 deploy         # publica; mostra a URL, ex.: https://lucent-sorteios-relay.<conta>.workers.dev
```

Teste rápido depois de publicar:

```sh
curl -s -X POST https://lucent-sorteios-relay.<conta>.workers.dev/v1/timestamp \
  -H 'content-type: application/json' \
  -d '{"hash":"d6af4d8f3b6126c60afbc36e4f21d987f940e9c53b7ce230c135e026d88518fa"}'
```

Depois, no Lucent Sorteios, abra **Detalhes técnicos** e cole a URL em **Relay de carimbo de tempo**.

Para rodar localmente: `npx wrangler@3 dev` (porta 8787).

## Limitações conhecidas

- Nada disto foi testado contra os serviços reais: os testes (`../run_tests.sh`) usam rede simulada,
  com respostas RFC 3161 geradas por uma TSA de teste local (openssl).
- O endpoint da Caixa pode recusar IPs fora do Brasil; os Workers saem por IPs da Cloudflare em
  vários países. Se o proxy de loteria falhar, a página pede a entrada manual do resultado.
- O upgrade OpenTimestamps não executa as operações `ripemd160` e `keccak256` (não existem em
  `crypto.subtle`); ramos que as usem não são atualizados. As agendas públicas usam `sha256`,
  `append` e `prepend`.
- Sem limite de taxa próprio; use as regras de rate limiting da Cloudflare se necessário.
