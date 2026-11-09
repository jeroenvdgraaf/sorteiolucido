# SorteioLúcido

Sorteios que qualquer pessoa pode conferir sem confiar em quem os organiza (protocolo
**LucentDraw/2**, família LucentCrypto). A lista de participantes é lacrada (hash SHA-256) antes de
existir o valor aleatório; o valor vem de uma fonte pública que ninguém controla (bloco Ethereum,
farol drand, Mega-Sena ou Loteria Federal); a ordem sai de uma regra publicada. A especificação
completa está em [`spec/SPEC.md`](spec/SPEC.md); as decisões de implementação, em [`DECISIONS.md`](DECISIONS.md).

## Conteúdo

| Arquivo | O que é |
|---|---|
| `SorteioLucido.html` | O aplicativo: um único arquivo, abas **Sortear** e **Conferir**. |
| `verifier/verify_draw.py` | Verificador de referência em Python (segunda implementação, independente). |
| `relay/` | Relay de carimbo de tempo (Cloudflare Worker), opcional. |
| `tests/` | Testes automáticos, todos sem rede. |
| `reference/LucentDraw.html` | Protótipo em inglês (LucentDraw/1). |

## Usar o HTML

Abra `SorteioLucido.html` num navegador atual (Chrome, Edge, Firefox ou Safari, também no celular),
direto do disco ou de qualquer servidor estático. Não há instalação nem cadastro.

1. **Preparar:** escolha *Ao vivo* ou *Agendado*, preencha título, ID do sorteio (anunciado antes) e
   participantes, e a fonte de aleatoriedade.
2. **Lacrar:** o formulário trava e o lacre aparece. Divulgue o lacre na hora (grupo, telão, ata).
3. **Resultado:** a página espera a aleatoriedade e mostra a ordem, o certificado (`.json`) e a ata.

Sorteios agendados podem ser fechados e reabertos depois do concurso. Se o site da Caixa recusar a
consulta, a página pede o resultado oficial digitado, e isso fica registrado como entrada manual.

Para carimbo de tempo, configure a URL do relay em **Detalhes técnicos**. Sem relay a página
funciona, mas avisa que não há carimbo de tempo.

## Conferir com Python

Requer Python 3.9+ e, para buscar os valores nas fontes, o pacote `requests`.

```sh
pip install requests
python3 verifier/verify_draw.py certificado-sorteio-<id>.json
python3 verifier/verify_draw.py certificado.json --rpc https://meu-no.exemplo   # seu próprio nó Ethereum
python3 verifier/verify_draw.py certificado.json --confirm-lottery              # conferi os números a olho
python3 verifier/verify_draw.py certificado.json --tsa-ca freetsa-cacert.pem    # valida a cadeia da TSA
```

Saída: 0 = confere, 1 = não confere, 2 = conferência incompleta. A assinatura BLS do drand é
verificada em Python puro; a dos carimbos RFC 3161 usa o `openssl`, se instalado.

## Publicar o relay

Veja [`relay/README.md`](relay/README.md). Em resumo: `cd relay && npx wrangler@3 login && npx wrangler@3 deploy`,
e cole a URL obtida nas configurações da página.

## Testes

```sh
./run_tests.sh      # ou: make test
```

Requer Node.js 18+ e Python 3.9+; `openssl` para os testes de carimbo de tempo. Os testes rodam o
núcleo do protocolo extraído do próprio HTML (marcadores `CORE-BEGIN`/`CORE-END`) e o
`verify_draw.py` sobre os mesmos vetores e certificados. O teste de interface com jsdom é opcional
(`JSDOM_DIR=<node_modules com jsdom> ./run_tests.sh`).

## Limitações atuais

- **Nada foi testado contra os serviços reais** (servidores Ethereum, drand, Caixa, TSAs,
  OpenTimestamps): todo o comportamento de rede foi testado com simulações.
- O endpoint da Caixa é não oficial; formato, bloqueio de CORS/IP e o calendário de sorteios
  precisam ser confirmados (ver `DECISIONS.md`).
- A página lê os tokens RFC 3161 (horário e hash carimbado), mas não valida a assinatura da TSA;
  isso é feito pelo `verify_draw.py`. A prova OpenTimestamps é guardada e atualizada, mas não é
  verificada aqui (use `ots verify`).
- A regra "um lacre por ID" vale só dentro do mesmo navegador.
- Carimbo do tempo ICP-Brasil: previsto na configuração, desligado.

## Licença

Copyright (C) 2026 Jeroen van de Graaf.

- **Especificação e verificador** ([`spec/`](spec/) e [`verifier/`](verifier/)): [Apache-2.0](spec/LICENSE). Qualquer pessoa pode usar, adaptar e reimplementar a conferência, inclusive em produtos fechados.
- **Todo o resto** (a página `SorteioLucido.html`, o relay, os testes): [GNU AGPL-3.0](LICENSE). Quem oferecer uma versão modificada como serviço on-line precisa publicar o código-fonte dessas modificações.
- **Licença comercial:** para usar a aplicação sem as obrigações da AGPL, entre em contato com o autor.
- Cada arquivo indica sua licença na linha `SPDX-License-Identifier`. A cópia do `drand-client` em `tests/vendor/` mantém a sua própria licença (Apache-2.0 ou MIT).
- **Contribuições externas** só são aceitas com um acordo de contribuição (CLA) que preserve a possibilidade de licenciamento comercial.
