# Decisões de implementação

Pontos em que a SPEC era ambígua, contraditória ou dependia de fatos externos. Em cada caso foi
escolhida a leitura mais conservadora. Nenhuma decisão altera entradas de hash, nomes de campos
ou ordem definidos nas seções 3.1, 4, 5 e 9.

## A confirmar pelo responsável

1. **Endpoint da Caixa** (`https://servicebus2.caixa.gov.br/portaldeloterias/api/<jogo>/<concurso>`):
   usado só como descrito na SPEC 4.5. Nada foi testado contra o serviço real. O formato da resposta
   foi assumido como `numero`, `dataApuracao` (`dd/mm/aaaa`) e `listaDezenas` (com
   `dezenasSorteadasOrdemSorteio` como alternativa). Para a Loteria Federal assume-se que
   `listaDezenas` traz os 5 bilhetes **na ordem dos prêmios** e que podem vir com 6 dígitos com zero
   à esquerda (são reduzidos a 5). Se o formato não bater, o resultado é tratado como indisponível e
   a página pede a entrada manual. **A confirmar pelo responsável.**
2. **Calendário de sorteios** (valores padrão, editáveis em Detalhes técnicos):
   Mega-Sena às terças, quintas e sábados, 21:00; Loteria Federal às quartas e sábados, 19:00
   (horário de Brasília, UTC−3 fixo). A SPEC pede para conferir o calendário atual, mas não o dá, e
   esta implementação não teve acesso à Caixa. **A confirmar pelo responsável.**
3. **Número do concurso sugerido:** sem um concurso de referência conhecido (número + data), a
   página sugere só a **data**; o número só é calculado se o responsável preencher a referência no
   calendário. Feriados e sorteios especiais não são previstos: o operador sempre confirma.
4. **Páginas oficiais de resultado** usadas como link: `https://loterias.caixa.gov.br/Paginas/Mega-Sena.aspx`
   e `.../Federal.aspx`. **A confirmar pelo responsável.**
5. **TSAs padrão** (freetsa.org, DigiCert) e agendas OpenTimestamps: copiadas da SPEC / do uso comum;
   não testadas ao vivo.

## Protocolo e conferência

6. **Veredito com três estados.** A SPEC 9.7 só define "confere" e "não confere". Itens *atenção* e
   *não verificado* (sem carimbo de tempo, fonte fora do ar) não são falhas, mas também não permitem
   dizer "confere". Foi adicionado um terceiro texto, "Conferência incompleta: nenhum item falhou, mas
   estes não puderam ser confirmados: …". A página nunca diz "confere" sem que tudo tenha passado
   (exceção prevista na SPEC: loteria *não verificada* com a caixa "conferi a olho" marcada, ou
   `--confirm-lottery` no Python). Consequência: sem carimbo de tempo, o melhor veredito possível é
   "incompleta". `verify_draw.py` sai com 0 = confere, 1 = não confere, 2 = incompleta.
7. **Lacre sem aleatoriedade** (SPEC 3.3): fontes ficam *não verificado* ("ainda não registrado"),
   não *falhou*.
8. **Rodada drand "at or after"**: `r = ceil((t − genesis) / 3) + 1`. O protótipo usava `floor + 1`,
   que pode escolher a rodada *anterior* ao instante pedido; corrigido.
9. **Lacre com loteria**: o sorteio do concurso precisa ser **pelo menos 2 h depois do lacre**
   (a SPEC fala em sugerir; aqui também é exigido ao lacrar).
10. **Horário da aleatoriedade na comparação com o carimbo** (SPEC 6.4): Ethereum = timestamp do bloco
    alvo (ou `notBefore + 1` se o bloco não puder ser lido); drand = horário da rodada; loteria = data do
    sorteio (do resultado oficial se obtido, senão do certificado) + hora do calendário assumido.
    Só tokens RFC 3161 que carimbam o compromisso (e cuja assinatura não falhou, no Python) entram na
    comparação. A prova OpenTimestamps não entra (não é validada aqui; use `ots verify`).
11. **Validação estrita do spec v2**: campos de topo e de cada fonte devem ser exatamente os da SPEC
    (campos extras falham), `chain`/`rule`/`chainHash` com os valores fixos, `confirmations ≥ 1`.
    Para LucentDraw/1 a validação é a do protótipo (aceita `rule`/`value` livres, só `eth`/`drand`).
12. **"Trim"** = conjunto de espaços de `String.prototype.trim` do ECMAScript, também no Python
    (o `str.strip()` do Python difere em `U+FEFF` e `U+001C–U+001F`, `U+0085`).
13. **Evidência inconsistente**: se o hash do bloco confere mas `timestamp`/`parentTimestamp` no
    certificado diferem da cadeia, a checagem `eth` falha.
14. **Bloco com menos confirmações que o exigido** na hora da conferência: *atenção*, não falha.
15. **Reorganização**: se o bloco canônico na altura do alvo mudou, `eth` falha com mensagem explícita
    e a ordem é recalculada com o bloco canônico (que passa a valer, SPEC 4.1); `order` então falha e
    a ordem correta é mostrada.
16. **Fonte devolve beacon com BLS inválido**: na página, a biblioteca recusa e a checagem fica *não
    verificado* (a falha é da fonte, não do certificado); no Python, a checagem `drand` falha.
17. **BLS no Python sem dependências**: a SPEC exige biblioteca padrão e verificação BLS. Foi escrita
    uma verificação BLS12-381 em Python puro (hash_to_curve RFC 9380, emparelhamento ate), testada
    contra vetores da RFC 9380 e assinaturas geradas com @noble/curves. Leva cerca de 1 s por rodada.
18. **Assinatura das TSAs no Python**: via binário `openssl` (`cms -verify -noverify` para a
    assinatura, `ts -verify` para a cadeia). Assinatura inválida = falha; cadeia sem CA confiável =
    atenção; `openssl` ausente = só leitura, com nota. Use `--tsa-ca` para a CA da freetsa.org.

## Interface e segurança

19. **Fontes Google removidas**: a SPEC 8 limita pedidos de rede às fontes, endpoints e relay; o
    protótipo carregava Google Fonts. A página usa fontes do sistema.
20. **Informação da cadeia quicknet fixada na página**: a verificação BLS usa a chave pública embutida,
    sem buscar `/info`. O `drand-client` 1.4.2 não exporta `verifyBeacon`; a página passa um
    ChainClient próprio a `fetchBeacon` (com fallback api.drand.sh → drand.cloudflare.com).
21. **Um lacre por ID**: a lista de IDs lacrados fica no localStorage do navegador; um ID já lacrado é
    recusado e o botão "Novo sorteio com outro ID" limpa o campo. Vários lacres pendentes ficam
    guardados e podem ser reabertos.
22. **Entrada manual**: só aparece quando a busca automática falha (ou 6 h após o horário previsto
    sem resultado) e exige marcar "Conferi estes números na página oficial".
23. **ICP-Brasil**: presente na configuração do relay (`enabled: false`), sem código que dependa dela.
    Autenticação junto a uma ACT não foi implementada.
24. **Não foi construído** nada da SPEC 12 (sorteio ponderado, grupos, FilaLúcida, interface em inglês etc.).
