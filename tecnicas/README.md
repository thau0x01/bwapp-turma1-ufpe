# Técnicas de SQL Injection — Material Aprofundado

Esta pasta complementa o [`guia_sqli.md`](../guia_sqli.md) da raiz do repositório. Onde o guia principal apresenta o método em fases (detecção → contexto → exploração) usando o bWAPP como laboratório, aqui cada arquivo entra fundo em **uma técnica específica**, com walkthrough completo de enumeração do `information_schema` aplicada ao próprio bWAPP deste repositório.

Cada documento é autossuficiente: traz a teoria da técnica, o passo a passo prático, payloads prontos pra colar no Burp Repeater, pegadinhas comuns e cheatsheet ao final.

---

## Sumário das técnicas

| Arquivo | Técnica | Lab bWAPP principal | Quando usar |
|---------|---------|---------------------|-------------|
| [`union_based.md`](union_based.md) | **UNION-based** (in-band) | `/sqli_1.php` | A aplicação reflete dados da query no HTML. Caminho mais rápido pra leitura. |
| [`error_based.md`](error_based.md) | **Error-based** (in-band) | `/sqli_1.php` | A aplicação exibe mensagens de erro do banco. Uma requisição = um dado extraído. |
| [`boolean_based.md`](boolean_based.md) | **Boolean-based Blind** | `/sqli_4.php` | Não tem reflexão nem erro, mas a página tem dois estados visíveis (existe / não existe). |
| [`time_based.md`](time_based.md) | **Time-based Blind** | `/sqli_15.php` | A resposta é idêntica em qualquer caso — só o tempo de resposta serve como canal. |
| [`stacked_queries.md`](stacked_queries.md) | **Stacked Queries** | — *(não funciona no bWAPP)* | Modificar dados ou executar comandos quando o driver permite múltiplas statements. Documento explica por que `mysqli_query` bloqueia, e onde stacked **funciona** (MSSQL, PostgreSQL, `mysqli_multi_query`). |

---

## Por onde começar

Se você está vindo do `guia_sqli.md` e quer aprofundar, sugestão de ordem:

1. **`union_based.md`** — é a técnica mais usada e a referência mental que sustenta todas as outras. Dominou UNION = dominou o information_schema.
2. **`error_based.md`** — leitura natural depois de UNION; mesmo alvo, técnica mais rápida quando aplicável.
3. **`boolean_based.md`** — primeiro contato com Blind. A metodologia caractere-por-caractere abre a cabeça pra como pensar quando não tem retorno direto.
4. **`time_based.md`** — extensão direta de boolean blind para cenários sem nenhum sinal visual. Lentíssimo, mas universal.
5. **`stacked_queries.md`** — diferente em natureza: a única técnica que **modifica** estado (INSERT/UPDATE/DROP/EXEC). Útil pra entender o vetor mesmo sem laboratório local.

---

## Árvore de decisão — qual técnica usar?

```
Confirmou SQLi (Fase 1 do guia_sqli.md).
│
├── A aplicação reflete dados da query no HTML?
│   └── SIM → UNION-based (union_based.md)
│
├── A aplicação mostra mensagens de erro do banco com conteúdo do erro?
│   └── SIM → Error-based (error_based.md)
│
├── A página muda visivelmente conforme a query retorna ou não (existe / não existe, redirect / sem redirect)?
│   └── SIM → Boolean-based blind (boolean_based.md)
│
├── A resposta é idêntica, mas dá pra medir tempo de resposta com precisão?
│   └── SIM → Time-based blind (time_based.md)
│
└── Quer escrever dados / RCE / modificar estado E o driver é MSSQL/PostgreSQL/multi_query?
    └── Stacked queries (stacked_queries.md)
```

> **Dica:** essas técnicas não são mutuamente exclusivas. Em alvos reais é comum começar tentando UNION, cair pra error-based quando UNION falha por algum motivo (charset, parênteses), e usar blind como fallback final. Mantenha a tabela acima em mente.

---

## Convenções compartilhadas

Todos os arquivos desta pasta assumem o ambiente descrito no [`guia_sqli.md` seção 2](../guia_sqli.md#2-setup-do-ambiente-de-prática):

- **bWAPP** no container customizado deste repositório (`docker compose up -d --build`)
- **MariaDB 10.6** como banco (compatível com sintaxe MySQL — `information_schema`, `GROUP_CONCAT`, `SLEEP`, `EXTRACTVALUE` etc.)
- **Burp Suite Repeater** como ferramenta padrão para repetir/variar payloads
- **Security level = `low`** salvo quando o texto disser explicitamente o contrário

Os payloads usam o final `-- -` (traço-traço-espaço-traço) como comentário, padrão MySQL/MariaDB que funciona dentro e fora de URL.
