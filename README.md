# Pre-Publish Check (`ppc`)

[![CI](https://github.com/Rimuro-Sama/Pre-Publish-Check-PPC/actions/workflows/ci.yml/badge.svg)](https://github.com/Rimuro-Sama/Pre-Publish-Check-PPC/actions/workflows/ci.yml)

Confere um repositório **antes de você torná-lo público**: procura segredos, dados pessoais, material de terceiros e rastros no **histórico do git**. Só lê, nunca altera nada, não tem dependências (só Python e git) e **nunca imprime o valor sensível que achou**.

> *EN: a zero-dependency CLI that audits a git repository before you make it public: secrets, personal data (with Brazilian formats such as CPF), third-party material you can't redistribute, and traces left in git history. Read-only, and it never prints the sensitive value it finds. Messages are in Portuguese.*

## Por que existe

Esta ferramenta nasceu de erros que aconteceram **de verdade** ao preparar repositórios de estudo para publicação. Todos passariam despercebidos numa revisão rápida:

- uma lista de **nomes completos de colegas** num `integrantes.txt`, ao lado de um **`Login: admin` / `Senha: admin123`**;
- um dump SQL com o **e-mail e o hash de senha de uma conta real**;
- uma pasta de arte que veio de um **pacote pago cujo arquivo de créditos diz que não pode ser redistribuído**;
- **fotos de colegas** numa pasta `avatars/`;
- scripts com `C:\Users\meu-usuario\Desktop\...` (expõe o nome de usuário e só funciona na máquina de quem escreveu);
- `seu-dominio-aqui.com` esquecido no `sitemap.xml`, e `SEU_LINK` esquecido no README;
- e o pior: depois de **corrigir** os arquivos, os nomes e o hash **continuavam no histórico do git**. Apagar não adianta: quem abrir um commit antigo vê tudo.

## Instalação

Requer Python 3.9 ou superior e o `git` no PATH. Não instala nenhuma dependência.

```bash
pip install git+https://github.com/Rimuro-Sama/Pre-Publish-Check-PPC
# ou, sem instalar nada, dentro de uma cópia do repositório:
python -m prepublishcheck --help        # a partir da pasta src/
```

## Uso

```bash
ppc                      # analisa a pasta atual
ppc ~/projetos/meu-app   # analisa outra pasta
ppc . --history          # também varre TODOS os commits (recomendado antes de publicar)
ppc . --staged           # só o que está no stage do git (para um hook de pre-commit)
ppc . --format json      # saída para scripts e CI
```

| Opção | O que faz |
|---|---|
| `--history` | Varre o histórico do git. É o que pega o que você "já apagou". |
| `--staged` | Analisa só o conteúdo do stage (o que iria no próximo commit). |
| `--format text\|json` | Formato da saída (padrão: `text`). |
| `--fail-on NIVEL` | Falha (código 1) com achados deste nível ou acima: `high`, `medium` (padrão), `low`, `info` ou `never`. |
| `--allow-email X` | Permite um e-mail ou um domínio (`@dominio.com`). Pode repetir. |
| `--disable REGRA` | Desativa uma regra. Pode repetir. |
| `--max-file-mb N` | Não lê o conteúdo de arquivos maiores que N MB (padrão: 2). |
| `--max-commits N` | Limite de commits do `--history` (padrão: 5000). |
| `--no-git` | Percorre a pasta em vez de usar a lista de arquivos do git. |
| `--list-rules` | Lista todas as regras. |

**Códigos de saída:** `0` nada acima do limite · `1` há achados no nível do limite ou acima · `2` erro de uso ou de execução.

### Exemplo de saída

Uma execução real sobre uma pasta de teste com problemas plantados (os valores são fictícios):

```text
Pre-Publish Check — /caminho/do/projeto
8 arquivo(s) de texto analisado(s), 0 pulado(s)

ALTO (4)
  [arquivo-env] .env
  [licenca-restricao] CREDITS.txt:1
      “…must not be redistributed…”
  [pii-cpf] dados.txt:1
      ***.***.***-35
  [segredo-aws] app.py:1
      AKIA[oculto, 20 car.]

MÉDIO (7)
  [pii-email] dados.txt:1
      a***@provedor-qualquer.com.br
  [pii-lista-de-pessoas] integrantes.txt
      2 linha(s) com nome completo
  [segredo-atribuicao] integrantes.txt:7
      Senha: [oculto, 8 car.]
  ...
Resumo: 4 alto, 7 médio, 3 baixo, 1 info. NÃO publique antes de resolver.
```

Depois dos achados, o relatório traz, **uma vez por regra**, *por que* aquilo importa e *como corrigir*.

## O que ele procura

Cada achado aponta para uma regra com nível de gravidade. `ppc --list-rules` mostra a lista completa.

**Segredos**

| Regra | Nível | O que detecta |
|---|---|---|
| `segredo-chave-privada` | Alto | Chave privada |
| `segredo-aws` | Alto | Chave de acesso da AWS |
| `segredo-github` | Alto | Token do GitHub |
| `segredo-google` | Alto | Chave de API do Google |
| `segredo-slack` | Alto | Token do Slack |
| `segredo-stripe` | Alto | Chave secreta do Stripe |
| `segredo-ia` | Alto | Chave de API de provedor de IA |
| `segredo-url-credenciais` | Alto | Credenciais dentro de uma URL |
| `segredo-atribuicao` | Médio | Senha ou segredo escrito no arquivo |
| `segredo-valor-forte` | Alto | Valor com cara de segredo real |
| `segredo-hash-senha` | Médio | Hash de senha (bcrypt) |

**Dados pessoais**

| Regra | Nível | O que detecta |
|---|---|---|
| `pii-cpf` | Alto | CPF |
| `pii-cnpj` | Baixo | CNPJ |
| `pii-email` | Médio | Endereço de e-mail |
| `pii-telefone` | Médio | Número de telefone |
| `pii-nome-completo` | Médio | Nome completo de pessoa |
| `pii-lista-de-pessoas` | Médio | Lista de pessoas |
| `pii-foto-pessoas` | Médio | Possíveis fotos de pessoas |

**Arquivos**

| Regra | Nível | O que detecta |
|---|---|---|
| `arquivo-env` | Alto | Arquivo de variáveis de ambiente (.env) |
| `arquivo-chave-privada` | Alto | Arquivo de chave ou certificado |
| `arquivo-credenciais` | Alto | Arquivo de credenciais |
| `arquivo-banco` | Médio | Arquivo de banco de dados |
| `arquivo-documento` | Baixo | Documento (PDF, Word, Excel, PowerPoint) |
| `arquivo-binario` | Baixo | Binário versionado (APK, EXE, JAR, ZIP...) |
| `arquivo-pesado` | Baixo | Arquivo muito grande |
| `arquivo-ferramenta` | Baixo | Arquivo de ferramenta ou de sistema |
| `arquivo-log` | Baixo | Arquivo de log |

**Conteúdo**

| Regra | Nível | O que detecta |
|---|---|---|
| `caminho-local` | Baixo | Caminho do seu computador |
| `licenca-restricao` | Alto | Material com restrição de redistribuição |
| `placeholder-esquecido` | Baixo | Marcador de exemplo esquecido |

**Repositório**

| Regra | Nível | O que detecta |
|---|---|---|
| `repo-sem-readme` | Baixo | Repositório sem README |
| `repo-sem-licenca` | Info | Repositório sem licença |

**Histórico do git**

| Regra | Nível | O que detecta |
|---|---|---|
| `historico-arquivo-sensivel` | Alto | Arquivo sensível que já esteve no histórico |
| `historico-segredo` | Alto | Segredo ou dado pessoal em commit antigo |
| `historico-email-autor` | Baixo | E-mail pessoal nos commits |

## Princípios de projeto

- **Nunca mostra o valor.** Segredos aparecem como `AKIA[oculto, 20 car.]`, CPF como `***.***.***-35`, e-mail como `a***@dominio.com`, nomes como iniciais. O relatório também **não mostra a linha inteira**, porque ela poderia ter outros dados que o detector não reconhece. Isso importa porque o log de um CI de repositório público é público: uma ferramenta que imprime o segredo que achou vaza o segredo.
- **Só olha o que seria publicado.** Em um repositório git usa a lista de arquivos do git: o que está no `.gitignore` (como um `.env` bem ignorado) não é acusado, porque não vai para o GitHub.
- **Só lê.** Não altera, não apaga, não faz `git add`. Desliga ganchos e configurações do git que poderiam executar comandos do repositório analisado, e **não segue links simbólicos** (poderiam apontar para fora do projeto).
- **Menos alarme falso.** CPF e CNPJ são validados pelos dígitos verificadores; chaves de exemplo da documentação, e-mails `@example.com`, marcadores como `troque-esta-senha` e referências como `${DB_PASSWORD}` são ignorados; `@users.noreply.github.com` e `git@github.com` também.
- **Zero dependências.** Só a biblioteca padrão do Python.

## Aceitando um achado de propósito: `.ppcignore`

Se um achado é intencional (um dado de teste fictício, o seu e-mail de contato), registre isso num arquivo `.ppcignore` na raiz:

```gitignore
docs/**                      # ignora estes caminhos por completo
*.pdf                        # sem barra: vale em qualquer pasta
tests/fixtures/**::pii-email # ignora só a regra pii-email nestes caminhos
email:fulano@meusite.example # permite este e-mail (ou @meusite.example para o domínio todo)
rule:arquivo-documento       # desativa a regra no projeto inteiro
```

E, dentro de um arquivo, `ppc:ignore` (ou `ppc:ignore=regra-a,regra-b`) na linha ignora aquela linha:

```python
EXEMPLO = "..."  # ppc:ignore=segredo-atribuicao
```

Este próprio repositório usa um [`.ppcignore`](.ppcignore): os testes contêm dados fictícios de propósito, e o código-fonte em `src/` é analisado normalmente.

## Usando como hook e no CI

**Antes de cada commit** (`.git/hooks/pre-commit`, com permissão de execução):

```bash
#!/bin/sh
ppc --staged --fail-on high || { echo "ppc: commit bloqueado (veja acima)."; exit 1; }
```

**No GitHub Actions**, para falhar se algo sensível entrar:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0          # histórico completo, senão o --history só vê o que foi baixado
- run: pip install git+https://github.com/Rimuro-Sama/Pre-Publish-Check-PPC
- run: ppc . --history
```

Este repositório roda o `ppc` sobre si mesmo no próprio CI.

## Como foi testado

**113 testes** (`python -m unittest discover -s tests`), sem dependências. O CI roda tudo em **8 combinações**: Python 3.9 a 3.13 em Linux, Python 3.9 e 3.13 em **Windows** e 3.13 em macOS, e depois a ferramenta se analisa a si mesma, histórico incluído.


| Arquivo | O que cobre |
|---|---|
| `test_texto.py` | Cada detector, com o que **deve** e o que **não deve** ser achado, e a garantia de que nenhum achado carrega o valor bruto |
| `test_integracao.py` | Repositórios git de verdade: `.gitignore`, histórico, modo `--staged`, links simbólicos, arquivos binários/UTF-16/enormes, agrupamento, `.ppcignore`, códigos de saída, JSON |
| `test_casos_reais.py` | Reproduções (com dados fictícios) dos erros da seção "Por que existe": se a ferramenta deixar de pegar um, é regressão grave |
| `test_catalogo.py` | O catálogo de regras é consistente com o código e com este README |

**O teste que mais importa** roda a ferramenta sobre um repositório cheio de valores sensíveis, em texto e JSON, com e sem `--history`, e confere que **nenhum valor bruto aparece na saída**.

Os segredos dos testes são **fictícios e montados em pedaços em tempo de execução**, para o código-fonte nunca conter um token inteiro (senão o próprio GitHub bloquearia o push).

### Verificado por mutação

Em vez de confiar em testes que nunca falharam, quebrei a ferramenta de propósito e conferi se a suíte reagia: vazar o valor bruto no relatório, aceitar qualquer CPF, seguir links simbólicos, ignorar o `.gitignore`, não achar a lista de pessoas no histórico, ler o disco no modo `--staged`, duplicar achados e remover a lista de domínios de exemplo. Das 8 mutações, **7 foram detectadas de primeira**. A oitava escapou, e investigá-la revelou um defeito real: essa lista continha provedores de e-mail verdadeiros (`mail.com`, `email.com`), que a ferramenta tratava como "exemplo" e deixava passar. Corrigido, com teste.

### Validado em repositórios reais

Rodei a ferramenta com `--history` sobre repositórios meus de estudo, onde eu já sabia o que existia. Ela achou o que devia: nomes completos que continuavam no histórico depois de corrigidos, o hash de senha de uma conta real num dump, a pasta de fotos de colegas, o arquivo de créditos que proibia redistribuição, e o e-mail pessoal nos commits. Nos projetos que já tinham sido limpos, não gerou alarme falso.

Esse uso real também achou **defeitos na própria ferramenta**, que foram corrigidos e viraram testes:

- a varredura do histórico **deixava passar a lista de nomes** que depois foi trocada por primeiros nomes (exatamente o caso que motivou o projeto);
- a lista de "domínios de exemplo" continha provedores **reais** (`mail.com`, `email.com`), escondendo e-mails de pessoas de verdade;
- `chave` sozinha, que em português também é "key" de dicionário ou de item, gerava alarme falso;
- `usuario:senha@servidor` numa URL era lido também como um e-mail;
- um dump com dezenas de e-mails gerava dezenas de achados idênticos (agora são agrupados).

## Limitações (leia antes de confiar)

- **É heurístico: tem falso positivo e falso negativo.** "Nada encontrado" **não** significa "seguro". Revise o repositório também à mão, principalmente antes de publicar algo com dados de terceiros.
- **Segredos sem formato conhecido** (uma senha inventada num campo qualquer) só são pegos pela regra de atribuição (`senha = "..."`), que depende do nome do campo.
- **Não olha dentro de imagens nem de documentos.** Não reconhece rostos em fotos, nem lê o texto de PDF, Word ou Excel; só avisa que existem (`pii-foto-pessoas`, `arquivo-documento`).
- **Nomes de pessoas são detectados só por padrões** (um campo `Nome: ...`, ou um arquivo cujo nome sugere uma lista de equipe). Um nome solto no meio de um texto não é achado.
- **Não troca nem apaga nada por você.** Se achar algo no histórico, a correção (repositório novo com histórico limpo, ou `git filter-repo` com push forçado) é decisão sua.
- **Repositórios muito grandes:** o `--history` lê o `git log -p` inteiro (limitado por `--max-commits`) e pode demorar.
- **Não substitui** ferramentas dedicadas de varredura de segredos (como gitleaks ou trufflehog), que têm bases de padrões muito maiores. A ideia aqui é complementar: foco em dados pessoais brasileiros, material de terceiros e no histórico de repositórios de estudo.
- **Nenhuma licença foi definida ainda.** Sem licença, o código é "todos os direitos reservados": pode ser visto, mas não reutilizado.

## Sobre o desenvolvimento

Projeto pessoal de estudo, feito por mim com apoio do Claude Code para código, testes e revisão. Os casos que motivaram as regras são reais; os testes e as validações descritos acima foram executados de verdade.
