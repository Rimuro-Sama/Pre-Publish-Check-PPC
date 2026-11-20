"""Detectores que olham o conteúdo de texto, linha a linha.

Regra de ouro: um detector nunca devolve o valor bruto, só o "trecho" já ocultado (ver mask.py). Também nunca
devolve a linha inteira, porque ela poderia conter outros dados sensíveis que o detector não reconhece.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Set

from .mask import impressao, oculta_email, oculta_final, oculta_nome, oculta_segredo
from .model import Achado

LIMITE_LINHA = 20000          # linhas maiores (ex.: JS minificado) são lidas só até aqui
EXT_TEXTO_LIVRE = {".txt", ".md", ".rst", ".env", ".properties", ".ini", ".cfg", ".conf", ".yml", ".yaml", ".toml", ".csv"}
EXT_DADOS = {".sql", ".csv", ".json", ".txt", ".xml", ".tsv", ".dump", ".yml", ".yaml"}
ARQUIVOS_IGNORADOS = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "composer.lock",
                      "Gemfile.lock", "go.sum", "uv.lock"}


@dataclass
class Contexto:
    """Configuração que os detectores consultam (vem do .ppcignore e da linha de comando)."""
    emails_permitidos: Set[str] = field(default_factory=set)      # endereços ou "@dominio"
    regras_desativadas: Set[str] = field(default_factory=set)

    def email_permitido(self, email: str) -> bool:
        e = email.lower()
        return e in self.emails_permitidos or "@" + e.partition("@")[2] in self.emails_permitidos


@dataclass
class Casamento:
    regra: str
    trecho: str
    valor: str          # só para deduplicar (vira "impressão"); nunca sai no relatório


# ------------------------------------------------------------------ marcadores e exemplos conhecidos

PALAVRAS_MARCADOR = (
    "troque", "trocar", "change", "example", "exemplo", "xxxx", "aqui", "your", "seu_", "seu-", "sua-", "dummy",
    "sample", "fake", "teste", "test", "placeholder", "redacted", "oculto", "todo", "${", "{{", "%(", "<", ">",
    "*****", "senha-de", "senha_de", "senha-local",
)
PALAVRAS_VAZIAS = {"password", "senha", "secret", "token", "required", "obrigatorio", "obrigatório", "none", "null",
                   "true", "false", "string", "vazio", "empty", "hidden", "changeit", "undefined", "nil", "n/a"}
EXEMPLOS_CONHECIDOS = ("EXAMPLE", "EXEMPLO")   # ex.: AKIAIOSFODNN7EXAMPLE, a chave de exemplo da documentação da AWS


def eh_marcador(valor: str) -> bool:
    """True se o valor é obviamente um exemplo/marcador e não uma credencial."""
    v = valor.strip().lower()
    if not v or v in PALAVRAS_VAZIAS or len(set(v)) <= 1:
        return True
    return any(p in v for p in PALAVRAS_MARCADOR)


def entropia(valor: str) -> float:
    """Entropia de Shannon em bits por caractere (valores aleatórios longos ficam acima de ~3,5)."""
    if not valor:
        return 0.0
    n = len(valor)
    return -sum((c / n) * math.log2(c / n) for c in (valor.count(x) for x in set(valor)))


# ------------------------------------------------------------------ 1. chaves e tokens com formato conhecido

TOKENS = [
    ("segredo-chave-privada", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----"), 0),
    ("segredo-aws", re.compile(r"\b(?:AKIA|ASIA)[A-Z2-7]{16}\b"), 4),
    ("segredo-github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"), 4),
    ("segredo-google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 4),
    ("segredo-slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"), 5),
    ("segredo-stripe", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}"), 8),
    ("segredo-ia", re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}"), 3),
]


def _tokens(linha: str) -> Iterator[Casamento]:
    for regra, rx, manter in TOKENS:
        for m in rx.finditer(linha):
            valor = m.group(0)
            if regra == "segredo-chave-privada":
                yield Casamento(regra, "-----BEGIN … PRIVATE KEY-----", valor)
            elif not any(x in valor for x in EXEMPLOS_CONHECIDOS):
                yield Casamento(regra, oculta_segredo(valor, manter), valor)


# ------------------------------------------------------------------ 2. URL com usuário e senha

URL_CRED = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]*://([^\s:/@\"'<>]+):([^\s@/\"'<>]+)@")


def _url_credenciais(linha: str) -> Iterator[Casamento]:
    for m in URL_CRED.finditer(linha):
        senha = m.group(2)
        if not eh_marcador(senha):
            yield Casamento("segredo-url-credenciais", f"://[usuário]:[oculto, {len(senha)} car.]@", senha)


# ------------------------------------------------------------------ 3. "senha = valor" e variações

# "chave" sozinha NÃO está aqui de propósito: em português também é "key" de dicionário ou de item (ex.: a chave de uma porta
# num jogo), e gerava alarme falso. Só as formas compostas contam.
_CHAVE = (r"(?:senha|password|passwd|pwd|secret|segredo|token|api[_\-]?key|apikey|access[_\-]?key|"
          r"chave[_\-]?(?:secreta|privada|api|de[_\-]?acesso)|credential)")
ATRIB_ENTRE_ASPAS = re.compile(
    r"""(?i)\b([\w.\-]*""" + _CHAVE + r"""[\w.\-]*)["']?\s*(?:[:=]|=>)\s*(["'])([^"'\r\n]{4,})\2""")
ATRIB_SEM_ASPAS = re.compile(
    r"""(?i)\b([\w.\-]*""" + _CHAVE + r"""[\w.\-]*)\s*[:=]\s*([^\s"'#]{4,})""")


def _valor_sem_aspas_plausivel(v: str) -> bool:
    v = v.rstrip(",;)")
    if len(v) < 4 or v[0] in "$/{[<(\\." or any(c in v for c in "()") or v.endswith("."):
        return False
    return any(c.isdigit() for c in v)        # "admin123" sim; "troque-esta-senha" ou "required" não


def _atribuicao(linha: str, texto_livre: bool) -> Iterator[Casamento]:
    vistos = set()
    for m in ATRIB_ENTRE_ASPAS.finditer(linha):
        chave, valor = m.group(1), m.group(3)
        if valor.lower() == chave.lower().split(".")[-1] or eh_marcador(valor) or valor.startswith("$"):
            continue
        vistos.add(m.start())
        yield _classifica(chave, valor, m.group(0)[len(chave):].lstrip("\"' ")[:1] or "=")
    if texto_livre:
        for m in ATRIB_SEM_ASPAS.finditer(linha):
            if m.start() in vistos:
                continue
            chave, valor = m.group(1), m.group(2).rstrip(",;")
            if _valor_sem_aspas_plausivel(valor) and not eh_marcador(valor):
                yield _classifica(chave, valor, ":")


def _classifica(chave: str, valor: str, operador: str) -> Casamento:
    forte = len(valor) >= 20 and entropia(valor) >= 3.5 and any(c.isdigit() for c in valor) and any(c.isalpha() for c in valor)
    regra = "segredo-valor-forte" if forte else "segredo-atribuicao"
    sep = ": " if operador == ":" else " = "
    return Casamento(regra, f"{chave}{sep}[oculto, {len(valor)} car.]", valor)


# ------------------------------------------------------------------ 4. hash bcrypt

BCRYPT = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")


def _hash_senha(linha: str) -> Iterator[Casamento]:
    for m in BCRYPT.finditer(linha):
        yield Casamento("segredo-hash-senha", "$2y$[hash bcrypt oculto]", m.group(0))


# ------------------------------------------------------------------ 5. dados pessoais

CPF_FORMATADO = re.compile(r"(?<!\d)\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)")
CPF_PURO = re.compile(r"(?<![\d.\-])\d{11}(?![\d.\-])")
CNPJ_FORMATADO = re.compile(r"(?<!\d)\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}(?!\d)")


def cpf_valido(txt: str) -> bool:
    d = [int(c) for c in txt if c.isdigit()]
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for n in (9, 10):
        soma = sum(d[i] * (n + 1 - i) for i in range(n))
        if d[n] != (soma * 10 % 11) % 10:
            return False
    return True


def cnpj_valido(txt: str) -> bool:
    d = [int(c) for c in txt if c.isdigit()]
    if len(d) != 14 or len(set(d)) == 1:
        return False
    for n, pesos in ((12, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]), (13, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])):
        soma = sum(d[i] * pesos[i] for i in range(n))
        resto = soma % 11
        if d[n] != (0 if resto < 2 else 11 - resto):
            return False
    return True


EMAIL = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
SUFIXOS_EXEMPLO = (".example", ".test", ".invalid", ".localhost", ".local", ".exemplo")
LOCAIS_GENERICOS = {"noreply", "no-reply", "donotreply", "do-not-reply", "git", "root", "postmaster", "webmaster"}


def email_ignorado(email: str, ctx: Contexto) -> bool:
    """E-mail de exemplo, genérico ou permitido pelo usuário: não conta como dado pessoal."""
    local, _, dominio = email.lower().partition("@")
    return (
        local in LOCAIS_GENERICOS
        or dominio.endswith(SUFIXOS_EXEMPLO)
        or dominio.startswith("example.")
        or dominio.endswith("users.noreply.github.com")
        or dominio.endswith(".png") or dominio.endswith(".jpg") or dominio.endswith(".svg")   # "icone@2x.png"
        or ctx.email_permitido(email)
    )


TELEFONE = re.compile(r"(?<![\d\-])(?:\+55[\s\-]?)?(?:\(\d{2}\)\s?|\d{2}\s)?9\d{4}[\-\s]\d{4}(?![\d\-])|(?<![\d\-])\(\d{2}\)\s?[2-5]\d{3}[\-\s]\d{4}(?![\d\-])")
_PARTE = r"[A-ZÀ-ÖØ-Ý][a-zà-öø-ÿ]+"
NOME_COMPLETO = _PARTE + r"(?:\s+(?:d[aeo]s?\s+|e\s+)?" + _PARTE + r"){2,}"
CAMPO_NOME = re.compile(r"(?i:\b(?:nome|name|integrante|aluno|aluna|colega|autor|author)\b)\s*[:=]\s*(" + NOME_COMPLETO + ")")


def _pessoais(linha: str, ctx: Contexto, texto_livre: bool) -> Iterator[Casamento]:
    for m in CPF_FORMATADO.finditer(linha):
        if cpf_valido(m.group(0)):
            yield Casamento("pii-cpf", oculta_final(m.group(0)), m.group(0))
    if "cpf" in linha.lower():
        for m in CPF_PURO.finditer(linha):
            if cpf_valido(m.group(0)):
                yield Casamento("pii-cpf", oculta_final(m.group(0)), m.group(0))
    for m in CNPJ_FORMATADO.finditer(linha):
        if cnpj_valido(m.group(0)):
            yield Casamento("pii-cnpj", oculta_final(m.group(0), 4), m.group(0))
    # "usuario:senha@servidor" numa URL é usuário e senha, não um e-mail (e já é tratado como credencial em _url_credenciais)
    em_url = [(m.start(2), m.end()) for m in URL_CRED.finditer(linha)]
    for m in EMAIL.finditer(linha):
        if any(ini <= m.start() < fim for ini, fim in em_url):
            continue
        if not email_ignorado(m.group(0), ctx):
            yield Casamento("pii-email", oculta_email(m.group(0)), m.group(0).lower())
    for m in TELEFONE.finditer(linha):
        yield Casamento("pii-telefone", oculta_final(m.group(0), 2), m.group(0))
    for m in CAMPO_NOME.finditer(linha):
        yield Casamento("pii-nome-completo", f"campo de nome: {oculta_nome(m.group(1))}", m.group(1))


# ------------------------------------------------------------------ 6. caminhos do computador do autor

CAMINHO_WIN = re.compile(r"\b[A-Za-z]:\\+Users\\+([^\\\s\"'<>|*?:/]+)")
CAMINHO_UNIX = re.compile(r"(?<![\w.\-])/(?:home|Users)/([A-Za-z_][\w.\-]*)/")
USUARIOS_GENERICOS = {"public", "default", "all users", "user", "usuario", "usuário", "runner", "ubuntu", "vscode", "node",
                      "app", "appuser", "circleci", "jenkins", "shared", "root", "username", "seu_usuario", "name", "me"}


def _usuario_real(nome: str) -> bool:
    """False para nomes genéricos e para marcadores de documentação como <seu-usuario>, [usuario], {user}, $USER, %USERNAME%."""
    return nome.lower() not in USUARIOS_GENERICOS and not re.match(r"[\[<{$%]", nome)


def _caminhos(linha: str) -> Iterator[Casamento]:
    for m in CAMINHO_WIN.finditer(linha):
        if _usuario_real(m.group(1)):
            yield Casamento("caminho-local", "C:\\Users\\[usuário]\\…", m.group(1))
    for m in CAMINHO_UNIX.finditer(linha):
        if _usuario_real(m.group(1)):
            yield Casamento("caminho-local", "/home/[usuário]/…", m.group(1))


# ------------------------------------------------------------------ 7. licença que proíbe redistribuir, marcadores esquecidos

RESTRICAO = [re.compile(p, re.I) for p in (
    r"\b(?:must|may|can|shall)\s+not\s+be\s+(?:re)?distributed",
    r"\bdo\s+not\s+(?:re)?distribute",
    r"\bno\s+(?:re)?distribution",
    r"\bnot\s+(?:be\s+)?redistribut",
    r"\bno\s+resale",
    r"\bpersonal\s+use\s+only",
    r"n[ãa]o\s+(?:pode|podem|deve|devem)\s+ser\s+redistribu",
    r"\bproibid[ao]\s+(?:a\s+)?redistribui",
    r"\buso\s+pessoal\s+apenas|\bsomente\s+para\s+uso\s+pessoal",
)]
NOME_ARQUIVO_LICENCA = re.compile(r"(?i)(credit|licen|notice|terms|termos|copyright|attribution|autoria|readme)")
MARCADOR_ESQUECIDO = re.compile(r"(?i)\bseu[-_]?dominio\b|\bSEU_(?:LINK|EMAIL|NOME|USUARIO)\b|\byour[-_]?domain\b|\bdominio\.exemplo\b")


def _restricao(linha: str) -> Iterator[Casamento]:
    for rx in RESTRICAO:
        m = rx.search(linha)
        if m:
            yield Casamento("licenca-restricao", f"“…{m.group(0)}…”", m.group(0).lower())
            return


def _marcadores(linha: str) -> Iterator[Casamento]:
    for m in MARCADOR_ESQUECIDO.finditer(linha):
        yield Casamento("placeholder-esquecido", m.group(0), m.group(0).lower())


# ------------------------------------------------------------------ orquestração por linha / arquivo

IGNORAR_LINHA = re.compile(r"ppc:ignore(?:=([\w\-,]+))?")


def _ignorada_na_linha(linha: str, regra: str) -> bool:
    m = IGNORAR_LINHA.search(linha)
    if not m:
        return False
    return m.group(1) is None or regra in m.group(1).split(",")


def analisa_linha(linha: str, caminho: str, ctx: Contexto, texto_livre: bool, restricao: bool, historico: bool = False
                  ) -> List[Casamento]:
    """Roda os detectores numa linha. No histórico só interessam segredos e dados pessoais."""
    if len(linha) > LIMITE_LINHA:
        linha = linha[:LIMITE_LINHA]
    saida: List[Casamento] = []
    saida.extend(_tokens(linha))
    saida.extend(_url_credenciais(linha))
    saida.extend(_atribuicao(linha, texto_livre))
    saida.extend(_hash_senha(linha))
    saida.extend(_pessoais(linha, ctx, texto_livre))
    if not historico:
        saida.extend(_caminhos(linha))
        if restricao:
            saida.extend(_restricao(linha))
        saida.extend(_marcadores(linha))
    # o mesmo valor já reconhecido por um detector específico (ex.: chave da AWS) não precisa de um achado genérico também
    conhecidos = {c.valor for c in saida if c.regra not in ("segredo-atribuicao", "segredo-valor-forte")}
    saida = [c for c in saida if not (c.regra in ("segredo-atribuicao", "segredo-valor-forte") and c.valor in conhecidos)]
    return [c for c in saida if c.regra not in ctx.regras_desativadas and not _ignorada_na_linha(linha, c.regra)]


def tipo_do_arquivo(caminho: str):
    """(texto_livre, tenta_restricao): texto livre aceita 'senha: valor' sem aspas; restrição só em textos."""
    base = os.path.basename(caminho)
    ext = os.path.splitext(base)[1].lower()
    texto_livre = ext in EXT_TEXTO_LIVRE or base.lower().startswith(".env")
    restricao = ext in {".txt", ".md", ".rst", ""} or bool(NOME_ARQUIVO_LICENCA.search(base))
    return texto_livre, restricao


def decodifica(dados: bytes) -> Optional[str]:
    """Texto do arquivo, ou None se for binário. Aceita UTF-8 (com ou sem BOM) e UTF-16 com BOM."""
    if dados.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return dados.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in dados[:8192]:
        return None
    return dados.decode("utf-8-sig", errors="replace")


# ------------------------------------------------------------------ lista de pessoas (nível de arquivo)

NOME_ARQUIVO_PESSOAS = re.compile(r"(?i)(equipe|integrantes?|membros?|alunos?|colegas|participantes|\bteam\b|members|students)")
LINHA_SO_NOME = re.compile(r"^\s*(?:[-*•]\s*|\d+[.)]\s*)?(" + NOME_COMPLETO + r")\s*$")


def eh_arquivo_de_pessoas(caminho: str) -> bool:
    """O nome do arquivo sugere uma lista de integrantes/alunos/colegas (ex.: equipe.txt, integrantes.md)."""
    base = os.path.basename(caminho)
    return bool(NOME_ARQUIVO_PESSOAS.search(base)) and os.path.splitext(base)[1].lower() in {".txt", ".csv", ".md", ".json", ""}


def lista_de_pessoas(caminho: str, linhas) -> Optional[Achado]:
    if not eh_arquivo_de_pessoas(caminho):
        return None
    nomes = [m.group(1) for m in (LINHA_SO_NOME.match(l) for l in linhas) if m]
    if not nomes:
        return None
    return Achado("pii-lista-de-pessoas", caminho, detalhe=f"{len(nomes)} linha(s) com nome completo",
                  impressao=impressao("|".join(nomes)))


def analisa_arquivo(caminho: str, texto: str, ctx: Contexto) -> List[Achado]:
    """Todos os achados de conteúdo de um arquivo de texto."""
    if os.path.basename(caminho) in ARQUIVOS_IGNORADOS or caminho.endswith((".min.js", ".min.css", ".map")):
        return []
    texto_livre, restricao = tipo_do_arquivo(caminho)
    linhas = texto.splitlines()
    achados: List[Achado] = []
    for n, linha in enumerate(linhas, 1):
        for c in analisa_linha(linha, caminho, ctx, texto_livre, restricao):
            achados.append(Achado(c.regra, caminho, n, c.trecho, impressao=impressao(c.valor)))
    lp = lista_de_pessoas(caminho, linhas)
    if lp and lp.regra not in ctx.regras_desativadas:
        achados.append(lp)
    return achados
