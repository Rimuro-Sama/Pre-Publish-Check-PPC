"""Orquestra o escaneamento: escolhe os arquivos, roda os detectores, aplica o .ppcignore e junta o resultado."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import gitutils
from .historico import analisa_historico
from .ignorar import Ignorar
from .model import Achado
from .pathscan import analisa_caminhos, verifica_repositorio
from .textscan import Contexto, analisa_arquivo, decodifica

PASTAS_PULADAS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
INSERT_SQL = re.compile(r"(?i)\binsert\s+into\b")


@dataclass
class Resultado:
    raiz: str
    achados: List[Achado] = field(default_factory=list)
    analisados: int = 0
    pulados: int = 0                      # ignorados pelo .ppcignore, links simbólicos, grandes demais...
    commits: Optional[int] = None
    avisos: List[str] = field(default_factory=list)


def _listar_arquivos(raiz: str, usar_git: bool, avisos: List[str]) -> List[str]:
    if usar_git and gitutils.eh_repositorio(raiz):
        try:
            return gitutils.arquivos_rastreados(raiz)
        except gitutils.ErroGit as e:
            avisos.append(f"Não consegui listar os arquivos pelo git ({e}); percorrendo a pasta.")
    saida = []
    for pasta, subpastas, nomes in os.walk(raiz, followlinks=False):
        subpastas[:] = [d for d in subpastas if d not in PASTAS_PULADAS]
        for n in nomes:
            saida.append(os.path.relpath(os.path.join(pasta, n), raiz).replace(os.sep, "/"))
    return sorted(saida)


def escaneia(raiz: str, *, historico: bool = False, staged: bool = False, max_bytes: int = 2 * 1024 * 1024,
             max_commits: int = 5000, usar_git: bool = True, ctx: Optional[Contexto] = None) -> Resultado:
    raiz = os.path.abspath(raiz)
    if not os.path.isdir(raiz):
        raise NotADirectoryError(raiz)
    res = Resultado(raiz)
    ignorar = Ignorar(raiz, ctx)
    ctx = ignorar.ctx

    if staged:
        if not gitutils.eh_repositorio(raiz):
            raise gitutils.ErroGit("--staged só funciona dentro de um repositório git")
        caminhos = gitutils.arquivos_staged(raiz)
    else:
        caminhos = _listar_arquivos(raiz, usar_git, res.avisos)

    entradas: List[Tuple[str, Optional[int]]] = []
    achados: List[Achado] = []
    for rel in caminhos:
        rel = rel.replace(os.sep, "/")
        if ignorar.caminho_ignorado(rel):
            res.pulados += 1
            continue
        completo = os.path.join(raiz, rel)
        if not staged and os.path.islink(completo):
            res.pulados += 1                    # não segue links simbólicos (poderiam apontar para fora do projeto)
            continue
        try:
            dados: Optional[bytes] = None
            if staged:
                dados = gitutils.conteudo_staged(raiz, rel)
                tamanho = len(dados)
            else:
                tamanho = os.path.getsize(completo)
                if not os.path.isfile(completo):
                    res.pulados += 1
                    continue
                if tamanho <= max_bytes:
                    with open(completo, "rb") as f:
                        dados = f.read()
        except (OSError, gitutils.ErroGit):
            res.pulados += 1
            continue

        entradas.append((rel, tamanho))
        if dados is None:                       # grande demais para ler o conteúdo
            res.pulados += 1
            continue
        texto = decodifica(dados)
        if texto is None:                       # binário
            continue
        res.analisados += 1
        achados.extend(analisa_arquivo(rel, texto, ctx))
        if rel.lower().endswith(".sql") and INSERT_SQL.search(texto):
            achados.append(Achado("arquivo-banco", rel, detalhe="dump SQL com INSERT (confira se há dados reais)"))

    achados.extend(analisa_caminhos(entradas))
    if not staged:
        achados.extend(verifica_repositorio(os.listdir(raiz)))

    if historico:
        if not gitutils.eh_repositorio(raiz):
            res.avisos.append("A pasta não é um repositório git: não há histórico para analisar.")
        else:
            res.commits = gitutils.contar_commits(raiz)
            if gitutils.eh_raso(raiz):
                res.avisos.append("O repositório é raso (clone com --depth): só o histórico baixado foi analisado.")
            try:
                achados.extend(analisa_historico(raiz, ctx, ignorar, {c.replace(os.sep, "/") for c in caminhos}, achados, max_commits))
            except gitutils.ErroGit as e:
                res.avisos.append(f"Não consegui ler o histórico: {e}")
            if res.commits and res.commits > max_commits:
                res.avisos.append(f"O histórico tem {res.commits} commits; só os {max_commits} mais recentes foram analisados.")

    # aplica o .ppcignore por regra, remove repetidos e ordena (mais grave primeiro)
    vistos: Dict[tuple, Achado] = {}
    for a in achados:
        if ignorar.regra_ignorada_em(a.caminho, a.regra):
            continue
        vistos.setdefault(a.chave(), a)
    res.achados = sorted(agrupa_repeticoes(list(vistos.values())), key=lambda a: (-a.rank, a.regra, a.caminho, a.linha or 0))
    return res


# Regras cujas ocorrências se repetem muito dentro de um arquivo (um dump com 200 e-mails, p. ex.).
REPETEM = {"pii-email", "pii-telefone", "pii-cpf", "pii-cnpj", "pii-nome-completo", "segredo-hash-senha", "caminho-local",
           "placeholder-esquecido", "historico-segredo"}
LIMITE_INDIVIDUAL = 3


def _tipo(a: Achado) -> str:
    """No histórico todos os achados são 'historico-segredo'; o tipo de verdade vem no prefixo do trecho: '[pii-email] ...'."""
    if a.regra == "historico-segredo" and a.trecho and a.trecho.startswith("["):
        return a.trecho[1:a.trecho.index("]")]
    return a.regra


def agrupa_repeticoes(achados: List[Achado]) -> List[Achado]:
    """Mais de 3 achados do mesmo TIPO no mesmo arquivo viram UM, com a contagem: o relatório continua legível."""
    grupos: Dict[tuple, List[Achado]] = {}
    for a in achados:
        if a.regra in REPETEM and a.linha is not None:
            grupos.setdefault((a.regra, _tipo(a), a.caminho, a.commit), []).append(a)
    agrupados = {k for k, v in grupos.items() if len(v) > LIMITE_INDIVIDUAL}
    saida = [a for a in achados if (a.regra, _tipo(a), a.caminho, a.commit) not in agrupados or a.linha is None]
    for chave in agrupados:
        itens = sorted(grupos[chave], key=lambda a: a.linha or 0)
        primeiro, ultimo = itens[0], itens[-1]
        linhas = sorted({a.linha for a in itens})
        saida.append(Achado(primeiro.regra, primeiro.caminho, primeiro.linha, primeiro.trecho,
                            detalhe=f"{len(itens)} ocorrências em {len(linhas)} linha(s) (de {linhas[0]} a {linhas[-1]}); só a primeira é mostrada",
                            commit=primeiro.commit, impressao=primeiro.impressao))
    return saida
