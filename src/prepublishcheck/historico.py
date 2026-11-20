"""Varredura do histórico do git.

Por que isto importa: apagar um segredo (ou um nome, ou um dump) num commit novo NÃO o tira do repositório. Ele
continua em todos os commits antigos e qualquer pessoa pode abri-lo. É o erro mais comum ao publicar um projeto.
"""
from __future__ import annotations

import os
from typing import Dict, List, Set, Tuple

from . import gitutils
from .ignorar import Ignorar
from .mask import impressao, oculta_email
from .model import Achado
from .pathscan import nome_sensivel
from .textscan import (ARQUIVOS_IGNORADOS, LINHA_SO_NOME, Contexto, analisa_linha, eh_arquivo_de_pessoas, email_ignorado,
                       tipo_do_arquivo)

EXT_SEM_TEXTO = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".jar", ".apk", ".exe", ".woff", ".woff2", ".ttf"}


def analisa_historico(raiz: str, ctx: Contexto, ignorar: Ignorar, caminhos_atuais: Set[str],
                      achados_atuais: List[Achado], max_commits: int) -> List[Achado]:
    achados: List[Achado] = []

    # 1) arquivos sensíveis que já existiram e hoje não existem mais (os que existem hoje o escaneamento normal já pega)
    ja_vistos: Set[str] = set()
    for commit, rel in gitutils.caminhos_no_historico(raiz, max_commits):
        if rel in ja_vistos or rel in caminhos_atuais or ignorar.caminho_ignorado(rel):
            continue
        regra = nome_sensivel(rel)
        if regra:
            ja_vistos.add(rel)
            achados.append(Achado("historico-arquivo-sensivel", rel, detalhe=f"{regra}; visto no commit {commit}", commit=commit))

    # 2) segredos e dados pessoais em linhas adicionadas em commits antigos, que não estão mais (iguais) na árvore atual
    atuais: Set[Tuple[str, str, str]] = {(a.regra, a.caminho, a.impressao) for a in achados_atuais if a.impressao}
    primeiro_commit: Dict[Tuple[str, str, str], tuple] = {}
    nomes_antigos: Dict[str, Dict[str, str]] = {}       # arquivo de equipe -> {nome (impressão): commit que o introduziu}
    for commit, caminho, n, texto in gitutils.linhas_adicionadas(raiz, max_commits):
        base = os.path.basename(caminho)
        if (base in ARQUIVOS_IGNORADOS or caminho.endswith((".min.js", ".min.css", ".map"))
                or os.path.splitext(base)[1].lower() in EXT_SEM_TEXTO or ignorar.caminho_ignorado(caminho)):
            continue
        if eh_arquivo_de_pessoas(caminho) and LINHA_SO_NOME.match(texto) and not ignorar.regra_ignorada_em(caminho, "pii-lista-de-pessoas"):
            nomes_antigos.setdefault(caminho, {})[impressao(texto.strip())] = commit
        texto_livre, _ = tipo_do_arquivo(caminho)
        for c in analisa_linha(texto, caminho, ctx, texto_livre, restricao=False, historico=True):
            if ignorar.regra_ignorada_em(caminho, c.regra):
                continue
            chave = (c.regra, caminho, impressao(c.valor))
            if chave not in atuais:
                primeiro_commit[chave] = (commit, n, c)       # o laço vai do mais novo ao mais antigo: fica o que introduziu
    for (regra, caminho, imp), (commit, n, c) in primeiro_commit.items():
        achados.append(Achado("historico-segredo", caminho, n, f"[{regra}] {c.trecho}", commit=commit, impressao=imp))

    # nomes completos numa lista de equipe que já foi corrigida na árvore atual (se ainda está lá, o escaneamento normal já pega)
    ainda_listados = {a.caminho for a in achados_atuais if a.regra == "pii-lista-de-pessoas"}
    for caminho, nomes in nomes_antigos.items():
        if caminho not in ainda_listados:
            commit = list(nomes.values())[-1]            # o laço vai do mais novo ao mais antigo: o último é o mais antigo
            achados.append(Achado("historico-segredo", caminho, trecho=f"[pii-lista-de-pessoas] {len(nomes)} nome(s) completo(s)",
                                  commit=commit, impressao=impressao("|".join(sorted(nomes)))))

    # 3) e-mails pessoais nos commits
    pessoais = [e for e in gitutils.emails_de_autores(raiz, max_commits) if not email_ignorado(e, ctx)]
    if pessoais:
        lista = ", ".join(oculta_email(e) for e in pessoais[:5]) + (" …" if len(pessoais) > 5 else "")
        achados.append(Achado("historico-email-autor", ".", detalhe=f"{len(pessoais)} e-mail(s): {lista}"))
    return achados
