"""Saída do relatório (texto para pessoas, JSON para máquinas). Nunca imprime valores sensíveis brutos."""
from __future__ import annotations

import json
from collections import Counter, OrderedDict
from typing import List

from .rules import ROTULO, SEVERIDADES, regra
from .scanner import Resultado

_COR = {"alto": "31;1", "medio": "33;1", "baixo": "36", "info": "2"}


def _c(texto: str, codigo: str, cor: bool) -> str:
    return f"\033[{codigo}m{texto}\033[0m" if cor else texto


def resumo(res: Resultado) -> Counter:
    return Counter(a.severidade for a in res.achados)


def como_json(res: Resultado, falhar_em: str) -> str:
    cont = resumo(res)
    corpo = {
        "versao": 1,
        "raiz": res.raiz,
        "arquivos_analisados": res.analisados,
        "arquivos_pulados": res.pulados,
        "commits_no_historico": res.commits,
        "resumo": {s: cont.get(s, 0) for s in reversed(SEVERIDADES)},
        "limite_para_falhar": falhar_em,
        "avisos": res.avisos,
        "achados": [a.como_dict() for a in res.achados],
    }
    return json.dumps(corpo, ensure_ascii=False, indent=2)


def como_texto(res: Resultado, cor: bool, falhou: bool) -> str:
    linhas: List[str] = []
    cont = resumo(res)
    historico = f" · {res.commits} commit(s) no histórico" if res.commits is not None else ""
    linhas.append(_c("Pre-Publish Check", "1", cor) + f" — {res.raiz}")
    linhas.append(f"{res.analisados} arquivo(s) de texto analisado(s), {res.pulados} pulado(s){historico}")
    for aviso in res.avisos:
        linhas.append(_c("aviso: ", "33", cor) + aviso)
    linhas.append("")

    if not res.achados:
        linhas.append(_c("Nada encontrado.", "32;1", cor) + " Isto não garante que o repositório está seguro: revise também à mão.")
        return "\n".join(linhas)

    for sev in reversed(SEVERIDADES):
        do_nivel = [a for a in res.achados if a.severidade == sev]
        if not do_nivel:
            continue
        linhas.append(_c(f"{ROTULO[sev]} ({len(do_nivel)})", _COR[sev], cor))
        for a in do_nivel:
            local = a.caminho + (f":{a.linha}" if a.linha else "")
            commit = f"  [commit {a.commit}]" if a.commit else ""
            linhas.append(f"  [{a.regra}] {local}{commit}")
            if a.trecho:
                linhas.append(f"      {a.trecho}")
            if a.detalhe:
                linhas.append(f"      {a.detalhe}")
        linhas.append("")

    # orientações: uma vez por regra, na ordem de gravidade
    linhas.append(_c("O que fazer", "1", cor))
    vistas: "OrderedDict[str, None]" = OrderedDict()
    for a in res.achados:
        vistas.setdefault(a.regra, None)
    for rid in vistas:
        r = regra(rid)
        linhas.append(f"  [{rid}] {r.titulo}")
        linhas.append(f"      Por quê: {r.por_que}")
        linhas.append(f"      Como corrigir: {r.correcao}")
    linhas.append("")

    partes = [f"{cont[s]} {ROTULO[s].lower()}" for s in reversed(SEVERIDADES) if cont.get(s)]
    veredito = "NÃO publique antes de resolver" if falhou else "Nenhum item acima do limite configurado"
    linhas.append(_c("Resumo: ", "1", cor) + ", ".join(partes) + f". {veredito}.")
    linhas.append("Para aceitar um item de propósito, use o arquivo .ppcignore (veja o README).")
    return "\n".join(linhas)
