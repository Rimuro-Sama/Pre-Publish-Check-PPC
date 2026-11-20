"""Ocultação de valores sensíveis. Princípio central da ferramenta: o relatório NUNCA mostra o valor bruto.

Relatórios vão para a tela, para logs de CI (públicos, em repositório público) e para arquivos JSON. Se a
ferramenta imprimisse o segredo que achou, ela mesma vazaria o segredo.
"""
from __future__ import annotations

import hashlib


def impressao(valor: str) -> str:
    """Identificador estável do valor, só para deduplicar achados. Não é impresso."""
    return hashlib.sha256(valor.encode("utf-8", "replace")).hexdigest()[:16]


def oculta_segredo(valor: str, manter_inicio: int = 0) -> str:
    """'ghp_abc...' -> 'ghp_[oculto, 40 car.]'. Só o início "público" (prefixo do tipo) pode ser mantido."""
    ini = valor[:manter_inicio] if manter_inicio else ""
    return f"{ini}[oculto, {len(valor)} car.]"


def oculta_email(email: str) -> str:
    local, _, dominio = email.partition("@")
    return f"{local[:1]}***@{dominio}"


def oculta_final(valor: str, visiveis: int = 2) -> str:
    """Mantém só os últimos caracteres alfanuméricos: um CPF vira '***.***.***-NN'."""
    total = sum(c.isalnum() for c in valor)
    vistos = 0
    saida = []
    for c in valor:
        if c.isalnum():
            vistos += 1
            saida.append(c if vistos > total - visiveis else "*")
        else:
            saida.append(c)
    return "".join(saida)


def oculta_nome(nome: str) -> str:
    """'Maria da Silva Souza' -> 'M. S. S.' (iniciais das partes em maiúscula)."""
    partes = [p for p in nome.split() if p[:1].isupper()]
    return " ".join(p[0] + "." for p in partes) or "[nome]"
