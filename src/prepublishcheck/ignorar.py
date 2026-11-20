"""Leitura do .ppcignore: o que o usuário decidiu aceitar de propósito.

Formato (uma entrada por linha, '#' começa comentário):

    docs/**                    # ignora estes caminhos por completo
    *.pdf                      # sem barra: vale para qualquer pasta
    fixtures/**::pii-email     # ignora só a regra pii-email nestes caminhos
    email:fulano@meusite.example   # permite este e-mail (ou "email:@meusite.example" para o domínio todo)
    rule:arquivo-documento     # desativa a regra no projeto inteiro

Dentro de um arquivo, 'ppc:ignore' (ou 'ppc:ignore=regra-a,regra-b') na linha ignora aquela linha.
"""
from __future__ import annotations

import os
import re
from typing import List, Tuple

from .textscan import Contexto

NOME_ARQUIVO = ".ppcignore"


def _glob_para_regex(padrao: str):
    ancorado = "/" in padrao.rstrip("/")
    padrao = padrao.strip("/")
    saida = []
    i = 0
    while i < len(padrao):
        c = padrao[i]
        if c == "*":
            if padrao[i:i + 2] == "**":
                i += 2
                if padrao[i:i + 1] == "/":
                    i += 1
                    saida.append("(?:.*/)?")
                else:
                    saida.append(".*")
                continue
            saida.append("[^/]*")
        elif c == "?":
            saida.append("[^/]")
        else:
            saida.append(re.escape(c))
        i += 1
    corpo = "".join(saida)
    prefixo = "" if ancorado else "(?:.*/)?"
    sufixo = "(?:/.*)?"          # um caminho ignorado vale também para tudo o que está dentro dele
    return re.compile("^" + prefixo + corpo + sufixo + "$")


class Ignorar:
    def __init__(self, raiz: str, extras: Contexto = None):
        self.ctx = extras or Contexto()
        self.caminhos: List = []
        self.por_regra: List[Tuple] = []
        self.avisos: List[str] = []
        arq = os.path.join(raiz, NOME_ARQUIVO)
        if os.path.isfile(arq):
            self._le(arq)

    def _le(self, arq: str):
        with open(arq, encoding="utf-8", errors="replace") as f:
            for n, bruta in enumerate(f, 1):
                linha = bruta.split(" #")[0].strip() if not bruta.lstrip().startswith("#") else ""
                if not linha:
                    continue
                if linha.startswith("email:"):
                    self.ctx.emails_permitidos.add(linha[6:].strip().lower())
                elif linha.startswith("rule:"):
                    self.ctx.regras_desativadas.add(linha[5:].strip())
                elif "::" in linha:
                    glob, _, regra = linha.partition("::")
                    self.por_regra.append((_glob_para_regex(glob.strip()), regra.strip()))
                else:
                    self.caminhos.append(_glob_para_regex(linha))

    def caminho_ignorado(self, rel: str) -> bool:
        return any(rx.match(rel) for rx in self.caminhos)

    def regra_ignorada_em(self, rel: str, regra: str) -> bool:
        if regra in self.ctx.regras_desativadas:
            return True
        return any(r == regra and rx.match(rel) for rx, r in self.por_regra)
