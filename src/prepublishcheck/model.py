from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .rules import RANK, regra


@dataclass(frozen=True)
class Achado:
    """Um problema encontrado. NUNCA guarda o valor sensível bruto: só um trecho já mascarado."""
    regra: str
    caminho: str                      # relativo à raiz, com "/" como separador
    linha: Optional[int] = None
    trecho: Optional[str] = None      # trecho da linha com os valores sensíveis ocultados
    detalhe: Optional[str] = None     # ex.: "3 linhas", "12 imagens"
    commit: Optional[str] = None      # hash curto, nos achados do histórico
    # usado só para não repetir o mesmo achado (hash do valor); fora do relatório e do repr
    impressao: Optional[str] = field(default=None, repr=False, compare=False)

    @property
    def severidade(self) -> str:
        return regra(self.regra).severidade

    @property
    def rank(self) -> int:
        return RANK[self.severidade]

    def chave(self):
        return (self.regra, self.caminho, self.linha, self.commit, self.impressao)

    def como_dict(self):
        d = {
            "regra": self.regra,
            "severidade": self.severidade,
            "caminho": self.caminho,
            "linha": self.linha,
            "trecho": self.trecho,
            "detalhe": self.detalhe,
            "commit": self.commit,
        }
        return {k: v for k, v in d.items() if v is not None}
