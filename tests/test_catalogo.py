"""Consistência do catálogo de regras com o código e com a documentação."""
import re
import unittest
from pathlib import Path

from helpers import RAIZ_PROJETO
from prepublishcheck.rules import RANK, REGRAS, SEVERIDADES

SRC = RAIZ_PROJETO / "src" / "prepublishcheck"
PADRAO_ID = re.compile(r"""["']((?:segredo|pii|arquivo|caminho|licenca|placeholder|repo|historico)-[a-z\-]+)["']""")


class Catalogo(unittest.TestCase):
    def test_toda_regra_tem_texto_completo_e_severidade_valida(self):
        for r in REGRAS.values():
            with self.subTest(r.id):
                self.assertIn(r.severidade, SEVERIDADES)
                self.assertGreaterEqual(len(r.titulo), 3)
                self.assertGreater(len(r.por_que), 20, "explique POR QUE importa")
                self.assertGreater(len(r.correcao), 20, "explique COMO corrigir")

    def test_todo_id_usado_no_codigo_existe_no_catalogo(self):
        usados = set()
        for arq in SRC.glob("*.py"):
            if arq.name == "rules.py":
                continue
            usados |= set(PADRAO_ID.findall(arq.read_text(encoding="utf-8")))
        faltando = {u for u in usados if u not in REGRAS}
        self.assertEqual(set(), faltando, "ids usados no código mas ausentes de rules.py")

    def test_toda_regra_do_catalogo_e_usada_em_algum_lugar(self):
        codigo = "\n".join(a.read_text(encoding="utf-8") for a in SRC.glob("*.py") if a.name != "rules.py")
        for rid in REGRAS:
            with self.subTest(rid):
                self.assertIn(f'"{rid}"', codigo, "regra no catálogo que nenhum detector produz")

    def test_ids_sao_unicos_e_bem_formados(self):
        for rid in REGRAS:
            self.assertRegex(rid, r"^[a-z]+(-[a-z]+)+$")

    def test_ordem_das_severidades(self):
        self.assertLess(RANK["info"], RANK["baixo"])
        self.assertLess(RANK["baixo"], RANK["medio"])
        self.assertLess(RANK["medio"], RANK["alto"])

    def test_toda_regra_esta_documentada_no_readme(self):
        readme = Path(RAIZ_PROJETO / "README.md")
        if not readme.exists():
            self.skipTest("README ainda não existe")
        texto = readme.read_text(encoding="utf-8")
        for rid in REGRAS:
            with self.subTest(rid):
                self.assertIn(rid, texto, "documente a regra no README")


if __name__ == "__main__":
    unittest.main()
