"""Utilidades dos testes: repositórios temporários e valores falsos montados em pedaços.

Os "segredos" abaixo são FICTÍCIOS e são montados por concatenação em tempo de execução. Assim o código-fonte dos
testes nunca contém um token inteiro (os detectores do GitHub e esta própria ferramenta não o acusam no repositório).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ_PROJETO = Path(__file__).resolve().parent.parent
SRC = RAIZ_PROJETO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# ---- valores falsos (montados em pedaços) ----
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GITHUB = "gh" + "p_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GOOGLE = "AI" + "za" + ("aB3-_x9Z" * 5)[:35]
SLACK = "xo" + "xb-" + "123456789012-abcdefghijklmnop"
STRIPE = "sk_" + "live_" + "a1b2c3d4e5f6g7h8i9j0k1l2"
IA = "sk-" + "ant-" + ("ab12CD34ef56GH78" * 3)
CHAVE_PRIVADA = "-----BEGIN " + "RSA PRIVATE KEY-----"
BCRYPT = "$2y" + "$10$" + "N9qo8uLOickgx2ZMRZoMye" + "IjZAgcfl7p92ldGxad68LJZdL17lhWy"
CPF = "111.444.777-35"                  # dígitos verificadores válidos (número de teste, não é de ninguém conhecido)
CNPJ = "11.222.333/0001-81"
EMAIL = "aluno" + "@" + "provedor-qualquer.com.br"
TELEFONE = "(11) 98765-4321"
SENHA_FRACA = "admin" + "123"
NOMES = ["Maria Souza Lima", "Joao Pedro Alves"]


def valores_sensiveis():
    """Tudo o que NUNCA pode aparecer na saída da ferramenta."""
    return [AWS, GITHUB, GOOGLE, SLACK, STRIPE, IA, BCRYPT, CPF, CNPJ, EMAIL, TELEFONE, SENHA_FRACA,
            "Maria Souza Lima", "Joao Pedro Alves", "zx81hd7QpL2m"]


def _ambiente_git(home):
    e = dict(os.environ)
    e.update({
        "HOME": home, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Teste", "GIT_AUTHOR_EMAIL": "teste@example.com",
        "GIT_COMMITTER_NAME": "Teste", "GIT_COMMITTER_EMAIL": "teste@example.com",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return e


class BaseTemp(unittest.TestCase):
    """Cria uma pasta temporária por teste, com atalhos para montar repositórios."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ppc-teste-")
        self.addCleanup(shutil.rmtree, self._tmp, True)
        self.raiz = Path(self._tmp) / "repo"
        self.raiz.mkdir()

    # --- arquivos ---
    def escreve(self, rel, conteudo="", binario=False):
        p = self.raiz / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(conteudo, bytes):
            p.write_bytes(conteudo)
        else:
            p.write_text(conteudo, encoding="utf-8")
        return p

    def remove(self, rel):
        (self.raiz / rel).unlink()

    # --- git ---
    def git(self, *args, cwd=None, env_extra=None):
        env = _ambiente_git(self._tmp)
        env.update(env_extra or {})
        r = subprocess.run(["git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", *args],
                           cwd=str(cwd or self.raiz), capture_output=True, text=True, env=env)
        if r.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} falhou: {r.stderr}")
        return r.stdout

    def init(self):
        self.git("init", "-q")

    def commit(self, mensagem="c", autor_email=None):
        self.git("add", "-A")
        extra = {"GIT_AUTHOR_EMAIL": autor_email, "GIT_COMMITTER_EMAIL": autor_email} if autor_email else None
        self.git("commit", "-q", "-m", mensagem, "--allow-empty", env_extra=extra)

    # --- execução da ferramenta ---
    def escaneia(self, **kw):
        from prepublishcheck.scanner import escaneia
        return escaneia(str(self.raiz), **kw)

    def regras(self, res):
        return {a.regra for a in res.achados}

    def cli(self, *args, cwd=None):
        """Roda a ferramenta como um processo (como o usuário faria). Devolve (código, stdout, stderr)."""
        env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
        env.pop("NO_COLOR", None)
        r = subprocess.run([sys.executable, "-m", "prepublishcheck", *args], cwd=str(cwd or self.raiz), capture_output=True,
                           text=True, encoding="utf-8", env=env)
        return r.returncode, r.stdout, r.stderr
