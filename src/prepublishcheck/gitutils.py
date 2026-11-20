"""Chamadas ao git. Só leitura; nunca altera o repositório analisado."""
from __future__ import annotations

import os
import subprocess
from typing import Iterator, List, Optional

# Configuração do próprio repositório analisado pode executar comandos (ex.: core.fsmonitor, core.pager).
# Como a ferramenta é feita para olhar repositórios de qualquer origem, desligamos esses ganchos.
_SEGURO = ["-c", "core.fsmonitor=false", "-c", "core.quotepath=off", "-c", "core.pager=cat", "-c", "core.hooksPath=/dev/null"]


class ErroGit(Exception):
    pass


def _env():
    e = dict(os.environ)
    e["GIT_TERMINAL_PROMPT"] = "0"
    e["LC_ALL"] = "C"
    e.pop("GIT_DIR", None)
    e.pop("GIT_WORK_TREE", None)
    return e


def _git(raiz: str, *args: str, entrada: Optional[bytes] = None) -> bytes:
    try:
        r = subprocess.run(["git", *_SEGURO, "-C", raiz, *args], capture_output=True, env=_env(), input=entrada, timeout=600)
    except FileNotFoundError as e:
        raise ErroGit("o programa 'git' não foi encontrado no PATH") from e
    except subprocess.TimeoutExpired as e:
        raise ErroGit("o git demorou demais para responder") from e
    if r.returncode != 0:
        raise ErroGit(r.stderr.decode("utf-8", "replace").strip() or f"git saiu com código {r.returncode}")
    return r.stdout


def eh_repositorio(raiz: str) -> bool:
    try:
        return _git(raiz, "rev-parse", "--is-inside-work-tree").strip() == b"true"
    except ErroGit:
        return False


def eh_raso(raiz: str) -> bool:
    try:
        return _git(raiz, "rev-parse", "--is-shallow-repository").strip() == b"true"
    except ErroGit:
        return False


def arquivos_rastreados(raiz: str) -> List[str]:
    """O que seria publicado: arquivos versionados + novos que o .gitignore não exclui (relativos a `raiz`)."""
    saida = _git(raiz, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    caminhos = [p.decode("utf-8", "replace") for p in saida.split(b"\0") if p]
    return sorted(set(caminhos))


def arquivos_staged(raiz: str) -> List[str]:
    saida = _git(raiz, "diff", "--cached", "--relative", "--name-only", "-z", "--diff-filter=ACMR")
    return [p.decode("utf-8", "replace") for p in saida.split(b"\0") if p]


def conteudo_staged(raiz: str, rel: str) -> bytes:
    return _git(raiz, "show", ":./" + rel)


def contar_commits(raiz: str) -> int:
    try:
        return int(_git(raiz, "rev-list", "--all", "--count").strip() or 0)
    except (ErroGit, ValueError):
        return 0


def caminhos_no_historico(raiz: str, max_commits: int) -> Iterator[tuple]:
    """(hash curto, caminho) de cada arquivo que já existiu em algum commit, do mais novo ao mais antigo."""
    saida = _git(raiz, "log", "--all", f"-n{max_commits}", "--name-only", "--no-renames", "--format=@@@%h")
    atual = ""
    for bruta in saida.decode("utf-8", "replace").splitlines():
        if bruta.startswith("@@@"):
            atual = bruta[3:]
        elif bruta:
            yield atual, bruta


def emails_de_autores(raiz: str, max_commits: int) -> List[str]:
    saida = _git(raiz, "log", "--all", f"-n{max_commits}", "--format=%ae%n%ce")
    return sorted({l.strip().lower() for l in saida.decode("utf-8", "replace").splitlines() if l.strip()})


def linhas_adicionadas(raiz: str, max_commits: int) -> Iterator[tuple]:
    """(hash curto, caminho, número da linha, texto) de cada linha ADICIONADA em algum commit, do mais novo ao mais antigo."""
    saida = _git(raiz, "log", "--all", f"-n{max_commits}", "-p", "-U0", "--no-color", "--no-ext-diff", "--no-renames",
                 "--format=@@@%h")
    commit = ""
    caminho: Optional[str] = None
    n = 0
    for bruta in saida.decode("utf-8", "replace").split("\n"):
        if bruta.startswith("@@@"):
            commit, caminho = bruta[3:], None
        elif bruta.startswith("+++ "):
            alvo = bruta[4:].strip()
            caminho = None if alvo == "/dev/null" else (alvo[2:] if alvo.startswith("b/") else alvo)
        elif bruta.startswith("@@ "):
            try:
                n = int(bruta.split("+")[1].split(" ")[0].split(",")[0])
            except (IndexError, ValueError):
                n = 0
        elif bruta.startswith("+") and caminho is not None:
            yield commit, caminho, n, bruta[1:].rstrip("\r")
            n += 1
