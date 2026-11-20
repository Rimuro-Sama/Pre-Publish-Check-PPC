"""Interface de linha de comando.

Códigos de saída: 0 = nada acima do limite; 1 = há achados no nível do limite ou acima; 2 = erro de uso ou de execução.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__, gitutils
from .relatorio import como_json, como_texto
from .rules import RANK, REGRAS, ROTULO, SEVERIDADES
from .scanner import escaneia
from .textscan import Contexto

NIVEIS = {"high": "alto", "alto": "alto", "medium": "medio", "medio": "medio", "médio": "medio", "low": "baixo",
          "baixo": "baixo", "info": "info"}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ppc",
        description="Pre-Publish Check: procura segredos, dados pessoais e material de terceiros antes de você tornar "
                    "um repositório público. Só lê; nunca altera nada.",
        epilog="Exemplos:  ppc .   |   ppc ~/projeto --history   |   ppc . --staged   |   ppc . --format json",
    )
    p.add_argument("caminho", nargs="?", default=".", help="pasta do repositório (padrão: a atual)")
    p.add_argument("--history", action="store_true", help="também varre o histórico do git (apagar um segredo não o tira dos commits antigos)")
    p.add_argument("--staged", action="store_true", help="analisa só o que está no stage do git (bom para um hook de pre-commit)")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="formato", help="formato da saída (padrão: text)")
    p.add_argument("--fail-on", default="medium", metavar="NIVEL",
                   help="falha (código 1) se houver achado deste nível ou acima: high, medium (padrão), low, info ou never")
    p.add_argument("--max-file-mb", type=float, default=2.0, help="não lê o conteúdo de arquivos maiores que isto (padrão: 2)")
    p.add_argument("--max-commits", type=int, default=5000, help="limite de commits no --history (padrão: 5000)")
    p.add_argument("--no-git", action="store_true", help="percorre a pasta em vez de usar a lista de arquivos do git")
    p.add_argument("--no-color", action="store_true", help="sem cores (também respeita a variável NO_COLOR)")
    p.add_argument("--allow-email", action="append", default=[], metavar="ENDERECO", help="permite um e-mail ou um domínio (@dominio.com); pode repetir")
    p.add_argument("--disable", action="append", default=[], metavar="REGRA", help="desativa uma regra; pode repetir")
    p.add_argument("--list-rules", action="store_true", help="lista todas as regras e sai")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _lista_regras() -> str:
    linhas = []
    for sev in reversed(SEVERIDADES):
        for r in REGRAS.values():
            if r.severidade == sev:
                linhas.append(f"{ROTULO[sev]:<6} {r.id:<28} {r.titulo}")
    return "\n".join(linhas)


def _saida_tolerante():
    """Terminais antigos (ex.: Windows com página de código 1252) não conseguem imprimir todo caractere: troca em vez de quebrar."""
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _saida_tolerante()
    parser = _parser()
    args, resto = parser.parse_known_args(argv)
    if resto:
        # Uma pasta cujo nome começa com "-" (ex.: "-Meu-Projeto") parece uma opção para o argparse. Se o argumento
        # que sobrou é uma pasta que existe, é ela que o usuário quis analisar.
        if len(resto) == 1 and os.path.isdir(resto[0]) and args.caminho == ".":
            args.caminho = resto[0]
        else:
            parser.error("argumentos não reconhecidos: " + " ".join(resto) + "  (para uma pasta que começa com '-', use ./pasta ou -- pasta)")
    if args.list_rules:
        print(_lista_regras())
        return 0

    falhar_em = args.fail_on.lower()
    if falhar_em not in NIVEIS and falhar_em != "never":
        print(f"erro: nível inválido para --fail-on: {args.fail_on!r} (use high, medium, low, info ou never)", file=sys.stderr)
        return 2
    desconhecidas = [r for r in args.disable if r not in REGRAS]
    if desconhecidas:
        print(f"erro: regra(s) desconhecida(s): {', '.join(desconhecidas)} (veja --list-rules)", file=sys.stderr)
        return 2

    ctx = Contexto(emails_permitidos={e.lower() for e in args.allow_email}, regras_desativadas=set(args.disable))
    try:
        res = escaneia(args.caminho, historico=args.history, staged=args.staged, max_bytes=int(args.max_file_mb * 1024 * 1024),
                       max_commits=args.max_commits, usar_git=not args.no_git, ctx=ctx)
    except (NotADirectoryError, FileNotFoundError):
        print(f"erro: pasta não encontrada: {args.caminho}", file=sys.stderr)
        return 2
    except gitutils.ErroGit as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2

    nivel = None if falhar_em == "never" else NIVEIS[falhar_em]
    falhou = nivel is not None and any(a.rank >= RANK[nivel] for a in res.achados)
    if args.formato == "json":
        print(como_json(res, falhar_em))
    else:
        cor = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        print(como_texto(res, cor, falhou))
    return 1 if falhou else 0


if __name__ == "__main__":
    sys.exit(main())
