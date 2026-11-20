"""Detectores que olham só o NOME e o TAMANHO dos arquivos (sem abrir o conteúdo)."""
from __future__ import annotations

import os
import re
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Tuple

from .model import Achado

LIMITE_PESADO = 5 * 1024 * 1024

EXT_CHAVE = {".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"}
NOMES_CHAVE = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "key.properties", "keystore.properties"}
NOMES_CREDENCIAIS = {"credentials.json", "secrets.json", "secrets.yml", "secrets.yaml", ".npmrc", ".pypirc", ".netrc",
                     ".git-credentials", ".htpasswd", "wp-config.php"}
PADRAO_CREDENCIAIS = re.compile(r"(?i)^(client_secret.*\.json|service[-_]?account.*\.json|terraform\.tfstate.*|.*\.tfvars)$")
EXT_BANCO = {".sqlite", ".sqlite3", ".db", ".mdb", ".accdb", ".dump"}
EXT_DOCUMENTO = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp"}
EXT_BINARIO = {".apk", ".aab", ".ipa", ".exe", ".msi", ".dll", ".so", ".dylib", ".jar", ".war", ".zip", ".7z", ".rar",
               ".tar", ".gz", ".tgz", ".iso", ".dmg", ".bin"}
EXT_IMAGEM = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".bmp"}
PASTAS_FERRAMENTA = {".claude", ".idea", ".vscode", ".vs", "__pycache__", "node_modules"}
ARQUIVOS_FERRAMENTA = {".ds_store", "thumbs.db", "desktop.ini", ".project", ".classpath"}
EXT_FERRAMENTA = {".lnk", ".swp", ".swo"}
PASTAS_FOTO = re.compile(r"(?i)^(avatars?|fotos?|photos?|pessoas?|integrantes?|equipe|team|alunos|membros|members|portraits?)$")
SUFIXOS_EXEMPLO = (".example", ".sample", ".template", ".dist", ".defaults", ".exemplo")


def _env(base: str) -> bool:
    b = base.lower()
    if b.endswith(SUFIXOS_EXEMPLO):
        return False
    return b == ".env" or b.startswith(".env.") or b.endswith(".env")


def nome_sensivel(rel: str) -> Optional[str]:
    """Regra (de severidade alta/média) que o NOME do arquivo dispara, ou None. Usada também no histórico."""
    base = os.path.basename(rel)
    ext = os.path.splitext(base)[1].lower()
    if _env(base):
        return "arquivo-env"
    if ext in EXT_CHAVE or base in NOMES_CHAVE:
        return "arquivo-chave-privada"
    if base.lower() in NOMES_CREDENCIAIS or PADRAO_CREDENCIAIS.match(base):
        return "arquivo-credenciais"
    if ext in EXT_BANCO and base.lower() != "thumbs.db":
        return "arquivo-banco"
    return None


def analisa_caminhos(entradas: Iterable[Tuple[str, Optional[int]]], limite_pesado: int = LIMITE_PESADO) -> List[Achado]:
    """entradas: (caminho relativo com '/', tamanho em bytes ou None). Agrupa o que se repete (pastas inteiras)."""
    achados: List[Achado] = []
    ferramentas: "OrderedDict[str, int]" = OrderedDict()
    fotos: Dict[str, int] = {}
    for rel, tamanho in entradas:
        partes = rel.split("/")
        base = partes[-1]
        ext = os.path.splitext(base)[1].lower()

        regra = nome_sensivel(rel)
        if regra:
            achados.append(Achado(regra, rel))
        if ext in EXT_DOCUMENTO:
            achados.append(Achado("arquivo-documento", rel))
        binario = ext in EXT_BINARIO
        if binario:
            achados.append(Achado("arquivo-binario", rel))
        if ext == ".log":
            achados.append(Achado("arquivo-log", rel))
        if tamanho is not None and tamanho > limite_pesado and not binario:
            achados.append(Achado("arquivo-pesado", rel, detalhe=f"{tamanho / 1024 / 1024:.1f} MB"))

        # ferramentas/IDE: uma pasta inteira vira UM achado
        pasta = next((i for i, p in enumerate(partes[:-1]) if p in PASTAS_FERRAMENTA), None)
        if pasta is not None:
            chave = "/".join(partes[: pasta + 1])
            ferramentas[chave] = ferramentas.get(chave, 0) + 1
        elif base.lower() in ARQUIVOS_FERRAMENTA or ext in EXT_FERRAMENTA or base.endswith("~"):
            achados.append(Achado("arquivo-ferramenta", rel))

        # fotos de pessoas: uma pasta com imagens vira UM achado
        if ext in EXT_IMAGEM and any(PASTAS_FOTO.match(p) for p in partes[:-1]):
            pasta_pai = "/".join(partes[:-1])
            fotos[pasta_pai] = fotos.get(pasta_pai, 0) + 1

    for pasta, n in ferramentas.items():
        achados.append(Achado("arquivo-ferramenta", pasta, detalhe=f"{n} arquivo(s)"))
    for pasta, n in sorted(fotos.items()):
        achados.append(Achado("pii-foto-pessoas", pasta, detalhe=f"{n} imagem(ns)"))
    return achados


def verifica_repositorio(nomes_na_raiz: Iterable[str]) -> List[Achado]:
    """README e licença na raiz."""
    baixos = [n.lower() for n in nomes_na_raiz]
    achados = []
    if not any(n.startswith("readme") for n in baixos):
        achados.append(Achado("repo-sem-readme", "."))
    if not any(n.startswith(("license", "licence", "copying", "unlicense")) for n in baixos):
        achados.append(Achado("repo-sem-licenca", "."))
    return achados
