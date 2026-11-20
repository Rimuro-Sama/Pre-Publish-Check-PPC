"""Testes com repositórios git de verdade em pastas temporárias."""
import json
import os
import unittest

from helpers import (AWS, BCRYPT, CPF, EMAIL, GITHUB, NOMES, SENHA_FRACA, TELEFONE, BaseTemp, valores_sensiveis)


class ArvoreDeTrabalho(BaseTemp):
    def test_so_o_que_seria_publicado_e_analisado(self):
        # .env está no .gitignore: não vai para o repositório, então NÃO deve ser acusado
        self.init()
        self.escreve(".gitignore", ".env\nsegredos-locais.txt\n")
        self.escreve(".env", f"TOKEN={GITHUB}\n")
        self.escreve("segredos-locais.txt", f"k={AWS}\n")
        self.escreve("README.md", "# x\n")
        self.commit()
        res = self.escaneia()
        self.assertNotIn("arquivo-env", self.regras(res))
        self.assertNotIn("segredo-github", self.regras(res))
        self.assertNotIn("segredo-aws", self.regras(res))

    def test_arquivo_versionado_com_segredo_e_acusado(self):
        self.init()
        self.escreve("app.py", f'k = "{AWS}"\n')
        self.escreve(".env", "X=1\n")
        self.commit()
        res = self.escaneia()
        self.assertEqual({"segredo-aws", "arquivo-env"} - self.regras(res), set())

    def test_arquivo_novo_ainda_nao_adicionado_conta_se_o_gitignore_nao_o_exclui(self):
        self.init()
        self.escreve("README.md", "x\n")
        self.commit()
        self.escreve("novo.py", f'k = "{AWS}"\n')        # não está no commit, mas iria no próximo "git add ."
        self.assertIn("segredo-aws", self.regras(self.escaneia()))

    def test_funciona_fora_de_um_repositorio_git(self):
        self.escreve("app.py", f'k = "{AWS}"\n')
        self.escreve("node_modules/x/index.js", f'k = "{AWS}"\n')     # pastas de dependências são puladas
        res = self.escaneia()
        self.assertEqual(1, sum(1 for a in res.achados if a.regra == "segredo-aws"))

    def test_nao_segue_link_simbolico_para_fora_do_projeto(self):
        fora = os.path.join(self._tmp, "fora.txt")
        with open(fora, "w") as f:
            f.write(f"k = {AWS}\n")
        try:
            os.symlink(fora, self.raiz / "atalho.txt")
        except (OSError, NotImplementedError):
            self.skipTest("este sistema não permite criar links simbólicos (comum no Windows sem privilégio)")
        self.escreve("README.md", "x\n")
        res = self.escaneia(usar_git=False)
        self.assertNotIn("segredo-aws", self.regras(res))
        self.assertGreaterEqual(res.pulados, 1)

    def test_arquivo_grande_demais_tem_o_conteudo_ignorado_mas_o_tamanho_conta(self):
        self.escreve("grande.txt", f"k = {AWS}\n" + "a" * (3 * 1024 * 1024))
        res = self.escaneia(max_bytes=1024 * 1024)
        self.assertNotIn("segredo-aws", self.regras(res))

    def test_arquivo_pesado_e_apontado(self):
        self.escreve("dados.bin.txt", "x" * 10)
        with open(self.raiz / "video.mp4", "wb") as f:
            f.truncate(6 * 1024 * 1024)
        self.assertIn("arquivo-pesado", self.regras(self.escaneia()))

    def test_binario_nao_quebra_e_nao_e_lido_como_texto(self):
        self.escreve("img.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00" + AWS.encode() + bytes(range(256)))
        self.assertNotIn("segredo-aws", self.regras(self.escaneia()))

    def test_arquivo_utf16_com_bom_e_lido(self):
        self.escreve("build.ps1", ("$k = '" + AWS + "'\n").encode("utf-16"))
        self.assertIn("segredo-aws", self.regras(self.escaneia()))

    def test_utf8_com_bom_e_nomes_com_acento_e_espaco(self):
        self.escreve("pasta com espaço/ação.txt", b"\xef\xbb\xbf" + f"Senha: {SENHA_FRACA}\n".encode())
        res = self.escaneia()
        self.assertIn("segredo-atribuicao", self.regras(res))
        self.assertTrue(any("ação.txt" in a.caminho for a in res.achados))

    def test_arquivo_com_bytes_invalidos_nao_derruba(self):
        self.escreve("x.txt", b"ola \xff\xfe\xfa mundo\n" + f"k={AWS}\n".encode())
        self.assertIn("segredo-aws", self.regras(self.escaneia()))

    def test_pasta_inexistente(self):
        from prepublishcheck.scanner import escaneia
        with self.assertRaises(NotADirectoryError):
            escaneia(str(self.raiz / "nao-existe"))

    def test_readme_e_licenca(self):
        res = self.escaneia()
        self.assertIn("repo-sem-readme", self.regras(res))
        self.assertIn("repo-sem-licenca", self.regras(res))
        self.escreve("README.md", "x\n")
        self.escreve("LICENSE", "MIT\n")
        res = self.escaneia()
        self.assertNotIn("repo-sem-readme", self.regras(res))
        self.assertNotIn("repo-sem-licenca", self.regras(res))

    def test_dump_sql_com_insert(self):
        self.escreve("db/dump.sql", "INSERT INTO usuarios VALUES (1, 'x');\n")
        self.escreve("db/schema.sql", "CREATE TABLE usuarios (id int);\n")
        res = self.escaneia()
        banco = [a.caminho for a in res.achados if a.regra == "arquivo-banco"]
        self.assertEqual(["db/dump.sql"], banco)

    def test_pasta_inteira_de_ferramenta_vira_um_achado(self):
        for i in range(30):
            self.escreve(f".idea/f{i}.xml", "<x/>")
        achados = [a for a in self.escaneia().achados if a.regra == "arquivo-ferramenta"]
        self.assertEqual(1, len(achados))
        self.assertIn("30", achados[0].detalhe)

    def test_pasta_inteira_de_fotos_vira_um_achado(self):
        for i in range(12):
            self.escreve(f"public/avatars/p{i}.jpg", b"\xff\xd8\xff")
        achados = [a for a in self.escaneia().achados if a.regra == "pii-foto-pessoas"]
        self.assertEqual(1, len(achados))
        self.assertEqual("public/avatars", achados[0].caminho)


class Agrupamento(BaseTemp):
    def test_muitas_ocorrencias_viram_um_achado_com_contagem(self):
        linhas = "\n".join(f"INSERT INTO t VALUES ('pessoa{i}@provedor-qualquer.com.br');" for i in range(40))
        self.escreve("dump.sql", linhas + "\n")
        emails = [a for a in self.escaneia().achados if a.regra == "pii-email"]
        self.assertEqual(1, len(emails))
        self.assertIn("40 ocorrências", emails[0].detalhe)

    def test_poucas_ocorrencias_continuam_individuais(self):
        self.escreve("a.txt", "\n".join(f"pessoa{i}@provedor-qualquer.com.br" for i in range(3)) + "\n")
        self.assertEqual(3, len([a for a in self.escaneia().achados if a.regra == "pii-email"]))

    def test_segredos_de_verdade_nunca_sao_agrupados(self):
        self.escreve("a.py", "\n".join(f'k{i} = "{"AKIA" + "ABCDEFGHIJKLMNO" + chr(65 + i)}"' for i in range(8)) + "\n")
        self.assertEqual(8, len([a for a in self.escaneia().achados if a.regra == "segredo-aws"]))

    def test_no_historico_tipos_diferentes_do_mesmo_arquivo_nao_se_escondem(self):
        # 4 achados de tipos diferentes no mesmo arquivo: nenhum pode "engolir" os outros
        self.init()
        self.escreve("clientes.txt", f"cpf {CPF}\nmail {EMAIL}\nfone {TELEFONE}\nNome: {NOMES[0]}\n")
        self.commit("v1")
        self.escreve("clientes.txt", "limpo\n")
        self.commit("v2")
        trechos = " ".join(a.trecho or "" for a in self.escaneia(historico=True).achados if a.regra == "historico-segredo")
        for esperado in ("pii-cpf", "pii-email", "pii-telefone", "pii-nome-completo"):
            self.assertIn(esperado, trechos)

    def test_arquivos_diferentes_nao_se_misturam(self):
        for arq in ("a.txt", "b.txt"):
            self.escreve(arq, "\n".join(f"pessoa{i}@provedor-qualquer.com.br" for i in range(10)) + "\n")
        emails = [a for a in self.escaneia().achados if a.regra == "pii-email"]
        self.assertEqual({"a.txt", "b.txt"}, {a.caminho for a in emails})


class Historico(BaseTemp):
    def test_segredo_apagado_continua_no_historico(self):
        self.init()
        self.escreve("config.py", f'KEY = "{AWS}"\n')
        self.commit("adiciona")
        self.escreve("config.py", 'KEY = os.environ["KEY"]\n')
        self.commit("remove o segredo")
        sem = self.escaneia()
        com = self.escaneia(historico=True)
        self.assertNotIn("segredo-aws", self.regras(sem))
        self.assertNotIn("historico-segredo", self.regras(sem))
        achados = [a for a in com.achados if a.regra == "historico-segredo"]
        self.assertEqual(1, len(achados))
        self.assertIn("segredo-aws", achados[0].trecho)
        self.assertTrue(achados[0].commit)
        self.assertEqual("config.py", achados[0].caminho)

    def test_acusa_o_commit_que_introduziu(self):
        self.init()
        self.escreve("a.py", "x = 1\n")
        self.commit("limpo")
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.commit("vaza")
        primeiro = self.git("rev-parse", "--short", "HEAD").strip()
        self.escreve("a.py", f'x = "{AWS}"\ny = 2\n')       # o mesmo valor segue lá em commits seguintes
        self.commit("depois")
        self.escreve("a.py", "x = 0\n")
        self.commit("limpa")
        achados = [a for a in self.escaneia(historico=True).achados if a.regra == "historico-segredo"]
        self.assertEqual(1, len(achados), "o mesmo valor aparece num commit só")
        self.assertTrue(primeiro.startswith(achados[0].commit) or achados[0].commit.startswith(primeiro[:4]))

    def test_valor_que_ainda_esta_na_arvore_nao_e_repetido_no_historico(self):
        self.init()
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.commit()
        res = self.escaneia(historico=True)
        self.assertIn("segredo-aws", self.regras(res))
        self.assertNotIn("historico-segredo", self.regras(res))

    def test_arquivo_sensivel_removido_continua_no_historico(self):
        self.init()
        self.escreve(".env", "A=1\n")
        self.escreve("README.md", "x\n")
        self.commit("com env")
        self.remove(".env")
        self.commit("sem env")
        res = self.escaneia(historico=True)
        arq = [a for a in res.achados if a.regra == "historico-arquivo-sensivel"]
        self.assertEqual([".env"], [a.caminho for a in arq])
        self.assertNotIn("arquivo-env", self.regras(res))

    def test_nome_completo_e_dump_com_hash_no_historico(self):
        self.init()
        self.escreve("equipe.txt", "\n".join(NOMES) + "\n")
        self.escreve("dump.sql", f"INSERT INTO users VALUES (1, '{BCRYPT}');\n")
        self.commit("v1")
        self.escreve("equipe.txt", "Maria\nJoao\n")                 # corrigido: só os primeiros nomes
        self.escreve("dump.sql", "-- sem dados\n")
        self.commit("v2 corrigido")
        res = self.escaneia(historico=True)
        self.assertNotIn("pii-lista-de-pessoas", self.regras(res))   # a árvore atual está limpa...
        trechos = " ".join(a.trecho or "" for a in res.achados if a.regra == "historico-segredo")
        self.assertIn("segredo-hash-senha", trechos)                 # ...mas o hash continua no histórico
        self.assertIn("pii-lista-de-pessoas", trechos)               # ...e os nomes completos dos colegas também
        self.assertIn("2 nome(s) completo(s)", trechos)

    def test_email_de_autor_e_apontado_mas_noreply_nao(self):
        self.init()
        self.escreve("a.txt", "x\n")
        self.commit("c1", autor_email="alguem@provedor-qualquer.com.br")
        self.commit("c2", autor_email="123+u@users.noreply.github.com")
        achados = [a for a in self.escaneia(historico=True).achados if a.regra == "historico-email-autor"]
        self.assertEqual(1, len(achados))
        self.assertIn("a***@provedor-qualquer.com.br", achados[0].detalhe)
        self.assertNotIn("alguem@", achados[0].detalhe)

    def test_sem_historico_sem_a_flag(self):
        self.init()
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.commit()
        self.escreve("a.py", "x = 1\n")
        self.commit()
        res = self.escaneia()
        self.assertIsNone(res.commits)
        self.assertFalse([a for a in res.achados if a.regra.startswith("historico-")])

    def test_historico_numa_pasta_que_nao_e_repositorio_avisa(self):
        self.escreve("a.txt", "x\n")
        res = self.escaneia(historico=True)
        self.assertTrue(any("não é um repositório git" in a for a in res.avisos))

    def test_repositorio_raso_avisa(self):
        import subprocess
        self.init()
        for i in range(3):
            self.escreve("a.txt", f"{i}\n")
            self.commit(f"c{i}")
        clone = self._tmp + "/clone"
        subprocess.run(["git", "clone", "-q", "--depth", "1", self.raiz.as_uri(), clone], check=True, capture_output=True)
        from prepublishcheck.scanner import escaneia
        res = escaneia(clone, historico=True)
        self.assertTrue(any("raso" in a for a in res.avisos))

    def test_limite_de_commits(self):
        self.init()
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.commit("vaza")
        for i in range(5):
            self.escreve("a.py", f"x = {i}\n")
            self.commit(f"c{i}")
        com_limite = self.escaneia(historico=True, max_commits=2)
        self.assertNotIn("historico-segredo", self.regras(com_limite))
        self.assertTrue(any("mais recentes" in a for a in com_limite.avisos))
        self.assertIn("historico-segredo", self.regras(self.escaneia(historico=True)))

    def test_ignorar_vale_tambem_no_historico(self):
        self.init()
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.commit()
        self.escreve("a.py", "x = 1\n")
        self.escreve(".ppcignore", "a.py\n")
        self.commit()
        self.assertNotIn("historico-segredo", self.regras(self.escaneia(historico=True)))


class ModoStaged(BaseTemp):
    def test_analisa_so_o_que_esta_no_stage(self):
        self.init()
        self.escreve("antigo.py", f'x = "{AWS}"\n')
        self.commit()
        self.escreve("novo.py", f'y = "{GITHUB}"\n')
        self.git("add", "novo.py")
        self.escreve("fora.py", f'z = "{AWS}"\n')            # não está no stage
        res = self.escaneia(staged=True)
        self.assertEqual({"segredo-github"}, {a.regra for a in res.achados})
        self.assertEqual(["novo.py"], [a.caminho for a in res.achados])

    def test_le_o_conteudo_do_stage_e_nao_o_do_disco(self):
        self.init()
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.git("add", "a.py")
        self.escreve("a.py", "x = 1\n")                      # já corrigiu no disco, mas o stage ainda tem o segredo
        self.assertIn("segredo-aws", self.regras(self.escaneia(staged=True)))

    def test_stage_vazio(self):
        self.init()
        self.escreve("a.py", f'x = "{AWS}"\n')
        self.commit()
        self.assertEqual([], self.escaneia(staged=True).achados)

    def test_fora_de_um_repositorio_da_erro(self):
        from prepublishcheck.gitutils import ErroGit
        with self.assertRaises(ErroGit):
            self.escaneia(staged=True)


class Ignorado(BaseTemp):
    def test_ppcignore_por_caminho_por_regra_email_e_regra(self):
        self.escreve("docs/exemplo.txt", f"k={AWS}\n")
        self.escreve("tests/fixtures/dados.txt", f"mail {EMAIL}\nk={AWS}\n")
        self.escreve("contato.md", f"fale com {EMAIL}\n")
        self.escreve("relatorio.pdf", b"%PDF")
        self.escreve(".ppcignore", "\n".join([
            "# comentário", "docs/**", "tests/fixtures/**::pii-email", f"email:{EMAIL}", "rule:arquivo-documento", ""]))
        res = self.escaneia()
        r = {(a.regra, a.caminho) for a in res.achados}
        self.assertNotIn(("segredo-aws", "docs/exemplo.txt"), r)               # caminho ignorado
        self.assertIn(("segredo-aws", "tests/fixtures/dados.txt"), r)          # só o e-mail foi liberado ali
        self.assertNotIn("pii-email", self.regras(res))                        # e-mail permitido em todo lugar
        self.assertNotIn("arquivo-documento", self.regras(res))                # regra desativada

    def test_glob_sem_barra_vale_em_qualquer_pasta(self):
        self.escreve("a/b/c/x.pdf", b"%PDF")
        self.escreve(".ppcignore", "*.pdf\n")
        self.assertNotIn("arquivo-documento", self.regras(self.escaneia()))


class Cli(BaseTemp):
    def preparar_com_problemas(self):
        self.init()
        self.escreve("app.py", f'k = "{AWS}"\n')
        self.escreve("README.md", "x\n")
        self.escreve("LICENSE", "x\n")
        self.commit()

    def test_codigo_de_saida_1_quando_ha_achado_alto(self):
        self.preparar_com_problemas()
        codigo, saida, _ = self.cli(".")
        self.assertEqual(1, codigo)
        self.assertIn("segredo-aws", saida)

    def test_codigo_de_saida_0_quando_esta_limpo(self):
        self.init()
        self.escreve("README.md", "# oi\n")
        self.escreve("LICENSE", "MIT\n")
        self.commit()
        codigo, saida, _ = self.cli(".")
        self.assertEqual(0, codigo)
        self.assertIn("Nada encontrado", saida)

    def test_fail_on_muda_o_limite(self):
        self.init()
        self.escreve("a.sh", r'cd "C:\Users\lucas\x"' + "\n")       # só um achado de nível "baixo"
        self.escreve("README.md", "x\n")
        self.commit()
        self.assertEqual(0, self.cli(".")[0])                          # padrão (medium): passa
        self.assertEqual(1, self.cli(".", "--fail-on", "low")[0])
        self.assertEqual(0, self.cli(".", "--fail-on", "never")[0])
        self.assertEqual(2, self.cli(".", "--fail-on", "banana")[0])

    def test_erros_de_uso_dao_codigo_2(self):
        self.assertEqual(2, self.cli("pasta-que-nao-existe")[0])
        self.assertEqual(2, self.cli(".", "--disable", "regra-inventada")[0])
        self.assertEqual(2, self.cli(".", "--staged")[0])               # não é um repositório git

    def test_json_e_valido_e_completo(self):
        self.preparar_com_problemas()
        codigo, saida, _ = self.cli(".", "--format", "json")
        dados = json.loads(saida)
        self.assertEqual(1, codigo)
        self.assertEqual(1, dados["versao"])
        self.assertEqual(1, dados["resumo"]["alto"])
        achado = next(a for a in dados["achados"] if a["regra"] == "segredo-aws")
        self.assertEqual({"regra", "severidade", "caminho", "linha", "trecho"}, set(achado))
        self.assertEqual("alto", achado["severidade"])

    def test_disable_e_allow_email(self):
        self.init()
        self.escreve("a.txt", f"fale com {EMAIL}\n")
        self.escreve("README.md", "x\n")
        self.commit()
        self.assertEqual(1, self.cli(".")[0])
        self.assertEqual(0, self.cli(".", "--allow-email", EMAIL)[0])
        self.assertEqual(0, self.cli(".", "--disable", "pii-email")[0])

    def test_list_rules_e_version(self):
        codigo, saida, _ = self.cli("--list-rules")
        self.assertEqual(0, codigo)
        self.assertIn("segredo-aws", saida)
        self.assertIn("historico-segredo", saida)
        codigo, saida, _ = self.cli("--version")
        self.assertEqual(0, codigo)
        self.assertIn("1.0.0", saida)

    def test_sem_cor_quando_nao_e_terminal(self):
        self.preparar_com_problemas()
        self.assertNotIn("\033[", self.cli(".")[1])

    def test_pasta_dada_como_argumento(self):
        self.preparar_com_problemas()
        codigo, saida, _ = self.cli(str(self.raiz), cwd=self._tmp)
        self.assertEqual(1, codigo)

    def test_pasta_cujo_nome_comeca_com_hifen(self):
        # o caso real: um repositório chamado "-Sites-E-Aplicativos"
        pasta = os.path.join(self._tmp, "-Meu-Projeto")
        os.mkdir(pasta)
        with open(os.path.join(pasta, "app.py"), "w") as f:
            f.write(f'k = "{AWS}"\n')
        codigo, saida, _ = self.cli(pasta.replace(self._tmp, ".").replace("\\", "/"), cwd=self._tmp)
        self.assertEqual(1, codigo)
        self.assertIn("segredo-aws", saida)
        codigo, _, erro = self.cli("--opcao-inexistente")
        self.assertEqual(2, codigo)
        self.assertIn("argumentos não reconhecidos", erro)

    def test_argumento_desconhecido_que_nao_e_pasta_da_erro(self):
        codigo, _, erro = self.cli("--banana")
        self.assertEqual(2, codigo)

    def test_modulo_roda_com_python_m(self):
        codigo, _, err = self.cli("--help")
        self.assertEqual(0, codigo, err)


class SaidaNuncaVazaValores(BaseTemp):
    """O teste que mais importa: nada sensível pode aparecer na saída, em nenhum formato, nem no histórico."""

    def monta(self):
        self.init()
        self.escreve("config.py", f'AWS = "{AWS}"\nGH = "{GITHUB}"\n')
        self.escreve("integrantes.txt", "\n".join(NOMES) + f"\nLogin: admin\nSenha: {SENHA_FRACA}\n")
        self.escreve("clientes.txt", f"cpf {CPF}\nmail {EMAIL}\nfone {TELEFONE}\nNome: {NOMES[0]}\n")
        self.escreve("dump.sql", f"INSERT INTO users VALUES (1, '{BCRYPT}');\n")
        self.escreve(".env", "DB_PASSWORD=zx81hd7QpL2m\n")
        self.escreve("db.py", 'URL = "postgres://app:zx81hd7QpL2m@h/x"\n')
        self.commit("vaza tudo")
        for f in ("config.py", "integrantes.txt", "clientes.txt", "dump.sql", ".env", "db.py"):
            self.escreve(f, "limpo\n")
        self.commit("limpa tudo")

    def _confere(self, texto, origem):
        for bruto in valores_sensiveis():
            self.assertNotIn(bruto, texto, f"{origem} vazou um valor sensível ({bruto[:6]}…)")

    def test_texto_e_json_com_e_sem_historico(self):
        self.monta()
        for args in ([], ["--history"], ["--format", "json"], ["--format", "json", "--history"], ["--history", "--fail-on", "never"]):
            with self.subTest(args=args):
                _, saida, err = self.cli(".", *args)
                self._confere(saida, f"stdout {args}")
                self._confere(err, f"stderr {args}")

    def test_o_historico_realmente_encontrou_tudo_isso(self):
        # garante que o teste acima não passa "por vazio": os achados existem, só estão ocultos
        self.monta()
        res = self.escaneia(historico=True)
        trechos = " ".join(a.trecho or "" for a in res.achados if a.regra == "historico-segredo")
        for esperado in ("segredo-aws", "segredo-github", "segredo-hash-senha", "pii-cpf", "pii-email", "pii-telefone", "segredo-url-credenciais"):
            self.assertIn(esperado, trechos)


if __name__ == "__main__":
    unittest.main()
