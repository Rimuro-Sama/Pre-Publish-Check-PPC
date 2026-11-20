"""Reproduções (com dados fictícios) dos problemas reais que motivaram esta ferramenta.

Cada caso nasceu de um erro que aconteceu de verdade ao preparar repositórios para publicação. Se a ferramenta
deixar de pegar qualquer um deles, é uma regressão grave.
"""
import unittest

from helpers import BCRYPT, BaseTemp


class CasosReais(BaseTemp):
    def regras_com_arquivos(self, arquivos, historico=False):
        for rel, conteudo in arquivos.items():
            self.escreve(rel, conteudo)
        return self.regras(self.escaneia(historico=historico))

    def test_jogo_web_com_pacote_de_arte_paga_dump_com_conta_e_fotos_de_colegas(self):
        r = self.regras_com_arquivos({
            "public/assets/sprites/CREDITS.txt": (
                "Character sprites come from the purchased \"Zombie Apocalypse AssetPack\".\n"
                "License: personal/commercial use allowed, modify freely, no resale as a standalone\n"
                "asset. Same author and license as the rest of the pack: the pack itself must not be redistributed.\n"),
            "public/sobre/assets/avatars/colega1.jpg": b"\xff\xd8\xff",
            "public/sobre/assets/avatars/colega2.jpg": b"\xff\xd8\xff",
            "database/dump.sql": f"INSERT INTO `users` VALUES (1,'pessoa.real@provedor-qualquer.com.br','pessoa','{BCRYPT}');\n",
        })
        self.assertIn("licenca-restricao", r)       # o pacote não pode ser redistribuído
        self.assertIn("pii-foto-pessoas", r)        # fotos de colegas
        self.assertIn("arquivo-banco", r)           # dump com INSERT
        self.assertIn("segredo-hash-senha", r)      # o hash da senha da conta
        self.assertIn("pii-email", r)               # o e-mail da conta

    def test_trabalho_de_faculdade_com_nomes_completos_e_login_admin(self):
        r = self.regras_com_arquivos({
            "integrantes.txt": ("INTEGRANTES DO GRUPO\n- Maria Souza Lima\n- Joao Pedro Alves\n- Ana Clara Ferreira Gandra\n\n"
                                "ACESSO AO SISTEMA\nLogin: admin\nSenha: admin123\n"),
            "equipe.txt": "Maria Souza Lima\nJoao Pedro Alves\n",
        })
        self.assertIn("pii-lista-de-pessoas", r)
        self.assertIn("segredo-atribuicao", r)      # Senha: admin123

    def test_nomes_corrigidos_mas_ainda_no_historico(self):
        """O caso do 'deixe só o primeiro nome': a árvore fica limpa, o histórico não."""
        self.init()
        self.escreve("equipe.txt", "Maria Souza Lima\nJoao Pedro Alves\nAna Clara Ferreira\n")
        self.commit("primeira versão")
        self.escreve("equipe.txt", "Maria\nJoao\nAna\n")
        self.commit("só os primeiros nomes")
        sem = self.escaneia()
        com = self.escaneia(historico=True)
        self.assertNotIn("pii-lista-de-pessoas", self.regras(sem))
        self.assertEqual([], [a for a in sem.achados if a.severidade in ("alto", "medio")])
        self.assertIn("historico-segredo", self.regras(com))            # a ferramenta avisa que os nomes seguem nos commits

    def test_dump_trocado_por_conta_ficticia_mas_a_real_ficou_no_historico(self):
        self.init()
        self.escreve("db/dump.sql", f"INSERT INTO users VALUES (1,'pessoa.real@provedor-qualquer.com.br','{BCRYPT}');\n")
        self.commit("dump")
        self.escreve("db/dump.sql", f"INSERT INTO users VALUES (1,'demo@example.com','{'$2y' + '$10$' + 'x' * 53}');\n")
        self.commit("troca por conta fictícia")
        com = self.escaneia(historico=True)
        trechos = " ".join(a.trecho or "" for a in com.achados if a.regra == "historico-segredo")
        self.assertIn("pii-email", trechos)
        self.assertIn("segredo-hash-senha", trechos)

    def test_scripts_com_caminho_do_computador_e_atalho(self):
        r = self.regras_com_arquivos({
            "build.ps1": '$root = "C:\\Users\\lucas\\Desktop\\Robocode"\n$cp = "$root\\libs"\n',
            "Robocode.lnk": b"L\x00\x00\x00",
        })
        self.assertIn("caminho-local", r)
        self.assertIn("arquivo-ferramenta", r)

    def test_ide_e_ferramenta_de_ia_versionadas(self):
        r = self.regras_com_arquivos({".claude/launch.json": "{}", ".idea/workspace.xml": "<x/>"})
        self.assertIn("arquivo-ferramenta", r)

    def test_dominio_de_exemplo_esquecido_no_sitemap_e_no_readme_do_perfil(self):
        r = self.regras_com_arquivos({
            "sitemap.xml": "<url><loc>https://seu-dominio-aqui.com/index.html</loc></url>\n",
            "robots.txt": "Sitemap: https://SEU-DOMINIO.exemplo/sitemap.xml\n",
            "README.md": "[LinkedIn](SEU_LINK)\n",
        })
        self.assertIn("placeholder-esquecido", r)

    def test_material_de_curso_em_pdf_e_provas(self):
        r = self.regras_com_arquivos({"apostila/Fundamentos de Programacao.pdf": b"%PDF-1.4", "enunciado.docx": b"PK"})
        self.assertIn("arquivo-documento", r)

    def test_conexao_com_hash_do_admin_embutido_no_codigo(self):
        r = self.regras_com_arquivos({
            "conexao.php": f"<?php\n$admin_senha_hash = '{BCRYPT}';\n$c = mysqli_connect('localhost', 'root', '');\n"})
        self.assertIn("segredo-hash-senha", r)
        self.assertNotIn("segredo-atribuicao", r)       # senha do root vazia: não há valor para acusar

    def test_projeto_bem_cuidado_passa_limpo(self):
        """O contrário: um projeto saudável (como os que publicamos depois) não pode gerar alarme falso."""
        r = self.regras_com_arquivos({
            "README.md": "# Projeto\nCopie `.env.example` para `.env` e troque as senhas.\n",
            "LICENSE": "MIT License\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"
                       "Redistribution and use in source and binary forms, with or without modification, are permitted\n",
            ".env.example": "DB_USER=biblioteca\nDB_PASSWORD=troque-esta-senha\nBIBLIOTECA_ADMIN_PASSWORD=troque-esta-senha-tambem\n",
            ".gitignore": ".env\ntarget/\n",
            "docker-compose.yml": "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${DB_PASSWORD:?defina DB_PASSWORD}\n",
            "src/App.java": 'class App { String url = System.getenv("DB_URL"); String senha = System.getenv("DB_PASSWORD"); }\n',
            "src/test/resources/application-test.yml": "biblioteca:\n  admin:\n    password: senha-de-teste-apenas\n"
                                                      "spring:\n  datasource:\n    password: ${TEST_DB_PASSWORD:postgres}\n",
            "src/Login.html": '<input type="password" name="senha" placeholder="Senha">\n',
            ".github/workflows/ci.yml": "env:\n  POSTGRES_PASSWORD: ci-somente-para-testes\n",
            "docs/exemplo.md": "Contato: fulano@example.com e tel (00) 00000-0000? não: use dados fictícios.\n",
        })
        self.assertEqual(set(), {x for x in r if x.startswith(("segredo-", "pii-", "licenca-", "caminho-"))})


if __name__ == "__main__":
    unittest.main()
