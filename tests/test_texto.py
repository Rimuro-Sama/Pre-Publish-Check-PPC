"""Detectores de conteúdo: o que deve ser achado e, tão importante quanto, o que NÃO deve."""
import unittest

from helpers import (AWS, BCRYPT, CHAVE_PRIVADA, CNPJ, CPF, EMAIL, GITHUB, GOOGLE, IA, SLACK, STRIPE, TELEFONE)  # noqa: F401
from prepublishcheck.mask import impressao
from prepublishcheck.textscan import Contexto, analisa_arquivo, cpf_valido, cnpj_valido, entropia, eh_marcador


def regras(caminho, texto, ctx=None):
    return [a.regra for a in analisa_arquivo(caminho, texto, ctx or Contexto())]


class TokensConhecidos(unittest.TestCase):
    def test_cada_tipo_de_chave(self):
        casos = {
            "segredo-aws": AWS, "segredo-github": GITHUB, "segredo-google": GOOGLE, "segredo-slack": SLACK,
            "segredo-stripe": STRIPE, "segredo-ia": IA, "segredo-chave-privada": CHAVE_PRIVADA,
        }
        for regra, valor in casos.items():
            with self.subTest(regra):
                self.assertIn(regra, regras("x.py", f"valor = {valor}\n"))

    def test_chave_de_exemplo_da_documentacao_da_aws_e_ignorada(self):
        self.assertEqual([], regras("x.py", "k = AKIAIOSFODNN7EXAMPLE\n"))

    def test_formato_quase_certo_nao_dispara(self):
        self.assertEqual([], regras("x.py", "k = AKIA123\n"))                 # curta demais
        self.assertEqual([], regras("x.py", "k = ghp_curto\n"))
        self.assertEqual([], regras("x.py", "k = task-force-" + "a" * 40 + "\n"))   # "sk-" no meio de uma palavra

    def test_url_com_senha(self):
        self.assertIn("segredo-url-credenciais", regras("x.py", 'u = "postgres://app:Zq8v2LmP4x@db.interno:5432/x"\n'))

    def test_senha_dentro_de_url_nao_vira_um_falso_email(self):
        # "SENHA@servidor.tld" tem cara de e-mail, mas aqui é a senha de uma URL: um achado só, como credencial
        r = regras("x.py", 'u = "postgres://app:Zq8v2LmP4x@servidor-interno.com.br:5432/x"\n')
        self.assertEqual(["segredo-url-credenciais"], r)
        # mas um e-mail de verdade, na mesma linha, continua sendo achado
        r = regras("x.py", f'u = "postgres://app:Zq8v2LmP4x@servidor-interno.com.br/x"  # fale com {EMAIL}\n')
        self.assertEqual({"segredo-url-credenciais", "pii-email"}, set(r))

    def test_url_com_marcador_ou_sem_senha_nao_dispara(self):
        self.assertEqual([], regras("x.py", 'u = "postgres://app:${DB_PASSWORD}@db:5432/x"\n'))
        self.assertEqual([], regras("x.py", 'u = "postgres://app:troque-esta-senha@db:5432/x"\n'))
        self.assertEqual([], regras("x.py", 'u = "https://github.com/usuario/repo"\n'))


class Atribuicoes(unittest.TestCase):
    def test_senha_literal_no_codigo(self):
        self.assertIn("segredo-atribuicao", regras("a.java", 'String senha = "k9Tz4Qa";\n'))
        self.assertIn("segredo-atribuicao", regras("a.json", '{"password": "Zq8v2LmP"}\n'))
        self.assertIn("segredo-atribuicao", regras("a.py", "API_KEY = 'ab12cd34ef'\n"))

    def test_chave_sozinha_em_portugues_nao_e_credencial(self):
        # "chave" também é "key" de dicionário/item: {"chave": "lanterna-do-hospital"} não é segredo
        self.assertEqual([], regras("a.json", '{"chave": "lanterna-do-hospital-01"}\n'))
        self.assertEqual([], regras("a.json", '{"chave": "Zq8v2LmP4xKd9T"}\n'))
        self.assertIn("segredo-atribuicao", regras("a.py", 'chave_secreta = "k9Tz4QaL2m"\n'))
        self.assertIn("segredo-atribuicao", regras("a.js", 'const chaveApi = "k9Tz4QaL2m";\n'))

    def test_senha_sem_aspas_em_texto_livre(self):
        self.assertIn("segredo-atribuicao", regras("integrantes.txt", "Senha: admin123\n"))
        self.assertIn("segredo-atribuicao", regras(".env", "DB_PASSWORD=zx81hd7QpL2m\n"))
        self.assertIn("segredo-atribuicao", regras("config.properties", "db.password=zx81hd7QpL2m\n"))

    def test_senha_sem_aspas_em_codigo_nao_dispara(self):
        # "password: String", "password = request.getParameter(...)" etc. não são literais
        self.assertEqual([], regras("a.ts", "password: string;\n"))
        self.assertEqual([], regras("a.java", "String senha = request.getParameter(x);\n"))
        self.assertEqual([], regras("a.py", "senha = input('Senha: ')\n"))

    def test_marcadores_e_referencias_nao_disparam(self):
        for linha in ("DB_PASSWORD=troque-esta-senha", "password: ${DB_PASSWORD}", 'senha = "changeme"',
                      'token = "<seu-token-aqui>"', "password: required", "SECRET_KEY={{ secret }}",
                      'senha = "senha"', "POSTGRES_PASSWORD: ci-somente-para-testes",
                      'api_key = "your-api-key-here"'):
            with self.subTest(linha):
                self.assertEqual([], regras(".env" if "=" in linha and ":" not in linha else "a.yml", linha + "\n"))

    def test_atributos_html_nao_disparam(self):
        self.assertEqual([], regras("a.html", '<input type="password" name="senha" placeholder="Senha">\n'))

    def test_valor_longo_e_aleatorio_vira_alto(self):
        valor = "q8Zv2LmP4xKd9TwR7bNc5YhJ3sFa"
        self.assertGreater(entropia(valor), 3.5)          # garante que o dado de teste é mesmo "aleatório"
        r = regras("a.py", f'token = "{valor}"\n')
        self.assertIn("segredo-valor-forte", r)
        self.assertNotIn("segredo-atribuicao", r)

    def test_valor_que_ja_foi_reconhecido_por_detector_especifico_nao_duplica(self):
        r = regras("a.py", f'chave = "{AWS}"\n')
        self.assertEqual(["segredo-aws"], r)

    def test_hash_bcrypt(self):
        self.assertIn("segredo-hash-senha", regras("dump.sql", f"INSERT INTO users VALUES (1, '{BCRYPT}');\n"))


class DadosPessoais(unittest.TestCase):
    def test_cpf_valido_formatado(self):
        self.assertIn("pii-cpf", regras("a.txt", f"cliente {CPF}\n"))

    def test_cpf_de_digitos_invalidos_nao_dispara(self):
        self.assertEqual([], regras("a.txt", "id 123.456.789-00\n"))
        self.assertEqual([], regras("a.txt", "111.111.111-11\n"))

    def test_cpf_sem_pontuacao_so_com_contexto(self):
        self.assertIn("pii-cpf", regras("a.txt", "CPF: 11144477735\n"))
        self.assertEqual([], regras("a.txt", "pedido 11144477735\n"))       # 11 dígitos sem a palavra "cpf": é só um número

    def test_validadores(self):
        self.assertTrue(cpf_valido("111.444.777-35"))
        self.assertFalse(cpf_valido("111.444.777-36"))
        self.assertTrue(cnpj_valido(CNPJ))
        self.assertFalse(cnpj_valido("11.222.333/0001-82"))

    def test_cnpj(self):
        self.assertIn("pii-cnpj", regras("a.txt", f"empresa {CNPJ}\n"))

    def test_email_real_dispara(self):
        self.assertIn("pii-email", regras("a.py", f'contato = "{EMAIL}"\n'))

    def test_emails_de_exemplo_e_genericos_nao_disparam(self):
        for e in ("fulano@example.com", "a@exemplo.example", "x@servidor.test", "git@github.com:org/r.git",
                  "noreply@empresa.com.br", "123+nome@users.noreply.github.com", "icone@2x.png", "lodash@4.17.21"):
            with self.subTest(e):
                self.assertEqual([], regras("a.txt", f"{e}\n"))

    def test_provedores_reais_de_email_NAO_sao_tratados_como_exemplo(self):
        # mail.com, email.com e domain.com são empresas de verdade: endereços ali são de pessoas reais
        for dominio in ("mail.com", "email.com", "domain.com", "gmail.com", "outlook.com"):
            with self.subTest(dominio):
                self.assertIn("pii-email", regras("a.txt", f"pessoa@{dominio}\n"))

    def test_email_permitido_pelo_usuario(self):
        ctx = Contexto(emails_permitidos={EMAIL})
        self.assertEqual([], regras("a.txt", f"{EMAIL}\n", ctx))
        ctx = Contexto(emails_permitidos={"@provedor-qualquer.com.br"})
        self.assertEqual([], regras("a.txt", f"{EMAIL}\n", ctx))

    def test_telefone(self):
        self.assertIn("pii-telefone", regras("a.txt", f"fone {TELEFONE}\n"))
        self.assertIn("pii-telefone", regras("a.txt", "fone +55 11 98765-4321\n"))
        self.assertIn("pii-telefone", regras("a.txt", "fixo (11) 3456-7890\n"))

    def test_numeros_comuns_nao_viram_telefone(self):
        for s in ("versao 1.2.3", "pedido 123456789", "cep 13201-000", "uuid 98765-4321-abcd", "total 1234567890123"):
            with self.subTest(s):
                self.assertEqual([], regras("a.txt", s + "\n"))

    def test_campo_com_nome_completo(self):
        self.assertIn("pii-nome-completo", regras("a.txt", "Nome: Maria da Silva Souza\n"))
        self.assertIn("pii-nome-completo", regras("a.txt", "integrante = Joao Pedro Alves\n"))

    def test_campo_com_so_um_nome_ou_dois_nao_dispara(self):
        self.assertEqual([], regras("a.txt", "Nome: Maria\n"))
        self.assertEqual([], regras("a.txt", "Nome: Maria Souza\n"))

    def test_lista_de_pessoas_em_arquivo_com_nome_de_equipe(self):
        achados = analisa_arquivo("equipe.txt", "Maria Souza Lima\nJoao Pedro Alves\nAna\n", Contexto())
        lista = [a for a in achados if a.regra == "pii-lista-de-pessoas"]
        self.assertEqual(1, len(lista))
        self.assertIn("2 linha(s)", lista[0].detalhe)

    def test_lista_de_pessoas_com_marcadores_de_lista(self):
        self.assertIn("pii-lista-de-pessoas", regras("integrantes.md", "# Grupo\n- Maria Souza Lima\n- Joao Pedro Alves\n"))

    def test_so_primeiros_nomes_nao_dispara(self):
        self.assertEqual([], regras("integrantes.txt", "André\nLucas\nSuiene\n"))

    def test_mesmo_conteudo_em_arquivo_comum_nao_vira_lista(self):
        self.assertNotIn("pii-lista-de-pessoas", regras("notas.txt", "Maria Souza Lima\nJoao Pedro Alves\n"))


class CaminhosLicencasMarcadores(unittest.TestCase):
    def test_caminho_do_windows_e_unix(self):
        self.assertIn("caminho-local", regras("a.ps1", r'$root = "C:\Users\lucas\Desktop\Proj"' + "\n"))
        self.assertIn("caminho-local", regras("a.json", r'{"p": "C:\\Users\\lucas\\Desktop"}' + "\n"))
        self.assertIn("caminho-local", regras("a.sh", "cd /home/lucas/projetos/x\n"))
        self.assertIn("caminho-local", regras("a.sh", "cd /Users/lucas/dev\n"))

    def test_caminhos_genericos_nao_disparam(self):
        for s in (r"C:\Users\Public\x", r"C:\Users\%USERNAME%\x", r"C:\Users\<seu-usuario>\x", r"C:\Users\[usuário]\x",
                  "/home/<user>/x", "/home/$USER/x", "/Users/{nome}/x", "/home/runner/work", "/home/user/app", "/Users/Shared/x",
                  r"C:\robocode\robots"):
            with self.subTest(s):
                self.assertEqual([], regras("a.sh", s + "\n"))

    def test_licenca_que_proibe_redistribuir(self):
        for frase in ("the pack itself must not be redistributed", "Do not redistribute this file", "No redistribution allowed",
                      "no resale as a standalone asset", "Personal use only", "Não pode ser redistribuído",
                      "É proibida a redistribuição deste material", "somente para uso pessoal"):
            with self.subTest(frase):
                self.assertIn("licenca-restricao", regras("CREDITS.txt", frase + "\n"))

    def test_licencas_permissivas_nao_disparam(self):
        permissiva = ("Redistribution and use in source and binary forms, with or without modification, are permitted\n"
                      "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
                      "You may redistribute it under the terms of the MIT license.\n")
        self.assertEqual([], regras("LICENSE", permissiva))

    def test_restricao_so_em_arquivos_de_texto_ou_de_licenca(self):
        self.assertEqual([], regras("main.py", "# do not redistribute\n"))

    def test_marcador_esquecido(self):
        self.assertIn("placeholder-esquecido", regras("sitemap.xml", "<loc>https://seu-dominio-aqui.com/</loc>\n"))
        self.assertIn("placeholder-esquecido", regras("README.md", "[LinkedIn](SEU_LINK)\n"))
        self.assertIn("placeholder-esquecido", regras("robots.txt", "Sitemap: https://SEU-DOMINIO.exemplo/sitemap.xml\n"))


class Ignorar(unittest.TestCase):
    def test_ignorar_na_linha(self):
        self.assertEqual([], regras("a.py", f'k = "{AWS}"  # ppc:ignore\n'))
        self.assertEqual([], regras("a.py", f'k = "{AWS}"  # ppc:ignore=segredo-aws\n'))

    def test_ignorar_outra_regra_nao_vale(self):
        self.assertIn("segredo-aws", regras("a.py", f'k = "{AWS}"  # ppc:ignore=pii-email\n'))

    def test_regra_desativada(self):
        self.assertEqual([], regras("a.py", f'k = "{AWS}"\n', Contexto(regras_desativadas={"segredo-aws"})))


class Robustez(unittest.TestCase):
    def test_arquivos_de_lock_e_minificados_sao_ignorados(self):
        self.assertEqual([], regras("package-lock.json", f'"x": "{AWS}"\n'))
        self.assertEqual([], regras("app.min.js", f"var a='{AWS}'\n"))

    def test_linha_gigante_nao_trava(self):
        regras("a.js", "x=" + "a" * 3_000_000 + "\n")

    def test_texto_vazio_e_so_quebras(self):
        self.assertEqual([], regras("a.txt", ""))
        self.assertEqual([], regras("a.txt", "\n\n\n"))

    def test_entropia_e_marcador(self):
        self.assertGreater(entropia("aB3xZ9q7Lm2PkR8vW4nY"), 3.5)
        self.assertLess(entropia("aaaaaaaaaaaa"), 0.1)
        self.assertTrue(eh_marcador("troque-esta-senha"))
        self.assertTrue(eh_marcador("xxxxxxxx"))
        self.assertFalse(eh_marcador("zx81hd7QpL2m"))


class NuncaVazaOValor(unittest.TestCase):
    """O princípio central: nenhum campo de um achado pode conter o valor sensível bruto."""

    def test_achados_nao_carregam_o_valor(self):
        from helpers import SENHA_FRACA
        texto = "\n".join([f'k = "{AWS}"', f"token {GITHUB}", f"cpf {CPF}", f"mail {EMAIL}", f"fone {TELEFONE}",
                           f"Senha: {SENHA_FRACA}", f"hash '{BCRYPT}'", "Nome: Maria Souza Lima", f"u = postgres://app:Zq8v2LmP4x@h/x"])
        achados = analisa_arquivo("dados.txt", texto, Contexto())
        self.assertGreaterEqual(len(achados), 8)
        for a in achados:
            visivel = " ".join(str(v) for v in (a.regra, a.caminho, a.trecho, a.detalhe, a.commit) if v)
            for bruto in (AWS, GITHUB, CPF, EMAIL, TELEFONE, SENHA_FRACA, BCRYPT, "Maria Souza Lima", "Zq8v2LmP4x"):
                self.assertNotIn(bruto, visivel, f"{a.regra} vazou {bruto[:6]}…")
                self.assertNotIn(bruto, repr(a))

    def test_impressao_e_estavel_e_nao_reversivel_a_olho(self):
        self.assertEqual(impressao("abc"), impressao("abc"))
        self.assertNotEqual(impressao("abc"), impressao("abd"))
        self.assertNotIn("abc", impressao("abc"))


if __name__ == "__main__":
    unittest.main()
