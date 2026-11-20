"""Catálogo de regras: cada achado aponta para uma regra com severidade, motivo e correção."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

SEVERIDADES = ("info", "baixo", "medio", "alto")
RANK = {s: i for i, s in enumerate(SEVERIDADES)}
ROTULO = {"info": "INFO", "baixo": "BAIXO", "medio": "MÉDIO", "alto": "ALTO"}


@dataclass(frozen=True)
class Regra:
    id: str
    severidade: str
    titulo: str
    por_que: str
    correcao: str


def _r(id_, sev, titulo, por_que, correcao):
    return Regra(id_, sev, titulo, por_que, correcao)


_REGRAS = [
    # ---------------- segredos ----------------
    _r("segredo-chave-privada", "alto", "Chave privada",
       "Uma chave privada publicada dá acesso a quem a copiar (servidores, assinatura de apps, certificados).",
       "Revogue/gere uma chave nova (a antiga deve ser considerada comprometida) e remova o arquivo. Guarde chaves fora do repositório."),
    _r("segredo-aws", "alto", "Chave de acesso da AWS",
       "Robôs varrem o GitHub o tempo todo atrás de chaves da AWS; abusos costumam acontecer em minutos.",
       "Desative a chave no console da AWS agora, crie outra e use variáveis de ambiente ou um gerenciador de segredos."),
    _r("segredo-github", "alto", "Token do GitHub",
       "O token dá acesso à sua conta ou aos seus repositórios, conforme as permissões dele.",
       "Revogue o token em Settings > Developer settings, crie outro com o mínimo de permissões e não o versione."),
    _r("segredo-google", "alto", "Chave de API do Google",
       "A chave pode ser usada por terceiros às suas custas e com a sua cota.",
       "Restrinja ou apague a chave no Google Cloud Console e gere uma nova, com restrição de origem/API."),
    _r("segredo-slack", "alto", "Token do Slack",
       "Dá acesso a mensagens e dados do workspace.",
       "Revogue o token no Slack e gere outro. Não o versione."),
    _r("segredo-stripe", "alto", "Chave secreta do Stripe",
       "Permite operar pagamentos da sua conta.",
       "Faça o rolling da chave no painel do Stripe e use variáveis de ambiente."),
    _r("segredo-ia", "alto", "Chave de API de provedor de IA",
       "Terceiros podem gastar seus créditos e acessar seus dados.",
       "Revogue a chave no painel do provedor, crie outra e use variável de ambiente."),
    _r("segredo-url-credenciais", "alto", "Credenciais dentro de uma URL",
       "Usuário e senha embutidos em URLs (banco, FTP, git) ficam visíveis a quem ler o repositório.",
       "Troque a senha, e passe usuário e senha por variáveis de ambiente, não pela URL."),
    _r("segredo-atribuicao", "medio", "Senha ou segredo escrito no arquivo",
       "Uma senha, token ou chave aparece como valor literal. Se for real, qualquer pessoa pode usá-la.",
       "Se for real: troque-a e leia o valor de uma variável de ambiente. Se for só um exemplo, use um marcador óbvio (ex.: troque-esta-senha) ou adicione 'ppc:ignore' na linha."),
    _r("segredo-valor-forte", "alto", "Valor com cara de segredo real",
       "O valor é longo e aleatório e está ligado a um nome como senha/token/chave: tem aparência de credencial verdadeira.",
       "Considere o valor comprometido: troque-o, e leia de variável de ambiente daqui para a frente."),
    _r("segredo-hash-senha", "medio", "Hash de senha (bcrypt)",
       "Hashes de senha publicados permitem ataques de força bruta offline contra a senha de alguém.",
       "Remova o hash do código/dados. Se a senha for usada em algum lugar, troque-a. Em dumps de banco, use dados fictícios."),
    # ---------------- dados pessoais ----------------
    _r("pii-cpf", "alto", "CPF",
       "O CPF é dado pessoal sensível no Brasil (LGPD) e facilita fraudes de identidade.",
       "Remova o CPF e use dados fictícios. Em repositório público, nunca publique CPF real."),
    _r("pii-cnpj", "baixo", "CNPJ",
       "CNPJ de empresa costuma ser público, mas de MEI é ligado a uma pessoa física.",
       "Confira se pode ser público; se não, remova."),
    _r("pii-email", "medio", "Endereço de e-mail",
       "E-mails publicados são coletados para spam e phishing, e podem ser de terceiros (colegas, clientes).",
       "Use endereços fictícios (@example.com) em dados de exemplo. Se for o seu e-mail de contato e você quer deixá-lo público, adicione 'email:<endereço>' no .ppcignore."),
    _r("pii-telefone", "medio", "Número de telefone",
       "Telefone é dado pessoal e serve a golpes e assédio.",
       "Use números fictícios nos exemplos e remova os reais."),
    _r("pii-nome-completo", "medio", "Nome completo de pessoa",
       "Nome completo de colegas, clientes ou alunos publicado sem autorização expõe terceiros.",
       "Use só o primeiro nome, apelidos ou nomes fictícios, ou obtenha autorização de cada pessoa."),
    _r("pii-lista-de-pessoas", "medio", "Lista de pessoas",
       "O arquivo parece listar nomes completos de integrantes, alunos ou colegas.",
       "Deixe só o primeiro nome (ou o que cada pessoa autorizar) e confira se o arquivo precisa ir para o repositório."),
    _r("pii-foto-pessoas", "medio", "Possíveis fotos de pessoas",
       "Imagens em pastas como avatars/fotos/equipe costumam ser de pessoas; publicar sem autorização expõe imagem de terceiros.",
       "Confirme a autorização de cada pessoa ou troque por ilustrações próprias ou livres."),
    # ---------------- arquivos ----------------
    _r("arquivo-env", "alto", "Arquivo de variáveis de ambiente (.env)",
       "Arquivos .env guardam senhas, tokens e chaves.",
       "Remova do repositório, adicione ao .gitignore e publique só um .env.example com marcadores."),
    _r("arquivo-chave-privada", "alto", "Arquivo de chave ou certificado",
       "Chaves, keystores e certificados com chave privada não devem ser públicos (ex.: assinatura de apps Android).",
       "Remova, revogue/gere outro e guarde fora do repositório; adicione o padrão ao .gitignore."),
    _r("arquivo-credenciais", "alto", "Arquivo de credenciais",
       "O arquivo costuma conter segredos de serviços (contas de serviço, estado do Terraform, tokens).",
       "Remova, revogue as credenciais e adicione o padrão ao .gitignore."),
    _r("arquivo-banco", "medio", "Arquivo de banco de dados",
       "Bancos e dumps frequentemente contêm dados reais de usuários.",
       "Publique só o esquema (migrações) e dados fictícios. Confira o conteúdo antes de qualquer coisa."),
    _r("arquivo-documento", "baixo", "Documento (PDF, Word, Excel, PowerPoint)",
       "Documentos podem ser material de terceiros (apostilas, provas, enunciados) ou conter dados pessoais.",
       "Confirme que o material é seu e pode ser publicado; do contrário, remova."),
    _r("arquivo-binario", "baixo", "Binário versionado (APK, EXE, JAR, ZIP...)",
       "Binários inflam o repositório, não podem ser revisados e às vezes embutem segredos ou material de terceiros.",
       "Prefira publicar em GitHub Releases e gerar o binário a partir do código."),
    _r("arquivo-pesado", "baixo", "Arquivo muito grande",
       "Arquivos grandes deixam o clone lento e ficam para sempre no histórico.",
       "Use Git LFS ou publique em Releases; mantenha o repositório leve."),
    _r("arquivo-ferramenta", "baixo", "Arquivo de ferramenta ou de sistema",
       "Pastas de IDE, atalhos e arquivos do sistema são ruído e podem vazar caminhos e configurações locais.",
       "Remova e adicione ao .gitignore."),
    _r("arquivo-log", "baixo", "Arquivo de log",
       "Logs frequentemente têm dados pessoais, tokens e caminhos internos.",
       "Remova e adicione *.log ao .gitignore."),
    # ---------------- conteúdo ----------------
    _r("caminho-local", "baixo", "Caminho do seu computador",
       "O caminho expõe o seu nome de usuário e faz o projeto funcionar só na sua máquina.",
       "Use caminhos relativos ou a pasta do próprio script/projeto."),
    _r("licenca-restricao", "alto", "Material com restrição de redistribuição",
       "Um arquivo de créditos ou licença diz que o material não pode ser redistribuído. Publicar o repositório é redistribuir.",
       "Remova o material do repositório público, troque por algo livre/seu, ou peça autorização. Documente como obter o original."),
    _r("placeholder-esquecido", "baixo", "Marcador de exemplo esquecido",
       "Links e domínios de exemplo (seu-dominio, SEU_LINK) ficam quebrados ou apontam para lugar errado.",
       "Troque pelo valor real ou remova."),
    # ---------------- repositório ----------------
    _r("repo-sem-readme", "baixo", "Repositório sem README",
       "Sem README ninguém entende o que o projeto é nem como rodá-lo.",
       "Adicione um README com o que é, como rodar e o estado do projeto."),
    _r("repo-sem-licenca", "info", "Repositório sem licença",
       "Sem licença, o código é 'todos os direitos reservados': pode ser visto, mas não reutilizado.",
       "Se quiser permitir reuso, adicione uma licença (ex.: MIT). Se não, tudo bem: é uma decisão sua."),
    # ---------------- histórico ----------------
    _r("historico-arquivo-sensivel", "alto", "Arquivo sensível que já esteve no histórico",
       "O arquivo foi removido, mas continua acessível em commits antigos: apagar não o tira do GitHub.",
       "Trate o conteúdo como vazado (troque senhas/chaves). Para publicar sem ele: crie um repositório novo com histórico limpo ou reescreva o histórico (git filter-repo) e faça push forçado."),
    _r("historico-segredo", "alto", "Segredo ou dado pessoal em commit antigo",
       "O valor foi removido do código atual, mas continua no histórico e pode ser recuperado por qualquer pessoa.",
       "Trate como vazado (troque/revogue). Para publicar limpo: repositório novo sem o histórico, ou git filter-repo + push forçado."),
    _r("historico-email-autor", "baixo", "E-mail pessoal nos commits",
       "O e-mail de autor dos commits fica público no repositório.",
       "Use o e-mail noreply do GitHub (Settings > Emails) em git config user.email; commits antigos continuam como estão."),
]

REGRAS: Dict[str, Regra] = {r.id: r for r in _REGRAS}


def regra(id_: str) -> Regra:
    return REGRAS[id_]
