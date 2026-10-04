"""
©AngelaMos | 2026
Copyright (C) 2026 Murilo Miacci
test_hash_identifier.py

Testes para o hash_identifier — focado nos casos mais utilizados

────────────────────────────────────────────────────────────────────
O que são "testes" e por que os escrevemos
────────────────────────────────────────────────────────────────────
Um teste é uma pequena função Python que chama nosso código real com uma
entrada conhecida e então AFIRMA (assert) que o resultado é o que esperávamos.
Se a afirmação falhar, o pytest imprime uma mensagem vermelha de FALHA — o que
significa que mudamos algo e quebramos um comportamento que nos importava.

Testes são um seguro. A primeira vez que você escreve o código, o teste
apenas confirma que ele funciona. Mas seis meses depois, quando você refatorar
ou adicionar um novo recurso, os testes existentes capturam qualquer quebra
acidental. É por isso que toda base de código sênior tem testes: não porque
o código é difícil de escrever, mas porque o código é difícil de manter
FUNCIONANDO ao longo do tempo.

────────────────────────────────────────────────────────────────────
O formato de um teste pytest
────────────────────────────────────────────────────────────────────
  def test_<o_que_estamos_verificando>() -> None:
      result = some_function(some_input)
      assert result == expected

Três regras:
  1. O nome da função deve começar com `test_` — o pytest apenas coleta
     funções que correspondem a esse padrão.
  2. A função não recebe argumentos (a menos que use fixtures).
  3. Use a palavra-chave `assert` para declarar o que deve ser verdadeiro.
     Se a condição for falsa, o teste falha.

Seguimos a estrutura "Arrange-Act-Assert" (Organizar-Agir-Afirmar) em cada teste:
  - Arrange: configurar as entradas (a linha `sample = ...`).
  - Act:     chamar o código real (`candidates = identify(sample)`).
  - Assert:  verificar o resultado (`assert candidates[0]...`).

────────────────────────────────────────────────────────────────────
Estratégia de cobertura
────────────────────────────────────────────────────────────────────
NÃO tentamos testar todos os algoritmos da tabela — isso resultaria em
centenas de testes quase idênticos. Em vez disso, exercitamos cada RAMO (branch)
do identify() pelo menos uma vez:

  - correspondências de prefixo (um bcrypt, um Argon2id, um Django, um crypt)
  - formato especial MySQL5
  - correspondências de comprimento hex (comprimentos MD5, SHA-1, SHA-256)
  - os fallbacks para vazio / lixo / espaços em branco
  - a imutabilidade do HashCandidate

Juntos, eles nos dão a confiança de que cada caminho de código executa sem
erros críticos e que as entradas mais comuns produzem o candidato esperado
no topo do ranking.
"""

# Importar de `hash_identifier` (NÃO `hash_identifier.py`) diz ao Python
# para carregar o módulo que vive neste mesmo diretório. Extraímos três coisas:
#   - `identify`     — a função sob teste
#   - `HashCandidate`— a dataclass do tipo de retorno (usada no teste de imutabilidade)
#   - `PREFIX_RULES` — a tabela de busca de prefixos (usada pelo teste
#                      parametrizado "every row is covered" no final deste arquivo)

# Terceiros: o próprio executor de testes. Também precisamos importá-lo aqui
# para podermos usar seu decorador `@pytest.mark.parametrize` abaixo.
import pytest

# Local: nosso próprio módulo. Extraímos as peças públicas sob teste —
# a tabela de regras de prefixo, a dataclass de resultado e a função de entrada.
from hash_identifier import PREFIX_RULES, HashCandidate, identify
import io
import sys
import json
import base64

import hash_identifier

# =============================================================================
# Correspondências de prefixo (alta confiança)
# =============================================================================
# Estes testes verificam o Passo 1 do identify(): quando a entrada começa com um
# prefixo conhecido, relatamos ALTA confiança. A carga útil (payload) exata do
# hash após o prefixo não importa para o identify() — ele apenas inspeciona os
# caracteres iniciais.


def test_bcrypt_prefix_is_recognized() -> None:
    """
    Um hash bcrypt real começa com `$2b$` e deve ser relatado como bcrypt
    """
    # Exemplo: um hash bcrypt real para a senha "password" com custo 12.
    # A parte interessante para o nosso teste é apenas o `$2b$` — nós nem
    # sequer decodificamos o resto.
    sample = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G"

    # Chama a função sob teste. `candidates` é uma lista de HashCandidate.
    candidates = identify(sample)

    # Primeiro afirma que a lista não está vazia. `assert <coisa>` falha quando
    # <coisa> é avaliada como falsa — listas vazias são falsas, então isso
    # captura o bug de "nenhum candidato retornado".
    assert candidates
    # Em seguida, verifica se o PRIMEIRO candidato (palpite de maior prioridade) é bcrypt.
    # `candidates[0]` é o primeiro item; `.algorithm` é o campo que verificamos.
    assert candidates[0].algorithm == "bcrypt"
    # E a confiança deve ser "high" — correspondências de prefixo são definitivas.
    assert candidates[0].confidence_score == pytest.approx(0.95)


def test_argon2id_prefix_is_recognized() -> None:
    """
    Strings PHC Argon2id começam com `$argon2id$`
    """
    # Formato PHC para Argon2id: $argon2id$v=<versao>$m=...,t=...,p=...$<salt>$<hash>
    sample = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA"
    candidates = identify(sample)
    # `any(...)` retorna True se pelo menos um elemento do iterável tornar a
    # expressão interna verdadeira. Verificamos se PELO MENOS UM candidato
    # é Argon2id — usar any() em vez de [0] mantém o teste robusto se algum
    # dia adicionarmos um segundo palpite ao mesmo prefixo.
    assert any(c.algorithm == "Argon2id" for c in candidates)


def test_sha512_crypt_prefix_is_recognized() -> None:
    """
    `$6$` é o marcador para SHA-512 crypt — o que o /etc/shadow usa no Linux
    """
    sample = "$6$rounds=10000$salt$hashedpasswordhere"
    candidates = identify(sample)
    # `[0]` porque queremos o candidato do TOPO. Se qualquer outra coisa fosse
    # classificada em primeiro, esta afirmação falharia ruidosamente.
    assert candidates[0].algorithm == "SHA-512 crypt"


def test_django_pbkdf2_prefix_is_recognized() -> None:
    """
    O Django armazena senhas como `pbkdf2_sha256$<iter>$<salt>$<hash>`
    """
    sample = "pbkdf2_sha256$260000$salt$hash"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Django PBKDF2-SHA256"


def test_apr1_prefix_is_recognized() -> None:
    """
    Hashes MD5 do Apache `.htpasswd` começam com $apr1$

    A ferramenta htpasswd gera estes por padrão com a flag `-m`.
    Mesma família MD5 do formato Unix $1$, mas com a manipulação de salt
    própria do Apache — e MUITO mais comum no mundo real.
    """
    # Hash apr1 com aparência real. A carga útil após o segundo `$` é a
    # codificação estilo base64 do digest MD5 + salt.
    # identify() nunca o decodifica — apenas o `$apr1$` inicial importa.
    sample = "$apr1$rsalt$mp7TYYDvbgvNCJN3JTd6q1"
    candidates = identify(sample)
    assert candidates[0].algorithm == "Apache MD5-crypt"
    assert candidates[0].confidence_score == pytest.approx(0.95)


def test_macos_prefix_is_recognized() -> None:
    """
    Hashes MacOS / iCloud Keychain começa, com $ml$
    """

    sample = '$ml$<iterações>$<salt hexadecimal>$<resultado hexadecimal>'
    candidates = identify(sample)
    assert candidates[0].algorithm == 'Apple PBKDF2-SHA512'
    assert candidates[0].confidence_score == pytest.approx(0.95)


# =============================================================================
# Formatos especiais
# =============================================================================
# Passo 2 do identify(): formatos que NÃO são strings PHC, mas ainda têm
# formatos inconfundíveis. Hoje reconhecemos NetNTLMv1, NetNTLMv2 e
# MySQL5 — três registros estruturalmente distintos.


def test_mysql5_format_is_recognized() -> None:
    """
    MySQL5 = literal `*` seguido por 40 caracteres hex maiúsculos

    O MySQL5 armazena SHA-1(SHA-1(senha)) impresso em hex maiúsculo com
    um asterisco inicial. Portanto, o hash todo tem exatamente 41 caracteres.
    """
    # O * importa — sem ele, seriam apenas 40 caracteres hex e cairia
    # na regra de comprimento do SHA-1.
    sample = "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257"
    candidates = identify(sample)

    # MySQL5 é um formato definitivo, então esperamos confiança ALTA (high).
    assert candidates[0].algorithm == "MySQL5"
    assert candidates[0].confidence_score == pytest.approx(0.85)


def test_mysql5_rejects_lowercase_body() -> None:
    """
    Hex minúsculo após o `*` inicial não é uma saída real do MySQL5

    O MySQL emite maiúsculas via `%02X`, então um `*` seguido por hex
    minúsculo é quase certamente lixo editado manualmente. Preferimos
    não retornar nada do que retornar uma resposta ERRADA com confiança.
    """
    # Versão minúscula do corpo do teste anterior. O `*` inicial é a única
    # coisa que compartilha com a saída real do MySQL5.
    lowercase_body = "23ae809ddacaf96af0fd78ed04b6a265e05aa257"
    candidates = identify("*" + lowercase_body)

    # Ou a lista está vazia (preferencial) OU o que quer que tenha
    # correspondido NÃO deve ser rotulado como MySQL5.
    if candidates:
        assert candidates[0].algorithm != "MySQL5"


def test_netntlmv2_format_is_recognized() -> None:
    """
    Registros NetNTLMv2 do Responder parecem com
    `usuario::dominio:desafio:hmac:blob`

    O campo hmac tem exatamente 32 caracteres hex. O `::` inicial é a
    pista de que este é um registro de desafio-resposta do AD.
    """
    # Constrói um registro NetNTLMv2 realista:
    #   alice :: CORP : <desafio de 16 chars> : <hmac de 32 hex> : <blob de 64 hex>
    sample = "alice::CORP:1122334455667788:" + "a" * 32 + ":" + "b" * 64
    candidates = identify(sample)

    # NetNTLMv2 é um formato definitivo — confiança ALTA (high).
    assert candidates[0].algorithm == "NetNTLMv2"
    assert candidates[0].confidence_score == pytest.approx(0.85)


def test_netntlmv1_format_is_recognized() -> None:
    """
    Registros NetNTLMv1 têm lmhash E nthash de 48 caracteres hex antes do desafio

    Layout: `usuario::dominio:lm(48 hex):nt(48 hex):desafio`.
    """
    sample = "alice::CORP:" + "a" * 48 + ":" + "b" * 48 + ":1122334455667788"
    candidates = identify(sample)
    assert candidates[0].algorithm == "NetNTLMv1"
    assert candidates[0].confidence_score == pytest.approx(0.85)


def test_descrypt_format_is_recognized() -> None:
    """
    O DES crypt tradicional NÃO possui prefixo — apenas o comprimento e o charset o identificam

    Arquivos /etc/passwd legados usavam este formato: 13 caracteres extraídos
    do alfabeto `./0-9A-Za-z`.
    """
    sample = "kRq14pmccuMOA"
    candidates = identify(sample)

    assert candidates[0].algorithm == "DES crypt"
    # Confiança MÉDIA (medium) porque uma string de 13 caracteres nesse charset
    # PODE tecnicamente ser outras coisas.
    assert candidates[0].confidence_score == pytest.approx(0.85)


# =============================================================================
# Correspondências de comprimento hex (confiança média / baixa)
# =============================================================================
# Passo 3 do identify(): quando a entrada é hex puro, o comprimento estreita
# o algoritmo. O PRIMEIRO algoritmo listado para cada comprimento recebe
# confiança média; o restante é baixa.


def test_mysql323_length_returns_mysql323_first() -> None:
    """
    16 caracteres hex apontam para MySQL323 (saída OLD_PASSWORD legada do MySQL)
    """
    sample = "5d2e19393cc5ef67"
    candidates = identify(sample)

    # MySQL323 fica ACIMA de CRC-64 porque em um contexto de segurança,
    # o MySQL323 é de longe a fonte mais provável.
    assert candidates[0].algorithm == "MySQL323"
    assert candidates[0].confidence_score == pytest.approx(0.60)


def test_md5_length_returns_md5_first() -> None:
    """
    32 caracteres hex correspondem a MD5, NTLM, MD4, RIPEMD-128

    MD5 é DE LONGE o hash de 32 hex mais comum, então deve ser o primeiro.
    """
    # O MD5 literal da string "password".
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)

    # O principal candidato é MD5.
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].confidence_score == pytest.approx(0.60)

    # NTLM deve aparecer na lista de candidatos como uma opção menos provável.
    algorithms = [c.algorithm for c in candidates]
    assert "NTLM" in algorithms


def test_hex_candidate_scores_decrease_by_position() -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)

    assert len(candidates) >= 3

    assert candidates[0].confidence_score == pytest.approx(0.55 / 1 + 0.05)
    assert candidates[1].confidence_score == pytest.approx(0.55 / 2 + 0.05)
    assert candidates[2].confidence_score == pytest.approx(0.55 / 3 + 0.05)

    assert (candidates[0].confidence_score > candidates[1].confidence_score >
            candidates[2].confidence_score)


def test_sha256_length_returns_sha256_first() -> None:
    """
    64 caracteres hex apontam para SHA-256 primeiro
    """
    # `"a" * 64` é um atalho Python para repetir o caractere 'a' 64 vezes.
    sample = "a" * 64
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-256"


def test_sha1_length_returns_sha1_first() -> None:
    """
    40 caracteres hex = SHA-1 (RIPEMD-160 como palpite secundário)
    """
    sample = "a" * 40
    candidates = identify(sample)
    assert candidates[0].algorithm == "SHA-1"


# =============================================================================
# Casos de não correspondência / borda
# =============================================================================
# Sempre teste os casos de borda entediantes: entradas vazias, apenas espaços, lixo.


def test_empty_input_returns_no_candidates() -> None:
    """
    String vazia retorna uma lista vazia — nunca quebra
    """
    assert identify("") == []
    assert identify("   ") == []


def test_garbage_returns_no_candidates() -> None:
    """
    Uma string que não tem prefixo conhecido nem formato hex retorna []
    """
    assert identify("olá, isso não é um hash") == []


def test_input_is_trimmed_of_whitespace() -> None:
    """
    Quebras de linha e espaços iniciais não devem impedir o reconhecimento

    Isso importa porque copiar e colar de um terminal costuma trazer espaços.
    """
    sample = "   5f4dcc3b5aa765d61d8327deb882cf99\n"
    candidates = identify(sample)
    # Se o trim funcionar, ainda reconhecemos o MD5 apesar do ruído ao redor.
    assert candidates[0].algorithm == "MD5"


# =============================================================================
# Fallbacks de correspondência suave (dicas de formato, confiança BAIXA)
# =============================================================================
# Passos 4 e 5 do identify(): quando nada nas tabelas anteriores dispara,
# tentamos duas correspondências suaves — formato genérico de string PHC e
# "isso parece um JWT / blob base64". Ambos retornam confiança BAIXA (low).


def test_unknown_phc_string_falls_back_to_generic() -> None:
    """
    Uma string PHC de um algoritmo para o qual não temos uma regra específica
    ainda é relatada como string PHC com o nome do algoritmo extraído.
    """
    # Codificação PHC pbkdf2-sha512 do Passlib. Não temos regra específica para
    # ela em PREFIX_RULES — mas o formato `$pbkdf2-sha512$...` é inequívoco.
    sample = "$pbkdf2-sha512$25000$cnNhbHQ$aGFzaA"
    candidates = identify(sample)

    assert candidates
    # A coluna de algoritmo deve dizer "PHC string (pbkdf2-sha512)".
    assert "PHC" in candidates[0].algorithm
    assert "pbkdf2-sha512" in candidates[0].algorithm
    assert candidates[0].confidence_score == pytest.approx(0.85)


def test_jwt_input_is_called_out_as_not_a_hash() -> None:
    """
    JWTs começam com `eyJ` e devem ser sinalizados como não-hash

    Iniciantes costumam colar JWTs em identificadores de hash. Dizer "isso é
    um JWT, não um hash" é mais útil do que o silêncio.
    """
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig"
    candidates = identify(sample)

    assert candidates
    assert "JWT" in candidates[0].algorithm
    assert candidates[0].confidence_score == pytest.approx(0.30)


def test_base64_blob_is_called_out_as_not_a_hash() -> None:
    """
    Uma string contendo caracteres exclusivos de base64 (`+`, `/`, `=`) não é hex
    """
    sample = "VGhpcyBpcyBub3QgYSBoYXNoLCBpdHMgYmFzZTY0Lg=="
    candidates = identify(sample)

    assert candidates
    assert "Base64" in candidates[0].algorithm


# =============================================================================
# HashCandidate é imutável
# =============================================================================
# Declaramos HashCandidate com @dataclass(frozen=True). Frozen significa
# que você não pode reatribuir campos após a construção.


def test_hash_candidate_is_frozen() -> None:
    """
    Tentar mudar um HashCandidate deve gerar um erro
    """
    candidate = HashCandidate(algorithm="MD5",
                              confidence_score=0.6,
                              reason="test",
                              crack_difficulty='hard')

    # try/except é a sintaxe do Python para "proteger contra um erro".
    try:
        # `# type: ignore[misc]` diz ao mypy: "Eu sei que isso é um erro de tipo;
        # estou fazendo de propósito para verificar se realmente falha na execução"
        candidate.algorithm = "SHA-1"  # type: ignore[misc]
    except (AttributeError, TypeError):
        # Recebeu a exceção esperada — o teste passa.
        return

    # Se chegarmos aqui, nenhuma exceção foi lançada — o frozen está quebrado.
    raise AssertionError(
        "HashCandidate deveria estar congelado (frozen); a atribuição deveria ter falhado"
    )


# =============================================================================
# Cobertura abrangente da tabela PREFIX_RULES
# =============================================================================
# Este último teste garante que CADA linha de PREFIX_RULES seja exercitada,
# para que um erro de digitação em qualquer linha falhe seu próprio caso de teste.
#
# `@pytest.mark.parametrize(name, values)` é o mecanismo do pytest para
# expandir UMA função de teste em MUITOS casos de teste.


@pytest.mark.parametrize("prefix,algorithm,_note", PREFIX_RULES)
def test_every_prefix_rule_is_recognized_with_high_confidence(
    prefix: str,
    algorithm: str,
    _note: str,
) -> None:
    """
    Cada entrada em PREFIX_RULES produz um candidato de ALTA confiança
    com o algoritmo correspondente quando seu prefixo está no início da entrada.
    """
    sample = prefix + "corpofakequenaoimporta"
    candidates = identify(sample)

    # Se o identify() não retornar nada, o ramo do loop de prefixos está
    # quebrado — falha com uma mensagem que nomeia o prefixo problemático.
    assert candidates, f"nenhum candidato retornado para o prefixo `{prefix}`"
    assert candidates[0].algorithm == algorithm
    assert candidates[0].confidence_score == pytest.approx(0.95)


def test_json_output_contains_input_and_candidates(
    monkeypatch,
    capsys,
) -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--json", sample],
    )

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out

    data = json.loads(output)

    assert exit_code == 0
    assert data["input"] == sample
    assert isinstance(data["candidates"], list)
    assert data["candidates"]
    assert data["candidates"][0]["algorithm"] == "MD5"


def test_json_top_limits_candidates(
    monkeypatch,
    capsys,
) -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--json", "--top", "2", sample],
    )

    exit_code = hash_identifier.main()
    data = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(data["candidates"]) == 2


def test_file_produces_one_json_line_per_hash(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    first_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    second_hash = "e10adc3949ba59abbe56e057f20f883e"

    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text(
        f"{first_hash}\n{second_hash}\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--file", str(hashes_file)],
    )

    exit_code = hash_identifier.main()
    lines = capsys.readouterr().out.strip().splitlines()

    assert exit_code == 0
    assert len(lines) == 2

    first_result = json.loads(lines[0])
    second_result = json.loads(lines[1])

    assert first_result["input"] == first_hash
    assert second_result["input"] == second_hash


def test_stdin_produces_one_json_line_per_hash(
    monkeypatch,
    capsys,
) -> None:
    first_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    second_hash = "e10adc3949ba59abbe56e057f20f883e"

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(f"{first_hash}\n{second_hash}\n"),
    )
    monkeypatch.setattr(sys, "argv", ["hashid"])

    exit_code = hash_identifier.main()
    lines = capsys.readouterr().out.strip().splitlines()

    assert exit_code == 0
    assert len(lines) == 2
    assert json.loads(lines[0])["input"] == first_hash
    assert json.loads(lines[1])["input"] == second_hash


def test_single_stdin_hash_still_uses_json_lines(
    monkeypatch,
    capsys,
) -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(f"{sample}\n"),
    )
    monkeypatch.setattr(sys, "argv", ["hashid"])

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out.strip()
    data = json.loads(output)

    assert exit_code == 0
    assert data["input"] == sample


def test_file_ignores_blank_lines(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text(
        f"\n{sample}\n\n   \n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--file", str(hashes_file)],
    )

    exit_code = hash_identifier.main()
    lines = capsys.readouterr().out.strip().splitlines()

    assert exit_code == 0
    assert len(lines) == 1
    assert json.loads(lines[0])["input"] == sample


def test_hash_and_file_together_are_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text(
        "5f4dcc3b5aa765d61d8327deb882cf99\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hashid",
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "--file",
            str(hashes_file),
        ],
    )

    with pytest.raises(SystemExit) as error:
        hash_identifier.main()

    assert error.value.code == 2


@pytest.mark.parametrize(
    ("extra_arguments", "expected_calls"),
    [
        ([], 3),
        (["--cache"], 1),
    ],
)
def test_cache_controls_identify_calls(
    tmp_path,
    monkeypatch,
    capsys,
    extra_arguments: list[str],
    expected_calls: int,
) -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text(
        f"{sample}\n{sample}\n{sample}\n",
        encoding="utf-8",
    )

    original_identify = hash_identifier.identify
    call_count = 0

    def counted_identify(text: str) -> list[HashCandidate]:
        nonlocal call_count
        call_count += 1
        return original_identify(text)

    monkeypatch.setattr(
        hash_identifier,
        "identify",
        counted_identify,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hashid",
            "--file",
            str(hashes_file),
            *extra_arguments,
        ],
    )

    exit_code = hash_identifier.main()
    lines = capsys.readouterr().out.strip().splitlines()

    assert exit_code == 0
    assert len(lines) == 3
    assert call_count == expected_calls


def test_md5_includes_hashcat_mode() -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)

    assert candidates[0].algorithm == "MD5"
    assert candidates[0].hashcat_mode == 0


def test_bcrypt_includes_hashcat_mode() -> None:
    sample = ("$2b$12$EixZaYVK1fsbw1ZfbX3OXe"
              "PaWxn96p36WQNQy.uK4Of2T7G")
    candidates = identify(sample)

    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].hashcat_mode == 3200


def test_unknown_algorithm_has_no_hashcat_mode() -> None:
    sample = "$algoritmo-desconhecido$dados"
    candidates = identify(sample)

    assert candidates
    assert candidates[0].hashcat_mode is None


def test_json_includes_hashcat_mode(
    monkeypatch,
    capsys,
) -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--json", sample],
    )

    exit_code = hash_identifier.main()
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["candidates"][0]["hashcat_mode"] == 0


def test_candidate_without_mapping_has_none_mode() -> None:
    candidate = HashCandidate(algorithm="Algoritmo sem cadastro",
                              confidence_score=0.3,
                              reason="teste",
                              crack_difficulty='hard')

    assert candidate.hashcat_mode is None


def test_table_and_next_step_include_hashcat_mode(
    monkeypatch,
    capsys,
) -> None:
    sample = ("$2b$12$EixZaYVK1fsbw1ZfbX3OXe"
              "PaWxn96p36WQNQy.uK4Of2T7G")

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", sample],
    )

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "modo hashcat" in output
    assert "3200" in output
    assert "hashcat -m 3200 -a 0" in output


def test_hex_candidates_receive_hashcat_modes() -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"
    candidates = identify(sample)

    modes_by_algorithm = {
        candidate.algorithm: candidate.hashcat_mode
        for candidate in candidates
    }

    assert modes_by_algorithm["MD5"] == 0
    assert modes_by_algorithm["NTLM"] == 1000


@pytest.mark.parametrize(
    "sample",
    [
        "http://example.com",
        "https://example.com/login",
    ],
)
def test_url_is_recognized_as_not_a_hash(sample: str) -> None:
    candidates = identify(sample)

    assert candidates
    assert "URL" in candidates[0].algorithm
    assert candidates[0].confidence_score == pytest.approx(0.30)
    assert candidates[0].hashcat_mode is None


def test_url_marker_must_be_at_the_start() -> None:
    sample = "prefixo-https://example.com"

    candidates = identify(sample)

    assert not any("URL" in candidate.algorithm for candidate in candidates)


def test_word_starting_with_http_is_not_a_url() -> None:
    sample = "httpqualquercoisa"

    candidates = identify(sample)

    assert not any("URL" in candidate.algorithm for candidate in candidates)


def test_0x_with_non_hex_body_is_not_recognized_as_hex() -> None:
    sample = "0xisso-nao-e-hexadecimal"

    candidates = identify(sample)

    assert not any("0x" in candidate.algorithm for candidate in candidates)


def test_base58_input_is_recognized() -> None:
    sample = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

    candidates = identify(sample)

    assert candidates
    assert "Base58" in candidates[0].algorithm
    assert candidates[0].confidence_score == pytest.approx(0.30)
    assert candidates[0].hashcat_mode is None


@pytest.mark.parametrize(
    "forbidden_character",
    ["0", "O", "I", "l"],
)
def test_base58_rejects_forbidden_characters(
    forbidden_character: str, ) -> None:
    sample = ("123456789ABCDEFGHJKLMNPQRSTUVWXYZ" + forbidden_character)

    candidates = identify(sample)

    assert not any("Base58" in candidate.algorithm for candidate in candidates)


def test_short_base58_compatible_word_is_not_recognized() -> None:
    sample = "Pedro"

    candidates = identify(sample)

    assert not any("Base58" in candidate.algorithm for candidate in candidates)


def test_unpadded_base32_is_recognized() -> None:
    sample = "JBSWY3DPEHPK3PXP"

    candidates = identify(sample)

    assert candidates
    assert "Base32" in candidates[0].algorithm
    assert candidates[0].confidence_score == pytest.approx(0.30)
    assert candidates[0].hashcat_mode is None


def test_padded_base32_is_recognized() -> None:
    sample = base64.b32encode(b"this is a sufficiently long secret").decode(
        "ascii")

    candidates = identify(sample)

    assert candidates
    assert "Base32" in candidates[0].algorithm
    assert candidates[0].confidence_score == pytest.approx(0.30)


def test_base32_rejects_invalid_digit() -> None:
    sample = "JBSWY3DPEHPK3PX8"

    candidates = identify(sample)

    assert not any("Base32" in candidate.algorithm for candidate in candidates)


def test_base32_rejects_padding_in_the_middle() -> None:
    sample = "JBSWY3D=EHPK3PXP"

    candidates = identify(sample)

    assert not any("Base32" in candidate.algorithm for candidate in candidates)


def test_md5_is_not_misclassified_as_encoded_data() -> None:
    sample = "5f4dcc3b5aa765d61d8327deb882cf99"

    candidates = identify(sample)

    assert candidates
    assert candidates[0].algorithm == "MD5"
    assert "Base58" not in candidates[0].algorithm
    assert "Base32" not in candidates[0].algorithm


def test_base32_has_priority_over_base58() -> None:
    sample = "JBSWY3DPEHPK3PXP"

    candidates = identify(sample)

    assert candidates
    assert "Base32" in candidates[0].algorithm


def test_split_mode_classifies_single_record(
    monkeypatch,
    capsys,
) -> None:
    sample_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    record = f"alice:{sample_hash}:salt123"

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--split", record],
    )

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Análise dos campos" in output

    assert "alice" in output
    assert "usuário" in output

    assert "hash" in output
    assert "MD5" in output

    assert "salt123" in output
    assert "salt" in output


def test_split_mode_recognizes_empty_field(
    monkeypatch,
    capsys,
) -> None:
    record = "alice::salt123"

    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--split", record],
    )

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "alice" in output
    assert "vazio" in output
    assert "campo sem conteúdo" in output
    assert "salt123" in output


def test_split_mode_reads_multiple_records_from_file(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
    sha1_hash = "a" * 40

    records_file = tmp_path / "records.txt"
    records_file.write_text(
        f"alice:{md5_hash}:salt123\n"
        f"bob:{sha1_hash}:secret456\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "hashid",
            "--split",
            "--file",
            str(records_file),
        ],
    )

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out

    assert exit_code == 0

    assert "alice" in output
    assert "bob" in output

    assert "MD5" in output
    assert "SHA-1" in output

    assert "salt123" in output
    assert "secret456" in output


def test_split_mode_reads_records_from_stdin(
    monkeypatch,
    capsys,
) -> None:
    md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"

    fake_stdin = io.StringIO(f"alice:{md5_hash}:salt123\n"
                             f"bob:{md5_hash}:secret456\n")

    monkeypatch.setattr(
        sys,
        "stdin",
        fake_stdin,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["hashid", "--split"],
    )

    exit_code = hash_identifier.main()
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "alice" in output
    assert "bob" in output
    assert "salt123" in output
    assert "secret456" in output
    assert "MD5" in output


@pytest.mark.parametrize(
    ("field", "expected_classification"),
    [
        ("", "vazio"),
        ("alice", "usuário"),
        (
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "hash",
        ),
        ("salt123", "salt"),
        ("!!!", "garbage"),
    ],
)
def test_classify_field(
    field: str,
    expected_classification: str,
) -> None:
    classification, detail = (hash_identifier._classify_fields(field))

    assert classification == expected_classification
    assert isinstance(detail, str)
    assert detail


def test_s_recognizes_non_hash_format() -> None:
    classification, detail = (
        hash_identifier._classify_fields("https://example.com"))

    assert classification == "outro formato"
    assert "URL" in detail


def test_md5_has_trivial_crack_difficulty() -> None:
    candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99")

    assert candidates[0].algorithm == "MD5"
    assert candidates[0].crack_difficulty == "trivial"


def test_bcrypt_has_hard_crack_difficulty() -> None:
    sample = ("$2b$12$EixZaYVK1fsbw1ZfbX3OXe"
              "PaWxn96p36WQNQy.uK4Of2T7G")

    candidates = identify(sample)

    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].crack_difficulty == "hard"


def test_non_hash_has_no_crack_difficulty() -> None:
    candidates = identify("https://example.com")

    assert candidates
    assert candidates[0].crack_difficulty is None

@pytest.mark.parametrize(
    ("hash_value", "expected_difficulty"),
    [
        (
            "$2b$04$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuv",
            "moderate",
        ),
        (
            "$2b$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuv",
            "hard",
        ),
        (
            "$2b$14$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuv",
            "very_hard",
        ),
    ],
)
def test_bcrypt_dynamic_crack_difficulty(
    hash_value: str,
    expected_difficulty: str,
) -> None:
    candidates = identify(hash_value)

    assert candidates
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].crack_difficulty == expected_difficulty

@pytest.mark.parametrize(
    ("hash_value", "expected_difficulty"),
    [
        (
            "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA",
            "moderate",
        ),
        (
            "$argon2id$v=19$m=32768,t=2,p=2$c2FsdA$aGFzaA",
            "hard",
        ),
        (
            "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
            "very_hard",
        ),
    ],
)
def test_argon2_dynamic_crack_difficulty(
    hash_value: str,
    expected_difficulty: str,
) -> None:
    candidates = identify(hash_value)

    assert candidates
    assert candidates[0].algorithm == "Argon2id"
    assert candidates[0].crack_difficulty == expected_difficulty

@pytest.mark.parametrize(
    ("prefix", "expected_algorithm"),
    [
        ("argon2id", "Argon2id"),
        ("argon2i", "Argon2i"),
        ("argon2d", "Argon2d"),
    ],
)
def test_argon2_variants_use_dynamic_difficulty(
    prefix: str,
    expected_algorithm: str,
) -> None:
    hash_value = (
        f"${prefix}$v=19$m=65536,t=3,p=4$"
        "c2FsdA$aGFzaA"
    )

    candidates = identify(hash_value)

    assert candidates
    assert candidates[0].algorithm == expected_algorithm
    assert candidates[0].crack_difficulty == "very_hard"

def test_argon2_invalid_parameters_use_fallback() -> None:
    hash_value = "$argon2id$v=19$m=invalid,t=3,p=4$c2FsdA$aGFzaA"

    candidates = identify(hash_value)

    assert candidates
    assert candidates[0].algorithm == "Argon2id"
    assert candidates[0].crack_difficulty == "very_hard"

def test_non_dynamic_algorithm_uses_difficulty_table() -> None:
    candidates = identify("5f4dcc3b5aa765d61d8327deb882cf99")

    assert candidates
    assert candidates[0].algorithm == "MD5"
    assert candidates[0].crack_difficulty == "trivial"

def test_bcrypt_invalid_cost_uses_fallback() -> None:
    candidates = identify(
        "$2b$xx$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuv"
    )

    assert candidates
    assert candidates[0].algorithm == "bcrypt"
    assert candidates[0].crack_difficulty == "hard"

def test_bcrypt_reason_includes_cost() -> None:
    candidates = identify(
        "$2b$04$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuv"
    )

    assert "cost=4" in candidates[0].reason
    assert "padrão 12" in candidates[0].reason

def test_argon2_reason_includes_parameters() -> None:
    candidates = identify(
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
    )

    assert "m=65536,t=3,p=4" in candidates[0].reason
    assert "very_hard" in candidates[0].reason