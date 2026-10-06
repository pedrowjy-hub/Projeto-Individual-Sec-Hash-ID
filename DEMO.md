# Documentação de conclusão — Hash_ID

## Visão geral

O **Hash_ID** é uma ferramenta de linha de comando que identifica candidatos a algoritmos de hash usando prefixo, comprimento e conjunto de caracteres. Para cada candidato, apresenta uma justificativa e uma pontuação de confiança.

A ferramenta apoia a triagem técnica de hashes em contextos autorizados. Ela **não quebra hashes** nem recupera o conteúdo original; reconhecer um formato não comprova o algoritmo nem reverte um hash.

## Funcionamento comprovado

A ferramenta pode ser executada por `just run` ou pelo executável `hashid` do ambiente do projeto:

```bash
just run 5f4dcc3b5aa765d61d8327deb882cf99
just run '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK'
just run --json 5d41402abc4b2a76b9719d911017c592
just run --file hashes.txt --cache
cat hashes.txt | uv run hashid
just run --split 'usuario:salt123:5d41402abc4b2a76b9719d911017c592'
```

A CLI aceita uma entrada isolada, arquivos e `stdin`. O modo `--split` separa registros delimitados por `:` para classificar campos como usuário, salt e possível hash. O cache é opcional, funciona somente durante a execução e não persiste dados em disco.

### Saídas reais da ferramenta

Os resultados abaixo foram capturados ao executar os comandos no projeto.

Comando:

```bash
just run --json 5d41402abc4b2a76b9719d911017c592
```

Saída:

```json
{
  "input": "5d41402abc4b2a76b9719d911017c592",
  "candidates": [
    {
      "algorithm": "MD5",
      "confidence_score": 0.6000000000000001,
      "reason": "32 caracteres hex — candidato mais provável para este comprimento",
      "crack_difficulty": "trivial",
      "hashcat_mode": 0
    },
    {
      "algorithm": "NTLM",
      "confidence_score": 0.325,
      "reason": "32 caracteres hex — também possível para este comprimento",
      "crack_difficulty": "trivial",
      "hashcat_mode": 1000
    },
    {
      "algorithm": "MD4",
      "confidence_score": 0.23333333333333334,
      "reason": "32 caracteres hex — também possível para este comprimento",
      "crack_difficulty": "trivial",
      "hashcat_mode": null
    },
    {
      "algorithm": "RIPEMD-128",
      "confidence_score": 0.1875,
      "reason": "32 caracteres hex — também possível para este comprimento",
      "crack_difficulty": null,
      "hashcat_mode": null
    }
  ]
}
```

A saída demonstra uma decisão importante: uma string hexadecimal de 32 caracteres pode representar mais de um algoritmo. Por isso, a ferramenta mostra candidatos e seus níveis de confiança, sem declarar uma certeza indevida.

Comando:

```bash
just run 'http://exemplo.com:8080/recurso'
```

Saída:

```text
                Candidatos para: http://exemplo.com:8080/recurso
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ algoritmo           ┃ confiança ┃ dificuldade ┃ modo hashcat ┃ motivo        ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ URL (não é um hash) │ 30% (low) │ —           │ —            │ começa com    │
│                     │           │             │              │ http:// ou    │
│                     │           │             │              │ https://      │
└─────────────────────┴───────────┴─────────────┴──────────────┴───────────────┘
```

Esse resultado comprova a prevenção de falsos positivos: uma URL não recebe uma classificação enganosa como hash.

## Validação automatizada

```bash
just test
```

Resultado registrado: **109 testes aprovados**. A suíte cobre formatos por prefixo e comprimento, JSON, arquivo, `stdin`, cache, modo Hashcat, `--split`, falsos positivos e estimativa de dificuldade.

A verificação `just lint` também pode ser executada. No estado atual, ela aponta um aviso de depreciação de `argparse.FileType`, item técnico a acompanhar, sem afetar os testes funcionais aprovados.

## Conhecimento aplicado na implementação

A classificação utiliza sinais de especificidade diferente:

1. **Prefixos:** bcrypt (`$2b$`), Argon2id (`$argon2id$`) e Apache MD5-crypt (`$apr1$`) possuem marcadores característicos e recebem maior confiança.
2. **Comprimento e hexadecimal:** sequências de 32 ou 64 caracteres permitem sugerir MD5 ou SHA-256, embora possam ser ambíguas.
3. **Conjunto de caracteres e formato:** regras complementares diferenciam hashes de URLs, JWTs e outros conteúdos codificados.
4. **Parâmetros internos:** bcrypt e Argon2 têm seus parâmetros lidos para estimar a dificuldade de quebra de modo contextualizado.

## Decisões técnicas e justificativas

| Decisão | Justificativa |
| --- | --- |
| Pipeline por prefixo, comprimento e charset | Prioriza padrões específicos e mantém as regras fáceis de auditar e ampliar. |
| Múltiplos candidatos com confiança | Representa a ambiguidade real de formatos iguais e evita conclusões incorretas. |
| Saída em tabela e JSON | Atende à leitura humana no terminal e à integração com scripts. |
| Entrada por argumento, arquivo e `stdin` | Permite tanto consultas isoladas quanto análise em lote. |
| `--split` para registros delimitados | Evita tratar usuário, salt e hash como uma única credencial. |
| Cache somente em memória | Reduz trabalho repetido sem persistir material possivelmente sensível. |
| Modos Hashcat como orientação | Oferece uma pista para auditorias autorizadas, que ainda exigem confirmação do algoritmo. |
| Testes de falsos positivos | Evita classificar URLs, JWTs, Base32/Base58 e texto comum como hashes. |

## Limitações, uso responsável e aprendizado compartilhável

A ferramenta infere o formato da entrada; ela não determina com certeza o algoritmo quando representações são iguais, nem confirma a origem de um hash. Qualquer auditoria deve ocorrer com autorização explícita e dentro do escopo permitido.

Os principais aprendizados que podem ser compartilhados são:

- Hash não é criptografia reversível: reconhecer um padrão não revela o conteúdo original.
- Prefixo, comprimento e conjunto de caracteres são os sinais centrais da classificação.
- A confiança depende da qualidade da evidência; formatos ambíguos exigem mais de um candidato.
- Prevenir falsos positivos é tão importante quanto reconhecer formatos conhecidos.
- Toda nova regra deve documentar seu padrão e limites, além de incluir testes automatizados para evitar regressões.

Com esta documentação, outro membro consegue repetir os comandos, observar as saídas reais e compreender as decisões que orientaram a implementação.
