<div align="center">

# MailAuth Drift

### Offline policy regression engine for SPF · DMARC (RFC 9989) · MTA-STS

[![CI](https://github.com/felipewatter/mailauth-drift/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/mailauth-drift/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Offline](https://img.shields.io/badge/Runtime-offline-blue)](docs/THREAT_MODEL.md)
[![SARIF](https://img.shields.io/badge/Reports-SARIF%202.1.0-8A2BE2)](docs/ARCHITECTURE.md)

**[Arquitetura](docs/ARCHITECTURE.md) · [Semântica e regras](docs/SEMANTICS.md) · [Modelo de ameaças](docs/THREAT_MODEL.md) · [Segurança](SECURITY.md) · [Exemplos](examples/)**

Projeto de segurança defensiva / DevSecOps de **Felipe Watter** · [GitHub](https://github.com/felipewatter)

</div>

> **Estado: v0.1.0 (experimental, sem auditoria independente).** O projeto não consulta DNS público, não faz requisições HTTP, não usa credenciais, não valida assinaturas DKIM e não executa o algoritmo completo de SPF ou DMARC. Recebe *snapshots* locais de políticas. Seus resultados são sinais de revisão, **não provas de exploração ou de conformidade**.

## Sumário

1. [Problema e proposta](#1-problema-e-proposta)
2. [Recursos implementados](#2-recursos-implementados)
3. [Instalação](#3-instalação)
4. [Demonstração em 60 segundos](#4-demonstração-em-60-segundos)
5. [Formato de snapshot](#5-formato-de-snapshot)
6. [Comandos](#6-comandos)
7. [Modelo analítico e limites](#7-modelo-analítico-e-limites)
8. [Testes e CI](#8-testes-e-ci)
9. [Publicação e cadeia de confiança](#9-publicação-e-cadeia-de-confiança)
10. [Segurança e contribuições](#10-segurança-e-contribuições)
11. [Referências e licença](#11-referências-e-licença)

## 1. Problema e proposta

Infraestruturas de e-mail dependem de registros TXT e políticas que podem mudar entre o deploy de ontem e o de hoje. Alterações aparentemente pequenas — trocar `-all` por `~all`, introduzir um `+all` numa dependência SPF, afrouxar a política DMARC ou desativar `MTA-STS` — nem sempre são rastreadas como **mudanças de segurança**. Ferramentas como [checkdmarc](https://github.com/domainaware/checkdmarc) são excelentes para verificação online de DNS; o MailAuth Drift cobre outro fluxo: **revisão determinística de snapshots versionados, sem resolver nomes nem contactar serviços**.

O programa lê duas versões de configurações declaradas pelo operador e gera evidências comparáveis para revisão de pull requests e pipelines. O fluxo de aplicação e os limites estão explícitos no [modelo de ameaças](docs/THREAT_MODEL.md).

### Diferencial dentro deste portfólio

Não é um scanner de segredos, dependências, cabeçalhos HTTP, certificados X.509 ou políticas RBAC. Trabalha especificamente com o **histórico de políticas de autenticação de domínios de e-mail e suas referências SPF**. O foco é o *security policy drift* e a rastreabilidade das revisões, não consultas DNS em tempo real.

## 2. Recursos implementados

| Módulo | Funcionalidade | Resultado |
| --- | --- | --- |
| SPF Dependency Graph | Interpreta `include:` / `redirect=`, segue referências estáticas, detecta ciclos, profundidade e referências ausentes | Grafo explicável e caminhos |
| SPF Risk Signals | Detecta `+all`, `~all`, `?all`, PTR, múltiplos registros, endereços inválidos, ausência de política | Achados com severidade e localização |
| SPF Lookup Estimate | Estimativa conservadora de caminho; sinaliza acima de 10 termos | Orienta revisão, não certifica limite RFC 7208 |
| DMARC (RFC 9989) | Avalia tags `p`, `sp`, `np`, `adkim`, `aspf`, `t`, `rua`, obsolescência de `pct`, `ri` e `rf` | Status de política solicitada |
| MTA-STS | Inspeciona TXT `_mta-sts` e política HTTPS declarada, modes `enforce`, `testing`, `none` | Identifica desativação e mudança de roteamento |
| Diff Gate | Compara baseline e candidate, incluindo exclusão de domínio monitorado | Bloqueia mudanças que exigem revisão |
| Relatórios | Texto, JSON determinístico e SARIF 2.1.0 para scans | Integrável a revisão e code scanning |
| CLI | `scan`, `diff`, `trace`, `--fail-on`, `--output` | Scripts e GitHub Actions |
| Hardening | Entrada 2 MiB, limites de objetos, recursão limitada, sem rede, sem execução de TXT | Superfície controlada |
| Release | ZIP fonte reprodutível, SHA-256, pipeline que exige CI em `main` | Distribuição versionada |

## 3. Instalação

Requer Python **3.11 ou superior**. Dependências de runtime: **nenhuma** (biblioteca padrão).

```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
mailauth-drift --help
```

```powershell
# PowerShell (Windows)
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
mailauth-drift --help
```

Também pode executar pelo módulo Python: `PYTHONPATH=src python -m mailauth_drift --help` (Linux/macOS) ou instalar o pacote normalmente.

## 4. Demonstração em 60 segundos

Estão incluídos dois arquivos **sintéticos**, sem dados de clientes: `examples/baseline.json` e `examples/candidate.json`.

```bash
# Baseline: políticas declaradas sem alertas do scanner
mailauth-drift scan --snapshot examples/baseline.json --fail-on high

# Candidate: alterações propositais com alertas
mailauth-drift scan --snapshot examples/candidate.json --format json --fail-on none

# Gate: compara as versões e retorna exit 1 quando há regressões
mailauth-drift diff \
  --baseline examples/baseline.json \
  --candidate examples/candidate.json \
  --fail-on-regression

# Explica vínculos entre registros SPF
mailauth-drift trace --snapshot examples/baseline.json --domain example.com

# SARIF 2.1.0
mailauth-drift scan --snapshot examples/candidate.json \
  --format sarif --fail-on none --output mailauth.sarif
```

**Por design**, a comparação de demonstração termina com código `1`: o baseline foi enfraquecido e o bloqueio funcionou. Erros de leitura ou parsing terminam com código `2`; uma avaliação bem-sucedida retorna `0`.

### Exemplo de saída da comparação

```text
MailAuth Drift | 9 policy changes | 9 review-required changes
[MEDIUM  ] example.com: dmarc.adkim | s -> r
[MEDIUM  ] example.com: dmarc.aspf | s -> r
[HIGH    ] example.com: dmarc.np | reject -> none
[HIGH    ] example.com: dmarc.p | reject -> none
[HIGH    ] example.com: dmarc.sp | reject -> none
[LOW     ] example.com: dmarc.t | n -> y
[LOW     ] example.com: mta_sts.max_age | 604800 -> 3600
[HIGH    ] example.com: mta_sts.mode | enforce -> testing
[HIGH    ] example.com: spf.terminal | fail -> softfail
```

Uma mudança marcada como regressão significa **necessidade de revisão**, não que o estado novo seja inválido em qualquer operação. Em especial, a RFC 9989 ressalva que políticas de DMARC devem considerar a interoperabilidade e a natureza do domínio.

## 5. Formato de snapshot

O programa recebe JSON, nunca configurações executáveis. A chave `domains` contém cada domínio que se quer acompanhar; valores `txt` representam os TXT visíveis para os donos DNS explicitados; `mta_sts_policy` é uma **cópia declarada** de uma política HTTPS, não algo baixado pelo programa.

```json
{
  "schema_version": 1,
  "domains": {
    "example.com": {
      "txt": {
        "example.com": ["v=spf1 include:_spf.example.com -all"],
        "_spf.example.com": ["v=spf1 ip4:192.0.2.0/24 -all"],
        "_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:reports@example.com"],
        "_mta-sts.example.com": ["v=STSv1; id=20261106"]
      },
      "mta_sts_policy": {
        "version": "STSv1",
        "mode": "enforce",
        "max_age": 604800,
        "mx": ["mx1.example.com"]
      }
    }
  }
}
```

Cada `TXT` é representado como **um registro lógico por string**. Fragmentos DNS que pertencem ao mesmo registro precisam ser concatenados no processo externo de captura. O snapshot deve conter as dependências referenciadas por SPF, inclusive subdomínios intermediários. O projeto **não importa dumps de zona BIND, arquivos Terraform nem YAML**, e não supõe que o snapshot reflita o estado do DNS público.

Limites: **2 MiB** por arquivo, **128 domínios**, **2048 nomes TXT**, **4096 TXT lógicos**, **4096 caracteres por TXT** e profundidade SPF de **20 nós**. Entradas fora do escopo geram erro e código `2`.

## 6. Comandos

```text
mailauth-drift scan --snapshot FILE [--format text|json|sarif]
                    [--fail-on none|info|low|medium|high|critical]
                    [--output FILE]

mailauth-drift diff --baseline FILE --candidate FILE
                    [--format text|json] [--fail-on-regression]
                    [--output FILE]

mailauth-drift trace --snapshot FILE --domain DNS_NAME
                     [--format text|json]
```

- `scan`: verificação estática de cada política declarada. Por padrão o gate falha a partir de `high`.
- `diff`: inspeciona o **sentido das alterações** e marca relaxamentos como revisáveis. Com `--fail-on-regression` falha para qualquer regressão (a partir de `low`).
- `trace`: exibe as arestas do grafo SPF de um domínio; úteis em revisão de code review.
- `--output`: salva relatório em arquivo local; recusa caminho de destino que seja link simbólico.
- Para bloquear um deploy, **execute tanto `scan` quanto `diff`**: novas zonas podem conter riscos mesmo que ainda não tenham baseline anterior.

## 7. Modelo analítico e limites

### SPF

Segue referências literais `include` e `redirect`, identifica ciclos, ausência de dependências, mecanismos que exigem lookup e estruturas que necessitam revisão. O número exibido é uma **estimativa conservadora de percurso estático**, não o custo de uma avaliação real; SPF pode encerrar antecipadamente e os mecanismos MX/PTR podem gerar consultas adicionais. Macros como `%{d}` não são resolvidas.

### DMARC

Respeita a atualização da [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989), que substituiu a RFC 7489. Identifica `t=y` e trata `pct`, `ri`, `rf` como tags históricas. `p=none` sinaliza monitoramento, não necessariamente erro. O projeto **não implementa** a nova descoberta de política por caminhada na árvore de DNS (*DNS Tree Walk*), não calcula alinhamento de mensagens e não valida DKIM. As políticas `sp`/`np` são tags declaradas/defaultadas, não simulações completas de subdomínios.

### MTA-STS

A política declarada é comparada entre versões; a ferramenta não baixa `https://mta-sts.<domain>/.well-known/mta-sts.txt`, não executa handshake SMTP/TLS, não verifica certificado do servidor nem valida o conteúdo remoto. Os eventos da política são relativos à configuração fornecida.

Veja a tabela de regras e ressalvas em [docs/SEMANTICS.md](docs/SEMANTICS.md).

## 8. Testes e CI

Ambiente local:

```bash
python -m pip install -e '.[dev]'
ruff check .
python -m compileall -q src scripts tests
pytest -q
python scripts/package.py
python scripts/verify_package.py
```

O workflow [CI](.github/workflows/ci.yml) executa Python 3.11, 3.12 e 3.13, Ruff, compilação, testes unitários, teste de CLI, caso que deve ser aprovado e **caso que intencionalmente retorna `1`**; gera distribuição com `python -m build`, ZIP reproduzível e checksum.

Resultados de execução atualizados **somente após rodar o Actions remoto**. Não confunda testes locais com CI aprovado no GitHub.

## 9. Publicação e cadeia de confiança

O fluxo inicial foi construído para publicar `v0.1.0` **apenas após** o GitHub Actions CI aprovar um push na branch principal. O workflow [Release](.github/workflows/release.yml):

1. aceita apenas `workflow_run` concluído com sucesso, de `push` no `main` do **mesmo repositório**;
2. faz checkout do SHA exato cujo CI passou (sem depender de artefatos de PR);
3. verifica que `main` ainda aponta para aquele SHA;
4. cria ZIP fonte reprodutível e valida CRC/SHA-256;
5. cria uma tag sem movê-la e um release com ZIP e SHA-256; se o release já existe, não o altera.

O token do CI é `contents: read`. Somente o job final da publicação tem `contents: write`; os Actions externos usam SHAs fixos. A publicação também depende de o administrador manter Actions e permissões de release habilitados no repositório. **Não há publicação no PyPI**.

## 10. Segurança e contribuições

- [SECURITY.md](SECURITY.md): disclosure privado, riscos, suporte.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): fronteiras de confiança, dados maliciosos, limitações.
- [CONTRIBUTING.md](CONTRIBUTING.md): testes mínimos, contribuições e requisitos.
- [CHANGELOG.md](CHANGELOG.md): histórico rastreável da versão.

Relate vulnerabilidades pelo fluxo **Security → Report a vulnerability**, nunca com dados sensíveis em issues públicos.

## 11. Referências e licença

- [RFC 7208 — Sender Policy Framework](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 9989 — Domain-Based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc9989)
- [RFC 8461 — SMTP MTA Strict Transport Security](https://www.rfc-editor.org/rfc/rfc8461)
- [RFC 8460 — SMTP TLS Reporting](https://www.rfc-editor.org/rfc/rfc8460)
- [checkdmarc](https://github.com/domainaware/checkdmarc) (ferramenta existente, para contexto e alternativas)

Licenciado sob **MIT**. © 2026 Felipe Watter.
