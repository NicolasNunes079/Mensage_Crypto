# Entrega 1 — Criptografia assimétrica e confiança

**Projeto Integrador · Segurança aplicada ao desenvolvimento**
Disciplina: Segurança da Informação · Docente: Profa. Ma. Ana Carla do Nascimento Santos
Curso: Sistemas de Informação/ADS · Universidade Tiradentes

---

## 1. Problema

Uma aplicação (**Empresa A**) precisa proteger uma mensagem enviada a outro serviço (**Empresa B**) e permitir que o destinatário verifique se ela chegou sem alterações.

A solução implementa **cifragem híbrida** com a biblioteca consolidada [`cryptography`](https://cryptography.io): o conteúdo é cifrado com **AES-256-GCM** e a chave AES é encapsulada com **RSA-OAEP**. Qualquer alteração no pacote durante o trânsito é detectada pelo destinatário.

> Nenhum algoritmo criptográfico foi implementado "na mão". Todas as primitivas vêm da biblioteca `cryptography`.

## 2. Estrutura do projeto

| Arquivo | Função |
|---|---|
| `main.py` | Simulação interativa: escolha do cenário, entrada da mensagem, envio pela Empresa A e verificação pela Empresa B |
| `cripto.py` | Geração e serialização de chaves, cifragem e decifragem híbridas |
| `adulteracao.py` | Emula um atacante que inverte 1 bit do pacote durante o trânsito |

## 3. Como executar

Requisitos: Python 3.10 ou superior.

```bash
pip install cryptography
python main.py
```

O programa pergunta:

1. **Cenário:** `1` = mensagem não alterada · `2` = mensagem alterada no trânsito
2. **Mensagem:** texto a ser enviado pela Empresa A (use apenas dados fictícios)

Fluxo executado:

1. A Empresa B gera o par de chaves RSA e entrega a chave pública (PEM) à Empresa A.
2. A Empresa A cifra a mensagem e monta o pacote.
3. O pacote trafega; no cenário 2, `adulteracao.py` inverte 1 bit do texto cifrado.
4. A Empresa B decifra e verifica. O resultado é **MENSAGEM ÍNTEGRA** ou **ADULTERAÇÃO DETECTADA**.

## 4. Algoritmos e parâmetros

| Componente | Algoritmo / parâmetro | Observação |
|---|---|---|
| Par de chaves | **RSA 3072 bits**, expoente público 65537 | Nível de segurança de cerca de 128 bits |
| Encapsulamento da chave | **RSA-OAEP**, hash SHA-256, MGF1-SHA-256, sem *label* | Preenchimento aleatório; evita os ataques conhecidos contra PKCS#1 v1.5 |
| Cifra do conteúdo | **AES-256-GCM** | Cifra autenticada (AEAD): sigilo e integridade |
| Chave AES | 256 bits, gerada por CSPRNG, **uso único** por mensagem | Nunca reutilizada |
| Nonce | 96 bits, aleatório (`os.urandom`), novo a cada mensagem | Tamanho recomendado para GCM |
| Tag de autenticação | 128 bits, anexada ao final do texto cifrado | Verificada antes de devolver qualquer texto |
| AAD | Contexto fixo `PI-Entrega1\|v1\|Empresa A -> Empresa B` | Autenticado, mas não cifrado; alterar o contexto invalida a tag |
| Formato das chaves | PEM: pública em SubjectPublicKeyInfo, privada em PKCS#8 | |
| Transporte do pacote | Campos em Base64 (`chave_encapsulada`, `nonce`, `texto_cifrado`) | |

### Por que híbrida?

- O RSA é lento e limita o tamanho do que cifra (com OAEP-SHA-256 e 3072 bits, no máximo 318 bytes).
- O AES é rápido e cifra mensagens de qualquer tamanho.
- A combinação usa cada algoritmo no que ele faz melhor: RSA para distribuir a chave, AES-GCM para proteger o conteúdo.

## 5. Gestão de chaves

| Aspecto | Tratamento nesta entrega | Em produção |
|---|---|---|
| Geração | `rsa.generate_private_key` (CSPRNG do sistema) | Idem, preferencialmente dentro de um HSM/KMS |
| Chave pública | Exportada em PEM e entregue à Empresa A | Distribuída por **certificado X.509** emitido por uma AC |
| Chave privada | Existe apenas na memória da Empresa B durante a execução; nunca é impressa nem gravada | Cofre de segredos/HSM; PEM protegido por senha (`serializar_chave_privada` aceita senha); **nunca** no repositório |
| Chave AES | Nova a cada mensagem, descartada após o uso | Idem |
| Nonce | Novo e aleatório a cada mensagem | Idem |
| Rotação | Não aplicável (as chaves são geradas a cada execução) | Rotação periódica e revogação em caso de comprometimento |

## 6. Sigilo × autenticidade × integridade

| Propriedade | Pergunta que responde | Quem a fornece aqui |
|---|---|---|
| **Sigilo** | Alguém não autorizado consegue ler? | RSA-OAEP + AES-GCM: só a chave privada da Empresa B recupera a chave AES |
| **Integridade** | A mensagem foi alterada? | Tag do AES-GCM: qualquer alteração faz a verificação falhar |
| **Autenticidade da origem** | Quem enviou realmente? | **Não é garantida por esta solução** (ver limites) |

**Certificados digitais e PKI:** um certificado X.509 vincula uma identidade a uma chave pública e é assinado por uma **Autoridade Certificadora (AC)**. A PKI (infraestrutura de chaves públicas) reúne ACs, cadeias de confiança, validade e revogação (CRL/OCSP). Sem isso, a Empresa A não tem como saber se a chave pública recebida pertence mesmo à Empresa B.

## 7. Testes realizados

| Teste | Resultado obtido |
|---|---|
| Cenário 1: mensagem íntegra | Mensagem recebida idêntica à original |
| Cenário 2: 1 bit invertido no texto cifrado | Falha na verificação, mensagem descartada |
| Adulteração do nonce | Falha na verificação |
| Adulteração da chave encapsulada | Falha na verificação |
| Decifrar com a chave privada errada | Falha na verificação |
| AAD (contexto) diferente | Falha na verificação |
| Pacote com campo ausente | Falha na verificação |
| Mesma mensagem cifrada duas vezes | Pacotes diferentes (nonce e chave AES novos) |

O destinatário devolve sempre a **mesma mensagem de erro genérica**, sem indicar em que ponto a verificação falhou, para não oferecer informação útil a um atacante.

## 8. Limites da solução

1. **Não autentica o remetente.** A chave pública da Empresa B é pública: qualquer pessoa pode cifrar uma mensagem para ela. O AES-GCM prova que o pacote não foi alterado, não que veio da Empresa A.
2. **Sem PKI na simulação.** A chave pública chega por PEM em um canal considerado confiável. Em uma rede real, um atacante poderia trocar essa chave (ataque *man-in-the-middle*). Falta validar um certificado X.509.
3. **Sem proteção contra repetição (*replay*).** Um pacote válido capturado pode ser reenviado e será aceito. Faltam identificador único ou *timestamp*.
4. **Sem sigilo futuro (*forward secrecy*).** Se a chave privada da Empresa B vazar, mensagens capturadas no passado podem ser decifradas.
5. **Chaves efêmeras.** As chaves são geradas a cada execução e não são persistidas; não há rotação nem revogação.
6. **Metadados não protegidos.** Tamanho da mensagem, momento do envio e as partes envolvidas continuam visíveis.
7. **Simulação em um único processo.** Os "dois lados" rodam juntos; não há rede, autenticação de transporte nem armazenamento seguro.
8. **Dependência da biblioteca.** A segurança depende da `cryptography` (OpenSSL) estar atualizada.

## 9. Melhorias possíveis

- Adicionar **assinatura digital RSA-PSS ou Ed25519** do pacote pela Empresa A, verificada pela Empresa B, para garantir a autenticidade da origem.
- Usar **certificados X.509** e validar a cadeia de confiança antes de cifrar.
- Incluir identificador de mensagem e *timestamp* para impedir *replay*.
- Trocar o encapsulamento RSA por **ECDH efêmero** (sigilo futuro) ou HPKE.
- Guardar as chaves em um KMS/HSM, com rotação e revogação.

## 10. Referências

- OWASP Top 10:2025 — A04 Falhas criptográficas
- OWASP ASVS 5.0 — V11 Criptografia e V12 Comunicação segura
- ISO/IEC 27002:2022 — controle 8.24 (Uso de criptografia)
- RFC 8017 — PKCS #1: RSA Cryptography Specifications v2.2 (OAEP)
- NIST SP 800-38D — Galois/Counter Mode (GCM)
- RFC 5280 — Perfil de certificado X.509 e CRL
- Documentação oficial da biblioteca [`cryptography`](https://cryptography.io)
