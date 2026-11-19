"""
cripto.py - Módulo criptográfico da Entrega 1 (Projeto Integrador)

Implementa CIFRAGEM HÍBRIDA usando apenas a biblioteca consolidada
`cryptography` (nenhum algoritmo é implementado "na mão"):

  * RSA-3072 ................ par de chaves do destinatário
  * AES-256-GCM ............. cifra o conteúdo da mensagem (sigilo + integridade)
  * RSA-OAEP (SHA-256) ...... encapsula (cifra) a chave AES com a chave pública

Fluxo:
  remetente:    chave AES aleatória -> AES-GCM cifra a mensagem
                chave pública RSA   -> OAEP cifra a chave AES
  destinatário: chave privada RSA   -> OAEP recupera a chave AES
                chave AES           -> AES-GCM decifra e VERIFICA a tag

Se qualquer byte do pacote for alterado, a verificação falha.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Parâmetros
# ---------------------------------------------------------------------------
TAMANHO_CHAVE_RSA = 3072      # bits (>= 2048 é o mínimo aceitável; 3072 ~ 128 bits de segurança)
EXPOENTE_PUBLICO = 65537      # valor padrão recomendado
TAMANHO_CHAVE_AES = 256       # bits
TAMANHO_NONCE = 12            # bytes (96 bits, tamanho recomendado para GCM)

# Dados autenticados adicionais (AAD): não são cifrados, mas entram no cálculo
# da tag do GCM. Se alguém alterar o contexto, a verificação falha.
AAD_PADRAO = b"PI-Entrega1|v1|Empresa A -> Empresa B"


class ErroDeIntegridade(Exception):
    """Levantada quando o pacote não pode ser decifrado/verificado."""


# ---------------------------------------------------------------------------
# Utilitários de codificação
# ---------------------------------------------------------------------------
def _b64e(dados: bytes) -> str:
    return base64.b64encode(dados).decode("ascii")


def _b64d(texto: str) -> bytes:
    return base64.b64decode(texto.encode("ascii"), validate=True)


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


# ---------------------------------------------------------------------------
# Gestão de chaves
# ---------------------------------------------------------------------------
def gerar_par_chaves():
    """Gera um par de chaves RSA. Retorna (chave_privada, chave_publica)."""
    chave_privada = rsa.generate_private_key(
        public_exponent=EXPOENTE_PUBLICO,
        key_size=TAMANHO_CHAVE_RSA,
    )
    return chave_privada, chave_privada.public_key()


def serializar_chave_publica(chave_publica) -> bytes:
    """Exporta a chave pública em PEM (formato SubjectPublicKeyInfo). Pode ser divulgada."""
    return chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def carregar_chave_publica(pem: bytes):
    """Importa uma chave pública a partir de PEM."""
    return serialization.load_pem_public_key(pem)


def serializar_chave_privada(chave_privada, senha: bytes | None = None) -> bytes:
    """
    Exporta a chave privada em PEM (PKCS#8).
    Em uso real, proteja-a com senha (aqui cifrada com a melhor opção disponível)
    e guarde-a em cofre/HSM, nunca no repositório.
    """
    if senha:
        protecao = serialization.BestAvailableEncryption(senha)
    else:
        protecao = serialization.NoEncryption()
    return chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=protecao,
    )


def carregar_chave_privada(pem: bytes, senha: bytes | None = None):
    """Importa uma chave privada a partir de PEM."""
    return serialization.load_pem_private_key(pem, password=senha)


# ---------------------------------------------------------------------------
# Cifragem híbrida
# ---------------------------------------------------------------------------
def cifrar_hibrido(mensagem: bytes, chave_publica, aad: bytes = AAD_PADRAO) -> dict:
    """
    Cifra `mensagem` para o dono da `chave_publica`.

    Retorna um "pacote" (dict com strings base64) pronto para ser enviado:
      - chave_encapsulada: chave AES cifrada com RSA-OAEP
      - nonce:             número único usado no AES-GCM
      - texto_cifrado:     mensagem cifrada + tag de autenticação (16 bytes no final)
    """
    # 1) chave simétrica de uso único (gerada pelo CSPRNG do sistema)
    chave_aes = AESGCM.generate_key(bit_length=TAMANHO_CHAVE_AES)

    # 2) nonce aleatório; NUNCA reutilizar com a mesma chave
    nonce = os.urandom(TAMANHO_NONCE)

    # 3) AES-GCM cifra o conteúdo e gera a tag de integridade
    texto_cifrado = AESGCM(chave_aes).encrypt(nonce, mensagem, aad)

    # 4) RSA-OAEP encapsula a chave AES com a chave pública do destinatário
    chave_encapsulada = chave_publica.encrypt(chave_aes, _oaep())

    return {
        "versao": 1,
        "algoritmos": "RSA-3072-OAEP-SHA256 + AES-256-GCM",
        "chave_encapsulada": _b64e(chave_encapsulada),
        "nonce": _b64e(nonce),
        "texto_cifrado": _b64e(texto_cifrado),
    }


def decifrar_hibrido(pacote: dict, chave_privada, aad: bytes = AAD_PADRAO) -> bytes:
    """
    Decifra e verifica o pacote com a chave privada do destinatário.
    Levanta ErroDeIntegridade se o pacote foi adulterado, está malformado
    ou foi cifrado para outra chave.
    """
    try:
        chave_encapsulada = _b64d(pacote["chave_encapsulada"])
        nonce = _b64d(pacote["nonce"])
        texto_cifrado = _b64d(pacote["texto_cifrado"])

        # RSA-OAEP recupera a chave AES (falha se a chave encapsulada foi alterada)
        chave_aes = chave_privada.decrypt(chave_encapsulada, _oaep())

        # AES-GCM decifra e confere a tag (falha se nonce, texto ou AAD foram alterados)
        return AESGCM(chave_aes).decrypt(nonce, texto_cifrado, aad)
    except (InvalidTag, ValueError, KeyError, TypeError) as erro:
        # Mensagem genérica de propósito: não revelar detalhes do ponto de falha
        raise ErroDeIntegridade("Falha na verificação de integridade/autenticação.") from erro
