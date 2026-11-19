"""
adulteracao.py - Emula um atacante no meio do caminho (man-in-the-middle)

Este módulo existe apenas para fins DIDÁTICOS e para os testes negativos da
Entrega 1: ele altera um único bit do pacote cifrado enquanto ele "trafega"
entre a Empresa A e a Empresa B. Não ataca nenhum sistema real.
"""

import base64
import copy
import secrets

CAMPOS_ALTERAVEIS = ("texto_cifrado", "nonce", "chave_encapsulada")


def adulterar_pacote(pacote: dict, campo: str = "texto_cifrado"):
    """
    Devolve uma CÓPIA do pacote com 1 bit invertido no `campo` escolhido,
    sem modificar o original.

    Retorna (pacote_adulterado, posicao_do_byte_alterado).
    """
    if campo not in CAMPOS_ALTERAVEIS:
        raise ValueError(f"Campo inválido. Use um de: {CAMPOS_ALTERAVEIS}")

    novo = copy.deepcopy(pacote)
    dados = bytearray(base64.b64decode(novo[campo]))

    posicao = secrets.randbelow(len(dados))  # byte aleatório
    dados[posicao] ^= 0x01                   # inverte apenas 1 bit

    novo[campo] = base64.b64encode(bytes(dados)).decode("ascii")
    return novo, posicao
