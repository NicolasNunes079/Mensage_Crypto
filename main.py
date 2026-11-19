"""
main.py - Simulação da Entrega 1: envio seguro de mensagem entre empresas

Empresa A (remetente) cifra uma mensagem para a Empresa B (destinatária).
A Empresa B tenta decifrar e verificar a integridade.

Cenários:
  1) Mensagem íntegra   -> chega sem alteração
  2) Mensagem adulterada -> um atacante altera 1 bit durante o trânsito

Arquivos:
  main.py         (este)  fluxo da simulação e interação com o usuário
  cripto.py               chaves + cifragem híbrida (AES-256-GCM + RSA-OAEP)
  adulteracao.py          emula a alteração da mensagem no trânsito

Execução:  python main.py      (requer: pip install cryptography)
"""

from adulteracao import adulterar_pacote
from cripto import (
    ErroDeIntegridade,
    carregar_chave_publica,
    cifrar_hibrido,
    decifrar_hibrido,
    gerar_par_chaves,
    serializar_chave_publica,
)

LARGURA = 70


def titulo(texto: str) -> None:
    print("\n" + "=" * LARGURA)
    print(texto)
    print("=" * LARGURA)


def escolher_cenario() -> int:
    print("Escolha o cenário do teste:")
    print("  [1] Mensagem NÃO alterada (trânsito seguro)")
    print("  [2] Mensagem ALTERADA no trânsito (atacante)")
    while True:
        opcao = input("Opção: ").strip()
        if opcao in ("1", "2"):
            return int(opcao)
        print("Opção inválida. Digite 1 ou 2.")


def ler_mensagem() -> bytes:
    while True:
        texto = input("\nDigite a mensagem que a Empresa A enviará à Empresa B: ").strip()
        if texto:
            return texto.encode("utf-8")
        print("A mensagem não pode ser vazia.")


def resumo(valor_b64: str, tamanho: int = 48) -> str:
    """Mostra só o começo de um campo base64 para não poluir a tela."""
    return valor_b64 if len(valor_b64) <= tamanho else valor_b64[:tamanho] + "..."


def main() -> None:
    titulo("SIMULAÇÃO - ENVIO SEGURO DE MENSAGEM (AES-256-GCM + RSA-OAEP)")
    cenario = escolher_cenario()
    mensagem = ler_mensagem()

    # ------------------------------------------------------------------
    # Passo 1 - Empresa B gera o par de chaves e publica a chave pública
    # ------------------------------------------------------------------
    titulo("PASSO 1 - Empresa B gera o par de chaves RSA")
    chave_privada_b, chave_publica_b = gerar_par_chaves()
    pem_publica = serializar_chave_publica(chave_publica_b)
    print("A chave PRIVADA permanece apenas com a Empresa B.")
    print("A chave PÚBLICA (PEM) é enviada à Empresa A:\n")
    print(pem_publica.decode("ascii"))

    # ------------------------------------------------------------------
    # Passo 2 - Empresa A cifra a mensagem
    # ------------------------------------------------------------------
    titulo("PASSO 2 - Empresa A cifra a mensagem")
    chave_publica_recebida = carregar_chave_publica(pem_publica)
    pacote = cifrar_hibrido(mensagem, chave_publica_recebida)
    print(f"Mensagem original : {mensagem.decode('utf-8')}")
    print(f"Algoritmos        : {pacote['algoritmos']}")
    print(f"Chave encapsulada : {resumo(pacote['chave_encapsulada'])}")
    print(f"Nonce             : {pacote['nonce']}")
    print(f"Texto cifrado+tag : {resumo(pacote['texto_cifrado'])}")

    # ------------------------------------------------------------------
    # Passo 3 - Trânsito pela rede (com ou sem atacante)
    # ------------------------------------------------------------------
    titulo("PASSO 3 - Trânsito pela rede")
    if cenario == 2:
        pacote_recebido, posicao = adulterar_pacote(pacote, campo="texto_cifrado")
        print("[ATACANTE] Interceptou o pacote e inverteu 1 bit do texto cifrado")
        print(f"[ATACANTE] Byte alterado: posição {posicao}")
        print(f"Texto cifrado original : {resumo(pacote['texto_cifrado'])}")
        print(f"Texto cifrado recebido : {resumo(pacote_recebido['texto_cifrado'])}")
    else:
        pacote_recebido = pacote
        print("Nenhuma interferência: o pacote chega exatamente como foi enviado.")

    # ------------------------------------------------------------------
    # Passo 4 - Empresa B decifra e verifica
    # ------------------------------------------------------------------
    titulo("PASSO 4 - Empresa B decifra e verifica a integridade")
    try:
        recebida = decifrar_hibrido(pacote_recebido, chave_privada_b)
    except ErroDeIntegridade as erro:
        print("[ALERTA] MENSAGEM ADULTERADA OU INVÁLIDA!")
        print(f"         {erro}")
        print("         A mensagem foi DESCARTADA e nenhum conteúdo foi entregue.")
        resultado = "ADULTERAÇÃO DETECTADA"
    else:
        print("[OK] Integridade verificada: a mensagem não foi alterada.")
        print(f"     Mensagem recebida: {recebida.decode('utf-8')}")
        resultado = "MENSAGEM ÍNTEGRA"

    titulo(f"RESULTADO FINAL: {resultado}")


if __name__ == "__main__":
    main()
