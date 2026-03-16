import hmac as hmac_lib
import base64
import json

def fnv(dados: str) -> int:
    FNV_OFFSET_BASIS = 0x811c9dc5
    FNV_PRIME = 0x01000193
    hash_valor = FNV_OFFSET_BASIS
    for byte in dados.encode('utf-8'):
        hash_valor ^= byte
        hash_valor *= FNV_PRIME
        hash_valor &= 0xFFFFFFFF
    return hash_valor

def xor_cifrar(texto: str, chave: str) -> str:
    chave_bytes = chave.encode('utf-8')
    texto_bytes = texto.encode('utf-8')
    cifrado = bytes([texto_bytes[i] ^ chave_bytes[i % len(chave_bytes)] for i in range(len(texto_bytes))])
    return base64.b64encode(cifrado).decode('utf-8')

def xor_decifrar(cifrado_b64: str, chave: str) -> str:
    chave_bytes = chave.encode('utf-8')
    cifrado = base64.b64decode(cifrado_b64.encode('utf-8'))
    texto = bytes([cifrado[i] ^ chave_bytes[i % len(chave_bytes)] for i in range(len(cifrado))])
    return texto.decode('utf-8')

def gerar_pacote(texto: str, segredo: str) -> str:
    chave_str = str(fnv(segredo))
    mensagem_cifrada = xor_cifrar(texto, chave_str)
    assinatura = hex(fnv(mensagem_cifrada + chave_str))
    pacote = {"c": mensagem_cifrada, "a": assinatura}
    return base64.b64encode(json.dumps(pacote).encode()).decode()

def abrir_pacote(pacote_b64: str, segredo: str):
    try:
        pacote = json.loads(base64.b64decode(pacote_b64.encode()).decode())
        mensagem_cifrada = pacote["c"]
        assinatura_original = pacote["a"]

        chave_str = str(fnv(segredo))
        assinatura_calculada = hex(fnv(mensagem_cifrada + chave_str))

        if not hmac_lib.compare_digest(assinatura_calculada, assinatura_original):
            print("Segredo inválido ou mensagem adulterada.")
            return

        texto = xor_decifrar(mensagem_cifrada, chave_str)
        print(f"\nMensagem decifrada: {texto}")
        print(f"   Hash FNV-32 da mensagem: {hex(fnv(texto))}")

    except Exception:
        print("Pacote inválido.")

while True:
    print("\n1 - Criar mensagem (remetente)\n2 - Abrir mensagem (destinatário)")
    opt = int(input("Opção: "))

    if opt == 1:
        texto = input("Mensagem: ")
        segredo = input("Segredo compartilhado: ")
        pacote = gerar_pacote(texto, segredo)
        print(f"\nPacote gerado — envie isso ao destinatário:\n\n{pacote}\n")

    elif opt == 2:
        pacote = input("Cole o pacote recebido: ").strip()
        segredo = input("Segredo compartilhado: ")
        abrir_pacote(pacote, segredo)
