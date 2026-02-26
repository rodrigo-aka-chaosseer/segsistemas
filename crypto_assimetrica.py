

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def gerar_chaves():
    """Gera chaves RSA de 512 bits e salva em arquivos .pem no estilo SSH."""
    print("\n Gerando par de chaves RSA\n")
    
    # 1. Gerar a chave privada(rsa)
    chave_pr = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512,
    )

    # 2. Extrair a chave pública a partir da privada (e pode isso gente - rsa)
    chave_pu = chave_pr.public_key()

    # 3. Salvar a Chave Privada em um arquivo (deus sabe como isso funciona)
    pem_privada = chave_pr.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption() # Em um ambiente real, use BestAvailableEncryption com senha(ok)
    )
    with open("chave_privada.pem", "wb") as f:
        f.write(pem_privada)

    # 4. Salvar a Chave Pública em um arquivo (igual o 3 com a pública)
    pem_publica = chave_pu.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("chave_publica.pem", "wb") as f:
        f.write(pem_publica)

    print("-" * 40)
    print("[+] Sucesso! Chaves geradas:")
    print("    - chave_privada.pem (MANTENHA EM SEGREDO!)")
    print("    - chave_publica.pem (COMPARTILHE COM QUEM FOR TE ENVIAR DADOS)")
    print("-" * 40)

def carregar_chave_publica(caminho):
    with open(caminho, "rb") as f:
        chave_pu = serialization.load_pem_public_key(f.read())
    return chave_pu

def carregar_chave_privada(caminho):
    with open(caminho, "rb") as f:
        chave_pr = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    return chave_pr

def criptografar_mensagem(mensagem, caminho_chave_pub="chave_publica.pem"):

    if not os.path.exists(caminho_chave_pub):
        print("[!] Erro: Chave pública não encontrada.")
        return

    chave_pu = carregar_chave_publica(caminho_chave_pub)
    mensagem_bytes = mensagem.encode('utf-8')

    try:
        # Usamos OAEP, que é o padrão de preenchimento (padding) mais seguro para RSA hoje(então tá)
        mensagem_criptografada = chave_publica.encrypt(
            mensagem_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),#comequeé
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("\n[+] Mensagem Criptografada (em HEX para visualização):")
        print(mensagem_criptografada.hex())
        return mensagem_criptografada
    except ValueError as e:
        print(f"[!] Erro ao criptografar (a mensagem é muito grande?): {e}")

def descriptografar_mensagem(mensagem,caminho_chave_pr="chave_privada.pem"):
    if not os.path.exists(caminho_chave_pr):
        print("[!] Erro: Chave privada não encontrada.")
        return
    chave_pr = carregar_chave_privada(caminho_chave_priv)
    try:
        mensagem_original = chave_privada.decrypt(
            mensagem_criptografada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("\n[+] Mensagem Descriptografada:")
        print(mensagem_original.decode('utf-8'))
    except Exception:
        print("[!] Erro: Falha ao descriptografar. Chave incorreta ou dados corrompidos.")

# --- Interface ---

def menu():
    mensagem_em_memoria = None # Variável temporária só para o teste no menu

    while True:
        print("\n=== Sistema RSA (Tipo SSH) ===")
        print("1. Gerar Novo Par de Chaves (.pem)")
        print("2. Criptografar uma Mensagem (Requer chave_publica.pem)")
        print("3. Descriptografar a Mensagem (Requer chave_privada.pem)")
        print("0. Sair")
        
        opcao = input("\nSelecione: ").strip()

        if opcao == "1":
            gerar_chaves()
        
        elif opcao == "2":
            texto = input("Digite a mensagem secreta (curta): ").strip()
            # Salva na variável global do menu para testarmos a opção 3 logo depois
            mensagem_em_memoria = criptografar_mensagem(texto)
        
        elif opcao == "3":
            if mensagem_em_memoria is None:
                print("[!] Nenhuma mensagem criptografada na memória. Use a opção 2 primeiro para testar.")
            else:
                descriptografar_mensagem(mensagem_em_memoria)
        
        elif opcao == "0":
            print("Encerrando...")
            break
        else:
            print("[!] Opção inválida.")

menu()

