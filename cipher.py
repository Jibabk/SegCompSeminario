def ler_arquivo_binario(caminho_arquivo):
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as arquivo:
            conteudo = arquivo.read()
            conteudo_binario = ''.join(format(ord(char), '08b') for char in conteudo)
        return conteudo_binario
    except FileNotFoundError:
        return "Arquivo não encontrado."
    except Exception as e:
        return f"Ocorreu um erro: {e}".encode('utf-8')

def getListOfBlocks(mensagem, blockSize):
    blocks = []
    for i in range(0,blockSize):
        blocks.append(int(mensagem[i*1024:(i+1)*1024],2))
    return blocks

needPading = False
numberOfBlocks = len(ler_arquivo_binario('message'))//1024
mensagem = ler_arquivo_binario('message')

if len(ler_arquivo_binario('message'))%1024 != 0:
    needPading = True
    numberOfBlocks += 1

print(getListOfBlocks(mensagem, numberOfBlocks))