# Documentação da Ferramenta de Criptografia (Crypt Tools)

## Visão Geral
`crypt_tools.py` é uma ferramenta de linha de comando para criptografar e descriptografar arquivos e textos usando o algoritmo AES (Advanced Encryption Standard). Ela oferece suporte a segurança aprimorada com PBKDF2 para derivação de chaves e compressão opcional de arquivos via zlib.

## Funcionalidades Principais
- **Criptografia AES-256**: Utiliza o modo GCM (Galois/Counter Mode) para criptografia autenticada, garantindo confidencialidade e integridade.
- **Derivação de Chave Robusta**: Implementa PBKDF2 com HMAC-SHA256, usando sal aleatório para proteger contra ataques de dicionário e rainbow tables.
- **Processamento em Stream**: Processa arquivos em blocos de 64KB, permitindo criptografar arquivos grandes com baixo uso de memória.
- **Compressão de Dados**: Opção para comprimir arquivos antes de criptografar, economizando espaço.
- **Interface de Linha de Comando (CLI)**: Argumentos flexíveis para operações rápidas.
- **Logs e Feedback Visual**: Ícones coloridos e feedback claro para o usuário.

## Como Usar

### Pré-requisitos
Certifique-se de ter as dependências instaladas (gerenciadas via `uv` ou `pip`):
- `pycryptodome`
- `animation`
- `zlib` (biblioteca padrão)

### Comandos Básicos

#### Criptografar um Texto
```bash
uv run crypt_tools.py --encrypt -t "Texto secreto" -p "sua_senha"
```

#### Descriptografar um Texto
```bash
uv run crypt_tools.py --decrypt -t "texto_criptografado_em_base64" -p "sua_senha"
```

#### Criptografar um Arquivo
```bash
# Criptografa arquivo.txt e cria arquivo.enc
uv run crypt_tools.py --encrypt -i arquivo.txt -p "sua_senha"

# Com compressão
uv run crypt_tools.py --encrypt -i arquivo.txt -p "sua_senha" -c
```

#### Descriptografar um Arquivo
```bash
# Descriptografa arquivo.enc e cria arquivo.dec
uv run crypt_tools.py --decrypt -i arquivo.enc -p "sua_senha"

# Se foi comprimido, a descompressão é automática se usar a flag -c
uv run crypt_tools.py --decrypt -i arquivo.enc -p "sua_senha" -c
```

## Estrutura do Código

### Classes Principais
- **`CryptoEngine`**: O núcleo da aplicação. Gerencia a geração de chaves (PBKDF2), criptografia (AES-GCM) e descriptografia.
- **`Config`**: Armazena constantes como tamanhos de chave (32 bytes), salt (16 bytes), nonce (12 bytes) e tag (16 bytes).
- **`Banner`**: Exibe o banner da aplicação.
- **`Logger`**: Sistema de logs coloridos para feedback do usuário.

### Detalhes Técnicos (Versão 2.0.0)
A versão atual (`crypt_tools.py`) utiliza AES-GCM e é incompatível com versões anteriores:
- **Chave**: 32 bytes (256 bits).
- **Salt**: 16 bytes (aleatório, por arquivo).
- **Nonce**: 12 bytes (padrão GCM, aleatório).
- **Tag**: 16 bytes (para verificação de integridade).

**Formato do Arquivo Criptografado**:
`[Salt (16)] + [Nonce (12)] + [Conteúdo Criptografado (Chunks)] + [Tag GCM (16)]`

## Testes
Os testes automatizados estão localizados na pasta `tests/` e podem ser executados com:
```bash
uv run pytest
```
