# MicroPKI

Минимальная инфраструктура открытых ключей (PKI) — CLI-инструмент для создания и управления Root CA, Intermediate CA и выпуска сертификатов.

## Зависимости

- Python 3.11+
- [`cryptography`](https://pypi.org/project/cryptography/) >= 43.0

## Установка

```bash
git clone <repo-url> && cd micropki

python -m venv venv

# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

pip install -r requirements.txt
```

## Использование

### 1. Инициализация Root CA

```bash
mkdir secrets
echo MySecretPassphrase > secrets/ca.pass

python -m micropki ca init \
    --subject "CN=Demo Root CA,O=MyOrg,C=US" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki \
    --validity-days 3650
```

### 2. Создание Intermediate CA

```bash
echo IntermediatePass > secrets/intermediate.pass

python -m micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/ca.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MyOrg" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
```

### 3. Выпуск серверного сертификата

```bash
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MyOrg" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs \
    --validity-days 365
```

### 4. Выпуск клиентского сертификата

```bash
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir ./pki/certs
```

### 5. Выпуск сертификата для подписи кода

```bash
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs
```

### 6. Валидация цепочки сертификатов

```bash
python -m micropki ca validate-chain \
    --cert ./pki/certs/example.com.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --root ./pki/certs/ca.cert.pem
```

### Структура директорий после работы

```
pki/
├── private/
│   ├── ca.key.pem               # Зашифрованный ключ Root CA (PKCS#8, AES-256)
│   └── intermediate.key.pem     # Зашифрованный ключ Intermediate CA
├── certs/
│   ├── ca.cert.pem              # Самоподписанный сертификат Root CA
│   ├── intermediate.cert.pem    # Сертификат Intermediate CA
│   ├── example.com.cert.pem     # Серверный сертификат
│   └── example.com.key.pem      # Приватный ключ (незашифрованный)
├── csrs/
│   └── intermediate.csr.pem     # CSR Intermediate CA
└── policy.txt                   # Документ политики сертификации
```

## Параметры CLI

### `ca init` — Инициализация Root CA

| Параметр             | Описание                                  | По умолчанию |
|----------------------|-------------------------------------------|--------------|
| `--subject`          | Distinguished Name (обязательный)         | —            |
| `--key-type`         | `rsa` или `ecc`                           | `rsa`        |
| `--key-size`         | Размер ключа: 4096 (RSA) или 384 (ECC)   | 4096 / 384   |
| `--passphrase-file`  | Путь к файлу с паролем (обязательный)     | —            |
| `--out-dir`          | Выходная директория                       | `./pki`      |
| `--validity-days`    | Срок действия (дни)                       | 3650         |
| `--log-file`         | Путь к лог-файлу                          | stderr       |
| `--force`            | Перезаписать существующие файлы           | `false`      |

### `ca issue-intermediate` — Создание Intermediate CA

| Параметр             | Описание                                  | По умолчанию |
|----------------------|-------------------------------------------|--------------|
| `--root-cert`        | Сертификат Root CA (PEM)                  | —            |
| `--root-key`         | Зашифрованный ключ Root CA (PEM)          | —            |
| `--root-pass-file`   | Файл с паролем Root CA                    | —            |
| `--subject`          | Distinguished Name                        | —            |
| `--key-type`         | `rsa` или `ecc`                           | `rsa`        |
| `--key-size`         | Размер ключа: 4096 (RSA) или 384 (ECC)   | 4096 / 384   |
| `--passphrase-file`  | Файл с паролем для Intermediate CA        | —            |
| `--out-dir`          | Выходная директория                       | `./pki`      |
| `--validity-days`    | Срок действия (дни)                       | 1825         |
| `--pathlen`          | Ограничение длины пути                    | 0            |
| `--log-file`         | Путь к лог-файлу                          | stderr       |

### `ca issue-cert` — Выпуск сертификата

| Параметр             | Описание                                       | По умолчанию |
|----------------------|-------------------------------------------------|--------------|
| `--ca-cert`          | Сертификат CA (PEM)                             | —            |
| `--ca-key`           | Зашифрованный ключ CA (PEM)                     | —            |
| `--ca-pass-file`     | Файл с паролем CA                               | —            |
| `--template`         | Шаблон: `server`, `client`, `code_signing`      | —            |
| `--subject`          | Distinguished Name                              | —            |
| `--san`              | SAN: `dns:`, `ip:`, `email:`, `uri:` (повтор.)  | —            |
| `--out-dir`          | Выходная директория                             | `./pki/certs`|
| `--validity-days`    | Срок действия (дни)                             | 365          |
| `--log-file`         | Путь к лог-файлу                                | stderr       |

### `ca validate-chain` — Валидация цепочки

| Параметр             | Описание                           | По умолчанию |
|----------------------|------------------------------------|--------------|
| `--cert`             | Leaf-сертификат (PEM)              | —            |
| `--intermediate`     | Intermediate CA сертификат (PEM)   | —            |
| `--root`             | Root CA сертификат (PEM)           | —            |
| `--log-file`         | Путь к лог-файлу                   | stderr       |

## Шаблоны сертификатов

| Шаблон          | Key Usage                                  | Extended Key Usage | Допустимые SAN        | SAN обязателен |
|-----------------|--------------------------------------------|--------------------|----------------------|----------------|
| `server`        | digitalSignature, keyEncipherment (RSA)    | serverAuth         | dns, ip              | Да             |
| `client`        | digitalSignature                           | clientAuth         | dns, email, ip, uri  | Нет            |
| `code_signing`  | digitalSignature                           | codeSigning        | dns, uri             | Нет            |

## Верификация через OpenSSL

```bash
# Просмотр Intermediate CA
openssl x509 -in pki/certs/intermediate.cert.pem -text -noout

# Проверка Intermediate CA через Root
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/intermediate.cert.pem

# Проверка leaf-сертификата через полную цепочку
openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem
```

## Запуск тестов

```bash
pytest tests/ -v
```

С покрытием кода:

```bash
pytest tests/ -v --cov=micropki --cov-report=term-missing
```

## Структура проекта

```
micropki/
├── micropki/
│   ├── __init__.py        # Версия пакета
│   ├── __main__.py        # Точка входа (python -m micropki)
│   ├── cli.py             # Парсер аргументов (argparse)
│   ├── ca.py              # Логика Root CA, Intermediate CA, выпуска сертификатов
│   ├── certificates.py    # Генерация X.509 сертификатов
│   ├── chain.py           # Валидация цепочки сертификатов (RFC 5280)
│   ├── csr.py             # Генерация и верификация CSR (PKCS#10)
│   ├── crypto_utils.py    # Генерация ключей, PEM I/O, парсинг DN
│   ├── templates.py       # Шаблоны сертификатов и парсинг SAN
│   └── logger.py          # Настройка логирования
├── tests/
│   ├── conftest.py        # Общие фикстуры
│   ├── test_ca.py         # Тесты Root CA
│   ├── test_certificates.py # Тесты генерации сертификатов
│   ├── test_chain.py      # Тесты валидации цепочки
│   ├── test_cli.py        # Тесты CLI (Sprint 1)
│   ├── test_cli_sprint2.py # Тесты CLI (Sprint 2)
│   ├── test_csr.py        # Тесты генерации CSR
│   ├── test_crypto_utils.py # Тесты утилит криптографии
│   ├── test_intermediate.py # Интеграционные тесты Intermediate CA
│   └── test_templates.py  # Тесты шаблонов и SAN
├── requirements.txt
├── pytest.ini
├── .gitignore
└── README.md
```
