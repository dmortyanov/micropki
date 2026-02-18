# MicroPKI

Минимальная инфраструктура открытых ключей (PKI) — CLI-инструмент для создания и управления Root CA.

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

### Инициализация Root CA (RSA-4096)

```bash
# 1. Создать файл с паролем для шифрования приватного ключа
mkdir secrets
echo MySecretPassphrase > secrets/ca.pass

# 2. Создать Root CA
python -m micropki ca init \
    --subject "/CN=Demo Root CA/O=MyOrg/C=US" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki \
    --validity-days 3650 \
    --log-file ./logs/ca-init.log
```

### Инициализация Root CA (ECC P-384)

```bash
python -m micropki ca init \
    --subject "CN=ECC Root CA,O=MyOrg" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki
```

### Результат

После выполнения в `--out-dir` появится следующая структура:

```
pki/
├── private/
│   └── ca.key.pem      # Зашифрованный приватный ключ (PKCS#8, AES-256)
├── certs/
│   └── ca.cert.pem     # Самоподписанный X.509v3 сертификат (PEM)
└── policy.txt           # Документ политики сертификации
```

### Параметры CLI

| Параметр             | Описание                                                      | По умолчанию |
|----------------------|---------------------------------------------------------------|--------------|
| `--subject`          | Distinguished Name (обязательный)                             | —            |
| `--key-type`         | `rsa` или `ecc`                                              | `rsa`        |
| `--key-size`         | Размер ключа: 4096 (RSA) или 384 (ECC)                       | 4096 / 384   |
| `--passphrase-file`  | Путь к файлу с паролем (обязательный)                         | —            |
| `--out-dir`          | Выходная директория                                           | `./pki`      |
| `--validity-days`    | Срок действия сертификата (дни)                               | 3650         |
| `--log-file`         | Путь к лог-файлу (если не указан — вывод в stderr)           | —            |
| `--force`            | Перезаписать существующие файлы без подтверждения             | `false`      |

### Верификация через OpenSSL

```bash
# Просмотр сертификата
openssl x509 -in pki/certs/ca.cert.pem -text -noout

# Самоверификация
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
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
│   ├── ca.py              # Логика инициализации Root CA
│   ├── certificates.py    # Генерация X.509 сертификатов
│   ├── crypto_utils.py    # Генерация ключей, PEM, парсинг DN
│   └── logger.py          # Настройка логирования
├── tests/
│   ├── conftest.py        # Общие фикстуры
│   ├── test_ca.py         # Интеграционные тесты CA
│   ├── test_certificates.py # Тесты генерации сертификатов
│   ├── test_cli.py        # Тесты CLI и edge cases
│   └── test_crypto_utils.py # Тесты утилит криптографии
├── requirements.txt
├── pytest.ini
├── .gitignore
└── README.md
```
