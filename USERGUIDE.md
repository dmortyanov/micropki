# MicroPKI — User Guide (по спринтам)

## 0) Подготовка и запуск CLI

В корне проекта `micropki`:
1. Установить зависимости:
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # macOS / Linux:
   source venv/bin/activate

   pip install -r requirements.txt
   ```
2. Все команды запускаются как:
   - `python -m micropki ...`

Рабочие каталоги (по умолчанию используются такие пути):
- `./pki/` — папка PKI
- `./pki/certs/` — CA и leaf сертификаты
- `./pki/private/` — приватные ключи CA
- `./pki/secrets/` — файлы с паролями (passphrase)
- `./pki/micropki.db` — SQLite база сертификатов (создаётся командой `db init`)

---

## Sprint 1: Root CA ( `ca init` )

### Подготовьте passphrase
Например:
```bash
mkdir -p ./pki/secrets
echo "MyRootPassphrase" > ./pki/secrets/ca.pass
```

### Создайте Root CA
```bash
python -m micropki ca init \
  --subject "CN=Demo Root CA,O=MyOrg,C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./pki/secrets/ca.pass \
  --out-dir ./pki \
  --validity-days 3650
```

Опции:
- `--force` — перезаписать уже существующие `ca.key.pem` / `ca.cert.pem`
- `--log-file` — лог в файл (по желанию)

Результат (в `./pki/`):
- `certs/ca.cert.pem`
- `private/ca.key.pem`
- `policy.txt`

---

## Sprint 2: Intermediate CA и выпуск leaf сертификатов

## 2.1) Intermediate CA ( `ca issue-intermediate` )

Подготовьте passphrase для Intermediate:
```bash
echo "MyIntermediatePassphrase" > ./pki/secrets/intermediate.pass
```

Выпуск Intermediate CA:
```bash
python -m micropki ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file ./pki/secrets/ca.pass \
  --subject "CN=MicroPKI Intermediate CA,O=MyOrg" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./pki/secrets/intermediate.pass \
  --out-dir ./pki \
  --validity-days 1825 \
  --pathlen 0
```

Результат:
- `certs/intermediate.cert.pem`
- `private/intermediate.key.pem`
- `csrs/intermediate.csr.pem`

## 2.2) Выпуск leaf сертификата ( `ca issue-cert` )

Шаблоны:
- `server`
  - SAN обязателен (допускаются `dns` и `ip`)
- `client`
  - SAN обычно не обязателен, поддерживаются `dns/email/ip/uri`
- `code_signing`
  - SAN не обязателен, поддерживаются `dns/uri`

### Пример: server сертификат (SAN обязателен)
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template server \
  --subject "CN=example.com,O=MyOrg" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.10 \
  --out-dir ./pki/certs \
  --validity-days 365
```

### Пример: client сертификат
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template client \
  --subject "CN=Alice Smith" \
  --san email:alice@example.com \
  --out-dir ./pki/certs
```

### Пример: code signing сертификат
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template code_signing \
  --subject "CN=MicroPKI Code Signer" \
  --out-dir ./pki/certs
```

### (Опция Sprint 2) Выпуск по внешнему CSR
Если есть внешний CSR PEM:
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template server \
  --subject "CN=from-csr.example.com,O=MyOrg" \
  --csr ./path/to/request.csr.pem \
  --out-dir ./pki/certs
```

Важно:
- если CSR просит `BasicConstraints: CA=TRUE`, выпуск end-entity отклоняется

## 2.3) Валидация цепочки ( `ca validate-chain` )
```bash
python -m micropki ca validate-chain \
  --cert ./pki/certs/example.com.cert.pem \
  --intermediate ./pki/certs/intermediate.cert.pem \
  --root ./pki/certs/ca.cert.pem
```

---

## Sprint 3: Certificate DB + репозиторий по HTTP

## 3.1) Инициализация SQLite базы ( `db init` )
```bash
python -m micropki db init --db-path ./pki/micropki.db
```

Опции:
- `--db-path` — путь к SQLite базе
- `--log-file` — лог в файл (по желанию)

## 3.2) CLI для работы с сертификатами в БД

### Список сертификатов ( `ca list-certs` )
Таблица:
```bash
python -m micropki ca list-certs --status valid --format table
```
JSON:
```bash
python -m micropki ca list-certs --format json
```
CSV:
```bash
python -m micropki ca list-certs --status valid --format csv
```

Опции:
- `--status` (`valid|revoked|expired`) — фильтр (по желанию)
- `--format` (`table|json|csv`, default: `table`)

### Показ сертификата по serial ( `ca show-cert` )
```bash
python -m micropki ca show-cert <SERIAL_HEX>
```
Команда печатает PEM в `stdout`.

## 3.3) Запуск HTTP-репозитория ( `repo serve` )
```bash
python -m micropki repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --db-path ./pki/micropki.db \
  --cert-dir ./pki/certs
```

Опции:
- `--log-file` (по желанию): создаёт текстовый лог, а также JSONL-файл HTTP-запросов (`<log-file>.jsonl`)

## 3.4) Проверка доступности сервера ( `repo status` — Could )
```bash
python -m micropki repo status --host 127.0.0.1 --port 8080
```

## 3.5) REST API: готовые примеры `curl`

Базовый URL (по умолчанию):
- `http://127.0.0.1:8080`

### GET /certificate/<serial>
```bash
curl http://127.0.0.1:8080/certificate/<SERIAL_HEX> --output cert.pem
```

### GET /ca/root
```bash
curl http://127.0.0.1:8080/ca/root --output root.pem
```

### GET /ca/intermediate
```bash
curl http://127.0.0.1:8080/ca/intermediate --output intermediate.pem
```

### GET /crl (заглушка Sprint 4)
```bash
curl http://127.0.0.1:8080/crl
```

---

## Конечный “сквозной” сценарий (1 → 2 → 3)

Пример последовательности (идея):
1. `ca init` (Root CA)
2. `ca issue-intermediate` (Intermediate CA)
3. `ca issue-cert` (leaf сертификаты)
4. `db init` (SQLite схема)
5. `repo serve`
6. `curl` по `/certificate/<serial>` / `/ca/root` / `/ca/intermediate`

# MicroPKI — User Guide (CLI + REST API)

## Как запускать CLI

1. В корне проекта `micropki`:
   - `python -m micropki ...`

2. Эквивалентно (если в системе есть entry-point):
   - `micropki ...`

Во всех примерах ниже предполагается структура:
- `./pki/` — рабочая папка PKI
- `./pki/certs/` — сертификаты (CA и leaf)
- `./pki/private/` — приватные ключи CA (root/intermediate)
- `./pki/secrets/` — файлы с паролями (passphrase)
- `./pki/micropki.db` — SQLite база (создаётся командой `db init`)

## REST API (репозиторий)

Когда запущен сервер:
- базовый URL: `http://127.0.0.1:8080`

Endpoints:
- `GET /certificate/<serial>` — PEM сертификат по serial (hex, case-insensitive)
- `GET /ca/root` — Root CA certificate PEM
- `GET /ca/intermediate` — Intermediate CA certificate PEM
- `GET /crl` — заглушка для Sprint 4 (в ответе `501`)

Примеры `curl`:
```bash
# сертификат по serial
curl http://127.0.0.1:8080/certificate/<SERIAL_HEX> --output cert.pem

# Root CA
curl http://127.0.0.1:8080/ca/root --output root.pem

# Intermediate CA
curl http://127.0.0.1:8080/ca/intermediate --output intermediate.pem

# CRL (заглушка)
curl http://127.0.0.1:8080/crl
```

## DB: инициализация SQLite

Команда создаёт схему таблиц для сертификатов (таблица `certificates`) в SQLite.

### db init
```bash
python -m micropki db init --db-path ./pki/micropki.db
```

Опции:
- `--db-path` (по умолчанию: `./pki/micropki.db`)
- `--log-file` (по желанию)

## CA: создание и выпуск

### ca init (Root CA)

Root CA — самоподписанный сертификат.

Пример:
```bash
python -m micropki ca init \
  --subject "CN=Demo Root CA,O=MyOrg,C=US" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./pki/secrets/ca.pass \
  --out-dir ./pki \
  --validity-days 3650
```

Опции:
- `--subject` (обязательный)
- `--key-type` (`rsa` или `ecc`, default: `rsa`)
- `--key-size`:
  - `rsa`: 4096
  - `ecc`: 384
- `--passphrase-file` (обязательный)
- `--out-dir` (default: `./pki`)
- `--validity-days` (default: `3650`)
- `--log-file` (по желанию)
- `--force` (перезапись файлов ключа/сертификата CA, если они уже есть)

### ca issue-intermediate (Intermediate CA)

Intermediate CA подписывается Root CA.

Пример:
```bash
python -m micropki ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file ./pki/secrets/ca.pass \
  --subject "CN=MicroPKI Intermediate CA,O=MyOrg" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./pki/secrets/intermediate.pass \
  --out-dir ./pki \
  --validity-days 1825 \
  --pathlen 0
```

Опции:
- `--root-cert` (обязательный)
- `--root-key` (обязательный)
- `--root-pass-file` (обязательный)
- `--subject` (обязательный)
- `--key-type` (`rsa` или `ecc`)
- `--key-size`:
  - `rsa`: 4096
  - `ecc`: 384
- `--passphrase-file` (обязательный)
- `--out-dir` (default: `./pki`)
- `--validity-days` (default: `1825`)
- `--pathlen` (default: `0`)
- `--log-file` (по желанию)

### ca issue-cert (leaf сертификаты)

Выпускает end-entity сертификат из указанного CA (Root/Intermediate).

Поддерживаемые шаблоны:
- `server`
- `client`
- `code_signing`

#### Вариант A: выпуск с генерацией ключа (обычный сценарий)

Пример серверного сертификата (для `server` SAN обязателен):
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template server \
  --subject "CN=example.com,O=MyOrg" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.10 \
  --out-dir ./pki/certs \
  --validity-days 365
```

Пример клиентского сертификата (для `client` SAN по проекту не обязателен, но поддерживается):
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template client \
  --subject "CN=Alice Smith" \
  --san email:alice@example.com \
  --out-dir ./pki/certs \
  --validity-days 365
```

Пример code signing сертификата (SAN не обязателен):
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template code_signing \
  --subject "CN=MicroPKI Code Signer" \
  --out-dir ./pki/certs \
  --validity-days 365
```

Опции:
- `--ca-cert` (обязательный)
- `--ca-key` (обязательный)
- `--ca-pass-file` (обязательный)
- `--template` (`server|client|code_signing`)
- `--subject` (обязательный)
- `--san` (повторяемый)
  - форматы: `dns:<name>`, `ip:<ip>`, `email:<email>`, `uri:<uri>`
- `--csr` (по желанию, если вы подаёте внешний CSR)
- `--out-dir` (default: `./pki/certs`)
- `--validity-days` (default: `365`)
- `--log-file` (по желанию)

#### Вариант B: выпуск из внешнего CSR (опция `--csr`)

Если вы заранее сгенерировали CSR (в отдельной утилите), можно передать его:
```bash
python -m micropki ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./pki/secrets/intermediate.pass \
  --template server \
  --subject "CN=from-csr.example.com,O=MyOrg" \
  --csr ./path/to/request.csr.pem \
  --out-dir ./pki/certs \
  --validity-days 365
```

Важно:
- если CSR просит `CA=TRUE`, выпуск end-entity отклоняется.

### ca validate-chain

Проверяет цепочку leaf → intermediate → root.

Пример:
```bash
python -m micropki ca validate-chain \
  --cert ./pki/certs/example.com.cert.pem \
  --intermediate ./pki/certs/intermediate.cert.pem \
  --root ./pki/certs/ca.cert.pem
```

Опции:
- `--cert` (leaf, обязательный)
- `--intermediate` (обязательный)
- `--root` (обязательный)
- `--log-file` (по желанию)

## Работа с базой сертификатов (Sprint 3)

### ca list-certs

Выводит список сертификатов из SQLite.

Пример (таблица):
```bash
python -m micropki ca list-certs --status valid --format table
```

Пример (JSON):
```bash
python -m micropki ca list-certs --format json
```

Пример (CSV):
```bash
python -m micropki ca list-certs --status valid --format csv
```

Опции:
- `--status` (`valid|revoked|expired`, по умолчанию: без фильтра)
- `--format` (`table|json|csv`, default: `table`)

### ca show-cert <serial>

Печатает PEM сертификат в stdout по `serial` (hex).

Пример:
```bash
python -m micropki ca show-cert <SERIAL_HEX>
```

## Репозиторий: HTTP server

### repo serve

Запускает HTTP-сервер.

Пример:
```bash
python -m micropki repo serve \
  --host 127.0.0.1 \
  --port 8080 \
  --db-path ./pki/micropki.db \
  --cert-dir ./pki/certs
```

Опции:
- `--host` (default: `127.0.0.1`)
- `--port` (default: `8080`)
- `--db-path` (default: `./pki/micropki.db`)
- `--cert-dir` (default: `./pki/certs`)
- `--log-file` (по желанию)

### repo status (Could)

Проверяет доступность хоста/порта.

Пример:
```bash
python -m micropki repo status --host 127.0.0.1 --port 8080
```

# USERGUIDE.md — Подробное руководство по MicroPKI

Этот документ предоставляет исчерпывающее руководство по всем командам и возможностям проекта MicroPKI, охватывая все три спринта разработки.

## Обзор

MicroPKI — это минималистичная инфраструктура открытых ключей (PKI), реализованная как CLI-инструмент на Python. Проект развивался поэтапно:

- **Sprint 1**: Создание самоподписанного корневого удостоверяющего центра (Root CA).
- **Sprint 2**: Введение промежуточного УЦ (Intermediate CA) и выпуск конечных сертификатов с использованием шаблонов и имен субъекта (SAN).
- **Sprint 3**: Управление жизненным циклом сертификатов, включая базу данных, отслеживание серийных номеров и HTTP-репозиторий для обслуживания сертификатов.

---

## 1. Установка и настройка

### Зависимости

- Python 3.11 или выше
- Библиотека `cryptography` (через `pip`)

### Установка из репозитория

```bash
git clone <ссылка_на_репозиторий>
cd micropki

# Создание виртуального окружения
python -m venv venv

# Активация (Windows)
venv\Scripts\activate

# Активация (macOS / Linux)
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt
```

### Тестирование

Запустите набор тестов для проверки корректности установки и работы:

```bash
# Запуск всех тестов с подробным выводом
pytest tests/ -v

# Запуск с отчетом о покрытии кода
pytest tests/ -v --cov=micropki --cov-report=term-missing
```

---

## 2. Структура проекта

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
│   ├── ...                # Автоматизированные тесты
├── requirements.txt
├── pytest.ini
├── .gitignore
├── README.md
├── Sprint1_status.md
├── Sprint2_status.md
└── USERGUIDE.md           # Этот документ
```

---

## 3. Работа с CLI: Команды и примеры

Все команды вызываются через `python -m micropki` или после установки пакета — просто `micropki`.

### 3.1. Sprint 1: Инициализация Root CA

Создаёт самоподписанный корневой сертификат и зашифрованный приватный ключ.

**Команда:** `ca init`

**Параметры:**

| Параметр             | Описание                                  | Обязательный | По умолчанию |
|----------------------|-------------------------------------------|--------------|--------------|
| `--subject`          | Distinguished Name (например, `CN=My Root CA,O=Org,C=US`) | Да | — |
| `--key-type`         | Алгоритм ключа: `rsa` или `ecc`           | Нет          | `rsa`        |
| `--key-size`         | Размер ключа: 4096 (RSA) или 384 (ECC)   | Нет          | 4096 / 384   |
| `--passphrase-file`  | Путь к файлу с паролем для шифрования ключа | Да           | —            |
| `--out-dir`          | Выходная директория                      | Нет          | `./pki`      |
| `--validity-days`    | Срок действия сертификата (в днях)       | Нет          | 3650 (~10 лет) |
| `--log-file`         | Путь к файлу логов                       | Нет          | stderr       |
| `--force`            | Перезаписать существующие файлы           | Нет          | `false`      |

**Пример:**

```bash
# Создание директорий и генерация пароля
echo "MySecretPassphrase" > secrets/ca.pass

# Инициализация Root CA
python -m micropki ca init \
    --subject "CN=Demo Root CA,O=MyOrg,C=US" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/ca.pass \
    --out-dir ./pki \
    --validity-days 3650
```

**Выходная структура (`./pki`):**

```
pki/
├── private/
│   └── ca.key.pem     # Зашифрованный приватный ключ Root CA (PKCS#8)
├── certs/
│   └── ca.cert.pem    # Самоподписанный сертификат Root CA
└── policy.txt         # Документ политики
```

---

### 3.2. Sprint 2: Создание Intermediate CA

Создаёт промежуточный УЦ, подписанный корневым УЦ. Это позволяет изолировать Root CA от повседневных операций по выдаче сертификатов.

**Команда:** `ca issue-intermediate`

**Параметры:**

| Параметр             | Описание                                  | Обязательный | По умолчанию |
|----------------------|-------------------------------------------|--------------|--------------|
| `--root-cert`        | Путь к сертификату Root CA (PEM)          | Да | — |
| `--root-key`         | Путь к зашифрованному ключу Root CA (PEM) | Да | — |
| `--root-pass-file`   | Файл с паролем от ключа Root CA           | Да | — |
| `--subject`          | Distinguished Name для Intermediate CA    | Да | — |
| `--key-type`         | `rsa` или `ecc`                           | Нет | `rsa` |
| `--key-size`         | 4096 (RSA) или 384 (ECC)                  | Нет | 4096 / 384 |
| `--passphrase-file`  | Файл с паролем для ключа Intermediate CA  | Да | — |
| `--out-dir`          | Выходная директория                       | Нет | `./pki` |
| `--validity-days`    | Срок действия (в днях)                   | Нет | 1825 (~5 лет) |
| `--pathlen`          | Ограничение длины пути (path length constraint) | Нет | 0 |

**Пример:**

```bash
echo "IntermediatePass" > secrets/intermediate.pass

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

**Результат:** В директории `pki/` появятся:

- `private/intermediate.key.pem` — зашифрованный ключ Intermediate CA
- `certs/intermediate.cert.pem` — сертификат Intermediate CA
- `csrs/intermediate.csr.pem` — файл запроса на сертификат (CSR)
- Обновлённый `policy.txt` с информацией об Intermediate CA

---

### 3.3. Sprint 2: Выпуск конечного сертификата (End-Entity Certificate)

Выпускает сертификат для конечного субъекта (сервер, клиент, код) с использованием шаблона.

**Команда:** `ca issue-cert`

**Параметры:**

| Параметр             | Описание                                       | Обязательный | По умолчанию |
|----------------------|-------------------------------------------------|--------------|--------------|
| `--ca-cert`          | Сертификат УЦ (Intermediate CA) (PEM)         | Да           | —            |
| `--ca-key`           | Зашифрованный ключ УЦ (PEM)                     | Да           | —            |
| `--ca-pass-file`     | Файл с паролем от ключа УЦ                      | Да           | —            |
| `--template`         | Шаблон: `server`, `client`, `code_signing`     | Да           | —            |
| `--subject`          | Distinguished Name субъекта                    | Да           | —            |
| `--san`              | Subject Alternative Name (формат: `тип:значение`, например `dns:example.com`). Может повторяться. | Нет | — |
| `--csr`              | Путь к внешнему CSR (PEM). Если указан, ключ не генерируется. | Нет | — |
| `--out-dir`          | Выходная директория                             | Нет          | `./pki/certs`|
| `--validity-days`    | Срок действия (в днях)                         | Нет          | 365          |
| `--log-file`         | Путь к файлу логов                              | Нет          | stderr       |

**Примеры:**

**1. Серверный сертификат:**
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

**2. Клиентский сертификат (с email):**
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

**3. Сертификат для подписи кода:**
```bash
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs
```

**4. Подписание внешнего CSR:**

```bash
python -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=external.com" \
    --csr ./requests/external.csr.pem \
    --out-dir ./pki/certs
```

**Результат:** Для каждого сертификата будут сгенерированы:
- `*.cert.pem` — сам сертификат
- `*.key.pem` — приватный ключ (незашифрованный, с предупреждением в логах)

---

### 3.4. Sprint 2: Валидация цепочки сертификатов

Проверяет целостность цепочки доверия: конечный сертификат → Intermediate CA → Root CA.

**Команда:** `ca validate-chain`

**Параметры:**

| Параметр             | Описание                           | Обязательный | По умолчанию |
|----------------------|------------------------------------|--------------|--------------|
| `--cert`             | Конечный сертификат (leaf) (PEM)   | Да           | —            |
| `--intermediate`     | Сертификат Intermediate CA (PEM)   | Да           | —            |
| `--root`             | Сертификат Root CA (PEM)           | Да           | —            |
| `--log-file`         | Путь к файлу логов                  | Нет          | stderr       |

**Пример:**

```bash
python -m micropki ca validate-chain \
    --cert ./pki/certs/example.com.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --root ./pki/certs/ca.cert.pem
```

**Результат:**
- `Chain validation PASSED` — если все проверки успешны.
- `FAIL` и подробное сообщение об ошибке — если цепочка невалидна.

---

### 3.5. Sprint 3: Управление базой данных сертификатов

Вводит SQLite базу данных для отслеживания всех выданных сертификатов.

**Команда:** `db init`

**Параметры:**

| Параметр             | Описание                                  | Обязательный | По умолчанию |
|----------------------|-------------------------------------------|--------------|--------------|
| `--db-path`          | Путь к файлу базы данных SQLite           | Нет          | `./pki/micropki.db` |


**Описание:** Создаёт базу данных и таблицу `certificates` со следующей схемой:

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_hex TEXT UNIQUE NOT NULL,          -- hex-представление серийного номера
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,                 -- ISO 8601
    not_after TEXT NOT NULL,                  -- ISO 8601
    cert_pem TEXT NOT NULL,                   -- полное PEM содержимое
    status TEXT NOT NULL,                     -- 'valid', 'revoked', 'expired'
    revocation_reason TEXT,                   -- NULL если не отозван
    revocation_date TEXT,                     -- NULL если не отозван
    created_at TEXT NOT NULL                  -- дата выдачи (ISO 8601)
);
```

**Пример:**

```bash
python -m micropki db init --db-path ./pki/micropki.db
```

---

### 3.6. Sprint 3: Работа с базой данных сертификатов

#### Список всех сертификатов

**Команда:** `ca list-certs`

**Параметры:**

| Параметр             | Описание                                  | Обязательный | По умолчанию |
|----------------------|-------------------------------------------|--------------|--------------|
| `--status`           | Фильтр по статусу (`valid`, `revoked`, `expired`) | Нет | нет |
| `--format`           | Формат вывода (`table`, `json`, `csv`)    | Нет          | `table`      |

**Пример:**

```bash
# Список всех валидных сертификатов в табличном виде
python -m micropki ca list-certs --status valid --format table
```

#### Просмотр одного сертификата

**Команда:** `ca show-cert <serial>`

**Параметры:**

| Параметр             | Описание                                  | Обязательный |
|----------------------|-------------------------------------------|--------------|
| `<serial>`           | Серийный номер сертификата в hex          | Да           |

**Пример:**

```bash
# Показать сертификат по его серийному номеру
python -m micropki ca show-cert 2A7F1234567890ABCDEF --format pem
```

---

### 3.7. Sprint 3: Запуск HTTP-репозитория

Запускает локальный HTTP-сервер для обслуживания сертификатов и списков отзыва (CRL).

**Команда:** `repo serve`

**Параметры:**

| Параметр             | Описание                                  | Обязательный | По умолчанию |
|----------------------|-------------------------------------------|--------------|--------------|
| `--host`             | Хост для привязки сервера                 | Нет          | `127.0.0.1`  |
| `--port`             | TCP порт                                  | Нет          | `8080`       |
| `--db-path`          | Путь к базе данных SQLite                 | Нет          | `./pki/micropki.db` |
| `--cert-dir`         | Директория с сертификатами (PEM)          | Нет          | `./pki/certs` |


**Пример:**

```bash
python -m micropki repo serve --host 0.0.0.0 --port 8443 --db-path ./pki/micropki.db
```

**Доступные REST-эндпоинты:**

- `GET /certificate/<serial>` — Возвращает сертификат по его серийному номеру.
- `GET /ca/root` — Возвращает корневой сертификат.
- `GET /ca/intermediate` — Возвращает сертификат промежуточного УЦ.
- `GET /crl` — Заглушка для Sprint 3. Возвращает `501 Not Implemented`.

**Примеры запросов:**

```bash
# Получить сертификат
curl http://localhost:8080/certificate/2A7F1234567890ABCDEF --output cert.pem

# Получить корневой сертификат
curl http://localhost:8080/ca/root --output root.pem

# Получить промежуточный сертификат
curl http://localhost:8080/ca/intermediate --output intermediate.pem
```

---

## 4. Шаблоны сертификатов

| Шаблон          | Key Usage                                  | Extended Key Usage | Допустимые SAN        | SAN обязателен |
|-----------------|--------------------------------------------|--------------------|----------------------|----------------|
| `server`        | digitalSignature, keyEncipherment (RSA)    | serverAuth         | dns, ip              | Да             |
| `client`        | digitalSignature                           | clientAuth         | dns, email, ip, uri  | Нет            |
| `code_signing`  | digitalSignature                           | codeSigning        | dns, uri             | Нет            |


---

## 5. Логирование

- Все логи содержат временную метку (ISO 8601 с миллисекундами), уровень (`INFO`, `WARNING`, `ERROR`) и сообщение.
- При запуске `repo serve`, каждый HTTP-запрос также логируется.
- Параметр `--log-file` направляет вывод в файл, иначе — в stderr.

---

## 6. Верификация через OpenSSL

После выпуска сертификатов их можно проверить с помощью OpenSSL:

```bash
# Просмотр содержимого сертификата
openssl x509 -in pki/certs/intermediate.cert.pem -text -noout

# Проверка подписи Intermediate CA корневым УЦ
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/intermediate.cert.pem

# Проверка конечного сертификата через полную цепочку
openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem
```

---

## 7. Важные замечания

- **Безопасность:** Приватные ключи Root и Intermediate CA хранятся зашифрованными. Ключи конечных субъектов (end-entity) хранятся незашифрованными — это осознанное решение для упрощения использования, но сопровождается предупреждением в логах.
- **Серийные номера:** Гарантированно уникальны. Для Sprint 3 используется комбинированный подход: часть от времени + CSPRNG.
- **Расширения:** Все обязательные расширения X.509v3 (BasicConstraints, KeyUsage, SKI, AKI) устанавливаются корректно, согласно RFC 5280.
- **Расширяемость:** Архитектура проекта позволяет легко добавлять новые команды и функции в будущих спринтах (например, отзыв сертификатов, CRL, OCSP).

---

**Документация завершена.**
