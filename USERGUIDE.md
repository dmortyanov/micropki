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
python -m micropki ca init ^
  --subject "CN=Demo Root CA,O=MyOrg,C=US" ^
  --key-type rsa ^
  --key-size 4096 ^
  --passphrase-file ./pki/secrets/ca.pass ^
  --out-dir ./pki ^
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
python -m micropki ca issue-intermediate ^
  --root-cert ./pki/certs/ca.cert.pem ^
  --root-key ./pki/private/ca.key.pem ^
  --root-pass-file ./pki/secrets/ca.pass ^
  --subject "CN=MicroPKI Intermediate CA,O=MyOrg" ^
  --key-type rsa ^
  --key-size 4096 ^
  --passphrase-file ./pki/secrets/intermediate.pass ^
  --out-dir ./pki ^
  --validity-days 1825 ^
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
python -m micropki ca issue-cert ^
  --ca-cert ./pki/certs/intermediate.cert.pem ^
  --ca-key ./pki/private/intermediate.key.pem ^
  --ca-pass-file ./pki/secrets/intermediate.pass ^
  --template server ^
  --subject "CN=example.com,O=MyOrg" ^
  --san dns:example.com ^
  --san dns:www.example.com ^
  --san ip:192.168.1.10 ^
  --out-dir ./pki/certs ^
  --validity-days 365
```

### Пример: client сертификат
```bash
python -m micropki ca issue-cert ^
  --ca-cert ./pki/certs/intermediate.cert.pem ^
  --ca-key ./pki/private/intermediate.key.pem ^
  --ca-pass-file ./pki/secrets/intermediate.pass ^
  --template client ^
  --subject "CN=Alice Smith" ^
  --san email:alice@example.com ^
  --out-dir ./pki/certs 
```

### Пример: code signing сертификат
```bash
python -m micropki ca issue-cert ^
  --ca-cert ./pki/certs/intermediate.cert.pem ^
  --ca-key ./pki/private/intermediate.key.pem ^
  --ca-pass-file ./pki/secrets/intermediate.pass ^
  --template code_signing ^
  --subject "CN=MicroPKI Code Signer" ^
  --out-dir ./pki/certs
```

### (Опция Sprint 2) Выпуск по внешнему CSR
Если есть внешний CSR PEM:
```bash
python -m micropki ca issue-cert ^
  --ca-cert ./pki/certs/intermediate.cert.pem ^
  --ca-key ./pki/private/intermediate.key.pem ^
  --ca-pass-file ./pki/secrets/intermediate.pass ^
  --template server ^
  --subject "CN=from-csr.example.com,O=MyOrg" ^
  --csr ./path/to/request.csr.pem ^
  --out-dir ./pki/certs
```

Важно:
- если CSR просит `BasicConstraints: CA=TRUE`, выпуск end-entity отклоняется

## 2.3) Валидация цепочки ( `ca validate-chain` )
```bash
python -m micropki ca validate-chain ^
  --cert ./pki/certs/example.com.cert.pem ^
  --intermediate ./pki/certs/intermediate.cert.pem ^
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
python -m micropki repo serve ^
  --host 127.0.0.1 ^
  --port 8080 ^
  --db-path ./pki/micropki.db ^
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

### GET /crl и /crl/<ca>.crl (Sprint 4)
```bash
curl http://127.0.0.1:8080/crl/intermediate.crl --output crl.pem
```

---

## Sprint 4: Отзыв сертификатов и CRL

### Отзыв сертификата ( `ca revoke` )
Отзывает выданный ранее сертификат и помечает его статус как `revoked` в базе.
```bash
python -m micropki ca revoke <SERIAL_HEX> --reason keycompromise --force
```
- `--reason` — причина отзыва (по умолчанию `unspecified`)
- `--force` — не запрашивать подтверждение (y/N)

### Проверка статуса отзыва ( `ca check-revoked` )
Быстрая проверка статуса (удобно для скриптов).
```bash
python -m micropki ca check-revoked <SERIAL_HEX>
```

### Генерация списка отзыва ( `ca gen-crl` )
Создает файл CRL.
```bash
python -m micropki ca gen-crl --ca intermediate --next-update 14
```
- `--ca` — уровень УЦ (`root` или `intermediate`)
- `--next-update` — срок действия CRL в днях (по умолчанию 7)


---

## Тестирование

> Все тесты расположены в каталоге `tests/` и запускаются с помощью `pytest`.
> Перед запуском убедитесь, что виртуальное окружение активно и зависимости установлены.

### Общий запуск всех тестов

```bash
# Запустить все тесты с подробным выводом
pytest tests/ -v

# С покрытием кода
pytest tests/ -v --cov=micropki --cov-report=term-missing

# Только «упавшие» тесты (быстрая перепроверка)
pytest tests/ -v --tb=short -x
```

---

### Sprint 1 — Root CA, криптоутилиты, CLI (базовый)

| Файл | Что проверяется |
|------|-----------------|
| `test_ca.py` | Инициализация Root CA: генерация ключа, подпись сертификата, policy.txt |
| `test_certificates.py` | Генерация X.509 v3 сертификатов, сериализация PEM, загрузка с диска |
| `test_crypto_utils.py` | Генерация RSA/ECC ключей, шифрование/дешифрование PEM, парсинг DN |
| `test_cli.py` | CLI-парсер: аргументы `ca init`, валидация, обработка ошибок |

```bash
# Запуск тестов Sprint 1
pytest tests/test_ca.py tests/test_certificates.py tests/test_crypto_utils.py tests/test_cli.py -v
```

---

### Sprint 2 — Intermediate CA, шаблоны, CSR, цепочка

| Файл | Что проверяется |
|------|-----------------|
| `test_intermediate.py` | Intermediate CA: CSR → подпись Root → цепочка, pathlen, расширения |
| `test_csr.py` | Генерация и верификация CSR (PKCS#10) |
| `test_templates.py` | Шаблоны `server`/`client`/`code_signing`, SAN-валидация, KeyUsage |
| `test_chain.py` | Валидация цепочки сертификатов (leaf → intermediate → root) |
| `test_cli_sprint2.py` | CLI: `issue-intermediate`, `issue-cert`, `validate-chain` |

```bash
# Запуск тестов Sprint 2
pytest tests/test_intermediate.py tests/test_csr.py tests/test_templates.py tests/test_chain.py tests/test_cli_sprint2.py -v
```

---

### Sprint 3 — База данных, HTTP-репозиторий, Serial

| Файл | Что проверяется |
|------|-----------------|
| `test_sprint3_db_cli.py` | SQLite схема, CRUD операции, CLI `db init`, `list-certs`, `show-cert` |
| `test_sprint3_repository_api.py` | HTTP-сервер: GET `/certificate/<serial>`, `/ca/root`, `/ca/intermediate`, 404/405 |
| `test_sprint3_serial_uniqueness.py` | Уникальность серийных номеров (последовательный + случайный компонент) |

```bash
# Запуск тестов Sprint 3
pytest tests/test_sprint3_db_cli.py tests/test_sprint3_repository_api.py tests/test_sprint3_serial_uniqueness.py -v
```

---

### Sprint 4 — Отзыв сертификатов и CRL

| Файл | Что проверяется |
|------|-----------------|
| `test_sprint4.py` | Жизненный цикл отзыва: `revoke` → статус в БД → `gen-crl` → CRL содержит серийный номер; инкремент `CRLNumber`; верификация CRL через OpenSSL |

```bash
# Запуск тестов Sprint 4
pytest tests/test_sprint4.py -v
```

---

### Верификация через OpenSSL (ручная)

Помимо автоматических тестов, результаты удобно проверять через `openssl`:

```bash
# Просмотр сертификата
openssl x509 -in pki/certs/intermediate.cert.pem -text -noout

# Проверка цепочки
openssl verify -CAfile pki/certs/ca.cert.pem \
    -untrusted pki/certs/intermediate.cert.pem \
    pki/certs/example.com.cert.pem

# Просмотр CRL
openssl crl -in pki/crl/intermediate.crl.pem -text -noout

# Проверка подписи CRL
openssl crl -in pki/crl/intermediate.crl.pem -CAfile pki/certs/intermediate.cert.pem -verify -noout
```

## Конечный “сквозной” сценарий (1 → 2 → 3 → 4)

Пример последовательности (идея):
1. `ca init` (Root CA)
2. `ca issue-intermediate` (Intermediate CA)
3. `ca issue-cert` (leaf сертификаты)
4. `db init` (SQLite схема)
5. `repo serve` (в отдельном окне)
6. `ca revoke` и `ca gen-crl` (отзыв и генерация CRL)
7. `curl` по `/certificate/<serial>` / `/ca/root` / `/ca/intermediate` / `/crl`

