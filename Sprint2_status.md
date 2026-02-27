# Sprint 2 — Статус выполнения требований

**Цель спринта:** Расширить PKI — создать Intermediate CA (промежуточный удостоверяющий центр) и реализовать движок шаблонов сертификатов для генерации серверных, клиентских и code signing сертификатов с расширениями X.509v3 и поддержкой SAN.

---

## 1. Структура проекта и репозиторий

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| STR-6 | Новые модули в логичной структуре (`csr.py`, `templates.py`, `chain.py`)      | Must      | Done   | `micropki/csr.py`, `micropki/templates.py`, `micropki/chain.py` |
| STR-7 | `README.md` обновлён с примерами Sprint 2                                     | Must      | Done   | Добавлены примеры `issue-intermediate`, `issue-cert`, `validate-chain` |
| STR-8 | Новый код следует стилю, документации и тестам Sprint 1                        | Must      | Done   | Docstrings, type hints, pytest — идентичный стиль        |

## 2. Интерфейс командной строки (CLI)

| ID     | Требование                                                                    | Приоритет | Статус | Реализация                                              |
|--------|-------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| CLI-7  | Подкоманда `ca issue-intermediate` с аргументами: --root-cert, --root-key, --root-pass-file, --subject, --key-type, --key-size, --passphrase-file, --out-dir, --validity-days, --pathlen | Must | Done | `cli.py` — `inter_parser` со всеми аргументами |
| CLI-8  | Подкоманда `ca issue-cert` с аргументами: --ca-cert, --ca-key, --ca-pass-file, --template, --subject, --san, --out-dir, --validity-days | Must | Done | `cli.py` — `cert_parser` со всеми аргументами |
| CLI-9  | Множественные SAN-записи через повторение `--san`                             | Must      | Done   | `--san` с `action="append"`, парсинг `type:value`        |
| CLI-10 | Валидация совместимости SAN-типов с шаблоном                                  | Should    | Done   | `validate_san_for_template()` в `templates.py`           |
| CLI-11 | Опциональный `--csr` для подписания внешнего CSR                              | Could     | Done   | `--csr` аргумент в `cert_parser`, валидация файла в `validate_issue_cert_args()` |

## 3. Реализация PKI

| ID     | Требование                                                                    | Приоритет | Статус | Реализация                                              |
|--------|-------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| PKI-6  | Генерация PKCS#10 CSR для Intermediate CA (subject, public key, BasicConstraints) | Must | Done | `csr.py::generate_csr()` с `is_ca=True`, `path_length` |
| PKI-7  | Root CA подписывает CSR Intermediate: v3, serial (CSPRNG), BasicConstraints(pathlen), KeyUsage, SKI, AKI | Must | Done | `certificates.py::sign_intermediate_certificate()` — все расширения |
| PKI-8  | Три шаблона end-entity: `server`, `client`, `code_signing` с правильными EKU и KeyUsage | Must | Done | `templates.py` — `SERVER_TEMPLATE`, `CLIENT_TEMPLATE`, `CODE_SIGNING_TEMPLATE` |
| PKI-9  | Парсинг SAN: `dns`, `ip`, `email`, `uri` → GeneralName per RFC 5280          | Must      | Done   | `parse_san_strings()`, `build_san_extension()` — DNSName, IPAddress, RFC822Name, URI |
| PKI-10 | Сертификаты в PEM. Intermediate → `intermediate.cert.pem`, end-entity → по CN | Must | Done | `issue_intermediate_ca()`, `issue_certificate()` + `_safe_filename()` |
| PKI-11 | Генерация ключа для end-entity (RSA-2048 / ECC P-256), сохранение незашифрованным, 0o600 | Must | Done | `generate_key()` + `serialize_private_key_unencrypted()` + warning в логах |
| PKI-12 | Подписание внешнего CSR (--csr): верификация подписи CSR, извлечение public key, отклонение CA=TRUE | Could | Done | `ca.py::issue_certificate()` — `verify_csr()`, проверка BasicConstraints, без сохранения ключа |

## 4. Безопасное хранение ключей

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| KEY-5 | Intermediate CA ключ зашифрован (PKCS#8/AES-256), `intermediate.key.pem`, 0o600 | Must | Done | `serialize_private_key()` → `private/intermediate.key.pem` |
| KEY-6 | Структура директорий: `private/`, `certs/`, `csrs/`, `policy.txt`             | Must      | Done   | `csrs/` создаётся при `issue-intermediate`, CSR сохраняется |
| KEY-7 | End-entity ключ сохраняется незашифрованным с предупреждением                  | Must      | Done   | `logger.warning("WARNING: ... UNENCRYPTED ...")` + 0o600  |

## 5. Документ политики и логирование

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| POL-2 | `policy.txt` дополнен секцией Intermediate CA (DN, serial, validity, algo, pathlen, issuer) | Must | Done | `_append_intermediate_policy()` в `ca.py` |
| LOG-4 | Логирование Sprint 2 операций: CSR генерация, подписание, выдача сертификатов, ошибки валидации | Must | Done | INFO-записи в `issue_intermediate_ca()` и `issue_certificate()` |
| LOG-5 | Аудит выдачи: serial, subject, template, timestamp                            | Should    | Done   | `logger.info("Certificate issued. Serial: %s, Template: %s, Subject: %s, SANs: %s", ...)` |

## 6. Тестирование и верификация

| ID      | Требование                                                                   | Приоритет | Статус | Реализация                                              |
|---------|------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| TEST-7  | Валидация цепочки leaf → intermediate → root (подписи, validity, BC, pathlen) | Must | Done | `chain.py::validate_chain()` + `ca validate-chain` CLI + `test_chain.py` |
| TEST-8  | Проверка расширений через OpenSSL (наличие SAN, critical/non-critical)       | Must      | Done   | Инструкция `openssl x509 -text -noout` в README          |
| TEST-9  | Round-trip тест: сертификат работает в TLS (openssl s_server/s_client)       | Should    | Done   | Документированная процедура в README                      |
| TEST-10 | Негативные тесты: server без SAN, неподдерживаемый SAN-тип, неверный пароль  | Should    | Done   | `test_cli_sprint2.py` + `test_templates.py`              |
| TEST-11 | Совместимость с OpenSSL: `openssl verify -CAfile root -untrusted inter leaf` | Should    | Done   | Документированная команда в README                        |
| TEST-12 | Unit-тесты: CSR генерация, расширения, SAN парсинг, шаблоны                  | Must      | Done   | `test_csr.py`, `test_templates.py`, `test_intermediate.py` |

---

**Итого:** все требования выполнены (включая Could).
