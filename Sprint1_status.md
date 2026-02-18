# Sprint 1 — Статус выполнения требований

**Цель спринта:** Создать фундамент PKI — самоподписанный Root CA с безопасным хранением ключей, генерацией сертификатов и базовым аудит-логированием.

---

## 1. Структура проекта и репозиторий

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| STR-1 | Git-репозиторий с `.gitignore` (исключает артефакты, venv, приватные ключи)    | Must      | Done   | `.gitignore` — venv, pki/, secrets/, logs/, __pycache__ |
| STR-2 | `README.md` с описанием, инструкцией сборки, примером использования, зависимостями | Must | Done | README.md — все четыре раздела                          |
| STR-3 | `requirements.txt` с зависимостями (`cryptography`)                           | Must      | Done   | `requirements.txt` — cryptography, pytest, pytest-cov   |
| STR-4 | Логичная организация исходного кода                                            | Should    | Done   | `micropki/` — cli, ca, certificates, crypto_utils, logger |
| STR-5 | Скрипт для запуска тестов                                                      | Should    | Done   | `pytest tests/ -v` (описано в README)                   |

## 2. Интерфейс командной строки (CLI)

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| CLI-1 | Инструмент вызывается как `micropki`                                          | Must      | Done   | `python -m micropki` через `__main__.py`                |
| CLI-2 | Подкоманда `ca init` для создания Root CA, расширяемый парсер                 | Must      | Done   | `cli.py` — argparse с subparsers                        |
| CLI-3 | Аргументы: --subject, --key-type, --key-size, --passphrase-file, --out-dir, --validity-days, --log-file | Must | Done | Все аргументы реализованы в `cli.py`            |
| CLI-4 | Валидация всех входных данных с понятными ошибками                            | Must      | Done   | `validate_args()` — проверка DN, размера ключа, файла пароля, validity |
| CLI-5 | Безопасная обработка пароля (чтение из файла, без вывода в логи)              | Must      | Done   | `read_passphrase()` — чтение байтов, strip newline       |
| CLI-6 | Защита от перезаписи (--force)                                                | Could     | Done   | Проверка существования файлов + флаг `--force`           |

## 3. Реализация PKI

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| PKI-1 | Генерация ключей: RSA-4096, ECC P-384                                         | Must      | Done   | `crypto_utils.generate_key()` — rsa / ec.SECP384R1      |
| PKI-2 | Самоподписанный X.509v3 сертификат (serial, subject, validity, signature algo) | Must | Done | `certificates.create_self_signed_cert()` — SHA256/SHA384 |
| PKI-3 | Расширения: BasicConstraints(CA=TRUE, critical), KeyUsage(critical), SKI, AKI  | Must | Done | Все 4 расширения, SKI == AKI для self-signed             |
| PKI-4 | Кодирование сертификата в PEM                                                  | Must      | Done   | `serialize_certificate()` — `BEGIN CERTIFICATE`          |
| PKI-5 | Вывод сертификата как `ca.cert.pem` в `certs/`                                | Must      | Done   | `save_certificate()` → `<out-dir>/certs/ca.cert.pem`    |

## 4. Безопасное хранение ключей

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| KEY-1 | Приватный ключ зашифрован паролем (PKCS#8, BestAvailableEncryption)           | Must      | Done   | `serialize_private_key()` — `ENCRYPTED PRIVATE KEY`      |
| KEY-2 | Ключ сохраняется как `ca.key.pem` в `private/`                               | Must      | Done   | `save_private_key()` → `<out-dir>/private/ca.key.pem`   |
| KEY-3 | Права доступа: директория 0o700, файл ключа 0o600 (+ warning на Windows)     | Must      | Done   | `save_private_key()` — chmod на Unix, skip на Windows    |
| KEY-4 | Структура директорий: private/, certs/, policy.txt                            | Must      | Done   | Создаётся автоматически в `ca.py`                        |

## 5. Документ политики и логирование

| ID    | Требование                                                                     | Приоритет | Статус | Реализация                                              |
|-------|--------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| POL-1 | `policy.txt` с DN, серийным номером, validity, алгоритмом, назначением, версией | Must | Done | `_write_policy()` в `ca.py`                              |
| LOG-1 | Логирование в файл (--log-file) или stderr, ISO 8601 с мс, уровень, сообщение | Must | Done | `logger.py` — `_MillisecondFormatter`                    |
| LOG-2 | Обязательные события: start/end генерации ключа, подписания, сохранения файлов | Must | Done | 7 log-записей уровня INFO в `init_root_ca()`            |
| LOG-3 | Пароль никогда не появляется в логах                                          | Must      | Done   | Passphrase не передаётся в logger                        |

## 6. Тестирование и верификация

| ID     | Требование                                                                    | Приоритет | Статус | Реализация                                              |
|--------|-------------------------------------------------------------------------------|-----------|--------|---------------------------------------------------------|
| TEST-1 | Самоверификация сертификата (verify signature с собственным public key)       | Must      | Done   | `test_ca.py::TestSelfConsistency` (RSA + ECC)           |
| TEST-2 | Соответствие приватного ключа и сертификата (sign + verify)                   | Must      | Done   | `test_ca.py::TestKeyCertMatching` (RSA + ECC)           |
| TEST-3 | Загрузка зашифрованного ключа с правильным паролем                           | Must      | Done   | `test_ca.py::TestEncryptedKeyLoading` + wrong passphrase |
| TEST-4 | Негативные/граничные случаи (missing subject, wrong key size, bad file, etc.) | Should | Done | `test_cli.py::TestCLIValidation` — 6 сценариев          |
| TEST-5 | Автоматизированные unit-тесты (key gen, DN parsing, PEM, cert extensions)     | Should | Done | `test_crypto_utils.py` + `test_certificates.py`          |
| TEST-6 | Совместимость с OpenSSL                                                       | Could     | Done   | Инструкция верификации через openssl в README             |

---

**Итого:** все требования выполнены.
