#!/bin/bash
set -euo pipefail

echo "============================================"
echo "  PKCS#12 Export/Import Test"
echo "============================================"

USB=/tmp/usb_simulation
mkdir -p "$USB"
echo "P12Password" > p12_pass.txt

echo ""
echo ">>> Шаг 1: Экспорт Root CA на 'флешку' ($USB)"
python3 -m micropki.cli ca export \
  --ca-cert ./demo_pki/pki/certs/ca.cert.pem \
  --ca-key ./demo_pki/pki/private/ca.key.pem \
  --ca-pass-file ./demo_pki/secrets/ca.pass \
  --out-p12 "$USB/root_ca.p12" \
  --p12-pass-file p12_pass.txt
echo "[OK] Экспорт завершён: $USB/root_ca.p12"

echo ""
echo ">>> Шаг 2: Удаляем локальный ключ CA"
rm -f ./demo_pki/pki/private/ca.key.pem
echo "[OK] Ключ удалён"

echo ""
echo ">>> Шаг 3: Попытка выпустить сертификат БЕЗ ключа (должна быть ошибка)"
if python3 -m micropki.cli ca issue-cert \
  --ca-cert ./demo_pki/pki/certs/ca.cert.pem \
  --ca-key ./demo_pki/pki/private/ca.key.pem \
  --ca-pass-file ./demo_pki/secrets/ca.pass \
  --template server \
  --subject "CN=test.example.com" \
  --san dns:test.example.com \
  --out-dir ./demo_pki/pki/certs 2>&1; then
  echo "[FAIL] Команда должна была завершиться ошибкой!"
  exit 1
else
  echo "[OK] Ожидаемая ошибка — ключ отсутствует, выпуск невозможен"
fi

echo ""
echo ">>> Шаг 4: Импорт ключа с 'флешки' обратно"
python3 -m micropki.cli ca import \
  --in-p12 "$USB/root_ca.p12" \
  --p12-pass-file p12_pass.txt \
  --new-pass-file ./demo_pki/secrets/ca.pass \
  --out-dir ./demo_pki/pki
echo "[OK] Ключ восстановлен"

echo ""
echo ">>> Шаг 5: Повторная попытка выпустить сертификат"
python3 -m micropki.cli ca issue-cert \
  --ca-cert ./demo_pki/pki/certs/ca.cert.pem \
  --ca-key ./demo_pki/pki/private/ca.key.pem \
  --ca-pass-file ./demo_pki/secrets/ca.pass \
  --template server \
  --subject "CN=test.example.com" \
  --san dns:test.example.com \
  --out-dir ./demo_pki/pki/certs
echo "[OK] Сертификат успешно выпущен"

echo ""
echo "============================================"
echo "  Тест пройден! PKCS#12 работает корректно"
echo "============================================"
