#!/bin/bash
set -euo pipefail

echo "[*] Starting ADB server..."
adb start-server

echo "[*] Connecting to Redroid at redroid:5555..."
if ! adb connect redroid:5555; then
    echo "[!] ERROR: Failed to connect to Redroid via ADB"
    exit 1
fi

echo "[*] Waiting for device..."
adb wait-for-device

echo "[*] Verifying device is reachable..."
adb shell true || {
    echo "[!] ERROR: Device not responding"
    exit 1
}

echo "[*] Running ADB as root..."
adb root

echo "[*] Pushing frida-server..."
adb push /app/frida-server /data/local/tmp/frida-server

echo "[*] Setting permissions..."
adb shell chmod 755 /data/local/tmp/frida-server

echo "[*] Starting frida-server in background..."
adb shell "/data/local/tmp/frida-server >/dev/null 2>&1 &"

echo "[✓] Frida server running"


# ---- Start ZAP ----
echo "[*] Starting ZAP daemon..."
/app/ZAP_2.17.0/zap.sh \
    -daemon \
    -host 0.0.0.0 \
    -port 8080 \
    -config api.disablekey=true &

echo "[*] Waiting for ZAP..."
until curl -s http://localhost:8080/JSON/core/view/version/ >/dev/null; do
    sleep 2
done

echo "[✓] ZAP ready"

# ---- Start Napscan ----
echo "[*] Starting Napscan..."
exec /app/napscan
