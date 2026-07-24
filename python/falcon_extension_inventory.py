#!/usr/bin/env python3
"""
CrowdStrike Falcon - Browser Extension Inventory Toplu Calistirici
=====================================================================
Bu script, bir host group'taki tum aktif (online) Windows host'larda
"BrowserExtensionInventory" adli RTR custom script'ini calistirir,
sonuclari toplar ve tek bir CSV dosyasinda birlestirir.

GEREKSINIMLER:
  - Python 3.8+
  - pip install requests
  - Falcon API Client ID / Secret (scope: Real Time Response Read/Write, Hosts Read)
  - Host group ID (Falcon konsolu > Host Management > Host Groups)
  - RTR Custom Script'in Falcon'a zaten yuklenmis olmasi (Name: BrowserExtensionInventory)

KULLANIM:
  Ortam degiskenleri ile (onerilen, kimlik bilgisi terminal gecmisinde kalmaz):
    export FALCON_CLIENT_ID="..."
    export FALCON_CLIENT_SECRET="..."
    export FALCON_BASE_URL="https://api.crowdstrike.com"   # bolgene gore degisebilir
    python3 falcon_extension_inventory.py --host-group-id <GROUP_ID> --script-name BrowserExtensionInventory

  Ya da parametre ile:
    python3 falcon_extension_inventory.py --client-id "..." --client-secret "..." \
        --host-group-id <GROUP_ID> --script-name BrowserExtensionInventory

NOT - API Base URL bolgeye gore degisir:
    US-1:   https://api.crowdstrike.com
    US-2:   https://api.us-2.crowdstrike.com
    EU-1:   https://api.eu-1.crowdstrike.com
    US-GOV: https://api.laggar.gcw.crowdstrike.com
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime

import requests

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
POLL_INTERVAL_SECONDS = 5
MAX_POLL_ATTEMPTS = 24  # 24 * 5sn = 120 saniye ek bekleme (host basina, ilk timeout'a EK olarak)
BATCH_INIT_TIMEOUT = 90  # saniye, ilk batch-command isteginde sunucunun beklemesi


def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def get_oauth_token(base_url, client_id, client_secret):
    """Falcon API icin OAuth2 access token alir."""
    url = f"{base_url}/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"client_id": client_id, "client_secret": client_secret}

    resp = requests.post(url, headers=headers, data=data, timeout=30)
    if resp.status_code != 201:
        log(f"HATA: Token alinamadi. HTTP {resp.status_code} - {resp.text}")
        sys.exit(1)

    token = resp.json().get("access_token")
    if not token:
        log("HATA: Token cevapta bulunamadi.")
        sys.exit(1)

    return token


def get_host_group_member_ids(base_url, token, host_group_id):
    """Belirtilen host group'taki tum device ID'leri sayfalayarak ceker."""
    url = f"{base_url}/devices/combined/host-group-members/v1"
    headers = {"Authorization": f"Bearer {token}"}

    all_ids = []
    offset = 0
    limit = 100

    while True:
        params = {"id": host_group_id, "limit": limit, "offset": offset}
        resp = requests.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code != 200:
            log(f"HATA: Host group uyeleri cekilemedi. HTTP {resp.status_code} - {resp.text}")
            sys.exit(1)

        body = resp.json()
        resources = body.get("resources", [])

        for device in resources:
            device_id = device.get("device_id")
            hostname = device.get("hostname", "unknown")
            online_state = device.get("state", "unknown")
            all_ids.append({"device_id": device_id, "hostname": hostname, "state": online_state})

        meta = body.get("meta", {}).get("pagination", {})
        total = meta.get("total", 0)
        offset += limit

        if offset >= total or not resources:
            break

    return all_ids


def init_batch_session(base_url, token, device_ids, timeout_seconds=BATCH_INIT_TIMEOUT):
    """Verilen device ID listesi icin batch RTR session baslatir."""
    url = f"{base_url}/real-time-response/combined/batch-init-session/v1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "host_ids": device_ids,
        "queue_offline": False,  # offline host'lari kuyruga almiyoruz, sadece online'lar
    }
    params = {"timeout": timeout_seconds}

    resp = requests.post(url, headers=headers, params=params, json=payload, timeout=timeout_seconds + 30)

    if resp.status_code not in (200, 201):
        log(f"HATA: Batch session baslatilamadi. HTTP {resp.status_code} - {resp.text}")
        sys.exit(1)

    body = resp.json()
    batch_id = body.get("batch_id")
    resources = body.get("resources", {})

    if not batch_id:
        log("HATA: Batch ID cevapta bulunamadi.")
        sys.exit(1)

    return batch_id, resources


def execute_script_on_batch(base_url, token, batch_id, script_name, timeout_seconds=BATCH_INIT_TIMEOUT):
    """
    Batch session uzerinde RTR custom script'ini calistirir (runscript komutu).
    NOT: 'runscript' bir RTR-Admin seviyesi komuttur. Bu yuzden ne
    'batch-command/v1' (Read-Only) ne de 'batch-active-responder-command/v1'
    (Active Responder) kullanilabilir -- ikisi de "Command not found" / "file not found"
    hatasi verir. Dogru endpoint: 'batch-admin-command/v1'.
    Bu, API Client scope'unda "Real Time Response (Admin): WRITE" gerektirir
    (sadece "Real Time Response: Read/Write" yeterli degildir).
    """
    url = f"{base_url}/real-time-response/combined/batch-admin-command/v1"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "base_command": "runscript",
        "command_string": f'runscript -CloudFile="{script_name}"',
        "batch_id": batch_id,
    }
    params = {"timeout": timeout_seconds}

    resp = requests.post(url, headers=headers, params=params, json=payload, timeout=timeout_seconds + 30)

    if resp.status_code not in (200, 201):
        log(f"HATA: Script calistirma komutu gonderilemedi. HTTP {resp.status_code} - {resp.text}")
        sys.exit(1)

    return resp.json()


def poll_incomplete_commands(base_url, token, command_response, max_attempts=MAX_POLL_ATTEMPTS, interval=POLL_INTERVAL_SECONDS):
    """
    batch-admin-command cevabinda 'complete: false' donen host'lar icin,
    her host'un kendi 'cloud_request_id' degeriyle
    GET /real-time-response/entities/admin-command/v1 endpoint'ine
    tekil olarak tekrar tekrar sorar (batch icin ayri bir status endpoint'i yok,
    CrowdStrike API'sinde durum sorgusu host bazli yapilir).
    """
    url = f"{base_url}/real-time-response/entities/admin-command/v1"
    headers = {"Authorization": f"Bearer {token}"}

    resources = command_response.get("combined", {}).get("resources", {})

    # Her pending host icin cloud_request_id'yi cikar
    pending = {}
    for device_id, result in resources.items():
        if result.get("complete", False) or result.get("offline_queued", False):
            continue
        cloud_request_id = result.get("cloud_request_id")
        if cloud_request_id:
            pending[device_id] = cloud_request_id

    if not pending:
        return command_response

    log(f"  {len(pending)} host icin sonuc bekleniyor, polling baslatiliyor...")

    for attempt in range(1, max_attempts + 1):
        time.sleep(interval)

        still_pending = {}
        for device_id, cloud_request_id in pending.items():
            params = {"cloud_request_id": cloud_request_id, "sequence_id": 0}
            try:
                resp = requests.get(url, headers=headers, params=params, timeout=30)
            except requests.RequestException as e:
                log(f"  UYARI: {device_id} icin poll istegi basarisiz: {e}")
                still_pending[device_id] = cloud_request_id
                continue

            if resp.status_code not in (200, 201):
                log(f"  UYARI: {device_id} poll HTTP {resp.status_code} - {resp.text[:150]}")
                still_pending[device_id] = cloud_request_id
                continue

            body = resp.json()
            host_resources = body.get("resources", [])
            if not host_resources:
                still_pending[device_id] = cloud_request_id
                continue

            result = host_resources[0]
            if result.get("complete", False):
                resources[device_id] = result
            else:
                still_pending[device_id] = cloud_request_id

        pending = still_pending
        log(f"  Poll denemesi {attempt}/{max_attempts}: {len(pending)} host hala bekliyor...")

        if not pending:
            break

    if pending:
        log(f"  UYARI: {len(pending)} host, maksimum bekleme suresinde tamamlanamadi (timeout kalacak).")

    command_response["combined"]["resources"] = resources
    return command_response


def parse_command_results(command_response, host_lookup):
    """
    Batch-command cevabindan her host icin stdout/stderr/durum bilgisini cikarir.
    host_lookup: device_id -> hostname eslemesi (raporda okunabilirlik icin)
    """
    parsed = []
    resources = command_response.get("combined", {}).get("resources", {})

    for device_id, result in resources.items():
        hostname = host_lookup.get(device_id, device_id)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        complete = result.get("complete", False)
        offline_queued = result.get("offline_queued", False)

        parsed.append({
            "device_id": device_id,
            "hostname": hostname,
            "stdout": stdout,
            "stderr": stderr,
            "complete": complete,
            "offline_queued": offline_queued,
        })

    return parsed


def extract_extension_rows(parsed_results):
    """
    Her host'un stdout'undaki JSON ciktisini parse eder, extension satirlarini
    duz bir liste haline getirir. Bozuk/bos ciktilari raporlar ama durdurmaz.
    """
    all_rows = []
    failed_hosts = []

    for entry in parsed_results:
        hostname = entry["hostname"]
        device_id = entry["device_id"]
        stdout = entry["stdout"].strip()

        if entry["offline_queued"]:
            failed_hosts.append({"hostname": hostname, "device_id": device_id, "reason": "Host offline, kuyruga alindi"})
            continue

        if not entry["complete"]:
            failed_hosts.append({"hostname": hostname, "device_id": device_id, "reason": "Script calismasi tamamlanmadi (timeout)"})
            continue

        if entry["stderr"]:
            failed_hosts.append({"hostname": hostname, "device_id": device_id, "reason": f"stderr: {entry['stderr'][:200]}"})
            # stderr olsa da stdout'ta veri olabilir, devam ediyoruz

        if not stdout:
            failed_hosts.append({"hostname": hostname, "device_id": device_id, "reason": "Bos cikti"})
            continue

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            failed_hosts.append({"hostname": hostname, "device_id": device_id, "reason": f"JSON parse hatasi: {e}"})
            continue

        # Script tek bir obje de dondurebilir (1 extension varsa), liste de dondurebilir
        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            failed_hosts.append({"hostname": hostname, "device_id": device_id, "reason": "Beklenmeyen JSON yapisi"})
            continue

        for item in data:
            all_rows.append(item)

    return all_rows, failed_hosts


def write_csv(rows, output_path):
    """Toplanan extension satirlarini CSV dosyasina yazar."""
    if not rows:
        log("UYARI: Yazilacak satir yok, CSV bos olusturulacak.")

    fieldnames = [
        "ComputerName", "OSUser", "Browser", "Profile",
        "ExtensionId", "ExtensionName", "ExtensionVersion", "ManifestPath"
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    log(f"CSV yazildi: {output_path} ({len(rows)} satir)")


def write_failures_csv(failed_hosts, output_path):
    """Basarisiz/eksik host'lari ayri bir CSV'de raporlar (rapor seffafligi icin onemli)."""
    if not failed_hosts:
        return

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["hostname", "device_id", "reason"])
        writer.writeheader()
        for item in failed_hosts:
            writer.writerow(item)

    log(f"Basarisiz host raporu yazildi: {output_path} ({len(failed_hosts)} host)")


def chunk_list(items, size):
    """Buyuk host listelerini batch limiti icin parcalara boler (API genelde 10000 limit verir ama guvenli tarafta kaliyoruz)."""
    for i in range(0, len(items), size):
        yield items[i:i + size]


def main():
    parser = argparse.ArgumentParser(description="Falcon RTR ile browser extension envanteri toplama araci")
    parser.add_argument("--client-id", default=os.environ.get("FALCON_CLIENT_ID"), help="Falcon API Client ID")
    parser.add_argument("--client-secret", default=os.environ.get("FALCON_CLIENT_SECRET"), help="Falcon API Client Secret")
    parser.add_argument("--base-url", default=os.environ.get("FALCON_BASE_URL", DEFAULT_BASE_URL), help="Falcon API base URL (bolgene gore)")
    parser.add_argument("--host-group-id", required=True, help="Hedef host group ID")
    parser.add_argument("--script-name", default="BrowserExtensionInventory", help="RTR custom script adi (Falcon'da kayitli isim)")
    parser.add_argument("--batch-size", type=int, default=500, help="Tek seferde batch session'a eklenecek max host sayisi")
    parser.add_argument("--output", default="extension_inventory.csv", help="Cikti CSV dosya adi")
    parser.add_argument("--failures-output", default="extension_inventory_failures.csv", help="Basarisiz host raporu CSV dosya adi")

    args = parser.parse_args()

    if not args.client_id or not args.client_secret:
        log("HATA: Client ID / Secret bulunamadi. --client-id/--client-secret ile ver ya da FALCON_CLIENT_ID/FALCON_CLIENT_SECRET ortam degiskenlerini ayarla.")
        sys.exit(1)

    log("Falcon API'ye baglaniliyor...")
    token = get_oauth_token(args.base_url, args.client_id, args.client_secret)
    log("Token alindi.")

    log(f"Host group uyeleri cekiliyor (group ID: {args.host_group_id})...")
    members = get_host_group_member_ids(args.base_url, token, args.host_group_id)
    log(f"Toplam {len(members)} host bulundu.")

    if not members:
        log("UYARI: Host group bos veya bulunamadi. Cikiliyor.")
        sys.exit(0)

    host_lookup = {m["device_id"]: m["hostname"] for m in members}
    all_device_ids = [m["device_id"] for m in members]

    all_extension_rows = []
    all_failed_hosts = []

    batches = list(chunk_list(all_device_ids, args.batch_size))
    log(f"{len(batches)} batch halinde isleniyor (batch boyutu: {args.batch_size})...")

    for batch_num, batch_device_ids in enumerate(batches, start=1):
        log(f"--- Batch {batch_num}/{len(batches)} ({len(batch_device_ids)} host) ---")

        log("Batch RTR session baslatiliyor...")
        batch_id, init_resources = init_batch_session(args.base_url, token, batch_device_ids)
        log(f"Batch session olusturuldu: {batch_id}")

        log(f"Script calistiriliyor: {args.script_name}")
        command_response = execute_script_on_batch(args.base_url, token, batch_id, args.script_name)

        command_response = poll_incomplete_commands(args.base_url, token, command_response)

        parsed_results = parse_command_results(command_response, host_lookup)

        rows, failed = extract_extension_rows(parsed_results)
        all_extension_rows.extend(rows)
        all_failed_hosts.extend(failed)

        log(f"Batch {batch_num} tamamlandi: {len(rows)} extension satiri, {len(failed)} sorunlu host.")

    log("=" * 60)
    log(f"TOPLAM: {len(all_extension_rows)} extension kaydi, {len(all_failed_hosts)} sorunlu/eksik host.")

    write_csv(all_extension_rows, args.output)
    write_failures_csv(all_failed_hosts, args.failures_output)

    log("Islem tamamlandi.")


if __name__ == "__main__":
    main()
