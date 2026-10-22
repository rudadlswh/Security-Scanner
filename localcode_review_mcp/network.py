"""한글 기능 설명: 루프백 주소·수신/방화벽 상태를 확인하고 프록시/리다이렉트를 차단한다."""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from urllib.parse import urlsplit

import httpx
from .workspace import ProductError


def loopback_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        raise ProductError("LITERAL_LOOPBACK_REQUIRED") from None
    if not address.is_loopback or parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ProductError("LOOPBACK_BASE_URL_INVALID")
    if parsed.port is None:
        raise ProductError("EXPLICIT_PORT_REQUIRED")
    return value.rstrip("/")


def access_boundary(base_url: str) -> dict:
    parsed = urlsplit(loopback_url(base_url))
    port = parsed.port
    if os.name != "nt":
        raise ProductError("LIVE_BINDING_FIREWALL_CHECK_WINDOWS_ONLY: this runtime has not verified other platforms")
    script = """
$ErrorActionPreference='Stop'
$listeners=@(Get-NetTCPConnection -LocalPort PORT -State Listen | Select-Object -ExpandProperty LocalAddress)
$rules=@()
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
  $rule=$_
  $app=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
  $ports=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
  if ($rule.DisplayName -like '*ollama*' -or $app.Program -like '*ollama*' -or @($ports.LocalPort) -contains 'PORT') {
    $address=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
    $rules+=@($address.RemoteAddress)
  }
}
@{listeners=$listeners; firewall_remote_addresses=$rules} | ConvertTo-Json -Compress
""".replace("PORT", str(port))
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, timeout=45, creationflags=subprocess.CREATE_NO_WINDOW, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise ProductError("ACCESS_BOUNDARY_QUERY_FAILED")
    try:
        value = json.loads(result.stdout.decode("utf-8-sig"))
        addresses = value["listeners"]
        if not addresses or any(not ipaddress.ip_address(a).is_loopback for a in addresses):
            raise ProductError("WILDCARD_OR_NON_LOOPBACK_LISTENER")
        remotes = value["firewall_remote_addresses"]
        if not remotes or any(a not in {"127.0.0.1", "::1", "127.0.0.1/255.255.255.255", "127.0.0.1/32", "::1/128"} for a in remotes):
            raise ProductError("FIREWALL_BOUNDARY_NOT_CONFIRMED")
        return {"listeners": addresses, "firewall_remote_addresses": remotes, "kind": "POINT_IN_TIME_NOT_A_CONFIGURATION_LOCK"}
    except (ValueError, KeyError, TypeError):
        raise ProductError("ACCESS_BOUNDARY_NOT_CONFIRMED") from None


async def json_request(client: httpx.AsyncClient, method: str, url: str, *, payload=None, maximum=4_194_304) -> dict:
    async with client.stream(method, url, json=payload) as response:
        response.raise_for_status()
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > maximum:
                raise ProductError("HTTP_RESPONSE_SIZE_LIMIT")
    result = json.loads(body)
    if not isinstance(result, dict):
        raise ProductError("HTTP_JSON_OBJECT_REQUIRED")
    return result
