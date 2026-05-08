import httpx
payload = {
    "raw_line": "{\"EventID\": 1, \"UtcTime\": \"2026-05-07T19:36:34.892156+00:00Z\", \"ProcessId\": 5100, \"Image\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\", \"CommandLine\": \"cmd.exe /c whoami\", \"User\": \"www-data\", \"ParentImage\": \"C:\\\\Program Files\\\\Apache\\\\apache2.exe\", \"ParentProcessId\": 1200, \"Hashes\": \"SHA256=12345abcdef\"}",
    "event_type": "PROCESS_CREATION",
    "hostname": "WEBSERVER01",
    "process_name": "cmd.exe",
    "parent_process_name": "apache2.exe"
}
r = httpx.post("http://127.0.0.1:8000/queue/inject", json=payload)
print(r.json())
