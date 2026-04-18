import type { DemoKey } from "./types";

export interface DemoTemplate {
  id: DemoKey;
  label: string;
  description: string;
  lang: "bash" | "python" | "node";
  profile: "nano" | "standard" | "crunch";
  timeoutMs: number;
  code: string;
}

export const DEMOS: DemoTemplate[] = [
  {
    id: "clean",
    label: "Clean Execution",
    description: "Simple contained execution with a signed receipt and no governed actions.",
    lang: "bash",
    profile: "nano",
    timeoutMs: 5000,
    code: "echo UI_DEMO_CLEAN_OK",
  },
  {
    id: "exfil",
    label: "Exfil Denied",
    description: "Attempts a direct outbound connect and expects a signed denial path.",
    lang: "python",
    profile: "standard",
    timeoutMs: 8000,
    code: `import socket
s = socket.socket()
s.settimeout(2)
try:
    rc = s.connect_ex(("1.2.3.4", 4444))
    print(f"connect_ex_rc={rc}")
except Exception as exc:
    print(f"connect_exc={type(exc).__name__}:{exc}")
finally:
    try:
        s.close()
    except Exception:
        pass
print("UI_DEMO_EXFIL_ATTEMPTED")`,
  },
  {
    id: "broker",
    label: "Brokered Outbound",
    description: "Uses the guest broker proxy to fetch the local health endpoint through the governed path.",
    lang: "bash",
    profile: "standard",
    timeoutMs: 8000,
    code: `#!/usr/bin/env bash
set -euo pipefail
exec 3<>/dev/tcp/127.0.0.1/8888
printf 'GET __TARGET_URL__ HTTP/1.1\\r\\nHost: __TARGET_HOST__\\r\\nConnection: close\\r\\n\\r\\n' >&3
response=''
while IFS= read -r line <&3; do
  response+="$line"$'\\n'
done || true
exec 3>&-
exec 3<&-
printf '%s\\n' "$response"
case "$response" in
  *'200 OK'*)
    echo 'UI_DEMO_BROKER_OK'
    exit 0
    ;;
esac
echo 'UI_DEMO_BROKER_FAILED'
exit 1`,
  },
];
