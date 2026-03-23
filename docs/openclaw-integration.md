# OpenClaw Integration

## Prerequisites

Before connecting OpenClaw to Aegis, make sure:

- Aegis is installed and running. Verify with `aegis health` and confirm it returns `status: ok`.
- OpenClaw is installed. Verify with `openclaw --version`.

## Install the Skill

```bash
# Create the skill directory
mkdir -p ~/.openclaw/workspace/skills/aegis-exec

# Download the skill file
curl -L https://raw.githubusercontent.com/jeshwanthsingh/Aegis/main/openclaw-plugin/SKILL.md \
  -o ~/.openclaw/workspace/skills/aegis-exec/SKILL.md
```

## What SKILL.md Does

The `SKILL.md` file tells the OpenClaw agent to route Python and bash execution requests through Aegis instead of running them locally. It instructs the agent to call the Aegis API from WSL, submit the code payload, and return the sandboxed execution result to the user.

## How to Use It

Example prompts:

- `Use the Aegis sandbox to run this Python code: print('hello')`
- `Run this bash script through Aegis: echo hello && date`

## How It Works

OpenClaw agent -> exec tool -> wsl curl -> Aegis API -> Firecracker microVM -> result. OpenClaw turns the user request into a shell command, sends the code to Aegis over HTTP, Aegis boots an isolated Firecracker microVM, executes the code inside the guest, and returns stdout, stderr, exit code, and timing back to the agent.

## Troubleshooting

### Aegis Not Running

If `aegis health` fails, start Aegis with your normal run command and verify the API is listening before trying OpenClaw again.

### WSL Not Available

If `wsl` is not installed or not working, install WSL2 first. The skill depends on `wsl curl` to reach the Aegis API running in the Linux environment.

### Timeout Errors

If executions time out, increase `timeout_ms` in the skill payload so Aegis gives the microVM more time to boot and run the code.
