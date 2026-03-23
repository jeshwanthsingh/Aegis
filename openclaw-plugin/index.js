const { definePluginEntry } = require("openclaw/plugin-sdk/plugin-entry");

const AEGIS_URL = process.env.AEGIS_URL || "http://localhost:8080";
const AEGIS_API_KEY = process.env.AEGIS_API_KEY || "";

module.exports = definePluginEntry({
  id: "aegis-exec",
  name: "Aegis Code Executor",
  description: "Runs Python and bash code in isolated Firecracker microVMs",
  register(api) {
    api.registerTool({
      name: "execute_code",
      description: "Execute Python or bash code safely in an isolated microVM sandbox. Use this whenever you need to run code, test scripts, or compute something.",
      parameters: {
        type: "object",
        properties: {
          lang: {
            type: "string",
            enum: ["python", "bash"],
            description: "Programming language"
          },
          code: {
            type: "string",
            description: "The code to execute"
          },
          timeout_ms: {
            type: "number",
            description: "Timeout in milliseconds (default 10000)"
          }
        },
        required: ["lang", "code"]
      },
      async execute(_id, params) {
        const headers = { "Content-Type": "application/json" };
        if (AEGIS_API_KEY) headers["Authorization"] = `Bearer ${AEGIS_API_KEY}`;

        const resp = await fetch(`${AEGIS_URL}/v1/execute`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            lang: params.lang,
            code: params.code,
            timeout_ms: params.timeout_ms || 10000
          })
        });

        const result = await resp.json();

        if (result.error) {
          return { content: [{ type: "text", text: `Error: ${result.error}` }] };
        }

        let output = "";
        if (result.stdout) output += result.stdout;
        if (result.stderr) output += `[stderr] ${result.stderr}`;
        if (result.exit_code !== 0) output += `\n[exit code ${result.exit_code}]`;
        output += `\n[done in ${result.duration_ms}ms]`;

        return { content: [{ type: "text", text: output.trim() }] };
      }
    });
  }
});
