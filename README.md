# SPHERE

Privacy-preserving synthetic data for AI agents. An MCP server plus a sealed
analysis engine, in one package.

SPHERE lets an AI assistant develop an analysis of your sensitive data without
ever seeing the records. The assistant works against a **synthetic twin**; the
finished code is then executed **locally** against the real file, and the results
go to you — not to the model.

---

## ⚠️ Read this before your first use

**Do not attach sensitive files to the chat.** Give SPHERE a local file path
instead.

```
✗  drag and drop patients.csv into the conversation
✓  type:  /Users/you/data/patients.csv
```

This is not a preference. A chat attachment is uploaded to your AI provider's
servers *before* any SPHERE tool is called. SPHERE runs as a local process on
your machine and has no way to intervene earlier than its own first invocation —
by which point the file has already left. See [Limits](#limits).

When you pass a local path, only the *path string* reaches the model. The file
itself is read locally, and the model receives a profile with no cell values.

---

## Requirements

- macOS (Apple Silicon or Intel). The sandbox uses macOS Seatbelt; Linux is not
  yet supported.
- Node.js ≥ 18
- Python 3 (used only to profile file shapes locally)

## Install

```bash
npm install -g sphere
```

To verify:

```bash
sphere --help
```

The first run downloads the sealed analysis engine (~22 MB) into
`~/.local/share/sphere-cli/`. This happens automatically; no install script is
required.

## Connect it to Claude Desktop

Add SPHERE to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sphere": {
      "command": "sphere-mcp",
      "env": {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

Quit Claude Desktop completely (⌘Q) and reopen it. A full restart is required —
reloading the window keeps the old server process alive.

## Use it

Type a local path and describe what you want:

```
/Users/me/data/patients.csv
Model systolic blood pressure from age, BMI and sex.
Develop it on the twin, then deploy the final code to the real data.
```

The assistant will work through these tools:

| Tool | What the model receives |
|---|---|
| `sphere_open` | Column shapes only — dtype, distinct count, masked format. No values. |
| `sphere_twin` | A synthetic twin plus fidelity and privacy scores |
| `sphere_run` | Full output of code run against the twin |
| `sphere_deploy` | Whether it succeeded. **Results go to you, not the model.** |
| `sphere_simulate` | A perturbed twin, for debugging a real-data discrepancy |
| `sphere_diff` | Whether the real file changed since the twin was made |
| `sphere_status` | The audit ledger for the session |

Deploy results are written to `~/.sphere/vault/session-*/real-output.txt`. The
assistant will show you the command to open them.

## Limits

Please read these before relying on SPHERE.

**The enforced boundary begins at tool invocation.** Anything your client does
before the first SPHERE call — chat attachments in particular — is outside it.
SPHERE cannot prevent an upload it is never told about. This is why the warning
above matters more than any setting in this package.

**The synthetic twin is not the real data.** SPHERE preserves column means and
the cross-product `Z'Z` exactly, so means, variances, correlations and linear
models agree with the real data. Quantities outside that guarantee — medians,
minima and maxima, non-linear relationships, subgroup effects — may differ.

**The twin can contain impossible values.** Because rotation is not constrained
to a variable's valid range, a twin may hold a negative BMI or a negative lab
value. Treat such values as artifacts of the method, not as facts about the real
cohort.

**macOS only.** The execution sandbox is built on Seatbelt.

**Results shown to you are real.** SPHERE protects the data from the model, not
from you. Handle deploy outputs according to your own data agreement.

## Uninstall

```bash
npm uninstall -g sphere
rm -rf ~/.local/share/sphere-cli   # sealed engine
rm -rf ~/.sphere                   # session vault, twins, deploy outputs
```

---

Contact: zihuai@stanford.edu
