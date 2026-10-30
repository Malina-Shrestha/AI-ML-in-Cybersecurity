# Turning on the local LLM (Ollama)

TriageMate runs fully without an LLM (it uses a rule based fallback). To enable
the real AI summaries and next steps, install a local model. No cloud, no key.

## 1. Install Ollama
Download from https://ollama.com and install it. It runs in the background.

## 2. Pull a model that supports tool/JSON output
```bash
ollama pull llama3.1:8b      # recommended, ~4.7 GB
# or a smaller/faster option:
ollama pull qwen2.5:7b
```

## 3. Confirm it is running
```bash
ollama list
```
Ollama serves on http://localhost:11434 by default. Keep it bound to localhost
(do not expose it to the network - its API has no authentication).

## 4. Run TriageMate
```bash
python app.py
```
On the Upload tab after loading, the status line shows "Local LLM: online".
Open the Alert detail tab, pick an alert, and click "Run AI analysis".

## Changing the model
Set an environment variable before running (optional):
```bash
# Windows PowerShell
$env:LLM_MODEL="qwen2.5:7b"; python app.py
# Mac/Linux/Git Bash
LLM_MODEL=qwen2.5:7b python app.py
```

## If it stays "offline"
- Make sure `ollama list` shows your model.
- Make sure nothing else blocks port 11434.
- The app still works offline using the rule based fallback, so your demo is safe.
