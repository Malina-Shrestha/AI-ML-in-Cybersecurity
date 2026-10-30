"""
TriageMate - SOC Alert Triage Agent (Week 4 MVP)

Deterministic pipeline (parse + rule score + MITRE lookup) runs on load.
The LLM agent (local, via Ollama) runs on demand in the Alert Detail tab and
writes the summary, priority reason, and safe next steps. If Ollama is not
running, a rule based fallback is used so the demo never breaks.

Run:  python app.py   then open the local URL it prints.
Optional LLM:  install Ollama, then  ollama pull llama3.1:8b
"""
import json
import time

import gradio as gr

from triage.pipeline import load_alerts, triage_all
from triage.llm import analyze_with_llm, llm_available
from triage.rag import retrieve, backend_name

DEFAULT_DATA = "data/all_alerts.jsonl"
PRIORITY_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
STATE = {"df": None, "approved": set(), "analysis": {}}


def build_queue(file_obj):
    path = file_obj.name if file_obj else DEFAULT_DATA
    try:
        df = triage_all(load_alerts(path))
    except Exception as e:
        return None, f"Could not read alerts: {e}", gr.update(choices=[]), gr.update(choices=[])
    STATE["df"] = df
    STATE["approved"] = set()
    STATE["analysis"] = {}
    view = df[["alert_id", "priority", "score", "category_guess",
               "mitre_id", "rule_name", "host"]].copy()
    view.insert(0, "", view["priority"].map(PRIORITY_EMOJI))
    choices = df["alert_id"].tolist()
    online = "online" if llm_available() else "offline (fallback will be used)"
    msg = (f"Loaded {len(df)} alerts. {df['priority'].value_counts().to_dict()}  "
           f"| Local LLM: {online} | RAG: {backend_name()}")
    first = choices[0] if choices else None
    return view, msg, gr.update(choices=choices, value=first), gr.update(choices=choices, value=first)


def show_detail(alert_id):
    df = STATE["df"]
    if df is None or not alert_id:
        return "Load alerts and pick one from the queue.", ""
    row = df[df["alert_id"] == alert_id].iloc[0]
    reasons = "\n".join(f"  - {r}" for r in row["reasons"])
    mitre = (f"{row['mitre_id']} {row['mitre_name']} ({row['mitre_tactic']})"
             if row["mitre_id"] else "No confident match")
    approved = "APPROVED" if alert_id in STATE["approved"] else "awaiting approval"

    # show any LLM analysis already run for this alert
    llm_block = "_Click 'Run AI analysis' to add the LLM summary and next steps._"
    if alert_id in STATE["analysis"]:
        a = STATE["analysis"][alert_id]
        steps = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(a.get("next_steps", [])))
        cites = "\n".join(f"  - {c}" for c in a.get("citations", [])) or "  - (none)"
        llm_block = (f"**AI summary:** {a.get('summary','')}\n\n"
                     f"**AI priority:** {a.get('priority','')} - {a.get('priority_reason','')}\n\n"
                     f"**Recommended safe next steps:**\n{steps}\n\n"
                     f"**Sources cited (RAG):**\n{cites}\n\n"
                     f"_source: {a.get('source','')}_")

    detail = f"""### {PRIORITY_EMOJI[row['priority']]} {row['alert_id']} - {row['priority']} (score {row['score']})

**Rule:** {row['rule_name']}
**Baseline category:** {row['category_guess']}
**MITRE ATT&CK:** {mitre}
**Host:** {row['host']}   **User:** {row['user']}
**Source IP:** {row['src_ip']}   **Log source:** {row['log_source']}
**Data source:** {row['data_source']}

**Why this score (rule based):**
{reasons}

**Raw log:**
```
{row['raw_log'][:500]}
```

---
{llm_block}

**Ticket status:** {approved}
"""
    return detail, ""


def run_ai(alert_id):
    """Run the LLM step for one alert and show a tool trace."""
    df = STATE["df"]
    if df is None or not alert_id:
        return "Load alerts and pick one first.", ""
    row = df[df["alert_id"] == alert_id].iloc[0].to_dict()

    trace = []
    t0 = time.time()
    trace.append(f"[parser]  normalized alert {alert_id}")
    trace.append(f"[scorer]  rule score={row['score']} priority={row['priority']}")
    trace.append(f"[mitre]   {row['mitre_id']} {row['mitre_name']}")
    hits = retrieve(f"{row['rule_name']} {row['raw_log']}", k=3)
    trace.append(f"[rag]     retrieved {len(hits)} passages via {backend_name()}:")
    for h in hits:
        trace.append(f"            - {h['score']} {h['source']}")
    trace.append(f"[llm]     calling local model...")
    analysis = analyze_with_llm(row)
    STATE["analysis"][alert_id] = analysis
    trace.append(f"[llm]     done in {time.time()-t0:.1f}s  source={analysis.get('source')}")
    detail, _ = show_detail(alert_id)
    return detail, "\n".join(trace)


def approve(alert_id):
    if STATE["df"] is None or not alert_id:
        return "Nothing to approve yet."
    STATE["approved"].add(alert_id)
    row = STATE["df"][STATE["df"]["alert_id"] == alert_id].iloc[0]
    analysis = STATE["analysis"].get(alert_id, {})
    ticket = {
        "alert_id": alert_id, "priority": row["priority"], "score": int(row["score"]),
        "category": row["category_guess"],
        "mitre": {"id": row["mitre_id"], "name": row["mitre_name"]},
        "rule_name": row["rule_name"], "host": row["host"],
        "ai_summary": analysis.get("summary", "(AI analysis not run)"),
        "next_steps": analysis.get("next_steps", []),
        "approved_by": "analyst",
    }
    return "Ticket approved and created:\n\n```json\n" + json.dumps(ticket, indent=2) + "\n```"


with gr.Blocks(title="TriageMate") as demo:
    gr.Markdown("# TriageMate\nSOC Alert Triage Agent - defensive use only.")

    with gr.Tab("1. Upload"):
        up = gr.File(label="Upload alerts (JSON Lines). Leave empty to use the sample set.")
        load_btn = gr.Button("Load and triage", variant="primary")
        load_msg = gr.Markdown()

    with gr.Tab("2. Alert queue"):
        queue = gr.Dataframe(label="Alerts sorted by risk", interactive=False)

    with gr.Tab("3. Alert detail"):
        picker = gr.Dropdown(label="Select an alert", choices=[])
        ai_btn = gr.Button("Run AI analysis (local LLM)", variant="primary")
        detail = gr.Markdown()
        gr.Markdown("**Tool trace** (shows the agent's steps):")
        trace_out = gr.Textbox(label="", lines=6, interactive=False)

    with gr.Tab("4. Approval & ticket"):
        approve_picker = gr.Dropdown(label="Alert to approve", choices=[])
        approve_btn = gr.Button("Approve ticket", variant="primary")
        ticket_out = gr.Markdown()

    load_btn.click(build_queue, inputs=up, outputs=[queue, load_msg, picker, approve_picker])
    picker.change(show_detail, inputs=picker, outputs=[detail, trace_out])
    ai_btn.click(run_ai, inputs=picker, outputs=[detail, trace_out])
    approve_btn.click(approve, inputs=approve_picker, outputs=ticket_out)

if __name__ == "__main__":
    demo.launch()
