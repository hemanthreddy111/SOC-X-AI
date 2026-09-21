import os
import httpx

def fallback_analysis(alert, related_events):
    evidence = alert.get("evidence", [])
    technique = alert.get("mitre_technique") or "Not mapped"
    return {
        "summary": f"{alert['title']}. The available evidence should be validated by an analyst before containment.",
        "severity": alert["severity"],
        "confidence": "Medium",
        "evidence": evidence,
        "mitre": [{"technique": technique, "name": alert.get("mitre_name")}],
        "investigation_questions": [
            "Was the observed activity expected for this user or host?",
            "Are there additional related events before or after the alert?",
            "Is the source IP known and authorized?"
        ],
        "recommended_actions": [
            "Validate the activity with the affected user/system owner.",
            "Review related authentication and endpoint events.",
            "Preserve relevant evidence and document the investigation."
        ],
    }

async def analyze_alert(alert, related_events):
    api_key = os.getenv("AI_API_KEY")
    base_url = os.getenv("AI_BASE_URL")
    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    if not api_key or not base_url:
        return fallback_analysis(alert, related_events)
    prompt = f"""You are assisting a SOC analyst. Do not invent evidence.
Alert: {alert}
Related events: {related_events}
Return JSON with summary, severity, confidence, evidence, mitre, investigation_questions, recommended_actions."""
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": model, "messages":[{"role":"user","content":prompt}], "temperature":0.1}
            )
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            import json
            return json.loads(content)
    except Exception:
        return fallback_analysis(alert, related_events)
