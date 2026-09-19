from datetime import datetime
from pathlib import Path
from config import REPORT_DIR
from .phishing_detector import score_url

def save_report():
    print("Security Report Generator")
    target = input("URL to include in report: ").strip()
    result = score_url(target)

    Path(REPORT_DIR).mkdir(exist_ok=True)
    filename = Path(REPORT_DIR) / ("report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt")

    lines = [
        "CYBERSECURITY TOOLKIT v1.0",
        "Created by Rudrapratap",
        "",
        "Security Analysis Report",
        "Generated: " + datetime.now().isoformat(timespec="seconds"),
        "",
        "Target: " + result["url"],
        f"Risk Score: {result['score']}/100",
        "Risk Level: " + result["level"],
        "",
        "Findings:"
    ]
    lines += ["- " + x for x in result["findings"]] or ["- No obvious heuristic indicators found."]
    lines += [
        "",
        "Important: This heuristic result is not proof of safety or maliciousness.",
        "Only analyze systems and data you are authorized to test."
    ]
    filename.write_text("\n".join(lines), encoding="utf-8")
    print("Report saved:", filename)
