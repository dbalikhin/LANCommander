import collections
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
summaries = []
for path in sorted(root.glob("*.sarif")):
    sarif = json.loads(path.read_text(encoding="utf-8-sig"))
    for run in sarif.get("runs", []):
        driver = run["tool"]["driver"]
        components = [driver, *run["tool"].get("extensions", [])]
        rules = {rule["id"]: rule for component in components for rule in component.get("rules", [])}
        findings = []
        for result in run.get("results", []):
            rule = rules.get(result.get("ruleId"), {})
            properties = rule.get("properties", {})
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append({
                "rule": result.get("ruleId"),
                "security": "security" in properties.get("tags", []) or "security-severity" in properties,
                "security_severity": properties.get("security-severity"),
                "precision": properties.get("precision"),
                "file": location.get("artifactLocation", {}).get("uri"),
                "line": location.get("region", {}).get("startLine"),
                "message": result.get("message"),
                "fingerprints": result.get("partialFingerprints", {}),
            })
        summary = {
            "sarif": path.name,
            "codeql_version": driver.get("semanticVersion", driver.get("version")),
            "rule_count": len(rules),
            "result_count": len(findings),
            "security_result_count": sum(f["security"] for f in findings),
            "by_rule": dict(collections.Counter(f["rule"] for f in findings)),
            "findings": findings,
            "invocations": run.get("invocations", []),
            "properties": run.get("properties", {}),
        }
        summaries.append(summary)
        print("CODEQL_COMPARISON_SUMMARY " + json.dumps(summary, separators=(",", ":")))
(root / "summary.json").write_text(json.dumps(summaries, indent=2), encoding="utf-8")
with open(os.environ.get("GITHUB_STEP_SUMMARY", root / "step-summary.txt"), "a", encoding="utf-8") as f:
    for s in summaries:
        f.write(f'Queries: {s["rule_count"]}; findings: {s["result_count"]}; security findings: {s["security_result_count"]}\n\n')
        f.write("| Rule | Findings |\n|---|---:|\n")
        for rule, count in sorted(s["by_rule"].items()):
            f.write(f"| {rule} | {count} |\n")

