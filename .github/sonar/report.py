"""SonarQube Cloud preflight and security-only result export; never persists credentials."""
import base64
import collections
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "https://sonarcloud.io"
PROJECT = "dbalikhin_LANCommander"
OUTPUT = pathlib.Path("sonar-artifacts")
OUTPUT.mkdir(exist_ok=True)
TOKEN = os.environ["SONAR_TOKEN"]


def api(path, parameters=None, post=False):
    encoded = urllib.parse.urlencode(parameters or {}).encode()
    url = HOST + "/api/" + path
    if not post and encoded:
        url += "?" + encoded.decode()
    request = urllib.request.Request(url, data=encoded if post else None)
    request.add_header("Authorization", "Basic " + base64.b64encode((TOKEN + ":").encode()).decode())
    if post:
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        # Status and server message are useful; never print request headers or tokens.
        message = error.read().decode(errors="replace").replace(TOKEN, "[redacted]")
        raise RuntimeError(f"Sonar API {path}: HTTP {error.code}: {message}") from None


def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, indent=2), encoding="utf-8")


def pages(path, parameters, key):
    records = []
    page = 1
    while True:
        data = api(path, {**parameters, "p": page, "ps": 500})
        records.extend(data.get(key, []))
        total = data.get("paging", {}).get("total", data.get("total", len(records)))
        if len(records) >= total or not data.get(key):
            return records
        page += 1


if sys.argv[1] == "preflight":
    if not api("authentication/validate").get("valid"):
        raise RuntimeError("SONAR_TOKEN is invalid for sonarcloud.io.")
    project = api("components/show", {"component": PROJECT})
    if project["component"]["organization"] != "dbalikhin":
        raise RuntimeError("Unexpected Sonar organization.")
    save("before-analysis.json", api("measures/component", {
        "component": PROJECT, "metricKeys": "ncloc,ncloc_language_distribution,files,vulnerabilities,security_hotspots"}))
    save("before-csharp-profiles.json", api("qualityprofiles/search", {"organization": "dbalikhin", "project": PROJECT, "language": "cs"}))
    profile_name = "LANCommander C# all security"
    profiles = api("qualityprofiles/search", {"organization": "dbalikhin", "language": "cs"})["profiles"]
    profile = next((item for item in profiles if item["name"] == profile_name), None)
    if profile is None:
        profile = api("qualityprofiles/create", {
            "organization": "dbalikhin", "language": "cs", "name": profile_name}, post=True)["profile"]
    filters = {"organization": "dbalikhin", "languages": "cs", "statuses": "READY,BETA", "is_template": "false"}
    selections = [{"types": "VULNERABILITY,SECURITY_HOTSPOT"}, {"impactSoftwareQualities": "SECURITY"}]
    expected = {}
    for selection in selections:
        expected.update((rule["key"], rule) for rule in pages("rules/search", {**filters, **selection}, "rules"))
        result = api("qualityprofiles/activate_rules", {**filters, **selection, "targetKey": profile["key"]}, post=True)
        if result.get("errors"):
            raise RuntimeError(f"Rule activation failed: {result['errors']}")
    active = pages("rules/search", {"organization": "dbalikhin", "qprofile": profile["key"], "activation": "true"}, "rules")
    active_keys = {rule["key"] for rule in active}
    if active_keys != set(expected):
        raise RuntimeError(f"Security profile mismatch: missing={sorted(set(expected) - active_keys)}, extra={sorted(active_keys - set(expected))}")
    api("qualityprofiles/add_project", {"organization": "dbalikhin", "project": PROJECT,
        "language": "cs", "qualityProfile": profile_name}, post=True)
    associated = api("qualityprofiles/search", {"organization": "dbalikhin", "project": PROJECT, "language": "cs"})
    if not any(item["key"] == profile["key"] for item in associated["profiles"]):
        raise RuntimeError("Project security profile association was not confirmed.")
    save("csharp-profiles.json", associated)
    save("security-rule-manifest.json", {"profile": profile, "rule_count": len(expected),
        "selection": selections, "statuses": ["READY", "BETA"], "rules": sorted(expected.values(), key=lambda rule: rule["key"])})
    print(f"Project profile: {profile_name}; {len(expected)} active C# security rules, including hotspots.")
    api("autoscan/activation", {"projectKey": PROJECT, "enable": "false"}, post=True)
    print("Authenticated; project-only automatic analysis disabled for CI analysis.")
elif sys.argv[1] == "collect":
    task_files = list(pathlib.Path(".sonarqube").rglob("report-task.txt"))
    if len(task_files) != 1:
        raise RuntimeError(f"Expected one Sonar report-task.txt, found {len(task_files)}.")
    task_text = task_files[0].read_text(encoding="utf-8-sig")
    task = dict(line.split("=", 1) for line in task_text.splitlines() if "=" in line)
    (OUTPUT / "report-task.txt").write_text(task_text, encoding="utf-8")
    deadline = time.monotonic() + 900
    while True:
        processing = api("ce/task", {"id": task["ceTaskId"]})
        status = processing["task"]["status"]
        if status not in {"PENDING", "IN_PROGRESS"}:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Sonar server processing exceeded 15 minutes.")
        time.sleep(10)
    save("server-processing.json", processing)
    if status != "SUCCESS":
        raise RuntimeError(f"Sonar server processing failed: {processing['task'].get('errorMessage', status)}")
    issue_selection = {"componentKeys": PROJECT, "languages": "cs", "resolved": "false"}
    issue_map = {}
    for selection in [{"types": "VULNERABILITY"}, {"impactSoftwareQualities": "SECURITY"}]:
        issue_map.update((issue["key"], issue) for issue in pages("issues/search", {**issue_selection, **selection}, "issues"))
    issues = list(issue_map.values())
    hotspots = pages("hotspots/search", {"projectKey": PROJECT}, "hotspots")
    hotspots = [item for item in hotspots if item.get("component", "").lower().endswith((".cs", ".cshtml", ".razor"))]
    save("csharp-security-issues.json", issues)
    save("security-hotspots.json", hotspots)
    measures = api("measures/component", {"component": PROJECT, "metricKeys": "ncloc,ncloc_language_distribution,files,vulnerabilities,security_hotspots,bugs,code_smells"})
    save("measures.json", measures)
    groups = collections.Counter(issue["rule"] for issue in issues)
    timings = {}
    for item in OUTPUT.glob("timing-*.json"):
        timings.update(json.loads(item.read_text(encoding="utf-8-sig")))
    execution_ms = processing["task"].get("executionTimeMs")
    timings["server_execution_seconds"] = execution_ms / 1000 if execution_ms is not None else None
    summary = {"project": PROJECT, "commit": os.environ["GITHUB_SHA"], "scanner_version": "12.0.0",
               "security_issue_reports": len(issues), "hotspot_reports": len(hotspots),
               "security_issues_by_rule": dict(groups), "timings": timings,
               "active_security_rules": json.loads((OUTPUT / "security-rule-manifest.json").read_text(encoding="utf-8"))["rule_count"],
               "scope": "full C# solution; all available READY/BETA security rules and hotspots; quality-only findings excluded"}
    save("summary.json", summary)
    lines = ["## SonarQube Cloud C# security", "", f"Security issue reports: {len(issues)}",
             f"Security hotspots (review candidates): {len(hotspots)}", "", "| Rule | Reports |", "|---|---:|"]
    lines += [f"| {rule} | {count} |" for rule, count in groups.most_common()]
    lines += ["", "Timing (seconds):", "", "```json", json.dumps(timings, indent=2), "```", "",
              "Build time includes Roslyn analysis; it is not isolated scanner CPU time.",
              "Quality findings are excluded from this security comparison.",
              "[Sonar project](https://sonarcloud.io/project/overview?id=dbalikhin_LANCommander)"]
    text = "\n".join(lines) + "\n"
    (OUTPUT / "summary.md").write_text(text, encoding="utf-8")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write(text)
    print(json.dumps(summary))
else:
    raise RuntimeError("Expected preflight or collect.")
