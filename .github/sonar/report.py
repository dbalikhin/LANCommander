"""Compare Cloud Automatic Analysis and compiled C# analysis without saving tokens."""
import base64
import collections
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "https://sonarcloud.io"
ORG = "dbalikhin"
PROJECT = os.environ["SONAR_PROJECT_KEY"]
MODE = sys.argv[1]
OUTPUT = pathlib.Path("sonar-artifacts") / ("automatic" if MODE.startswith("automatic") else "compiled")
OUTPUT.mkdir(parents=True, exist_ok=True)
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
        message = error.read().decode(errors="replace").replace(TOKEN, "[redacted]")
        raise RuntimeError(f"Sonar API {path}: HTTP {error.code}: {message}") from None


def save(name, data):
    (OUTPUT / name).write_text(json.dumps(data, indent=2), encoding="utf-8")


def pages(path, parameters, key):
    records = []
    for page in range(1, 100):
        data = api(path, {**parameters, "p": page, "ps": 500})
        records.extend(data.get(key, []))
        total = data.get("paging", {}).get("total", data.get("total", len(records)))
        if len(records) >= total or not data.get(key):
            return records
    raise RuntimeError("Unexpected result pagination limit.")


def configure(automatic):
    if not api("authentication/validate").get("valid"):
        raise RuntimeError("SONAR_TOKEN is invalid for sonarcloud.io.")
    component = api("components/show", {"component": PROJECT})["component"]
    if component["organization"] != ORG:
        raise RuntimeError("Unexpected organization.")
    save("before-measures.json", api("measures/component", {"component": PROJECT,
        "metricKeys": "ncloc,ncloc_language_distribution,files,vulnerabilities,security_hotspots"}))
    profile_name = component["name"] + " C# all security"
    profiles = api("qualityprofiles/search", {"organization": ORG, "language": "cs"})["profiles"]
    profile = next((item for item in profiles if item["name"] == profile_name), None)
    if profile is None:
        profile = api("qualityprofiles/create", {"organization": ORG,
            "language": "cs", "name": profile_name}, post=True)["profile"]
    filters = {"organization": ORG, "languages": "cs", "statuses": "READY,BETA", "is_template": "false"}
    expected = {}
    for selection in [{"types": "VULNERABILITY,SECURITY_HOTSPOT"}, {"impactSoftwareQualities": "SECURITY"}]:
        expected.update((rule["key"], rule) for rule in pages("rules/search", {**filters, **selection}, "rules"))
        result = api("qualityprofiles/activate_rules", {**filters, **selection, "targetKey": profile["key"]}, post=True)
        if result.get("errors"):
            raise RuntimeError(f"Rule activation failed: {result['errors']}")
    for attempt in range(24):
        active = pages("rules/search", {"organization": ORG, "qprofile": profile["key"], "activation": "true"}, "rules")
        if {rule["key"] for rule in active} == set(expected):
            break
        time.sleep(5)
    else:
        raise RuntimeError("Active security profile does not match the current security rule catalog.")
    api("qualityprofiles/add_project", {"organization": ORG, "project": PROJECT,
        "language": "cs", "qualityProfile": profile_name}, post=True)
    save("security-rule-manifest.json", {"profile": profile, "rule_count": len(expected),
        "rules": sorted(expected.values(), key=lambda item: item["key"])})
    for key, value in {"sonar.inclusions": "**/*.cs,**/*.cshtml,**/*.razor",
                       "sonar.exclusions": "**/node_modules/**,**/bin/**,**/obj/**"}.items():
        api("settings/set", {"component": PROJECT, "key": key, "values": value}, post=True)
    api("settings/set", {"component": PROJECT, "key": "sonar.cs.analyzeRazorCode", "value": "true"}, post=True)
    api("autoscan/activation", {"projectKey": PROJECT, "enable": str(automatic).lower()}, post=True)
    tracked = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    files = {}
    for name in tracked:
        if pathlib.Path(name).suffix.lower() in {".cs", ".cshtml", ".razor", ".csproj", ".props", ".targets", ".sln", ".slnx"}:
            files[name] = hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
    save("source-manifest.json", files)
    print(f"{PROJECT}: {len(expected)} security rules; {len(files)} C# source/build files; automatic={automatic}.")


def github(path, data=None, allow_missing=False):
    request = urllib.request.Request("https://api.github.com/repos/" + os.environ["GITHUB_REPOSITORY"] + "/" + path,
        data=json.dumps(data).encode() if data is not None else None, method="PUT" if data is not None else "GET")
    request.add_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404 and allow_missing:
            return None
        raise RuntimeError(f"GitHub comparison trigger failed: HTTP {error.code}.") from None


def trigger_automatic():
    branch = os.environ["GITHUB_REF_NAME"]
    head = github("branches/" + urllib.parse.quote(branch, safe=""))["commit"]["sha"]
    if head != os.environ["GITHUB_SHA"]:
        raise RuntimeError("Default branch changed; rerun the comparison against its current commit.")
    name = ".github/sonar/automatic-trigger.json"
    existing = github("contents/" + name + "?ref=" + urllib.parse.quote(branch, safe=""), allow_missing=True)
    content = json.dumps({"run": os.environ["GITHUB_RUN_ID"], "attempt": os.environ["GITHUB_RUN_ATTEMPT"], "source_commit": head})
    body = {"branch": branch, "message": "Trigger Sonar automatic C# security comparison",
            "content": base64.b64encode(content.encode()).decode()}
    if existing:
        body["sha"] = existing["sha"]
    commit = github("contents/" + name, body)["commit"]
    if commit["parents"][0]["sha"] != head:
        raise RuntimeError("Branch changed during comparison trigger; refusing to compare different sources.")
    save("trigger.json", {"commit": commit["sha"], "source_commit": head})
    return commit["sha"]


def export(processing, commit, timings):
    # Server processing and issue-search indexing complete separately.
    for attempt in range(30):
        measures = api("measures/component", {"component": PROJECT,
            "metricKeys": "ncloc,ncloc_language_distribution,files,vulnerabilities,security_hotspots"})
        values = {item["metric"]: item.get("value", "0") for item in measures["component"]["measures"]}
        expected = int(values.get("vulnerabilities", 0))
        indexed = api("issues/search", {"componentKeys": PROJECT, "types": "VULNERABILITY", "resolved": "false", "ps": 1})
        if indexed.get("paging", {}).get("total", indexed.get("total", 0)) == expected:
            break
        time.sleep(10)
    else:
        raise RuntimeError("Issue search has not caught up with processed vulnerability measures.")
    issue_map = {}
    for selection in [{"types": "VULNERABILITY"}, {"impactSoftwareQualities": "SECURITY"}]:
        issue_map.update((item["key"], item) for item in pages("issues/search",
            {"componentKeys": PROJECT, "languages": "cs", "resolved": "false", **selection}, "issues"))
    issues = list(issue_map.values())
    hotspots = pages("hotspots/search", {"projectKey": PROJECT}, "hotspots")
    hotspots = [item for item in hotspots if item.get("component", "").lower().endswith((".cs", ".cshtml", ".razor"))]
    save("csharp-security-issues.json", issues)
    save("security-hotspots.json", hotspots)
    save("measures.json", measures)
    save("server-processing.json", processing)
    for item in OUTPUT.glob("timing-*.json"):
        timings.update(json.loads(item.read_text(encoding="utf-8-sig")))
    languages = dict(part.split("=", 1) for part in values.get("ncloc_language_distribution", "").split(";") if "=" in part)
    count = int(languages.get("cs", 0))
    summary = {"project": PROJECT, "mode": "automatic" if MODE.startswith("automatic") else "compiled", "commit": commit,
        "csharp_ncloc": count, "security_issue_reports": len(issues), "hotspot_reports": len(hotspots),
        "security_issues_by_rule": dict(collections.Counter(item["rule"] for item in issues)), "timings": timings,
        "active_security_rules": json.loads((OUTPUT / "security-rule-manifest.json").read_text())["rule_count"],
        "coverage_status": "C# analyzed" if count else "No C# measured; incomplete C# coverage", "tp_fp_reviewed": False}
    save("summary.json", summary)
    text = "## Sonar C# security â€” " + summary["mode"] + "\n\n```json\n" + json.dumps(summary, indent=2) + "\n```\n"
    (OUTPUT / "summary.md").write_text(text, encoding="utf-8")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write(text)
    print(json.dumps(summary))


try:
    if MODE == "preflight":
        configure(False)
    elif MODE.startswith("automatic"):
        existing_analyses = {item["key"] for item in api("project_analyses/search", {"project": PROJECT, "ps": 10})["analyses"]}
        configure(True)
        start = time.monotonic()
        commit = os.environ.get("SONAR_AUTOMATIC_COMMIT")
        if commit:
            save("trigger.json", {"commit": commit, "source_commit": os.environ["SONAR_SOURCE_COMMIT"]})
            print("Automatic profile ready; waiting for the specified external trigger commit.", flush=True)
        else:
            commit = trigger_automatic()
        while True:
            analyses = api("project_analyses/search", {"project": PROJECT, "ps": 10})["analyses"]
            analysis = next((item for item in analyses if item.get("revision") == commit), None)
            if analysis:
                break
            if time.monotonic() - start > 1800:
                raise RuntimeError("Automatic analysis did not publish this commit within 30 minutes; coverage unverified.")
            time.sleep(15)
        export({"analysis": analysis, "method": "Cloud Automatic Analysis; no user build; scanner logs unavailable"},
            commit, {"automatic_wall_seconds": None if analysis["key"] in existing_analyses else time.monotonic() - start,
                "reused_completed_analysis": analysis["key"] in existing_analyses, "isolated_scanner_seconds": None})
    elif MODE == "collect":
        task_files = list(pathlib.Path(".sonarqube").rglob("report-task.txt"))
        if len(task_files) != 1:
            raise RuntimeError("Expected one report-task.txt.")
        task_text = task_files[0].read_text(encoding="utf-8-sig")
        (OUTPUT / "report-task.txt").write_text(task_text, encoding="utf-8")
        task = dict(line.split("=", 1) for line in task_text.splitlines() if "=" in line)
        start = time.monotonic()
        while True:
            processing = api("ce/task", {"id": task["ceTaskId"]})
            status = processing["task"]["status"]
            if status not in {"PENDING", "IN_PROGRESS"}:
                break
            if time.monotonic() - start > 1200:
                raise RuntimeError("Server processing exceeded 20 minutes.")
            time.sleep(10)
        if status != "SUCCESS":
            raise RuntimeError("Server processing failed: " + processing["task"].get("errorMessage", status))
        milliseconds = processing["task"].get("executionTimeMs")
        export(processing, os.environ.get("COMPARISON_COMMIT", os.environ["GITHUB_SHA"]),
            {"server_execution_seconds": milliseconds / 1000 if milliseconds is not None else None})
    else:
        raise RuntimeError("Expected automatic, preflight, or collect.")
except Exception as error:
    save("error.json", {"mode": MODE, "error": str(error).replace(TOKEN, "[redacted]")})
    raise
