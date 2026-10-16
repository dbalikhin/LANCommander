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
    save("csharp-profiles.json", api("qualityprofiles/search", {"organization": "dbalikhin", "project": PROJECT, "language": "cs"}))
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
    issues = pages("issues/search", {"componentKeys": PROJECT, "languages": "cs", "types": "VULNERABILITY", "resolved": "false"}, "issues")
    hotspots = pages("hotspots/search", {"projectKey": PROJECT}, "hotspots")
    save("csharp-vulnerabilities.json", issues)
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
               "vulnerability_reports": len(issues), "hotspot_reports": len(hotspots),
               "vulnerabilities_by_rule": dict(groups), "timings": timings,
               "scope": "built C# projects; existing security profile; quality findings excluded from comparison"}
    save("summary.json", summary)
    lines = ["## SonarQube Cloud C# security", "", f"Vulnerability reports: {len(issues)}",
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
