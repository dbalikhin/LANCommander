import json
import os
import subprocess
from pathlib import Path

def output(*args):
    return subprocess.check_output(args, text=True).strip()

record = {k: os.environ[k] for k in ("MODE", "SUITE", "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
record.update(
    language="csharp",
    source_tree=output("git", "rev-parse", "HEAD^{tree}"),
    dotnet_sdk=output("dotnet", "--version"),
    node_version=output("node", "--version"),
    codeql_bundle="2.27.2",
    baseline_commit="92e30cc90b9910d8bd2fefe5e82d9361fb229d36",
    baseline_tree="0e4d10dd6a3d5ee14a227f55e859b85d86636ee6",
    scope="Entire repository, including solution projects and tests. Manual build: LANCommander.slnx Release. Autobuild scope must be verified from extraction logs.",
    runner=os.environ.get("RUNNER_OS"),
)
Path("evidence/provenance.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
