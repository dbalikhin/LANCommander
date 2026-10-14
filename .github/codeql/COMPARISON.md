# LANCommander C# CodeQL comparison

The workflow runs nine independent jobs: `none`, `autobuild`, and `manual`, each with default, security-extended, and all-security queries. JavaScript and the quality suite are excluded. All-security selects bundled security-tagged problem and path-problem queries without a precision filter; it does not claim to include arbitrary third-party rules.

Baseline: `LANCommander/LANCommander` main commit `92e30cc90b9910d8bd2fefe5e82d9361fb229d36`. CodeQL bundle 2.27.2 and the action revision match the previous most-vulnerable-app comparison. Windows 2025, .NET SDK 10.0.401, Node 20. Manual mode restores and builds the entire `LANCommander.slnx` solution in Release, including tests and Razor projects. Autobuild selects projects itself; verify its logs before treating coverage as equivalent. No-build may miss generated code; inspect extraction warnings before interpreting fewer findings.

Each job preserves SARIF, findings with file/line locations, invocation diagnostics and provenance in a 90-day artifact. Manual build and frontend logs are also retained. SARIF upload is disabled. Use Actions job/step timestamps for job and action durations; CodeQL query evaluation/export logs provide scanner timings. Manual restore/build duration is recorded separately. A workflow duration includes scheduling and concurrency and is not scanner time.

Push to `codeql-mode-comparison` starts all nine jobs. Workflow dispatch is available once this workflow is present on the default branch. Compare findings on the same source revision and review TP/FP separately; counts alone do not establish detection quality.
