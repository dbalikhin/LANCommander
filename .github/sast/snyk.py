import json, os, pathlib, subprocess, time
args = ['snyk', 'code', 'test', os.environ['RUNNER_TEMP'] + '/snyk-csharp-input', '--severity-threshold=low', '--sarif-file-output=' + str(pathlib.Path('results/snyk-code.sarif').resolve()), '--remote-repo-url=https://github.com/' + os.environ['GITHUB_REPOSITORY']]
if os.environ.get('SNYK_ORG'): args += ['--org=' + os.environ['SNYK_ORG']]
start = time.perf_counter()
with open('benchmark-evidence/snyk-code.log', 'w') as log:
    result = subprocess.run(args, stdout=log, stderr=subprocess.STDOUT)
pathlib.Path('benchmark-evidence/snyk-timing.json').write_text(json.dumps({'version':'1.1308.1','scanner_wall_seconds':time.perf_counter()-start,'exit_code':result.returncode,'timing_scope':'CLI wall including transfer and cloud processing'}, indent=2))
raise SystemExit(0 if result.returncode in (0,1) else result.returncode)
