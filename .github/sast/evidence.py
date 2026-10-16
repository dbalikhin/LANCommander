import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path.cwd()
OUT = ROOT / 'benchmark-evidence'
OUT.mkdir(exist_ok=True)


def save(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2), encoding='utf-8')


def tracked():
    return [os.fsdecode(p) for p in subprocess.check_output(['git', 'ls-files', '-z']).split(b'\0') if p]


def provenance():
    paths = [p for p in tracked() if Path(p).suffix.lower() in {'.cs', '.cshtml', '.razor', '.aspx', '.csproj', '.sln', '.slnx', '.props', '.targets'} or Path(p).name.lower() in {'global.json', 'nuget.config'}]
    manifest = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths if (ROOT / p).is_file()}
    save('source-manifest.json', manifest)
    save('provenance.json', {
        'repository': os.environ.get('GITHUB_REPOSITORY'),
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'run': os.environ.get('GITHUB_RUN_ID'), 'attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
        'runner_os': os.environ.get('RUNNER_OS'), 'profile': os.environ.get('PROFILE'),
        'files_by_extension': dict(collections.Counter(Path(p).suffix.lower() for p in manifest)),
        'source_manifest_sha256': hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
    })


def stage_snyk():
    target = Path(os.environ['RUNNER_TEMP']) / 'snyk-csharp-input'
    target.mkdir(exist_ok=True)
    paths = json.loads((OUT / 'source-manifest.json').read_text(encoding='utf-8'))
    for path in paths:
        destination = target / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, destination)
    save('snyk-scope.json', {'staging_path': str(target), 'paths': list(paths), 'scope': 'Tracked C#/Razor and build metadata, including tests. No JS/TS or SCA.'})


def group():
    groups = collections.defaultdict(list)
    artifacts = []
    invocations = []
    for path in sorted(ROOT.rglob('*.sarif')):
        if any(part in {'node_modules', '.git', 'obj', 'bin'} for part in path.parts):
            continue
        try:
            data = json.loads(path.read_text(encoding='utf-8-sig'))
        except (ValueError, OSError):
            continue
        artifacts.append({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        for run in data.get('runs', []):
            invocations.append({'artifact': str(path.relative_to(ROOT)), 'tool': run.get('tool'), 'invocations': run.get('invocations', [])})
            for finding in run.get('results', []):
                if finding.get('ruleId') == 'DNA9000':
                    continue
                locations = finding.get('locations') or [{}]
                physical = locations[0].get('physicalLocation', {})
                file = physical.get('artifactLocation', {}).get('uri', '')
                line = physical.get('region', {}).get('startLine')
                groups[(finding.get('ruleId', ''), file, line)].append(finding)
    records = [{'rule': rule, 'file': file, 'line': line, 'report_count': len(items), 'findings': items} for (rule, file, line), items in sorted(groups.items(), key=lambda item: str(item[0]))]
    save('groups.json', records)
    save('artifact-manifest.json', artifacts)
    save('scanner-invocations.json', invocations)
    save('summary.json', {'raw_reports': sum(len(v) for v in groups.values()), 'rule_file_line_groups': len(groups), 'reports_by_rule': dict(collections.Counter({rule: sum(len(v) for (r, _, _), v in groups.items() if r == rule) for rule, _, _ in groups})), 'tp_fp_reviewed': False, 'sarif_files': len(artifacts)})


{'provenance': provenance, 'stage-snyk': stage_snyk, 'group': group}[sys.argv[1]]()
