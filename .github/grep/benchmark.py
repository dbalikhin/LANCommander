import collections
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time
import urllib.request

ENGINE=os.environ['ENGINE']
RESULTS=Path('results'); EVIDENCE=Path('evidence')
RESULTS.mkdir(exist_ok=True);EVIDENCE.mkdir(exist_ok=True)
STATE=EVIDENCE/'scanner-state.json'
RULES_COMMIT='9bbf021d0acffa3095fcffd17b2bc7787eb4796d'
OG_VERSION='1.30.2';SG_VERSION='1.181.0'
def save(path,obj): path.write_text(json.dumps(obj,indent=2),encoding='utf-8')
def output(*args): return subprocess.check_output(args,text=True).strip()
def run_logged(args,path):
    start=time.perf_counter()
    # Do not emit token-bearing arguments; token is supplied only through the environment.
    with path.open('w',encoding='utf-8') as log:
        proc=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,text=True)
    return proc.returncode,round(time.perf_counter()-start,6)
def prepare():
    start=time.perf_counter()
    state=dict(engine=ENGINE,available=False,requested_mode='cross-file' if ENGINE=='semgrep-pro' else 'community',rules_commit=RULES_COMMIT)
    save(STATE,state)
    tracked=output('git','ls-files','-z').split('\0')
    targets=[p for p in tracked if p.lower().endswith('.cs')]
    save(EVIDENCE/'source-provenance.json',dict(commit=output('git','rev-parse','HEAD'),repository=os.environ.get('GITHUB_REPOSITORY'),run=os.environ.get('GITHUB_RUN_ID'),tracked_csharp_count=len(targets),tracked_csharp_files=targets,scope='Tracked source checkout, .cs only, including tests. No compilation, Razor files or generated code. Scanner reported paths/errors are authoritative for actual coverage.'))
    if ENGINE=='semgrep-pro' and not os.environ.get('SEMGREP_APP_TOKEN'):
        state.update(status='unavailable',reason='SEMGREP_APP_TOKEN repository secret is absent; Pro engine not installed or scanned',setup_seconds=round(time.perf_counter()-start,6))
        save(STATE,state);print(state['reason']);return
    temp=Path(os.environ.get('RUNNER_TEMP','/tmp'))
    upstream=temp/'community-rules'
    subprocess.run(['git','clone','--filter=blob:none','--no-checkout','https://github.com/semgrep/semgrep-rules.git',str(upstream)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['git','-C',str(upstream),'sparse-checkout','set','csharp'],check=True)
    subprocess.run(['git','-C',str(upstream),'checkout',RULES_COMMIT],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    import yaml
    selected=temp/'selected-csharp-security-rules'
    selected.mkdir(exist_ok=True)
    manifest=[]
    for file in sorted((upstream/'csharp').rglob('*.yaml')):
        rules=(yaml.safe_load(file.read_text()) or {}).get('rules',[])
        matches=[r for r in rules if r.get('metadata',{}).get('category')=='security' and all(str(l).lower() in ('csharp','c#') for l in r.get('languages',[]))]
        if not matches:continue
        if len(matches)!=len(rules):raise RuntimeError('Mixed rule file requires explicit review: '+str(file))
        dest=selected/file.relative_to(upstream)
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(file,dest)
        for r in matches:manifest.append(dict(id=r['id'],source=str(file.relative_to(upstream)),sha256=hashlib.sha256(file.read_bytes()).hexdigest(),category='security',languages=r['languages']))
    # Preserve license notices locally; do not redistribute downloaded rule patterns in artifacts.
    shutil.copyfile(upstream/'LICENSE',selected/'LICENSE')
    if not manifest:raise RuntimeError('No security C# rules selected')
    save(EVIDENCE/'rules-manifest.json',dict(repository='semgrep/semgrep-rules',commit=RULES_COMMIT,count=len(manifest),rules=manifest,license_url='https://semgrep.dev/legal/rules-license/'))
    state['rules_dir']=str(selected);state['rule_count']=len(manifest)
    if ENGINE=='opengrep':
        binary=temp/'opengrep'
        urllib.request.urlretrieve('https://github.com/opengrep/opengrep/releases/download/v'+OG_VERSION+'/opengrep_manylinux_x86',binary)
        if hashlib.sha256(binary.read_bytes()).hexdigest()!='a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7':raise RuntimeError('OpenGrep checksum mismatch')
        binary.chmod(0o755)
        executable=str(binary)
    else:
        subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','semgrep=='+SG_VERSION],check=True,stdout=subprocess.DEVNULL)
        executable=shutil.which('semgrep')
        if ENGINE=='semgrep-pro':
            code,elapsed=run_logged([executable,'install-semgrep-pro'],EVIDENCE/'pro-install.log')
            state['pro_install_seconds']=elapsed
            if code:
                state.update(status='unavailable',reason='Pro installation/access check failed; see pro-install.log',install_exit_code=code,setup_seconds=round(time.perf_counter()-start,6));save(STATE,state);return
    state.update(executable=executable,version=output(executable,'--version'),available=True,status='ready',setup_seconds=round(time.perf_counter()-start,6))
    save(STATE,state);print(json.dumps(state))
def scan():
    state=json.loads(STATE.read_text())
    if not state['available']:
        save(RESULTS/'summary.json',dict(engine=ENGINE,status='unavailable',reason=state.get('reason'),runs=[]))
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:f.write(ENGINE+': unavailable â€” '+state.get('reason','')+'\n')
        return
    runs=[]
    for i in range(1,4):
        result=RESULTS/f'run-{i}.json'
        args=[state['executable'],'scan','--config',state['rules_dir'],'--include','*.cs','--no-git-ignore','--exclude','results','--exclude','evidence','--disable-version-check','--jobs','2','--timeout','120','--max-target-bytes','0','--json','--output',str(result),'--sarif-output',str(RESULTS/f'run-{i}.sarif'),'--time']
        if ENGINE!='opengrep':args.extend(['--metrics','off'])
        if ENGINE=='semgrep-ce':args.append('--oss-only')
        if ENGINE=='semgrep-pro':args.append('--pro')
        args.append('.')
        code,elapsed=run_logged(args,EVIDENCE/f'scan-{i}.log')
        data=json.loads(result.read_text()) if result.exists() else {}
        findings=data.get('results',[])
        record=dict(repetition=i,scanner_wall_seconds=elapsed,exit_code=code,result_count=len(findings),unique_rule_file_line=len({(r['check_id'],r['path'],r['start']['line']) for r in findings}),by_rule=dict(collections.Counter(r['check_id'] for r in findings)),errors=data.get('errors',[]),paths=data.get('paths'),engine_requested=data.get('engine_requested'),time=data.get('time'))
        runs.append(record)
        print(json.dumps({k:v for k,v in record.items() if k not in ('time','paths','errors','by_rule')}))
    summary=dict(engine=ENGINE,status='completed' if all(r['exit_code']==0 for r in runs) else 'scanner_error',version=state['version'],rules_commit=RULES_COMMIT,rule_count=state['rule_count'],setup_seconds=state['setup_seconds'],median_scanner_wall_seconds=statistics.median(r['scanner_wall_seconds'] for r in runs),runs=runs)
    save(RESULTS/'summary.json',summary)
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:
        f.write(f"{ENGINE}: {summary['status']}; rules {state['rule_count']}; median scanner wall {summary['median_scanner_wall_seconds']:.3f}s; alerts {[r['result_count'] for r in runs]}; errors {[len(r['errors']) for r in runs]}\n")
    if summary['status']!='completed':sys.exit(1)
if sys.argv[1]=='prepare':prepare()
elif sys.argv[1]=='scan':scan()
else:raise ValueError(sys.argv[1])
