import collections,datetime,hashlib,json,os,pathlib,statistics,subprocess,sys,time
import yaml
from semgrep.config_resolver import ConfigLoader
from semgrep.state import get_state

profile=os.environ['PROFILE']; config='policy' if profile=='policy' else 'p/'+profile
evidence=pathlib.Path('profile-evidence');evidence.mkdir(exist_ok=True)
results=pathlib.Path('profile-results');results.mkdir(exist_ok=True)
def save(p,d):p.write_text(json.dumps(d,indent=2),encoding='utf-8')
def capture(args,log):
    t=time.perf_counter()
    with log.open('w',encoding='utf-8') as f:p=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT)
    return p.returncode,round(time.perf_counter()-t,6)
state=get_state();state.app_session.authenticate()
inventory=dict(profile=profile,config=config,authenticated=state.app_session.is_authenticated,cli_version='1.181.0',repo=os.environ['GITHUB_REPOSITORY'],commit=os.environ['GITHUB_SHA'],downloaded_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
try:
    loaded=ConfigLoader(config,project_url='https://github.com/'+os.environ['GITHUB_REPOSITORY']).load_config()
except Exception as ex:
    # Credentials are never emitted. ConfigLoader reports endpoint/status, not token values.
    inventory.update(status='config_unavailable',error=str(ex).replace(os.environ.get('SEMGREP_APP_TOKEN','__no_token__'),'[REDACTED]'))
    save(evidence/'inventory.json',inventory);print(json.dumps(inventory));sys.exit(1)
rules=[]
for f in loaded:rules.extend((yaml.safe_load(f.contents) or {}).get('rules',[]))
selected=[];manifest=[];excluded=collections.Counter()
for rule in rules:
    langs=[str(l).lower() for l in rule.get('languages',[])]
    if not any(l in ('csharp','c#') for l in langs):excluded['not_csharp']+=1;continue
    if rule.get('metadata',{}).get('category')!='security':excluded['not_security_category']+=1;continue
    if any(l not in ('csharp','c#') for l in langs):
        excluded['mixed_language_rule']+=1;continue
    meta=rule.get('metadata',{});options=rule.get('options',{}) or {}
    origin=meta.get('semgrep.dev',{})
    manifest.append(dict(id=rule['id'],sha256=hashlib.sha256(json.dumps(rule,sort_keys=True).encode()).hexdigest(),mode=rule.get('mode','search'),interfile=options.get('interfile',False),metadata=meta))
    selected.append(rule)
inventory.update(status='ready' if selected else 'no_csharp_security_rules',total_rules=len(rules),selected_rules=len(selected),excluded=dict(excluded),by_mode=dict(collections.Counter(r.get('mode','search') for r in selected)),interfile_rules=sum(bool((r.get('options',{}) or {}).get('interfile')) for r in selected),rules=manifest)
save(evidence/'inventory.json',inventory)
print(json.dumps({k:v for k,v in inventory.items() if k!='rules'}))
if not selected:
    save(results/'summary.json',dict(profile=profile,status='no_csharp_security_rules',runs=[]));sys.exit(0)
# Preserve original rule metadata/licenses, never export rule patterns in public artifacts.
local=pathlib.Path(os.environ['RUNNER_TEMP'])/'selected-profile-rules.json'
local.write_text(json.dumps(dict(rules=selected)),encoding='utf-8')
runs=[]
for i in range(1,4):
    out=results/f'run-{i}.json'
    args=['semgrep','scan','--pro','--config',str(local),'--no-rewrite-rule-ids','--include','*.cs','--no-git-ignore','--exclude','profile-results','--exclude','profile-evidence','--metrics','off','--disable-version-check','--jobs','2','--timeout','120','--max-target-bytes','0','--json','--output',str(out),'--sarif-output',str(results/f'run-{i}.sarif'),'--time','.']
    code,seconds=capture(args,evidence/f'scan-{i}.log')
    d=json.loads(out.read_text()) if out.exists() else {}
    runs.append(dict(repetition=i,exit_code=code,scanner_wall_seconds=seconds,result_count=len(d.get('results',[])),unique_rule_file_line=len({(r['check_id'],r['path'],r['start']['line']) for r in d.get('results',[])}),engine_requested=d.get('engine_requested'),rules_executed=len(d.get('time',{}).get('rules',[])),paths=d.get('paths'),errors=d.get('errors',[]),time=d.get('time')))
    print(json.dumps({k:v for k,v in runs[-1].items() if k not in ('paths','errors','time')}))
summary=dict(profile=profile,config=config,status='completed' if all(r['exit_code']==0 for r in runs) else 'scanner_error',selected_rules=len(selected),interfile_rules=inventory['interfile_rules'],median_scanner_wall_seconds=statistics.median(r['scanner_wall_seconds'] for r in runs),runs=runs)
save(results/'summary.json',summary)
with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:f.write(f"{profile}: selected {len(selected)} C# security rules; {inventory['interfile_rules']} interfile; findings {[r['result_count'] for r in runs]}; median scanner {summary['median_scanner_wall_seconds']:.3f}s\n")
if summary['status']!='completed':sys.exit(1)
