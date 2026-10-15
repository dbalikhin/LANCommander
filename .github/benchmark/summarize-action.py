import collections,json,os,pathlib,subprocess
root=pathlib.Path('action-evidence');root.mkdir(exist_ok=True)
p=pathlib.Path('dotnetarium-action-results.sarif')
data=dict(repo=os.environ['GITHUB_REPOSITORY'],workflow_commit=os.environ['GITHUB_SHA'],run_id=os.environ['GITHUB_RUN_ID'],mode=os.environ['MODE'],requested_profile=os.environ['PROFILE'],target=os.environ['TARGET'],action_commit='8e63bfc79a99d11f07f39331709534fec013d82e',requested_cli_version='2.7.0',scope='Solution scans omit tests; no application build is requested. Source baseline preserved from prior scanner comparison.',outputs=dict(findings=os.environ.get('FINDINGS'),input_status=os.environ.get('INPUT_STATUS'),analysis_status=os.environ.get('ANALYSIS_STATUS')))
if p.exists():
    sarif=json.loads(p.read_text(encoding='utf-8-sig'));run=sarif['runs'][0]
    results=[r for r in run.get('results',[]) if r['ruleId']!='DNA9000']
    data.update(actual_driver=run['tool']['driver'],findings=len(results),by_rule=dict(collections.Counter(r['ruleId'] for r in results)),invocations=run.get('invocations',[]),analysis_limit_results=[r for r in run.get('results',[]) if r['ruleId']=='DNA9000'])
timing=root/'scanner-process-timing.json'
if timing.exists():data['process_timing']=json.loads(timing.read_text())
data['dotnet_info']=subprocess.run(['dotnet','--info'],text=True,capture_output=True).stdout
(root/'summary.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in data.items() if k not in ('actual_driver','invocations','analysis_limit_results','dotnet_info')},indent=2))
