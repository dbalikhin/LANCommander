import datetime,json,os,pathlib,time

root=pathlib.Path('action-evidence');root.mkdir(exist_ok=True)
ready=root/'observer-ready';stop=root/'observer-stop'
found={};poll=0.05
def save():
    (root/'scanner-process-timing.json').write_text(json.dumps(dict(measure='Observed scanner-process lifetime via Linux procfs; 50ms polling, approximately 60ms boundary uncertainty. Excludes tool installation, SDK setup, restore and upload.',poll_seconds=poll,processes=list(found.values())),indent=2))
ready.write_text('ready')
deadline=time.monotonic()+3500
while time.monotonic()<deadline:
    now=time.monotonic();seen=set()
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit():continue
        try:
            args=proc.joinpath('cmdline').read_bytes().decode(errors='replace').split('\0')
            if '--sarif' not in args:continue
            executable=pathlib.Path(args[0]).name.lower()
            if executable!='dotnetarium' and not any(a.endswith('/Dotnetarium.Tool.dll') for a in args):continue
            seen.add(proc.name)
            if proc.name not in found:
                ticks=int(proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19])
                started=ticks/os.sysconf('SC_CLK_TCK')
                found[proc.name]=dict(pid=int(proc.name),command=args[:-1] if args[-1]=='' else args,start_monotonic_seconds=started,first_observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),last_observed_monotonic_seconds=now,completed=False)
            found[proc.name]['last_observed_monotonic_seconds']=now
        except (OSError,ValueError,IndexError):pass
    for pid,item in found.items():
        if pid not in seen and not item['completed']:
            item.update(completed=True,observed_scanner_wall_seconds=round(now-item['start_monotonic_seconds'],6))
    save()
    if stop.exists():break
    time.sleep(poll)
save()
