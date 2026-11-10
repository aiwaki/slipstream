from pathlib import Path
import subprocess,json,datetime,hashlib,re,resource,time
root=Path(__file__).resolve().parent
base=root.parent/'pr476/geph-audit/official/sqlx-wrapper-compatibility'
records=[]
for version in ('0.30.1','0.39.1'):
 source=(base/f'libsqlite3-sys-{version}/sqlite3/sqlite3.c').resolve()
 output=root/('wal-read-'+version)
 cmd=['/usr/bin/clang','-O0','-g0','-DSQLITE_THREADSAFE=1','-DSQLITE_ENABLE_API_ARMOR','-DSQLITE_ENABLE_COLUMN_METADATA','-DSQLITE_ENABLE_UNLOCK_NOTIFY','-DSOURCE_SQLITE="'+str(source)+'"',str(root/'wal-read-regression.c'),'-o',str(output)]
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();clock=time.monotonic()
 before=resource.getrusage(resource.RUSAGE_CHILDREN)
 p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
 (root/('compile-'+version+'.log')).write_bytes(p.stdout)
 assert p.returncode==0,(version,p.returncode,p.stdout[-1000:])
 compile_time=time.monotonic()-clock
 compiled=resource.getrusage(resource.RUSAGE_CHILDREN)
 p=subprocess.run([str(output)],capture_output=True,timeout=10)
 (root/('wal-read-'+version+'.jsonl')).write_bytes(p.stdout)
 (root/('wal-read-'+version+'.stderr')).write_bytes(p.stderr)
 assert p.returncode==0,(version,p.returncode,p.stderr)
 lines=[json.loads(line) for line in p.stdout.splitlines()]
 cases=lines[1:]
 assert len(cases)==6
 for c in cases:
  tail=c['requested']-c['read_bytes']
  assert c['tail_zeros']==(tail if version=='0.39.1' else 0)
  assert c['tail_markers']==(0 if version=='0.39.1' else tail)
 records.append({'wrapper':version,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'binary_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'compile_command':cmd,'started_at':start,'compile_seconds':round(compile_time,3),'child_max_rss_bytes':compiled.ru_maxrss,'result':lines,'returncode':p.returncode})
result={'schema_version':1,'status':'PASS','scope':'Full unmodified SQLite amalgamation compiled into test; actual internal sqlite3WalReadFrame and sqlite3OsRead call with deterministic synthetic VFS. Not a public SQL parser/database-file exploit or compiled Geph/app qualification.','test_sha256':hashlib.sha256((root/'wal-read-regression.c').read_bytes()).hexdigest(),'compiler':subprocess.run(['/usr/bin/clang','--version'],capture_output=True,text=True,check=True).stdout,'cases_per_version':6,'vulnerable_control':'0.30.1 retains 0xA5 outside smaller WAL frame; 0.39.1 zeroes the complete requested tail. Both preserve payload/offset/count/bounds and propagate I/O error.','records':records}
(root/'wal-read-regression-receipt.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'cases_per_version':6,'versions':[r['result'][0]['version'] for r in records],'compile_seconds':[r['compile_seconds'] for r in records],'max_rss_bytes':[r['child_max_rss_bytes'] for r in records]}))
