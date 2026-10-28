#!/usr/bin/env python3
"""Prepare a comparison record only when both independent inputs are present."""
import argparse,hashlib,json,pathlib,re
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--lab',type=pathlib.Path,required=True);p.add_argument('--independent',type=pathlib.Path,required=True);p.add_argument('--source-commit',required=True);p.add_argument('--independent-commit',required=True);p.add_argument('--author',required=True);a=p.parse_args()
for pin in (a.source_commit,a.independent_commit):
 if not re.fullmatch('[0-9a-f]{40}',pin):p.error('full commit hashes required')
if a.lab.resolve()==a.independent.resolve():p.error('statements must be separate artifacts')
records=[]
for role,path,pin in [('lab',a.lab,a.source_commit),('independent',a.independent,a.independent_commit)]:
 raw=path.read_bytes()
 if not raw.strip():p.error('empty statement')
 records.append({'role':role,'file':str(path),'commit':pin,'sha256':hashlib.sha256(raw).hexdigest()})
print(json.dumps({'status':'prepared; comparison not run','inputs':records,'independent_author':a.author,'verdict':None,'bridge_lemma':None,'reviewer':None},indent=2))
