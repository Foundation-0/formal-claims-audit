#!/usr/bin/env python3
"""Inventory catalogue candidates from a local pinned CONTENTS.md, without building code."""
import argparse,json,re
p=argparse.ArgumentParser(description=__doc__);p.add_argument('contents');p.add_argument('--commit',required=True);a=p.parse_args()
if not re.fullmatch('[0-9a-f]{40}',a.commit):p.error('full source commit required')
s=open(a.contents).read();rows=[]
for m in re.finditer(r'^\*\*(\d+)\. (.+?)\*\*(.*)$',s,re.M):
 n,title,tail=m.groups()
 if re.search('erd[oő]s',title+' '+tail,re.I):rows.append({'catalog_number':int(n),'title':title,'scope_pages':re.findall(r'\]\((lean/docs/[^)]+)\)',tail),'build':'not-run','axioms':None})
print(json.dumps({'source_commit':a.commit,'selection':'catalogue text mentions Erdos, not a complete problem-number census','records':rows},indent=2))
