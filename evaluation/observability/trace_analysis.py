import sqlite3, json
from pathlib import Path
from collections import Counter

DATA = Path('data')
RESULTS = Path('evaluation/results')

def q(db, sql):
    p = DATA / db
    if not p.exists(): return []
    c = sqlite3.connect(p)
    c.row_factory = sqlite3.Row
    r = c.execute(sql).fetchall()
    c.close()
    return [dict(x) for x in r]

convs = q('shld_conversations.db', 'SELECT * FROM conversations ORDER BY updated_at DESC')
audit = q('shld_audit.db', 'SELECT * FROM approval_audit ORDER BY id DESC')
events = q('shld.db', 'SELECT * FROM security_events ORDER BY created_at DESC')

counts = Counter(x['decision'] for x in audit)
report = {'conversations': {'total': len(convs), 'data': convs}, 'audit': {'total': len(audit), 'approved': counts.get('approved',0), 'rejected': counts.get('rejected',0), 'data': audit}, 'security_events': {'total': len(events), 'data': events[:20]}}

out = RESULTS / 'trace_report.json'
out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
print('Conversaciones:', len(convs))
print('Decisiones aprobacion:', len(audit))
print('Eventos seguridad:', len(events))
print('Guardado en:', out)

