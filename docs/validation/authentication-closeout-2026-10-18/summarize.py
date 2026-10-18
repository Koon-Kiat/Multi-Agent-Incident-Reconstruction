import collections
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
summary = {}
reviews = []
for group in ('autonomy', 'corpus', 'synthetic', 'investigations'):
    manifest_path = ROOT / group / 'manifest.json'
    if not manifest_path.exists():
        continue
    manifest = json.loads(manifest_path.read_text())
    rows = []
    for item in manifest['cases']:
        path = ROOT / group / item['file']
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
        case = json.loads(path.read_text())
        result = case['result']
        ops = result['metadata']['operations']
        model_ops = [o for o in ops if o['origin'] == 'model']
        assessment = case.get('evaluation_only', {}).get('assessment', {})
        turns = []
        for call in case['model_calls']:
            context = json.loads(call['messages'][-1]['content'])
            turns.append({'context_sha256': hashlib.sha256(call['messages'][-1]['content'].encode()).hexdigest(),
                          'remaining_budget': context['tool_calls_remaining'],
                          'visible_ids': [e['evidence_id'] for o in context['observations'] for e in o['events']],
                          'last_tool_result': context['last_tool_result'],
                          'decision': json.loads(call['reply']) if 'reply' in call else None,
                          'error': call.get('error_code'), 'metrics': call.get('response_metrics', {}),
                          'elapsed_seconds': call['elapsed_seconds']})
        row = {'file': group + '/' + item['file'], 'status': result['status'],
               'error': result['error_code'], 'check_errors': case['check_errors'],
               'behavior_errors': assessment.get('behavior_errors', []),
               'elapsed_seconds': case['elapsed_seconds'],
               'optional_operations': len(model_ops),
               'new_optional_ids': sorted({e for o in model_ops for e in o['new_evidence_ids']}),
               'repeated_operations': sum(o['reused_from'] is not None for o in model_ops),
               'strict_useful': assessment.get('useful_autonomous_retrieval_demonstrated'),
               'relevant_new_ids': assessment.get('relevant_new_evidence_ids', []),
               'uncertainty': result['uncertainty']}
        rows.append(row)
        if row['check_errors'] or row['behavior_errors'] or row['new_optional_ids']:
            reviews.append({**row, 'request': result['request'], 'limits': result['metadata']['limits'],
                            'expected': case.get('evaluation_only', {}).get('unresolved_question'),
                            'directed_first_tool': result['metadata']['llm'].get('directed_first_tool'),
                            'operations': ops, 'turns': turns})
    summary[group] = {'total': len(rows), 'check_pass': sum(not r['check_errors'] for r in rows),
                      'behavior_pass': sum(not r['behavior_errors'] and not r['check_errors'] for r in rows),
                      'strict_useful': sum(r['strict_useful'] is True for r in rows),
                      'result_error_codes': dict(collections.Counter(r['error'] for r in rows if r['error'])),
                      'elapsed_seconds': sum(r['elapsed_seconds'] for r in rows), 'cases': rows}
(ROOT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(ROOT / 'case-review.json').write_text(json.dumps(reviews, indent=2) + '\n')
print(json.dumps({k: {a:b for a,b in v.items() if a != 'cases'} for k,v in summary.items()}, indent=2))
