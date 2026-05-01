#!/usr/bin/env python3
"""Generate a commit message summary from release_report.json."""
import json
from pathlib import Path

r = Path('dist/release_report.json')
if not r.exists():
    print('auto-update')
else:
    try:
        d = json.loads(r.read_text())
        total      = d.get('rule_delta', {}).get('total_rules_now', 0)
        delta      = d.get('rule_delta', {}).get('delta')
        fetch      = d.get('fetch') or {}
        new_domains = fetch.get('total_new_domains', 0)
        skipped    = fetch.get('total_platform_skipped', 0)
        parts = [f'rules={total}']
        if delta is not None:
            sign = '+' if delta >= 0 else ''
            parts.append(f'delta={sign}{delta}')
        if new_domains:
            parts.append(f'new={new_domains}')
        if skipped:
            parts.append(f'platform-skip={skipped}')
        print(' | '.join(parts))
    except Exception:
        print('auto-update')
