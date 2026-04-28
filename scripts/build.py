#!/usr/bin/env python3
"""
ShieldNova Build Script
Merges source rule files (src/) into distributable combo files (dist/)
and generates multi-client output files under formats/.

Design goals:
- Conservative, compatibility-first output
- Deterministic rule ordering
- Syntax validation and duplicate checks
- Optional allowlist guardrail
- Per-bundle statistics for maintenance visibility
"""

import json
import os
import re
from collections import OrderedDict
from datetime import datetime, timezone

HEADER_TEMPLATE = """! Title: ShieldNova - {title}
! Description: {description}
! Author: Harry (https://github.com/harryheros)
! Homepage: https://github.com/harryheros/shieldnova
! License: CC BY-NC-SA 4.0
! Profile: Conservative / Compatibility-First
! Built: {date}
! Total: {count}
{extra}"""

SRC_DIR = os.path.join(os.path.dirname(__file__), '..', 'src')
DIST_DIR = os.path.join(os.path.dirname(__file__), '..', 'dist')
FORMATS_DIR = os.path.join(os.path.dirname(__file__), '..', 'formats')
DOMAIN_RE = re.compile(r'^\|\|([A-Za-z0-9.-]+)\^(?:\$.*)?$')


def utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def read_rules(filepath):
    """Read a rule file while stripping file-level metadata headers."""
    rules = []
    if not os.path.exists(filepath):
        return rules
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith((
                '! Title:', '! Description:', '! Author:', '! Homepage:',
                '! License:', '! Updated:', '! Built:', '! Total:',
                '! STATUS:', '! NOTE:', '! PURPOSE:', '! Profile:',
                '! Breakdown:'
            )):
                continue
            rules.append(line)
    return rules


def count_active_rules(rules):
    return sum(1 for r in rules if r.strip() and not r.strip().startswith(('!', '#')))


def active_rules_only(rules):
    return [r.strip() for r in rules if r.strip() and not r.strip().startswith(('!', '#'))]


def dedupe_preserve_order(items):
    seen = set()
    output = []
    for item in items:
        if item not in seen:
            seen.add(item)
            output.append(item)
    return output


def extract_domain(rule):
    rule = rule.strip()
    if '!' in rule:
        rule = rule.split('!', 1)[0].rstrip()
    m = DOMAIN_RE.match(rule)
    if not m:
        return None
    return m.group(1).lower()


def validate_rule(rule):
    domain = extract_domain(rule)
    if not domain:
        return False
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    return True


def normalize_rules(rules):
    cleaned = []
    invalid = []
    for line in rules:
        stripped = line.strip()
        if not stripped:
            cleaned.append('')
            continue
        if stripped.startswith('!'):
            cleaned.append(line.rstrip())
            continue
        if validate_rule(stripped):
            cleaned.append(stripped)
        else:
            invalid.append(stripped)
    return cleaned, invalid


def load_allowlist():
    allow_rules = []
    for candidate in [
        os.path.join(SRC_DIR, 'allowlist', 'core.txt'),
        os.path.join(SRC_DIR, 'allowlist', 'custom.txt'),
    ]:
        allow_rules += read_rules(candidate)
    return {r for r in active_rules_only(allow_rules) if validate_rule(r)}


def apply_allowlist(rules, allow_rules):
    if not allow_rules:
        return rules, 0
    filtered = []
    removed = 0
    for rule in rules:
        if rule.strip() and not rule.strip().startswith('!') and rule.strip() in allow_rules:
            removed += 1
            continue
        filtered.append(rule)
    return filtered, removed


def compact_rule_block(rules):
    """Drop duplicate rules, keep comments, collapse repeated blank lines."""
    output = []
    seen_rules = set()
    previous_blank = True
    for line in rules:
        stripped = line.strip()
        if not stripped:
            if not previous_blank:
                output.append('')
            previous_blank = True
            continue

        if stripped.startswith('!'):
            output.append(line.rstrip())
            previous_blank = False
            continue

        # Extract just the rule part (before inline comment) for dedup
        rule_part = stripped.split('!', 1)[0].rstrip() if '!' in stripped else stripped
        if rule_part not in seen_rules:
            output.append(stripped)
            seen_rules.add(rule_part)
        previous_blank = False

    if output and output[-1] != '':
        return output
    while output and output[-1] == '':
        output.pop()
    return output


def format_breakdown(breakdown):
    parts = [f"{k}={v}" for k, v in breakdown.items() if v is not None]
    return '! Breakdown: ' + ', '.join(parts)


def write_dist(filename, title, description, rules, breakdown):
    count = count_active_rules(rules)
    extra = format_breakdown(breakdown)
    header = HEADER_TEMPLATE.format(
        title=title,
        description=description,
        date=utc_now(),
        count=count,
        extra=extra,
    )
    filepath = os.path.join(DIST_DIR, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(header.strip() + '\n\n')
        if rules:
            f.write('\n'.join(rules) + '\n')
    print(f"  Built dist: {filename} ({count} rules)")


def convert_rule(rule, tool):
    domain = extract_domain(rule)
    if not domain:
        return None

    if tool == 'adguard':
        # AdGuard native syntax: ||domain.com^
        return f"||{domain}^"
    if tool == 'surge':
        # Surge: DOMAIN-SUFFIX,domain.com,REJECT
        return f"DOMAIN-SUFFIX,{domain},REJECT"
    if tool == 'shadowrocket':
        # Shadowrocket: DOMAIN-SUFFIX,domain.com,REJECT
        return f"DOMAIN-SUFFIX,{domain},REJECT"
    if tool == 'loon':
        # Loon: DOMAIN-SUFFIX,domain.com,REJECT
        return f"DOMAIN-SUFFIX,{domain},REJECT"
    if tool == 'quantumultx':
        # Quantumult X: HOST-SUFFIX,domain.com,reject
        return f"HOST-SUFFIX,{domain},reject"
    if tool == 'clash':
        # Clash: DOMAIN-SUFFIX,domain.com (action defined in proxy group, not inline)
        return f"DOMAIN-SUFFIX,{domain}"
    return None


def format_header_lines(title, description, count, tool, breakdown):
    date = utc_now()
    breakdown_text = ', '.join(f'{k}={v}' for k, v in breakdown.items() if v is not None)

    if tool == 'adguard':
        # AdGuard uses ! for comments
        return [
            f"! Title: ShieldNova - {title}",
            f"! Description: {description}",
            "! Profile: Conservative / Compatibility-First",
            "! Author: Harry (https://github.com/harryheros)",
            "! Homepage: https://github.com/harryheros/shieldnova",
            "! License: CC BY-NC-SA 4.0",
            f"! Built: {date}",
            f"! Total: {count}",
            f"! Breakdown: {breakdown_text}",
        ]

    if tool == 'clash':
        # Clash YAML uses # for comments, needs payload: key
        return [
            f"# ShieldNova - {title}",
            f"# Description: {description}",
            "# Profile: Conservative / Compatibility-First",
            "# Author: Harry (https://github.com/harryheros)",
            "# Homepage: https://github.com/harryheros/shieldnova",
            "# License: CC BY-NC-SA 4.0",
            f"# Built: {date}",
            f"# Total: {count}",
            f"# Breakdown: {breakdown_text}",
            "payload:",
        ]

    # Surge, Shadowrocket, Quantumult X, Loon all use # for comments
    return [
        f"# ShieldNova - {title}",
        f"# Description: {description}",
        "# Profile: Conservative / Compatibility-First",
        "# Author: Harry (https://github.com/harryheros)",
        "# Homepage: https://github.com/harryheros/shieldnova",
        "# License: CC BY-NC-SA 4.0",
        f"# Built: {date}",
        f"# Total: {count}",
        f"# Breakdown: {breakdown_text}",
    ]


def convert_rules_for_tool(rules, tool):
    converted = []
    for rule in active_rules_only(rules):
        converted_rule = convert_rule(rule, tool)
        if converted_rule:
            converted.append(converted_rule)
    return dedupe_preserve_order(converted)


def write_format(tool, filename, title, description, rules, breakdown):
    converted = convert_rules_for_tool(rules, tool)
    count = len(converted)
    filepath = os.path.join(FORMATS_DIR, tool, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    header_lines = format_header_lines(title, description, count, tool, breakdown)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header_lines) + '\n\n')
        if tool == 'clash':
            for rule in converted:
                f.write(f"  - {rule}\n")
        elif converted:
            f.write('\n'.join(converted) + '\n')

    print(f"  Built {tool}: {filename} ({count} rules)")


def write_all_formats(filename, title, description, rules, breakdown):
    for tool in ('adguard', 'surge', 'shadowrocket', 'clash', 'quantumultx', 'loon'):
        write_format(tool, filename, title, description, rules, breakdown)


def bundle_stats(filename, title, description, rules, breakdown):
    return OrderedDict([
        ('filename', filename),
        ('title', title),
        ('description', description),
        ('total', count_active_rules(rules)),
        ('breakdown', breakdown),
    ])


def write_stats_report(report):
    os.makedirs(DIST_DIR, exist_ok=True)
    json_path = os.path.join(DIST_DIR, 'stats.json')
    md_path = os.path.join(DIST_DIR, 'stats.md')

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    lines = [
        '# ShieldNova Build Stats',
        '',
        f'Built: {utc_now()}',
        '',
        '| File | Total | Breakdown |',
        '|---|---:|---|',
    ]
    for item in report['bundles']:
        breakdown = ', '.join(f'{k}={v}' for k, v in item['breakdown'].items())
        lines.append(f"| `{item['filename']}` | {item['total']} | {breakdown} |")

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    print('  Built dist: stats.json')
    print('  Built dist: stats.md')


def build():
    print("ShieldNova Build")
    print("=" * 50)

    os.makedirs(DIST_DIR, exist_ok=True)
    os.makedirs(FORMATS_DIR, exist_ok=True)

    allow_rules = load_allowlist()

    # --- Source files ---
    privacy_core = read_rules(os.path.join(SRC_DIR, 'privacy', 'core.txt'))
    privacy_cn = read_rules(os.path.join(SRC_DIR, 'privacy', 'cn.txt'))
    privacy_hktw = read_rules(os.path.join(SRC_DIR, 'privacy', 'hktw.txt'))
    ads_core = read_rules(os.path.join(SRC_DIR, 'advertising', 'core.txt'))
    ads_cn = read_rules(os.path.join(SRC_DIR, 'advertising', 'cn.txt'))
    ads_hktw = read_rules(os.path.join(SRC_DIR, 'advertising', 'hktw.txt'))
    sec_phishing = read_rules(os.path.join(SRC_DIR, 'security', 'phishing.txt'))
    sec_malware = read_rules(os.path.join(SRC_DIR, 'security', 'malware.txt'))
    sec_crypto = read_rules(os.path.join(SRC_DIR, 'security', 'cryptojacking.txt'))

    invalid_rules = []
    normalized_sources = {}
    for name, rules in {
        'privacy_core': privacy_core,
        'privacy_cn': privacy_cn,
        'privacy_hktw': privacy_hktw,
        'ads_core': ads_core,
        'ads_cn': ads_cn,
        'ads_hktw': ads_hktw,
        'sec_phishing': sec_phishing,
        'sec_malware': sec_malware,
        'sec_crypto': sec_crypto,
    }.items():
        normalized, invalid = normalize_rules(rules)
        normalized_sources[name] = normalized
        invalid_rules.extend(f'{name}: {rule}' for rule in invalid)

    if invalid_rules:
        print('\nWARNING: invalid rules skipped:')
        for item in invalid_rules:
            print(f'  - {item}')

    privacy_core = normalized_sources['privacy_core']
    privacy_cn = normalized_sources['privacy_cn']
    privacy_hktw = normalized_sources['privacy_hktw']
    ads_core = normalized_sources['ads_core']
    ads_cn = normalized_sources['ads_cn']
    ads_hktw = normalized_sources['ads_hktw']
    sec_phishing = normalized_sources['sec_phishing']
    sec_malware = normalized_sources['sec_malware']
    sec_crypto = normalized_sources['sec_crypto']

    # --- Individual module outputs ---
    bundles = []

    def finalize_rules(rules):
        filtered, removed = apply_allowlist(rules, allow_rules)
        compacted = compact_rule_block(filtered)
        return compacted, removed

    privacy_title = 'Privacy Protection'
    privacy_desc = 'Low-risk analytics, attribution, fingerprinting, and telemetry blocking.'
    privacy_rules, privacy_allow_removed = finalize_rules(privacy_core)
    privacy_breakdown = OrderedDict([('privacy', count_active_rules(privacy_core)), ('allowlist_removed', privacy_allow_removed)])
    write_dist('shieldnova-privacy.txt', privacy_title, privacy_desc, privacy_rules, privacy_breakdown)
    write_all_formats('shieldnova-privacy.txt', privacy_title, privacy_desc, privacy_rules, privacy_breakdown)
    bundles.append(bundle_stats('shieldnova-privacy.txt', privacy_title, privacy_desc, privacy_rules, privacy_breakdown))

    ads_title = 'Ads Protection'
    ads_desc = 'Low-risk ad networks, exchanges, and ad-serving domains.'
    ads_rules, ads_allow_removed = finalize_rules(ads_core)
    ads_breakdown = OrderedDict([('ads', count_active_rules(ads_core)), ('allowlist_removed', ads_allow_removed)])
    write_dist('shieldnova-ads.txt', ads_title, ads_desc, ads_rules, ads_breakdown)
    write_all_formats('shieldnova-ads.txt', ads_title, ads_desc, ads_rules, ads_breakdown)
    bundles.append(bundle_stats('shieldnova-ads.txt', ads_title, ads_desc, ads_rules, ads_breakdown))

    security_title = 'Security Protection'
    security_desc = 'Conservative phishing, malware, scam, and cryptojacking domains.'
    security_source = sec_phishing + sec_malware + sec_crypto
    security_rules, security_allow_removed = finalize_rules(security_source)
    security_breakdown = OrderedDict([
        ('phishing', count_active_rules(sec_phishing)),
        ('malware', count_active_rules(sec_malware)),
        ('cryptojacking', count_active_rules(sec_crypto)),
        ('allowlist_removed', security_allow_removed),
    ])
    write_dist('shieldnova-security.txt', security_title, security_desc, security_rules, security_breakdown)
    write_all_formats('shieldnova-security.txt', security_title, security_desc, security_rules, security_breakdown)
    bundles.append(bundle_stats('shieldnova-security.txt', security_title, security_desc, security_rules, security_breakdown))

    # --- Full combos ---
    global_source = privacy_core + ads_core + sec_phishing + sec_malware + sec_crypto
    global_rules, global_allow_removed = finalize_rules(global_source)
    full_title = 'Full (Global)'
    full_desc = 'Complete protection with a conservative compatibility-first profile.'
    global_breakdown = OrderedDict([
        ('privacy', count_active_rules(privacy_core)),
        ('ads', count_active_rules(ads_core)),
        ('security', count_active_rules(sec_phishing + sec_malware + sec_crypto)),
        ('allowlist_removed', global_allow_removed),
    ])
    write_dist('shieldnova-full.txt', full_title, full_desc, global_rules, global_breakdown)
    write_all_formats('shieldnova-full.txt', full_title, full_desc, global_rules, global_breakdown)
    bundles.append(bundle_stats('shieldnova-full.txt', full_title, full_desc, global_rules, global_breakdown))

    cn_source = global_source + privacy_cn + ads_cn
    cn_rules, cn_allow_removed = finalize_rules(cn_source)
    full_cn_title = 'Full (China Mainland)'
    full_cn_desc = 'Complete protection with additional China mainland trackers and ad domains.'
    cn_breakdown = OrderedDict([
        ('privacy_global', count_active_rules(privacy_core)),
        ('privacy_cn', count_active_rules(privacy_cn)),
        ('ads_global', count_active_rules(ads_core)),
        ('ads_cn', count_active_rules(ads_cn)),
        ('security', count_active_rules(sec_phishing + sec_malware + sec_crypto)),
        ('allowlist_removed', cn_allow_removed),
    ])
    write_dist('shieldnova-full-cn.txt', full_cn_title, full_cn_desc, cn_rules, cn_breakdown)
    write_all_formats('shieldnova-full-cn.txt', full_cn_title, full_cn_desc, cn_rules, cn_breakdown)
    bundles.append(bundle_stats('shieldnova-full-cn.txt', full_cn_title, full_cn_desc, cn_rules, cn_breakdown))

    hktw_source = global_source + privacy_hktw + ads_hktw
    hktw_rules, hktw_allow_removed = finalize_rules(hktw_source)
    full_hktw_title = 'Full (Hong Kong & Taiwan)'
    full_hktw_desc = 'Complete protection with additional Hong Kong and Taiwan domains.'
    hktw_breakdown = OrderedDict([
        ('privacy_global', count_active_rules(privacy_core)),
        ('privacy_hktw', count_active_rules(privacy_hktw)),
        ('ads_global', count_active_rules(ads_core)),
        ('ads_hktw', count_active_rules(ads_hktw)),
        ('security', count_active_rules(sec_phishing + sec_malware + sec_crypto)),
        ('allowlist_removed', hktw_allow_removed),
    ])
    write_dist('shieldnova-full-hktw.txt', full_hktw_title, full_hktw_desc, hktw_rules, hktw_breakdown)
    write_all_formats('shieldnova-full-hktw.txt', full_hktw_title, full_hktw_desc, hktw_rules, hktw_breakdown)
    bundles.append(bundle_stats('shieldnova-full-hktw.txt', full_hktw_title, full_hktw_desc, hktw_rules, hktw_breakdown))

    report = OrderedDict([
        ('profile', 'Conservative / Compatibility-First'),
        ('built', utc_now()),
        ('allowlist_entries', len(allow_rules)),
        ('invalid_rules_skipped', len(invalid_rules)),
        ('bundles', bundles),
    ])
    write_stats_report(report)

    print("\nDone.")


if __name__ == '__main__':
    build()
