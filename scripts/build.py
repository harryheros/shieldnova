#!/usr/bin/env python3
"""
ShieldNova Build Script
Merges source rule files (src/) into distributable combo files (dist/).
"""

import os
import glob
from datetime import datetime, timezone

HEADER_TEMPLATE = """! Title: ShieldNova - {title}
! Description: {description}
! Author: Harry (https://github.com/harryheros)
! Homepage: https://github.com/harryheros/shieldnova
! License: CC BY-NC-SA 4.0
! Built: {date}
! Total: {count}
"""

SRC_DIR = os.path.join(os.path.dirname(__file__), '..', 'src')
DIST_DIR = os.path.join(os.path.dirname(__file__), '..', 'dist')


def read_rules(filepath):
    """Read rules from a file, stripping file-level headers but keeping annotations."""
    rules = []
    if not os.path.exists(filepath):
        return rules
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            # Skip file-level metadata (Title, Author, etc.)
            if line.startswith('! Title:') or line.startswith('! Description:') or \
               line.startswith('! Author:') or line.startswith('! Homepage:') or \
               line.startswith('! License:') or line.startswith('! Updated:') or \
               line.startswith('! Built:') or line.startswith('! Total:') or \
               line.startswith('! STATUS:') or line.startswith('! NOTE:') or \
               line.startswith('! PURPOSE:'):
                continue
            rules.append(line)
    return rules


def count_active_rules(rules):
    """Count non-empty, non-comment lines."""
    return sum(1 for r in rules if r.strip() and not r.strip().startswith('!'))


def write_dist(filename, title, description, rules):
    """Write a distribution file with header and rules."""
    count = count_active_rules(rules)
    date = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    header = HEADER_TEMPLATE.format(
        title=title, description=description, date=date, count=count
    )
    filepath = os.path.join(DIST_DIR, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(header.strip() + '\n\n')
        f.write('\n'.join(rules) + '\n')
    print(f"  Built: {filename} ({count} rules)")


def build():
    print("ShieldNova Build")
    print("=" * 50)

    os.makedirs(DIST_DIR, exist_ok=True)

    # --- Module files ---
    privacy_core = read_rules(os.path.join(SRC_DIR, 'privacy', 'core.txt'))
    privacy_cn = read_rules(os.path.join(SRC_DIR, 'privacy', 'cn.txt'))
    privacy_hktw = read_rules(os.path.join(SRC_DIR, 'privacy', 'hktw.txt'))
    ads_core = read_rules(os.path.join(SRC_DIR, 'advertising', 'core.txt'))
    ads_cn = read_rules(os.path.join(SRC_DIR, 'advertising', 'cn.txt'))
    ads_hktw = read_rules(os.path.join(SRC_DIR, 'advertising', 'hktw.txt'))
    sec_phishing = read_rules(os.path.join(SRC_DIR, 'security', 'phishing.txt'))
    sec_malware = read_rules(os.path.join(SRC_DIR, 'security', 'malware.txt'))
    sec_crypto = read_rules(os.path.join(SRC_DIR, 'security', 'cryptojacking.txt'))

    # --- Individual module outputs ---
    write_dist('shieldnova-privacy.txt',
               'Privacy Protection',
               'Global analytics, attribution, fingerprinting, and telemetry blocking.',
               privacy_core)

    write_dist('shieldnova-ads.txt',
               'Ads Protection',
               'Global ad networks, ad exchanges, and ad-serving domains.',
               ads_core)

    write_dist('shieldnova-security.txt',
               'Security Protection',
               'Phishing, malware, scam, and cryptojacking domains.',
               sec_phishing + sec_malware + sec_crypto)

    # --- Full combos ---
    global_rules = privacy_core + ads_core + sec_phishing + sec_malware + sec_crypto
    write_dist('shieldnova-full.txt',
               'Full (Global)',
               'Complete protection: privacy + advertising + security. Global edition.',
               global_rules)

    cn_rules = global_rules + privacy_cn + ads_cn
    write_dist('shieldnova-full-cn.txt',
               'Full (China Mainland)',
               'Complete protection with China mainland trackers and ad providers.',
               cn_rules)

    hktw_rules = global_rules + privacy_hktw + ads_hktw
    write_dist('shieldnova-full-hktw.txt',
               'Full (Hong Kong & Taiwan)',
               'Complete protection with HK & Taiwan specific trackers and ads.',
               hktw_rules)

    # --- Services (copy as-is) ---
    services_dir = os.path.join(SRC_DIR, 'services')
    if os.path.exists(services_dir):
        for f in sorted(glob.glob(os.path.join(services_dir, '*.txt'))):
            name = os.path.basename(f)
            rules = read_rules(f)
            service_name = os.path.splitext(name)[0].replace('-', ' ').title()
            write_dist(f'services/{name}',
                       f'Services / {service_name}',
                       f'Domain set for {service_name} traffic routing.',
                       rules)

    print("\nDone.")


if __name__ == '__main__':
    build()
