"""Offline consumer checks, FIRST CVSS 3.1 base scoring and CSV evidence rules."""
import csv
import io
import ipaddress
import math
import re
from collections import defaultdict
from urllib.parse import urlsplit


def cvss(vector):
    if not isinstance(vector, str) or not vector.startswith('CVSS:3.1/'):
        raise ValueError('Use a CVSS:3.1 base vector. Other versions are not supported.')
    allowed = {'AV': 'NALP', 'AC': 'LH', 'PR': 'NLH', 'UI': 'NR', 'S': 'UC',
               'C': 'NLH', 'I': 'NLH', 'A': 'NLH'}
    metrics = {}
    for part in vector[9:].split('/'):
        pieces = part.split(':')
        if len(pieces) != 2:
            raise ValueError('Malformed CVSS metric.')
        key, value = pieces
        if key not in allowed or key in metrics or value not in list(allowed[key]):
            raise ValueError('Invalid, duplicate or non-base CVSS metric: ' + part)
        metrics[key] = value
    if set(metrics) != set(allowed):
        raise ValueError('All eight base metrics are required.')
    m = metrics
    impact_values = {'N': 0, 'L': .22, 'H': .56}
    iss = 1 - math.prod(1 - impact_values[m[k]] for k in ('C', 'I', 'A'))
    changed = m['S'] == 'C'
    impact = 7.52 * (iss - .029) - 3.25 * (iss - .02)**15 if changed else 6.42 * iss
    pr = {'N': .85, 'L': .68 if changed else .62, 'H': .5 if changed else .27}[m['PR']]
    exploitability = 8.22 * {'N': .85, 'A': .62, 'L': .55, 'P': .2}[m['AV']] * {'L': .77, 'H': .44}[m['AC']] * pr * {'N': .85, 'R': .62}[m['UI']]
    raw = min((1.08 if changed else 1) * (impact + exploitability), 10)
    integer = math.floor(raw * 100000 + .5)
    score = (integer / 100000 if integer % 10000 == 0 else (integer // 10000 + 1) / 10) if impact > 0 else 0.0
    severity = 'Critical' if score >= 9 else 'High' if score >= 7 else 'Medium' if score >= 4 else 'Low' if score > 0 else 'None'
    return {'vector': 'CVSS:3.1/' + '/'.join(k + ':' + m[k] for k in allowed),
            'score': score, 'severity': severity, 'version': '3.1 base',
            'note': 'Vulnerability severity, not exploit probability or proof your device is affected. CVSS 4.0, temporal and environmental scoring are not implemented.'}


def check_message(text):
    if not isinstance(text, str) or not text.strip() or len(text) > 20000:
        raise ValueError('Enter 1–20,000 characters of message text or a URL.')
    findings = []
    checks = [
        (r'\b(urgent|immediately|within 24 hours|account.{0,20}suspend)\b', 'Urgency or account pressure', 15),
        (r'\b(password|verification code|one.time code|seed phrase|private key|otp)\b', 'Sensitive credential or recovery-code language', 25),
        (r'\b(gift card|wire transfer|crypto|bitcoin|pay.{0,15}fee)\b', 'Payment method or upfront-fee language', 20),
        (r'\b(won|winner|lottery|guaranteed return|free money)\b', 'Prize or guaranteed-return claim', 20),
        (r'\b(anydesk|teamviewer|remote access)\b', 'Remote-access request; verify independently', 20),
    ]
    for pattern, reason, weight in checks:
        match = re.search(pattern, text, re.I)
        if match:
            findings.append({'reason': reason, 'evidence': match.group(0), 'weight': weight})
    urls = re.findall(r'https?://[^\s<>"\']+', text, re.I)
    if not urls and re.fullmatch(r'[^\s]+\.[^\s]+', text.strip()):
        urls = ['https://' + text.strip()]
    for url in urls[:30]:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname or ''
            _ = parsed.port
            if not host:
                raise ValueError()
            reasons = []
            if parsed.scheme == 'http': reasons.append(('Unencrypted HTTP link', 10))
            if parsed.username is not None: reasons.append(('User-info can disguise the destination host', 25))
            if 'xn--' in host or not host.isascii(): reasons.append(('Internationalized hostname: check for impersonation', 15))
            try:
                ipaddress.ip_address(host)
                reasons.append(('IP-address URL; verify who operates it', 15))
            except ValueError:
                pass
            if host in ('bit.ly', 'tinyurl.com', 't.co', 'is.gd'):
                reasons.append(('Shortened URL hides the final destination', 15))
            for reason, weight in reasons:
                findings.append({'reason': reason, 'evidence': url, 'weight': weight})
        except ValueError:
            findings.append({'reason': 'Malformed URL', 'evidence': url, 'weight': 10})
    score = min(100, sum(f['weight'] for f in findings))
    return {'score': score, 'verdict': 'High concern' if score >= 50 else 'Review carefully' if score else 'No listed warning signs found',
            'findings': findings, 'urls_checked': len(urls[:30]), 'mode': 'offline heuristics',
            'note': 'This is not a safety certification. Links were not opened, redirects and reputation were not checked. Verify through an independently opened official app or website. Never share passwords or recovery codes.'}


def analyze_csv(text):
    """Normalized Splunk/Cisco exports; no live device access or scanning."""
    if not isinstance(text, str) or not text.strip() or len(text) > 1_000_000:
        raise ValueError('Provide a CSV export up to 1 MB.')
    reader = csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
    required = {'timestamp', 'event_type', 'src_ip', 'host', 'user', 'outcome', 'dest_port', 'query'}
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError('Required CSV columns: ' + ', '.join(sorted(required)))
    rows = []
    failures, ports = defaultdict(list), defaultdict(list)
    findings = []
    for number, row in enumerate(reader, 2):
        if len(rows) >= 1000:
            raise ValueError('CSV limit: 1000 event records.')
        if None in row or any(v is None for v in row.values()):
            raise ValueError(f'CSV row {number}: unexpected column count.')
        row = {k: v.strip() for k, v in row.items()}
        kind = row['event_type'].lower()
        if kind not in ('auth', 'network', 'dns'):
            raise ValueError(f'CSV row {number}: event_type must be auth, network or dns.')
        if row['src_ip']:
            try: ipaddress.ip_address(row['src_ip'])
            except ValueError: raise ValueError(f'CSV row {number}: invalid src_ip.') from None
        rows.append({'source_row': number, 'record': row})
        identity = (row['src_ip'], row['host'], row['user'])
        if kind == 'auth':
            if not all(row[k] for k in ('src_ip', 'host', 'user')):
                raise ValueError(f'CSV row {number}: auth requires src_ip, host and user.')
            if row['outcome'].lower() not in ('success', 'failure'):
                raise ValueError(f'CSV row {number}: auth outcome must be success or failure.')
            if row['outcome'].lower() == 'failure': failures[identity].append(number)
        if kind == 'network':
            if not row['src_ip'] or not row['dest_port'].isdigit() or not 1 <= int(row['dest_port']) <= 65535:
                raise ValueError(f'CSV row {number}: network requires src_ip and a valid dest_port.')
            ports[(row['src_ip'], row['host'])].append((int(row['dest_port']), number))
        if kind == 'dns' and not row['query']:
            raise ValueError(f'CSV row {number}: DNS requires query.')
        if kind == 'dns' and len(row['query'].split('.')[0]) >= 50:
            findings.append({'rule': 'Long DNS label', 'severity': 'medium', 'source_rows': [number],
                             'reason': 'First DNS label has at least 50 characters; investigate baseline before inferring tunneling.'})
    for identity, refs in failures.items():
        if len(refs) >= 5:
            successes = [r['source_row'] for r in rows if r['record']['event_type'].lower() == 'auth' and
                         (r['record']['src_ip'], r['record']['host'], r['record']['user']) == identity and
                         r['record']['outcome'].lower() == 'success' and r['source_row'] > refs[4]]
            findings.append({'rule': 'Repeated authentication failures' + (' with later success in file' if successes else ''),
                             'severity': 'high' if successes else 'medium', 'source_rows': refs + successes,
                             'reason': f'{len(refs)} failures for source/host/user {identity}. Sequence follows file order, not timestamp order; no time-window or brute-force confirmation.'})
    for identity, values in ports.items():
        count = len({port for port, _ in values})
        if count >= 10:
            findings.append({'rule': 'Many destination ports', 'severity': 'medium',
                             'source_rows': [n for _, n in values],
                             'reason': f'{count} distinct destination ports for {identity} across this file; possible scan or legitimate administration.'})
    by_row = {r['source_row']: r['record'] for r in rows}
    for f in findings:
        f['evidence'] = [{'source_row': n, 'record': by_row[n]} for n in f['source_rows']]
    return {'events': len(rows), 'findings': findings, 'mode': 'offline rules',
            'note': 'Normalized CSV only: not a live Splunk/Cisco connection, packet capture or continuous monitor. File row 1 is the header.'}
