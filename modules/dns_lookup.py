import dns.resolver


def lookup(domain):
    records = {}
    for kind in ('A', 'AAAA', 'MX', 'NS', 'TXT'):
        try: records[kind] = [str(r) for r in dns.resolver.resolve(domain, kind, lifetime=5)]
        except Exception: records[kind] = []
    return records
