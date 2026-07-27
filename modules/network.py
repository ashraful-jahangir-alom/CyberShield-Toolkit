def arp_scan(network):
    try:
        from scapy.all import ARP, Ether, srp
        answered, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=network), timeout=2, verbose=False)
        return [{'ip': r.psrc, 'mac': r.hwsrc, 'hostname': '', 'vendor': 'Unknown', 'os': 'Not assessed'} for _, r in answered]
    except Exception as exc:
        raise RuntimeError(f'ARP scan unavailable: {exc}')
