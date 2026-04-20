#!/usr/bin/env python3
"""
Compare IP bucketing from master's Interface.bucket_based_on_ipaddress()
(plain /16,/48 prefix) against this branch's asmap-aware variant.

Run from the repository root:
    python3 compare_asmap_bucketing.py
"""
import os
import sys
from collections import defaultdict
from ipaddress import IPv4Network, IPv6Network, ip_address

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from electrum.asmap import ASMap  # noqa: E402

BUCKET_PREFIX_OF_ASN = "AS"

IPS = [
    "136.107.155.173",
    "136.107.225.110",
    "136.107.72.87",
    "136.110.114.84",
    "136.110.67.212",
    "34.101.170.221",
    "34.101.39.54",
    "34.116.254.239",
    "34.118.1.54",
    "34.121.73.82",
    "34.128.68.204",
    "34.128.81.215",
    "34.13.139.195",
    "34.133.127.109",
    "34.138.250.15",
    "34.141.75.29",
    "34.153.192.8",
    "34.159.103.181",
    "34.159.228.34",
    "34.171.34.8",
    "34.172.232.121",
    "34.173.233.138",
    "34.174.156.170",
    "34.174.158.243",
    "34.174.167.84",
    "34.174.217.104",
    "34.174.46.235",
    "34.175.239.109",
    "34.179.190.163",
    "34.18.66.115",
    "34.18.69.244",
    "34.19.148.24",
    "34.19.234.1",
    "34.21.56.132",
    "34.32.12.235",
    "34.32.226.149",
    "34.32.36.131",
    "34.32.48.252",
    "34.32.48.56",
    "34.32.51.209",
    "34.38.117.239",
    "34.39.9.100",
    "34.40.149.244",
    "34.47.18.226",
    "34.47.183.146",
    "34.47.55.201",
    "34.48.222.31",
    "34.50.93.134",
    "34.64.177.133",
    "34.7.95.198",
    "34.77.81.160",
    "34.84.171.172",
    "34.87.220.132",
    "34.87.227.41",
    "34.88.214.4",
    "34.90.51.226",
    "34.93.250.242",
    "34.93.251.171",
    "34.94.210.245",
    "34.96.220.189",
    "35.189.13.187",
    "35.190.233.80",
    "35.194.147.142",
    "35.197.22.214",
    "35.198.35.60",
    "35.200.169.149",
    "35.200.205.108",
    "35.203.107.152",
    "35.204.93.87",
    "35.205.207.213",
    "35.205.222.207",
    "35.221.221.16",
    "35.225.75.62",
    "35.233.45.83",
    "35.238.228.147",
    "35.244.75.164",
    "35.244.75.18",
    "35.244.89.238",
    "35.246.146.80",
]


def _prefix_bucket(ip_addr) -> str:
    if ip_addr.version == 4:
        return str(IPv4Network(ip_addr).supernet(prefixlen_diff=32 - 16))
    if ip_addr.version == 6:
        return str(IPv6Network(ip_addr).supernet(prefixlen_diff=128 - 48))
    return ""


def bucket_master(ip_str: str) -> str:
    """Mirror of master's Interface.bucket_based_on_ipaddress() for non-onion IPs."""
    ip_addr = ip_address(ip_str)
    if ip_addr.is_loopback:
        return ""
    return _prefix_bucket(ip_addr)


def bucket_with_asmap(ip_str: str, asmap: ASMap) -> str:
    """Mirror of this branch's asmap-aware Interface.bucket_based_on_ipaddress()."""
    ip_addr = ip_address(ip_str)
    if ip_addr.is_loopback:
        return ""
    if asmap is not None and ip_addr.is_global:
        asn = asmap.lookup_asn(ip_addr)
        if asn is not None:
            return f"{BUCKET_PREFIX_OF_ASN}{asn}"
    return _prefix_bucket(ip_addr)


def _print_buckets(title: str, buckets: dict) -> None:
    print(f"=== {title} ===")
    print(f"distinct buckets: {len(buckets)}")
    for bucket, ips in sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        print(f"  {bucket:<20} [{len(ips):>2}]  {', '.join(ips)}")
    print()


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    asmap_path = os.path.join(here, "electrum", "asmap", "asmap.dat")
    asmap = ASMap.from_file(asmap_path)
    print(f"loaded asmap: {asmap_path}")
    print(f"  size   = {asmap.size} bytes")
    print(f"  sha256 = {asmap.sha256}")
    print(f"  ips    = {len(IPS)}")
    print()

    master_buckets = defaultdict(list)
    asmap_buckets = defaultdict(list)
    for ip in IPS:
        master_buckets[bucket_master(ip)].append(ip)
        asmap_buckets[bucket_with_asmap(ip, asmap)].append(ip)

    _print_buckets("master branch (/16 for IPv4, /48 for IPv6)", master_buckets)
    _print_buckets("asmap_claude branch (ASN via asmap, /16,/48 fallback)", asmap_buckets)

    master_max = max(len(v) for v in master_buckets.values())
    asmap_max = max(len(v) for v in asmap_buckets.values())
    print("=== summary ===")
    print(f"master  : {len(master_buckets):>3} buckets, largest bucket = {master_max} IPs")
    print(f"asmap   : {len(asmap_buckets):>3} buckets, largest bucket = {asmap_max} IPs")


if __name__ == "__main__":
    main()
