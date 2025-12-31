import argparse
import csv
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

try:
    # Import scapy last so the script can still show a helpful error if it's missing
    from scapy.all import (
        conf,
        get_if_addr,
        sr,
        srp,
        sr1,
        Ether,
        ARP,
        IP,
        ICMP,
    )
except Exception as e:
    print("Scapy is required. Install with: pip install scapy", file=sys.stderr)
    print(f"Import error: {e}", file=sys.stderr)
    sys.exit(1)


def detect_default_iface_and_network() -> Tuple[str, Optional[str], Optional[ipaddress.IPv4Network]]:
    iface = conf.iface
    ip = None
    try:
        ip = get_if_addr(iface)
        if not ip or ip == "0.0.0.0":
            raise Exception("no IP")
    except Exception:
        # Try to get a source IP from the routing table
        try:
            route = conf.route.route("0.0.0.0")
            # route returns (iface, gateway, addr)
            # depending on scapy version, positions can vary; try to pull sensible values
            if route and len(route) >= 3:
                detected_iface = route[0] or iface
                detected_ip = route[1] or None
                iface = detected_iface or iface
                ip = detected_ip or ip
        except Exception:
            pass
    if ip:
        try:
            net = ipaddress.ip_network(ip + "/24", strict=False)
        except Exception:
            net = None
    else:
        net = None
    return iface, ip, net


def prompt_for_network(detected_network: Optional[ipaddress.IPv4Network]) -> Optional[ipaddress.IPv4Network]:
    """
    Prompt the user to enter a target IP or network.
    If user presses Enter, return the detected_network.
    The prompt itself is the minimal string "># " per request.

    Accepts:
      - single IP: 192.168.1.5  (treated as /32)
      - network CIDR: 192.168.1.0/24
      - IPv4 only
    """
    # Show the detected network on its own line so the prompt itself stays exactly "># "
    if detected_network:
        try:
            print(f"Detected network: {detected_network}")
        except Exception:
            pass

    try:
        user = input("># ").strip()
    except (EOFError, KeyboardInterrupt):
        # If prompting is not possible or user cancelled, fall back to detected_network
        return detected_network

    if not user:
        return detected_network

    # Try parsing as network first
    try:
        net = ipaddress.ip_network(user, strict=False)
        return net
    except Exception:
        # Try as single IP
        try:
            ip = ipaddress.ip_address(user)
            # treat single IP as /32 network (works for ICMP and ARP pdst)
            return ipaddress.ip_network(str(ip) + "/32", strict=False)
        except Exception:
            print(f"Invalid IP or network entered: '{user}'", file=sys.stderr)
            return None


def arp_scan(network: ipaddress.IPv4Network, iface: Optional[str] = None, timeout: float = 2.0) -> List[Tuple[str, str]]:
    """
    ARP scan using scapy.srp. network is an IPv4Network object.
    Returns list of tuples: (ip, mac)
    """
    target = str(network)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=0)
    results = []
    for snd, rcv in ans:
        ip = getattr(rcv, "psrc", None)
        mac = getattr(rcv, "hwsrc", None)
        if ip:
            results.append((ip, mac or ""))
    # sort by IP numeric order
    results.sort(key=lambda x: tuple(int(p) for p in x[0].split(".")))
    return results


def icmp_ping_one(host: str, iface: Optional[str], timeout: float) -> Optional[str]:
    """
    Send a single ICMP echo (sr1) to host. Returns host if reply received, else None.
    Uses sr1 to get single reply; verbose=0 to suppress output.
    """
    try:
        pkt = IP(dst=host) / ICMP()
        resp = sr1(pkt, timeout=timeout, iface=iface, verbose=0)
        if resp is not None:
            return host
    except PermissionError:
        raise
    except Exception:
        # Ignore send errors per-host
        return None
    return None


def icmp_scan_concurrent(network: ipaddress.IPv4Network, iface: Optional[str], timeout: float = 1.0, parallelism: int = 100) -> List[str]:
    """
    Concurrent ICMP ping sweep using ThreadPoolExecutor.
    Returns sorted list of responsive IPs.
    """
    hosts = [str(h) for h in network.hosts()]
    if not hosts:
        return []
    alive: Set[str] = set()
    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        futures = {ex.submit(icmp_ping_one, host, iface, timeout): host for host in hosts}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                if res:
                    alive.add(res)
            except PermissionError:
                raise
            except Exception:
                # ignore per-host exceptions
                pass
    return sorted(alive, key=lambda ip: tuple(int(p) for p in ip.split(".")))


def reverse_dns_lookup(ip: str, timeout: float = 3.0) -> Optional[str]:
    """
    Attempt a reverse DNS lookup. Uses socket.gethostbyaddr with a short timeout.
    """
    try:
        # socket.gethostbyaddr does not take timeout param; we rely on global default timeout
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def merge_results(arp: List[Tuple[str, str]], icmp: List[str], do_reverse: bool, parallelism: int = 20) -> List[Dict]:
    """
    Merge ARP and ICMP results into a list of dicts:
    {
      "ip": "x.x.x.x",
      "mac": "aa:bb:cc:dd:ee:ff" or "",
      "seen_by": ["arp","icmp"],
      "hostname": "host.example.com" or ""
    }
    """
    data: Dict[str, Dict] = {}
    for ip, mac in arp:
        data.setdefault(ip, {"ip": ip, "mac": "", "seen_by": set(), "hostname": ""})
        data[ip]["mac"] = mac
        data[ip]["seen_by"].add("arp")
    for ip in icmp:
        data.setdefault(ip, {"ip": ip, "mac": "", "seen_by": set(), "hostname": ""})
        data[ip]["seen_by"].add("icmp")

    # reverse DNS optionally in parallel
    ips = list(data.keys())
    if do_reverse and ips:
        # set a socket default timeout so gethostbyaddr won't hang long
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3.0)
        with ThreadPoolExecutor(max_workers=parallelism) as ex:
            futures = {ex.submit(reverse_dns_lookup, ip): ip for ip in ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    hn = fut.result()
                    if hn:
                        data[ip]["hostname"] = hn
                except Exception:
                    pass
        # restore
        socket.setdefaulttimeout(old_timeout)

    # convert seen_by to list and sort final list by IP
    results = []
    for ip in sorted(data.keys(), key=lambda ip: tuple(int(p) for p in ip.split("."))):
        item = data[ip]
        results.append(
            {
                "ip": item["ip"],
                "mac": item["mac"],
                "seen_by": sorted(list(item["seen_by"])),
                "hostname": item["hostname"] or "",
            }
        )
    return results


def print_table(results: List[Dict]):
    if not results:
        print("No hosts found.")
        return
    max_ip = max(len(r["ip"]) for r in results)
    max_mac = max(len(r["mac"]) for r in results)
    max_host = max(len(r["hostname"]) for r in results)
    print(f"{'IP'.ljust(max_ip)}  {'MAC'.ljust(max_mac)}  {'HOSTNAME'.ljust(max_host)}  SEEN_BY")
    print("-" * (max_ip + 2 + max_mac + 2 + max_host + 2 + 10))
    for r in results:
        seen = ",".join(r["seen_by"])
        print(f"{r['ip'].ljust(max_ip)}  {r['mac'].ljust(max_mac)}  {r['hostname'].ljust(max_host)}  {seen}")


def write_json(path: str, results: List[Dict]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scanned_at": datetime.utcnow().isoformat() + "Z", "results": results}, f, indent=2)


def write_csv(path: str, results: List[Dict]):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "mac", "hostname", "seen_by"])
        for r in results:
            writer.writerow([r["ip"], r["mac"], r["hostname"], ";".join(r["seen_by"])])


def parse_args():
    p = argparse.ArgumentParser(prog="network_scan_full.py", description="All-in-one network scanner using Scapy")
    p.add_argument("-n", "--network", help="Target network in CIDR (e.g. 192.168.1.0/24) or single IP (e.g. 192.168.1.5). If omitted you'll be prompted.")
    p.add_argument("-i", "--iface", help="Interface to use (default: scapy default)")
    p.add_argument("-m", "--method", choices=("arp", "icmp", "both"), default="arp", help="Scan method: arp (default), icmp, or both")
    p.add_argument("-t", "--timeout", type=float, default=None, help="Timeout for requests (seconds). Default optimized per method")
    p.add_argument("-p", "--parallelism", type=int, default=100, help="Parallelism for ICMP and reverse DNS (default 100 for ICMP, 20 for DNS)")
    p.add_argument("-r", "--reverse", action="store_true", help="Perform reverse DNS lookups for discovered IPs")
    p.add_argument("-o", "--output", choices=("table", "json", "csv"), default="table", help="Output format (table,json,csv)")
    p.add_argument("-f", "--file", help="Write output to file (path). If omitted, prints to stdout")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet: suppress extra headers, print only results")
    return p.parse_args()


def main():
    if not hasattr(conf, "route"):
        print("Scapy route info not available. Is scapy installed correctly?", file=sys.stderr)
        sys.exit(1)

    args = parse_args()
    iface = args.iface or conf.iface
    method = args.method
    timeout = args.timeout
    parallelism = max(1, args.parallelism)
    do_reverse = args.reverse

    # Determine network (with interactive prompt if no --network provided)
    network: Optional[ipaddress.IPv4Network] = None
    if args.network:
        try:
            network = ipaddress.ip_network(args.network, strict=False)
        except Exception as e:
            # try single IP fallback
            try:
                ip = ipaddress.ip_address(args.network)
                network = ipaddress.ip_network(str(ip) + "/32", strict=False)
            except Exception:
                print(f"Invalid network or IP provided via --network: '{args.network}': {e}", file=sys.stderr)
                sys.exit(1)
    else:
        detected_iface, detected_ip, detected_net = detect_default_iface_and_network()
        iface = args.iface or detected_iface
        # Prompt user for network/IP (press Enter to accept detected)
        network = prompt_for_network(detected_net)
        if network is None:
            print("No valid network provided and auto-detection failed. Please provide --network.", file=sys.stderr)
            sys.exit(1)

    if not args.quiet:
        print(f"Scan start: {datetime.now().isoformat()}")
        print(f"Network: {network}  Interface: {iface}  Method: {method}")
        if do_reverse:
            print("Reverse DNS: enabled")
        print("")

    arp_results: List[Tuple[str, str]] = []
    icmp_results: List[str] = []

    try:
        if method in ("arp", "both"):
            if not args.quiet:
                print("Starting ARP scan...")
            t_out = timeout if timeout is not None else 2.0
            arp_results = arp_scan(network, iface=iface, timeout=t_out)
            if not args.quiet:
                print(f"ARP scan finished: {len(arp_results)} hosts (ARP)")

        if method in ("icmp", "both"):
            if not args.quiet:
                print("Starting ICMP scan (concurrent)...")
            t_out = timeout if timeout is not None else 1.0
            # Use provided parallelism
            icmp_results = icmp_scan_concurrent(network, iface=iface, timeout=t_out, parallelism=parallelism)
            if not args.quiet:
                print(f"ICMP scan finished: {len(icmp_results)} hosts (ICMP)")

    except PermissionError:
        print("Permission denied: run as root/administrator.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        sys.exit(1)

    merged = merge_results(arp_results, icmp_results, do_reverse, parallelism=min(20, parallelism))

    # Output
    if args.output == "table":
        # print table to stdout or file
        out_text = None
        # build printable text
        from io import StringIO
        buf = StringIO()
        # temporarily print to buf
        _stdout = sys.stdout
        try:
            sys.stdout = buf
            print_table(merged)
            out_text = buf.getvalue()
        finally:
            sys.stdout = _stdout
            buf.close()

        if args.file:
            with open(args.file, "w", encoding="utf-8") as f:
                f.write(out_text)
            if not args.quiet:
                print(f"Results written to {args.file}")
        else:
            print(out_text.rstrip("\n"))

    elif args.output == "json":
        if args.file:
            write_json(args.file, merged)
            if not args.quiet:
                print(f"JSON written to {args.file}")
        else:
            print(json.dumps({"scanned_at": datetime.utcnow().isoformat() + "Z", "results": merged}, indent=2))

    elif args.output == "csv":
        if args.file:
            write_csv(args.file, merged)
            if not args.quiet:
                print(f"CSV written to {args.file}")
        else:
            # print CSV to stdout
            writer = csv.writer(sys.stdout)
            writer.writerow(["ip", "mac", "hostname", "seen_by"])
            for r in merged:
                writer.writerow([r["ip"], r["mac"], r["hostname"], ";".join(r["seen_by"])])

    if not args.quiet:
        print(f"Scan end: {datetime.now().isoformat()}")

if __name__ == "__main__":
    main()