import socket
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# GKE node VPC subnets — auto-detected, fallback to GCP auto-subnet defaults.
# GCP assigns one /20 per region; eem = europe-west4 → 10.164.0.0/20.
# Also try neighbours and common custom ranges.
FALLBACK_NETWORKS = [
    "10.164.0.0/20",   # GCP auto-subnet: europe-west4 (eem)
    "10.132.0.0/20",   # GCP auto-subnet: europe-west1
    "10.128.0.0/20",   # GCP auto-subnet: us-central1
    "10.48.0.0/16",    # pod secondary range (sibling pods / daemonsets on node)
    "10.0.0.0/20",
    "10.1.0.0/16",
]

# GKE-specific ports to probe on each candidate node
KUBELET_PORTS = [10250, 10255, 10248]  # rw (authed), ro (anon), healthz
GKE_PORTS = [
    10250,  # kubelet API (authenticated)
    10255,  # kubelet read-only — anonymous, disabled by default in GKE 1.16+ but often still open
    10248,  # kubelet healthz
    10249,  # kube-proxy metrics
    10256,  # kube-proxy healthz
    4194,   # cAdvisor (removed from kubelet in 1.16 but still deployed standalone)
    9100,   # node-exporter (prometheus)
    2381,   # etcd metrics (control plane nodes only)
    6443,   # kube-apiserver
]
NODEPORT_RANGE = range(30000, 32769)
TIMEOUT = 1
WORKERS = 512


def detect_network():
    """
    GKE VPC-native: pods get a secondary range (e.g. 10.48.x.x/24 per node),
    nodes live in a separate primary VPC subnet (e.g. 10.128.0.x/24).
    The link-local gateway (169.254.x.x) is a virtual ARP-proxy — not the
    real node IP.  We discover the pod's own IP via a connected UDP socket,
    then guess the node subnet by trying common GKE primary ranges (/20 slices
    of 10.128.0.0/9, which is GCP's default auto-subnet region).
    """
    try:
        # pod's own outbound IP — reveals the secondary pod CIDR
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        pod_ip = s.getsockname()[0]
        s.close()
        print(f"[+] pod IP: {pod_ip}")

        # parse routing table for the default gateway (link-local in GKE)
        import struct
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 8 or parts[1] != "00000000":
                    continue
                gw_ip = socket.inet_ntoa(struct.pack("<I", int(parts[2], 16)))
                print(f"[+] default gw: {gw_ip}")
                break
    except Exception as e:
        print(f"[-] network detection failed: {e}")

    # Return None — caller will iterate over FALLBACK_NETWORKS which cover
    # GKE's typical node primary ranges (10.128.0.0/20 etc.)
    return None


def probe(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def find_node(network):
    hosts = [str(h) for h in ipaddress.ip_network(network).hosts()]
    for port in KUBELET_PORTS:
        executor = ThreadPoolExecutor(max_workers=WORKERS)
        futures = {executor.submit(probe, h, port): h for h in hosts}
        result = None
        for f in as_completed(futures):
            if f.result():
                result = futures[f]
                break
        executor.shutdown(wait=False, cancel_futures=True)
        if result:
            return result
    return None


def scan_ports(ip, ports):
    found = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(probe, ip, p): p for p in ports}
        for f in as_completed(futures):
            if f.result():
                found.append(futures[f])
    return sorted(found)


# GKE-specific vuln checks per open port
GKE_CHECKS = {
    # kubelet read-only: anonymous access to pod list
    10255: [
        ("/pods",    "kubelet anon pod list"),
        ("/metrics", "kubelet anon metrics"),
        ("/stats/summary", "kubelet anon stats"),
    ],
    # kubelet rw: anonymous exec would be critical, healthz just informational
    10250: [
        ("/healthz",      "kubelet healthz"),
        ("/pods",         "kubelet rw pod list (authed?)"),
        ("/metrics",      "kubelet rw metrics"),
    ],
    10248: [("/healthz", "kubelet healthz (local)")],
    10249: [("/metrics", "kube-proxy metrics")],
    10256: [("/healthz", "kube-proxy healthz")],
    4194:  [("/metrics", "cAdvisor metrics"), ("/api/v1.3/subcontainers/", "cAdvisor subcontainers")],
    9100:  [("/metrics", "node-exporter metrics")],
    2381:  [("/metrics", "etcd metrics"), ("/health", "etcd health")],
    6443:  [("/version", "kube-apiserver version (unauthed?)"), ("/api/v1/namespaces", "kube-apiserver namespaces")],
}

MISTRAL_CHECKS = [
    "/v1/internal/connectors/mistral",
    "/v1/internal/",
]


def http_get(ip, port, path, https=False):
    scheme = "https" if https else "http"
    url = f"{scheme}://{ip}:{port}{path}"
    try:
        ctx = None
        if https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = r.read(256).decode(errors="replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return None, ""


def check_gke_vulns(ip, open_ports):
    findings = []
    for port in open_ports:
        https = port == 6443
        paths = GKE_CHECKS.get(port, [])
        for path, label in paths:
            status, body = http_get(ip, port, path, https=https)
            if status is not None:
                findings.append((ip, port, path, status, label, body[:120]))
        # also check Mistral-specific paths on every open port
        for path in MISTRAL_CHECKS:
            status, body = http_get(ip, port, path)
            if status == 200:
                findings.append((ip, port, path, status, "mistral internal", body[:120]))
    return findings


# ── main ──────────────────────────────────────────────────────────────────────

network = detect_network()
if not network:
    networks_to_try = FALLBACK_NETWORKS
else:
    networks_to_try = [network] + FALLBACK_NETWORKS

node_ip = None
for net in networks_to_try:
    print(f"[*] scanning {net} for kubelet ...")
    node_ip = find_node(net)
    if node_ip:
        break

if not node_ip:
    print("[-] no responding node found")
    raise SystemExit(1)

print(f"[+] node_ip: {node_ip}")

print("[*] scanning GKE ports ...")
open_ports = scan_ports(node_ip, GKE_PORTS)
print(f"[+] open ports: {open_ports}")

print("[*] scanning nodeport range ...")
open_nodeports = scan_ports(node_ip, NODEPORT_RANGE)
print(f"[+] open nodeports: {open_nodeports}")

all_open = sorted(set(open_ports + open_nodeports))
print("\n[*] probing GKE endpoints ...")
findings = check_gke_vulns(node_ip, all_open)

if findings:
    print("\n=== FINDINGS ===")
    for ip, port, path, status, label, body in findings:
        print(f"  {status}  {ip}:{port}{path}  [{label}]")
        if body:
            print(f"       {body!r}")
else:
    print("[-] no exposed endpoints found")
