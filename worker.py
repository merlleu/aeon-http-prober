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


@activity(start_to_close_timeout=datetime.timedelta(seconds=30))
async def probe_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """TCP-connect probe a single ip:port — the atomic one-port unit.

    Granular counterpart to port_scan: instead of fanning out across a CIDR
    inside one activity, the workflow calls probe_port once per (ip, port)
    and controls concurrency itself.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return {"ip": ip, "port": port, "open": False}
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return {"ip": ip, "port": port, "open": True}


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
                params.get("scan_prefix", 24),
                params.get("workers", 512),
                params.get("concurrency", 32),
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
                             nodeport_range: list[int], scan_prefix: int,
                             workers: int, concurrency: int,
                             timeout: float, vuln_path: str) -> dict:
        """Locate a live node, scan its NodePort range, then probe each open
        NodePort for a known vulnerable endpoint.

        Each phase fans out granular activities, throttled by `concurrency`:
          1. find_node  — port_scan(subnet, kubelet_port) per subnet×port,
                          short-circuiting on the first open host.
          2. nodeports  — probe_port(ip, port) once per port in the range.
          3. vuln check — http_check(url) per open port.
        """
        import ipaddress

        net = ipaddress.IPv4Network(cidr, strict=False)
        subnets = [str(sub) for sub in net.subnets(new_prefix=scan_prefix)]
        sem = asyncio.Semaphore(concurrency)

        # 1. Find a live node via kubelet ports.
        async def scan_subnet(subnet: str, port: int) -> str | None:
            async with sem:
                res = await port_scan(subnet, port, workers, timeout)
            open_hosts = res.get("open", [])
            return open_hosts[0] if open_hosts else None

        node_ip: str | None = None
        for port in kubelet_ports:
            if node_ip:
                break
            tasks = [asyncio.ensure_future(scan_subnet(sub, port)) for sub in subnets]
            try:
                for fut in asyncio.as_completed(tasks):
                    hit = await fut
                    if hit:
                        node_ip = hit
                        break
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()

        if not node_ip:
            return {"cidr": cidr, "node_ip": None, "open_ports": [], "vulnerable": []}

        # 2. Scan the NodePort range — one probe_port activity per port.
        port_start, port_end = nodeport_range

        async def probe_one(port: int) -> int | None:
            async with sem:
                res = await probe_port(node_ip, port, timeout)
            return port if res["open"] else None

        tasks = [probe_one(p) for p in range(port_start, port_end + 1)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports: list[int] = []
        for r in results:
            if isinstance(r, Exception):
                continue
            if r:
                open_ports.append(r)
        open_ports.sort()

        # 3. Probe each open NodePort for the vulnerable endpoint.
        async def check_port(port: int) -> dict | None:
            url = f"http://{node_ip}:{port}{vuln_path}"
            async with sem:
                res = await http_check(url, timeout, 200)
            return {"port": port, "status": res["status"]} if res["vulnerable"] else None

        tasks = [check_port(p) for p in open_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        vulnerable: list[dict] = []
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
