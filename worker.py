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


@activity(start_to_close_timeout=datetime.timedelta(seconds=120))
async def scan_subnet(cidr: str, port: int, workers: int = 200, timeout: float = 1.0) -> dict:
    """Scan a single small CIDR (e.g. /24) for an open TCP port.

    One activity == one process with its own modest socket pool, so the
    ephemeral-port/fd exhaustion that plagues a single giant ThreadPoolExecutor
    is avoided. The workflow fans many of these out in parallel via
    execute_activities_in_parallel.
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


@activity(start_to_close_timeout=datetime.timedelta(seconds=60))
async def build_chunks(cidr: str, chunk_prefix: int = 24) -> list[str]:
    """Split a CIDR into smaller subnets of size /chunk_prefix."""
    import ipaddress
    net = ipaddress.IPv4Network(cidr, strict=False)
    return [str(sub) for sub in net.subnets(new_prefix=chunk_prefix)]


@workflow.define(name="http-prober", execution_timeout=datetime.timedelta(hours=6))
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
                params.get("chunk_prefix", 24),
                params.get("workers", 200),
                params.get("timeout", 1.0),
                params.get("max_concurrent", 64),
            )

        return await http_request(
            params["url"],
            params.get("method", "GET"),
            params.get("headers", {}),
            params.get("body"),
        )

    async def _scan(
        self,
        cidr: str,
        port: int,
        chunk_prefix: int,
        workers: int,
        timeout: float,
        max_concurrent: int,
    ) -> dict:
        chunks = await build_chunks(cidr, chunk_prefix)
        results = await workflows.execute_activities_in_parallel(
            scan_subnet,
            items=[{"cidr": c, "port": port, "workers": workers, "timeout": timeout}
                   for c in chunks],
            max_concurrent_scheduled_tasks=max_concurrent,
            max_concurrent_executions_per_worker=max_concurrent,
        )
        open_hosts: list[str] = []
        scanned = 0
        for r in results or []:
            scanned += r.get("scanned", 0)
            open_hosts.extend(r.get("open", []))
        open_hosts.sort(key=lambda x: tuple(int(p) for p in x.split(".")))
        return {"cidr": cidr, "port": port, "scanned": scanned,
                "chunks": len(chunks), "open": open_hosts}


async def main() -> None:
    await workflows.run_worker([HttpProberWorkflow])


if __name__ == "__main__":
    asyncio.run(main())
