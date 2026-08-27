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
async def dns_resolve(host: str, family: str | None = None) -> dict:
    """Raw DNS resolution from inside the worker pod.

    family: None (all) | "ipv4" | "ipv6"
    Returns every address the pod's resolver returns for the host, which
    reveals the real ClusterIP/PodIP the pod would connect to.
    """
    import socket

    family_map = {
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }
    fam = family_map.get(family)
    try:
        infos = socket.getaddrinfo(host, None, fam or 0, socket.SOCK_STREAM)
        addrs = sorted({info[4][0] for info in infos})
    except socket.gaierror as e:
        return {"host": host, "error": str(e)}
    return {"host": host, "addresses": addrs}


@workflow.define(name="http-prober")
class HttpProberWorkflow:
    @workflow.entrypoint
    async def run(self, params: dict) -> dict:
        action = params.get("action", "http")

        if action == "dns":
            return await dns_resolve(
                params["host"],
                params.get("family"),
            )

        return await http_request(
            params["url"],
            params.get("method", "GET"),
            params.get("headers", {}),
            params.get("body"),
        )


async def main() -> None:
    await workflows.run_worker([HttpProberWorkflow])


if __name__ == "__main__":
    asyncio.run(main())
