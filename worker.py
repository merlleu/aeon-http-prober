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


@workflow.define(name="http-prober")
class HttpProberWorkflow:
    @workflow.entrypoint
    async def run(self, params: dict) -> dict:
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
