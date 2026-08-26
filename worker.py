import asyncio

import httpx
import mistralai.workflows as workflows
from mistralai.workflows import workflow


@workflow.define(name="http-prober")
class HttpProberWorkflow:
    @workflow.entrypoint
    async def run(self, params: dict) -> dict:
        url = params["url"]
        headers = params.get("headers", {})
        method = params.get("method", "GET")
        body = params.get("body", None)

        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            response = await client.request(method, url, headers=headers, content=body)

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text,
        }


async def main() -> None:
    await workflows.run_worker([HttpProberWorkflow])


if __name__ == "__main__":
    asyncio.run(main())
