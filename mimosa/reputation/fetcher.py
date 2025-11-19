"""Descarga de listas de reputación de IPs."""
from typing import Iterable

import httpx


class ReputationFetcher:
    """Descarga listas desde URLs configuradas."""

    def __init__(self, urls: Iterable[str]):
        self.urls = list(urls)

    async def fetch(self) -> Iterable[str]:
        async with httpx.AsyncClient() as client:
            for url in self.urls:
                response = await client.get(url)
                response.raise_for_status()
                for line in response.text.splitlines():
                    yield line
