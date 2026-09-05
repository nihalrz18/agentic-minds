import asyncpg
import os
from typing import Optional
from urllib.parse import urlparse, parse_qs

_pool: Optional[asyncpg.Pool] = None


def _ssl_mode(database_url: str) -> str:
    """
    Resolve the SSL mode from the DSN itself.
    Neon.tech DSNs carry ?sslmode=require and stay on SSL; a plain local
    Postgres (docker-compose) has no SSL listener, so honour its sslmode=disable
    instead of forcing a connection it cannot complete.
    """
    sslmode = parse_qs(urlparse(database_url).query).get("sslmode", [None])[0]
    if sslmode:
        return sslmode
    host = (urlparse(database_url).hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "postgres", "db", "::1"}:
        return "disable"
    return "require"


async def get_pool() -> asyncpg.Pool:
    """
    Returns singleton asyncpg connection pool.
    DATABASE_URL comes from Neon.tech dashboard.
    Format: postgresql://user:password@host/dbname?sslmode=require
    Neon requires SSL — always set ssl='require' in connect().
    """
    global _pool
    if _pool is None:
        database_url = os.getenv("DATABASE_URL")
        if not database_url:
            raise ValueError("DATABASE_URL environment variable is not set")
        _pool = await asyncpg.create_pool(
            dsn=database_url,
            ssl=_ssl_mode(database_url),   # Neon.tech requires SSL; local dev may not
            min_size=1,
            max_size=5,               # Free tier connection limit
            command_timeout=60,
            server_settings={
                "application_name": "swarmaudit"
            }
        )
    return _pool


async def close_pool():
    global _pool
    if _pool:
        await _pool.close()
        _pool = None


async def execute(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.execute(query, *args)


async def fetch(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetch(query, *args)


async def fetchrow(query: str, *args):
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchrow(query, *args)
