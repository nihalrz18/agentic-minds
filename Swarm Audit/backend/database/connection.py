import asyncpg
import os
from typing import Optional

_pool: Optional[asyncpg.Pool] = None


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
            ssl="require",            # Neon.tech requires SSL
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
