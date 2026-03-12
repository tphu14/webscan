"""
retry.py - Exponential backoff retry decorator cho async HTTP requests.
"""
import asyncio
import random
import functools
from rich.console import Console

console = Console()


def async_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exceptions: tuple = (Exception,),
):
    """
    Decorator: retry async function với exponential backoff + jitter.

    Công thức delay: min(base * 2^attempt, max_delay) + random jitter
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt < max_attempts - 1:
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        jitter = random.uniform(0, delay * 0.2)
                        total = delay + jitter
                        console.print(
                            f"  [dim]Retry {attempt+1}/{max_attempts-1} "
                            f"after {total:.1f}s ({type(e).__name__})[/dim]"
                        )
                        await asyncio.sleep(total)
            raise last_exc
        return wrapper
    return decorator