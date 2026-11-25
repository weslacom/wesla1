import asyncio
import json
import os

import psycopg


class PostgresEventHub:
    """One LISTEN connection per app process, fan-out to all local SSE clients."""

    def __init__(self):
        self._subscribers = set()
        self._task = None
        self._lock = asyncio.Lock()

    async def subscribe(self):
        queue = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscribers.add(queue)
            if self._task is None or self._task.done():
                self._task = asyncio.create_task(self._listen())
        return queue

    async def unsubscribe(self, queue):
        async with self._lock:
            self._subscribers.discard(queue)
            if not self._subscribers and self._task is not None:
                self._task.cancel()
                self._task = None

    def _publish(self, payload):
        for queue in tuple(self._subscribers):
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                pass

    async def _listen(self):
        dsn = os.getenv("DATABASE_URL", "")
        dsn = dsn.replace("postgresql+psycopg://", "postgresql://", 1)
        if dsn.startswith("postgres://"):
            dsn = dsn.replace("postgres://", "postgresql://", 1)
        if not dsn or dsn.startswith("sqlite:"):
            return
        delay = 1
        while True:
            async with self._lock:
                if not self._subscribers:
                    return
            try:
                async with await psycopg.AsyncConnection.connect(dsn, autocommit=True, connect_timeout=8) as conn:
                    await conn.execute("LISTEN wesla_changes")
                    delay = 1
                    while True:
                        async with self._lock:
                            if not self._subscribers:
                                return
                        async for notification in conn.notifies(timeout=15, stop_after=1):
                            self._publish(notification.payload)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._publish(json.dumps({"status": "reconnecting"}))
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)


event_hub = PostgresEventHub()
