import asyncio


def retire_session(owner, session):
    """Detach immediately; let requests already using the connector drain."""
    if session is None or session.closed:
        return
    tasks = getattr(owner, "_retired_session_tasks", None)
    if tasks is None:
        tasks = owner._retired_session_tasks = set()

    async def drain():
        try:
            # Allow borrowers between session lookup and request startup to run.
            await asyncio.sleep(30)
            while not session.closed:
                connector = session.connector
                if connector is None or not (
                    getattr(connector, "_acquired", ())
                    or getattr(connector, "_waiters", ())
                ):
                    break
                await asyncio.sleep(1)
        finally:
            await session.close()

    task = asyncio.create_task(drain())
    tasks.add(task)
    task.add_done_callback(tasks.discard)
