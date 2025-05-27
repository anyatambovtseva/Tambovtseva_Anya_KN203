import asyncio

from ui import console

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(console.main())