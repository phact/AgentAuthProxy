import asyncio
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from cancel_wait_redirect import addons

async def main():
    # Configure mitmproxy options. For instance:
    # - listen on 127.0.0.1:8080
    # - allow untrusted TLS (if needed), etc.
    opts = Options(
        listen_host='127.0.0.1',
        listen_port=8080,
        ssl_insecure=True,  # if you want to ignore server cert errors
    )

    # "DumpMaster" is a headless mode runner for mitmproxy
    m = DumpMaster(opts)
    # Add our custom addon(s)
    for addon in addons:
        m.addons.add(addon)

    try:
        # This starts the mitmproxy event loop
        await m.run()
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        await m.shutdown()


def app():
    asyncio.run(main())

if __name__ == "__main__":
    asyncio.run(main())
