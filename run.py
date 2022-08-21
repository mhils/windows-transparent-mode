"""A simple transparent proxy test script."""

import asyncio
import ipaddress
import socket

from pathlib import Path

exe = Path(__file__).parent / "target/debug/mitmproxy-windows-transparent-mode.exe"


async def main():

    lock = asyncio.Lock()

    async def query(addr) -> tuple[str, int, str, int]:
        """Asks the redirector for the original destination via stdin/stdout."""
        host, port = addr
        async with lock:
            redirector.stdin.write(f"{host}:{port}\n".encode())
            await redirector.stdin.drain()
            originaldst = await redirector.stdout.readline()
        src_host, src_port, dst_host, dst_port = originaldst.strip().split(b" ")
        src_host = src_host.decode()
        src_port = int(src_port)
        dst_host = dst_host.decode()
        dst_port = int(dst_port)
        print(f"{host}:{port} == {src_host}:{src_port} => {dst_host}:{dst_port}")
        return src_host, src_port, dst_host, dst_port

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        _, _, dst_host, dst_port = await query(addr)
        try:
            (r, w) = await asyncio.open_connection(dst_host, dst_port)
        except Exception:
            writer.close()
            return

        async def pipe(r, w):
            try:
                while True:
                    data = await r.read(16384)
                    # print(f"{data=}")
                    if not data:
                        w.write_eof()
                        break

                    w.write(data)
            except OSError:
                pass

        await asyncio.gather(pipe(reader, w), pipe(r, writer))
        w.close()
        writer.close()
        print("Connection handled.")

    port = 4424
    await asyncio.start_server(handle_client, "", port)

    loop = asyncio.get_running_loop()

    class EchoServerProtocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, meta_addr):
            sup = self

            async def forward():
                src_host, src_port, dst_host, dst_port = await query(meta_addr)

                src_addr = f"{src_host}:{src_port}"
                dst_addr = f"{dst_host}:{dst_port}"

                try:
                    ipaddress.IPv6Address(dst_host)
                except ValueError:
                    ipv6 = False
                else:
                    ipv6 = True

                s = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((dst_host, dst_port))

                print(f"Sending UDP: {src_addr} => {dst_addr} {data[:50]=}")
                s.send(data)

                while True:
                    try:
                        resp = await asyncio.wait_for(loop.sock_recv(s, 4096), 60)
                    except Exception:
                        s.close()
                    else:
                        print(f"Returning UDP: {dst_addr} => {src_addr} {resp[:50]=}")
                        sup.transport.sendto(resp, meta_addr)

            asyncio.create_task(forward())

    await loop.create_datagram_endpoint(
        lambda: EchoServerProtocol(),
        local_addr=('127.0.0.1', port)
    )


    redirector = await asyncio.create_subprocess_exec(
        "launcher.exe", exe, str(port),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )

    try:
        await asyncio.sleep(9999)
    except KeyboardInterrupt:
        pass

    redirector.stdin.close()
    await redirector.wait()


if __name__ == "__main__":
    asyncio.run(main())
