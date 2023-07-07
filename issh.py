#!/usr/bin/env python3
# coding=utf-8
# date 2022-09-04 04:14:14
# author calllivecn <c-all@qq.com>


import io
import os
import sys
import tty
import pty
import enum
import fcntl
import signal
import struct
import socket
import termios
import asyncio
import logging
import argparse
import threading
import multiprocessing as mprocess

from logging.handlers import TimedRotatingFileHandler

from asyncio import (
    streams,
    StreamReader,
    StreamWriter,
    StreamReaderProtocol,
)

from typing import (
    Union,
    # Self,
    Optional,
    BinaryIO,
    Tuple,
    TypeVar,
)

Self = TypeVar("Self")

SHELL="bash"

BUFSIZE = 1<<12 # 4K


def getlogger(level=logging.INFO):
    fmt = logging.Formatter("%(asctime)s %(filename)s:%(funcName)s:%(lineno)d %(levelname)s %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")

    # stream = logging.StreamHandler(sys.stdout)
    # stream.setFormatter(fmt)

    # fp = logging.FileHandler("rshell.logs")
    prog, _ = os.path.splitext(os.path.basename(sys.argv[0]))
    fp = TimedRotatingFileHandler(f"{prog}.logs", when="D", interval=1, backupCount=7)
    fp.setFormatter(fmt)

    logger = logging.getLogger(f"{prog}")
    logger.setLevel(level)
    # logger.addHandler(stream)
    logger.addHandler(fp)
    return logger


logger = getlogger()



TermSize = struct.Struct("HH")

def get_pty_size(fd) -> bytes:
    size = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"0000") # 占位符
    h, w = TermSize.unpack(size)
    return h, w


def set_pty_size(fd, columns, rows):
# def set_pty_size(fd, columns, rows):
    # size = struct.pack("HH", columns, rows)
    # 这个返回还不知道是什么
    return fcntl.ioctl(fd, termios.TIOCSWINSZ, TermSize.pack(columns, rows))


# 窗口大小调整, 这样是调控制端的。 (这是同步方法)
def signal_SIGWINCH_handle(sock: socket.SocketType, fd):
    """
    usage: lambda sigNum, frame: signal_SIGWINCH_handle(sock, sigNum, frame)
    """
    columns, rows = get_pty_size(fd)
    # logging 在异步的信号量模式下不安全。在 signal handle 里不要用 logging
    # logger.debug(f"窗口大小改变: {size}")
    # logger.debug("sigwinch 向对端发送新窗口大小")
    # set_pty_size(STDOUT, *size)

    h = Packet()
    payload = h.tobuf(PacketType.TTY_RESIZE, TermSize.pack(columns, rows))
    sock.send(payload)

# 窗口大小调整, 这样是调控制端的。 (试试协程, 不行。 TypeError: coroutines cannot be used with add_signal_handler())
async def signal_SIGWINCH_asyncio(sock: "RecvSend", fd):
    columns, rows = get_pty_size(fd)
    await sock.write(PacketType.TTY_RESIZE, TermSize.pack(columns, rows))


class PacketError(Exception):
    pass


class PacketType(enum.IntEnum):
    """
    一字节，数据包类型。
    """
    ZERO = 0 # 保留
    EXIT = enum.auto()
    TTY_RESIZE = enum.auto()
    TRANER = enum.auto()


class Packet:
    """
    1B: protocol version
    1B: package type
    2B: payload lenght
    data: payload
    """

    header = struct.Struct("!BBH")

    hsize = header.size

    # def __init__(self, I: Self, frombuf: Optional(bytes, BinaryIO)):
    def __init__(self):
        self.Version = 0x01 # protocol version


    def tobuf(self, typ: PacketType, data: bytes) -> Union[bytes, memoryview]:
        self.buf = io.BytesIO()
        h = self.header.pack(self.Version, typ, len(data))
        self.buf.write(h)
        self.buf.write(data)

        # return self.buf.getbuffer()
        return self.buf.getvalue()
    

    def frombuf(self, data: bytes):
        self.Version, typ, lenght = self.header.unpack(data[:self.hsize])
        self.typ = PacketType(typ)
        self.lenght = lenght


class RecvSend:

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        self.reader = reader
        self.writer = writer

        self.max_payload = 65536
    
    async def read(self) -> Tuple[PacketType, Union[bytes, memoryview]]:
        logger.debug(f"__read() Packet.hsize")

        data = await self.__read(Packet.hsize)
        if data == b"":
            return PacketType.EXIT, b""

        if len(data) != Packet.hsize:
            raise PacketError("invalid data")
        
        ph = Packet()
        ph.frombuf(data)

        payload = await self.__read(ph.lenght)

        logger.debug(f"__read() typ:{ph.typ.name}, lenght:{ph.lenght} payload:{payload}")


        if len(payload) != ph.lenght:
            raise PacketError("invalid data")
        
        return ph.typ, payload
    
    async def write(self, typ: PacketType, data: bytes) -> int:
        data_len = len(data)
        if data_len > self.max_payload:
            raise ValueError(f"数据包太大： 0 ~ {self.max_payload}")
        
        ph = Packet()
        payload = ph.tobuf(typ, data)

        await self.__write(payload)

    
    def getsockname(self):
        # return self.sock.getsockname()
        return self.writer.get_extra_info("peername")

    def fileno(self):
        return self.sock.fileno()

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
    

    async def __read(self, size: int) -> Union[bytes, memoryview]:
        buf = io.BytesIO()
        while (d := await self.reader.read(size)) != b"":
            buf.write(d)
            size -= len(d)
        
        # return buf.getbuffer()
        return buf.getvalue()
    

    async def __write(self, data: Union[bytes, memoryview]):

        self.writer.write(data)
        await self.writer.drain()

        return len(data)

        """
        l = len(data)
        mv = memoryview(data)
        n = 0 
        while n < l:
            n += self.writer.write(mv[n:])
        """



async def waitproc(shell: str, pty_slave: int) -> int:
    logger.debug(f"sub shell start")
    # p = await subprocess.create_subprocess_exec(shell, stdin=pty_slave, stdout=pty_slave, stderr=pty_slave, preexec_fn=os.setsid)
    p = await asyncio.create_subprocess_exec(shell, stdin=pty_slave, stdout=pty_slave, stderr=pty_slave, preexec_fn=os.setsid)
    recode = await p.wait()
    logger.debug(f"shell wait() done, recode: {recode}")
    os.close(pty_slave)
    return recode


async def connect_read_write(pty_master) -> Tuple[StreamReader, StreamWriter]:
    fileobj = open(pty_master)
    loop = asyncio.get_running_loop()

    reader = StreamReader()
    protocol = StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, fileobj)

    w_transport, w_protocol = await loop.connect_write_pipe(streams.FlowControlMixin, fileobj)
    writer = StreamWriter(w_transport, w_protocol, reader, loop)

    return reader, writer


# 好像使用协议后，不能这样直接转发了。。。
async def relay(reader: StreamReader, writer: StreamWriter):
    logger.debug(f"relay: {reader} --> {writer}")
    while (data := await reader.read(BUFSIZE)) != b"":
        logger.debug(f"relay: {data}")
        writer.write(data)
        await writer.drain()
    logger.debug(f"stream close()")


Pty = TypeVar("Pty")
# server 从 sock -> pty_master
# async def sock2pty(traner: RecvSend, writer: StreamWriter, pty_master: Pty):
async def sock2pty(traner: RecvSend, writer: StreamWriter):

    pty_master = writer.get_extra_info("pipe")

    while True:

        logger.debug(f"tnraner.read() start")
        typ, payload = await traner.read()
        logger.debug(f"typ:{PacketType(typ).name} payload: {payload}")

        if typ == PacketType.TRANER:
            writer.write(payload)
            await writer.drain()
        
        elif typ == PacketType.TTY_RESIZE:
            logger.debug(f"tty resize: {TermSize.unpack(payload)}")
            set_pty_size(pty_master, *TermSize.unpack(payload))

        elif typ == PacketType.EXIT:
            # writer.close()
            # await writer.wait_closed()
            # 应该放在 pty_master 退出后。由
            logger.debug(f"peer exit")
            break

        else:
            logger.warning(f"未知协议类型.")
            break


async def pty2sock(pty_master: Pty, traner: RecvSend):
    try:
        while (data := await pty_master.read(BUFSIZE)) != b"":
            await traner.write(PacketType.TRANER, data)
    except OSError:
        await traner.write(PacketType.EXIT, b"")
        await traner.close()

    logger.debug("pty2sock done, shell exit.")


# async def socketshell(shell: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
async def socketshell(shell: str, client: socket.SocketType):

    r, w = await asyncio.open_connection(sock=client)
    traner = RecvSend(r, w)

    addr = w.get_extra_info("peername")
    logger.info(f"client {addr} connected.")

    pty_master, pty_slave = pty.openpty()
    pty_reader, pty_writer = await connect_read_write(pty_master)


    p_task = asyncio.create_task(waitproc(shell, pty_slave))
    # pty2sock_task = asyncio.create_task(relay(pty_reader, w))
    # sock2pty = asyncio.create_task(relay(reader, pty_writer))

    sock2pty_task = asyncio.create_task(sock2pty(traner, pty_writer))
    # sock2pty_task = asyncio.create_task(sock2pty(traner, pty_writer, pty_master))
    pty2sock_task = asyncio.create_task(pty2sock(pty_reader, traner))


    logger.debug("shell start")
    await p_task
    logger.debug("shell exit")

    await pty2sock_task
    await sock2pty_task

    logger.debug("task start ?")

    w.close()
    await w.wait_closed()

    # 什么 pty_master 或者 pty_writer 不用close() ???
    # 目前看应该是 connect_read_write() 自动关闭的。
    # pty_writer.close()
    # await pty_writer.wait_closed()

    """
    logger.debug("pty2sock start")
    pty2sock_task.cancel()
    logger.debug("pty2sock end")

    logger.debug("sock2pty start")
    sock2pty_task.cancel()
    logger.debug("sockpty end")
    """

    results = await asyncio.gather(pty2sock_task, sock2pty_task, p_task, return_exceptions=True)
    logger.debug(f"gather() --> {results}")

    recode = p_task.result()
    logger.info(f"client {addr} disconnect, recode: {recode}")


# 为登录的shell开一个子进程，这样不行。不能直接启动协程
def start_shell(shell, client):
    p = mprocess.Process(target=lambda: asyncio.run(socketshell(shell, client)))
    p.start()

    # 传给子进程后，在父进程需要关闭。
    client.close()
    
    p.join()
    logger.debug(f"子进程 {p.pid} shell退出.")


# 旧的方案代码先保留
async def server(args):
    sock = await asyncio.start_server(lambda r, w: socketshell(args.cmd, r, w), args.addr, args.port, reuse_address=True)
    logger.info(f"listent: {args.addr}, {args.port}")
    async with sock:
        await sock.serve_forever()



# 2023-04-16 使用多进程开启子进程
def server_process(args):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.addr, args.port))
    sock.listen(128)

    logger.info(f"listen: {args.addr} port:{args.port}")

    try:
        while True:
            client, addr = sock.accept()
            # start_shell(args.cmd, client)
            th = threading.Thread(target=start_shell, args=(args.cmd, client))
            th.start()

    # 不能使用CTRL+C这样已经登录的子进程也会被干掉。
    except KeyboardInterrupt:
        pass


# client 从 stdin -> sock
async def stdin2sock(r: StreamReader, w: RecvSend):
    try:
        while (payload := await r.read(BUFSIZE)) != b"":
            await w.write(PacketType.TRANER, payload)
            logger.debug(f"stdin2sock: {payload}")
    except asyncio.CancelledError:
        logger.debug("stdin2sock Cancelled")

    logger.debug("stdin2sock exit.")


async def sock2stdout(r: RecvSend, w: StreamWriter):
    while True:
        logger.debug(f"read()")
        typ, payload = await r.read()
        logger.debug(f"{PacketType(typ).name}, {payload}")

        if typ == PacketType.TRANER:
            logger.debug(f"w.write(payload) --> stdout")
            w.write(payload)
            await w.drain()

        elif typ == PacketType.TTY_RESIZE:
            pty_fd = w.get_extra_info("pipe")
            set_pty_size(pty_fd, *TermSize.unpack(payload))

        elif typ == PacketType.EXIT:
            await r.close()
            logger.debug(f"peer sock close")
            break
        else:
            logger.debug(f"不符合的包：{typ}, {payload}")

    logger.debug(f"done")

async def client(args):

    # 这两个只在client 使用
    STDIN = sys.stdin.fileno()
    # STDOUT = sys.stdout.fileno()


    r, w = await asyncio.open_connection(args.addr, args.port)
    traner = RecvSend(r, w)

    loop = asyncio.get_running_loop()



    # 窗口大小调整, 这样是调控制端的。 (这是同步方法)
    sock = w.get_extra_info("socket")
    loop.add_signal_handler(signal.SIGWINCH, signal_SIGWINCH_handle, sock, STDIN)

    # 窗口大小调整, 这样是调控制端的。 尝试使用asyncio: TypeError: coroutines cannot be used with add_signal_handler()
    # loop.add_signal_handler(signal.SIGWINCH, signal_SIGWINCH_asyncio(traner, STDIN))

    # 初始化对面终端
    columns, rows = get_pty_size(STDIN)
    logger.debug(f"向对面发送 终端 大小:{columns}x{rows}")

    await traner.write(PacketType.TTY_RESIZE, TermSize.pack(columns, rows))

    tty_bak = termios.tcgetattr(STDIN)
    tty.setraw(STDIN)
    

    stdiner = StreamReader()
    protocol = StreamReaderProtocol(stdiner)
    r_transport, r_protocol = await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    w_transport, w_protocol = await loop.connect_write_pipe(streams.FlowControlMixin, sys.stdout)
    stdouter = StreamWriter(w_transport, w_protocol, stdiner, loop)

    stdin2sock_task = asyncio.create_task(stdin2sock(stdiner, traner))
    sock2stdout_task = asyncio.create_task(sock2stdout(traner, stdouter))

    await sock2stdout_task

    
    stdin2sock_task.cancel()
    # sock2stdout_task.cancel()

    await traner.close()

    termios.tcsetattr(STDIN, termios.TCSADRAIN, tty_bak)
    logger.debug("restore termios")



def main():
    parse = argparse.ArgumentParser(
        usage="%(prog)s <命令> [option]",
        description="远程shell连接",
        epilog="END",
    )

    parse.add_argument("--parse", action="store_true", help=argparse.SUPPRESS)
    parse.add_argument("--debug", action="store_true", help="debug")

    parse.add_argument("--addr", default="::", help="需要连接的IP或域名")
    parse.add_argument("--port", default=6789, type=int, help="端口(default: 6789")

    parse.add_argument("--server", action="store_true", help="启动服务端。")
    parse.add_argument("--cmd", default=SHELL, help=f"需要使用的交互程序(default: {SHELL})")

    # parse.add_argument("--Spub", action="store", nargs="+", required=True, help="使用加密通信的对方公钥，server端可能有多个。")
    # parse.add_argument("--Spriv", action="store", required=True, help="使用加密通信的私钥。")

    """
    subparsers = parse.add_subparsers(title="指令", metavar="", required=True)
    server_func =  subparsers.add_parser("server", help="启动服务端")
    client_func = subparsers.add_parser("client", help="使用client端")
    server_func.add_argument("--cmd", default=SHELL, help=f"需要使用的交互程序(default: {SHELL})")

    # server_func.set_defaults(func=server)
    server_func.set_defaults(func=server_process)
    
    client_func.set_defaults(func=client)
    """

    args = parse.parse_args()
    if args.parse:
        print(args)
        sys.exit(0)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    
    if args.server:
        server_process(args)

    else:
        # asyncio.run(args.func(args.addr, args.port), debug=True)
        asyncio.run(client(args), debug=True)


if __name__ == "__main__":
    main()