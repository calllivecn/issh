#!/usr/bin/env python3
# coding=utf-8
# date 2022-09-04 04:14:14
# author calllivecn <calllivecn@outlook.com>


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
from pathlib import Path
import multiprocessing as mprocess

from logging.handlers import TimedRotatingFileHandler

from asyncio import (
    streams,
    StreamReader,
    StreamWriter,
    StreamReaderProtocol,
)


SHELL="bash"

BUFSIZE = 1<<12 # 4K


def getlogger(level=logging.INFO):
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d %(levelname)s %(filename)s:%(funcName)s:%(lineno)d %(message)s", datefmt="%Y-%m-%d-%H:%M:%S")

    # stream = logging.StreamHandler(sys.stdout)
    # stream.setFormatter(fmt)

    # fp = logging.FileHandler("rshell.log")
    prog = Path(sys.argv[0]).stem
    fp = TimedRotatingFileHandler(f"{prog}.log", when="D", interval=1, backupCount=7)
    fp.setFormatter(fmt)

    logger = logging.getLogger(f"{prog}")
    logger.setLevel(level)
    # logger.addHandler(stream)
    logger.addHandler(fp)
    return logger


logger = getlogger()


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


    def tobuf(self, typ: PacketType, data: bytes) -> bytes|memoryview:
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
    
    async def read(self) -> tuple[PacketType, bytes|memoryview]:
        logger.debug("__read() Packet.hsize")

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

        return await self.__write(payload)

    
    def getsockname(self):
        # return self.sock.getsockname()
        return self.writer.get_extra_info("peername")


    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()
    

    async def __read(self, size: int) -> bytes|memoryview:
        buf = io.BytesIO()
        while (d := await self.reader.read(size)) != b"":
            buf.write(d)
            size -= len(d)
        
        # return buf.getbuffer()
        return buf.getvalue()
    

    async def __write(self, data: bytes|memoryview):

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


TermSize = struct.Struct("HH")

def get_pty_size(fd) -> tuple[int, int]:
    size = fcntl.ioctl(fd, termios.TIOCGWINSZ, b"00000000") # 占位符
    #h, w, xpixels, ypixels = TermSize.unpack(size)
    return struct.unpack("HHHH", size)[:2]

def set_pty_size(fd, columns, rows):
    # 这个返回还不知道是什么
    return fcntl.ioctl(fd, termios.TIOCSWINSZ, TermSize.pack(columns, rows))

# py3.11 新增
def get_pty_size2(fd) -> tuple[int, int]:
    return termios.tcgetwinsize(fd)

def set_pty_size2(fd, winsize):
    return termios.tcsetwinsize(fd, winsize)


async def resize_pty(sock: RecvSend, fd):
    columns, rows = get_pty_size(fd)
    logger.debug(f"窗口大小改变: {columns}x{rows}")
    logger.debug("sigwinch 向对端发送新窗口大小")
    await sock.write(PacketType.TTY_RESIZE, TermSize.pack(columns, rows))


# 窗口大小调整, 这样是调控制端的。 (这是同步方法)
def signal_SIGWINCH_handle(sock: RecvSend, fd: int):
    """
    usage: lambda sigNum, frame: signal_SIGWINCH_handle(sock, sigNum, frame)
    """
    loop = asyncio.get_running_loop()
    loop.create_task(resize_pty(sock, fd), name="resize_pty")


async def wait_process(shell: str, pty_slave: int) -> int:
    logger.debug("sub shell start")
    p = await asyncio.create_subprocess_exec(shell, stdin=pty_slave, stdout=pty_slave, stderr=pty_slave, preexec_fn=os.setsid)
    logger.debug(f"shell pid: {p.pid}")
    recode = await p.wait()
    logger.debug(f"shell exit pid: {p.pid}, recode: {recode}")
    os.close(pty_slave)
    return recode


async def connect_read_write(pty_master) -> tuple[StreamReader, StreamWriter]:
    """
    把对pipe 的读写，封闭为， StreamReader, StreamWriter
    """
    fileobj = open(pty_master)
    loop = asyncio.get_running_loop()

    reader = StreamReader()
    protocol = StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, fileobj)

    w_transport, w_protocol = await loop.connect_write_pipe(streams.FlowControlMixin, fileobj)
    writer = StreamWriter(w_transport, w_protocol, reader, loop)

    return reader, writer


# server 从 sock -> pty_master
async def sock2pty(traner: RecvSend, writer: StreamWriter):

    pty_master = writer.get_extra_info("pipe")

    while True:

        logger.debug("tnraner.read() start")
        typ, payload = await traner.read()
        logger.debug(f"typ:{PacketType(typ).name} payload: {payload}")

        if typ == PacketType.TRANER:
            writer.write(payload)
            await writer.drain()
        
        elif typ == PacketType.TTY_RESIZE:
            logger.debug(f"tty resize: {TermSize.unpack(payload)}")
            set_pty_size(pty_master, *TermSize.unpack(payload))

        elif typ == PacketType.EXIT:
            # 应该放在 pty_master 退出后。由
            logger.debug("peer exit")
            break

        else:
            logger.warning("未知协议类型.")
            break


async def pty2sock(pty_master: StreamReader, traner: RecvSend):
    try:
        while (data := await pty_master.read(BUFSIZE)) != b"":
            await traner.write(PacketType.TRANER, data)
    except OSError:
        await traner.write(PacketType.EXIT, b"")
        await traner.close()

    logger.debug("pty2sock done, shell exit.")


async def socketshell(shell: str, client: socket.SocketType):
    """
    server端，在客户端建立连接后，为远端shell，单独生成子进程处理。
    """

    r, w = await asyncio.open_connection(sock=client)
    traner = RecvSend(r, w)

    addr = w.get_extra_info("peername")
    logger.info(f"client {addr} connected.")

    pty_master, pty_slave = pty.openpty()

    pty_reader, pty_writer = await connect_read_write(pty_master)

    p_task = asyncio.create_task(wait_process(shell, pty_slave))

    sock2pty_task = asyncio.create_task(sock2pty(traner, pty_writer))
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

    # results = await asyncio.gather(pty2sock_task, sock2pty_task, p_task, return_exceptions=True)
    # logger.debug(f"gather() --> {results}")

    recode = p_task.result()
    logger.info(f"client {addr} disconnect, recode: {recode}")

"""
# 信号处理器函数
def sigchld_handler(signum: int, frame: None|object):
    while True:
        try:
            # 使用非阻塞模式回收所有退出的子进程
            pid, status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:  # 没有子进程退出
                break
            logger.debug(f"信号处理器：回收了子进程 {pid}，退出状态为 {status}")
        except ChildProcessError:
            # 没有子进程可回收，捕获错误并退出循环
            break

# 注册 SIGCHLD 信号处理器
signal.signal(signal.SIGCHLD, signal.SIG_IGN)
"""


# 为登录的shell开一个子进程，这样不行。不能直接启动协程
def start_shell(shell, client):
    asyncio.run(socketshell(shell, client))


def start_shell_process(shell, client):
    p = mprocess.Process(target=start_shell, args=(shell, client))
    p.start()
    client.close()
    logger.debug(f"启动子进程 {p.pid} 处理登录")
    p.join()
    logger.debug(f"回收子进程 {p.pid}")


def server_process(args):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.addr, args.port))
    sock.listen(128)

    logger.info(f"listen: {args.addr} port:{args.port}")

    try:
        while True:
            client, addr = sock.accept()
            logger.debug(f"新连接: {addr}")
            th = threading.Thread(target=start_shell_process, args=(args.cmd, client), name=f"shell-{addr}")
            th.start()

    # 不能使用CTRL+C这样已经创建的子进程也会被干掉。只是kill server端就没问题
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
        logger.debug("read()")
        typ, payload = await r.read()
        logger.debug(f"{PacketType(typ).name}, {payload}")

        if typ == PacketType.TRANER:
            logger.debug("w.write(payload) --> stdout")
            w.write(payload)
            await w.drain()

        elif typ == PacketType.TTY_RESIZE:
            pty_fd = w.get_extra_info("pipe")
            set_pty_size(pty_fd, *TermSize.unpack(payload))

        elif typ == PacketType.EXIT:
            await r.close()
            logger.debug("peer sock close")
            break
        else:
            logger.debug(f"不符合的包：{typ}, {payload}")

    logger.debug("done")


async def client(args):

    # 这两个只在client 使用
    STDIN = sys.stdin.fileno()
    # STDOUT = sys.stdout.fileno()

    r, w = await asyncio.open_connection(args.addr, args.port)
    traner = RecvSend(r, w)

    loop = asyncio.get_running_loop()


    # 窗口大小调整, 这样是调控制端的。 (必须是普通函数。同步方法)
    # sock = w.get_extra_info("socket")
    # logger.debug(f"{sock=}\n{dir(sock)=}")
    # loop.add_signal_handler(signal.SIGWINCH, signal_SIGWINCH_handle, sock, STDIN)
    loop.add_signal_handler(signal.SIGWINCH, signal_SIGWINCH_handle, traner, STDIN)

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
        usage="%(prog)s [option]",
        description="远程shell连接",
        epilog="END",
    )

    parse.add_argument("--parse", action="store_true", help=argparse.SUPPRESS)
    parse.add_argument("--debug", action="store_true", help="debug")

    parse.add_argument("--addr", default="::", help="需要连接的IP或域名")
    parse.add_argument("--port", default=6789, type=int, help="端口(default: 6789")

    parse.add_argument("--server", action="store_true", help="启动服务端。")
    parse.add_argument("--cmd", default=SHELL, help=f"需要使用的交互程序(default: {SHELL})")

    # parse.add_argument("--log", action="store", help="日志文件")

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
    
    # if args.log:
        # fp = logging.FileHandler(args.log)
        # logger.addHandler(fp)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    
    if args.server:
        server_process(args)

    else:
        # asyncio.run(args.func(args.addr, args.port), debug=True)
        asyncio.run(client(args), debug=True)


if __name__ == "__main__":
    main()