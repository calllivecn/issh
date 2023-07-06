# 重复造轮子 类似ssh的远程shell工具

## issh.py

- 使用asyncio提高并发
- 还没有做连接加密

```shell
# 示例一
$ issh.py --help
usage: issh.py <命令> [option]

远程shell连接

options:
  -h, --help   show this help message and exit
  --debug      debug
  --addr ADDR  需要连接的IP或域名
  --port PORT  端口(default: 6789

指令:
  
    server     启动服务端
    client     使用client端

END

# 示例二
$ issh.py server --help
usage: issh.py <命令> [option] server [-h] [--cmd CMD]

options:
  -h, --help  show this help message and exit
  --cmd CMD   需要使用的交互程序(default: bash)
```


## rshell.py

- 反向连接shell
- 使用了认证加密连接。

```shell
#示例一
$ rshell.py --help
usage: rshell.py <命令> [option]

反向shell连接

key1.json:

{
        "Spriv": "QMU540a6tp0eBvZrZ9y+MUP/EJ7YAVHTlIXEev2O8ko=",
        "Spub": [
                "A7rc6wXszIcl89Rwk/vXke1obnT74MEgDxUNfWiTOy0="
        ]
}
        

options:
  -h, --help         show this help message and exit
  --addr ADDR        需要连接的IP或域名
  --port PORT        端口
  --keyfile KEYFILE  使用加密通信和指定公私钥。

指令:
  
    server           启动服务端
    client           使用client端

END

# 示例二
$ rshell.py server --help
usage: rshell.py <命令> [option] server [-h] [--cmd CMD]

options:
  -h, --help  show this help message and exit
  --cmd CMD   需要使用的交互程序(default: bash)

# 示例三
$ rshell.py client --help
usage: rshell.py <命令> [option] client [-h]

options:
  -h, --help  show this help message and exit

```