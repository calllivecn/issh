# 重复造轮子 类似ssh的远程shell工具

## issh.py

- 使用asyncio提高并发
- 还没有做连接加密

```shell
# 示例一
$ issh.py --help
usage: issh.py [option]

远程shell连接

options:
  -h, --help   show this help message and exit
  --debug      debug
  --addr ADDR  需要连接的IP或域名
  --port PORT  端口(default: 6789
  --server     启动服务端。
  --cmd CMD    需要使用的交互程序(default: bash)

END

```


## rshell.py

- 使用selectors提高并发
- 反向连接shell
- 使用了认证加密连接。

```shell
#示例一
$ rshell.py --help
usage: rshell.py [option]

反向shell连接
这里是使用反向shell连接到服务端的, Server是控制端，client是被控制端。

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
  --keyfile KEYFILE  使用加密通信并指定公私钥配置文件。
  --server           启动服务端

END

```