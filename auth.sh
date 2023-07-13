#!/bin/bash
# date 2023-07-13 19:43:47
# author calllivecn <c-all@qq.com>

# 忽略一些信号
trap : SIGINT SIGTERM

if [ "$1"x = "-v"x ];then
	DEBUG=1
else
	DEBUG=0
fi

log(){
	if [ "$DEBUG" = 1 ];then
		echo "$@"
	fi
}


input(){
	while :
	do

		echo -n "$1"
		read text

		log "这次的输入：${text}"

		if [ "$text"x = x ];then 
			:
		else
			break
		fi
	done
}

text=

input "用户名："
user="$text"

stty -echo
input "密码: "
stty echo
echo
password="$text"

if [ "$password"x = "your password"x ];then
	exec bash
else
	echo "密码错误"
fi

