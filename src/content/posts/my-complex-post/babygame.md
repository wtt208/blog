---
title: babygame
published: 2026-02-02
pinned: false
description: ciscn 2025 -reverse
tags:
  - reverse
category: ctf
author: wtt
draft: true
date: 2026-01-19
---

题目获取：[CISCN-2025](https://github.com/CTF-Archives/2025-CCB-CISCN-Quals)

下载附件为babygame.exe 运行起来为小游戏
```bash
strings BabyGame.exe | grep -i godot
```

分析为godot文件
使用binwalk解包？并不能很好的分析出来
使用GDRE_tools解包

其中script一般为关键文件 cd进去发现有flag.gd

```python
extends CenterContainer

@onready var flagTextEdit: Node = $PanelContainer / VBoxContainer / FlagTextEdit
@onready var label2: Node = $PanelContainer / VBoxContainer / Label2

static var key = "FanAglFanAglOoO!"
var data = ""

func _on_ready() -> void :
    Flag.hide()

func get_key() -> String:
    return key

func submit() -> void :
    data = flagTextEdit.text

    var aes = AESContext.new()
    aes.start(AESContext.MODE_ECB_ENCRYPT, key.to_utf8_buffer())
    var encrypted = aes.update(data.to_utf8_buffer())
    aes.finish()

    if encrypted.hex_encode() == "d458af702a680ae4d089ce32fc39945d":
        label2.show()
    else:
        label2.hide()

func back() -> void :
    get_tree().change_scene_to_file("res://scenes/menu.tscn")

```

分析得出这是AES的ECB加密 
密钥为FanAglFanAglOoO! 
密文为d458af702a680ae4d089ce32fc39945d

放入解密工具分析，得出flag
注意ECB没有IV ，且没有padding(需要选择nopadding模式)
![](images/Pasted%20image%2020260202163659.png)
得出flag