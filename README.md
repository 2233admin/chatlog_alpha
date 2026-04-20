# chatlog_alpha

微信 4.x 聊天记录本地查询工具，支持 `macOS` 与 `Windows`。

> 警告：Windows 平台当前未完成实机测试，可能无法正常运行。请优先在测试环境验证后再用于正式数据。

## 平台与能力

- 数据库 Key 获取：内置扫描流程（兼容 `all_keys.json`）
- 图片 Key 获取：内置扫描与校验流程
- 数据查询：HTTP + MCP（wx-cli 风格接口）
- 数据源：内置 `wcdb_api` 兼容查询链路（非外部 DLL）

## GitHub 自动构建产物

当前 `Release` 工作流会自动构建以下平台与架构：

- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

发布时会在 `dist/` 生成对应压缩包与二进制文件（Windows 为 `.exe`）。

## 快速开始

### 本地运行

```bash
go run .
```

或：

```bash
go build -o chatlog ./cmd/chatlog
./chatlog
```

### 常用命令（CLI）

```bash
chatlog server -a :5030 -p darwin -v 4 -d <wechat_data_dir>
chatlog server -a :5030 -p windows -v 4 -d <wechat_data_dir>
```

```bash
chatlog decrypt -p darwin -v 4 -d <wechat_data_dir> -k <data_key>
chatlog decrypt -p windows -v 4 -d <wechat_data_dir> -k <data_key>
```

```bash
chatlog batch-decrypt --data-dir <wechat_data_dir> --data-key <data_key> --platform darwin --version 4
chatlog batch-decrypt --data-dir <wechat_data_dir> --data-key <data_key> --platform windows --version 4
```

## macOS 权限说明（务必阅读）

### 1) 推荐用 `sudo` 运行

macOS 内存读取依赖 `task_for_pid`，建议以 root 启动程序。

### 2) 若使用 setuid 方案（可执行文件自动 root）

请在每次重新编译后执行：

```bash
BIN_PATH="/你的实际路径/chatlog"
sudo chown root:wheel "$BIN_PATH"
sudo chmod 4755 "$BIN_PATH"
ls -l "$BIN_PATH"
```

看到 `-rwsr-xr-x` 表示生效。

### 3) SIP

在多数机器上，仅 root 仍可能不足以读取微信进程内存。  
如需稳定扫描 Key，通常还需要关闭 SIP（System Integrity Protection）。

## Windows 权限说明

- 请使用“管理员权限”启动程序，否则可能无法读取微信进程内存。

## HTTP 接口（摘要）

基础：

- `GET /health`
- `GET /api/v1/ping`

媒体：

- `GET /image/*key`
- `GET /video/*key`
- `GET /file/*key`
- `GET /voice/*key`
- `GET /data/*path`

查询（wx-cli 风格）：

- `GET /api/v1/sessions`
- `GET /api/v1/history`
- `GET /api/v1/search`
- `GET /api/v1/unread`
- `GET /api/v1/members`
- `GET /api/v1/new_messages`
- `GET /api/v1/stats`
- `GET /api/v1/favorites`
- `GET /api/v1/sns_notifications`
- `GET /api/v1/sns_feed`
- `GET /api/v1/sns_search`
- `GET /api/v1/contacts`
- `GET /api/v1/chatrooms`

数据库调试：

- `GET /api/v1/db`
- `GET /api/v1/db/tables`
- `GET /api/v1/db/data`
- `GET /api/v1/db/query`
- `POST /api/v1/cache/clear`

输出格式：

- 默认 `YAML`
- 可选 `JSON`（`format=json`）

## MCP

端点：

- `ANY /mcp`
- `ANY /sse`
- `ANY /message`

## 安全与隐私

- 所有处理在本地完成
- 请妥善保管解密数据与密钥文件

## 免责声明

详见 [DISCLAIMER.md](./DISCLAIMER.md)
