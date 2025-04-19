# eBPF Linux网络监控工具

一个使用eBPF技术监控Linux内核网络栈的高性能工具，可以实时捕获和分析TCP数据包，帮助开发人员和系统管理员诊断网络问题。

![Output Example](https://github.com/yourusername/linux-network-monitor/raw/main/screenshots/output_example.png)

## 功能特点

- 实时监控Linux内核网络栈中的TCP数据包
- 跟踪关键网络处理函数（netif_receive_skb, ip_rcv_finish, tcp_v4_do_rcv等）
- 显示详细的连接信息（源/目标IP、端口、TCP序列号等）
- 支持按IP地址或端口号过滤
- 内置速率限制机制，确保在高流量环境下性能稳定
- 美观的表格化输出格式
- 提供统计模式和详细错误报告

## 技术原理

此工具基于eBPF (Extended Berkeley Packet Filter) 技术，这是Linux内核中的一种强大机制，允许在不修改内核代码的情况下注入和执行代码。通过在关键网络处理函数上附加kprobes，我们可以：

1. 捕获经过内核网络栈的TCP包
2. 提取包的详细信息（IP、端口、序列号等）
3. 高效地将这些信息传递给用户空间
4. 实时分析和显示结果

工具使用BCC (BPF Compiler Collection) 框架，简化了eBPF程序的开发和部署过程。

## 安装要求

- Linux内核 4.8+ (推荐5.0+以获得最佳性能)
- Python 3.7+
- BCC工具集
- 必要的依赖库（包含在安装说明中）

## 安装步骤

### 1. 安装必要的依赖

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r) python3-bpfcc
```

#### Fedora:
```bash
sudo dnf install bcc bcc-tools bcc-devel python3-bcc
```

#### 其他系统请参考BCC文档：
[BCC Installation Instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md)

### 2. 克隆仓库

```bash
git clone https://github.com/yourusername/linux-network-monitor.git
cd linux-network-monitor
```

### 3. 确认权限

工具需要root权限才能加载eBPF程序：

```bash
sudo python3 ./linux_net_kernel.py
```

## 使用方法

### 基本用法

监控所有TCP连接：

```bash
sudo python3 linux_net_kernel.py
```

### 过滤指定IP地址

```bash
sudo python3 linux_net_kernel.py -i 192.168.1.100
```

### 过滤指定端口

```bash
sudo python3 linux_net_kernel.py -p 443
```

### 仅显示统计信息

```bash
sudo python3 linux_net_kernel.py -s
```

### 启用详细错误输出

```bash
sudo python3 linux_net_kernel.py -v
```

### 调试函数名问题

```bash
sudo python3 linux_net_kernel.py -d
```

### 组合使用

```bash
sudo python3 linux_net_kernel.py -i 192.168.1.100 -p 80 -v
```

## 命令行参数

| 参数 | 描述 |
|------|------|
| `-i, --ip` | 按源或目标IP地址过滤 |
| `-p, --port` | 按源或目标端口过滤 |
| `-v, --verbose` | 启用详细错误消息 |
| `-s, --stats` | 仅显示统计信息，不显示单个数据包 |
| `-d, --debug-func` | 启用函数名称调试功能 |

## 输出解释

工具的输出是一个表格，包含以下列：

| 列名 | 描述 |
|------|------|
| KERNEL FUNCTION | 捕获数据包的内核函数名称 |
| SRC IP | 源IP地址 |
| DST IP | 目标IP地址 |
| SRC PORT | 源端口 |
| DST PORT | 目标端口 |
| SEQ | TCP序列号 |
| ACK SEQ | TCP确认序列号 |
| TIMESTAMP | 捕获时间 |

### 内核函数说明

- `netif_receive_skb`: 网络接口接收到数据包时调用
- `ip_rcv_finish`: IP层处理完成
- `tcp_v4_do_rcv`: TCP协议处理函数
- `tcp_queue_rcv`: 将数据包放入接收队列
- `sock_def_readable`: 套接字数据可读

## 性能考虑

为防止高流量环境下系统过载，工具实现了速率限制(每秒10000个事件)。在极高流量的生产环境中使用时，建议调整此值或使用过滤器缩小监控范围。

## 故障排除

### 问题：无法启动工具或报错 "Failed to compile BPF module"

**解决方案**：
- 确认您的内核版本兼容 (`uname -r`)
- 确认已安装正确的内核头文件
- 尝试使用 `-v` 参数获取详细错误信息

### 问题：函数名显示为空或乱码

**解决方案**：
- 使用 `-d` 参数启用函数名调试
- 检查输出中的原始字节值
- 确认您的内核版本支持使用的BPF函数

## 贡献指南

欢迎贡献！请按照以下步骤：

1. Fork 仓库
2. 创建新的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

## 致谢

- [BCC项目](https://github.com/iovisor/bcc) - eBPF编程框架
- Linux内核社区 - eBPF支持和网络堆栈开发

---

如有问题，请在GitHub上提交issue或联系：yourname@example.com