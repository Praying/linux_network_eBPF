from bcc import BPF
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import time
import signal
import argparse
import sys
from datetime import datetime

# eBPF程序代码（修复内存安全问题）
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/if_ether.h>
#include <linux/in.h>

struct data_t {
    u64 ts;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack_seq;
    char func[64];  // 增加函数名缓冲区大小
};

// 事件输出通道
BPF_PERF_OUTPUT(events);

// 添加速率限制 - 每秒最多1000000个事件
#define MAX_EVENTS_PER_SECOND 1000000
BPF_ARRAY(last_event_time, u64, 1);
BPF_ARRAY(event_count, u64, 1);

// 自定义函数名称赋值，避免使用指针传递
static void set_function_name(struct data_t *data, const char *name) {
    // 直接逐字节拷贝，而不是使用bpf_probe_read_kernel_str
    for (int i = 0; i < sizeof(data->func) - 1 && name[i] != '\\0'; i++) {
        data->func[i] = name[i];
    }
}

static int extract_tcp_info(struct pt_regs *ctx, struct sk_buff *skb, int func_id) {
    int zero = 0;
    
    // 速率限制检查
    u64 *last_time = last_event_time.lookup(&zero);
    u64 *count = event_count.lookup(&zero);
    u64 current_time = bpf_ktime_get_ns();
    
    if (last_time && count) {
        // 如果在同一秒内且已超过限制，则丢弃
        if (current_time - *last_time < 1000000000ULL && *count >= MAX_EVENTS_PER_SECOND) {
            return 0;
        }
        
        // 更新计数器
        if (current_time - *last_time >= 1000000000ULL) {
            *count = 0;
            *last_time = current_time;
        }
        *count += 1;
    }
    
    // 只检查 skb 指针有效性，func_id 是整数不需要检查
    if (!skb) {
        return 0;
    }
    
    // 检查网络层和传输层头指针有效性
    if (skb->network_header == 0 || skb->transport_header == 0) {
        return 0;
    }

    struct iphdr *ip = (void *)skb->head + skb->network_header;
    
    // 验证IP头长度
    if ((void*)ip + sizeof(struct iphdr) > (void*)skb->head + skb->tail) {
        return 0;
    }
    
    // 验证是否为TCP协议
    u8 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip->protocol);
    if (protocol != IPPROTO_TCP) {
        return 0;
    }
    
    struct tcphdr *tcp = (void *)skb->head + skb->transport_header;
    
    // 验证TCP头长度
    if ((void*)tcp + sizeof(struct tcphdr) > (void*)skb->head + skb->tail) {
        return 0;
    }

    struct data_t data = {};
    __builtin_memset(&data, 0, sizeof(data));
    
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &ip->saddr);
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &ip->daddr);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &tcp->source);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &tcp->dest);
    bpf_probe_read_kernel(&data.seq, sizeof(data.seq), &tcp->seq);
    bpf_probe_read_kernel(&data.ack_seq, sizeof(data.ack_seq), &tcp->ack_seq);

    data.ts = current_time;
    
    // 根据func_id设置函数名
    switch (func_id) {
        case 1:
            __builtin_memcpy(data.func, "netif_receive_skb", 17);
            break;
        case 2:
            __builtin_memcpy(data.func, "ip_rcv_finish", 13);
            break;
        case 3:
            __builtin_memcpy(data.func, "tcp_v4_do_rcv", 13);
            break;
        case 4:
            __builtin_memcpy(data.func, "tcp_queue_rcv", 13);
            break;
        case 5:
            __builtin_memcpy(data.func, "sock_def_readable", 17);
            break;
        default:
            __builtin_memcpy(data.func, "unknown", 7);
            break;
    }
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_netif_receive_skb(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return extract_tcp_info(ctx, skb, 1);  // 使用ID替代字符串
}
int trace_ip_rcv_finish(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    return extract_tcp_info(ctx, skb, 2);
}
int trace_tcp_v4_do_rcv(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return extract_tcp_info(ctx, skb, 3);
}
int trace_tcp_queue_rcv(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
    return extract_tcp_info(ctx, skb, 4);
}
int trace_sock_def_readable(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        return 0;
    }
    
    struct data_t data = {};
    __builtin_memset(&data, 0, sizeof(data));
    
    // 尝试获取sock信息
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), &inet->inet_daddr);
    bpf_probe_read_kernel(&data.saddr, sizeof(data.saddr), &inet->inet_saddr);
    bpf_probe_read_kernel(&data.dport, sizeof(data.dport), &inet->inet_dport);
    bpf_probe_read_kernel(&data.sport, sizeof(data.sport), &inet->inet_sport);
    
    // 现在我们无法访问seq和ack_seq，因为这是sock级别而不是skb级别
    // 但至少我们有基本的连接信息

    data.ts = bpf_ktime_get_ns();
    
    // 直接设置函数名，不使用bpf_probe_read_kernel_str
    __builtin_memcpy(data.func, "sock_def_readable", 17);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""
class TrafficMonitor:
    def __init__(self, args=None):
        # 默认参数
        self.filter_ip = None
        self.filter_port = None
        self.verbose = False
        self.stats_only = False
        self.debug_func = True
        self.packet_count = 0
        self.err_count = 0
        
        # 如果传入了参数，解析它们
        if args:
            self.filter_ip = args.filter_ip
            self.filter_port = args.filter_port
            self.verbose = args.verbose
            self.stats_only = args.stats
            self.debug_func = getattr(args, 'debug_func', False)
        
        # 编译并加载BPF程序
        self.b = BPF(text=prog)
        
        # 修改为包含说明的探针列表
        self.attached_probes = [
            ("netif_receive_skb", "trace_netif_receive_skb"),   # 当网络接口接收到数据包时
            ("ip_rcv_finish", "trace_ip_rcv_finish"),           # IP 接收完成阶段
            ("tcp_v4_do_rcv", "trace_tcp_v4_do_rcv"),           # TCP v4 接收处理
            ("tcp_queue_rcv", "trace_tcp_queue_rcv"),           # TCP 数据包放入接收队列
            ("sock_def_readable", "trace_sock_def_readable")    # 套接字数据可读时
        ]
        self.exit_flag = False
        self.setup_signal_handlers()
        self.attach_probes()
        
        print(f"Started TCP monitoring...")
        if self.filter_ip:
            print(f"Filtering for IP: {self.filter_ip}")
        if self.filter_port:
            print(f"Filtering for Port: {self.filter_port}")

    def setup_signal_handlers(self):
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, sig, frame):
        print(f"\nReceived signal {sig}, cleaning up...")
        self.exit_flag = True

    def attach_probes(self):
        for event, fn_name in self.attached_probes:
            self.b.attach_kprobe(event=event, fn_name=fn_name)

    def cleanup(self):
        print("\nDetaching probes...")
        for event, _ in self.attached_probes:
            try:
                self.b.detach_kprobe(event)
            except Exception as e:
                print(f"Error detaching {event}: {str(e)}")
        print("Cleaning BPF resources...")
        self.b.cleanup()

    def print_header(self):
        if self.stats_only:
            print("TCP Event Monitoring - Statistics Mode")
            print("-" * 40)
            return
        
        # 修改表头格式，使所有列对齐
        headers = ["KERNEL FUNCTION", "SRC IP", "DST IP", "SRC PORT", "DST PORT", "SEQ", "ACK SEQ", "TIMESTAMP"]
        col_widths = [20, 17, 17, 10, 10, 14, 14, 26]
        
        header_line = " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers)))
        print(header_line)
        print("-" * len(header_line))

    def print_event(self, cpu, data, size):
        self.packet_count += 1
        event = self.b["events"].event(data)
        
        try:
            # 更明确地解码和处理函数名
            func_raw = event.func
            try:
                # 改进函数名解码逻辑
                # 先尝试查找非零字节
                non_zero_bytes = bytes([b for b in func_raw if b != 0])
                if non_zero_bytes:
                    # 如果有非零字节，尝试解码
                    func = non_zero_bytes.decode('utf-8', 'replace').strip()
                    if not func:
                        func = f"<binary:{non_zero_bytes.hex()}>"
                else:
                    # 完全为零的情况
                    func = "<empty>"
                
            except Exception as e:
                # 保留原始字节以便调试
                func = f"<err:{[b for b in func_raw if b != 0]}>"
                if self.debug_func:
                    print(f"Function decode error: {str(e)}")
                    print(f"Raw bytes: {[b for b in func_raw]}")
                
            saddr = inet_ntop(AF_INET, pack("I", event.saddr)) if event.saddr else "-"
            daddr = inet_ntop(AF_INET, pack("I", event.daddr)) if event.daddr else "-"
            sport = ntohs(event.sport) if event.sport else 0
            dport = ntohs(event.dport) if event.dport else 0
            
            # 过滤逻辑
            if self.filter_ip and self.filter_ip not in [saddr, daddr]:
                return
            if self.filter_port and self.filter_port not in [sport, dport]:
                return
                
            # 统计模式下不打印详细信息
            if self.stats_only:
                if self.packet_count % 100 == 0:
                    print(f"Processed {self.packet_count} events, {self.err_count} errors", end="\r")
                return
                
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # 统一所有列的宽度，确保对齐一致
            col_values = [
                f"[{func}]",
                saddr,
                daddr,
                str(sport),
                str(dport),
                str(event.seq),
                str(event.ack_seq),
                now_str
            ]
            
            # 使用与表头相同的列宽度
            col_widths = [20, 17, 17, 10, 10, 14, 14, 26]
            
            # 构建格式化输出行
            output_line = " | ".join(f"{col_values[i]:<{col_widths[i]}}" for i in range(len(col_values)))
            print(output_line)
            
            # 添加调试输出
            if self.debug_func:
                print(f"  Debug - Function name: '{func}'")
                print(f"  Debug - Raw bytes: {[b for b in func_raw if b != 0]}")
        except Exception as e:
            self.err_count += 1
            if self.verbose:
                print(f"Error processing event: {str(e)}")

    def print_stats(self):
        print("\n\nMonitoring Statistics:")
        print(f"Total events processed: {self.packet_count}")
        print(f"Error count: {self.err_count}")
        
    def run(self):
        self.print_header()
        
        # 为事件处理设置回调
        self.b["events"].open_perf_buffer(self.print_event)
        
        try:
            while not self.exit_flag:
                try:
                    self.b.perf_buffer_poll(timeout=1000)  # 1秒超时
                except KeyboardInterrupt:
                    self.exit_flag = True
                    break
                except Exception as e:
                    if not self.exit_flag:
                        if self.verbose:
                            print(f"Polling error: {str(e)}")
                        else:
                            self.err_count += 1
        finally:
            self.print_stats()
            self.cleanup()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Monitor TCP packets in the Linux networking stack using eBPF")
    parser.add_argument("-i", "--ip", dest="filter_ip",
                        help="Filter by IP address (source or destination)")
    parser.add_argument("-p", "--port", dest="filter_port", type=int,
                        help="Filter by port (source or destination)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose error messages and debugging information")
    parser.add_argument("-s", "--stats", action="store_true",
                        help="Show only statistics, not individual packets")
    parser.add_argument("-d", "--debug-func", action="store_true",
                        help="Enable function name debugging")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    monitor = TrafficMonitor(args)
    
    try:
        monitor.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)
    finally:
        print("Monitoring stopped.")

