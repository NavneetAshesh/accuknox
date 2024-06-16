from bcc import BPF
import pyroute2

# Define the BPF program
bpf_code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>

BPF_HASH(blocked_port, u32, u32);

int drop_tcp_packets(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethhdr *eth = cursor_advance(cursor, sizeof(*eth));
    struct iphdr *ip = cursor_advance(cursor, sizeof(*ip));
    
    if (ip->protocol != IPPROTO_TCP) {
        return 0;
    }
    
    struct tcphdr *tcp = cursor_advance(cursor, sizeof(*tcp));
    
    u32 port = tcp->dest;
    u32 *blocked = blocked_port.lookup(&port);
    
    if (blocked) {
        return TC_ACT_SHOT; // Drop the packet
    }
    
    return TC_ACT_OK;
}
"""

# Compile and load the BPF program
b = BPF(text=bpf_code)
fn = b.load_func("drop_tcp_packets", BPF.SCHED_CLS)

# Attach the BPF program to the network interface (replace 'eth0' with your interface)
interface = "eth0"
ip = pyroute2.IPRoute()
idx = ip.link_lookup(ifname=interface)[0]
ip.tc("add", "clsact", idx)
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", action="drop", classid=1)

# Define the port to block (default is 4040)
blocked_port = 4040

# Function to set the blocked port from userspace
def set_blocked_port(port):
    global blocked_port
    blocked_port = port
    b["blocked_port"].clear()
    b["blocked_port"][ct.c_uint32(blocked_port)] = ct.c_uint32(1)
    print(f"Blocking TCP packets on port: {blocked_port}")

# Set the initial blocked port
set_blocked_port(4040)

# Allow the user to change the blocked port
try:
    while True:
        port = int(input("Enter port number to block (or Ctrl+C to exit): "))
        set_blocked_port(port)
except KeyboardInterrupt:
    print("Exiting...")

# Cleanup
ip.tc("del", "clsact", idx)
