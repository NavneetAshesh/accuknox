from bcc import BPF
import pyroute2
import ctypes as ct

# Define the BPF program
bpf_code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <linux/sched.h>

BPF_HASH(allowed_port, u32, u32);
BPF_HASH(process_name, u32, char[16]);

int allow_specific_port(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethhdr *eth = cursor_advance(cursor, sizeof(*eth));
    struct iphdr *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = cursor_advance(cursor, sizeof(*tcp));

    u32 port = tcp->dest;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char pname[16];
    bpf_get_current_comm(&pname, sizeof(pname));

    char *target_pname = process_name.lookup(&pid);
    if (target_pname && !strcmp(pname, target_pname)) {
        u32 *allowed = allowed_port.lookup(&port);
        if (!allowed) {
            return TC_ACT_SHOT; // Drop the packet
        }
    }

    return TC_ACT_OK;
}
"""

# Compile and load the BPF program
b = BPF(text=bpf_code)
fn = b.load_func("allow_specific_port", BPF.SCHED_CLS)

# Attach the BPF program to the network interface (replace 'eth0' with your interface)
interface = "eth0"
ip = pyroute2.IPRoute()
idx = ip.link_lookup(ifname=interface)[0]
ip.tc("add", "clsact", idx)
ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff2", action="drop", classid=1)

# Define the allowed port (default is 4040) and the process name
allowed_port = 4040
process_name = "myprocess"

# Function to set the allowed port and process name from userspace
def set_allowed_port_and_process(port, pname):
    global allowed_port, process_name
    allowed_port = port
    process_name = pname.encode('utf-8')

    b["allowed_port"].clear()
    b["allowed_port"][ct.c_uint32(allowed_port)] = ct.c_uint32(1)

    b["process_name"].clear()
    for task in b.get_table("task_structs").items():
        if task.comm == process_name:
            b["process_name"][ct.c_uint32(task.pid)] = process_name
            break

    print(f"Allowing TCP packets on port: {allowed_port} for process: {process_name}")

# Set the initial allowed port and process name
set_allowed_port_and_process(4040, "myprocess")

# Allow the user to change the allowed port and process name
try:
    while True:
        port = int(input("Enter port number to allow (or Ctrl+C to exit): "))
        pname = input("Enter process name to allow (or Ctrl+C to exit): ")
        set_allowed_port_and_process(port, pname)
except KeyboardInterrupt:
    print("Exiting...")

# Cleanup
ip.tc("del", "clsact", idx)