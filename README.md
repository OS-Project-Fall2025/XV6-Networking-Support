# xv6 Networking Support

This project extends the RISC-V xv6 teaching operating system with a small
kernel-level networking stack. It drives a QEMU-emulated Intel E1000 network
adapter, transfers packets through DMA descriptor rings, implements basic
Ethernet/ARP/IPv4/UDP processing, and exposes port-based networking system calls
to user programs.

The implementation is intentionally compact and educational. It demonstrates
the complete path from a user-space `send()` call to a transmitted Ethernet
frame, and from an E1000 receive interrupt to a blocked user-space `recv()`.

## Features

- Intel E1000 initialization through PCI Express configuration space
- 16-entry transmit and receive DMA descriptor rings
- Interrupt-driven packet reception
- Ethernet, ARP, IPv4, UDP, and basic ICMP parsing
- IPv4 and UDP packet construction in the kernel
- Port-based `bind`, `unbind`, `send`, and `recv` system calls
- Bounded per-socket receive queues with packet dropping on overflow
- Blocking receive operations using xv6 `sleep()` and `wakeup()`
- ICMP Destination Unreachable propagation to a waiting receiver
- QEMU user-mode networking, UDP port forwarding, and packet capture
- Host/guest integration tests for transmission, reception, queueing, DNS, and
  memory retention

## Architecture Overview

```text
User process
    |
    | bind / unbind / send / recv
    v
Network syscalls and socket table (kernel/net.c)
    |
    | Ethernet + IPv4 + UDP frames
    v
E1000 driver and DMA rings (kernel/e1000.c)
    |
    v
QEMU E1000 device and user-mode network
    |
    v
Host test server (nettest.py)
```

The kernel uses the following QEMU network identity:

| Component | Address |
| --- | --- |
| xv6 IPv4 address | `10.0.2.15` |
| QEMU gateway IPv4 address | `10.0.2.2` |
| xv6 MAC address | `52:54:00:12:34:56` |
| QEMU gateway MAC address | `52:55:0a:00:02:02` |

The `Makefile` chooses host UDP ports from the current user ID to reduce
collisions between simultaneous xv6 instances.

## Send Path

1. A user process calls `send(sport, dst, dport, buf, len)`.
2. `sys_send()` allocates one kernel page and constructs Ethernet, IPv4, and UDP
   headers.
3. The payload is copied from the process address space with `copyin()`.
4. `e1000_transmit()` selects the descriptor at the device's transmit tail.
5. If the descriptor is available, the driver associates the allocated page
   with the descriptor and advances `E1000_TDT`.
6. The E1000 device reads the frame through DMA and transmits it through QEMU.
7. A completed transmit buffer is reclaimed when its descriptor is reused.

IPv4 header fields and UDP port/length fields are converted to network byte
order. UDP checksums are left as zero, which is permitted for IPv4 UDP packets.

## Receive Path

1. The E1000 device writes an incoming frame into a receive page through DMA.
2. A receive interrupt enters `e1000_intr()`.
3. The driver drains descriptors marked done and transfers each page to
   `net_rx()`.
4. `net_rx()` dispatches the frame according to its Ethernet type.
5. ARP requests are answered with a minimal ARP reply.
6. UDP packets are matched to a bound destination port and appended to that
   socket's bounded queue.
7. A blocked receiver is awakened.
8. `sys_recv()` removes the oldest queued packet, copies its payload and source
   address information to user space, and frees the kernel page.
9. The receive descriptor is replenished with a newly allocated page and
   returned to the device.

Packets for unbound ports and packets that arrive when a socket queue is full
are dropped and their pages are freed.

## Synchronization Design

The networking code uses three levels of synchronization:

- `e1000_lock` serializes access to the transmit descriptor ring.
- `sock_lock` protects socket-table lookup, allocation, and port uniqueness.
- Each socket has a spinlock protecting its queue indices, queued metadata, and
  pending ICMP error flag.

The lock order used by receive and ICMP paths is:

```text
sock_lock -> socket lock
```

`recv()` holds the socket lock while checking the queue condition and passes
that lock to `sleep()`. Packet delivery updates the queue while holding the same
lock and calls `wakeup()` on the socket address. This follows xv6's standard
condition-wait pattern and prevents a packet wakeup from being missed.

## ICMP Support

The receive path recognizes IPv4 ICMP packets. For an ICMP Destination
Unreachable message, it examines the embedded original IPv4 and UDP headers,
extracts the original UDP source port, and marks the corresponding local socket
with an error.

A process blocked in `recv()` on that port is awakened. If its queue is empty,
`recv()` consumes the pending error and returns `-1`.

## Requirements

- A RISC-V GCC/binutils toolchain, such as
  `riscv64-unknown-elf-gcc`
- QEMU with RISC-V system emulation, version 7.2 or newer
- GNU Make
- Python 3

The toolchain binaries and `qemu-system-riscv64` must be available on `PATH`.

## Build and Run

The repository is configured for the networking lab in `conf/lab.mk`:

```make
LAB=net
```

Build and boot xv6:

```sh
make qemu
```

At the xv6 shell prompt, individual guest tests can be run with:

```sh
nettest txone
nettest rx
nettest ping0
nettest ping1
nettest ping2
nettest ping3
nettest dns
nettest icmp
```

Press `Ctrl-a x` to exit QEMU.

## Testing

### Automated grader

Run the complete networking grader:

```sh
make grade
```

If the grader script cannot be executed directly because of local file
permissions, invoke it through Python:

```sh
python3 ./grade-lab-net -v
```

The grader starts a host UDP reflector, boots xv6, runs `nettest grade`, and
checks transmission, ARP, IP reception, multi-port delivery, bounded queueing,
DNS, and retained free pages.

### Manual host/guest tests

For an echo test, start the host helper first:

```sh
python3 nettest.py ping
```

Then boot xv6 in another terminal and run:

```sh
nettest ping0
nettest ping1
nettest ping2
nettest ping3
```

Other host helper modes include `txone`, `rxone`, `rx`, `rx2`, `rxburst`, `tx`,
and `grade`.

QEMU writes captured Ethernet traffic to `packets.pcap`. It can be inspected
with Wireshark or:

```sh
tcpdump -XXnr packets.pcap
```

## Example Test Output

The networking checks currently produce:

```text
== Test   nettest: txone == 
  nettest: txone: OK
== Test   nettest: arp_rx == 
  nettest: arp_rx: OK
== Test   nettest: ip_rx == 
  nettest: ip_rx: OK
== Test   nettest: ping0 == 
  nettest: ping0: OK
== Test   nettest: ping1 == 
  nettest: ping1: OK
== Test   nettest: ping2 == 
  nettest: ping2: OK
== Test   nettest: ping3 == 
  nettest: ping3: OK
== Test   nettest: dns == 
  nettest: dns: OK
== Test   nettest: free == 
  nettest: free: OK
```

## Repository Structure

| Path | Purpose |
| --- | --- |
| `kernel/e1000.c` | E1000 initialization, DMA rings, TX, RX, and interrupts |
| `kernel/e1000_dev.h` | E1000 register and descriptor definitions |
| `kernel/net.c` | Socket table, syscalls, packet construction, and parsing |
| `kernel/net.h` | Protocol headers and byte-order helpers |
| `kernel/pci.c` | QEMU PCIe discovery and E1000 BAR configuration |
| `kernel/plic.c` | E1000 interrupt enablement through the PLIC |
| `kernel/trap.c` | Dispatch of E1000 device interrupts |
| `kernel/syscall.c` | Kernel syscall registration |
| `kernel/syscall.h` | Networking syscall numbers |
| `user/user.h` | User-visible networking syscall declarations |
| `user/usys.pl` | Generation of user-space syscall stubs |
| `user/nettest.c` | xv6-side networking and memory tests |
| `nettest.py` | Host-side UDP sender, receiver, and reflector |
| `grade-lab-net` | Automated QEMU grading script |
| `Makefile` | Network build flags, QEMU device setup, and port forwarding |

## Known Limitations

- The implementation supports a fixed QEMU network topology rather than
  general interface configuration, routing, or dynamic ARP resolution.
- Only IPv4 UDP delivery and a narrow subset of ARP and ICMP are implemented.
  TCP, IPv6, fragmentation, IP options, and reassembly are not supported.
- The socket table is global and contains 16 entries. A ring-buffer sentinel
  means each 16-slot receive queue can hold at most 15 packets.
- Queue overflow drops the newest packet without backpressure or statistics.
- Transmit completion pages are reclaimed lazily when descriptors are reused.
- The RX path assumes packets fit in one descriptor and does not fully validate
  descriptor error/EOP state.
- Protocol length and checksum validation is incomplete; the code should not be
  exposed to untrusted traffic without stricter bounds checks.
- `unbind()` does not yet drain queued pages or provide complete coordination
  with blocked receivers and immediate socket-slot reuse.
- ICMP errors are represented by one per-socket flag, so repeated errors may be
  coalesced and are not matched to a complete remote endpoint tuple.

## Contributors

Student project team:

- Parmis Hemasian
- Sobhan Aghasi Zadeh
- Parsa Haji Ghasemi
- Ali Amini

## Course Context

This project was implemented for the Operating Systems course at Sharif
University of Technology. It is based on the MIT xv6 RISC-V codebase and its
networking lab infrastructure.

The upstream xv6 source and acknowledgments remain available in `README`.
See `LICENSE` for the repository's license terms.
