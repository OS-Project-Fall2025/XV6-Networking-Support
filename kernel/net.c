#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };

static struct spinlock netlock;

// our code
#define MAX_UDP_PYLD 1400
#define MAX_PACKETS 16  // max packet buffer per socket
#define NSOCK 16 // max sock

struct sock {
  int port;              
  int valid;              // is sock in use?
  struct spinlock lock;
  int err;   
  
  //queue for pointers to waiting packet buffers
  char *queue[MAX_PACKETS]; 
  int len[MAX_PACKETS];       // length data in packet
  uint32 src_ip[MAX_PACKETS]; // source IP
  uint16 src_port[MAX_PACKETS]; // source port
  
  int head; // queue header (reads from)
  int tail; // queue tail (writes on)
};

struct sock sockets[NSOCK];
struct spinlock sock_lock; 

// find sock from port
struct sock*
find_socket(uint16 port)
{
  for(int i = 0; i < NSOCK; i++){
    if(sockets[i].valid && sockets[i].port == port){
      return &sockets[i];
    }
  }
  return 0;
}

void
netinit(void)
{
  initlock(&netlock, "netlock");
  
  // protect sock list
  initlock(&sock_lock, "sock_lock"); 
  
  // protect queue / head / tail
  for(int i = 0; i < NSOCK; i++) {
    initlock(&sockets[i].lock, "sock");
  }
}


//
// bind(int port)
// prepare to receive UDP packets addressed to the port.
//
uint64
sys_bind(void)
{
  int port;
  struct sock *s;

  // get port number
  argint(0, &port);

  // lock on sock list
  acquire(&sock_lock);
  
  // check if port alredy has connection to sock
  if(find_socket(port)) {
    release(&sock_lock);
    return -1;
  }

  // find empty sock
  for(int i = 0; i < NSOCK; i++){
    if(!sockets[i].valid){
      // use empty sock
      s = &sockets[i];
      s->port = port;
      s->valid = 1;      
      s->head = 0;      
      s->tail = 0;
      s->err = 0;       
      release(&sock_lock);
      return 0; 
    }
  }

  // no empty sock :(
  release(&sock_lock);
  return -1;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  int port;
  struct sock *s;

  // get port number
  argint(0, &port);

  // lock on sock list
  acquire(&sock_lock);
  s = find_socket(port);
  
  if(s) {
    s->valid = 0;
  }

  release(&sock_lock);
  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.

uint64
sys_recv(void)
{
  int dport, maxlen;
  uint64 src_addr, sport_addr, buf_addr;
  struct sock *s;

  argint(0, &dport);
  argaddr(1, &src_addr);
  argaddr(2, &sport_addr);
  argaddr(3, &buf_addr);
  argint(4, &maxlen);

  // find sock
  acquire(&sock_lock);
  s = find_socket(dport);
  if(!s) {
    release(&sock_lock);
    return -1; 
  }
  
  // lock sock
  acquire(&s->lock);
  release(&sock_lock); 

  // check if there is packet in sock queue
  // if not sleep and wait for it
  while(s->head == s->tail) {
    if(s->err) {
      s->err = 0; // Clear the error immediately (for the next recv - icmp)
      release(&s->lock);
      return -1; // Return -1 to user space
    }
    if(myproc()->killed){
      release(&s->lock);
      return -1;
    }
    sleep(s, &s->lock);
  }

  // dequeue packet
  char *pbuf = s->queue[s->head];
  int plen = s->len[s->head];
  uint32 sip = s->src_ip[s->head];
  uint16 sport = s->src_port[s->head];
  s->head = (s->head + 1) % MAX_PACKETS;
  release(&s->lock);

  // copy data to user space
  // calc copy length
  int to_copy = (plen < maxlen) ? plen : maxlen;
  
  // calc offset to payload
  // Eth Header (14) + IP Header (20) + UDP Header (8) = 42 bytes
  char *payload = pbuf + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);

  //copy : 1. payload 2. sender ip addr 3. sender port 

  if(copyout(myproc()->pagetable, buf_addr, payload, to_copy) < 0 ||
     copyout(myproc()->pagetable, src_addr, (char*)&sip, sizeof(sip)) < 0 ||
     copyout(myproc()->pagetable, sport_addr, (char*)&sport, sizeof(sport)) < 0) {
    // copy failed
    kfree(pbuf); 
    return -1;
  }

  // free kernel buf
  kfree(pbuf);
  
  return to_copy; // return num bytes of copy
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void
ip_rx(char *buf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  struct ip *ip = (struct ip *)(buf + sizeof(struct eth));
  struct udp *udp = (struct udp *)(ip + 1);
  struct sock *s;

  // check packet size
  if(len < sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp)) {
    kfree(buf);
    return;
  }

  // check ip version = 4 and protocol = UDP
  if(ip->ip_vhl != 0x45 || ip->ip_p != IPPROTO_UDP) {
    kfree(buf);
    return;
  }

  // find dest port
  // change network byte order to host byte order
  uint16 dport = ntohs(udp->dport);

  acquire(&sock_lock);
  s = find_socket(dport);
  
  if(s) {
    acquire(&s->lock);
    release(&sock_lock); 

    int next_tail = (s->tail + 1) % MAX_PACKETS;
    
    // check if queue is full
    if(next_tail == s->head) {
      release(&s->lock);
      kfree(buf);
      return;
    }

    // enqueue the packet
    s->queue[s->tail] = buf;
    
    s->len[s->tail] = ntohs(udp->ulen) - sizeof(struct udp); 
    s->src_ip[s->tail] = ntohl(ip->ip_src);                  
    s->src_port[s->tail] = ntohs(udp->sport);                

    s->tail = next_tail;

    // wake up sys_recv
    wakeup(s);

    release(&s->lock);
    return;
  }
  release(&sock_lock);
  kfree(buf);  // no socket for this port, drop packet
}

//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if(seen_arp){
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  char *buf = kalloc();
  if(buf == 0)
    panic("send_arp_reply");
  
  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN); // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
icmp_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *)buf;
  struct ip *ip = (struct ip *)(eth + 1);
  // ICMP header starts after IP header
  struct icmp {
    uint8 type;
    uint8 code;
    uint16 checksum;
    uint32 unused;
  } *icmp = (struct icmp *)(ip + 1);

  // Validation: Ensure packet is long enough to have inner IP + Port
  if(len < sizeof(struct eth) + sizeof(struct ip) + 8 + sizeof(struct ip) + 8) {
    kfree(buf);
    return;
  }

  // Type 3 = Destination Unreachable
  if(icmp->type == 3) {
    // Skip 8 bytes of ICMP header to find the original IP header
    struct ip *inner_ip = (struct ip *)((char *)icmp + 8);
    int inner_ip_len = (inner_ip->ip_vhl & 0x0F) * 4;
    
    // Find the original UDP header to get the port
    struct udp *inner_udp = (struct udp *)((char *)inner_ip + inner_ip_len);
    uint16 local_port = ntohs(inner_udp->sport);

    acquire(&sock_lock);
    struct sock *s = find_socket(local_port);
    if(s) {
      acquire(&s->lock);
      s->err = 1;
      wakeup(s);
      release(&s->lock);
    }
    release(&sock_lock);
  }
  
  kfree(buf); 
}


void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;
  uint16 type = ntohs(eth->type);

  if(type == ETHTYPE_IP){
    struct ip *ip = (struct ip *)(eth + 1);
    
    // Check if it is ICMP (Protocol 1)
    if(ip->ip_p == 1){
      icmp_rx(buf, len); // icmp_rx will handle everything and kfree
      return;
    }
    
    ip_rx(buf, len); 
  } else if(type == ETHTYPE_ARP){
    arp_rx(buf); // arp_rx will do kfree
  } else {
    kfree(buf); // Unknown types must be freed here
  }
}

