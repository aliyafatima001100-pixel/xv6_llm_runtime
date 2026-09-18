//
// Node identity defaults.
//
// This node's IPv4 host octet (10.0.0.XV6_IP_D) and the last octet of its MAC.
// The qemu-node* targets pass -DXV6_IP_D / -DXV6_MAC_LAST to give each node in a
// multi-node topology a distinct identity; these #ifndef defaults make a plain
// `make LAB=net` build (single node, and every regression gate that builds one)
// compile without them. Without a default, kernel/e1000.c and kernel/net.c fail
// to compile outside the qemu-node* targets, which is what silently made the L1
// kernel gate unbuildable on this branch.
//
#ifndef XV6_IP_D
#define XV6_IP_D 2
#endif

#ifndef XV6_MAC_LAST
#define XV6_MAC_LAST 0x56
#endif

//
// endianness support
//

static inline uint16 bswaps(uint16 val)
{
  return (((val & 0x00ffU) << 8) |
          ((val & 0xff00U) >> 8));
}

static inline uint32 bswapl(uint32 val)
{
  return (((val & 0x000000ffUL) << 24) |
          ((val & 0x0000ff00UL) << 8) |
          ((val & 0x00ff0000UL) >> 8) |
          ((val & 0xff000000UL) >> 24));
}

// Use these macros to convert network bytes to the native byte order.
// Note that Risc-V uses little endian while network order is big endian.
#define ntohs bswaps
#define ntohl bswapl
#define htons bswaps
#define htonl bswapl


//
// useful networking headers
//

#define ETHADDR_LEN 6
#define ICMP_DEST_UNREACH   3
#define ICMP_PORT_UNREACH   3

// ICMP message types we recognize (RFC 792). Any other/unknown type is silently
// discarded on receive (RFC 1122 3.2.2), so only these need names here.
#define ICMP_ECHOREPLY      0   // Echo Reply   (we emit this in response to a ping)
#define ICMP_ECHO           8   // Echo Request (a ping addressed to us)

// Defense-in-depth size bound for an inbound/echoed ICMP message (type+code+...+data).
// The mandated ceiling is RFC 791's 16-bit Total Length (<= 65535) and the existing
// "claimed length <= delivered" rule in ip_rx; a single Ethernet frame already caps an
// ICMP message at ~1480 bytes. This tighter bound just rejects abnormally large pings
// (the "ping of death" family is a fragment-reassembly bug, which xv6 has no code for).
#define ICMP_MAX_LEN        1024

// an Ethernet packet header (start of the packet).
struct eth {
  uint8  dhost[ETHADDR_LEN];
  uint8  shost[ETHADDR_LEN];
  uint16 type;
} __attribute__((packed));

#define ETHTYPE_IP  0x0800 // Internet protocol
#define ETHTYPE_ARP 0x0806 // Address resolution protocol

// an IP packet header (comes after an Ethernet header).
struct ip {
  uint8  ip_vhl; // version << 4 | header length >> 2
  uint8  ip_tos; // type of service
  uint16 ip_len; // total length, including this IP header
  uint16 ip_id;  // identification
  uint16 ip_off; // fragment offset field
  uint8  ip_ttl; // time to live
  uint8  ip_p;   // protocol
  uint16 ip_sum; // checksum, covers just IP header
  uint32 ip_src, ip_dst;
};

#define IPPROTO_ICMP 1  // Control message protocol
#define IPPROTO_TCP  6  // Transmission control protocol
#define IPPROTO_UDP  17 // User datagram protocol

#define MAKE_IP_ADDR(a, b, c, d)           \
  (((uint32)a << 24) | ((uint32)b << 16) | \
   ((uint32)c << 8) | (uint32)d)

// a UDP packet header (comes after an IP header).
struct udp {
  uint16 sport; // source port
  uint16 dport; // destination port
  uint16 ulen;  // length, including udp header, not including IP header
  uint16 sum;   // checksum
};

#define UDP_RL_SLOTS  16   // slots in the UDP rate-limit hash table
#define UDP_RL_BURST  8    // tokens per bucket
// refill rate is 1 token per tick

struct udp_bucket {
  uint32 ip;
  uint16 port;
  int    tokens;
  uint   last;
};

/**
 * @brief Rate-limiting parameters for inbound ARP packets, per Ethernet source MAC
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * ARP_RL_SLOTS controls how many distinct source MACs the rate limiter tracks
 * simultaneously. When all slots are occupied the idlest bucket (most tokens,
 * i.e. least recently active) is evicted to make room for the new sender.
 *
 * ARP_RL_BURST is the token-bucket depth: a fresh MAC starts with this many
 * tokens, each ARP packet consumes one, and one token is restored per xv6 tick
 * (~10 Hz). A back-to-back flood from a single MAC is therefore capped at
 * ARP_RL_BURST replies before the sender is throttled.
 *
 * These constants mirror ICMP_RL_SLOTS / ICMP_RL_BURST and UDP_RL_SLOTS /
 * UDP_RL_BURST for consistency across all three rate-limited protocols.
 */
#define ARP_RL_SLOTS  16   // slots in the ARP rate-limit hash table
#define ARP_RL_BURST  8    // tokens per bucket

/**
 * @brief Per-source token bucket for ARP rate limiting
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * One slot in the arp_rl[ARP_RL_SLOTS] table. Keyed on the Ethernet source MAC
 * (6 bytes) rather than an IP address because ARP is a Layer-2 protocol and the
 * MAC is the authoritative identity at that layer.
 *
 * A slot is considered unused when mac is all-zero. The rate-limiter initialises
 * new slots with ARP_RL_BURST tokens and evicts the idlest slot (highest token
 * count) when the table is full, matching the strategy used for ICMP and UDP.
 *
 * Access is protected by arp_rl_lock in net.c.
 */
struct arp_bucket {
    uint8 mac[ETHADDR_LEN]; //< Ethernet source MAC; all-zero = unused slot
    int   tokens;           //< Remaining tokens; decremented on each admitted packet
    uint  last;             //< Tick count at last refill (used to compute elapsed ticks)
};

int arp_lookup(uint32 ip, uint8 *mac_out);

/**
 * @brief One entry in the static ARP binding table used by Dynamic ARP Inspection
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * Associates a known IP address with its trusted MAC address. Entries are
 * compiled into arp_static_table[] in net.c and act as ground truth for DAI:
 * any inbound ARP whose sender IP matches an entry here must also present the
 * matching MAC, or the packet is dropped as a spoofing attempt.
 *
 * IPs not present in the table are accepted without MAC validation (fail-open),
 * keeping the kernel functional for hosts that are not pre-registered.
 *
 * @note ip is stored in host byte order (consistent with local_ip and the rest
 * of the network stack). mac holds the raw 6-byte hardware address.
 */
struct arp_entry {
    uint32 ip;               //< IP address in host byte order
    uint8  mac[ETHADDR_LEN]; //< Trusted Ethernet MAC address for this IP
};

// an ARP packet (comes after an Ethernet header).
struct arp {
  uint16 hrd; // format of hardware address
  uint16 pro; // format of protocol address
  uint8  hln; // length of hardware address
  uint8  pln; // length of protocol address
  uint16 op;  // operation

  char   sha[ETHADDR_LEN]; // sender hardware address
  uint32 sip;              // sender IP address
  char   tha[ETHADDR_LEN]; // target hardware address
  uint32 tip;              // target IP address
} __attribute__((packed));

#define ARP_HRD_ETHER 1 // Ethernet

enum {
  ARP_OP_REQUEST = 1, // requests hw addr given protocol addr
  ARP_OP_REPLY = 2,   // replies with the hw addr of the protocol addr
};

// an DNS packet (comes after an UDP header).
struct dns {
  uint16 id;  // request ID

  uint8 rd: 1;  // recursion desired
  uint8 tc: 1;  // truncated
  uint8 aa: 1;  // authoritive
  uint8 opcode: 4; 
  uint8 qr: 1;  // query/response
  uint8 rcode: 4; // response code
  uint8 cd: 1;  // checking disabled
  uint8 ad: 1;  // authenticated data
  uint8 z:  1;  
  uint8 ra: 1;  // recursion available
  
  uint16 qdcount; // number of question entries
  uint16 ancount; // number of resource records in answer section
  uint16 nscount; // number of NS resource records in authority section
  uint16 arcount; // number of resource records in additional records
} __attribute__((packed));

struct dns_question {
  uint16 qtype;
  uint16 qclass;
} __attribute__((packed));
  
#define ARECORD (0x0001)
#define QCLASS  (0x0001)

struct dns_data {
  uint16 type;
  uint16 class;
  uint32 ttl;
  uint16 len;
} __attribute__((packed));

struct icmp {
  uint8  type;     // message type
  uint8  code;     // type sub-code
  uint16 checksum;
  uint16 id;
  uint16 seq;
};

//
// ICMP generation rate limiting, per remote IP (a simple token bucket).
//
// RFC 1812 4.3.2.8 requires a *router* to limit the rate at which it generates ICMP
// messages. For a host this is not strictly mandated, but it is standard OS-level
// practice (Linux net.ipv4.icmp_ratelimit / icmp_msgs_per_sec; BSD net.inet.icmp.icmplim)
// and is exactly the mitigation used against UDP floods, where the storm of ICMP
// port-unreachable replies the host would otherwise emit is throttled. We therefore
// rate-limit the ICMP we *send* (echo replies and port-unreachable errors), per peer.
//
// Caveat: under a real flood this may also drop a few legitimate replies, and it does
// nothing when the bottleneck is an upstream firewall's connection-state table.
//
#define ICMP_RL_SLOTS 16 // distinct remote IPs remembered (idlest slot is evicted)
#define ICMP_RL_BURST 8  // bucket depth: max back-to-back ICMP sent to one peer

struct icmp_bucket {
  uint32 ip;     // remote IP (host byte order); 0 means the slot is unused
  int    tokens; // tokens currently available
  uint   last;   // tick count at last refill
};

struct udp_pseudo_hdr {
  uint32 src_ip;
  uint32 dst_ip;
  uint8  zero;
  uint8  proto;
  uint16 udp_len;
};

// Result codes
#define FILTER_ACCEPT  0
#define FILTER_DROP    1

// A trusted interface binding: packets arriving on iface_id
// must have source IPs within net/mask.
struct iface_rule {
    uint32 iface_id;   // interface index (0 = only one NIC in xv6)
    uint32 net;        // expected source network (host byte order)
    uint32 mask;       // subnet mask (host byte order)
};

// Bogon filter rules: packets with source IPs in these reserved ranges are dropped.
// Purposely left out   (((ip) & 0xFF000000) == 0x0A000000) ||         /* 10.0.0.0/8      private RFC 1918 */
//   (((ip) & 0xFF000000) == 0x7F000000) ||         /* 127.0.0.0/8     loopback */ 

#define IS_BOGON(ip) ( \
  ((ip) == 0x00000000) ||                        /* 0.0.0.0/8       RFC 1122 */ \
  (((ip) & 0xFFC00000) == 0x64400000) ||         /* 100.64.0.0/10   shared address RFC 6598 */ \
  (((ip) & 0xFFF00000) == 0xAC100000) ||         /* 172.16.0.0/12   private RFC 1918 */ \
  (((ip) & 0xFFFF0000) == 0xC0A80000) ||         /* 192.168.0.0/16  private RFC 1918 */ \
  (((ip) & 0xFFFF0000) == 0xA9FE0000) ||         /* 169.254.0.0/16  link-local RFC 3927 */ \
  (((ip) & 0xFFFFFF00) == 0xC0000200) ||         /* 192.0.2.0/24    TEST-NET RFC 5737 */ \
  (((ip) & 0xFF000000) == 0xE0000000) ||         /* 224.0.0.0/4     multicast RFC 5771 */ \
  ((ip) == 0xFFFFFFFF)                           /* 255.255.255.255 broadcast */ \
)


// Reassemly
#define MAX_REASM_SESSIONS   32     // max concurrent incomplete datagrams
#define REASM_TIMEOUT_TICKS  150    // 15s at 10 Hz (RFC 1122 minimum)
#define REASM_MAX_DGRAM      65535  // IPv4 maximum datagram size (RFC 791)
#define REASM_MAX_FRAGS      64     // per-session fragment cap (DoS guard)
#define IP_MF       0x2000    // more fragments flag
#define IP_OFFMASK  0x1FFF    // fragment offset mask

// Link MTU used by the send path: an IP datagram larger than this is fragmented
// on transmit (sys_send), since the e1000 RX buffers are one page with no
// long-packet mode and would drop an over-MTU frame. 1500 is the standard
// Ethernet payload; the receive path reassembles fragments back (RFC 791).
#define IP_SEND_MTU 1500

// A single received fragment within a reassembly session
struct fragment {
    struct fragment *next;
    uint16 offset;      // fragment offset in bytes (already * 8)
    uint16 len;         // payload length of this fragment
    char  *data;        // kalloc'd copy of this fragment's data
};

// One reassembly session = one incomplete fragmented datagram
struct reasm_session {
    uint8   inuse;
    uint32  src_ip;     // RFC 791: key is (src, dst, proto, id)
    uint32  dst_ip;
    uint16  ip_id;
    uint8   proto;

    uint    expires;            // ticks deadline (set on first fragment)
    int     total_len;          // set when we receive the last fragment (MF=0)
    int     frag_count;         // DoS guard: drop session if too many fragments
    struct  fragment *frags;    // list of received fragments, sorted by offset
};

/**
 * @brief Maximum number of UDP ports supported by the network stack
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * Defines the total number of UDP ports available in the system, spanning the complete
 * IANA-defined port range from 0 to 65535. This encompasses:
 * - Well-known ports: 0-1023 (system services and privileged applications)
 * - Registered ports: 1024-49151 (user applications and services)  
 * - Dynamic/private ports: 49152-65535 (ephemeral client connections)
 * 
 * The value 65536 represents the total number of distinct port numbers available
 * in the 16-bit UDP port field (2^16 = 65536 possible values).
 * 
 * This constant is used to size the udp_ports array that tracks port allocation
 * state and manages packet queues for each potential UDP port:
 * - struct udp_port udp_ports[UDP_PORTS]
 * - Provides O(1) access to any port's state and packet queue
 * - Enables efficient port validation (port < UDP_PORTS)
 * 
 * @note Port 0 is technically valid but rarely used in practice, as it typically
 * indicates an ephemeral port assignment by the operating system.
 * 
 * @remark
 * While a sparse data structure might conserve memory for typically unused ports,
 * the array approach provides simplicity and constant-time access crucial for
 * network performance. The memory overhead is acceptable for the xv6 environment.
 */
#define UDP_PORTS 65536

void net_rx(char *pkt, int len);