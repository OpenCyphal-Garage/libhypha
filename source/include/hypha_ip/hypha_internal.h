#ifndef HYPHA_IP_INTERNAL_H_
#define HYPHA_IP_INTERNAL_H_

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The internal include file for the Hypha IP stack. This includes all the
/// definitions and structures necessary to use the stack which don't need to
/// shared with the client.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_ip.h"

#ifndef HYPHA_IP_ARP_TABLE_SIZE
/// The number of ARP entries to keep in the ARP table
#define HYPHA_IP_ARP_TABLE_SIZE 32
#endif

#ifndef HYPHA_IP_IPv4_FILTER_TABLE_SIZE
/// The number of entries to keep in the IP Address filter table
#define HYPHA_IP_IPv4_FILTER_TABLE_SIZE 32
#endif

#ifndef HYPHA_IP_MAC_FILTER_TABLE_SIZE
/// The number of entries to keep in the Ethernet MAC filter table
#define HYPHA_IP_MAC_FILTER_TABLE_SIZE 32
#endif

#ifndef HYPHA_IP_USE_IP_CHECKSUM
/// Whether to use the IP Checksum in the IPv4 header
#define HYPHA_IP_USE_IP_CHECKSUM (true)
#endif

#ifndef HYPHA_IP_USE_UDP_CHECKSUM
/// Whether to use the UDP Checksum in the UDP header (optional)
#define HYPHA_IP_USE_UDP_CHECKSUM (false)
#endif

#ifndef HYPHA_IP_ALLOW_ANY_LOCALHOST
/// Whether to allow any localhost address in the Hypha IP stack for both ethernet and IPv4.
/// @note This is could be a security risk, and should only be used in trusted environments
#define HYPHA_IP_ALLOW_ANY_LOCALHOST (1)
#endif

#ifndef HYPHA_IP_ALLOW_ANY_MULTICAST
/// Whether to use Multicast in the Hypha IP stack for both ethernet and IPv4.
#define HYPHA_IP_ALLOW_ANY_MULTICAST (1)
#endif

#ifndef HYPHA_IP_ALLOW_ANY_BROADCAST
/// Whether to allow any broadcast address in the Hypha IP stack for both ethernet and IPv4.
#define HYPHA_IP_ALLOW_ANY_BROADCAST (0)
#endif

#ifndef HYPHA_IP_USE_MAC_FILTER
/// Whether to use the MAC Filter in the Hypha IP stack
#define HYPHA_IP_USE_MAC_FILTER (1)
#endif

#ifndef HYPHA_IP_USE_IP_FILTER
/// Whether to use the IP Filter in the Hypha IP stack
#define HYPHA_IP_USE_IP_FILTER (1)
#endif

#ifndef HYPHA_IP_USE_ARP_CACHE
/// Whether to use the ARP Cache in the Hypha IP stack
#define HYPHA_IP_USE_ARP_CACHE (1)
#endif

#ifndef HYPHA_IP_EXPIRATION_TIME
/// The default expiration time for ARP and IP Filter entries in Timestamp_t units. If these were milliseconds this
/// would be 31.7 years.
#define HYPHA_IP_EXPIRATION_TIME 1'000'000'000'000U
#endif

static_assert(HYPHA_IP_MTU >= 64U, "The MTU must be greater than 64 bytes");
static_assert(HYPHA_IP_TTL > 0U, "The TTL must be greater than 0");
static_assert(HYPHA_IP_ARP_TABLE_SIZE > 0U, "The ARP table size must be greater than 0");
static_assert(HYPHA_IP_IPv4_FILTER_TABLE_SIZE > 0U, "The IP filter table size must be greater than 0");
static_assert(HYPHA_IP_MAC_FILTER_TABLE_SIZE > 0U, "The MAC filter table size must be greater than 0");
static_assert(HYPHA_IP_EXPIRATION_TIME > 0U, "The expiration time must be greater than 0");
static_assert(HYPHA_IP_VLAN_ID >= 0U && HYPHA_IP_VLAN_ID <= 4095U, "The VLAN ID must be 0 <= x <= (2^12)-1");
static_assert(HYPHA_IP_ALLOW_ANY_BROADCAST == 0 || HYPHA_IP_ALLOW_ANY_BROADCAST == 1,
              "HYPHA_IP_ALLOW_ANY_BROADCAST must be 0 or 1 to enable or disable broadcast support");
static_assert(HYPHA_IP_ALLOW_ANY_MULTICAST == 0 || HYPHA_IP_ALLOW_ANY_MULTICAST == 1,
              "HYPHA_IP_ALLOW_ANY_MULTICAST must be 0 or 1 to enable or disable multicast support");
static_assert(HYPHA_IP_USE_MAC_FILTER == 0 || HYPHA_IP_USE_MAC_FILTER == 1,
              "HYPHA_IP_USE_MAC_FILTER must be 0 or 1 to enable or disable MAC filtering");
static_assert(HYPHA_IP_USE_IP_FILTER == 0 || HYPHA_IP_USE_IP_FILTER == 1,
              "HYPHA_IP_USE_IP_FILTER must be 0 or 1 to enable or disable IP filtering");
static_assert(HYPHA_IP_USE_ARP_CACHE == 0 || HYPHA_IP_USE_ARP_CACHE == 1,
              "HYPHA_IP_USE_ARP_CACHE must be 0 or 1 to enable or disable ARP caching");
static_assert(HYPHA_IP_USE_VLAN == 0 || HYPHA_IP_USE_VLAN == 1,
              "HYPHA_IP_USE_VLAN must be 0 or 1 to enable or disable VLAN support");

/// The Checksum enumeration special values
typedef enum HyphaIpChecksum : uint16_t {
    HyphaIpChecksumDisabled = 0x0000U,  ///< The checksum is disabled
    HyphaIpChecksumValid = 0xFFFFU,     ///< The checksum must match this to be valid.
} HyphaIpChecksum_e;

/// The list of supported IP layer protocols
typedef enum HyphaIpProtocol : uint16_t {
    HyphaIpProtocol_ICMP = 0x01,  ///< Internet Control Message Protocol
    HyphaIpProtocol_IGMP = 0x02,  ///< Internet Group Management Protocol
    HyphaIpProtocol_UDP = 0x11,   ///< User Datagram Protocol
} HyphaIpProtocol_e;

/// The IPv4 Header definition
/// @note This is listed in LSB local order in some areas and in network order in others. DO NOT CHECKSUM THIS
/// STRUCTURE!
typedef struct HyphaIpIPv4Header {
    uint16_t IHL : 4;                  ///<  Internet Header Length
    uint16_t version : 4;              ///<  Internal Protocol Header Version (must be 4)
    uint16_t ECN : 2;                  ///<  Explicit Congestion Notification
    uint16_t DSCP : 6;                 ///<  Differentiated Services Code Point
    uint16_t length;                   ///<  The length in bytes of the header + the payload
    uint16_t identification;           ///<  Used by fragmentation algorithms to identify fragments
    uint16_t zero : 1;                 ///<  Reserved. Set to zero.
    uint16_t DF : 1;                   ///<  Do not Fragment
    uint16_t MF : 1;                   ///<  More Fragments
    uint16_t fragment_offset : 13;     ///<  The offset which a fragment is within the overall packet. Not used here.
    uint16_t TTL : 8;                  ///<  The time to live. @ref HYPHA_IP_TTL for the default value
    uint16_t protocol : 8;             ///<  @ref HyphaIpProtocol_e
    uint16_t checksum;                 ///<  the 1's compliment checksum.
    HyphaIpIPv4Address_t source;       ///<  The source address
    HyphaIpIPv4Address_t destination;  ///<  The destination address
} HyphaIpIPv4Header_t;
static_assert(sizeof(HyphaIpIPv4Header_t) == 20U, "Must be this size, no options allowed");

/// The maximum number of bytes for a IP packet
#define HYPHA_IP_MAX_IP_PACKET_SIZE (HYPHA_IP_MAX_ETHERNET_FRAME_SIZE - sizeof(HyphaIpIPv4Header_t))

/// The IPv4 Packet
typedef struct HyphaIpIPv4Packet {
    HyphaIpIPv4Header_t header;                    ///< the IPv4 Header
    uint8_t payload[HYPHA_IP_MAX_IP_PACKET_SIZE];  ///< The IPv4 Payload, usually is the UDP datagram.
} HyphaIpIPv4Packet_t;

/// The UDP Header Definition
typedef struct HyphaIpUDPHeader {
    uint16_t source_port;       ///<  Source Port, usually doesn't matter
    uint16_t destination_port;  ///<  Destination Port, usually matters
    uint16_t length;            ///<  In Bytes
    uint16_t checksum;          ///<  Over data as uint16_t's!
} HyphaIpUdpHeader_t;

/// The maximum number of bytes for a UDP datagram
#define HYPHA_IP_MAX_UDP_DATAGRAM_SIZE (HYPHA_IP_MAX_IP_PACKET_SIZE - sizeof(HyphaIpUdpHeader_t))

/// The UDP Datagram definition
typedef struct HyphaIpUDPDatagram {
    HyphaIpUdpHeader_t header;                        ///< The UDP Header
    uint8_t payload[HYPHA_IP_MAX_UDP_DATAGRAM_SIZE];  ///< The UDP Payload
} HyphaIpUdpDatagram_t;

/// The List of ICMP Types
typedef enum HyphaIpIcmpType : uint8_t {
    HyphaIpIcmpTypeEchoReply = 0x00,               ///<  Echo Reply
    HyphaIpIcmpTypeDestinationUnreachable = 0x03,  ///<  Destination Unreachable
    HyphaIpIcmpTypeSourceQuench = 0x04,            ///<  Source Quench
    HyphaIpIcmpTypeRedirect = 0x05,                ///<  Redirect
    HyphaIpIcmpTypeEchoRequest = 0x08,             ///<  Echo Request
    HyphaIpIcmpTypeTimeExceeded = 0x0B,            ///<  Time Exceeded
    HyphaIpIcmpTypeParameterProblem = 0x0C,        ///<  Parameter Problem
} HyphaIpICMPType_e;

/// The List of ICMP Codes
typedef enum HyphaIpIcmpCode : uint8_t {
    HyphaIpIcmpCodeNoCode = 0x00,               ///<  No Code
    HyphaIpIcmpCodeNetworkUnreachable = 0x00,   ///<  Network Unreachable
    HyphaIpIcmpCodeHostUnreachable = 0x01,      ///<  Host Unreachable
    HyphaIpIcmpCodeProtocolUnreachable = 0x02,  ///<  Protocol Unreachable
    HyphaIpIcmpCodePortUnreachable = 0x03,      ///<  Port Unreachable
    HyphaIpIcmpCodeFragmentationNeeded = 0x04,  ///<  Fragmentation Needed
} HyphaIpICMPCode_e;

/// The ICMP Header
typedef struct HyphaIpICMPHeader {
    uint8_t type;       ///< The ICMP Type, see @ref HyphaIpICMPType_e */
    uint8_t code;       ///< The ICMP Code, see @ref HyphaIpICMPCode_e */
    uint16_t checksum;  ///< The ICMP Checksum, computed over the entire datagram
} HyphaIpICMPHeader_t;
static_assert(sizeof(HyphaIpICMPHeader_t) == 4U, "Must be this size");

/// The ICMP Datagram definition
typedef struct HyphaIpICMPDatagram {
    HyphaIpICMPHeader_t header;  ///< The ICMP header
    uint8_t payload[64];         ///< The ICMP Payload, can be anything, but usually is the UDP datagram.
} HyphaIpICMPDatagram_t;

/// The ARP Hardware Types
typedef enum HyphaIpArpHardwareType : uint16_t {
    HyphaIpArpHardwareTypeEthernet = 0x0001,  ///<  Ethernet
} HyphaIpArpHardwareType_e;

/// The ARP Protocol (Software) Types
typedef enum HyphaIpArpProtocolType : uint16_t {
    HyphaIpArpProtocolTypeIPv4 = 0x0800,  ///<  IPv4
} HyphaIpArpProtocolType_e;

/// The ARP Operation Types
typedef enum HyphaIpArpOperation : uint16_t {
    HyphaIpArpOperationRequest = 0x0001,  ///<  ARP Request
    HyphaIpArpOperationReply = 0x0002,    ///<  ARP Reply
} HyphaIpArpOperation_e;

/// The ARP packet
typedef struct HyphaIpARPPacket {
    uint16_t hardware_type;                    ///<  @ref HyphaIpArpHardwareType
    uint16_t protocol_type;                    ///<  @ref HyphaIpArpProtocolType
    uint16_t hardware_length : 8;              ///< The hardware address length
    uint16_t protocol_length : 8;              ///< The protocol address length
    uint16_t operation;                        ///<  @ref HyphaIpArpOperation
    HyphaIpEthernetAddress_t sender_hardware;  ///< The sender hardware address
    HyphaIpIPv4Address_t sender_protocol;      ///< The sender protocol address
    HyphaIpEthernetAddress_t target_hardware;  ///< The target hardware address
    HyphaIpIPv4Address_t target_protocol;      ///< the target protocol address
} HyphaIpArpPacket_t;
static_assert(sizeof(HyphaIpArpPacket_t) == 28U, "Must be this size");

/// The Address Resolution Protocol Entry in the Cache
typedef struct HyphaIpARPEntry {
    bool valid;                     ///< Is the address valid
    HyphaIpTimestamp_t expiration;  ///< A time in the future when this expires
    HyphaIpAddressMatch_t match;    ///< The address match information
} HyphaIpARPEntry_t;

/// A structure control
typedef struct HyphaIpEthernetFilter {
    bool valid;                     ///<  Is this entry valid?
    HyphaIpTimestamp_t expiration;  ///<  A time in the future when this expires
    HyphaIpEthernetAddress_t mac;   ///<  The Ethernet Address
} HyphaIpEthernetFilter_t;

/// The IPv4 Address Filter Entry
typedef struct HyphaIpIPv4Filter {
    bool valid;                     ///<  Is this entry valid?
    HyphaIpTimestamp_t expiration;  ///<  A time in the future when this expires
    HyphaIpIPv4Address_t ipv4;      ///<  The IPv4 Address
} HyphaIpIPv4Filter_t;

/// THe UDP Header checksum is computed over this structure + the payload
typedef struct HyphaIpPseudoHeader {
    HyphaIpIPv4Address_t source;       ///<  The Source Address
    HyphaIpIPv4Address_t destination;  ///<  The Destination Address
    uint8_t zero;                      ///<  A reserved tree
    uint8_t protocol;                  ///<  Likely UDP here
    uint16_t length;                   ///<  The length of the packet in bytes
    HyphaIpUdpHeader_t header;         ///<  The UDP Header
} HyphaIpPseudoHeader_t;

/// The IGMP Packet
typedef struct HyphaIpIgmpPacket {
    uint32_t type : 8;               ///<  IGMP Type
    uint32_t max_response_time : 8;  ///<  Max Response Time
    uint32_t checksum : 16;          ///<  Checksum
    HyphaIpIPv4Address_t group;      ///<  Group Address
} HyphaIpIgmpPacket_t;

/// The IGMP Codes
typedef enum HyphaIpIgmpType : uint8_t {
    HyphaIpIgmpTypeQuery = 0x11,      ///< Perform a query
    HyphaIpIgmpTypeReport_v1 = 0x12,  ///< Report Group Membership v1
    HyphaIpIgmpTypeReport_v2 = 0x16,  ///< Report Group Membership v2
    HyphaIpIgmpTypeLeave = 0x17,      ///< Leave Group
    HyphaIpIgmpTypeReport_v3 = 0x22,  ///< Report Group Membership v3
} HyphaIpIgmpType_e;

/// The Hypha IP Features
typedef struct HyphaIpFeatures {
    /// Enables allowing any localhost through
    bool allow_any_localhost;
    /// Enables allowing any multicast through
    bool allow_any_multicast;
    /// Enables allowing any broadcast through
    bool allow_any_broadcast;
    /// Enables the MAC software filter. If pre-filtered by hardware, disable filtering here.
    bool allow_mac_filtering;
    /// Enables the IP software filter. If pre-filtered by hardware, disable filtering here.
    bool allow_ip_filtering;
    /// Enables the ARP cache. If pre-filtered by hardware, disable caching here.
    bool allow_arp_cache;
#if (HYPHA_IP_USE_VLAN == 1)
    /// Enables the VLAN filtering. If pre-filtered by hardware, disable filtering here.
    bool allow_vlan_filtering;
#endif
} HyphaIpFeatures_t;

/// Our internal context for the Stack
struct HyphaIpContext {
    HyphaIpPrintInfo_t debugging;         ///<  The debugging mask for this stack
    HyphaIpNetworkInterface_t interface;  ///< The Network interface given to the context
    HyphaIpExternalContext_t theirs;      ///< The external context to give to the external interfaces
    HyphaIpExternalInterface_t external;  ///< The structure of interface pointers for external functions.
    HyphaIpFeatures_t features;           ///<  The features of this stack
#if (HYPHA_IP_USE_MAC_FILTER == 1)
    /// The Allow list of ethernet addresses, only used if allow_mac_filtering==true
    HyphaIpEthernetFilter_t allowed_ethernet_addresses[HYPHA_IP_MAC_FILTER_TABLE_SIZE];
#endif
#if (HYPHA_IP_USE_IP_FILTER == 1)
    /// The Allow list of IPv4 addresses, only used if allow_ip_filtering==true
    HyphaIpIPv4Filter_t allowed_ipv4_addresses[HYPHA_IP_IPv4_FILTER_TABLE_SIZE];
#endif
#if (HYPHA_IP_USE_ARP_CACHE == 1)
    /// The Address Resolution Protocol Cache of Addresses Matches
    HyphaIpARPEntry_t arp_cache[HYPHA_IP_ARP_TABLE_SIZE];
#endif
    /// The statistics and metrics structure
    HyphaIpStatistics_t statistics;
};

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// INTERNAL API
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// @return The offset of the IP Header in the Ethernet Frame
size_t HyphaIpOffsetOfIPHeader(void);

/// @return The offset of the UDP Header in the Ethernet Frame
size_t HyphaIpOffsetOfUpdHeader(void);

/// @return The offset of the ICMP Datagram in the Ethernet Frame
size_t HyphaIpOffsetOfIcmpDatagram(void);

/// @return The offset of the UDP Datagram in the Ethernet Frame
size_t HyphaIpOffsetOfUpdDatagram(void);

/// @return True if the Ethernet Addresses are the same, false otherwise
bool HyphaIpIsSameEthernetAddress(HyphaIpEthernetAddress_t mac1, HyphaIpEthernetAddress_t mac2);

/// @return True if the MAC address is a local Ethernet address, false otherwise
bool HyphaIpIsLocalEthernetAddress(HyphaIpEthernetAddress_t mac);

/// @return True if the MAC is a multicast mac address, false otherwise
bool HyphaIpIsMulticastEthernetAddress(HyphaIpEthernetAddress_t mac);

/// @return True if the IP addresses are the same.
bool HyphaIpIsSameIPv4Address(HyphaIpIPv4Address_t a, HyphaIpIPv4Address_t b);

/// @return True if the address is our interface address
bool HyphaIpIsOurIPv4Address(HyphaIpContext_t context, HyphaIpIPv4Address_t address);

/// @return True if the address is a limited local broadcast
bool HyphaIpIsLimitedBroadcastIPv4Address(HyphaIpIPv4Address_t address);

/// @return True if the address is in the same network as our interface is
bool HyphaIpIsInOurNetwork(HyphaIpContext_t context, HyphaIpIPv4Address_t ipv4);

/// @return True if the address is a private address
bool HyphaIpIsPrivateIPv4Address(HyphaIpIPv4Address_t address);

/// @return True if the address is in the given network
bool HyphaIpIsInNetwork(HyphaIpIPv4Address_t ipv4, uint32_t network, uint32_t netmask);

/// @return uint32_t The Address as a 32 bit number.
uint32_t HyphaIpIPv4AddressToValue(HyphaIpIPv4Address_t ipv4);

/// @return HyphaIpIPv4Address_t The Address from a 32 bit number.
HyphaIpIPv4Address_t HyphaIpValueToIPv4Address(uint32_t value);

/// @return True if the ip address can be converted to a multicast MAC address
bool HyphaIpConvertMulticast(HyphaIpEthernetAddress_t *mac, HyphaIpIPv4Address_t ip);

/// @return True if the address is in the Allowed IP Source Table.
bool HyphaIpIsPermittedIPv4Address(HyphaIpContext_t context, HyphaIpIPv4Address_t address);

/// @return True if the address is routable off the network, i.e. not private
bool HyphaIpIsRoutableIPv4Address(HyphaIpIPv4Address_t address);

/// @return True if the MAC address is our interface's.
bool HyphaIpIsOurEthernetAddress(HyphaIpContext_t context, HyphaIpEthernetAddress_t mac);

/// @brief Checks if the given Ethernet address is a permitted address.
bool HyphaIpIsPermittedEthernetAddress(HyphaIpContext_t context, HyphaIpEthernetAddress_t mac);

/// @return True if the MAC address is a local broadcast.
bool HyphaIpIsLocalBroadcastEthernetAddress(HyphaIpEthernetAddress_t mac);

/// @return True if the MAC address is a unicast address, false otherwise
bool HyphaIpIsUnicastEthernetAddress(HyphaIpEthernetAddress_t mac);

/// @return True if the MAC address is a multicast address, false otherwise
bool HyphaIpIsMulticastEthernetAddress(HyphaIpEthernetAddress_t mac);

/// @return True if the MAC address is a locally administered address, false otherwise
bool HyphaIpIsLocallyAdministeredEthernetAddress(HyphaIpEthernetAddress_t mac);

/// @return True if the address is a local host address, false otherwise
bool HyphaIpIsLocalhostIPv4Address(HyphaIpIPv4Address_t address);

/// @return True if the address is a multicast address, false otherwise
bool HyphaIpIsMulticastIPv4Address(HyphaIpIPv4Address_t address);

/// @return True if the address is a reserved address, false otherwise
bool HyphaIpIsReservedIPv4Address(HyphaIpIPv4Address_t address);

/// @return A span covering the IP Header within the Ethernet Frame
HyphaIpSpan_t HyphaIpSpanIpHeader(HyphaIpEthernetFrame_t *frame);

/// @return A span covering the UDP Header within the Ethernet Frame
HyphaIpSpan_t HyphaIpSpanUdpHeader(HyphaIpEthernetFrame_t *frame);

/// @return A span covering the UDP Payload of the Datagram within the Ethernet Frame
HyphaIpSpan_t HyphaIpSpanUdpPayload(HyphaIpEthernetFrame_t *frame);

/// @brief Copies the Ethernet Header from the frame to the destination.
/// @param dst The destination Ethernet Header
/// @param src The source Ethernet Frame
void HyphaIpCopyEthernetHeaderFromFrame(HyphaIpEthernetHeader_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the Ethernet Header from the source to the frame.
/// @param dst The destination Ethernet Frame
/// @param src The source Ethernet Header
void HyphaIpCopyEthernetHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpEthernetHeader_t const *src);

/// @brief Copies the IP Header from the Ethernet Frame
/// @param dst The destination IP Header
/// @param src The source Ethernet Frame
void HyphaIpCopyIPHeaderFromFrame(HyphaIpIPv4Header_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the IP Header to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param src The source IP Header
void HyphaIpCopyIPHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpIPv4Header_t const *src);

/// @brief Copies the UDP Header from the Ethernet Frame
/// @param dst The destination UDP Header
/// @param src The source Ethernet Frame
void HyphaIpCopyUdpHeaderFromFrame(HyphaIpUdpHeader_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the UDP Header to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param src The source UDP Header
void HyphaIpCopyUdpHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpUdpHeader_t const *src);

/// @brief Copies the UDP Datagram from the Ethernet Frame
/// @param dst The destination UDP Datagram
/// @param src The source Ethernet Frame
void HyphaIpCopyUdpDatagramFromFrame(uint8_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the UDP Datagram to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param span The span of the UDP Datagram to copy
void HyphaIpCopyUdpDatagramToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpSpan_t span);

/// @brief Copies the ICMP Header from the Ethernet Frame
/// @param dst The destination ICMP Header
/// @param src The source Ethernet Frame
void HyphaIpCopyIcmpHeaderFromFrame(HyphaIpICMPHeader_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the ICMP Header to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param src The source ICMP Header
void HyphaIpCopyIcmpHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpICMPHeader_t const *src);

/// @brief Copies the ICMP Datagram from the Ethernet Frame
/// @param dst The destination ICMP Datagram
/// @param src The source Ethernet Frame
void HyphaIpCopyIcmpDatagramFromFrame(uint8_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the ICMP Datagram to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param src The source ICMP Datagram
void HyphaIpCopyIcmpDatagramToFrame(HyphaIpEthernetFrame_t *dst, uint8_t const *src);

/// @brief Copies the ARP Packet from the Ethernet Frame
/// @param dst The destination ARP Packet
/// @param src The source Ethernet Frame
void HyphaIpCopyArpPacketFromFrame(HyphaIpArpPacket_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the ARP Packet to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param src The source ARP Packet
void HyphaIpCopyArpPacketToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpArpPacket_t const *src);

/// @brief Updates the IP Checksum in the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param checksum The checksum to write into the frame
void HyphaIpUpdateIpChecksumInFrame(HyphaIpEthernetFrame_t *dst, uint16_t checksum);

/// @brief Copies the IGMP Packet from the Ethernet Frame
/// @param dst The destination IGMP Packet
/// @param src The source Ethernet Frame
void HyphaIpCopyIgmpPacketFromFrame(HyphaIpIgmpPacket_t *dst, HyphaIpEthernetFrame_t *src);

/// @brief Copies the IGMP Packet to the Ethernet Frame
/// @param dst The destination Ethernet Frame
/// @param src The source IGMP Packet
void HyphaIpCopyIgmpPacketToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpIgmpPacket_t const *src);

/// A unit of memory which can be flipped
typedef struct HyphaIpFlipUnit {
    uint8_t bytes;  ///<  How many bytes in the unit
    uint8_t units;  ///<  How many units to flip
} HyphaIpFlipUnit_t;

/// @brief Copies memory from source to destination, flipping the bytes according to the flip_units.
/// This is used to handle endianness and byte order issues in network protocols.
/// The flip_units array defines how many bytes to flip and how many units to copy.
/// @param num_flip_units the number of flip units in the array
/// @param flip_units The array of flip units, each defining how many bytes to flip and how many units to
/// copy.
/// @param destination the destination pointer where the flipped data will be copied
/// @param source the source pointer from which the data will be copied from
/// @return size_t The number of bytes copied to the destination.
/// @note The function assumes that the destination has enough space to hold the flipped data.
size_t HyphaIpFlipCopy(size_t num_flip_units, HyphaIpFlipUnit_t const flip_units[num_flip_units], void *destination,
                       void const *source);

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// ETHERNET
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

/// @brief Transmits an Ethernet Frame over the Network Interface
/// This will pass the frame down the stack if accepted.
/// @param context The Hypha IP context
/// @param frame The Ethernet Frame to transmit
/// @param metadata The metadata for the frame
/// @param ether_type The Ethernet Type to use (e.g., IPv4, ARP)
/// @param payload_length The length of the payload in the frame (including the Ethernet header)
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpEthernetTransmitFrame(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                             HyphaIpMetaData_t *metadata, HyphaIpEtherType_e ether_type,
                                             size_t payload_length);

/// @brief Receives an Ethernet Frame from the Network Interface
/// This will pass the frame up the stack if accepted.
/// @param context The Hypha IP context
/// @param frame The Ethernet Frame to receive
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpEthernetReceiveFrame(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame);

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// IP
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

/// @brief Receives an IPv4 Packet from the Ethernet Frame
/// This will pass the packet up the stack if accepted.
/// @param context The Hypha IP context
/// @param frame The Ethernet Frame containing the IPv4 Packet
/// @param timestamp The timestamp of the packet
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpIPv4ReceivePacket(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                         HyphaIpTimestamp_t timestamp);

/// @brief Transmits an IPv4 Packet over the Ethernet Frame
/// @param context The Hypha IP context
/// @param frame The Ethernet Frame to transmit the packet in
/// @param metadata The metadata for the packet
/// @param ip_protocol The IP Protocol to use (e.g., UDP, ICMP)
/// @param packet The packet to transmit, which contains the subheader and payload
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpIPv4TransmitPacket(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                          HyphaIpMetaData_t *metadata, HyphaIpProtocol_e ip_protocol,
                                          HyphaIpSpan_t packet);

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// UDP (transmit is an external function)
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

/// @brief Receives a UDP Datagram from the Ethernet Frame
/// @param context The Hypha IP context
/// @param header The IPv4 Header of the Datagram
/// @param timestamp The timestamp of the packet
/// @param frame The Ethernet Frame containing the UDP Datagram
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpUdpReceiveDatagram(HyphaIpContext_t context, HyphaIpIPv4Header_t *header,
                                          HyphaIpTimestamp_t timestamp, HyphaIpEthernetFrame_t *frame);

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// ARP
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

/// @brief Processes an incoming ARP packet
/// @param context The Hypha IP context
/// @param frame The Ethernet Frame containing the ARP packet
/// @param timestamp The timestamp of the packet
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpArpProcessPacket(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                        HyphaIpTimestamp_t timestamp);

/// @brief Sends an ARP Announcement (request for itself)
/// @param context The Hypha IP context
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpArpAnnouncement(HyphaIpContext_t context);

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
// IGMP
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

/// @brief Produces a Join (Membership Report) for a given multicast address
/// @param context The Hypha IP context
/// @param multicast The multicast address to join
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpMembershipReport(HyphaIpContext_t context, HyphaIpIPv4Address_t multicast);

/// @brief Leaves a multicast group.
/// @param context The Hypha IP context.
/// @param multicast The multicast address to leave.
/// @return HyphaIpStatus_e The status of the operation.
HyphaIpStatus_e HyphaIpLeaveGroup(HyphaIpContext_t context, HyphaIpIPv4Address_t multicast);

/// @brief Computes a 1's compliment checksum over two spans.
/// Either span can be empty.
/// @param header_span The span over the Header
/// @param payload_span The span over the Payload
/// @return uint16_t. When saving into a header, this result must be 1's complimented.
/// When checking against an incoming checksum the result should be @ref HyphaIpChecksumValid
/// @warning Checksums should ONLY be computed on the Network Order data as local structures may or may not
/// be 100% short-flipped versions.
uint16_t HyphaIpComputeChecksum(HyphaIpSpan_t header_span, HyphaIpSpan_t payload_span);

/// The Hypha IP Debug Printing macro with Mask
#define HYPHA_DEBUG(context, mask, format, ...)                                                 \
    {                                                                                           \
        if (context->external.printer && ((context->debugging.mask.fields.layer & mask) > 0) && \
            ((context->debugging.mask.fields.level & mask) > 0)) {                              \
            context->external.printer(context->theirs, format, ##__VA_ARGS__);                  \
        }                                                                                       \
    }

#endif  // HYPHA_IP_INTERNAL_H_
