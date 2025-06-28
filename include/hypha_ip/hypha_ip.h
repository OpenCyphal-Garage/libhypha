#ifndef HYPHA_IP_H_
#define HYPHA_IP_H_

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The main include file for the Hypha IP stack. This includes all the
/// definitions and structures necessary to use the stack.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @page HighLevel High Level Overview
/// @section Overview Overview
/// Users of this library need to provide:
/// <ol>
/// <li> an instance of the @ref HyphaIpExternalInterface_t. a set of basic functions that the library needs to use.
/// Each of these will be given the pointer to the external context via the HyphaIpExternalContext_t.
/// <li> a definition of the @ref HyphaIpExternalContext_t structure for your functions.
/// <li> an instance of the @ref HyphaIpNetworkInterface_t structure for your network interface.
/// <li> an instance of the @ref HyphaIpContext_t variable, which is opaque to the user.
/// </ol>
/// @section External Context
/// @section User Provided Definitions
/// Users must fill in the @ref HyphaIpExternalInterface_t structure with their own functions.
/// <ol>
/// <li> @ref HyphaIpAcquireEthernetFrame_f
/// <li> @ref HyphaIpReleaseEthernetFrame_f
/// <li> @ref HyphaIpEthernetReceiveFrame_f
/// <li> @ref HyphaIpEthernetTransmitFrame_f
/// <li> @ref HyphaIpGetMonotonicTimestamp_f
/// <li> @ref HyphaIpReport_f
/// <li> @ref HyphaIpUdpDatagramListener_f
/// <li> @ref HyphaIpPrinter_f
/// @cond USE_ICMP <li> @ref HyphaIpIcmpDatagramListener_f @endcond
/// </ol>
/// This is an example set of functions.
/// @snippet examples/hypha_ip_lifecycle.c Hypha IP User Provided Definitions
/// @section Network Interface
/// An example network setup. This is a Ethernet interface with a MAC address, an IPv4 address, a netmask and a gateway.
/// @snippet examples/hypha_ip_lifecycle.c Hypha IP Network Interface Example
/// @section Example Lifecycle
/// @snippet examples/hypha_ip_lifecycle.c Hypha IP Lifecycle Example
/// @section HardwareConsiderations Hardware Considerations
/// The Hypha IP stack is designed to be used with a hardware Ethernet interface. However many such interfaces
/// provide some level of functionality to handle filters, checksums and other features which overlap with Hypha. This
/// is why these are configurable in the Hypha IP stack. If you find that your hardware does not support a specific
/// feature, you can enable the software implementation of that feature by defining the appropriate macro in your build
/// system and vice versa.
/// @warning It should go without saying that the software implementation of these features will be slower than
/// the hardware implementation.
/// @page CodingPolicy Coding Policy
/// @section General General
/// <ol>
/// <li>Use stdint.h. Don't reinvent these types.
/// <li>_t for mainly struct types
/// <li>_e for enumerations
/// <li>_f for function pointers
/// <li>CAPS for Macros and defines
/// <li>Typedef all structures, "struct Name" does not have _t, the typedef does.
/// <li>All things must be namespaced: using HyphaIp, hypha_ip or HYPHA_IP
/// </ol>
/// @section MISRA MISRA
/// Currently we are unevaluated for MISRA compliance.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "assert.h"
#include "inttypes.h"
#include "stdbool.h"
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

/// The 802.3 Ethernet defined types for EtherTypes in MAC headers.
typedef enum HyphaIpEtherType : uint16_t {
    HyphaIpEtherType_IPv4 = 0x0800U,  ///< Internet Protocol version 4
    HyphaIpEtherType_ARP = 0x0806U,   ///< Address Resolution Protocol
    HyphaIpEtherType_IPv6 = 0x86DDU,  ///< Internet Protocol version 6
    HyphaIpEtherType_VLAN = 0x8100U,  ///< Virtual LAN Tagging Protocol
} HyphaIpEtherType_e;

#ifndef HYPHA_IP_MTU
/// The Maximum Transmission Unit (MTU) for the Hypha IP stack.
/// This is the maximum size of an Ethernet frame that can be transmitted.
/// The default is 1500 bytes, which is the standard for Ethernet connections.
/// If you are using a different MTU, you can define it in your build system.
#define HYPHA_IP_MTU 1500
#endif

#ifndef HYPHA_IP_TTL
/// The Time To Live (TTL) for the Hypha IP stack.
/// This is the default value for the TTL field in IPv4 packets.
/// The default is 64, which is a common value for many systems.
/// If you are using a different TTL, you can define it in your build system.
#define HYPHA_IP_TTL 64
#endif

#ifndef HYPHA_INTERNAL
/// Define this as blank to expose internal functions to debuggers
#define HYPHA_INTERNAL static
#endif

#ifndef HYPHA_IP_USE_VLAN
/// Whether to use VLAN in the Hypha IP stack
#define HYPHA_IP_USE_VLAN (1)
#endif

#ifndef HYPHA_IP_VLAN_ID
/// The VLAN ID to use in the Hypha IP stack.
#define HYPHA_IP_VLAN_ID 1
#endif

#if (__STDC_VERSION__ != 202311L)
#ifndef nullptr
/// Define nullptr if not already defined
#define nullptr NULL
#endif
#endif

/// The 802.3 Ethernet 48-bit address
typedef struct HyphaIpEthernetAddress {
    uint8_t oui[3];  ///< The Organization Unique Identifier, typically unique to Vendors
    uint8_t uid[3];  ///< The Unique Identifier for this MAC
} HyphaIpEthernetAddress_t;
static_assert(sizeof(HyphaIpEthernetAddress_t) == 6U, "Must be exactly this size");

/// For use with printf-like format strings for Ethernet Addresses
#define PRIuEthernetAddress "%02x:%02x:%02x:%02x:%02x:%02x"

/// The 802.3 Ethernet Frame Header
typedef struct HyphaIpEthernetHeader {
    HyphaIpEthernetAddress_t destination;  ///< The destination MAC address
    HyphaIpEthernetAddress_t source;       ///< The source MAC address
#if (HYPHA_IP_USE_VLAN == 1)
    uint16_t tpid;               ///<  See @ref HyphaIpEtherType
    uint16_t priority : 3;       ///<  The priority of the frame, 0-7
    uint16_t drop_eligible : 1;  ///<  Used to indicate that the frame can be dropped if necessary
    uint16_t vlan : 12;          ///<  The VLAN ID, if any
#endif
    uint16_t type;  ///<  See @ref HyphaIpEtherType
} HyphaIpEthernetHeader_t;
#if (HYPHA_IP_USE_VLAN == 1)
static_assert(sizeof(HyphaIpEthernetHeader_t) == 18U, "Must be exactly this size");
#else
static_assert(sizeof(HyphaIpEthernetHeader_t) == 14U, "Must be exactly this size");
#endif

/// The maximum size of an Ethernet frame payload
#define HYPHA_IP_MAX_ETHERNET_FRAME_SIZE (HYPHA_IP_MTU)

/// The 802.3 header and payload
/// @note CRC32 is assumed to be handled by the Peripheral/Hardware
typedef struct HyphaIpEthernetFrame {
    /// The Ethernet Header
    HyphaIpEthernetHeader_t header;
    /// The payload of the Ethernet Frame. Contains the IP header, the UDP header and so forth.
    uint8_t payload[HYPHA_IP_MAX_ETHERNET_FRAME_SIZE];
} HyphaIpEthernetFrame_t;
static_assert(sizeof(HyphaIpEthernetFrame_t) == HYPHA_IP_MTU + sizeof(HyphaIpEthernetHeader_t),
              "Must fit a whole single MTU");

/// The IPv4 Address in Network Order
typedef struct HyphaIpIPv4Address {
    uint8_t a;  ///< Previously, the Class A subnet
    uint8_t b;  ///< Previously, the Class B subnet
    uint8_t c;  ///< Previously, the Class C subnet
    uint8_t d;  ///< Previously, the Class D subnet
} HyphaIpIPv4Address_t;
static_assert(sizeof(HyphaIpIPv4Address_t) == sizeof(uint32_t), "Must be exactly this size");

/// Printing Helper for IPv4 Address
#define PRIuIPv4Address "%u.%u.%u.%u"

/// A simplified Network Interface for Hypha
typedef struct HyphaIpNetworkInterface {
    HyphaIpEthernetAddress_t mac;  ///<  The MAC Address of the Network Interface
    HyphaIpIPv4Address_t address;  ///<  The IPv4 Address of the Network Interface
    HyphaIpIPv4Address_t netmask;  ///<  The IPv4 Netmask of the Network Interface
    HyphaIpIPv4Address_t gateway;  ///<  The IPv4 Address of the Gateway on this Network
} HyphaIpNetworkInterface_t;

/// A signed timestamp. The time basis (what scale of seconds) is stipulated by the @ref HyphaIpGetMonotonicTimestamp_f
/// type.
typedef int64_t HyphaIpTimestamp_t;

/// A structure to correlate the MAC address and the IPv4 Address
typedef struct HyphaIpAddressMatch {
    HyphaIpEthernetAddress_t mac;  ///< The Media Access Controller Address
    HyphaIpIPv4Address_t ipv4;     ///< The IPv4 Protocol Address
} HyphaIpAddressMatch_t;

/// @brief The types of pointers in a Span.
/// These are limited due to the space in the field. Complex structures should use
/// either Undefined or Uint8_t
typedef enum HyphaIpSpanType {
    /// Undefined type, used for empty spans or spans that have a structured type but not mentioned here.
    HyphaIpSpanTypeUndefined = 0,
    HyphaIpSpanTypeChar = 1,       ///< "C" `char`. Does not count the nul!
    HyphaIpSpanTypeShort = 2,      ///< "C" `short1s
    HyphaIpSpanTypeInt = 3,        ///< "C" `int`s
    HyphaIpSpanTypeLong = 4,       ///< "C" `long`
    HyphaIpSpanTypeLongLong = 5,   ///< "C" `long long`
    HyphaIpSpanTypeFloat = 6,      ///< 4-byte floating point number
    HyphaIpSpanTypeDouble = 7,     ///< 8-byte floating point number
    HyphaIpSpanTypeInt8_t = 8,     ///< 1-byte signed integer
    HyphaIpSpanTypeInt16_t = 9,    ///< 2-byte signed integer
    HyphaIpSpanTypeInt32_t = 10,   ///< 4-byte signed integer
    HyphaIpSpanTypeInt64_t = 11,   ///< 8-byte signed integer
    HyphaIpSpanTypeUint8_t = 12,   ///< 1-byte unsigned integer
    HyphaIpSpanTypeUint16_t = 13,  ///< 2-byte unsigned integer
    HyphaIpSpanTypeUint32_t = 14,  ///< 4-byte unsigned integer
    HyphaIpSpanTypeUint64_t = 15,  ///< 8-byte unsigned integer
} HyphaIpSpanType_e;

/// A simple pointer, length and type structure
typedef struct HyphaIpSpan {
    void *pointer;        ///<  The pointer to the address
    uint32_t count : 28;  ///<  Up to 2^28-1
    uint32_t type : 4;    ///<  @see HyphaIpSpanType_e The type of the pointer and unit
} HyphaIpSpan_t;

/// A default span which is empty and undefined.
/// This is used to indicate that there is no data in the span.
/// It is also used to initialize spans.
#define HYPHA_IP_DEFAULT_SPAN {nullptr, 0, HyphaIpSpanTypeUndefined}

/// A Printer helper for Spans
#define PRIuSpan "%p:%u:%u"

/// Holds the IP and UDP metadata of a Datagram
/// This structure is used to pass the metadata of a UDP Datagram down to the network layer or up from the network
/// layer.
typedef struct HyphaIpMetaData {
    /// The network address which originated the message.
    /// @note When transmitting this will always be replaced by the interface aaddress, any value except a localhost
    /// network value will be ignored.
    HyphaIpIPv4Address_t source_address;
    /// The network address which is the intended recipient
    HyphaIpIPv4Address_t destination_address;
    /// The port on the source address which originated the message. Users can pick any value when sending.
    uint16_t source_port;
    /// The port on the destination address which is the intended recipient.
    uint16_t destination_port;
    /// The timestamp of the message (either received or transmitted),
    /// used for ordering and deduplication
    HyphaIpTimestamp_t timestamp;
} HyphaIpMetaData_t;

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// CONSTANTS
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// The default IPv4 netmask for Class A networks
extern const HyphaIpIPv4Address_t hypha_ip_class_a_mask;

/// The default IPv4 netmask for Class B networks
extern const HyphaIpIPv4Address_t hypha_ip_class_b_mask;

/// The default IPv4 netmask for Class C networks
extern const HyphaIpIPv4Address_t hypha_ip_class_c_mask;

/// The default IPv4 address for the local host
extern const HyphaIpIPv4Address_t hypha_ip_localhost;

/// The default IPv4 network for the local host subnet
extern const HyphaIpIPv4Address_t hypha_ip_local_network;

/// The default IPv4 netmask for the local host subnet
extern const HyphaIpIPv4Address_t hypha_ip_local_netmask;

/// The default IPv4 network for the 24-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_24bit_network;

/// The default IPv4 netmask for the 24-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_24bit_netmask;

/// The default IPv4 network for the 20-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_20bit_network;

/// The default IPv4 netmask for the 20-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_20bit_netmask;

/// The default IPv4 network for the 16-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_16bit_network;

/// The default IPv4 netmask for the 16-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_16bit_netmask;

/// RFC 5737 TEST-NET-1
extern const HyphaIpIPv4Address_t hypha_ip_private_8bit_network1;

/// RFC 5737 TEST-NET-2
extern const HyphaIpIPv4Address_t hypha_ip_private_8bit_network2;

/// RFC 5737 TEST-NET-3
extern const HyphaIpIPv4Address_t hypha_ip_private_8bit_network3;

/// The default IPv4 netmask for the 8-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_private_8bit_netmask;

/// The default IPv4 network for the 8-bit private network
extern const HyphaIpIPv4Address_t hypha_ip_link_local_network;

/// The default IPv4 address for the link-local network
extern const HyphaIpIPv4Address_t hypha_ip_link_local_netmask;

/// The default IPv4 address for the default route
extern const HyphaIpIPv4Address_t hypha_ip_default_route;

/// The default IPv4 address for the limited broadcast
extern const HyphaIpIPv4Address_t hypha_ip_limited_broadcast;

/// The default IPv4 address for the all hosts multicast group
extern const HyphaIpIPv4Address_t hypha_ip_mdns;

/// The default MAC address multicast group
extern const HyphaIpEthernetAddress_t hypha_ip_ethernet_broadcast;

/// The default MAC address for the multicast group
extern const HyphaIpEthernetAddress_t hypha_ip_ethernet_multicast;

/// The default MAC address for no address
extern const HyphaIpEthernetAddress_t hypha_ip_ethernet_local;

/// The default IP multicast group for IGMPv1
extern const HyphaIpIPv4Address_t hypha_ip_igmpv1;

/// The default IP multicast group for IGMPv2
extern const HyphaIpIPv4Address_t hypha_ip_igmpv2;

/// The default IP multicast group for IGMPv3
extern const HyphaIpIPv4Address_t hypha_ip_igmpv3;

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// ENUMS
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// The list of possible Hypha IP Status codes
typedef enum HyphaIpStatus {
    HyphaIpStatusOk = 0,               ///<  The operation was successful
    HyphaIpStatusFailure = -1,         ///< The operation failed, but the reason is not specified
    HyphaIpStatusNotImplemented = -2,  ///< The operation is not implemented in this version of the stack
    HyphaIpStatusInvalidContext = -3,  ///< The context is invalid or null
    HyphaIpStatusOutOfMemory = -4,     ///< The operation failed due to insufficient memory
    HyphaIpStatusArpTableFull = -5,    ///< The ARP table is full and cannot accept more entries
    HyphaIpStatusBusy = -6,  ///< The operation cannot be performed because the stack is busy or in an invalid state
    HyphaIpStatusInvalidArgument = -7,  ///< An argument other than the Context is invalid
    HyphaIpStatusMacRejected = -8,      ///< The MAC address was rejected, possibly due to a filter or invalid format
    HyphaIpStatusEthernetTypeRejected =
        -9,  ///< The Ethernet type was rejected, possibly due to a filter or unsupported type
    HyphaIpStatusIPv4ChecksumRejected = -10,  ///< The IPv4 checksum was rejected, indicating a malformed packet
    HyphaIpStatusIPv4HeaderRejected =
        -11,  ///< The IPv4 header was rejected, possibly due to a filter or invalid format
    HyphaIpStatusIPv4DestinationRejected =
        -12,  ///< The IPv4 destination address was rejected, possibly due to a filter or invalid format
    HyphaIpStatusIPv4SourceRejected =
        -13,  ///< The IPv4 source address was rejected, possibly due to a filter or invalid format
    HyphaIpStatusUDPChecksumRejected = -14,  ///< The UDP checksum was rejected, indicating a malformed packet
    HyphaIpStatusInvalidNetwork =
        -15,  ///< The source network is invalid, possibly due to a filter or unsupported network type
    HyphaIpStatusUnsupportedProtocol = -16,      ///< The protocol is not supported by the stack
    HyphaIpStatusInvalidSpan = -17,              ///< The span was invalid
    HyphaIpStatusInvalidMacAddress = -18,        ///< The MAC address was not a valid address
    HyphaIpStatusInvalidIpAddress = -20,         ///< The IPv4 address was not a valid address
    HyphaIpStatusNotSupported = -21,             ///<  The requested feature is not supported by the implementation
    HyphaIpStatusArpResolutionFailed = -22,      ///<  The ARP resolution failed for the given address
    HyphaIpStatusEthernetFilterTableFull = -23,  ///<  The Ethernet filter table is full and cannot accept more entries
    HyphaIpStatusIPv4FilterTableFull = -24,      ///<  The IPv4 filter table is full and cannot accept more entries
    HyphaIpStatusIPv4SourceFiltered = -25,       ///<  The source address was filtered out
    HyphaIpStaticVLANFiltered = -26,             ///<  The VLAN ID was filtered out
} HyphaIpStatus_e;

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// Contextless API
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// @return True if the status is Successful, false otherwise.
bool HyphaIpIsSuccess(HyphaIpStatus_e status);
/// @return True if the status is not successful, false otherwise.
bool HyphaIpIsFailure(HyphaIpStatus_e status);

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// Contextual API
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// The opaque Context type which is not externally visible
typedef struct HyphaIpContext *HyphaIpContext_t;

#ifndef HYPHA_IP_DIMOF
/// A macro to determine the number of elements in an array, or dimension of an array.
#define HYPHA_IP_DIMOF(x) (sizeof(x) / sizeof(x[0]))
#endif

/// A macro generic function to print an array of integers
#define HyphaIpPrintArray(context, X)    \
    _Generic((X),                        \
        uint64_t *: HyphaIpPrintArray64, \
        uint32_t *: HyphaIpPrintArray32, \
        uint16_t *: HyphaIpPrintArray16, \
        uint8_t *: HyphaIpPrintArray08)(context, HYPHA_IP_DIMOF(X), X)

/// Prints an array of 64-bit integers
/// @param context The Hypha IP Context to use for printing
/// @param len The length of the array
/// @param data The array of 64-bit integers to print
void HyphaIpPrintArray64(HyphaIpContext_t context, size_t len, uint64_t data[len]);

/// Prints an array of 32-bit integers
/// @param context The Hypha IP Context to use for printing
/// @param len The length of the array
/// @param data The array of 32-bit integers to print
void HyphaIpPrintArray32(HyphaIpContext_t context, size_t len, uint32_t data[len]);

/// Prints an array of 16-bit integers
/// @param context The Hypha IP Context to use for printing
/// @param len The length of the array
/// @param data The array of 16-bit integers to print
void HyphaIpPrintArray16(HyphaIpContext_t context, size_t len, uint16_t data[len]);

/// Prints an array of 8-bit integers
/// @param context The Hypha IP Context to use for printing
/// @param len The length of the array
/// @param data The array of 8-bit integers to print
void HyphaIpPrintArray08(HyphaIpContext_t context, size_t len, uint8_t data[len]);

/// Prints the value of a span
void HyphaIpSpanPrint(HyphaIpContext_t context, HyphaIpSpan_t span);

/// @return The number of bytes that the span contains
size_t HyphaIpSizeOfSpan(HyphaIpSpan_t span);

/// Determines if the span is empty
bool HyphaIpSpanIsEmpty(HyphaIpSpan_t span);

/// Counts the number of accepted and rejects at a specific layer of the stack
typedef struct HyphaIpLayerResult {
    size_t accepted;  ///< The number of accepted frames, packets, datagrams, etc.
    size_t rejected;  ///< The number of rejected frames, packets, datagrams, etc.
} HyphaIpLayerResult_t;

/// Counts the throughput of a single direction
typedef struct HyphaIpDirectionalThroughput {
    size_t bytes;  ///<  The number of bytes
    size_t count;  ///<  The number of collections (datagrams, packets, frames, etc)
} HyphaIpDirectionalThroughput_t;

/// The total throughput at a layer
typedef struct HyphaIpThroughput {
    HyphaIpDirectionalThroughput_t tx;  ///<  Transmit throughput
    HyphaIpDirectionalThroughput_t rx;  ///<  Receive throughput
} HyphaIpThroughput_t;

/// Collects the bandwidth statistics for each protocol
typedef struct HyphaIpCounter {
    HyphaIpThroughput_t mac;   ///<  Bandwidth at the MAC layer
    HyphaIpThroughput_t arp;   ///<  Bandwidth at the ARP protocol
    HyphaIpThroughput_t ipv4;  ///<  Bandwidth at the IPv4 protocol
    HyphaIpThroughput_t udp;   ///<  Bandwidth at the UDP protocol
    HyphaIpThroughput_t icmp;  ///<  Bandwidth at the ICMP protocol
    HyphaIpThroughput_t igmp;  ///<  Bandwidth at the IGMP protocol
} HyphaIpCounter_t;

/// Collects the ARP statistics for the stack
typedef struct HyphaIpArpCounter {
    size_t lookups;    ///<  The number of ARP lookups
    size_t announces;  ///<  The number of ARP announcements
    size_t additions;  ///<  The number of ARP additions
    size_t removals;   ///<  The number of ARP removals
} HyphaIpArpCounter_t;

/// Counts the number of allocator statistics
typedef struct HyphaIpAllocationCounter {
    size_t acquires;  ///<  The number of acquires
    size_t releases;  ///<  The number of releases
    size_t failures;  ///<  The number of failed acquires or releases
} HyphaIpFrameCounter_t;

/// The Statistics structure for Hypha IP stack
typedef struct HyphaIpStatistics {
    HyphaIpLayerResult_t mac;        ///< MAC Layer statistics
    HyphaIpLayerResult_t ethertype;  ///< Ethernet Type statistics
    HyphaIpLayerResult_t ip;         ///< IPv4 Layer statistics
    HyphaIpLayerResult_t udp;        ///< UDP Layer statistics
    HyphaIpLayerResult_t unknown;    ///< Unknown protocols, not supported
    HyphaIpArpCounter_t arp;         ///< ARP Layer statistics
    HyphaIpCounter_t counter;        ///< The throughput statistics for each layer
    HyphaIpFrameCounter_t frames;    ///< The number of allocations and deallocations
} HyphaIpStatistics_t;

/// The internal Debugging Levels
enum HyphaIpPrintLevel : uint16_t {
    HyphaIpPrintLevelError = 0x01,  ///<  Error messages
    HyphaIpPrintLevelWarn = 0x02,   ///<  Warning messages
    HyphaIpPrintLevelInfo = 0x04,   ///<  Informational messages
    HyphaIpPrintLevelDebug = 0x08,  ///<  Debug messages
    HyphaIpPrintLevelTrace = 0x10,  ///<  Trace messages
};

/// The internal Debugging Layers
enum HyphaIpPrintLayer : uint16_t {
    HyphaIpPrintLayerMAC = 0x01,     ///<  MAC Layer messages
    HyphaIpPrintLayerARP = 0x02,     ///<  ARP Layer messages
    HyphaIpPrintLayerIPv4 = 0x04,    ///<  IPv4 Layer messages
    HyphaIpPrintLayerUDP = 0x08,     ///<  UDP Layer messages
    HyphaIpPrintLayerICMP = 0x10,    ///<  ICMP Layer messages
    HyphaIpPrintLayerIGMP = 0x20,    ///<  IGMP Layer messages
    HyphaIpPrintLayerUnknown = 0x40  ///<  Unknown Layer messages
};

/// The structure which indicates what prints can be emitted at any given time.
typedef struct HyphaIpPrintInfo {
    /// The union of a mask value and a split set of debug fields
    union HyphaIpPrintMask {
        uint32_t value;  ///<  The raw value of the debug mask
        /// The fields of the print mask.
        /// This allows for easy access to the individual fields without needing to
        /// manipulate the raw value.
        struct HyphaIpPrintFields {
            uint16_t level : 8U;  ///<  The type mask of the printer (Error, Warn, Info, etc)
            uint16_t layer : 8U;  ///<  The layer mask of the printer (MAC, IP, UDP, etc)
        } fields;                 ///<  The print mask fields structure
    } mask;                       ///< The union of a full mask and a set of subfields
} HyphaIpPrintInfo_t;

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// EXTERN (The required interfaces which we depend on)
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// The external context defined by clients
typedef struct HyphaIpExternalContext *HyphaIpExternalContext_t;

/// Acquire a Frame from the Frame provider.The frame could be used to receive or transmit data.
/// @param context The handle to the external context
/// @return A pointer to a Frame, or nullptr if none are available
/// @post HyphaIpEthernetReceiveFrame_f
/// @post HyphaIpEthernetTransmitFrame_f
typedef HyphaIpEthernetFrame_t *(*HyphaIpAcquireEthernetFrame_f)(HyphaIpExternalContext_t context);

/// Receives an ethernet frame into the given frame pointer.
/// @param context The handle to the external context
/// @param frame The pointer to the frame to receive the data into
typedef HyphaIpStatus_e (*HyphaIpEthernetReceiveFrame_f)(HyphaIpExternalContext_t context,
                                                         HyphaIpEthernetFrame_t *frame);
/// Transmits an ethernet frame.
/// @param context The handle to the external context
/// @param frame The pointer to the frame to transmit
typedef HyphaIpStatus_e (*HyphaIpEthernetTransmitFrame_f)(HyphaIpExternalContext_t context,
                                                          HyphaIpEthernetFrame_t *frame);

/// Releases an ethernet frame back to the frame provider.
/// @param context The handle to the external context
/// @param frame The pointer to the frame to release
typedef HyphaIpStatus_e (*HyphaIpReleaseEthernetFrame_f)(HyphaIpExternalContext_t context,
                                                         HyphaIpEthernetFrame_t *frame);

/// A printf-like function which is used to print debug information.
/// @param context The handle to the context of the stack
/// @param format The format string
/// @param ... The arguments to the format string
/// @return The number of characters printed, or a negative value if an error occurred
typedef int (*HyphaIpPrinter_f)(HyphaIpExternalContext_t context, char const *const format, ...);

/// A function which returns a monotonically increasing timestamp.
/// The timestamp is in milliseconds.
/// @param context The handle to the external context
/// @return A monotonically increasing timestamp in milliseconds.
typedef HyphaIpTimestamp_t (*HyphaIpGetMonotonicTimestamp_f)(HyphaIpExternalContext_t context);

/// The callback provided by the Client.
/// @param context The handle to the context of the stack
/// @param metadata The metadata of the incoming datagram
/// @param datagram The UDP Datagram
/// @retval HyphaIpStatusOk Datagram was received and is acceptable.
/// @retval HyphaIpStatusFailure
/// @retval HyphaIpStatus Size or pointer/array is invalid
/// @note It should be safe to call @ref HyphaIpTransmitUdpDatagram from within this callback, so long as the
/// allocator can spare another frame.
typedef HyphaIpStatus_e (*HyphaIpUdpDatagramListener_f)(HyphaIpExternalContext_t context, HyphaIpMetaData_t *metadata,
                                                        HyphaIpSpan_t datagram);

/// Used to report internal issues all the way out of the API to an observer.
typedef void (*HyphaIpReport_f)(HyphaIpExternalContext_t context, HyphaIpStatus_e status, char const *const func,
                                unsigned int line);

#if defined(HYPHA_IP_USE_ICMP) || defined(HYPHA_IP_USE_ICMPv6)
/// @brief The callback provided by the Client for ICMP datagrams.
/// @param context The handle to the context of the stack
/// @param metadata The metadata of the incoming ICMP datagram
/// @param datagram The ICMP Datagram
/// @retval HyphaIpStatusOk Datagram was received and is acceptable.
/// @retval HyphaIpStatusFailure The Datagram was not acceptable, or the function failed.
typedef HyphaIpStatus_e (*HyphaIpIcmpDatagramListener_f)(HyphaIpExternalContext_t context, HyphaIpMetaData_t *metadata,
                                                         HyphaIpSpan_t datagram);
#endif

/// The function pointers to user defined interfaces used by the stack
typedef struct HyphaIpExternalInterface {
    HyphaIpAcquireEthernetFrame_f acquire;                   ///< The interface to acquire frames
    HyphaIpEthernetReceiveFrame_f receive;                   ///< The interface to receive incoming frames
    HyphaIpEthernetTransmitFrame_f transmit;                 ///< The interface to transmit frames
    HyphaIpReleaseEthernetFrame_f release;                   ///< The interface to release frames
    HyphaIpPrinter_f print;                                  ///<  Optional, if not given no prints will occur.
    HyphaIpGetMonotonicTimestamp_f get_monotonic_timestamp;  ///< The interface to get the monotonic timestamp
    HyphaIpReport_f report;                                  ///< The interface to report errors deep within functions
    HyphaIpUdpDatagramListener_f receive_udp;                ///< The interface to receive UDP datagrams
#if defined(HYPHA_IP_USE_ICMP) || defined(HYPHA_IP_USE_ICMPv6)
    HyphaIpIcmpDatagramListener_f receive_icmp;  ///< The interface to receive ICMP datagrams
#endif
} HyphaIpExternalInterface_t;

//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// API
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/// Initializes the HyphaIp Context
/// @param[out] context The location to store the opaque context
/// @param[in] interface The network interface to the HyphaIp
/// @param[in] theirs The external context defined by the client
/// @param[in] externals The external interfaces to the HyphaIp
/// @return The status of the operation
HyphaIpStatus_e HyphaIpInitialize(HyphaIpContext_t *context, HyphaIpNetworkInterface_t *interface,
                                  HyphaIpExternalContext_t theirs, HyphaIpExternalInterface_t *externals);

/// De-initializes the Hypha IP Context.
/// @param[inout] context The location where the opaque context in stored. Will be set to nullptr.
/// @return The status of the operation
HyphaIpStatus_e HyphaIpDeinitialize(HyphaIpContext_t *context);

/// Finds a matching IPv4 Address in the ARP table
/// @param[in] context The opaque context
/// @param[in] mac The MAC Address to match
/// @return The IPv4 Address, default_route if not found
HyphaIpIPv4Address_t HyphaIpFindIPv4Address(HyphaIpContext_t context, HyphaIpEthernetAddress_t *mac);

/// Finds a matching Ethernet address in the ARP table
/// @param[in] context The opaque context
/// @param[in] ipv4 The IPv4 Address to match
/// @return The ethernet address, or {0,0,0,0,0,0} if not found
HyphaIpEthernetAddress_t HyphaIpFindEthernetAddress(HyphaIpContext_t context, HyphaIpIPv4Address_t *ipv4);

/// Allows Clients to pre-populate the ARP table with matches.
/// @warning This will enable the ARP table, and all ARP requests will be answered, regardless of
/// @ref HYPHA_IP_USE_ARP_CACHE.
/// @param[in] context The opaque context
/// @param[in] len The number of matches
/// @param[in] matches The array of matches
/// @return The status of the operation
/// @retval HyphaIpStatusArpTableFull The matches won't fit in the table
HyphaIpStatus_e HyphaIpPopulateArpTable(HyphaIpContext_t context, size_t len, HyphaIpAddressMatch_t matches[len]);

/// @brief Populates entries in the software Ethernet Filter.
/// @warning By calling this, the MAC Filter will be enabled, and all MAC addresses will be filtered, regardless of
/// @ref HYPHA_IP_USE_MAC_FILTER.
/// @param context The opaque context
/// @param len The number of entries in the provided filter
/// @param filters The array of Ethernet addresses to filter on.
/// @return HyphaIpStatus_e
HyphaIpStatus_e HyphaIpPopulateEthernetFilter(HyphaIpContext_t context, size_t len,
                                              HyphaIpEthernetAddress_t filters[len]);

/// @brief Populates entries in the software IPv4 Allow Filter. A
/// @warning By calling this, the IPv4 Filter will be enabled, and all IPv4 packets will be filtered, regardless of
/// @ref HYPHA_IP_USE_IP_FILTER. Anything not in the filter will be dropped.
/// @param context The opaque context
/// @param len The number of entries in the provided filter.
/// @param filters The array of IPv4 addresses to filter on.
/// @return HyphaIpStatus_e
HyphaIpStatus_e HyphaIpPopulateIPv4Filter(HyphaIpContext_t context, size_t len, HyphaIpIPv4Address_t filters[len]);

/// Runs the Hypha IP Stack once, Receiving and then Transmitting.
/// @note This will not block and will try to receive a single frame then return.
/// @param[in] context The opaque context
/// @return The status of the operation
HyphaIpStatus_e HyphaIpRunOnce(HyphaIpContext_t context);

/// Transmits a UDP Datagram now. This will not enqueue or wait until later or do the work in the @ref HyphaIpRunOnce.
/// @param[in] context The opaque context
/// @param[in] metadata The metadata of the datagram
/// @param[in] datagram The UDP Datagram
/// @return The status of the operation
HyphaIpStatus_e HyphaIpTransmitUdpDatagram(HyphaIpContext_t context, HyphaIpMetaData_t *metadata,
                                           HyphaIpSpan_t datagram);

/// Gets the statistics of the Hypha IP Stack
/// @param[in] context The opaque context
/// @return The statistics of the Hypha IP Stack
HyphaIpStatistics_t const *HyphaIpGetStatistics(HyphaIpContext_t context);

/// Prepares the Hypha IP Stack to receive UDP datagrams on some address and port
/// @param[in] context The opaque context
/// @param[in] address The IPv4 Address to listen on
/// @param[in] port The port to listen on
/// @return The status of the operation
HyphaIpStatus_e HyphaIpPrepareUdpReceive(HyphaIpContext_t context, HyphaIpIPv4Address_t address, uint16_t port);

/// Prepares the Hypha IP Stack to transmit UDP datagrams on some address and port.
/// @param[in] context The opaque context
/// @param[in] address The IPv4 Address to transmit to (destination, not source)
/// @param[in] port The port to transmit to (destination, not source)
/// @return The status of the operation
HyphaIpStatus_e HyphaIpPrepareUdpTransmit(HyphaIpContext_t context, HyphaIpIPv4Address_t address, uint16_t port);

#if defined(HYPHA_IP_USE_ICMP) || defined(HYPHA_IP_USE_ICMPv6)

/// @brief The types of ICMP Types.
typedef enum HyphaIpIcmpType {
    HyphaIpIcmpTypeEchoReply = 0,               ///< ICMP Echo Reply
    HyphaIpIcmpTypeDestinationUnreachable = 3,  ///< ICMP Destination Unreachable
    HyphaIpIcmpTypeSourceQuench = 4,            ///< ICMP Source Quench
    HyphaIpIcmpTypeRedirect = 5,                ///< ICMP Redirect
    HyphaIpIcmpTypeEchoRequest = 8,             ///< ICMP Echo Request
    HyphaIpIcmpTypeTimeExceeded = 11,           ///< ICMP Time Exceeded
    HyphaIpIcmpTypeParameterProblem = 12,       ///< ICMP Parameter Problem
} HyphaIpIcmpType_e;

/// @brief The ICMP Code for the ICMP Type.
typedef enum HyphaIpIcmpCode {
    HyphaIpIcmpCodeNoCode = 0,                                    ///< No code, used for Echo Reply and Echo Request
    HyphaIpIcmpCodeNetworkUnreachable = 0,                        ///< Network Unreachable
    HyphaIpIcmpCodeHostUnreachable = 1,                           ///< Host Unreachable
    HyphaIpIcmpCodeProtocolUnreachable = 2,                       ///< Protocol Unreachable
    HyphaIpIcmpCodePortUnreachable = 3,                           ///< Port Unreachable
    HyphaIpIcmpCodeFragmentationRequired = 4,                     ///< Fragmentation Required
    HyphaIpIcmpCodeSourceRouteFailed = 5,                         ///< Source Route Failed
    HyphaIpIcmpCodeDestinationNetworkUnknown = 6,                 ///< Destination Network Unknown
    HyphaIpIcmpCodeDestinationHostUnknown = 7,                    ///< Destination Host Unknown
    HyphaIpIcmpCodeSourceHostIsolated = 8,                        ///< Destination Host
    HyphaIpIcmpCodeDestinationNetworkProhibited = 9,              ///< Destination Network Prohibited
    HyphaIpIcmpCodeDestinationHostProhibited = 10,                ///< Destination Host
    HyphaIpIcmpCodeDestinationNetworkUnreachableForTos = 11,      ///< Destination Network Unreachable for TOS
    HyphaIpIcmpCodeDestinationHostUnreachableForTos = 12,         ///< Destination Host Unreachable for TOS
    HyphaIpIcmpCodeCommunicationAdministrativelyProhibited = 13,  ///< Communication Administratively Prohibited
    HyphaIpIcmpCodeHostPrecedenceViolation = 14,                  ///< Host Precedence Violation
    HyphaIpIcmpCodePrecedenceCutoffInEffect = 15,                 ///< Precedence Cutoff In Effect
} HyphaIpIcmpCode_e;

/// @brief Sends an ICMP Echo Request to the given destination.
/// @param context The opaque context
/// @param destination The destination IPv4 address
/// @return The status of the operation
HyphaIpStatus_e HyphaIpTransmitIcmpDatagram(HyphaIpContext_t context, HyphaIpIcmpType_e type, HyphaIpIcmpCode_e code,
                                            HyphaIpIPv4Address_t destination);
#endif  // HYPHA_IP_USE_ICMP || HYPHA_IP_USE_ICMPv6

#endif  // HYPHA_IP_H_
