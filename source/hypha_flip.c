//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP Flip Copy implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include <string.h>

#include "hypha_ip/hypha_internal.h"

size_t HyphaIpFlipCopy(size_t num_flip_units, HyphaIpFlipUnit_t const flip_units[num_flip_units], void *destination,
                       void const *source) {
    size_t bytes = 0U;
    for (size_t u = 0U; u < num_flip_units; u++) {
        if (flip_units[u].bytes == sizeof(uint8_t)) {
            uint8_t *dst = (uint8_t *)destination;
            uint8_t *src = (uint8_t *)source;
            for (size_t i = 0U; i < flip_units[u].units; i++) {
                *dst = *src;
                dst++;
                src++;
            }
            destination = dst;
            source = src;
        } else if (flip_units[u].bytes == sizeof(uint16_t)) {
            uint16_t *dst = (uint16_t *)destination;
            uint16_t *src = (uint16_t *)source;
            for (size_t i = 0; i < flip_units[u].units; i++) {
                *dst = __builtin_bswap16(*src);
                dst++;
                src++;
            }
            destination = dst;
            source = src;
        } else if (flip_units[u].bytes == sizeof(uint32_t)) {
            uint32_t *dst = (uint32_t *)destination;
            uint32_t *src = (uint32_t *)source;
            for (size_t i = 0; i < flip_units[u].units; i++) {
                *dst = __builtin_bswap32(*src);
                dst++;
                src++;
            }
            destination = dst;
            source = src;
        } else if (flip_units[u].bytes == sizeof(uint64_t)) {
            uint64_t *dst = (uint64_t *)destination;
            uint64_t *src = (uint64_t *)source;
            for (size_t i = 0; i < flip_units[u].units; i++) {
                *dst = __builtin_bswap64(*src);
                dst++;
                src++;
            }
            destination = dst;
            source = src;
        }
        bytes += flip_units[u].units * flip_units[u].bytes;
    }
    return bytes;
}

/// Outlines the flipping units for ethernet headers
HYPHA_INTERNAL const HyphaIpFlipUnit_t flip_ethernet_header[] = {{sizeof(uint8_t), 12},
                                                                 {sizeof(uint16_t), 1 + (2 * HYPHA_IP_USE_VLAN)}};

/// Outlines the flipping units for IPv4 headers
HYPHA_INTERNAL const HyphaIpFlipUnit_t flip_ip_header[] = {
    {sizeof(uint8_t), 2}, {sizeof(uint16_t), 3}, {sizeof(uint8_t), 2}, {sizeof(uint16_t), 1}, {sizeof(uint8_t), 8},
};

/// Outlines the flipping units for ICMP headers
HYPHA_INTERNAL const HyphaIpFlipUnit_t flip_icmp_header[] = {{sizeof(uint16_t), 2}};

/// Outlines the flipping units for UDP headers
HYPHA_INTERNAL const HyphaIpFlipUnit_t flip_udp_header[] = {{sizeof(uint16_t), 4}};

/// Outlines the flipping units for ARP packets
HYPHA_INTERNAL const HyphaIpFlipUnit_t flip_arp_packet[] = {
    {sizeof(uint16_t), 4},  // enums and sizes
    {sizeof(uint8_t), 6},   // mac
    {sizeof(uint8_t), 4},   // ipv4
    {sizeof(uint8_t), 6},   // mac
    {sizeof(uint8_t), 4},   // ipv4
};

/// Outlines the flipping units for IGMP packets
HYPHA_INTERNAL const HyphaIpFlipUnit_t flip_igmp_packet[] = {
    {sizeof(uint16_t), 2},  // type, max_response_time, checksum (treat them as two 16-bit units)
    {sizeof(uint8_t), 4}    // group address (don't flip)
};

size_t HyphaIpOffsetOfIPHeader(void) { return 0; }

size_t HyphaIpOffsetOfUDPHeader(void) { return HyphaIpOffsetOfIPHeader() + sizeof(HyphaIpIPv4Header_t); }

size_t HyphaIpOffsetOfICMPDatagram(void) {
    return HyphaIpOffsetOfIPHeader() + sizeof(HyphaIpIPv4Header_t) + sizeof(HyphaIpICMPHeader_t);
}

size_t HyphaIpOffsetOfUDPPayload(void) {
    return HyphaIpOffsetOfIPHeader() + sizeof(HyphaIpIPv4Header_t) + sizeof(HyphaIpUDPHeader_t);
}

void HyphaIpCopyEthernetHeaderFromFrame(HyphaIpEthernetHeader_t *dst, HyphaIpEthernetFrame_t *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_ethernet_header), flip_ethernet_header, dst, (void *)&src->header);
}

void HyphaIpCopyEthernetHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpEthernetHeader_t const *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_ethernet_header), flip_ethernet_header, dst, src);
}

void HyphaIpCopyIPHeaderFromFrame(HyphaIpIPv4Header_t *dst, HyphaIpEthernetFrame_t *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_ip_header), flip_ip_header, dst, src->payload);
}

void HyphaIpCopyIPHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpIPv4Header_t const *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_ip_header), flip_ip_header, dst->payload, src);
}

void HyphaIpUpdateIpChecksumInFrame(HyphaIpEthernetFrame_t *dst, uint16_t checksum) {
    size_t offset = HyphaIpOffsetOfIPHeader();
    offset += offsetof(HyphaIpIPv4Header_t, checksum);
    uint16_t *checksum_ptr = (uint16_t *)&dst->payload[offset];
    *checksum_ptr = checksum;  // does not needs to be flipped if we computed only over the in frame memory!
    // printf("Wrote out %04x as checksum\r\n", *checksum_ptr);
}

void HyphaIpCopyUdpHeaderFromFrame(HyphaIpUDPHeader_t *dst, HyphaIpEthernetFrame_t *src) {
    size_t offset = HyphaIpOffsetOfUDPHeader();
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_udp_header), flip_udp_header, dst, &src->payload[offset]);
}

void HyphaIpCopyUdpHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpUDPHeader_t const *src) {
    size_t offset = HyphaIpOffsetOfUDPHeader();
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_udp_header), flip_udp_header, &dst->payload[offset], src);
}

void HyphaIpCopyUdpPayloadFromFrame(HyphaIpSpan_t span, HyphaIpEthernetFrame_t *src) {
    size_t offset = HyphaIpOffsetOfUDPPayload();
    memcpy(span.pointer, &src->payload[offset], HyphaIpSpanSize(span));
}

void HyphaIpCopyUdpPayloadToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpSpan_t span) {
    size_t offset = HyphaIpOffsetOfUDPPayload();
    memcpy(&dst->payload[offset], span.pointer, HyphaIpSpanSize(span));
}

void HyphaIpCopyIcmpHeaderFromFrame(HyphaIpICMPHeader_t *dst, HyphaIpEthernetFrame_t *src) {
    size_t offset = sizeof(HyphaIpIPv4Header_t);
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_icmp_header), flip_icmp_header, dst, &src->payload[offset]);
}

void HyphaIpCopyIcmpHeaderToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpICMPHeader_t const *src) {
    size_t offset = sizeof(HyphaIpIPv4Header_t);
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_icmp_header), flip_icmp_header, &dst->payload[offset], src);
}

void HyphaIpCopyIcmpDatagramFromFrame(uint8_t *dst, HyphaIpEthernetFrame_t *src) {
    size_t offset = sizeof(HyphaIpIPv4Header_t) + sizeof(HyphaIpICMPHeader_t);
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_udp_header), flip_udp_header, dst, &src->payload[offset]);
}

void HyphaIpCopyIcmpDatagramToFrame(HyphaIpEthernetFrame_t *dst, uint8_t const *src) {
    size_t offset = sizeof(HyphaIpIPv4Header_t) + sizeof(HyphaIpICMPHeader_t);
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_udp_header), flip_udp_header, &dst->payload[offset], src);
}

void HyphaIpCopyArpPacketFromFrame(HyphaIpArpPacket_t *dst, HyphaIpEthernetFrame_t *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_arp_packet), flip_arp_packet, dst, src->payload);
}

void HyphaIpCopyArpPacketToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpArpPacket_t const *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_arp_packet), flip_arp_packet, dst->payload, src);
}

void HyphaIpCopyIgmpPacketFromFrame(HyphaIpIgmpPacket_t *dst, HyphaIpEthernetFrame_t *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_igmp_packet), flip_igmp_packet, dst, src->payload);
}

void HyphaIpCopyIgmpPacketToFrame(HyphaIpEthernetFrame_t *dst, HyphaIpIgmpPacket_t const *src) {
    HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_igmp_packet), flip_igmp_packet, dst->payload, src);
}
