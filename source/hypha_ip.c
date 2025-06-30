//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP IPv4 implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

const HyphaIpIPv4Address_t hypha_ip_class_a_mask = {255, 0, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_class_b_mask = {255, 255, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_class_c_mask = {255, 255, 255, 0};
const HyphaIpIPv4Address_t hypha_ip_localhost = {127, 0, 0, 1};
const HyphaIpIPv4Address_t hypha_ip_local_network = {127, 0, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_local_netmask = hypha_ip_class_a_mask;
const HyphaIpIPv4Address_t hypha_ip_private_24bit_network = {10, 0, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_private_24bit_netmask = hypha_ip_class_a_mask;
const HyphaIpIPv4Address_t hypha_ip_private_20bit_network = {172, 16, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_private_20bit_netmask = {255, 240, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_private_16bit_network = {192, 168, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_private_16bit_netmask = hypha_ip_class_b_mask;
const HyphaIpIPv4Address_t hypha_ip_private_8bit_network1 = {192, 0, 2, 0};
const HyphaIpIPv4Address_t hypha_ip_private_8bit_network2 = {198, 51, 100, 0};
const HyphaIpIPv4Address_t hypha_ip_private_8bit_network3 = {203, 0, 113, 0};
const HyphaIpIPv4Address_t hypha_ip_private_8bit_netmask = hypha_ip_class_c_mask;
const HyphaIpIPv4Address_t hypha_ip_link_local_network = {169, 254, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_link_local_netmask = hypha_ip_class_b_mask;
const HyphaIpIPv4Address_t hypha_ip_default_route = {0, 0, 0, 0};
const HyphaIpIPv4Address_t hypha_ip_limited_broadcast = {255, 255, 255, 255};
const HyphaIpIPv4Address_t hypha_ip_mdns = {224, 0, 0, 251};
const HyphaIpIPv4Address_t hypha_ip_igmpv1 = {224, 0, 0, 1};
const HyphaIpIPv4Address_t hypha_ip_igmpv2 = {224, 0, 0, 2};
const HyphaIpIPv4Address_t hypha_ip_igmpv3 = {224, 0, 0, 22};

uint32_t HyphaIpIPv4AddressToValue(HyphaIpIPv4Address_t ipv4) {
    return (uint32_t)(ipv4.a << 24) | (uint32_t)(ipv4.b << 16) | (uint32_t)(ipv4.c << 8) | (uint32_t)(ipv4.d);
}

HyphaIpIPv4Address_t HyphaIpValueToIPv4Address(uint32_t value) {
    HyphaIpIPv4Address_t ipv4;
    ipv4.a = (value >> 24) & 0xFFU;
    ipv4.b = (value >> 16) & 0xFFU;
    ipv4.c = (value >> 8) & 0xFFU;
    ipv4.d = value & 0xFFU;
    return ipv4;
}

bool HyphaIpIsInNetwork(HyphaIpIPv4Address_t ipv4, uint32_t network, uint32_t netmask) {
    uint32_t ipv4_value = HyphaIpIPv4AddressToValue(ipv4);
    return ((ipv4_value & netmask) == (network & netmask));
}

bool HyphaIpIsInOurNetwork(HyphaIpContext_t context, HyphaIpIPv4Address_t ipv4) {
    uint32_t netmask = HyphaIpIPv4AddressToValue(context->interface.netmask);
    uint32_t address = HyphaIpIPv4AddressToValue(context->interface.address);
    uint32_t network = address & netmask;
    return HyphaIpIsInNetwork(ipv4, network, netmask);
}

bool HyphaIpIsLocalhostIPv4Address(HyphaIpIPv4Address_t address) { return (address.a == 0b0111'1111); }

bool HyphaIpIsMulticastIPv4Address(HyphaIpIPv4Address_t address) { return (address.a >= 224U && address.a <= 239U); }

bool HyphaIpIsReservedIPv4Address(HyphaIpIPv4Address_t address) { return ((address.a & 0xF0) == 0b1111'0000); }

bool HyphaIpIsSameIPv4Address(HyphaIpIPv4Address_t a, HyphaIpIPv4Address_t b) {
    return (memcmp(&a, &b, sizeof(HyphaIpIPv4Address_t)) == 0);
}

bool HyphaIpIsOurIPv4Address(HyphaIpContext_t context, HyphaIpIPv4Address_t address) {
    return HyphaIpIsSameIPv4Address(context->interface.address, address);
}

bool HyphaIpIsLimitedBroadcastIPv4Address(HyphaIpIPv4Address_t address) {
    return HyphaIpIsSameIPv4Address(address, hypha_ip_limited_broadcast);
}

#if (HYPHA_IP_USE_IP_FILTER == 1)
HyphaIpStatus_e HyphaIpPopulateIPv4Filter(HyphaIpContext_t context, size_t len, HyphaIpIPv4Address_t addresses[len]) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (len > HYPHA_IP_IPv4_FILTER_TABLE_SIZE || len == 0 || addresses == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    // count the number of free entries in the table
    size_t free_count = 0;
    for (size_t i = 0; i < HYPHA_IP_IPv4_FILTER_TABLE_SIZE; i++) {
        HyphaIpIPv4Filter_t *filter = &context->allowed_ipv4_addresses[i];
        if (filter->valid == false) {
            free_count++;
        }
    }
    if (free_count < len) {
        return HyphaIpStatusIPv4FilterTableFull;
    }
    context->features.allow_ip_filtering = true;
    size_t index = 0U;
    HyphaIpTimestamp_t now = context->external.get_monotonic_timestamp(context->theirs);
    for (size_t i = 0; i < HYPHA_IP_IPv4_FILTER_TABLE_SIZE; i++) {
        HyphaIpIPv4Filter_t *filter = &context->allowed_ipv4_addresses[i];
        if (filter->valid == false) {
            if (index < len) {
                // copy the filter
                filter->ipv4 = addresses[index];
                filter->expiration = now + HYPHA_IP_EXPIRATION_TIME;  // set the expiration time
                filter->valid = true;
                index++;
            } else {
                // we are done, no more filters to add
                break;
            }
        }
    }
    return HyphaIpStatusOk;
}

bool HyphaIpIsPermittedIPv4Address(HyphaIpContext_t context, HyphaIpIPv4Address_t address) {
    if (context == nullptr) {
        return false;  // invalid context
    }
    if (context->features.allow_any_localhost && HyphaIpIsLocalhostIPv4Address(address)) {
        return true;  // localhost
    }
    if (context->features.allow_any_broadcast && HyphaIpIsLimitedBroadcastIPv4Address(address)) {
        return true;  // limited broadcast address
    }
    if (context->features.allow_any_multicast && HyphaIpIsMulticastIPv4Address(address)) {
        return true;  // multicast address
    }
    if (context->features.allow_ip_filtering == false) {
        return true;  // filtering is not enabled, so all addresses are allowed
    }
    HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                   "Checking if " PRIuIPv4Address " is in the filter table\r\n", address.a, address.b, address.c,
                   address.d);
    // TODO improve the performance of this function by using an AVL or something similar
    // we assume there will be a small CPU penalty, these platforms can not tolerate a large memory penalty
    for (size_t i = 0; i < HYPHA_IP_IPv4_FILTER_TABLE_SIZE; i++) {
        HyphaIpIPv4Filter_t *filter = &context->allowed_ipv4_addresses[i];
        if (filter->valid && HyphaIpIsSameIPv4Address(filter->ipv4, address)) {
            return true;  // found a match
        }
    }
    HYPHA_IP_PRINT(context, HyphaIpPrintLevelError, HyphaIpPrintLayerIPv4,
                   "Address " PRIuIPv4Address " is not in the filter table\r\n", address.a, address.b, address.c,
                   address.d);
    return false;  // not found in the filter table
}
#endif  // HYPHA_IP_USE_IP_FILTER

bool HyphaIpIsPrivateIPv4Address(HyphaIpIPv4Address_t address) {
    // An address is private if it is in one of the private address ranges
    // Private addresses are defined in RFC 1918 and RFC 5737?

    bool is_class_a_private = HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_private_24bit_network),
                                                 HyphaIpIPv4AddressToValue(hypha_ip_private_24bit_netmask));
    bool is_class_b_private = HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_private_20bit_network),
                                                 HyphaIpIPv4AddressToValue(hypha_ip_private_20bit_netmask));
    bool is_class_c_private = HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_private_16bit_network),
                                                 HyphaIpIPv4AddressToValue(hypha_ip_private_16bit_netmask));
    bool is_class_d_private = HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_private_8bit_network1),
                                                 HyphaIpIPv4AddressToValue(hypha_ip_private_8bit_netmask)) ||
                              HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_private_8bit_network2),
                                                 HyphaIpIPv4AddressToValue(hypha_ip_private_8bit_netmask)) ||
                              HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_private_8bit_network3),
                                                 HyphaIpIPv4AddressToValue(hypha_ip_private_8bit_netmask));
    bool is_link_local_private = HyphaIpIsInNetwork(address, HyphaIpIPv4AddressToValue(hypha_ip_link_local_network),
                                                    HyphaIpIPv4AddressToValue(hypha_ip_link_local_netmask));
    if (is_class_a_private || is_class_b_private || is_class_c_private || is_class_d_private || is_link_local_private) {
        return true;  // private address
    }
    return false;  // not a private address
}

HyphaIpStatus_e HyphaIpIPv4ReceivePacket(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                         HyphaIpTimestamp_t timestamp) {
    context->statistics.counter.ipv4.rx.count++;
    HyphaIpIPv4Header_t ip_header;
    HyphaIpCopyIPHeaderFromFrame(&ip_header, frame);

    HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                   "RX: IP Header: Version=%u, IHL=%u, DSCP=%u, ECN=%u, Length=%u, ID=%u, DF=%u, MF=%u, "
                   "Offset=%u, TTL=%u, Protocol=%u, Checksum=%04X\r\n",
                   ip_header.version, ip_header.IHL, ip_header.DSCP, ip_header.ECN, ip_header.length,
                   ip_header.identification, ip_header.DF, ip_header.MF, ip_header.fragment_offset, ip_header.TTL,
                   ip_header.protocol, ip_header.checksum);
    HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                   "RX: Source: " PRIuIPv4Address " => Destination: " PRIuIPv4Address "\r\n", ip_header.source.a,
                   ip_header.source.b, ip_header.source.c, ip_header.source.d, ip_header.destination.a,
                   ip_header.destination.b, ip_header.destination.c, ip_header.destination.d);
    HYPHA_IP_DO(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                HyphaIpPrintArray16(context, sizeof(ip_header) / sizeof(uint16_t), (uint16_t *)&ip_header););

    // IP Header acceptance rules
    if (HYPHA_IP_USE_IP_CHECKSUM) {
        HyphaIpSpan_t ip_header_span = HyphaIpSpanIpHeader(frame);
        HyphaIpSpan_t ip_payload_span = HYPHA_IP_DEFAULT_SPAN;
        // 0.) Is the HEADER Checksum valid?
        uint16_t checksum = HyphaIpComputeChecksum(ip_header_span, ip_payload_span);
        HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                       "Computed Checksum: %04X (should be %04X)\r\n", checksum, HyphaIpChecksumValid);
        HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4, "Provided Checksum: %04X\r\n",
                       ip_header.checksum);
        bool valid_checksum = (checksum == HyphaIpChecksumValid);
        if (!valid_checksum) {
            context->statistics.ip.rejected++;
            HYPHA_IP_REPORT(context, HyphaIpStatusIPv4ChecksumRejected);
            return HyphaIpStatusIPv4ChecksumRejected;
        }
    }
    // 1.) Is the IP version 4?
    bool ipv4_version = (ip_header.version == 4);
    // 2.) check to make sure the header length is valid
    bool header_length_valid = (ip_header.IHL == 5);
    // no fragmentation is allowed, offset must be zero.
    bool no_fragmentation = (ip_header.MF == 0) && (ip_header.fragment_offset == 0);
    if (!ipv4_version || !header_length_valid || (ip_header.length > HYPHA_IP_MAX_IP_LENGTH) || !no_fragmentation) {
        context->statistics.ip.rejected++;
        HYPHA_IP_PRINT(context, HyphaIpPrintLevelError, HyphaIpPrintLayerIPv4,
                       "Invalid IPv4 Header: Version=%u, IHL=%u, Length=%u, DF=%u, MF=%u, Offset=%u\r\n",
                       ip_header.version, ip_header.IHL, ip_header.length, ip_header.DF, ip_header.MF,
                       ip_header.fragment_offset);
        return HyphaIpStatusIPv4HeaderRejected;
    }
    // 3.) check to make sure the destination address is valid (localhost from some localhost, our interface but then
    // from our network) or is a multicast or is a limited broadcast.
    bool to_our_address = HyphaIpIsOurIPv4Address(context, ip_header.destination);
    bool to_localhost = HyphaIpIsLocalhostIPv4Address(ip_header.destination);
    bool to_multicast = HyphaIpIsMulticastIPv4Address(ip_header.destination);
    bool to_limited_broadcast = HyphaIpIsLimitedBroadcastIPv4Address(ip_header.destination);
    bool valid_destination = to_our_address || (context->features.allow_any_multicast && to_multicast) ||
                             (context->features.allow_any_broadcast && to_limited_broadcast) ||
                             (context->features.allow_any_localhost && to_localhost);
    if (!valid_destination) {
        context->statistics.ip.rejected++;
        return HyphaIpStatusIPv4DestinationRejected;
    }
    // 4.) Check to make sure the source address is within our network mask
    bool is_same_network = HyphaIpIsInOurNetwork(context, ip_header.source);
    bool from_localhost = HyphaIpIsLocalhostIPv4Address(ip_header.source);
    bool valid_localhost = context->features.allow_any_localhost && to_localhost && from_localhost;
    bool valid_network = valid_localhost || is_same_network;
    if (!valid_network) {
        context->statistics.ip.rejected++;
        return HyphaIpStatusIPv4SourceRejected;
    }
    // 5.) Check to make the source address is not filtered out
    bool from_our_address = HyphaIpIsOurIPv4Address(context, ip_header.source);
    if (context->features.allow_ip_filtering == true && !from_our_address) {
        bool found = HyphaIpIsPermittedIPv4Address(context, ip_header.source);
        if (!found) {
            HYPHA_IP_PRINT(context, HyphaIpPrintLevelInfo, HyphaIpPrintLayerIPv4,
                           "Source Address " PRIuIPv4Address " not in filter table\r\n", ip_header.source.a,
                           ip_header.source.b, ip_header.source.c, ip_header.source.d);

            context->statistics.ip.rejected++;
            return HyphaIpStatusIPv4SourceFiltered;
        }
    }

    context->statistics.ip.accepted++;
    context->statistics.counter.ipv4.rx.bytes += sizeof(ip_header) + ip_header.length;

    /// now handle each protocol
    if (ip_header.protocol == HyphaIpProtocol_UDP) {
        return HyphaIpUdpReceiveDatagram(context, &ip_header, timestamp, frame);
    } else if (ip_header.protocol == HyphaIpProtocol_ICMP) {
        // TODO support?
        context->statistics.counter.icmp.rx.count++;
        HYPHA_IP_REPORT(context, HyphaIpStatusNotImplemented);
        return HyphaIpStatusNotImplemented;
    } else if (ip_header.protocol == HyphaIpProtocol_IGMP) {
        // TODO support receiving?
        context->statistics.counter.igmp.rx.count++;
        HYPHA_IP_REPORT(context, HyphaIpStatusNotImplemented);
        return HyphaIpStatusNotImplemented;
    }
    context->statistics.unknown.rejected++;
    return HyphaIpStatusUnsupportedProtocol;
}

HyphaIpStatus_e HyphaIpIPv4TransmitPacket(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                          HyphaIpMetaData_t *metadata, HyphaIpProtocol_e ip_protocol,
                                          HyphaIpSpan_t packet) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (frame == nullptr || metadata == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    if (HyphaIpSpanIsEmpty(packet)) {
        return HyphaIpStatusInvalidSpan;
    }
    if (HyphaIpSpanSize(packet) > HYPHA_IP_MAX_IP_PAYLOAD_SIZE) {
        return HyphaIpStatusIPv4PacketTooLarge;
    }
    // check to make sure the destination is valid
    bool to_multicast = HyphaIpIsMulticastIPv4Address(metadata->destination_address);
    bool to_broadcast = HyphaIpIsLimitedBroadcastIPv4Address(metadata->destination_address);
    bool to_localhost = HyphaIpIsLocalhostIPv4Address(metadata->destination_address);
    bool to_our_address = HyphaIpIsOurIPv4Address(context, metadata->destination_address);

    HyphaIpIPv4Address_t source_ip = context->interface.address;
    if (to_localhost) {
        bool from_localhost = HyphaIpIsLocalhostIPv4Address(metadata->source_address);
        if (!from_localhost) {
            source_ip = hypha_ip_localhost;
        } else {
            // this allows you to use 127.x.x.x for testing
            source_ip = metadata->source_address;
        }
    }

    if (!to_multicast && !to_broadcast && !to_localhost && !to_our_address) {
        return HyphaIpStatusIPv4DestinationRejected;
    }

    HyphaIpIPv4Header_t ip_header = {
        .version = 4,
        .IHL = 5,  // no options are supported, so the header length is 5 * sizeof(uint32_t) = 20 bytes
        .DSCP = 0,
        .ECN = 0,
        .length = (uint16_t)(sizeof(HyphaIpIPv4Header_t) + (uint16_t)HyphaIpSpanSize(packet)),
        .identification = 0,  // no fragmentation, so ID is 0
        .zero = 0,
        .DF = 0,
        .MF = 0,
        .fragment_offset = 0,
        .TTL = HYPHA_IP_TTL,
        .protocol = ip_protocol,
        .checksum = 0,  // must start as zero
        .source = source_ip,
        .destination = metadata->destination_address,
    };

    HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                   "TX: IP Header: Version=%u, IHL=%u, DSCP=%u, ECN=%u, Length=%u, ID=%u, DF=%u, MF=%u, "
                   "Offset=%u, TTL=%u, Protocol=%u, Checksum=%04X\r\n",
                   ip_header.version, ip_header.IHL, ip_header.DSCP, ip_header.ECN, ip_header.length,
                   ip_header.identification, ip_header.DF, ip_header.MF, ip_header.fragment_offset, ip_header.TTL,
                   ip_header.protocol, ip_header.checksum);
    // print the source and destination addresses
    HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                   "TX: Source: " PRIuIPv4Address " => Destination: " PRIuIPv4Address "\r\n", ip_header.source.a,
                   ip_header.source.b, ip_header.source.c, ip_header.source.d, ip_header.destination.a,
                   ip_header.destination.b, ip_header.destination.c, ip_header.destination.d);
    HYPHA_IP_DO(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerIPv4,
                HyphaIpPrintArray16(context, sizeof(ip_header) / sizeof(uint16_t), (uint16_t *)&ip_header));

    // copy-flip the header into the right place, payload is already there
    HyphaIpCopyIPHeaderToFrame(frame, &ip_header);

    if (HYPHA_IP_USE_IP_CHECKSUM) {
        HyphaIpSpan_t ip_header_span = HyphaIpSpanIpHeader(frame);
        HyphaIpSpan_t ip_payload_span = HYPHA_IP_DEFAULT_SPAN;
        // compute the IP checksum (and save the 1's compliment)
        ip_header.checksum = ~HyphaIpComputeChecksum(ip_header_span, ip_payload_span);
        HyphaIpUpdateIpChecksumInFrame(frame, ip_header.checksum);
    } else {
        // maybe hardware will do this for us? leave it as 0
    }

    if (to_localhost || to_our_address) {
        // capture the timestamp now since it's going to the ethernet driver
        metadata->timestamp = context->external.get_monotonic_timestamp(context->theirs);
        // call the receive function directly since it's localhost
        return HyphaIpIPv4ReceivePacket(context, frame, metadata->timestamp);
    }  // otherwise continue to the ethernet layer

    size_t const full_packet_length = sizeof(ip_header) + HyphaIpSpanSize(packet);
    // fill in the ethernet header and transmit in this function
    HyphaIpStatus_e status =
        HyphaIpEthernetTransmitFrame(context, frame, metadata, HyphaIpEtherType_IPv4, full_packet_length);
    if (HyphaIpIsSuccess(status)) {
        // if the transmission was successful, we can update the statistics
        context->statistics.counter.ipv4.tx.count++;
        context->statistics.counter.ipv4.tx.bytes += full_packet_length;
        context->statistics.ip.accepted++;
    } else {
        // if the transmission failed, we can update the statistics
        context->statistics.ip.rejected++;
    }
    HYPHA_IP_REPORT(context, status);
    return status;
}
