//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The ethernet layer implementation for the Hypha IP stack.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

const HyphaIpEthernetAddress_t hypha_ip_ethernet_broadcast = {{0xFF, 0xFF, 0xFF}, {0xFF, 0xFF, 0xFF}};
const HyphaIpEthernetAddress_t hypha_ip_ethernet_multicast = {{0x01, 0x00, 0x5E}, {0x00, 0x00, 0x00}};
const HyphaIpEthernetAddress_t hypha_ip_ethernet_local = {{0, 0, 0}, {0, 0, 0}};

bool HyphaIpIsUnicastEthernetAddress(HyphaIpEthernetAddress_t mac) { return ((mac.oui[0] & 0x01U) == 0x00U); }

bool HyphaIpIsMulticastEthernetAddress(HyphaIpEthernetAddress_t mac) { return ((mac.oui[0] & 0x01U) == 0x01U); }

bool HyphaIpIsLocallyAdministeredEthernetAddress(HyphaIpEthernetAddress_t mac) {
    return ((mac.oui[0] & 0x02U) == 0x02U);
}

bool HyphaIpIsSameEthernetAddress(HyphaIpEthernetAddress_t mac1, HyphaIpEthernetAddress_t mac2) {
    return (memcmp(&mac1, &mac2, sizeof(HyphaIpEthernetAddress_t)) == 0);
}

bool HyphaIpIsOurEthernetAddress(HyphaIpContext_t context, HyphaIpEthernetAddress_t mac) {
    if (context == nullptr) {
        return false;
    }
    // check if the mac is the same as our interface mac
    return HyphaIpIsSameEthernetAddress(context->interface.mac, mac);
}

bool HyphaIpIsLocalBroadcastEthernetAddress(HyphaIpEthernetAddress_t mac) {
    return HyphaIpIsSameEthernetAddress(hypha_ip_ethernet_broadcast, mac);
}

bool HyphaIpIsLocalEthernetAddress(HyphaIpEthernetAddress_t mac) {
    return HyphaIpIsSameEthernetAddress(mac, hypha_ip_ethernet_local);
}

#if (HYPHA_IP_USE_MAC_FILTER == 1)
bool HyphaIpIsPermittedEthernetAddress(HyphaIpContext_t context, HyphaIpEthernetAddress_t mac) {
    if (context == nullptr) {
        return false;  // if there is no context, we cannot do anything
    }
    if (HyphaIpIsOurEthernetAddress(context, mac)) {
        return true;  // if the MAC is our own, allow it
    }
    if (context->features.allow_any_localhost && HyphaIpIsLocalEthernetAddress(mac)) {
        return true;  // allow localhost if enabled
    }
    if (context->features.allow_any_broadcast && HyphaIpIsLocalBroadcastEthernetAddress(mac)) {
        return true;  // allow broadcast if enabled
    }
    if (context->features.allow_any_multicast && HyphaIpIsMulticastEthernetAddress(mac) &&
        !HyphaIpIsLocalBroadcastEthernetAddress(mac)) {
        return true;  // allow multicast if enabled
    }
    if (context->features.allow_mac_filtering == false) {
        return true;  // if MAC filtering is not enabled, allow any addresses
    }
    // TODO improve the algorithm here. at first we'll just use the brute force approach to prove correctness of the
    // stack but this should be replaced with a AVL style tree.
    for (size_t i = 0U; i < HYPHA_IP_DIMOF(context->allowed_ethernet_addresses); i++) {
        HyphaIpEthernetFilter_t *filter = &context->allowed_ethernet_addresses[i];
        if (filter->valid && HyphaIpIsSameEthernetAddress(filter->mac, mac)) {
            return true;
        }
    }
    return false;
}

HyphaIpStatus_e HyphaIpPopulateEthernetFilter(HyphaIpContext_t context, size_t len,
                                              HyphaIpEthernetAddress_t filters[len]) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (filters == nullptr || len == 0U) {
        return HyphaIpStatusInvalidArgument;
    }
    // how many are free in the filter table?
    size_t free = 0U;
    for (size_t i = 0U; i < HYPHA_IP_DIMOF(context->allowed_ethernet_addresses); i++) {
        if (context->allowed_ethernet_addresses[i].valid == false) {
            free++;
        }
    }
    if (len > free) {
        return HyphaIpStatusEthernetFilterTableFull;
    }
    context->features.allow_mac_filtering = true;  // enable the MAC filter
    size_t index = 0U;
    HyphaIpTimestamp_t now = context->external.get_monotonic_timestamp(context->theirs);
    for (size_t i = 0U; i < HYPHA_IP_DIMOF(context->allowed_ethernet_addresses) && index < len; i++) {
        // TODO check is the filter is already in the table first
        if (context->allowed_ethernet_addresses[i].valid == false) {
            context->allowed_ethernet_addresses[i].valid = true;
            context->allowed_ethernet_addresses[i].expiration =
                now + HYPHA_IP_EXPIRATION_TIME;  // set the expiration time
            memcpy(&context->allowed_ethernet_addresses[i].mac, &filters[index],
                   sizeof(HyphaIpEthernetAddress_t));  // copy the filter
            index++;
        }
    }
    return HyphaIpStatusOk;
}
#endif  // HYPHA_IP_USE_MAC_FILTER

bool HyphaIpConvertMulticast(HyphaIpEthernetAddress_t *mac, HyphaIpIPv4Address_t ip) {
    if (HyphaIpIsMulticastIPv4Address(ip)) {
        mac->oui[0] = hypha_ip_ethernet_multicast.oui[0];
        mac->oui[1] = hypha_ip_ethernet_multicast.oui[1];
        mac->oui[2] = hypha_ip_ethernet_multicast.oui[2];
        mac->uid[0] = (ip.b & 0x7FU);
        mac->uid[1] = ip.c;
        mac->uid[2] = ip.d;
        return true;
    }
    return false;
}

#if (HYPHA_IP_USE_ARP_CACHE == 1)
HyphaIpStatus_e HyphaIpPopulateArpTable(HyphaIpContext_t context, size_t len, HyphaIpAddressMatch_t matches[len]) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (matches == nullptr || len == 0U) {
        return HyphaIpStatusInvalidArgument;
    }
    // how many are free in the arp_cache?
    size_t free = 0U;
    for (size_t i = 0U; i < HYPHA_IP_DIMOF(context->arp_cache); i++) {
        if (context->arp_cache[i].valid == false) {
            free++;
        }
    }
    if (len > free) {
        return HyphaIpStatusArpTableFull;
    }
    context->features.allow_arp_cache = true;  // enable the ARP cache
    size_t index = 0U;
    HyphaIpTimestamp_t now = context->external.get_monotonic_timestamp(context->theirs);
    for (size_t i = 0U; i < HYPHA_IP_DIMOF(context->arp_cache) && index < len; i++) {
        if (context->arp_cache[i].valid == false) {
            context->arp_cache[i].valid = true;
            context->arp_cache[i].expiration = now + HYPHA_IP_EXPIRATION_TIME;  // set the expiration time
            memcpy(&context->arp_cache[i].match, &matches[index], sizeof(HyphaIpAddressMatch_t));
            index++;
            context->statistics.arp.additions++;
        }
    }
    return HyphaIpStatusOk;
}

HyphaIpIPv4Address_t HyphaIpFindIPv4Address(HyphaIpContext_t context, HyphaIpEthernetAddress_t *mac) {
    for (size_t i = 0U; context->features.allow_arp_cache && i < HYPHA_IP_DIMOF(context->arp_cache); i++) {
        HyphaIpARPEntry_t *entry = &context->arp_cache[i];
        if (entry->valid && HyphaIpIsSameEthernetAddress(entry->match.mac, *mac)) {
            context->statistics.arp.lookups++;
            return context->arp_cache[i].match.ipv4;
        }
    }
    return hypha_ip_default_route;
}

HyphaIpEthernetAddress_t HyphaIpFindEthernetAddress(HyphaIpContext_t context, HyphaIpIPv4Address_t *ipv4) {
    for (size_t i = 0U; context->features.allow_arp_cache && i < HYPHA_IP_DIMOF(context->arp_cache); i++) {
        HyphaIpARPEntry_t *entry = &context->arp_cache[i];

        if (entry->valid && memcmp(&entry->match.ipv4, ipv4, sizeof(HyphaIpIPv4Address_t)) == 0) {
            context->statistics.arp.lookups++;
            return context->arp_cache[i].match.mac;
        }
    }
    return hypha_ip_ethernet_local;
}
#endif  // HYPHA_IP_USE_ARP_CACHE

HyphaIpStatus_e HyphaIpEthernetTransmitFrame(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                             HyphaIpMetaData_t *metadata, HyphaIpEtherType_e ether_type,
                                             size_t payload_length) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (frame == nullptr || metadata == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    HyphaIpEthernetHeader_t ethernet_header = {
        .destination = hypha_ip_ethernet_broadcast,  // default to a broadcast incase we can't resolve it
        .source = context->interface.mac,
#if (HYPHA_IP_USE_VLAN == 1)
        .tpid = HyphaIpEtherType_VLAN,  // VLAN tag
        .priority = 0,                  // default priority
        .drop_eligible = 0,             // not drop eligible
        .vlan = HYPHA_IP_VLAN_ID,
#endif
        .type = ether_type,
    };
    // find the ethernet mac to send to
    if (HyphaIpConvertMulticast(&ethernet_header.destination, metadata->destination_address)) {
        // this was a multicast, nothing else to do
    } else {
        // it may be a local address, so lookup in the ARP cache
        ethernet_header.destination = HyphaIpFindEthernetAddress(context, &metadata->destination_address);
    }

    // if debug, print the header
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        printer(context->theirs, "Transmitting Ethernet Frame %p:\r\n", frame);
        printer(context->theirs, "  Destination: %02X:%02X:%02X:%02X:%02X:%02X\r\n", ethernet_header.destination.oui[0],
                ethernet_header.destination.oui[1], ethernet_header.destination.oui[2],
                ethernet_header.destination.uid[0], ethernet_header.destination.uid[1],
                ethernet_header.destination.uid[2]);
        printer(context->theirs, "  Source: %02X:%02X:%02X:%02X:%02X:%02X\r\n", ethernet_header.source.oui[0],
                ethernet_header.source.oui[1], ethernet_header.source.oui[2], ethernet_header.source.uid[0],
                ethernet_header.source.uid[1], ethernet_header.source.uid[2]);
        printer(context->theirs, "  Type: %04X\r\n", (unsigned int)ethernet_header.type);
    }

    // copy-flip each header into the right place
    HyphaIpCopyEthernetHeaderToFrame(frame, &ethernet_header);

    // transmit
    HyphaIpStatus_e status = context->external.transmit(context->theirs, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    if (HyphaIpIsSuccess(status)) {
        // this is the closest timestamp for success
        metadata->timestamp = context->external.get_monotonic_timestamp(context->theirs);
        // if the transmission was successful, we can update the statistics
        context->statistics.counter.mac.tx.count++;
        context->statistics.counter.mac.tx.bytes += sizeof(ethernet_header) + payload_length;
        context->statistics.mac.accepted++;
    } else {
        // if the transmission failed, we can update the statistics
        context->statistics.mac.rejected++;
    }

    return status;
}

HyphaIpStatus_e HyphaIpEthernetReceiveFrame(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (frame == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    HyphaIpPrinter_f printer = context->external.print;
    HyphaIpTimestamp_t timestamp = context->external.get_monotonic_timestamp(context->theirs);
    HyphaIpEthernetHeader_t ethernet_header;
    context->statistics.counter.mac.rx.count++;
    context->statistics.counter.mac.rx.bytes += sizeof(HyphaIpEthernetHeader_t);
    HyphaIpCopyEthernetHeaderFromFrame(&ethernet_header, frame);
    if (printer) {
        printer(context->theirs, "Receiving Ethernet Frame %p:\r\n", frame);
        printer(context->theirs, "  Destination: %02X:%02X:%02X:%02X:%02X:%02X\r\n", ethernet_header.destination.oui[0],
                ethernet_header.destination.oui[1], ethernet_header.destination.oui[2],
                ethernet_header.destination.uid[0], ethernet_header.destination.uid[1],
                ethernet_header.destination.uid[2]);
        printer(context->theirs, "  Source: %02X:%02X:%02X:%02X:%02X:%02X\r\n", ethernet_header.source.oui[0],
                ethernet_header.source.oui[1], ethernet_header.source.oui[2], ethernet_header.source.uid[0],
                ethernet_header.source.uid[1], ethernet_header.source.uid[2]);
        printer(context->theirs, "  Type: %04X\r\n", (unsigned int)ethernet_header.type);
    }
    // Ethernet Acceptance Rules
    // 1.) Is it destined for us, explicitly?
    bool our_mac_address = HyphaIpIsOurEthernetAddress(context, ethernet_header.destination);
    // 2.) Is it destined for a multicast address?
    bool to_multicast_mac = HyphaIpIsMulticastEthernetAddress(ethernet_header.destination);
    // 3.) Is it a broadcast?
    bool to_broadcast_mac = HyphaIpIsLocalBroadcastEthernetAddress(ethernet_header.destination);
    bool allowed_broadcast = context->features.allow_any_broadcast && to_broadcast_mac;
    bool allowed_multicast_mac = context->features.allow_any_multicast && to_multicast_mac;
    // 4.) Is it a MAC address we allow?
    bool allowed_mac = HyphaIpIsPermittedEthernetAddress(context, ethernet_header.destination);
    if (!our_mac_address && !allowed_multicast_mac && !allowed_broadcast && !allowed_mac) {
        context->statistics.mac.rejected++;
        return HyphaIpStatusMacRejected;
    }
    if (printer) {
        printer(context->theirs, "MAC Accepted\r\n");
    }
    context->statistics.mac.accepted++;

    // 5.) Is it a type we accept?
    bool arp_type = (ethernet_header.type == HyphaIpEtherType_ARP);
    bool ipv4_type = (ethernet_header.type == HyphaIpEtherType_IPv4);
    bool vlan_type = (ethernet_header.type == HyphaIpEtherType_VLAN);
    if (!arp_type && !ipv4_type && !vlan_type) {
        context->statistics.ethertype.rejected++;
        return HyphaIpStatusEthernetTypeRejected;
    }
    if (printer) {
        printer(context->theirs, "EtherType Accepted\r\n");
    }
#if (HYPHA_IP_USE_VLAN == 1)
    if (context->features.allow_vlan_filtering && vlan_type && ethernet_header.vlan != HYPHA_IP_VLAN_ID) {
        context->statistics.ethertype.rejected++;
        if (printer) {
            printer(context->theirs, "VLAN ID %u Rejected\r\n", ethernet_header.vlan);
        }
        return HyphaIpStaticVLANFiltered;
    }
#endif

    context->statistics.ethertype.accepted++;

    if ((our_mac_address || allowed_broadcast) && context->features.allow_arp_cache && arp_type) {
        return HyphaIpArpProcessPacket(context, frame, timestamp);
    } else if (ipv4_type) {
        return HyphaIpIPv4ReceivePacket(context, frame, timestamp);
    }
    return HyphaIpStatusOk;
}
