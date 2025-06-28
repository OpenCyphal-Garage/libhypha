//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The main API implementation for the Hypha IP stack.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

/// The internal Global Context singleton for the Hypha IP stack.
struct HyphaIpContext gHyphaIpContext;

HyphaIpStatus_e HyphaIpInitialize(HyphaIpContext_t *context, HyphaIpNetworkInterface_t *interface,
                                  HyphaIpExternalContext_t theirs, HyphaIpExternalInterface_t *externals) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (interface == nullptr || externals == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    // check every external pointer!
    // support functions
    if (externals->print == nullptr || externals->get_monotonic_timestamp == nullptr || externals->report == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    // top level functions
    if (externals->receive_udp == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    // bottom level functions
    if (externals->acquire == nullptr || externals->release == nullptr || externals->receive == nullptr ||
        externals->transmit == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    // check the interface mac
    if (HyphaIpIsMulticastEthernetAddress(interface->mac)) {
        return HyphaIpStatusInvalidMacAddress;
    }
    // check that we don't have a multicast address
    if (HyphaIpIsMulticastIPv4Address(interface->address)) {
        return HyphaIpStatusInvalidIpAddress;
    }
    // check that we don't have a localhost address
    if (HyphaIpIsLocalhostIPv4Address(interface->address)) {
        return HyphaIpStatusInvalidIpAddress;
    }

    // the address & mask should be on the same network as the gateway & mask
    uint32_t network_mask = HyphaIpIPv4AddressToValue(interface->netmask);
    uint32_t our_network = HyphaIpIPv4AddressToValue(interface->address) & network_mask;
    uint32_t gateway_network = HyphaIpIPv4AddressToValue(interface->gateway) & network_mask;
    bool same_network = (our_network == gateway_network);
    if (!same_network) {
        return HyphaIpStatusInvalidNetwork;
    }
    *context = &gHyphaIpContext;
    // initialize the variables
    gHyphaIpContext.features.allow_any_localhost = (HYPHA_IP_ALLOW_ANY_LOCALHOST == 1);
    gHyphaIpContext.features.allow_any_multicast = (HYPHA_IP_ALLOW_ANY_MULTICAST == 1);
    gHyphaIpContext.features.allow_any_broadcast = (HYPHA_IP_ALLOW_ANY_BROADCAST == 1);
    gHyphaIpContext.features.allow_mac_filtering = (HYPHA_IP_USE_MAC_FILTER == 1);
    gHyphaIpContext.features.allow_ip_filtering = (HYPHA_IP_USE_IP_FILTER == 1);
    gHyphaIpContext.features.allow_arp_cache = (HYPHA_IP_USE_ARP_CACHE == 1);
#if (HYPHA_IP_USE_VLAN == 1)
    gHyphaIpContext.features.allow_vlan_filtering = true;  // can be disabled by the user
#else
    gHyphaIpContext.features.allow_vlan_filtering = false;  // VLAN is not supported
#endif
    memcpy(&gHyphaIpContext.interface, interface, sizeof(HyphaIpNetworkInterface_t));
    gHyphaIpContext.theirs = theirs;
    memcpy(&gHyphaIpContext.external, externals, sizeof(HyphaIpExternalInterface_t));
#if (HYPHA_IP_USE_MAC_FILTER == 1)
    memset(gHyphaIpContext.allowed_ethernet_addresses, 0, sizeof(gHyphaIpContext.allowed_ethernet_addresses));
#endif
#if (HYPHA_IP_USE_IP_FILTER == 1)
    memset(gHyphaIpContext.allowed_ipv4_addresses, 0, sizeof(gHyphaIpContext.allowed_ipv4_addresses));
#endif
#if (HYPHA_IP_USE_ARP_CACHE == 1)
    memset(gHyphaIpContext.arp_cache, 0, sizeof(gHyphaIpContext.arp_cache));
#endif
    memset(&gHyphaIpContext.statistics, 0, sizeof(gHyphaIpContext.statistics));
    return HyphaIpStatusOk;
}

HyphaIpStatus_e HyphaIpDeinitialize(HyphaIpContext_t *context) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    memset(*context, 0, sizeof(struct HyphaIpContext));
    *context = nullptr;
    return HyphaIpStatusOk;
}

HyphaIpStatus_e HyphaIpRunOnce(HyphaIpContext_t context) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    HyphaIpEthernetFrame_t *frame = context->external.acquire(context->theirs);
    HyphaIpStatus_e status = HyphaIpStatusOk;
    if (frame == nullptr) {
        context->statistics.frames.failures++;
        status = HyphaIpStatusOutOfMemory;
        context->external.report(context->theirs, status, __func__, __LINE__);
    }
    context->statistics.frames.acquires++;
    // receive a frame from the ethernet driver
    status = context->external.receive(context->theirs, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    // receive the frame with the stack
    status = HyphaIpEthernetReceiveFrame(context, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    // release the frame back to the client
    status = context->external.release(context->theirs, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    if (HyphaIpIsSuccess(status)) {
        context->statistics.frames.releases++;
    } else {
        context->statistics.frames.failures++;
    }
    return status;
}

HyphaIpStatistics_t const *HyphaIpGetStatistics(HyphaIpContext_t context) {
    if (context == nullptr) {
        return nullptr;
    }
    return &context->statistics;
}