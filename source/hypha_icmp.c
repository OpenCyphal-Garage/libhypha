//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP ICMP implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

#if defined(HYPHA_IP_USE_ICMP) || defined(HYPHA_IP_USE_ICMPv6)
HyphaIpStatus_e HyphaIpTransmitIcmpDatagram(HyphaIpContext_t context, HyphaIpIcmpType_e type, HyphaIpIcmpCode_e code,
                                            HyphaIpIPv4Address_t destination) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    (void)type;         // Suppress unused parameter warning
    (void)code;         // Suppress unused parameter warning
    (void)destination;  // Suppress unused parameter warning
    // TODO Implement the ICMP Echo Request sending logic.
    return HyphaIpStatusNotImplemented;
}
#endif
