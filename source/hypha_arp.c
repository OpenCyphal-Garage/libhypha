//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The ARP implementation for the Hypha IP stack.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#include "hypha_ip/hypha_internal.h"

HyphaIpStatus_e HyphaIpArpAnnouncement(HyphaIpContext_t context) {
    HyphaIpPrinter_f printer = context->external.print;
    HyphaIpIPv4Address_t ipv4 = context->interface.address;
    if (printer) {
        printer(context->theirs, "ARP Announcement for " PRIuIPv4Address "\r\n", ipv4.a, ipv4.b, ipv4.c, ipv4.d);
    }
    HyphaIpEthernetFrame_t *frame = context->external.acquire(context->theirs);
    if (frame == nullptr) {
        return HyphaIpStatusOutOfMemory;
    }
    HyphaIpArpPacket_t arp_packet = {
        .hardware_type = HyphaIpArpHardwareTypeEthernet,
        .protocol_type = HyphaIpArpProtocolTypeIPv4,
        .hardware_length = sizeof(HyphaIpEthernetAddress_t),
        .protocol_length = sizeof(HyphaIpIPv4Address_t),
        .operation = HyphaIpArpOperationRequest,
        .sender_hardware = context->interface.mac,
        .sender_protocol = context->interface.address,
        .target_hardware = hypha_ip_ethernet_broadcast,  // we don't know the target MAC yet
        .target_protocol = context->interface.address,   // we are asking for our own address
    };
    HyphaIpCopyArpPacketToFrame(frame, &arp_packet);
    HyphaIpStatus_e status = context->external.transmit(context->theirs, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    if (status == HyphaIpStatusOk) {
        context->statistics.arp.announces++;
    }
    status = context->external.release(context->theirs, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    return status;
}

HyphaIpStatus_e HyphaIpArpProcessPacket(HyphaIpContext_t context, HyphaIpEthernetFrame_t *frame,
                                        HyphaIpTimestamp_t timestamp) {
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        printer(context->theirs, "ARP Type Detected\r\n");
    }
    // TODO the lengths must match 48 bit address and IPv4 address
    context->statistics.counter.arp.rx.count++;
    context->statistics.counter.arp.rx.bytes += sizeof(HyphaIpArpPacket_t);
    HyphaIpArpPacket_t arp_packet;
    HyphaIpCopyArpPacketFromFrame(&arp_packet, frame);
    // TODO deal with ARP, could require queueing up a send for later?
    (void)timestamp;  // Suppress unused parameter warning
    return HyphaIpStatusNotImplemented;
}
