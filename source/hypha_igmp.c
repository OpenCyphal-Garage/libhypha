//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP IGMP implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

/// @brief Sends an IGMP packet to the given multicast address with the specified type.
/// @param context The Hypha IP context
/// @param multicast The multicast address to send the IGMP packet to
/// @param type The type of the IGMP packet (Membership Report or Leave Group)
/// @return HyphaIpStatus_e The status of the operation.
HYPHA_INTERNAL HyphaIpStatus_e HyphaIpIgmpPacket(HyphaIpContext_t context, HyphaIpIPv4Address_t multicast,
                                                 HyphaIpIgmpType_e type) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        printer(context->theirs, "IGMP Group: " PRIuIPv4Address "\r\n", multicast.a, multicast.b, multicast.c,
                multicast.d);
    }
    HyphaIpStatus_e status = HyphaIpStatusOk;
    // acquire a frame for the IGMP packet
    HyphaIpEthernetFrame_t *frame = context->external.acquire(context->theirs);
    if (frame == nullptr) {
        context->statistics.frames.failures++;
        status = HyphaIpStatusOutOfMemory;
        context->external.report(context->theirs, status, __func__, __LINE__);
        return status;
    }
    context->statistics.frames.acquires++;
    // fill in an IGMP packet
    HyphaIpIgmpPacket_t igmp_packet = {
        .type = HyphaIpIgmpTypeReport_v2,  // IGMPv2 Membership Report
        .max_response_time = 0,            // not used in v1/v2, in deci-seconds
        .checksum = 0,                     // will be computed later
        .group = multicast,
    };
    // create a span over the IGMP packet
    HyphaIpSpan_t igmp_span = {
        .pointer = &igmp_packet,
        .count = sizeof(HyphaIpIgmpPacket_t),
        .type = HyphaIpSpanTypeUint8_t,
    };
    // create a null span for the payload
    HyphaIpSpan_t payload_span = {
        .pointer = nullptr,
        .count = 0,
        .type = HyphaIpSpanTypeUndefined,
    };
    // compute the checksum for the IGMP packet
    igmp_packet.checksum = HyphaIpComputeChecksum(igmp_span, payload_span);
    // copy the IGMP packet into the frame
    HyphaIpCopyIgmpPacketToFrame(frame, &igmp_packet);
    // make a metadata structure
    HyphaIpMetaData_t metadata = {
        .source_address = context->interface.address,  // ours
        .destination_address = multicast,              // send to the multicast group
        .source_port = 0,                              // IGMP does not use ports
        .destination_port = 0,                         // IGMP does not use ports
    };
    // let the lower layer no figure out the ethernet stuff
    status = HyphaIpIPv4TransmitPacket(context, frame, &metadata, HyphaIpProtocol_IGMP, igmp_span);
    context->external.report(context->theirs, status, __func__, __LINE__);
    if (printer) {
        if (HyphaIpIsSuccess(status)) {
            printer(context->theirs, "IGMP Membership Report sent successfully\r\n");
        }
    }
    // now free the frame
    status = context->external.release(context->theirs, frame);
    context->external.report(context->theirs, status, __func__, __LINE__);
    if (HyphaIpIsSuccess(status)) {
        context->statistics.frames.releases++;
    } else {
        context->statistics.frames.failures++;
    }

    return status;
}

HyphaIpStatus_e HyphaIpMembershipReport(HyphaIpContext_t context, HyphaIpIPv4Address_t multicast) {
    return HyphaIpIgmpPacket(context, multicast, HyphaIpIgmpTypeReport_v2);
}

HyphaIpStatus_e HyphaIpLeaveGroup(HyphaIpContext_t context, HyphaIpIPv4Address_t multicast) {
    return HyphaIpIgmpPacket(context, multicast, HyphaIpIgmpTypeLeave);
}
