//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP UDP implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

HyphaIpStatus_e HyphaIpTransmitUdpDatagram(HyphaIpContext_t context, HyphaIpMetaData_t* metadata, HyphaIpSpan_t span) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (metadata == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    if (HyphaIpSpanIsEmpty(span)) {
        return HyphaIpStatusInvalidSpan;
    }
    if (span.type != HyphaIpSpanTypeUint8_t) {
        return HyphaIpStatusInvalidArgument;
    }
    HyphaIpStatus_e status = HyphaIpStatusOk;

    // replace the source address with the one from the interface, users can not create fake source addresses
    metadata->source_address = context->interface.address;

    // for each part of the udp datagram we'll have to make a new packet
    size_t offset = 0;
    size_t const limit = HyphaIpSpanSize(span);
    do {
        size_t remaining = limit - offset;
        size_t chunk = (remaining <= HYPHA_IP_MAX_UDP_PAYLOAD_SIZE) ? remaining : HYPHA_IP_MAX_UDP_PAYLOAD_SIZE;
        uint8_t* tmp = &((uint8_t*)span.pointer)[offset];
        HyphaIpSpan_t fragment = {.pointer = tmp, .count = (uint32_t)chunk, .type = HyphaIpSpanTypeUint8_t};
        HYPHA_IP_PRINT(context, HyphaIpPrintLevelInfo, HyphaIpPrintLayerUDP,
                       "Transmitting UDP Datagram Fragment: " PRIuSpan "\r\n", fragment.pointer, fragment.count,
                       fragment.type);
        // acquire a frame which we will start to write all the information into
        HyphaIpEthernetFrame_t* frame = context->external.acquire(context->theirs);
        if (frame == nullptr) {
            context->statistics.frames.failures++;
            status = HyphaIpStatusOutOfMemory;
        } else {
            context->statistics.frames.acquires++;
            status = HyphaIpStatusOk;
        }
        HYPHA_IP_REPORT(context, status);

        HyphaIpUDPHeader_t udp_header = {
            .source_port = metadata->source_port,
            .destination_port = metadata->destination_port,
            .length = (uint16_t)(sizeof(HyphaIpUDPHeader_t) + HyphaIpSpanSize(fragment)),
            .checksum = 0,
        };
        if (HYPHA_IP_USE_UDP_CHECKSUM) {
            HyphaIpPseudoHeader_t pseudo_header = {
                .source = metadata->source_address,            // Network Order!
                .destination = metadata->destination_address,  // Network Order!
                .protocol = HyphaIpProtocol_UDP,
                .length = udp_header.length + sizeof(HyphaIpPseudoHeader_t),
            };
            memcpy(&pseudo_header.header, &udp_header, sizeof(HyphaIpUDPHeader_t));
            // TODO flip the pseudo header then do checksum
            // compute the checksum over the pseudo header and the fragment
            HyphaIpSpan_t header_span = {&pseudo_header, sizeof(pseudo_header), HyphaIpSpanTypeUint8_t};
            // compute the checksum over the header and the fragment
            uint16_t checksum = ~HyphaIpComputeChecksum(header_span, fragment);
            // TODO write the checksum (Host order) back into the udp_header
            (void)checksum;  // suppress unused variable warning
        }
        // copy the UDP header into the frame
        HyphaIpCopyUdpHeaderToFrame(frame, &udp_header);
        // copy the UDP payload into the frame
        HyphaIpCopyUdpPayloadToFrame(frame, fragment);
        // create a span over the whole header+datagram
        HyphaIpSpan_t datagram = HyphaIpSpanUdpDatagram(frame);

        status = HyphaIpIPv4TransmitPacket(context, frame, metadata, HyphaIpProtocol_UDP, datagram);
        if (HyphaIpIsSuccess(status)) {
            // if the transmission was successful, we can update the statistics
            context->statistics.counter.udp.tx.count++;
            context->statistics.counter.udp.tx.bytes += udp_header.length;  // the length includes the header
            context->statistics.udp.accepted++;
        } else {
            // if the transmission failed, we can update the statistics
            context->statistics.udp.rejected++;
        }
        HYPHA_IP_REPORT(context, status);

        status = context->external.release(context->theirs, frame);
        if (HyphaIpIsSuccess(status)) {
            context->statistics.frames.releases++;
        } else {
            context->statistics.frames.failures++;
            // TODO how to recover?
        }
        HYPHA_IP_REPORT(context, status);
        frame = nullptr;  // forget the frame, so we don't use it again

        offset += chunk;
    } while (offset < limit);
    return HyphaIpStatusOk;
}

HyphaIpStatus_e HyphaIpUdpReceiveDatagram(HyphaIpContext_t context, HyphaIpIPv4Header_t* ip_header,
                                          HyphaIpTimestamp_t timestamp, HyphaIpEthernetFrame_t* frame) {
    context->statistics.counter.udp.rx.count++;

    HyphaIpUDPHeader_t udp_header;
    HyphaIpCopyUdpHeaderFromFrame(&udp_header, frame);
    HyphaIpSpan_t payload_span = HyphaIpSpanUdpPayload(frame);
    HYPHA_IP_PRINT(context, HyphaIpPrintLevelDebug, HyphaIpPrintLayerUDP, "UDP Header: %04X->%04X Length: %u\r\n",
                   udp_header.source_port, udp_header.destination_port, udp_header.length);

    if (udp_header.checksum != 0 && HYPHA_IP_USE_UDP_CHECKSUM) {
        HyphaIpPseudoHeader_t pseudo_header = {
            .source = ip_header->source,
            .destination = ip_header->destination,
            .zero = 0,
            .protocol = HyphaIpProtocol_UDP,
            .length = __builtin_bswap16(udp_header.length + sizeof(HyphaIpPseudoHeader_t))};
        memcpy(&pseudo_header.header, &frame->payload[HyphaIpOffsetOfUDPHeader()], sizeof(HyphaIpUDPHeader_t));
        HyphaIpSpan_t header_span = {&pseudo_header, sizeof(pseudo_header), HyphaIpSpanTypeUint8_t};
        // can't trust the length, yet. compute from IP header minus header
        payload_span.count =
            (ip_header->length - sizeof(HyphaIpIPv4Header_t)) / sizeof(uint16_t);  // TODO this needs a unit test

        HyphaIpSpanPrint(context, header_span);
        HyphaIpSpanPrint(context, payload_span);
        // HyphaIpSpan_t empty = {
        //     .pointer = nullptr,
        //     .count = 0U,
        //     .type = HyphaIpSpanTypeUndefined,
        // };
        uint16_t udp_checksum = HyphaIpComputeChecksum(header_span, payload_span);
        // 0.) Is the UDP checksum valid?
        bool udp_checksum_valid = (udp_checksum == HyphaIpChecksumValid);
        HYPHA_IP_PRINT(context, HyphaIpPrintLevelInfo, HyphaIpPrintLayerUDP,
                       "Computed Checksum: %04X (should be %04X)\r\n", udp_checksum, HyphaIpChecksumValid);
        HYPHA_IP_PRINT(context, HyphaIpPrintLevelInfo, HyphaIpPrintLayerUDP, "Provided Checksum: %04X\r\n",
                       udp_header.checksum);
        if (!udp_checksum_valid) {
            context->statistics.udp.rejected++;
            return HyphaIpStatusUDPChecksumRejected;
        }
    }

    // TODO Check again previously registered Ports? Denied Ports?

    context->statistics.udp.accepted++;
    context->statistics.counter.udp.rx.bytes += udp_header.length;

    HyphaIpMetaData_t metadata = {.source_address = ip_header->source,
                                  .destination_address = ip_header->destination,
                                  .source_port = udp_header.source_port,
                                  .destination_port = udp_header.destination_port,
                                  .timestamp = timestamp};
    // limit to what we're actually processing
    payload_span.count = udp_header.length - sizeof(HyphaIpUDPHeader_t);
    payload_span.type = HyphaIpSpanTypeUint8_t;
    // call the listener
    return context->external.receive_udp(context->theirs, &metadata, payload_span);
}

HyphaIpStatus_e HyphaIpPrepareUdpReceive(HyphaIpContext_t context, HyphaIpIPv4Address_t address, uint16_t port) {
    (void)port;  // suppress unused parameter warning
    if (HyphaIpIsMulticastIPv4Address(address)) {
        // multicast address, we need to send a membership report
        return HyphaIpMembershipReport(context, address);
    }
    return HyphaIpStatusNotSupported;  // only multicast is can make a membership report
}

HyphaIpStatus_e HyphaIpPrepareUdpTransmit(HyphaIpContext_t context, HyphaIpIPv4Address_t address, uint16_t port) {
    (void)context;  // suppress unused parameter warning
    (void)port;     // suppress unused parameter warning
    if (HyphaIpIsMulticastIPv4Address(address)) {
        // nothing has to be done for multicast transmit
        return HyphaIpStatusOk;
    }
    return HyphaIpStatusNotSupported;  // only multicast is can make a membership report
}
