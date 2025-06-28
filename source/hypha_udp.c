//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP UDP implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

HyphaIpStatus_e HyphaIpTransmitUdpDatagram(HyphaIpContext_t context, HyphaIpMetaData_t* metadata, HyphaIpSpan_t span) {
    if (context == nullptr) {
        return HyphaIpStatusInvalidContext;
    }
    if (HyphaIpSpanIsEmpty(span)) {
        return HyphaIpStatusInvalidSpan;
    }
    if (metadata == nullptr) {
        return HyphaIpStatusInvalidArgument;
    }
    HyphaIpStatus_e status = HyphaIpStatusOk;

    // replace the source address with the one from the interface, users can not create fake source addresses
    metadata->source_address = context->interface.address;

    // for each part of the udp datagram we'll have to make a new packet
    size_t offset = 0;
    size_t const limit = HyphaIpSizeOfSpan(span);
    do {
        size_t remaining = limit - offset;
        size_t chunk = (remaining <= HYPHA_IP_MAX_UDP_DATAGRAM_SIZE) ? remaining : HYPHA_IP_MAX_UDP_DATAGRAM_SIZE;
        uint8_t* tmp = &((uint8_t*)span.pointer)[offset];
        HyphaIpSpan_t fragment = {.pointer = tmp, .count = (uint32_t)chunk, .type = HyphaIpSpanTypeUint8_t};
        // acquire a frame which we will start to write all the information into
        HyphaIpEthernetFrame_t* frame = context->external.acquire(context->theirs);
        if (frame == nullptr) {
            context->statistics.frames.failures++;
            status = HyphaIpStatusOutOfMemory;
        } else {
            context->statistics.frames.acquires++;
            status = HyphaIpStatusOk;
        }
        context->external.report(context->theirs, status, __func__, __LINE__);

        HyphaIpUdpHeader_t udp_header = {
            .source_port = metadata->source_port,
            .destination_port = metadata->destination_port,
            .length = (uint16_t)(sizeof(HyphaIpUdpHeader_t) + HyphaIpSizeOfSpan(fragment)),
            .checksum = 0,
        };
        if (HYPHA_IP_USE_UDP_CHECKSUM) {
            HyphaIpPseudoHeader_t pseudo_header = {
                .source = metadata->source_address,
                .destination = metadata->destination_address,
                .protocol = HyphaIpProtocol_UDP,
                .length = udp_header.length,
            };
            (void)pseudo_header;  // suppress unused variable warning
            // TODO compute the checksum
        }
        // copy the UDP header into the frame
        HyphaIpCopyUdpHeaderToFrame(frame, &udp_header);
        // copy the UDP payload into the frame
        HyphaIpCopyUdpDatagramToFrame(frame, fragment);
        // create a span over the whole header+datagram
        HyphaIpSpan_t datagram = {.pointer = &frame->payload[HyphaIpOffsetOfUpdHeader()],
                                  .count = udp_header.length,
                                  .type = HyphaIpSpanTypeUint8_t};

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
        context->external.report(context->theirs, status, __func__, __LINE__);

        status = context->external.release(context->theirs, frame);
        if (HyphaIpIsSuccess(status)) {
            context->statistics.frames.releases++;
        } else {
            context->statistics.frames.failures++;
            // TODO how to recover?
        }
        context->external.report(context->theirs, status, __func__, __LINE__);
        frame = nullptr;  // forget the frame, so we don't use it again

        offset += chunk;
    } while (offset < limit);
    return HyphaIpStatusOk;
}

HyphaIpStatus_e HyphaIpUdpReceiveDatagram(HyphaIpContext_t context, HyphaIpIPv4Header_t* ip_header,
                                          HyphaIpTimestamp_t timestamp, HyphaIpEthernetFrame_t* frame) {
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        printer(context->theirs, "UDP Type Detected\r\n");
    }
    context->statistics.counter.udp.rx.count++;

    HyphaIpUdpHeader_t udp_header;
    HyphaIpCopyUdpHeaderFromFrame(&udp_header, frame);
    HyphaIpSpan_t payload_span = HyphaIpSpanUdpPayload(frame);

    if (udp_header.checksum != 0 && HYPHA_IP_USE_UDP_CHECKSUM) {
        HyphaIpPseudoHeader_t pseudo_header = {
            .source = ip_header->source,
            .destination = ip_header->destination,
            .zero = 0,
            .protocol = HyphaIpProtocol_UDP,
            .length = __builtin_bswap16(udp_header.length + sizeof(HyphaIpUdpHeader_t))};
        memcpy(&pseudo_header.header, &frame->payload[HyphaIpOffsetOfUpdHeader()], sizeof(HyphaIpUdpHeader_t));
        HyphaIpSpan_t header_span = {&pseudo_header, sizeof(pseudo_header), HyphaIpSpanTypeUint8_t};
        // can't trust the length, yet. compute from IP header minus header
        payload_span.count = (ip_header->length - sizeof(HyphaIpIPv4Header_t)) / sizeof(uint16_t);
        if (printer) {
            HyphaIpSpanPrint(context, header_span);
            HyphaIpSpanPrint(context, payload_span);
        }
        // HyphaIpSpan_t empty = {
        //     .pointer = nullptr,
        //     .count = 0U,
        //     .type = HyphaIpSpanTypeUndefined,
        // };
        uint16_t udp_checksum = HyphaIpComputeChecksum(header_span, payload_span);
        // 0.) Is the UDP checksum valid?
        bool udp_checksum_valid = (udp_checksum == HyphaIpChecksumValid);
        printer(context->theirs, "Computed Checksum: %04X (should be %04X)\r\n", udp_checksum, HyphaIpChecksumValid);
        printer(context->theirs, "Provided Checksum: %04X\r\n", udp_header.checksum);
        if (!udp_checksum_valid) {
            context->statistics.udp.rejected++;
            return HyphaIpStatusUDPChecksumRejected;
        }
    }

    context->statistics.udp.accepted++;
    context->statistics.counter.udp.rx.bytes += sizeof(udp_header) + udp_header.length;

    HyphaIpMetaData_t metadata = {.source_address = ip_header->source,
                                  .destination_address = ip_header->destination,
                                  .source_port = udp_header.source_port,
                                  .destination_port = udp_header.destination_port,
                                  .timestamp = timestamp};
    // limit to what we're actually processing
    payload_span.count = udp_header.length - sizeof(HyphaIpUdpHeader_t);
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
