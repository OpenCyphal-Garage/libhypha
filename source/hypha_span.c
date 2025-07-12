//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP Span implementations
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#include "hypha_ip/hypha_internal.h"

bool HyphaIpSpanIsEmpty(HyphaIpSpan_t span) { return (span.count == 0U); }

size_t HyphaIpSpanSize(HyphaIpSpan_t span) {
    size_t bytes = 0U;
    switch (span.type) {
        case HyphaIpSpanTypeUndefined: {
            bytes = 0U;
            break;
        }
        case HyphaIpSpanTypeChar: {
            bytes = span.count * sizeof(char);
            break;
        }
        case HyphaIpSpanTypeShort: {
            bytes = span.count * sizeof(short);
            break;
        }
        case HyphaIpSpanTypeInt: {
            bytes = span.count * sizeof(int);
            break;
        }
        case HyphaIpSpanTypeLong: {
            bytes = span.count * sizeof(long);
            break;
        }
        case HyphaIpSpanTypeLongLong: {
            bytes = span.count * sizeof(long long);
            break;
        }
        case HyphaIpSpanTypeFloat: {
            bytes = span.count * sizeof(float);
            break;
        }
        case HyphaIpSpanTypeDouble: {
            bytes = span.count * sizeof(double);
            break;
        }
        case HyphaIpSpanTypeInt8_t: {
            bytes = span.count * sizeof(int8_t);
            break;
        }
        case HyphaIpSpanTypeInt16_t: {
            bytes = span.count * sizeof(int16_t);
            break;
        }
        case HyphaIpSpanTypeInt32_t: {
            bytes = span.count * sizeof(int32_t);
            break;
        }
        case HyphaIpSpanTypeInt64_t: {
            bytes = span.count * sizeof(int64_t);
            break;
        }
        case HyphaIpSpanTypeUint8_t: {
            bytes = span.count * sizeof(uint8_t);
            break;
        }
        case HyphaIpSpanTypeUint16_t: {
            bytes = span.count * sizeof(uint16_t);
            break;
        }
        case HyphaIpSpanTypeUint32_t: {
            bytes = span.count * sizeof(uint32_t);
            break;
        }
        case HyphaIpSpanTypeUint64_t: {
            bytes = span.count * sizeof(uint64_t);
            break;
        }
    }
    return bytes;
}

void HyphaIpSpanPrint(HyphaIpContext_t context, HyphaIpSpan_t span) {
    void *pointer = span.pointer;
    size_t count = span.count;
    int type = span.type;
    HYPHA_IP_PRINT(context, HyphaIpPrintLevelInfo, HyphaIpPrintLayerUnknown, "" PRIuSpan "\r\n", pointer, count, type);
    switch (span.type) {
        case HyphaIpSpanTypeUint8_t: {
            uint8_t *tmp = (uint8_t *)pointer;
            HyphaIpPrintArray08(context, count, tmp);
            break;
        }
        case HyphaIpSpanTypeUint16_t: {
            uint16_t *tmp = (uint16_t *)pointer;
            HyphaIpPrintArray16(context, count, tmp);
            break;
        }
        case HyphaIpSpanTypeUint32_t: {
            uint32_t *tmp = (uint32_t *)pointer;
            HyphaIpPrintArray32(context, count, tmp);
            break;
        }
        case HyphaIpSpanTypeUint64_t: {
            uint64_t *tmp = (uint64_t *)pointer;
            HyphaIpPrintArray64(context, count, tmp);
            break;
        }
    }
}

HyphaIpSpan_t HyphaIpSpanIpHeader(HyphaIpEthernetFrame_t *frame) {
    size_t offset = 0u;
    return (HyphaIpSpan_t){.pointer = &frame->payload[offset],
                           .count = sizeof(HyphaIpIPv4Header_t) / sizeof(uint16_t),
                           .type = HyphaIpSpanTypeUint16_t};
}

HyphaIpSpan_t HyphaIpSpanUdpHeader(HyphaIpEthernetFrame_t *frame) {
    size_t offset = HyphaIpOffsetOfUDPHeader();
    return (HyphaIpSpan_t){.pointer = &frame->payload[offset],
                           .count = sizeof(HyphaIpUDPHeader_t) / sizeof(uint16_t),
                           .type = HyphaIpSpanTypeUint16_t};
}

HyphaIpSpan_t HyphaIpSpanUdpDatagram(HyphaIpEthernetFrame_t *frame) {
    size_t offset = HyphaIpOffsetOfUDPHeader();
    size_t length = (sizeof(frame->payload) - offset) / sizeof(uint16_t);
    return (HyphaIpSpan_t){
        .pointer = &frame->payload[offset], .count = (uint32_t)length, .type = HyphaIpSpanTypeUint16_t};
}

HyphaIpSpan_t HyphaIpSpanUdpPayload(HyphaIpEthernetFrame_t *frame) {
    size_t offset = HyphaIpOffsetOfUDPPayload();
    size_t length = (sizeof(frame->payload) - offset) / sizeof(uint16_t);
    return (HyphaIpSpan_t){
        .pointer = &frame->payload[offset], .count = (uint32_t)length, .type = HyphaIpSpanTypeUint16_t};
}

bool HyphaIpSpanResize(HyphaIpSpan_t *span, uint32_t new_size) {
    if (new_size > span->count) {
        return false;  // Cannot resize to a larger size
    }
    span->count = (uint32_t)new_size;
    return true;
}
