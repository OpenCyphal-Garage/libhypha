//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The checksum implementation for the Hypha IP stack.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
#include "hypha_ip/hypha_internal.h"

uint16_t HyphaIpComputeChecksum(HyphaIpSpan_t header_span, HyphaIpSpan_t payload_span) {
    // TODO check types, must be uint8_t or uint16_t
    // TODO support byte payload data (odd lengths) if so, have to be uint8_ts
    // TODO then remove debug prints
    // printf("Header " PRIuSpan " Payload " PRIuSpan "\r\n", header_span.pointer, header_span.count, header_span.type,
    //        payload_span.pointer, payload_span.count, payload_span.type);
    uint16_t *header = (uint16_t *)header_span.pointer;
    uint16_t *payload = (uint16_t *)payload_span.pointer;
    uint32_t sum = 0U;
    uint16_t lss = 0U;  // least significant short
    uint16_t mss = 0U;  // most significant short
    for (size_t i = 0U; i < header_span.count; i++) {
        // printf("sum=%08x += %04x\r\n", sum, header[i]);
        sum += header[i];
        // printf("sum=%08x\r\n", sum);
    }
    for (size_t i = 0U; i < payload_span.count; i++) {
        // printf("sum=%08x += %04x\r\n", sum, payload[i]);
        sum += payload[i];
        // printf("sum=%08x\r\n", sum);
    }
    // printf("intermediate sum=%08x\r\n", sum);
    // perform the overflow reduction
    do {
        lss = (sum & 0x0000FFFFU) >> 0u;
        mss = (sum & 0xFFFF0000U) >> 16u;
        // printf("MSS=%04x LSS=%04X\r\n", mss, lss);
        sum = lss + mss;
        // printf("Added Sum=%08x\r\n", sum);
    } while (mss > 0);  // while it overflows, repeat
    lss = (sum & 0x0000FFFFU) >> 0;
    // printf("result = %04x\r\n", lss);
    return lss;
}
