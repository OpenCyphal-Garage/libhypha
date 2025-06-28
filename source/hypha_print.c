//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP Printing implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

void HyphaIpPrintArray64(HyphaIpContext_t context, size_t len, uint64_t data[len]) {
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        for (size_t i = 0U; i < len; i++) {
            if (((i % 4) == 0) && (i != 0)) {
                printer(context->theirs, "\r\n");
            }
            printer(context->theirs, "%016" PRIx64 " ", data[i]);
        }
        printer(context->theirs, "\r\n");
    }
}

void HyphaIpPrintArray32(HyphaIpContext_t context, size_t len, uint32_t data[len]) {
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        for (size_t i = 0U; i < len; i++) {
            if (((i % 8) == 0) && (i != 0)) {
                printer(context->theirs, "\r\n");
            }
            printer(context->theirs, "%08" PRIx32 " ", data[i]);
        }
        printer(context->theirs, "\r\n");
    }
}

void HyphaIpPrintArray16(HyphaIpContext_t context, size_t len, uint16_t data[len]) {
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        for (size_t i = 0U; i < len; i++) {
            if (((i % 16) == 0) && (i != 0)) {
                printer(context->theirs, "\r\n");
            }
            printer(context->theirs, "%04" PRIx16 " ", data[i]);
        }
        printer(context->theirs, "\r\n");
    }
}

void HyphaIpPrintArray08(HyphaIpContext_t context, size_t len, uint8_t data[len]) {
    HyphaIpPrinter_f printer = context->external.print;
    if (printer) {
        for (size_t i = 0U; i < len; i++) {
            if (((i % 32) == 0) && (i != 0)) {
                printer(context->theirs, "\r\n");
            }
            printer(context->theirs, "%02" PRIx8 " ", data[i]);
        }
        printer(context->theirs, "\r\n");
    }
}
