//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP Test implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"
#include "hypha_ip/hypha_ip.h"
#include "stdarg.h"
#include "string.h"
#include "unity.h"

char const *boolean(bool value) { return value ? "true" : "false"; }

/// We, the client, must define this
struct HyphaIpExternalContext {
    HyphaIpTimestamp_t timestamp;
};

HyphaIpStatus_e expected_status = HyphaIpStatusOk;
HyphaIpMetaData_t expected_metadata;
HyphaIpSpan_t expected_payload;
HyphaIpEthernetAddress_t expected_ethernet_source_address;
HyphaIpEthernetAddress_t expected_ethernet_destination_address;
uint16_t expected_reversed_ethertype;
bool expected_receive_udp;
bool actual_receive_udp;
HyphaIpEthernetFrame_t *expected_frame;

void report(HyphaIpExternalContext_t mine, HyphaIpStatus_e status, const char *const func, unsigned int line) {
    TEST_ASSERT_NOT_NULL(mine);
    if (status != HyphaIpStatusOk) {
        printf("%p Error %d in %s:%u\r\n", (void *)mine, (int)status, func, line);
    }
    TEST_ASSERT_EQUAL(expected_status, status);
}

HyphaIpTimestamp_t get_timestamp(HyphaIpExternalContext_t context) {
    TEST_ASSERT_NOT_NULL(context);
    return ++context->timestamp;
}

HyphaIpEthernetFrame_t *acquire(HyphaIpExternalContext_t mine) {
    TEST_ASSERT_NOT_NULL(mine);
    HyphaIpEthernetFrame_t *frame = nullptr;
    frame = (HyphaIpEthernetFrame_t *)malloc(sizeof(HyphaIpEthernetFrame_t));
    return frame;
}

HyphaIpStatus_e release(HyphaIpExternalContext_t mine, HyphaIpEthernetFrame_t *frame) {
    TEST_ASSERT_NOT_NULL(mine);
    TEST_ASSERT_NOT_NULL(frame);
    free(frame);
    return HyphaIpStatusOk;
}

unsigned char test_frame[] = {
    0x01, 0x00, 0x5e, 0x00, 0x00, 0x9b,  // mac (6 bytes)
    0x80, 0x90, 0xa0, 0x12, 0x34, 0x56,  // mac (6 bytes)
#if (HYPHA_IP_USE_VLAN == 1)
    0x81, 0x00, 0x00, 0x01,  // vlan tag (4 bytes)
#endif
    0x08, 0x00,  // ethertype (2)

    0x45, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x80, 0x11, 0x9e, 0xf4,  // ipv4 header (20 bytes)
    172, 16, 0, 7,                                                           // source
    239, 0, 0, 155,                                                          // destination

    // udp header (8 bytes)
    0x04, 0x01, 0x24, 0xa6, 0x00, 0x32, 0xb0, 0xea,
    // cyphal header (24 bytes)
    0x01, 0x04, 0x2e, 0x00, 0xff, 0xff, 0x9b, 0x00, 0x98, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0xd0, 0xa1,
    // cyphal payload
    0x08, 0x90, 0x00, 0x00, 0x90, 0x6a, 0x01, 0x00, 0x38, 0xa9, 0x00, 0x00, 0x00, 0x11,  // end payload
    0x54, 0x0f, 0x30, 0x59                                                               // CRC32 (last 4)
};

#if (HYPHA_IP_USE_VLAN == 1)
#define HYPHA_IP_PAYLOAD_OFFSET 46
#else
#define HYPHA_IP_PAYLOAD_OFFSET 42
#endif

void hyphaip_expected_test_values() {
    HyphaIpIPv4Address_t source = {172, 16, 0, 7};
    expected_metadata.source_address = source;
    HyphaIpIPv4Address_t destination = {239, 0, 0, 155};
    expected_metadata.destination_address = destination;
    expected_metadata.source_port = 1025;
    expected_metadata.destination_port = 9382;
    expected_payload.pointer = &test_frame[HYPHA_IP_PAYLOAD_OFFSET];
    expected_payload.count = sizeof(test_frame) - HYPHA_IP_PAYLOAD_OFFSET;
    expected_payload.type = HyphaIpSpanTypeUint8_t;
    expected_ethernet_destination_address = (HyphaIpEthernetAddress_t){{0x01, 0x00, 0x5e}, {0x00, 0x00, 0x9b}};
    expected_ethernet_source_address = (HyphaIpEthernetAddress_t){{0x80, 0x90, 0xa0}, {0x12, 0x34, 0x56}};
    expected_reversed_ethertype = 0x0008;
    expected_receive_udp = true;
    actual_receive_udp = false;
    expected_frame = (HyphaIpEthernetFrame_t *)&test_frame[0];
}

HyphaIpStatus_e receive(HyphaIpExternalContext_t mine, HyphaIpEthernetFrame_t *frame) {
    TEST_ASSERT_NOT_NULL(mine);
    TEST_ASSERT_NOT_NULL(frame);
    // TODO make a bunch more frames and send them in
    memcpy(frame, test_frame, sizeof(test_frame));
    printf("Receiving frame %p\r\n", (void *)frame);
    return HyphaIpStatusOk;
}

HyphaIpStatus_e transmit(HyphaIpExternalContext_t mine, HyphaIpEthernetFrame_t *frame) {
    TEST_ASSERT_NOT_NULL(mine);
    TEST_ASSERT_NOT_NULL(frame);
    printf("Transmitting frame %p\r\n", (void *)frame);
    // verify that the ETH header is right
    TEST_ASSERT_EQUAL_MEMORY(&expected_ethernet_destination_address, &frame->header.destination,
                             sizeof(HyphaIpEthernetAddress_t));
    TEST_ASSERT_EQUAL_MEMORY(&expected_ethernet_source_address, &frame->header.source,
                             sizeof(HyphaIpEthernetAddress_t));
    TEST_ASSERT_EQUAL(expected_reversed_ethertype, frame->header.type);  // reversed
    // TODO verify that the IP header is right
    // TODO verify that the UDP header is right
    return HyphaIpStatusOk;
}

HyphaIpStatus_e receive_udp(HyphaIpExternalContext_t mine, HyphaIpMetaData_t *meta, HyphaIpSpan_t span) {
    TEST_ASSERT_NOT_NULL(mine);
    TEST_ASSERT_NOT_NULL(meta);
    TEST_ASSERT_NOT_NULL(span.pointer);
    TEST_ASSERT_NOT_EQUAL(0, span.count);  // this may be empty
    printf("Receiving UDP @ %llu ms from " PRIuIPv4Address ":%" PRIu16 " to " PRIuIPv4Address ":%" PRIu16
           " Span " PRIuSpan "\r\n",
           meta->timestamp, meta->source_address.a, meta->source_address.b, meta->source_address.c,
           meta->source_address.d, meta->source_port, meta->destination_address.a, meta->destination_address.b,
           meta->destination_address.c, meta->destination_address.d, meta->destination_port, span.pointer, span.count,
           span.type);

    // verify that the metadata has the correct fields from the ethernet frame above
    uint32_t source_address = HyphaIpIPv4AddressToValue(meta->source_address);
    uint32_t expected_address = HyphaIpIPv4AddressToValue(expected_metadata.source_address);
    TEST_ASSERT_EQUAL(expected_address, source_address);
    TEST_ASSERT_EQUAL(expected_metadata.source_port, meta->source_port);
    uint32_t destination_address = HyphaIpIPv4AddressToValue(meta->destination_address);
    expected_address = HyphaIpIPv4AddressToValue(expected_metadata.destination_address);
    TEST_ASSERT_EQUAL(expected_address, destination_address);
    TEST_ASSERT_EQUAL(expected_metadata.destination_port, meta->destination_port);

    // verify that the bytes to the payload are the expected ones
    TEST_ASSERT_EQUAL_MEMORY(expected_payload.pointer, span.pointer, span.count);
    actual_receive_udp = true;
    return HyphaIpStatusOk;
}

int printer(HyphaIpExternalContext_t mine, char const *const format, ...) {
    TEST_ASSERT_NOT_NULL(mine);
    TEST_ASSERT_NOT_NULL(format);
    va_list args;
    va_start(args, format);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    int ret = vprintf(format, args);
#pragma clang diagnostic pop
    va_end(args);
    return ret;
}

HyphaIpExternalInterface_t externals = {.acquire = acquire,
                                        .release = release,
                                        .transmit = transmit,
                                        .receive = receive,
                                        .print = printer,
                                        .get_monotonic_timestamp = get_timestamp,
                                        .report = report,
                                        .receive_udp = receive_udp};

HyphaIpNetworkInterface_t interface = {
    .mac = {{0x80, 0x90, 0xA0}, {0x12, 0x34, 0x56}},
    .address = {172, 16, 0, 7},
    .netmask = {255, 255, 255, 0},
    .gateway = {172, 16, 0, 1},
};

bool use_good_setup = false;
bool bad_setup_passed = false;
bool use_prepopulated_arp = false;
bool use_prepare_multicast = false;
bool use_prepopulated_ip_filter = false;

HyphaIpContext_t context;
struct HyphaIpExternalContext mine;

void hyphaip_setUp(void) {
    // Set up code for each test
    expected_status = HyphaIpStatusOk;
    if (use_good_setup == true) {
        HyphaIpStatus_e status = HyphaIpInitialize(&context, &interface, &mine, &externals);
        TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
        TEST_ASSERT_NOT_NULL(context);

        if (use_prepopulated_arp) {
            HyphaIpAddressMatch_t matches[] = {
                {{{0x80, 0x90, 0xA0}, {0x12, 0x34, 0x57}}, {172, 16, 0, 11}},
            };
            status = HyphaIpPopulateArpTable(context, HYPHA_IP_DIMOF(matches), matches);
            TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
        }

        if (use_prepopulated_ip_filter) {
            HyphaIpIPv4Address_t addresses[] = {
                {172, 16, 0, 11},
                {172, 16, 0, 12},
                {172, 16, 0, 13},
            };
            status = HyphaIpPopulateIPv4Filter(context, HYPHA_IP_DIMOF(addresses), addresses);
            TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
        }

        if (use_prepare_multicast) {
            HyphaIpIPv4Address_t address = {239, 0, 0, 155};
            status = HyphaIpPrepareUdpReceive(context, address, 9382);
            TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
        }
    }
}

void hyphaip_tearDown(void) {
    HyphaIpStatus_e status;
    if (use_good_setup == true) {
        status = HyphaIpDeinitialize(&context);
        TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
    }
    if (bad_setup_passed == true) {
        use_good_setup = true;
    }
}

void hyphaip_test_NormalChecksum(void) {
    HyphaIpSpan_t empty = HYPHA_IP_DEFAULT_SPAN;
    uint16_t normal_test[] = {0x0001, 0xf203, 0xf4f5, 0xf6f7};
    HyphaIpSpan_t normal_payload = {
        .pointer = normal_test,
        .count = HYPHA_IP_DIMOF(normal_test),
        .type = HyphaIpSpanTypeUint16_t,
    };
    TEST_ASSERT_EQUAL_HEX16(0xddf2, HyphaIpComputeChecksum(empty, normal_payload));
}

void hyphaip_test_FlippedChecksum(void) {
    HyphaIpSpan_t empty = HYPHA_IP_DEFAULT_SPAN;
    uint16_t flipped_test[] = {0x0100, 0x03f2, 0xf5f4, 0xf7f6};
    HyphaIpSpan_t flipped_payload = {
        .pointer = flipped_test,
        .count = HYPHA_IP_DIMOF(flipped_test),
        .type = HyphaIpSpanTypeUint16_t,
    };
    TEST_ASSERT_EQUAL_HEX16(0xf2dd, HyphaIpComputeChecksum(empty, flipped_payload));
}

void hyphaip_test_NormalChecksum2(void) {
    HyphaIpSpan_t empty = HYPHA_IP_DEFAULT_SPAN;
    uint16_t normal_test[] = {0x0001, 0xf203, 0xf4f5, 0xf6f7,
                              0x220d};  // last element is the ~ of the checksum from previous
    HyphaIpSpan_t normal_payload = {
        .pointer = normal_test,
        .count = HYPHA_IP_DIMOF(normal_test),
        .type = HyphaIpSpanTypeUint16_t,
    };
    TEST_ASSERT_EQUAL_HEX16(0xffff, HyphaIpComputeChecksum(empty, normal_payload));
}

void hyphaip_test_FlippedChecksum2(void) {
    HyphaIpSpan_t empty = HYPHA_IP_DEFAULT_SPAN;
    uint16_t flipped_test[] = {0x0100, 0x03f2, 0xf5f4, 0xf7f6,
                               0x0d22};  // last element is the ~ of the checksum from previous
    HyphaIpSpan_t flipped_payload = {
        .pointer = flipped_test,
        .count = HYPHA_IP_DIMOF(flipped_test),
        .type = HyphaIpSpanTypeUint16_t,
    };
    TEST_ASSERT_EQUAL_HEX16(0xffff, HyphaIpComputeChecksum(empty, flipped_payload));
}

void hyphaip_test_BadContext(void) {
    HyphaIpStatus_e status = HyphaIpInitialize(nullptr, &interface, &mine, &externals);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, status);
}

void hyphaip_test_BadInterfacePointer(void) {
    HyphaIpStatus_e status = HyphaIpInitialize(&context, nullptr, &mine, &externals);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);
}

void hyphaip_test_BadInterfaceMac(void) {
    HyphaIpNetworkInterface_t bad_interface = {
        .mac = {{0x01, 0x00, 0x5e}, {0x78, 0x90, 0xAB}},  // can't use multicast address
        .address = {172, 16, 0, 42},
        .netmask = {255, 255, 255, 0},
        .gateway = {172, 16, 0, 1},
    };
    HyphaIpStatus_e status = HyphaIpInitialize(&context, &bad_interface, &mine, &externals);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidMacAddress, status);
}

void hyphaip_test_BadInterfaceGateway(void) {
    HyphaIpNetworkInterface_t bad_interface = {
        .mac = {{0x12, 0x34, 0x56}, {0x78, 0x90, 0xAB}},
        .address = {172, 16, 0, 42},
        .netmask = {255, 255, 255, 0},
        .gateway = {172, 17, 0, 1},  // not on the same network
    };
    HyphaIpStatus_e status = HyphaIpInitialize(&context, &bad_interface, &mine, &externals);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidNetwork, status);
}

void hyphaip_test_BadInterfaceAddress(void) {
    HyphaIpNetworkInterface_t bad_interface = {
        .mac = {{0x12, 0x34, 0x56}, {0x78, 0x90, 0xAB}},
        .address = {239, 0, 0, 155},  // can't use a Multicast as your network interface
        .netmask = {255, 255, 255, 0},
        .gateway = {239, 0, 0, 1},
    };
    HyphaIpStatus_e status = HyphaIpInitialize(&context, &bad_interface, &mine, &externals);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidIpAddress, status);
}

void hyphaip_test_BadInterfaceAddress2(void) {
    HyphaIpNetworkInterface_t bad_interface = {
        .mac = {{0x12, 0x34, 0x56}, {0x78, 0x90, 0xAB}},
        .address = {127, 7, 9, 2},  // can't use a Localhost as your network interface
        .netmask = {255, 255, 255, 0},
        .gateway = {239, 0, 0, 1},
    };
    HyphaIpStatus_e status = HyphaIpInitialize(&context, &bad_interface, &mine, &externals);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidIpAddress, status);
}

void hyphaip_test_BadExternalPointer(void) {
    HyphaIpStatus_e status = HyphaIpInitialize(&context, &interface, &mine, nullptr);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);
}

void hyphaip_test_BadExternalFunctions(void) {
    // Bad external structure
    HyphaIpExternalInterface_t bad_external = {.acquire = nullptr,
                                               .release = nullptr,
                                               .transmit = nullptr,
                                               .receive = nullptr,
                                               .print = nullptr,
                                               .get_monotonic_timestamp = nullptr,
                                               .report = nullptr,
                                               .receive_udp = nullptr};

    HyphaIpStatus_e status = HyphaIpInitialize(&context, &interface, &mine, &bad_external);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);
}

void hyphaip_test_BadDeinitialize(void) {
    HyphaIpStatus_e status = HyphaIpDeinitialize(nullptr);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, status);

    bad_setup_passed = true;
}

void hyphaip_test_GoodLifeCycle() {
    TEST_ASSERT_TRUE(use_good_setup);
    // do nothing as the setup and teardown should do the work
    hyphaip_expected_test_values();  // set the expected values for the next tests
}

void hyphaip_test_Flip16(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpFlipUnit_t flip_test[] = {{sizeof(uint16_t), 3}};
    uint16_t test[] = {0xDEAD, 0xC0DE, 0xFACE};
    uint16_t out[HYPHA_IP_DIMOF(test)] = {};
    // HyphaIpPrintArray(context, test);
    // HyphaIpPrintArray(context, out);
    TEST_ASSERT_EQUAL(6, HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_test), flip_test, out, test));
    // HyphaIpPrintArray(context, out);
    uint16_t expected[] = {0xADDE, 0xDEC0, 0xCEFA};
    TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));
}

void hyphaip_test_Flip32(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpFlipUnit_t flip_test[] = {{sizeof(uint32_t), 3}};
    uint32_t test[] = {0xDEADFFCC, 0xB00CC0DE, 0xAAEEFACE};
    uint32_t out[HYPHA_IP_DIMOF(test)] = {};
    // HyphaIpPrintArray(context, test);
    // HyphaIpPrintArray(context, out);
    TEST_ASSERT_EQUAL(12, HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_test), flip_test, out, test));
    // HyphaIpPrintArray(context, out);
    uint32_t expected[] = {0xCCFFADDE, 0xDEC00CB0, 0xCEFAEEAA};
    TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));
}

void hyphaip_test_Flip64(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpFlipUnit_t flip_test[] = {{sizeof(uint64_t), 3}};
    uint64_t test[] = {0xFACE'CCCC'DEAD'FFFF, 0xBABE'BBBB'FFFF'C0DE, 0xDEAD'9999'EEEE'FACE};
    uint64_t out[HYPHA_IP_DIMOF(test)] = {};
    // HyphaIpPrintArray(context, test);
    // HyphaIpPrintArray(context, out);
    TEST_ASSERT_EQUAL(24, HyphaIpFlipCopy(HYPHA_IP_DIMOF(flip_test), flip_test, out, test));
    // HyphaIpPrintArray(context, out);
    uint64_t expected[] = {0xFFFF'ADDE'CCCC'CEFA, 0xDEC0'FFFF'BBBB'BEBA, 0xCEFA'EEEE'9999'ADDE};
    // HyphaIpPrintArray(context, expected);
    TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));
}

void hyphaip_test_Contextless(void) {
    TEST_ASSERT_EQUAL(true, HyphaIpIsLocalhostIPv4Address(hypha_ip_localhost));
    TEST_ASSERT_EQUAL(true, HyphaIpIsMulticastEthernetAddress(hypha_ip_ethernet_multicast));
    TEST_ASSERT_EQUAL(true, HyphaIpIsMulticastIPv4Address(hypha_ip_mdns));
    HyphaIpIPv4Address_t hypha_ip_reserved = {240, 17, 99, 1};
    TEST_ASSERT_EQUAL(true, HyphaIpIsReservedIPv4Address(hypha_ip_reserved));
    TEST_ASSERT_EQUAL(0x7F000001U, HyphaIpIPv4AddressToValue(hypha_ip_localhost));
#if (HYPHA_IP_USE_VLAN == 1)
    TEST_ASSERT_EQUAL(18U, offsetof(HyphaIpEthernetFrame_t, payload));
#else
    TEST_ASSERT_EQUAL(14U, offsetof(HyphaIpEthernetFrame_t, payload));
#endif
    // Test a bunch of addresses for being private
    HyphaIpIPv4Address_t private_addresses[] = {
        {10, 0, 0, 1},      // Class A
        {172, 16, 0, 1},    // Class B
        {192, 168, 0, 1},   // Class C
        {192, 0, 2, 1},     // Documentation
        {198, 51, 100, 1},  // Documentation
        {203, 0, 113, 1},   // Documentation
        {169, 254, 0, 1},   // Link-local
    };
    for (size_t i = 0; i < HYPHA_IP_DIMOF(private_addresses); i++) {
        TEST_ASSERT_TRUE(HyphaIpIsPrivateIPv4Address(private_addresses[i]));
    }
    // Test a bunch of addresses for not being private
    HyphaIpIPv4Address_t non_private_addresses[] = {
        {8, 8, 8, 8},       // Public DNS
        {1, 1, 1, 1},       // Public IP
        {172, 15, 0, 1},    // Class B, not
        {192, 169, 0, 1},   // Class C, not
        {204, 0, 113, 2},   // Close but not it
        {198, 51, 102, 2},  // Close but not it
        hypha_ip_mdns       // mDNS
    };
    for (size_t i = 0; i < HYPHA_IP_DIMOF(non_private_addresses); i++) {
        TEST_ASSERT_FALSE(HyphaIpIsPrivateIPv4Address(non_private_addresses[i]));
    }
}

void hyphaip_test_ConvertMulticast(void) {
    HyphaIpIPv4Address_t ip = {239, 1, 0, 15};
    HyphaIpEthernetAddress_t mac = hypha_ip_ethernet_local;
    HyphaIpConvertMulticast(&mac, ip);
    HyphaIpEthernetAddress_t expected = {{0x01, 0x00, 0x5E}, {0x01, 0x00, 0x0F}};
    TEST_ASSERT_EQUAL_MEMORY(&mac, &expected, 6);
}

void hyphaip_test_PopulateArpTable(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpStatus_e status;

    // Pre-populate the ARP table with a single entry
    // This is used to test the ARP resolution in the receive and transmit functions

    HyphaIpAddressMatch_t matches[] = {
        {{{0x80, 0x90, 0xA0}, {0x12, 0x34, 0x57}}, {172, 16, 0, 11}},
    };

    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, HyphaIpPopulateArpTable(nullptr, 0, nullptr));
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, HyphaIpPopulateArpTable(context, 0, nullptr));
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, HyphaIpPopulateArpTable(context, HYPHA_IP_DIMOF(matches), nullptr));
    status = HyphaIpPopulateArpTable(context, HYPHA_IP_DIMOF(matches), matches);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);

    // Verify that the ARP table has been populated correctly
    HyphaIpIPv4Address_t ipv4 = HyphaIpFindIPv4Address(context, &matches[0].mac);
    HyphaIpEthernetAddress_t mac = HyphaIpFindEthernetAddress(context, &matches[0].ipv4);
    TEST_ASSERT_EQUAL_MEMORY(&mac, &matches[0].mac, sizeof(HyphaIpEthernetAddress_t));
    TEST_ASSERT_EQUAL_MEMORY(&ipv4, &matches[0].ipv4, sizeof(HyphaIpIPv4Address_t));

    use_prepopulated_arp = true;
}

void hyphaip_test_PopulateEthernetFilter(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpEthernetAddress_t addresses[] = {
        {{0x80, 0x90, 0xA0}, {0x12, 0x34, 0x57}},
        {{0x80, 0x90, 0xA1}, {0x12, 0x34, 0x58}},
        {{0x80, 0x90, 0xA2}, {0x12, 0x34, 0x59}},
    };

    // before the filter has been enabled all addresses are permitted
    // TEST_ASSERT_TRUE(HyphaIpIsPermittedEthernetAddress(context, addresses[0]));
    // TEST_ASSERT_TRUE(HyphaIpIsPermittedEthernetAddress(context, addresses[1]));
    // TEST_ASSERT_TRUE(HyphaIpIsPermittedEthernetAddress(context, addresses[2]));

    // TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_LOCALHOST == 1,
    //                   HyphaIpIsPermittedEthernetAddress(context, hypha_ip_ethernet_local));
    // TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_BROADCAST == 1,
    //                   HyphaIpIsPermittedEthernetAddress(context, hypha_ip_ethernet_broadcast));
    // TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_MULTICAST,
    //                   HyphaIpIsPermittedEthernetAddress(context, hypha_ip_ethernet_multicast));

    HyphaIpStatus_e status = HyphaIpPopulateEthernetFilter(nullptr, HYPHA_IP_DIMOF(addresses), addresses);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, status);

    status = HyphaIpPopulateEthernetFilter(context, 0, addresses);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);

    status = HyphaIpPopulateEthernetFilter(context, HYPHA_IP_DIMOF(addresses), nullptr);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);

    status = HyphaIpPopulateEthernetFilter(context, HYPHA_IP_DIMOF(addresses), addresses);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);

    TEST_ASSERT_TRUE(HyphaIpIsPermittedEthernetAddress(context, addresses[0]));
    TEST_ASSERT_TRUE(HyphaIpIsPermittedEthernetAddress(context, addresses[1]));
    TEST_ASSERT_TRUE(HyphaIpIsPermittedEthernetAddress(context, addresses[2]));
    TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_LOCALHOST,
                      HyphaIpIsPermittedEthernetAddress(context, hypha_ip_ethernet_local));
    // broadcasts are a subtype of multicast to the logic internally will hit the multicast check first
    TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_BROADCAST,
                      HyphaIpIsPermittedEthernetAddress(context, hypha_ip_ethernet_broadcast));
    TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_MULTICAST,
                      HyphaIpIsPermittedEthernetAddress(context, hypha_ip_ethernet_multicast));
}

void hyphaip_test_BadRunOnce(void) {
    HyphaIpStatus_e status = HyphaIpRunOnce(nullptr);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, status);
}

void hyphaip_test_PrepareMulticast(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpIPv4Address_t address = {239, 0, 0, 155};
    HyphaIpStatus_e status = HyphaIpPrepareUdpReceive(nullptr, address, 9382);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, status);

    status = HyphaIpPrepareUdpReceive(context, address, 9382);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);

    use_prepare_multicast = true;
}

void hyphaip_test_PrepareIpFilter(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpIPv4Address_t addresses[] = {
        {172, 16, 0, 11},
        {172, 16, 0, 12},
        {172, 16, 0, 13},
    };
    HyphaIpStatus_e status = HyphaIpPopulateIPv4Filter(nullptr, HYPHA_IP_DIMOF(addresses), addresses);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidContext, status);

    status = HyphaIpPopulateIPv4Filter(context, 0, addresses);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);

    status = HyphaIpPopulateIPv4Filter(context, HYPHA_IP_DIMOF(addresses), nullptr);
    TEST_ASSERT_EQUAL(HyphaIpStatusInvalidArgument, status);

    status = HyphaIpPopulateIPv4Filter(context, HYPHA_IP_DIMOF(addresses), addresses);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);

    TEST_ASSERT_TRUE(HyphaIpIsPermittedIPv4Address(context, addresses[0]));
    TEST_ASSERT_TRUE(HyphaIpIsPermittedIPv4Address(context, addresses[1]));
    TEST_ASSERT_TRUE(HyphaIpIsPermittedIPv4Address(context, addresses[2]));

    TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_LOCALHOST == 1, HyphaIpIsPermittedIPv4Address(context, hypha_ip_localhost));
    TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_MULTICAST == 1, HyphaIpIsPermittedIPv4Address(context, hypha_ip_mdns));
    TEST_ASSERT_EQUAL(HYPHA_IP_ALLOW_ANY_BROADCAST == 1,
                      HyphaIpIsPermittedIPv4Address(context, hypha_ip_limited_broadcast));
    TEST_ASSERT_FALSE(HyphaIpIsPermittedIPv4Address(context, hypha_ip_default_route));

    use_prepopulated_ip_filter = true;
}

void hyphaip_test_ReceiveOneFrame(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpStatus_e status = HyphaIpRunOnce(context);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
}

void hyphaip_test_TransmitOneFrame(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    HyphaIpMetaData_t metadata = {.source_address = hypha_ip_localhost,  // ignored
                                  .source_port = 1025,
                                  .destination_address = {239, 0, 0, 155},
                                  .destination_port = 9382,
                                  .timestamp = 0};  // will be filled in by the transmit function
    HyphaIpSpan_t datagram = {.pointer = &test_frame[HYPHA_IP_PAYLOAD_OFFSET],
                              .count = sizeof(test_frame) - HYPHA_IP_PAYLOAD_OFFSET,
                              .type = HyphaIpSpanTypeUint8_t};
    HyphaIpStatus_e status = HyphaIpTransmitUdpDatagram(context, &metadata, datagram);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
    TEST_ASSERT_NOT_EQUAL(0U, metadata.timestamp);  // has to fill in the timestamp
    TEST_ASSERT_GREATER_THAN(0U, HyphaIpGetStatistics(context)->udp.accepted);
    TEST_ASSERT_GREATER_THAN(0U, HyphaIpGetStatistics(context)->ip.accepted);
    TEST_ASSERT_GREATER_THAN(0U, HyphaIpGetStatistics(context)->mac.accepted);
}

void hyphaip_test_TransmitReceiveLocalhost(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    expected_metadata.source_address = hypha_ip_localhost;  // ignored
    expected_metadata.source_port = 1025;
    expected_metadata.destination_address = hypha_ip_localhost;
    expected_metadata.destination_port = 9382;
    HyphaIpMetaData_t metadata = {.source_address = hypha_ip_localhost,  // ignored
                                  .source_port = 1025,
                                  .destination_address = hypha_ip_localhost,
                                  .destination_port = 9382,
                                  .timestamp = 0};  // will be filled in by the transmit function
    HyphaIpSpan_t datagram = {.pointer = &test_frame[HYPHA_IP_PAYLOAD_OFFSET],
                              .count = sizeof(test_frame) - HYPHA_IP_PAYLOAD_OFFSET,
                              .type = HyphaIpSpanTypeUint8_t};
    HyphaIpStatus_e status = HyphaIpTransmitUdpDatagram(context, &metadata, datagram);
    TEST_ASSERT_EQUAL(HyphaIpStatusOk, status);
    TEST_ASSERT_NOT_EQUAL(0U, metadata.timestamp);  // has to fill in the timestamp
    TEST_ASSERT_GREATER_THAN(0U, HyphaIpGetStatistics(context)->udp.accepted);
    TEST_ASSERT_GREATER_THAN(0U, HyphaIpGetStatistics(context)->ip.accepted);
    TEST_ASSERT_EQUAL(1U, HyphaIpGetStatistics(context)->mac.accepted);  // IGMP went out already
}

void hyphaip_test_ReceiveOneLargeFrame(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    TEST_IGNORE_MESSAGE("We need to have a way to generate large frames for this test");
}

void hyphaip_test_TransmitOneLargeFrame(void) {
    TEST_ASSERT_TRUE(use_good_setup);
    TEST_IGNORE_MESSAGE("We need to have a way to generate large frames for this test");
}
