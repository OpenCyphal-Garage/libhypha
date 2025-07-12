#include "hypha_ip/hypha_ip.h"

/// ![Hypha IP External Context Example]
/// @brief The following is what you need to define in order to use Hypha IP.
struct HyphaIpExternalContext {
    // Define the structure of your external context here
    // This would contain context you need for your Ethernet Driver
    // a Time system, etc.
    int dummy;  ///< [replace] Placeholder for actual context data so this will compile.
};
/// ![Hypha IP External Context Example]

/// ![Hypha IP User Provided Definitions]
void report(HyphaIpExternalContext_t mine, HyphaIpStatus_e status, const char *const func, const char *const file,
            unsigned int line) {
    (void)mine;    // Suppress unused parameter warning
    (void)status;  // Suppress unused parameter warning
    (void)func;    // Suppress unused parameter warning
    (void)file;    // Suppress unused parameter warning
    (void)line;    // Suppress unused parameter warning
    return;
}

HyphaIpTimestamp_t get_timestamp(HyphaIpExternalContext_t context) {
    (void)context;  // Suppress unused parameter warning
    return 0U;
}

HyphaIpEthernetFrame_t *acquire(HyphaIpExternalContext_t mine) {
    (void)mine;  // Suppress unused parameter warning
    return nullptr;
}

HyphaIpStatus_e release(HyphaIpExternalContext_t mine, HyphaIpEthernetFrame_t *frame) {
    (void)mine;                          // Suppress unused parameter warning
    (void)frame;                         // Suppress unused parameter warning
    return HyphaIpStatusNotImplemented;  // This is a stub for the test
}

HyphaIpStatus_e receive(HyphaIpExternalContext_t mine, HyphaIpEthernetFrame_t *frame) {
    (void)mine;                          // Suppress unused parameter warning
    (void)frame;                         // Suppress unused parameter warning
    return HyphaIpStatusNotImplemented;  // This is a stub for the test
}

HyphaIpStatus_e transmit(HyphaIpExternalContext_t mine, HyphaIpEthernetFrame_t *frame) {
    (void)mine;                          // Suppress unused parameter warning
    (void)frame;                         // Suppress unused parameter warning
    return HyphaIpStatusNotImplemented;  // This is a stub for the test
}

HyphaIpStatus_e receive_udp(HyphaIpExternalContext_t mine, HyphaIpMetaData_t *meta, HyphaIpSpan_t span) {
    (void)mine;                          // Suppress unused parameter warning
    (void)meta;                          // Suppress unused parameter warning
    (void)span;                          // Suppress unused parameter warning
    return HyphaIpStatusNotImplemented;  // This is a stub for the test
}

int printer(HyphaIpExternalContext_t mine, char const *const format, ...) {
    (void)mine;                          // Suppress unused parameter warning
    (void)format;                        // Suppress unused parameter warning
    return HyphaIpStatusNotImplemented;  // This is a stub for the test
}

HyphaIpExternalInterface_t externals = {.acquire = acquire,
                                        .release = release,
                                        .transmit = transmit,
                                        .receive = receive,
                                        .print = printer,
                                        .get_monotonic_timestamp = get_timestamp,
                                        .report = report,
                                        .receive_udp = receive_udp};
/// ![Hypha IP User Provided Definitions]

/// ![Hypha IP Network Interface Example]
HyphaIpNetworkInterface_t interface = {
    .mac = {{0x80, 0x90, 0xA0}, {0x12, 0x34, 0x56}},
    .address = {172, 16, 0, 42},
    .netmask = {255, 255, 255, 0},
    .gateway = {172, 16, 0, 1},
};
/// ![Hypha IP Network Interface Example]]

HyphaIpContext_t context;

// Statically allocated external context or can come from whatever allocator you need.
struct HyphaIpExternalContext mine;

int main(int argc, char *argv[argc]) {
    (void)argc;  // Suppress unused parameter warning
    (void)argv;  // Suppress unused parameter warning

    /// ![Hypha IP Lifecycle Example]
    // Initialize the Hypha IP context
    HyphaIpStatus_e status = HyphaIpInitialize(&context, &interface, &mine, &externals);
    // check if the initialization was successful
    if (HyphaIpIsSuccess(status)) {
        // Initialization was successful, proceed with the lifecycle
    } else {
        // Handle initialization failure
        return -1;
    }

    // Initialize any necessary ARP
    HyphaIpAddressMatch_t matches[] = {
        {{{0x80, 0x90, 0xA0}, {0x12, 0x34, 0x57}}, {172, 16, 0, 11}},
    };
    status = HyphaIpPopulateArpTable(context, HYPHA_IP_DIMOF(matches), matches);
    // check if the ARP table was populated successfully

    // Initialize any necessary IPv4 filters
    HyphaIpIPv4Address_t addresses[] = {
        {172, 16, 0, 11},
        {172, 16, 0, 12},
        {172, 16, 0, 13},
    };
    status = HyphaIpPopulateIPv4Filter(context, HYPHA_IP_DIMOF(addresses), addresses);
    // check if the IPv4 filter was populated successfully

    // Prepare to receive UDP on a multicast address
    HyphaIpIPv4Address_t address = {239, 0, 0, 155};
    status = HyphaIpPrepareUdpReceive(context, address, 9382);
    // check if the UDP receive preparation was successful

    // The main loop
    while (true) {
        // This will handle incoming frames, process them, and respond as necessary. It will call into
        // the provided Receive functions when specific types are received.
        status = HyphaIpRunOnce(context);
        // check if the run was successful

        // Send whatever frames you want to send via the transmit function
        uint8_t data[42];  // <-- put whatever you want to send as a datagram here
        HyphaIpSpan_t datagram = {.pointer = data, .count = HYPHA_IP_DIMOF(data), .type = HyphaIpSpanTypeUint8_t};
        // Define the metadata for the datagram
        HyphaIpMetaData_t metadata = {
            .source_address = interface.address,
            .destination_address = {239, 0, 0, 153},
            .source_port = 9382,  // whatever you want, the stack doesn't track this.
            .destination_port = 9382,
            .timestamp = 0U,
        };
        // Transmit UDP datagrams as needed
        status = HyphaIpTransmitUdpDatagram(context, &metadata, datagram);
        // check if the transmit was successful

        /// @cond USE_ICMP
#if defined(HYPHA_IP_USE_ICMP) || defined(HYPHA_IP_USE_ICMPv6)
        // Transmit ICMP datagrams as needed
        status = HyphaIpTransmitIcmpDatagram(context, HyphaIpIcmpTypeEchoRequest, 0, &metadata, datagram);
#endif
        /// @endcond
    }

    // Once we are done, we can deinitialize the context
    status = HyphaIpDeinitialize(&context);
    // check if the deinitialization was successful

    // Any context cleanup for the client context can be done here

    /// ![Hypha IP Lifecycle Example]
    return 0;  // Exit the program
}
