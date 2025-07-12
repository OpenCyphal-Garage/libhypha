//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP Unity Test Main File.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "unity.h"

extern void hyphaip_setUp(void);
extern void hyphaip_tearDown(void);

void setUp(void) { hyphaip_setUp(); }

void tearDown(void) { hyphaip_tearDown(); }

extern void hyphaip_test_Constants(void);
extern void hyphaip_test_Span(void);
extern void hyphaip_test_NormalChecksum(void);
extern void hyphaip_test_FlippedChecksum(void);
extern void hyphaip_test_NormalChecksum2(void);
extern void hyphaip_test_FlippedChecksum2(void);
extern void hyphaip_test_BadContext(void);
extern void hyphaip_test_BadInterfacePointer(void);
extern void hyphaip_test_BadInterfaceGateway(void);
extern void hyphaip_test_BadInterfaceAddress(void);
extern void hyphaip_test_BadInterfaceAddress2(void);
extern void hyphaip_test_BadInterfaceMac(void);
extern void hyphaip_test_BadExternalPointer(void);
extern void hyphaip_test_BadExternalFunctions(void);
extern void hyphaip_test_BadDeinitialize(void);
extern void hyphaip_test_GoodLifeCycle(void);
extern void hyphaip_test_Contextless(void);
extern void hyphaip_test_Flip16(void);
extern void hyphaip_test_Flip32(void);
extern void hyphaip_test_Flip64(void);
extern void hyphaip_test_PopulateArpTable(void);
extern void hyphaip_test_PopulateEthernetFilter(void);
extern void hyphaip_test_PopulateIpFilter(void);
extern void hyphaip_test_ConvertMulticast(void);
extern void hyphaip_test_PrepareMulticast(void);
extern void hyphaip_test_BadRunOnce(void);
extern void hyphaip_test_CheckOffsets(void);
extern void hyphaip_test_ReceiveOneFrame(void);
extern void hyphaip_test_TransmitOneFrame(void);
extern void hyphaip_test_TransmitReceiveLocalhost(void);
extern void hyphaip_test_ReceiveOneLargeFrame(void);
extern void hyphaip_test_TransmitOneLargeFrame(void);

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(hyphaip_test_Constants);
    RUN_TEST(hyphaip_test_Span);
    RUN_TEST(hyphaip_test_NormalChecksum);
    RUN_TEST(hyphaip_test_NormalChecksum2);
    RUN_TEST(hyphaip_test_FlippedChecksum);
    RUN_TEST(hyphaip_test_FlippedChecksum2);
    RUN_TEST(hyphaip_test_BadContext);
    RUN_TEST(hyphaip_test_BadInterfacePointer);
    RUN_TEST(hyphaip_test_BadInterfaceGateway);
    RUN_TEST(hyphaip_test_BadInterfaceAddress);
    RUN_TEST(hyphaip_test_BadInterfaceAddress2);
    RUN_TEST(hyphaip_test_BadInterfaceMac);
    RUN_TEST(hyphaip_test_BadExternalPointer);
    RUN_TEST(hyphaip_test_BadExternalFunctions);
    RUN_TEST(hyphaip_test_BadDeinitialize);  // <-- this has to be called before doing "good" cycles
    RUN_TEST(hyphaip_test_GoodLifeCycle);
    RUN_TEST(hyphaip_test_Flip16);
    RUN_TEST(hyphaip_test_Flip32);
    RUN_TEST(hyphaip_test_Flip64);
    RUN_TEST(hyphaip_test_ConvertMulticast);
    RUN_TEST(hyphaip_test_Contextless);
    RUN_TEST(hyphaip_test_BadRunOnce);
    RUN_TEST(hyphaip_test_CheckOffsets);
    RUN_TEST(hyphaip_test_PopulateArpTable);
    RUN_TEST(hyphaip_test_PopulateEthernetFilter);
    RUN_TEST(hyphaip_test_PrepareMulticast);
    RUN_TEST(hyphaip_test_PopulateIpFilter);
    RUN_TEST(hyphaip_test_ReceiveOneFrame);
    RUN_TEST(hyphaip_test_TransmitOneFrame);
    RUN_TEST(hyphaip_test_TransmitReceiveLocalhost);
    // RUN_TEST(hyphaip_test_ReceiveOneLargeFrame);
    // RUN_TEST(hyphaip_test_TransmitOneLargeFrame);

    return UNITY_END();
}
