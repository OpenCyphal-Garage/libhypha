//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
/// @file
/// The Hypha IP Status implementation.
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#include "hypha_ip/hypha_internal.h"

bool HyphaIpIsSuccess(HyphaIpStatus_e status) { return (status == HyphaIpStatusOk); }

bool HyphaIpIsFailure(HyphaIpStatus_e status) {
    return (status < 0);  // negative values are failures
}
