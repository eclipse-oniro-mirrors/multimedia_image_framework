#ifndef INTERFACES_INNERKITS_NATIVE_HITRACE_METER_H
#define INTERFACES_INNERKITS_NATIVE_HITRACE_METER_H

#include <string>

#ifdef __cplusplus
extern "C" {
#endif
#define HITRACE_TAG_ZIMAGE -1
/**
 * Track the beginning of a context.
 */
void StartTrace(uint64_t label, const std::string& value, float limit = -1);

/**
 * Track the end of a context.
 */
void FinishTrace(uint64_t label);

#ifdef __cplusplus
}
#endif
#endif // INTERFACES_INNERKITS_NATIVE_HITRACE_METER_H