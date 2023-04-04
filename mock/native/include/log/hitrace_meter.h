/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOCK_NATIVE_INCLUDE_HILOG_HITRACE_METER_H
#define MOCK_NATIVE_INCLUDE_HILOG_HITRACE_METER_H

#include <string>

namespace OHOS {
#ifdef __cplusplus
extern "C" {
#endif
#define HITRACE_TAG_ZIMAGE (-1)
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
#endif // MOCK_NATIVE_INCLUDE_HILOG_HITRACE_METER_H
}