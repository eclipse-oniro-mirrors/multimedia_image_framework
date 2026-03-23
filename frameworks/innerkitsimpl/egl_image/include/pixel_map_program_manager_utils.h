/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_PROGRAM_MANAGER_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_PROGRAM_MANAGER_UTILS_H

#include <cstddef>
#include <cstdint>

#include "pixel_map_gl_utils.h"

namespace OHOS {
namespace Media {
namespace PixelMapProgramManagerUtils {
constexpr int32_t MAX_GL_INSTANCE_NUM = 8;

inline bool IsPoolStateValid(int32_t totalInstances, size_t availableInstances)
{
    return totalInstances >= 0 && static_cast<size_t>(totalInstances) >= availableInstances;
}

inline bool CanCreateProgram(int32_t totalInstances, int32_t maxInstanceCount)
{
    return totalInstances >= 0 && totalInstances < maxInstanceCount;
}

inline bool ShouldWaitForAvailableProgram(int32_t totalInstances, int32_t maxInstanceCount, size_t availableInstances)
{
    return availableInstances == 0 && totalInstances >= maxInstanceCount;
}

inline bool ShouldStopDestroyThread(int32_t totalInstances, size_t availableInstances)
{
    return totalInstances <= 0 || availableInstances == 0;
}

inline int32_t ComputeDestroySleepSeconds(
    long now, long lastTouchTime, int32_t totalInstances, int32_t maxInstanceCount)
{
    if (lastTouchTime <= 0 || now <= lastTouchTime) {
        return PixelMapGlUtils::GetContextExpireDelaySec(totalInstances, maxInstanceCount);
    }
    const long elapsed = now - lastTouchTime;
    const int32_t delay = PixelMapGlUtils::GetContextExpireDelaySec(totalInstances, maxInstanceCount);
    if (elapsed >= delay) {
        return 0;
    }
    return delay - static_cast<int32_t>(elapsed);
}
} // namespace PixelMapProgramManagerUtils
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_PROGRAM_MANAGER_UTILS_H
