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

#ifndef FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SHADER_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SHADER_UTILS_H

#include <cstdint>
#include <mutex>
#include <utility>

namespace OHOS {
namespace Media {
namespace PixelMapGlShaderUtils {
constexpr uint64_t MAX_SHADER_CACHE_FILE_SIZE = 64ULL * 1024ULL * 1024ULL;

inline bool IsShaderCacheFileSizeValid(uint64_t fileSize, uint64_t metadataSize)
{
    return metadataSize > 0 && fileSize >= metadataSize && fileSize <= MAX_SHADER_CACHE_FILE_SIZE;
}

inline std::mutex &GetShaderCacheMutex()
{
    static std::mutex shaderCacheMutex;
    return shaderCacheMutex;
}

template<typename Function>
bool WithShaderCacheLock(Function &&function)
{
    std::lock_guard<std::mutex> lock(GetShaderCacheMutex());
    return std::forward<Function>(function)();
}
} // namespace PixelMapGlShaderUtils
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_EGL_IMAGE_INCLUDE_PIXEL_MAP_GL_SHADER_UTILS_H
