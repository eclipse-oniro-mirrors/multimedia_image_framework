/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DATA_TRACE_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DATA_TRACE_H

#include <string>

namespace OHOS {
namespace Media {
class ImageDataStatistics {
public:
    ImageDataStatistics() = delete;
    explicit ImageDataStatistics(const std::string &title);
    explicit ImageDataStatistics(const char *fmt, ...);
    ~ImageDataStatistics();
    void SetRequestMemory(uint32_t size);
    void AddTitle(const std::string title);
    void AddTitle(const char *fmt, ...);
private:
    std::string title_;
    uint64_t startTime_;
    uint32_t memorySize_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_DATA_TRACE_H