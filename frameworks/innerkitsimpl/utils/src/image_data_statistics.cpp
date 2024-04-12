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

#include "image_data_statistics.h"

#include "securec.h"
#include "image_log.h"
#include "image_utils.h"

namespace OHOS {
namespace Media {
static constexpr int32_t FORMAT_BUF_SIZE = 254;
static constexpr uint64_t MEMORY_THRESHOLD_BYTE = 314572800;
static constexpr uint64_t TIME_THRESHOLD_MS = 500;

ImageDataStatistics::ImageDataStatistics(const std::string &title) : title_(title), memorySize_(0)
{
    startTime_ = ImageUtils::GetNowTimeMilliSeconds();
}

ImageDataStatistics::ImageDataStatistics(const char *fmt, ...) : memorySize_(0)
{
#if !defined(_WIN32) && !defined(_APPLE)
    if (fmt == nullptr) {
        title_ = "ImageDataTraceFmt Param invalid";
    } else {
        char buf[FORMAT_BUF_SIZE] = { 0 };
        va_list args;
        va_start(args, fmt);
        int32_t ret = vsprintf_s(buf, FORMAT_BUF_SIZE, fmt, args);
        va_end(args);
        if (ret != -1) {
            title_ = buf;
        } else {
            title_ = "ImageDataTraceFmt Format Error";
        }
    }
    startTime_ = ImageUtils::GetNowTimeMilliSeconds();
#endif
}

ImageDataStatistics::~ImageDataStatistics()
{
#if !defined(_WIN32) && !defined(_APPLE)
    uint64_t endTime = ImageUtils::GetNowTimeMilliSeconds();
    uint64_t timeInterval = endTime - startTime_;

    if ((memorySize_ != 0) && (memorySize_ > MEMORY_THRESHOLD_BYTE)) {
        IMAGE_LOGD("%{public}s The requested memory [%{public}lu]bytes, exceeded the threshold [%{public}lu]bytes\n",
            title_.c_str(), static_cast<unsigned long>(memorySize_), static_cast<unsigned long>(MEMORY_THRESHOLD_BYTE));
    }

    if (timeInterval > TIME_THRESHOLD_MS) {
        IMAGE_LOGD("%{public}s Costtime: [%{public}llu]ms timethreshold: [%{public}llu]ms," \
            "startTime: [%{public}llu]ms, endTime: [%{public}llu]ms\n", title_.c_str(),
            static_cast<unsigned long long>(timeInterval), static_cast<unsigned long long>(TIME_THRESHOLD_MS),
            static_cast<unsigned long long>(startTime_), static_cast<unsigned long long>(endTime));
    }
#endif
}

void ImageDataStatistics::SetRequestMemory(uint32_t size)
{
    memorySize_ = size;
}

void ImageDataStatistics::AddTitle(const std::string title)
{
    title_ += title;
}

void ImageDataStatistics::AddTitle(const char *fmt, ...)
{
#if !defined(_WIN32) && !defined(_APPLE)
    if (fmt == nullptr) {
        title_ += "AddTitle Param invalid";
    } else {
        char buf[FORMAT_BUF_SIZE] = { 0 };
        va_list args;
        va_start(args, fmt);
        int32_t ret = vsprintf_s(buf, FORMAT_BUF_SIZE, fmt, args);
        va_end(args);
        if (ret != -1) {
            title_ += buf;
        } else {
            title_ += "AddTitle Format Error";
        }
    }
#endif
}
} // namespace Media
} // namespace OHOS