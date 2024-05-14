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

#include "image_func_timer.h"

#include "securec.h"

#include "hitrace_meter.h"
#include "image_utils.h"
#include "image_log.h"

namespace OHOS {
namespace Media {
static constexpr int32_t FORMAT_BUF_SIZE = 254;

ImageFuncTimer::ImageFuncTimer(const std::string &desc) : desc_(desc)
{
#if !defined(_WIN32) && !defined(_APPLE)
    startTime_ = ImageUtils::GetNowTimeMicroSeconds();
    StartTrace(HITRACE_TAG_ZIMAGE, desc);
#endif
}

ImageFuncTimer::~ImageFuncTimer()
{
#if !defined(_WIN32) && !defined(_APPLE)
    FinishTrace(HITRACE_TAG_ZIMAGE);
    uint64_t timeInterval = ImageUtils::GetNowTimeMicroSeconds() - startTime_;
    IMAGE_LOGI("%{public}s cost %{public}llu us", desc_.c_str(), static_cast<unsigned long long>(timeInterval));
#endif
}

ImageFuncTimer::ImageFuncTimer(const char *fmt, ...)
{
#if !defined(_WIN32) && !defined(_APPLE)
    if (fmt == nullptr) {
        desc_ = "ImageFuncTimerFmt Param invalid";
    } else {
        char buf[FORMAT_BUF_SIZE] = { 0 };
        va_list args;
        va_start(args, fmt);
        int32_t ret = vsprintf_s(buf, FORMAT_BUF_SIZE, fmt, args);
        va_end(args);
        if (ret != -1) {
            desc_ = buf;
        } else {
            desc_ = "ImageTraceFmt Format Error";
        }
    }
    startTime_ = ImageUtils::GetNowTimeMicroSeconds();
    StartTrace(HITRACE_TAG_ZIMAGE, desc_);
#endif
}

} // namespace Media
} // namespace OHOS