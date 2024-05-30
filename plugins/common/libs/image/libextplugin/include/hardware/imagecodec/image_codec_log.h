/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef IMAGE_CODEC_LOG_H
#define IMAGE_CODEC_LOG_H

#include <cinttypes>
#include <chrono>
#include "log_tags.h"
#include "hilog/log.h"
#ifdef BUILD_ENG_VERSION
#include "hitrace_meter.h"
#endif

inline constexpr OHOS::HiviewDFX::HiLogLabel IMAGE_CODEC_LABEL = {
    LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "HEIF_HW_DECODER"};

#ifdef __FILE_NAME__
#define FILENAME __FILE_NAME__
#else
#define FILENAME __FILE__
#endif

#define LOG_FMT "[%{public}s][%{public}s %{public}d] "
#define LOGE(x, ...) \
    OHOS::HiviewDFX::HiLog::Error(IMAGE_CODEC_LABEL, LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGW(x, ...) \
    OHOS::HiviewDFX::HiLog::Warn(IMAGE_CODEC_LABEL, LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGI(x, ...) \
    OHOS::HiviewDFX::HiLog::Info(IMAGE_CODEC_LABEL, LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGD(x, ...) \
    OHOS::HiviewDFX::HiLog::Debug(IMAGE_CODEC_LABEL, LOG_FMT x, FILENAME, __FUNCTION__, __LINE__, ##__VA_ARGS__)

// for ImageCodecBuffer
#define HLOG_FMT "%{public}s[%{public}s][%{public}s %{public}d] "
#define HLOGE(x, ...) OHOS::HiviewDFX::HiLog::Error(IMAGE_CODEC_LABEL, HLOG_FMT x, compUniqueStr_.c_str(), \
    currState_->GetName().c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define HLOGW(x, ...) OHOS::HiviewDFX::HiLog::Warn(IMAGE_CODEC_LABEL, HLOG_FMT x, compUniqueStr_.c_str(), \
    currState_->GetName().c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define HLOGI(x, ...) OHOS::HiviewDFX::HiLog::Info(IMAGE_CODEC_LABEL, HLOG_FMT x, compUniqueStr_.c_str(), \
    currState_->GetName().c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define HLOGD(x, ...) \
    do {    \
        if (debugMode_) {   \
            OHOS::HiviewDFX::HiLog::Debug(IMAGE_CODEC_LABEL, HLOG_FMT x, compUniqueStr_.c_str(), \
            currState_->GetName().c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        }   \
    } while (0)

// for ImageCodecBuffer inner state
#define SLOGE(x, ...) OHOS::HiviewDFX::HiLog::Error(IMAGE_CODEC_LABEL, HLOG_FMT x, \
    codec_->compUniqueStr_.c_str(), stateName_.c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define SLOGW(x, ...) OHOS::HiviewDFX::HiLog::Warn(IMAGE_CODEC_LABEL, HLOG_FMT x, \
    codec_->compUniqueStr_.c_str(), stateName_.c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define SLOGI(x, ...) OHOS::HiviewDFX::HiLog::Info(IMAGE_CODEC_LABEL, HLOG_FMT x, \
    codec_->compUniqueStr_.c_str(), stateName_.c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define SLOGD(x, ...) \
    do {    \
        if (codec_->debugMode_) {   \
            OHOS::HiviewDFX::HiLog::Debug(IMAGE_CODEC_LABEL, HLOG_FMT x, \
            codec_->compUniqueStr_.c_str(), stateName_.c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        }   \
    } while (0)

#define IF_TRUE_RETURN_VAL(cond, val)  \
    do {                               \
        if (cond) {                    \
            return val;                \
        }                              \
    } while (0)
#define IF_TRUE_RETURN_VAL_WITH_MSG(cond, val, msg, ...) \
    do {                                        \
        if (cond) {                             \
            LOGE(msg, ##__VA_ARGS__);           \
            return val;                         \
        }                                       \
    } while (0)
#define IF_TRUE_RETURN_VOID(cond)  \
    do {                                \
        if (cond) {                     \
            return;                     \
        }                               \
    } while (0)
#define IF_TRUE_RETURN_VOID_WITH_MSG(cond, msg, ...)     \
    do {                                        \
        if (cond) {                             \
            LOGE(msg, ##__VA_ARGS__);           \
            return;                             \
        }                                       \
    } while (0)

#ifdef BUILD_ENG_VERSION
#ifdef H_SYSTRACE_TAG
#undef H_SYSTRACE_TAG
#endif
#define H_SYSTRACE_TAG HITRACE_TAG_ZMEDIA
#endif // BUILD_ENG_VERSION

class HeifPerfTracker {
public:
    explicit HeifPerfTracker(std::string desc) : desc_(desc)
    {
        startTimeInUs_ = GetCurrentTimeInUs();
#ifdef BUILD_ENG_VERSION
        StartTrace(H_SYSTRACE_TAG, desc);
#endif
    }
    ~HeifPerfTracker()
    {
#ifdef BUILD_ENG_VERSION
        FinishTrace(H_SYSTRACE_TAG);
#endif
        static constexpr float MILLISEC_TO_MICROSEC = 1000.0f;
        int64_t timeSpanInUs = GetCurrentTimeInUs() - startTimeInUs_;
        LOGI("%{public}s cost: %{public}.2f ms",
             desc_.c_str(), static_cast<float>(timeSpanInUs / MILLISEC_TO_MICROSEC));
    }
private:
    int64_t GetCurrentTimeInUs()
    {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    }

    int64_t startTimeInUs_;
    std::string desc_;
};

#endif // IMAGE_CODEC_LOG_H