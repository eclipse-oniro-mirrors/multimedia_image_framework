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

#include "image_dfx.h"
#include "image_decode_aggregate.h"

#include <unistd.h>
#include <atomic>
#include <fstream>
#include <chrono>

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include <sys/timerfd.h>
#include "ffrt.h"
#include "hisysevent.h"
#endif

#include "image_utils.h"
#include "image_log.h"

namespace OHOS {
namespace Media {
static constexpr char IMAGE_FWK_UE[] = "IMAGE_FWK_UE";
const static std::string DEFAULT_VERSION_ID = "1";

std::string GetInvokeTypeStr(uint16_t invokeType);

namespace {
const char *InvokeTypeName(uint16_t invokeType)
{
    switch (invokeType) {
        case (JS_INTERFACE):
            return "js_interface";
        case (C_INTERFACE):
            return "c_interface";
        default:
            return "inner_interface";
    }
}
} // namespace

#if !defined(CROSS_PLATFORM)
namespace {
// /proc/self/cmdline 在进程生命周期内不变，缓存后避免每次打点都读文件。
const std::string &GetProcessName()
{
    static const std::string processName = ImageUtils::GetCurrentProcessName();
    return processName;
}

// FFRT 能力探测：可用后进程内保持可用；不可用时按固定间隔重试，避免受限进程
// 每次打点都创建并关闭探测 fd，同时保留 fd 临时耗尽后的恢复能力。
bool IsFfrtAvailable()
{
    constexpr uint64_t retryIntervalMs = 60000;
    static std::atomic<int32_t> state {-1}; // -1 未探测，0 不可用，1 可用
    static std::atomic<uint64_t> retryAtMs {0};
    const int32_t cached = state.load(std::memory_order_relaxed);
    if (cached == 1) {
        return true;
    }
    uint64_t nowMs = 0;
    if (cached == 0 && DecodeDfx::ReadClock(nowMs) && nowMs < retryAtMs.load(std::memory_order_relaxed)) {
        return false;
    }
    int timerFd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    const bool available = timerFd >= 0;
    if (available) {
        close(timerFd);
    } else if (DecodeDfx::ReadClock(nowMs)) {
        retryAtMs.store(nowMs + retryIntervalMs, std::memory_order_relaxed);
    }
    state.store(available ? 1 : 0, std::memory_order_relaxed);
    return available;
}

}
#endif

ImageEvent::ImageEvent()
{
    startTime_ = 0;
    startValid_ = DecodeDfx::ReadClock(startTime_);
}

ImageEvent::~ImageEvent()
{
    Report();
}

void ImageEvent::Report()
{
    if (reported_) {
        return;
    }
    reported_ = true;
    // 选项填充时源流可能尚未给出有效大小，上报前从活流补取一次；仍不可得则保持 0。
    if (options_.sourceSize == 0 && sourceSizeProvider_ != nullptr) {
        options_.sourceSize = sourceSizeProvider_();
    }
    IMAGE_LOGD("[ImageEvent]report point:%{public}d result:%{public}d error:%{public}d",
        static_cast<int32_t>(point_), static_cast<int32_t>(result_), static_cast<int32_t>(error_));
    uint64_t end = 0;
    const bool valid = DecodeDfx::ReadClock(end) && startValid_ && end >= startTime_;
    DecodeDfx::ClassifyRequest request;
    request.options = &options_;
    request.point = point_;
    request.result = result_;
    request.error = error_;
    request.costMs = valid ? end - startTime_ : 0;
    request.costValid = valid;
    request.optionsValid = optionsValid_;
    request.contextValid = contextValid_;
    DecodeDfx::Record(request);
    // 成功与失败统一累加到小时窗口，只在 DECODE_HOURLY_STATISTICS 中上报，不再逐次写明细事件。
}

void ImageEvent::SetDecodeInfoOptions(DecodeInfoOptions options)
{
    options_ = std::move(options);
    optionsValid_ = true;
}

DecodeInfoOptions& ImageEvent::GetDecodeInfoOptions()
{
    return options_;
}

void ImageEvent::SetDecodeErrorMsg(const std::string &msg)
{
    options_.errorMsg = msg;
    result_ = DecodeResult::FAILURE;
    error_ = DecodeError::DECODE;
}

std::string GetImageFileExtension(const std::string &path, int fd)
{
    std::string filePath = path;
#if !defined(_WIN32)
    if (filePath.empty() && fd >= 0) {
        constexpr size_t maxFilePathSize = 4096;
        char target[maxFilePathSize];
        const std::string link = "/proc/self/fd/" + std::to_string(fd);
        const ssize_t length = readlink(link.c_str(), target, sizeof(target));
        if (length <= 0 || static_cast<size_t>(length) == sizeof(target)) {
            return "unknown";
        }
        filePath.assign(target, static_cast<size_t>(length));

        const std::string deletedSuffix = " (deleted)";
        if (filePath.size() > deletedSuffix.size() && filePath.compare(filePath.size() -
            deletedSuffix.size(), deletedSuffix.size(), deletedSuffix) == 0) {
            filePath.erase(filePath.size() - deletedSuffix.size());
        }
    }
#endif
    const auto separator = filePath.find_last_of("/\\");
    const size_t nameStart = separator == std::string::npos ? 0 : separator + 1;
    const auto dot = filePath.find_last_of('.');
    constexpr size_t maxExtensionSize = 16;
    if (dot == std::string::npos || dot <= nameStart || dot + 1 == filePath.size() ||
        filePath.size() - dot - 1 > maxExtensionSize) {
        return "unknown";
    }
    std::string extension = filePath.substr(dot + 1);
    for (char &ch : extension) {
        if (ch >= 'A' && ch <= 'Z') {
            ch += 'a' - 'A';
        } else if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))) {
            return "unknown";
        }
    }
    return extension;
}

std::string ImageEvent::getInvokeType()
{
    return InvokeTypeName(options_.invokeType);
}

void ImageEvent::ReportDecodeFault()
{
    SetDecodeResult(DecodeResult::FAILURE, DecodeError::DECODE);
    Report();
}

std::string GetInvokeTypeStr(uint16_t invokeType)
{
    return InvokeTypeName(invokeType);
}

void ImageEvent::ReportDecodeInfo()
{
    SetDecodeResult(DecodeResult::SUCCESS);
    Report();
}

void ReportCreateImageSourceFault(uint32_t width, uint32_t height, std::string type, std::string message,
    std::string fileExtension)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::string packageName = ImageUtils::GetCurrentProcessName();
    HiSysEventWrite(IMAGE_FWK_UE,
                    "CREATE_IMAGESOURCE_FAULT",
                    OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
                    "PNAMEID", packageName,
                    "PVERSIONID", DEFAULT_VERSION_ID,
                    "WIDTH", width,
                    "HEIGHT", height,
                    "TYPE", type,
                    "ERROR_MSG", message,
                    "SOURCE_FILE_EXTENSION", fileExtension);
#endif
}

void ReportEncodeFault(uint32_t width, uint32_t height, std::string mimeType, std::string message)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::string packageName = ImageUtils::GetCurrentProcessName();
    HiSysEventWrite(IMAGE_FWK_UE,
                    "ENCODE_FAULT",
                    OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
                    "PNAMEID", packageName,
                    "PVERSIONID", DEFAULT_VERSION_ID,
                    "WIDTH", width,
                    "HEIGHT", height,
                    "MIME_TYPE", mimeType,
                    "ERROR_MSG", message);
#endif
}

void ReportEncodeInfo(const EncodeInfoOptions &options)
{
#if !defined(CROSS_PLATFORM)
    // FFRT 能力探测与既有打点约定一致：受限进程探测失败时静默放弃，不影响编码主流程。
    if (!IsFfrtAvailable()) {
        return;
    }
    EncodeInfoOptions encodeOptions = options;
    ffrt::submit([encodeOptions = std::move(encodeOptions)] {
        const std::string &packageName = GetProcessName();
        HiSysEventWrite(IMAGE_FWK_UE,
                        "ENCODE_INFORMATION",
                        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
                        "PNAMEID", packageName,
                        "PVERSIONID", DEFAULT_VERSION_ID,
                        "APPLICATION_NAME", packageName,
                        "MIMETYPE", encodeOptions.mimeType,
                        "PIXEL_FORMAT", encodeOptions.pixelFormat,
                        "QUALITY", encodeOptions.quality,
                        "OUTPUT_SIZE", encodeOptions.outputSize,
                        "COST_TIME", encodeOptions.costTime,
                        "HARDWARE_ENCODE", encodeOptions.isHardware);
        }, {}, {});
#endif
}
} // namespace Media
} // namespace OHOS