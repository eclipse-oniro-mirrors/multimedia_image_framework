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
// 明细事件参数：公共参数 29 项 + 结果参数 1 项 + 源流参数 4 项。
constexpr uint32_t DECODE_COMMON_PARAM_COUNT = 29;
constexpr uint32_t DECODE_SOURCE_PARAM_COUNT = 4;
constexpr uint32_t DECODE_EVENT_PARAM_CAPACITY = 34;
static_assert(DECODE_COMMON_PARAM_COUNT + 1 + DECODE_SOURCE_PARAM_COUNT == DECODE_EVENT_PARAM_CAPACITY,
    "decode event param capacity must match the filled parameter count");

// /proc/self/cmdline 在进程生命周期内不变，缓存后避免每次打点都读文件。
const std::string &GetProcessName()
{
    static const std::string processName = ImageUtils::GetCurrentProcessName();
    return processName;
}

// FFRT 能力探测：可用后进程内保持可用，避免每次打点都创建并关闭探测 fd。
bool IsFfrtAvailable()
{
    static std::atomic<bool> available {false};
    if (available.load(std::memory_order_relaxed)) {
        return true;
    }
    int timerFd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timerFd < 0) {
        return false;
    }
    close(timerFd);
    available.store(true, std::memory_order_relaxed);
    return true;
}

// 填充单次解码明细事件的公共参数，返回已写入的条目数。
uint32_t FillDecodeCommonParams(HiSysEventParam params[], const DecodeInfoOptions &options,
    const char *invokeType)
{
    const std::string &packageName = GetProcessName();
    uint32_t count = 0;
    params[count++] = { .name = "PNAMEID", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(packageName.c_str()) } };
    params[count++] = { .name = "PVERSIONID", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(DEFAULT_VERSION_ID.c_str()) } };
    params[count++] = { .name = "APPLICATION_NAME", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(packageName.c_str()) } };
    params[count++] = { .name = "ROTATE", .t = HISYSEVENT_FLOAT, .v = { .f = options.rotate } };
    params[count++] = { .name = "EDITABLE", .t = HISYSEVENT_BOOL, .v = { .b = options.editable } };
    params[count++] = { .name = "SAMPLE_SIZE", .t = HISYSEVENT_UINT32, .v = { .ui32 = options.sampleSize } };
    params[count++] = { .name = "SOURCE_WIDTH", .t = HISYSEVENT_INT32, .v = { .i32 = options.sourceWidth } };
    params[count++] = { .name = "SOURCE_HEIGHT", .t = HISYSEVENT_INT32, .v = { .i32 = options.sourceHeight } };
    params[count++] = { .name = "DESIRE_SIZE_WIDTH", .t = HISYSEVENT_INT32,
        .v = { .i32 = options.desireSizeWidth } };
    params[count++] = { .name = "DESIRE_SIZE_HEIGHT", .t = HISYSEVENT_INT32,
        .v = { .i32 = options.desireSizeHeight } };
    params[count++] = { .name = "DESIRE_REGION_WIDTH", .t = HISYSEVENT_INT32,
        .v = { .i32 = options.desireRegionWidth } };
    params[count++] = { .name = "DESIRE_REGION_HEIGHT", .t = HISYSEVENT_INT32,
        .v = { .i32 = options.desireRegionHeight } };
    params[count++] = { .name = "DESIRE_REGION_X", .t = HISYSEVENT_INT32, .v = { .i32 = options.desireRegionX } };
    params[count++] = { .name = "DESIRE_REGION_Y", .t = HISYSEVENT_INT32, .v = { .i32 = options.desireRegionY } };
    params[count++] = { .name = "DESIRE_DESIRE_PIXEL_FORMAT", .t = HISYSEVENT_INT32,
        .v = { .i32 = options.desirePixelFormat } };
    params[count++] = { .name = "INDEX", .t = HISYSEVENT_UINT32, .v = { .ui32 = options.index } };
    params[count++] = { .name = "FIT_DENSITY", .t = HISYSEVENT_INT32, .v = { .i32 = options.fitDensity } };
    params[count++] = { .name = "DESIRE_COLOR_SPACE", .t = HISYSEVENT_INT32, .v = { .i32 = options.desireColorSpace } };
    params[count++] = { .name = "MIMETYPE", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(options.mimeType.c_str()) } };
    params[count++] = { .name = "MEMORY_SIZE", .t = HISYSEVENT_UINT32, .v = { .ui32 = options.memorySize } };
    params[count++] = { .name = "MEMORY_TYPE", .t = HISYSEVENT_INT32, .v = { .i32 = options.memoryType } };
    params[count++] = { .name = "IMAGE_SOURCE", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(options.imageSource.c_str()) } };
    params[count++] = { .name = "INVOKE_TYPE", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(invokeType) } };
    params[count++] = { .name = "INCREMENTAL_DECODE", .t = HISYSEVENT_BOOL, .v = { .b = options.isIncrementalDecode } };
    params[count++] = { .name = "HARD_DECODE", .t = HISYSEVENT_BOOL, .v = { .b = options.isHardDecode } };
    params[count++] = { .name = "HARD_DECODE_ERROR", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(options.hardDecodeError.c_str()) } };
    params[count++] = { .name = "PLUGIN_TYPE", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(options.pluginType.c_str()) } };
    params[count++] = { .name = "HEIF_GRID_WIDTH", .t = HISYSEVENT_INT32, .v = { .i32 = options.heifGridWidth } };
    params[count++] = { .name = "HEIF_GRID_HEIGHT", .t = HISYSEVENT_INT32, .v = { .i32 = options.heifGridHeight } };
    return count;
}

// 填充源流四项参数：大小、图源色域、YUV 采样格式、文件后缀，返回已写入的条目数。
uint32_t FillDecodeSourceParams(HiSysEventParam params[], const DecodeInfoOptions &options)
{
    uint32_t count = 0;
    params[count++] = { .name = "SOURCE_SIZE", .t = HISYSEVENT_UINT64, .v = { .ui64 = options.sourceSize } };
    params[count++] = { .name = "SOURCE_COLOR_SPACE", .t = HISYSEVENT_INT32, .v = { .i32 = options.sourceColorSpace } };
    params[count++] = { .name = "SOURCE_YUV_SAMPLING", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(options.sourceYuvSampling.c_str()) } };
    params[count++] = { .name = "SOURCE_FILE_EXTENSION", .t = HISYSEVENT_STRING,
        .v = { .s = const_cast<char*>(options.sourceFileExtension.c_str()) } };
    return count;
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
    // 明细事件与小时聚合并存：失败上报 DECODE_FAULT，成功与增量未完成上报 DECODE_INFORMATION。
    SubmitDecodeEvent(result_ == DecodeResult::FAILURE, request.costMs);
}

void ImageEvent::SubmitDecodeEvent(bool isFault, uint64_t costTime)
{
#if !defined(CROSS_PLATFORM)
    // 受限进程无 FFRT 能力时静默放弃上报，不影响解码主流程。
    if (!IsFfrtAvailable()) {
        return;
    }
    // 异步任务持有选项副本，捕获时移动避免二次拷贝其中的字符串。
    DecodeInfoOptions options = options_;
    const char *invokeType = InvokeTypeName(options.invokeType);
    auto decodeTask = [options = std::move(options), invokeType, isFault, costTime] {
        HiSysEventParam params[DECODE_EVENT_PARAM_CAPACITY] = {};
        uint32_t count = FillDecodeCommonParams(params, options, invokeType);
        if (isFault) {
            params[count++] = { .name = "ERROR_MSG", .t = HISYSEVENT_STRING,
                .v = { .s = const_cast<char*>(options.errorMsg.c_str()) } };
        } else {
            params[count++] = { .name = "COST_TIME", .t = HISYSEVENT_UINT64, .v = { .ui64 = costTime } };
        }
        count += FillDecodeSourceParams(params + count, options);
        OH_HiSysEvent_Write(IMAGE_FWK_UE, isFault ? "DECODE_FAULT" : "DECODE_INFORMATION",
            HISYSEVENT_BEHAVIOR, params, count);
    };
    ffrt::submit(decodeTask);
#endif
}

void ImageEvent::SetDecodeInfoOptions(const DecodeInfoOptions &options)
{
    options_ = options;
    optionsValid_ = true;
}

DecodeInfoOptions& ImageEvent::GetDecodeInfoOptions()
{
    return options_;
}

void ImageEvent::SetDecodeErrorMsg(std::string msg)
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