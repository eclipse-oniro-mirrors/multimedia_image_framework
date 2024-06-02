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

#include <unistd.h>
#include <fstream>
#include <chrono>

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "ffrt.h"
#include "hisysevent.h"
#endif
#include "image_utils.h"
#include "image_log.h"

namespace OHOS {
namespace Media {
static constexpr char IMAGE_FWK_UE[] = "IMAGE_FWK_UE";
const static std::string DEFAULT_VERSION_ID = "1";

ImageEvent::ImageEvent()
{
    startTime_ = ImageUtils::GetNowTimeMilliSeconds();
}

ImageEvent::~ImageEvent()
{
    if (!options_.errorMsg.empty()) {
        ReportDecodeFault();
    } else {
        ReportDecodeInfo();
    }
}

void ImageEvent::SetDecodeInfoOptions(const DecodeInfoOptions &options)
{
    options_ = options;
}

DecodeInfoOptions& ImageEvent::GetDecodeInfoOptions()
{
    return options_;
}

void ImageEvent::SetDecodeErrorMsg(std::string msg)
{
    options_.errorMsg = msg;
}

void ImageEvent::ReportDecodeFault()
{
    std::string temp;
    switch (options_.invokeType) {
        case (JS_INTERFACE):
            temp = "js_interface";
            break;
        case (C_INTERFACE):
            temp = "c_interface";
            break;
        default:
            temp = "inner_interface";
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    DecodeInfoOptions options = options_;
    ffrt::submit([options, temp] {
        std::string packageName = ImageUtils::GetCurrentProcessName();
        HiSysEventWrite(IMAGE_FWK_UE,
                        "DECODE_FAULT",
                        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
                        "PNAMEID", packageName,
                        "PVERSIONID", DEFAULT_VERSION_ID,
                        "APPLICATION_NAME", packageName,
                        "ROTATE", options.rotate,
                        "EDITABLE", options.editable,
                        "SAMPLE_SIZE", options.sampleSize,
                        "SOURCE_WIDTH", options.sourceWidth,
                        "SOURCE_HEIGHT", options.sourceHeight,
                        "DESIRE_SIZE_WIDTH", options.desireSizeWidth,
                        "DESIRE_SIZE_HEIGHT", options.desireSizeHeight,
                        "DESIRE_REGION_WIDTH", options.desireRegionWidth,
                        "DESIRE_REGION_HEIGHT", options.desireRegionHeight,
                        "DESIRE_REGION_X", options.desireRegionX,
                        "DESIRE_REGION_Y", options.desireRegionY,
                        "DESIRE_DESIRE_PIXEL_FORMAT", options.desirePixelFormat,
                        "INDEX", options.index,
                        "FIT_DENSITY", options.fitDensity,
                        "DESIRE_COLOR_SPACE", options.desireColorSpace,
                        "MIMETYPE", options.mimeType,
                        "MEMORY_SIZE", options.memorySize,
                        "MEMORY_TYPE", options.memoryType,
                        "IMAGE_SOURCE", options.imageSource,
                        "INVOKE_TYPE", temp,
                        "INCREMENTAL_DECODE", options.isIncrementalDecode,
                        "HARD_DECODE", options.isHardDecode,
                        "HARD_DECODE_ERROR", options.hardDecodeError,
                        "ERROR_MSG", options.errorMsg);
        }, {}, {});
#endif
}

void ImageEvent::ReportDecodeInfo()
{
    uint64_t costTime = ImageUtils::GetNowTimeMilliSeconds() - startTime_;
    std::string temp;
    switch (options_.invokeType) {
        case (JS_INTERFACE):
            temp = "js_interface";
            break;
        case (C_INTERFACE):
            temp = "c_interface";
            break;
        default:
            temp = "inner_interface";
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    DecodeInfoOptions options = options_;
    ffrt::submit([options, temp, costTime] {
        std::string packageName = ImageUtils::GetCurrentProcessName();
        HiSysEventWrite(IMAGE_FWK_UE,
                        "DECODE_INFORMATION",
                        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
                        "PNAMEID", packageName,
                        "PVERSIONID", DEFAULT_VERSION_ID,
                        "APPLICATION_NAME", packageName,
                        "ROTATE", options.rotate,
                        "EDITABLE", options.editable,
                        "SAMPLE_SIZE", options.sampleSize,
                        "SOURCE_WIDTH", options.sourceWidth,
                        "SOURCE_HEIGHT", options.sourceHeight,
                        "DESIRE_SIZE_WIDTH", options.desireSizeWidth,
                        "DESIRE_SIZE_HEIGHT", options.desireSizeHeight,
                        "DESIRE_REGION_WIDTH", options.desireRegionWidth,
                        "DESIRE_REGION_HEIGHT", options.desireRegionHeight,
                        "DESIRE_REGION_X", options.desireRegionX,
                        "DESIRE_REGION_Y", options.desireRegionY,
                        "DESIRE_DESIRE_PIXEL_FORMAT", options.desirePixelFormat,
                        "INDEX", options.index,
                        "FIT_DENSITY", options.fitDensity,
                        "DESIRE_COLOR_SPACE", options.desireColorSpace,
                        "MIMETYPE", options.mimeType,
                        "MEMORY_SIZE", options.memorySize,
                        "MEMORY_TYPE", options.memoryType,
                        "IMAGE_SOURCE", options.imageSource,
                        "INVOKE_TYPE", temp,
                        "INCREMENTAL_DECODE", options.isIncrementalDecode,
                        "HARD_DECODE", options.isHardDecode,
                        "HARD_DECODE_ERROR", options.hardDecodeError,
                        "COST_TIME", costTime);
        }, {}, {});
#endif
}

void ReportCreateImageSourceFault(uint32_t width, uint32_t height, std::string type, std::string message)
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
                    "ERROR_MSG", message);
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
} // namespace Media
} // namespace OHOS