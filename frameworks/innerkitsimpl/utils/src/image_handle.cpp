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

#include "image_handle.h"

#include "file_ex.h"
#include "nlohmann/json.hpp"

#include "image_log.h"
#include "image_utils.h"
#include "image_system_properties.h"

namespace OHOS {
namespace Media {

static const int32_t NUM_2 = 2;
static const int32_t NUM_3 = 3;
static const int32_t NUM_4 = 4;
static const int32_t WIDTH_DEFAULT = 1920;
static const int32_t HEIGHT_DEFAULT = 1080;
static const int32_t SCREEN_WIDTH_DEFAULT = 1244;
static const int32_t SCREEN_HEIGHT_DEFAULT = 2700;
static const std::string IMAGE_LOW_SAMPLE_CONFIG_PATH = "sys_prod/etc/media/lowsample.json";
static const std::string IMAGE_LOW_SAMPLE = "ImageLowSample";
static const std::string WIDTH = "Width";
static const std::string HEIGHT = "Height";
static const std::string SCREEN_WIDTH = "ScreenWidth";
static const std::string SCREEN_HEIGHT = "ScreenHeight";
static const std::string MEM_CRITICAL = "MemCritical";
static const std::string BLACK_BUNDLE_LIST = "BlackBundleList";

constexpr float HALF = 0.5f;
static inline int FloatToInt(float a)
{
    return static_cast<int>(a + HALF);
}

ImageHandle::ImageHandle() noexcept
{
    LoadJson();
}

ImageHandle::~ImageHandle() noexcept
{
}

ImageHandle& ImageHandle::GetInstance()
{
    static ImageHandle instance;
    return instance;
}

void ImageHandle::LowRamDeviceOptsOptimize(DecodeOptions& opts, const ImageInfo& info)
{
    if (!isLowSampleEnable_) {
        return;
    }

    IMAGE_LOGD("LowRamDeviceOptsOptimize image:%{public}d, %{public}d, desiredSize:%{public}d, %{public}d",
        info.size.width, info.size.height, opts.desiredSize.width, opts.desiredSize.height);
    if (IsBlackBundle() || !CheckOptsNeedOptimize(opts) || !CheckImageNeedResize(info)) {
        return;
    }

    if (info.size.height > screenHeight_ && info.size.width > screenWidth_) {
        HandleOnScreen(opts, info);
    } else {
        if (!IsMemCritical()) {
            HandleOnNormal(opts, info);
        } else {
            HandleOnCritical(opts, info);
        }
    }
}

void ImageHandle::LoadJson()
{
    std::string content;
    if (!LoadStringFromFile(IMAGE_LOW_SAMPLE_CONFIG_PATH, content)) {
        IMAGE_LOGD("ReadFile failed:%{public}s", IMAGE_LOW_SAMPLE_CONFIG_PATH.c_str());
        return;
    }

    nlohmann::json root = nlohmann::json::parse(content, nullptr, false);
    if (root.is_discarded()) {
        IMAGE_LOGD("LoadJson failed:%{public}s", IMAGE_LOW_SAMPLE_CONFIG_PATH.c_str());
        return;
    }

    isLowSampleEnable_ = root.value(IMAGE_LOW_SAMPLE, false);
    screenWidth_ = root.value(SCREEN_WIDTH, SCREEN_WIDTH_DEFAULT);
    screenHeight_ = root.value(SCREEN_HEIGHT, SCREEN_WIDTH_DEFAULT);
    width_ = root.value(WIDTH, WIDTH_DEFAULT);
    height_ = root.value(HEIGHT, HEIGHT_DEFAULT);
    blackBundleList_ = root.value(BLACK_BUNDLE_LIST, std::unordered_set<std::string>());
}

bool ImageHandle::CheckOptsNeedOptimize(const DecodeOptions& opts)
{
    if ((opts.desiredSize.width != 0 || opts.desiredSize.height != 0) ||
        opts.resolutionQuality != ResolutionQuality::UNKNOWN ||
        CheckOptsSetDesiredRegion(opts)) {
        return false;
    }
    return true;
}

bool ImageHandle::CheckOptsSetDesiredRegion(const DecodeOptions& opts)
{
    if (opts.desiredRegion.left != 0 || opts.desiredRegion.top != 0 ||
        opts.desiredRegion.width != 0 || opts.desiredRegion.height != 0) {
        return true;
    }
    return false;
}

bool ImageHandle::CheckImageNeedResize(const ImageInfo& info)
{
    if (info.size.width < width_ || info.size.height < height_) {
        return false;
    }
    return true;
}

bool ImageHandle::IsBlackBundle()
{
    static std::string processName = ImageUtils::GetCurrentProcessName();
    static bool isBlackBundle = blackBundleList_.find(processName) != blackBundleList_.end();
    return isBlackBundle;
}

bool ImageHandle::IsMemCritical()
{
    return ImageSystemProperties::IsImageLowSampleCritical();
}

void ImageHandle::HandleOnScreen(DecodeOptions& opts, const ImageInfo& info)
{
    IMAGE_LOGI("HandleOnScreen");
    float width_scalar = float(info.size.width) / float(screenWidth_);
    float height_scalar = float(info.size.height) / float(screenHeight_);
    float scalar = width_scalar < height_scalar ? width_scalar : height_scalar;

    float desiredWidth = float(info.size.width) / scalar;
    float desiredHeight = float(info.size.height) / scalar;

    opts.desiredSize.width = FloatToInt(desiredWidth);
    opts.desiredSize.height = FloatToInt(desiredHeight);
}

void ImageHandle::HandleOnNormal(DecodeOptions& opts, const ImageInfo& info)
{
    IMAGE_LOGI("HandleOnNormal");
    opts.desiredSize.width = info.size.width * NUM_3 / NUM_4;
    opts.desiredSize.height = info.size.height * NUM_3 / NUM_4;
}

void ImageHandle::HandleOnCritical(DecodeOptions& opts, const ImageInfo& info)
{
    IMAGE_LOGI("HandleOnCritical");
    opts.desiredSize.width = info.size.width / NUM_2;
    opts.desiredSize.height = info.size.height / NUM_2;
}

} // namespace Media
} // namespace OHOS