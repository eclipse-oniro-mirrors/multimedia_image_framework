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

#include "image_log.h"
#include "image_utils.h"
#include "image_system_properties.h"

namespace OHOS {
namespace Media {

static const int32_t NUM_3 = 3;
static const int32_t NUM_4 = 4;
static const int32_t WIDTH = 1080;
static const int32_t HEIGHT = 1920;

ImageHandle::ImageHandle() noexcept
{
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
    if (!IsImageSubSample()) {
        return;
    }

    IMAGE_LOGI("LowRamDeviceOptsOptimize image:%{public}d, %{public}d, desiredSize:%{public}d, %{public}d",
        info.size.width, info.size.height, opts.desiredSize.width, opts.desiredSize.height);
    if (!CheckOptsNeedOptimize(opts) || !CheckImageNeedResize(info)) {
        return;
    }
    HandleSubSample(opts, info);
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
    if (info.size.width < WIDTH || info.size.height < HEIGHT) {
        return false;
    }
    return true;
}

bool ImageHandle::IsImageSubSample()
{
    return ImageSystemProperties::IsImageSubSample();
}

void ImageHandle::HandleSubSample(DecodeOptions& opts, const ImageInfo& info)
{
    IMAGE_LOGI("HandleSubSample");
    opts.desiredSize.width = info.size.width * NUM_3 / NUM_4;
    opts.desiredSize.height = info.size.height * NUM_3 / NUM_4;
}

} // namespace Media
} // namespace OHOS