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

#ifndef INTERFACES_INNERKITS_INCLUDE_IMAGE_HANDLE_H
#define INTERFACES_INNERKITS_INCLUDE_IMAGE_HANDLE_H

#include <unordered_set>
#include "image_type.h"

namespace OHOS {
namespace Media {

class ImageHandle {
public:
    static ImageHandle& GetInstance();
    void LowRamDeviceOptsOptimize(DecodeOptions& opts, const ImageInfo& info);

private:
    ImageHandle() noexcept;
    ~ImageHandle() noexcept;
    void LoadJson();
    bool CheckOptsNeedOptimize(const DecodeOptions& opts);
    bool CheckOptsSetDesiredRegion(const DecodeOptions& opts);
    bool CheckImageNeedResize(const ImageInfo& info);
    bool IsBlackBundle();
    bool IsMemCritical();
    void HandleOnScreen(DecodeOptions& opts, const ImageInfo& info);
    void HandleOnNormal(DecodeOptions& opts, const ImageInfo& info);
    void HandleOnCritical(DecodeOptions& opts, const ImageInfo& info);

private:
    bool isLowSampleEnable_ {false};
    int32_t screenWidth_ {0};
    int32_t screenHeight_ {0};
    int32_t width_ {0};
    int32_t height_ {0};
    std::unordered_set<std::string> blackBundleList_ {};
};

} // namespace Media
} // namespace OHOS
#endif // INTERFACES_INNERKITS_INCLUDE_IMAGE_HANDLE_H