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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_FWK_EXT_MANAGER_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_FWK_EXT_MANAGER_H

#include <cstdint>
#include <vector>

namespace OHOS::ImagePlugin {
    struct PlEncodeOptions;
    struct HevcSoftDecodeParam;
}

namespace OHOS::Media {
    class PixelMap;
    class Picture;
}

class SkWStream;

using DoHardWareEncodeFunc = int32_t (*)(SkWStream* output, const OHOS::ImagePlugin::PlEncodeOptions& opts,
    OHOS::Media::PixelMap* pixelMap);
using HevcSoftwareDecodeFunc = int32_t (*)(std::vector<std::vector<uint8_t>>& inputs,
                                           OHOS::ImagePlugin::HevcSoftDecodeParam& param);

using DoHardwareEncodePictureFunc = int32_t (*)(SkWStream* output, const OHOS::ImagePlugin::PlEncodeOptions& opts,
    OHOS::Media::Picture* picture);

namespace OHOS {
namespace Media {
class ImageFwkExtManager {
public:
    ImageFwkExtManager();
    ~ImageFwkExtManager();
    bool LoadImageFwkExtNativeSo();
    DoHardWareEncodeFunc doHardWareEncodeFunc_;
    DoHardwareEncodePictureFunc doHardwareEncodePictureFunc_;
    HevcSoftwareDecodeFunc hevcSoftwareDecodeFunc_;
private:
    bool isImageFwkExtNativeSoOpened_;
    void* extNativeSoHandle_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_FWK_EXT_MANAGER_H