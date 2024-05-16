/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H

#include <vector>

#include "abs_image_encoder.h"
#include "plugin_class_base.h"
#include "ext_wstream.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkEncodedImageFormat.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#endif

namespace OHOS {
namespace ImagePlugin {
class ExtEncoder : public AbsImageEncoder, public OHOS::MultimediaPlugin::PluginClassBase {
public:
    ExtEncoder();
    ~ExtEncoder() override;
    uint32_t StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option) override;
    uint32_t AddImage(Media::PixelMap &pixelMap) override;
    uint32_t FinalizeEncode() override;

private:
    DISALLOW_COPY_AND_MOVE(ExtEncoder);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    uint32_t EncodeSdrImage(ExtWStream& outputStream);
    uint32_t EncodeDualVivid(ExtWStream& outputStream);
    uint32_t EncodeSingleVivid(ExtWStream& outputStream);
    sk_sp<SkData> GetImageEncodeData(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info, bool needExif);
    uint32_t EncodeImageBySurfaceBuffer(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info,
        bool needExif, SkWStream& outputStream);
#endif
    uint32_t EncodeImageByBitmap(SkBitmap& bitmap, bool needExif, SkWStream& outStream);
    uint32_t EncodeImageByPixelMap(Media::PixelMap* pixelMap, bool needExif, SkWStream& outputStream);
    SkEncodedImageFormat encodeFormat_;
    OutputDataStream* output_ = nullptr;
    PlEncodeOptions opts_;
    Media::PixelMap* pixelmap_ = nullptr;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H
