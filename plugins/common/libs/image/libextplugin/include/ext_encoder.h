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
    OutputDataStream* output_ = nullptr;
    PlEncodeOptions opts_;
    Media::PixelMap* pixelmap_ = nullptr;
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_EXT_ENCODER_H
