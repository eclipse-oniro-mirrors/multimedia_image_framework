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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_IMAGE_DATA_WRITER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_IMAGE_DATA_WRITER_H

#include <cstdint>

class SkWStream;

namespace OHOS::ImagePlugin {

class ImageDataWriter final {
public:
    static bool WriteJpegC2paDataToStream(SkWStream &output, const uint8_t *jpegData, uint32_t jpegSize,
        uint32_t reservedSize);

private:
    ImageDataWriter() = delete;
    ~ImageDataWriter() = delete;
};

} // namespace OHOS::ImagePlugin

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_IMAGE_DATA_WRITER_H