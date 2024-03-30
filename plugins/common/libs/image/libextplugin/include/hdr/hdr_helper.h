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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HDR_HDR_HELPER_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HDR_HDR_HELPER_H


#include "include/codec/SkCodec.h"
#include "hdr_type.h"

namespace OHOS {
namespace Media {
class HdrHelper {
public:
    static ImageHdrType CheckHdrType(SkCodec* codec, uint32_t& offset);
    static bool GetMetadata(SkCodec* codec, ImageHdrType type, HdrMetadata& metadata);
};

class HdrJpegPackerHelper {
public:
    static uint32_t SpliceHdrStream(sk_sp<SkData>& baseImage, sk_sp<SkData>& gainmapImage,
        SkWStream& output, HdrMetadata& metadata);
private:
    static std::vector<uint8_t> PackVividMetadataMarker(HdrMetadata& metadata);
    static std::vector<uint8_t> PackISOMetadataMarker(HdrMetadata& metadata);
    static std::vector<uint8_t> PackBaseVividMarker(uint32_t gainmapOffset, uint32_t appSize);
    static std::vector<uint8_t> PackBaseMpfMarker(uint32_t baseSize, uint32_t gainmapSize, uint32_t appOffset);
    static std::vector<uint8_t> PackBaseISOMarker();
    static uint32_t GetBaseVividMarkerSize();
    static uint32_t GetMpfMarkerSize();
};
} // namespace Media
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HDR_HDR_HELPER_H