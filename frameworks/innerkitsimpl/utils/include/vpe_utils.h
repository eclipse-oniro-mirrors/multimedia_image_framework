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

#ifndef FRAMEWORKS_INNERKITSIMPL_IMAGE_INCLUDE_VPE_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_IMAGE_INCLUDE_VPE_UTILS_H

#ifdef IMAGE_HDR_CONVERTER_FLAG
#include "colorspace_converter.h"
#endif
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {
class VpeUtils {
public:
    static bool SetSbColorSpaceType(sptr<SurfaceBuffer>& buffer,
        const HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType& colorSpaceType);
    static bool GetSbColorSpaceType(const sptr<SurfaceBuffer>& buffer,
        HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType& colorSpaceType);
    static bool SetSbMetadataType(sptr<SurfaceBuffer>& buffer,
        const HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type& metadataType);
    static bool GetSbMetadataType(const sptr<SurfaceBuffer>& buffer,
        HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type& metadataType);
    static bool SetSbDynamicMetadata(sptr<SurfaceBuffer>& buffer, const std::vector<uint8_t>& dynamicMetadata);
    static bool GetSbDynamicMetadata(const sptr<SurfaceBuffer>& buffer, std::vector<uint8_t>& dynamicMetadata);
    static bool SetSbStaticMetadata(sptr<SurfaceBuffer>& buffer, const std::vector<uint8_t>& staticMetadata);
    static bool GetSbStaticMetadata(const sptr<SurfaceBuffer>& buffer, std::vector<uint8_t>& staticMetadata);
    
#ifdef IMAGE_HDR_CONVERTER_FLAG
    static std::shared_ptr<VideoProcessingEngine::ColorSpaceConverter> GetColorSpaceConverter();
#endif
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_IMAGE_INCLUDE_VPE_UTILS_H