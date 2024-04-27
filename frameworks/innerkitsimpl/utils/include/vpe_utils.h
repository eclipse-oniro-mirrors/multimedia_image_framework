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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_VPE_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_VPE_UTILS_H

#include "v2_0/cm_color_space.h"
#include "v2_0/hdr_static_metadata.h"
#include "surface_buffer.h"
#include "hdr_type.h"

namespace OHOS {
namespace Media {
constexpr int32_t VPE_ERROR_FAILED = -1;
constexpr int32_t VPE_ERROR_OK = 0;

struct VpeSurfaceBuffers {
    sptr<SurfaceBuffer> sdr;
    sptr<SurfaceBuffer> gainmap;
    sptr<SurfaceBuffer> hdr;
};

class VpeUtils {
public:
    VpeUtils();
    ~VpeUtils();
    int32_t ColorSpaceConverterComposeImage(VpeSurfaceBuffers& sb, bool legacy);
    int32_t ColorSpaceConverterDecomposeImage(VpeSurfaceBuffers& sb);
    static bool SetSbColorSpaceType(sptr<SurfaceBuffer>& buffer,
        const HDI::Display::Graphic::Common::V2_0::CM_ColorSpaceType& colorSpaceType);
    static bool GetSbColorSpaceType(const sptr<SurfaceBuffer>& buffer,
        HDI::Display::Graphic::Common::V2_0::CM_ColorSpaceType& colorSpaceType);
    static bool SetSbMetadataType(sptr<SurfaceBuffer>& buffer,
        const HDI::Display::Graphic::Common::V2_0::CM_HDR_Metadata_Type& metadataType);
    static bool GetSbMetadataType(const sptr<SurfaceBuffer>& buffer,
        HDI::Display::Graphic::Common::V2_0::CM_HDR_Metadata_Type& metadataType);
    static bool SetSbDynamicMetadata(sptr<SurfaceBuffer>& buffer, const std::vector<uint8_t>& dynamicMetadata);
    static bool GetSbDynamicMetadata(const sptr<SurfaceBuffer>& buffer, std::vector<uint8_t>& dynamicMetadata);
    static bool SetSbStaticMetadata(sptr<SurfaceBuffer>& buffer, const std::vector<uint8_t>& staticMetadata);
    static bool GetSbStaticMetadata(const sptr<SurfaceBuffer>& buffer, std::vector<uint8_t>& staticMetadata);
    static void SetSurfaceBufferInfo(sptr<SurfaceBuffer>& buffer, bool isGainmap, ImageHdrType type,
        HDI::Display::Graphic::Common::V2_0::CM_ColorSpaceType color, HdrMetadata& metadata);

private:
    int32_t ColorSpaceConverterCreate(void* handle, int32_t* instanceId);
    int32_t ColorSpaceConverterDestory(void* handle, int32_t* instanceId);
    std::mutex vpeMtx_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_VPE_UTILS_H