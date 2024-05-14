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

#include <mutex>

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "surface_buffer.h"
#endif

#include "hdr_type.h"

namespace OHOS {
namespace Media {
constexpr int32_t VPE_ERROR_FAILED = -1;
constexpr int32_t VPE_ERROR_OK = 0;

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
struct VpeSurfaceBuffers {
    sptr<SurfaceBuffer> sdr;
    sptr<SurfaceBuffer> gainmap;
    sptr<SurfaceBuffer> hdr;
};
#endif

class VpeUtils {
public:
    VpeUtils();
    ~VpeUtils();
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    int32_t ColorSpaceConverterComposeImage(VpeSurfaceBuffers& sb, bool legacy);
    int32_t ColorSpaceConverterDecomposeImage(VpeSurfaceBuffers& sb);
    int32_t ColorSpaceConverterImageProcess(sptr<SurfaceBuffer>& input, sptr<SurfaceBuffer>& output);
    int32_t DetailEnhancerImageProcess(sptr<SurfaceBuffer>& input, sptr<SurfaceBuffer>& output, int32_t level);
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
    static void SetSurfaceBufferInfo(sptr<SurfaceBuffer>& buffer, bool isGainmap, ImageHdrType type,
        HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType color, HdrMetadata& metadata);
    static void SetSurfaceBufferInfo(sptr<SurfaceBuffer>& buffer,
        HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType color);
    static bool SetSbColorSpaceDefault(sptr<SurfaceBuffer>& buffer);
#endif
    static bool LoadLibVpe();
    static void UnloadLibVpe();

private:
    int32_t ColorSpaceConverterCreate(void* handle, int32_t* instanceId);
    int32_t ColorSpaceConverterDestory(void* handle, int32_t* instanceId);
    int32_t DetailEnhancerCreate(void* handle, int32_t* instanceId);
    int32_t DetailEnhancerDestory(void* handle, int32_t* instanceId);
    std::mutex vpeMtx_;
    static void* dlHandler_;
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_VPE_UTILS_H