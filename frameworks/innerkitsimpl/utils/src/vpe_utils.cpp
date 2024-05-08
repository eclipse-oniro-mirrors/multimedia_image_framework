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

#include "vpe_utils.h"

#include <dlfcn.h>

#include "hilog/log.h"
#include "log_tags.h"
#include "image_log.h"
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/buffer_handle_meta_key_type.h"
#include "metadata_convertor.h"
#include "external_window.h"
#include "native_window.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "VpeUtils"

namespace OHOS {
namespace Media {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
static constexpr uint32_t TRANSFUNC_OFFSET = 8;
static constexpr uint32_t MATRIX_OFFSET = 16;
static constexpr uint32_t RANGE_OFFSET = 21;
constexpr uint8_t INDEX_ZERO = 0;
constexpr uint8_t INDEX_ONE = 1;
constexpr uint8_t INDEX_TWO = 2;
#endif
const static char* VPE_SO_NAME = "libvideoprocessingengine.z.so";
void* VpeUtils::dlHandler_ = nullptr;
__attribute__((destructor)) void VpeUtilsDeinitLibVpe()
{
    IMAGE_LOGD("destructor VpeUtilsDeinitLibVpe");
    VpeUtils::UnloadLibVpe();
}

using CreateT = int32_t (*)(int32_t*);
using DestoryT = int32_t (*)(int32_t*);

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using ComposeImageT =
    int32_t (*)(int32_t, OHNativeWindowBuffer*, OHNativeWindowBuffer*, OHNativeWindowBuffer*, bool);
using DecomposeImageT =
    int32_t (*)(int32_t, OHNativeWindowBuffer*, OHNativeWindowBuffer*, OHNativeWindowBuffer*);
using HdrProcessImageT =
    int32_t (*)(int32_t, OHNativeWindowBuffer*, OHNativeWindowBuffer*);
using SrProcessImageT =
    int32_t (*)(int32_t, OHNativeWindowBuffer*, OHNativeWindowBuffer*, int32_t);
#endif


VpeUtils::VpeUtils()
{
    static std::once_flag flag;
    std::function<void()> func = std::bind(&VpeUtils::LoadLibVpe);
    std::call_once(flag, func);
}

bool VpeUtils::LoadLibVpe()
{
    dlHandler_ = dlopen(VPE_SO_NAME, RTLD_LAZY);
    if (dlHandler_ == nullptr) {
        IMAGE_LOGE("VpeUtils LoadLibVpe, failed");
        return false;
    }
    IMAGE_LOGD("VpeUtils LoadLibVpe, success");
    return true;
}

void VpeUtils::UnloadLibVpe()
{
    IMAGE_LOGD("VpeUtils UnloadLibVpe");
    if (dlHandler_) {
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
    }
}

VpeUtils::~VpeUtils()
{
}

int32_t VpeUtils::ColorSpaceConverterCreate(void* handle, int32_t* instanceId)
{
    if (handle == nullptr) {
        return VPE_ERROR_FAILED;
    }
    CreateT create = (CreateT)dlsym(handle, "ColorSpaceConverterCreate");
    if (!create) {
        return VPE_ERROR_FAILED;
    }
    return create(instanceId);
}

int32_t VpeUtils::ColorSpaceConverterDestory(void* handle, int32_t* instanceId)
{
    if (*instanceId == VPE_ERROR_FAILED || handle == nullptr) {
        return VPE_ERROR_FAILED;
    }
    DestoryT destory = (DestoryT)dlsym(handle, "ColorSpaceConverterDestroy");
    if (!destory) {
        return VPE_ERROR_FAILED;
    }
    return destory(instanceId);
}

int32_t VpeUtils::DetailEnhancerCreate(void* handle, int32_t* instanceId)
{
    if (handle == nullptr) {
        return VPE_ERROR_FAILED;
    }
    CreateT create = (CreateT)dlsym(handle, "DetailEnhancerCreate");
    if (!create) {
        return VPE_ERROR_FAILED;
    }
    return create(instanceId);
}

int32_t VpeUtils::DetailEnhancerDestory(void* handle, int32_t* instanceId)
{
    if (*instanceId == VPE_ERROR_FAILED || handle == nullptr) {
        return VPE_ERROR_FAILED;
    }
    DestoryT destory = (DestoryT)dlsym(handle, "DetailEnhancerDestroy");
    if (!destory) {
        return VPE_ERROR_FAILED;
    }
    return destory(instanceId);
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
int32_t VpeUtils::ColorSpaceConverterComposeImage(VpeSurfaceBuffers& sb, bool legacy)
{
    std::lock_guard<std::mutex> lock(vpeMtx_);
    if (dlHandler_ == nullptr) {
        return VPE_ERROR_FAILED;
    }
    
    int32_t res;
    int32_t instanceId;
    res = ColorSpaceConverterCreate(dlHandler_, &instanceId);
    if (instanceId == VPE_ERROR_FAILED || res != VPE_ERROR_OK) {
        return VPE_ERROR_FAILED;
    }

    ComposeImageT composeImage = (ComposeImageT)dlsym(dlHandler_, "ColorSpaceConverterComposeImage");
    if (!composeImage) {
        return VPE_ERROR_FAILED;
    }
    if (sb.sdr == nullptr || sb.gainmap == nullptr || sb.hdr == nullptr) {
        return VPE_ERROR_FAILED;
    }
    OHNativeWindowBuffer* sdr = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sb.sdr);
    OHNativeWindowBuffer* gainmap = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sb.gainmap);
    OHNativeWindowBuffer* hdr = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sb.hdr);
    res = composeImage(instanceId, sdr, gainmap, hdr, legacy);
    OH_NativeWindow_DestroyNativeWindowBuffer(sdr);
    OH_NativeWindow_DestroyNativeWindowBuffer(gainmap);
    OH_NativeWindow_DestroyNativeWindowBuffer(hdr);
    ColorSpaceConverterDestory(dlHandler_, &instanceId);
    return res;
}

int32_t VpeUtils::ColorSpaceConverterDecomposeImage(VpeSurfaceBuffers& sb)
{
    std::lock_guard<std::mutex> lock(vpeMtx_);
    if (dlHandler_ == nullptr) {
        return VPE_ERROR_FAILED;
    }
 
    int32_t res;
    int32_t instanceId;
    res = ColorSpaceConverterCreate(dlHandler_, &instanceId);
    if (instanceId == VPE_ERROR_FAILED || res != VPE_ERROR_OK) {
        return VPE_ERROR_FAILED;
    }
    
    DecomposeImageT decomposeImage = (DecomposeImageT)dlsym(dlHandler_, "ColorSpaceConverterDecomposeImage");
    if (!decomposeImage) {
        return VPE_ERROR_FAILED;
    }
    if (sb.sdr == nullptr || sb.gainmap == nullptr || sb.hdr == nullptr) {
        return VPE_ERROR_FAILED;
    }
    OHNativeWindowBuffer* sdr = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sb.sdr);
    OHNativeWindowBuffer* gainmap = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sb.gainmap);
    OHNativeWindowBuffer* hdr = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sb.hdr);
    res = decomposeImage(instanceId, hdr, sdr, gainmap);
    OH_NativeWindow_DestroyNativeWindowBuffer(sdr);
    OH_NativeWindow_DestroyNativeWindowBuffer(gainmap);
    OH_NativeWindow_DestroyNativeWindowBuffer(hdr);
    ColorSpaceConverterDestory(dlHandler_, &instanceId);
    return res;
}

// surfacebuffer metadata
static GSError SetColorSpaceInfo(sptr<SurfaceBuffer>& buffer, const CM_ColorSpaceInfo& colorSpaceInfo)
{
    std::vector<uint8_t> colorSpaceInfoVec;
    auto ret = MetadataManager::ConvertMetadataToVec(colorSpaceInfo, colorSpaceInfoVec);
    if (ret != GSERROR_OK) {
        return ret;
    }
    return buffer->SetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec);
}

static bool GetColorSpaceInfo(const sptr<SurfaceBuffer>& buffer, CM_ColorSpaceInfo& colorSpaceInfo)
{
    std::vector<uint8_t> colorSpaceInfoVec;
    auto ret = buffer->GetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("GetColorSpaceInfo GetMetadata failed, return value is %{public}d", ret);
        return false;
    }
    return MetadataManager::ConvertVecToMetadata(colorSpaceInfoVec, colorSpaceInfo) == GSERROR_OK;
}

bool VpeUtils::SetSbColorSpaceType(sptr<SurfaceBuffer>& buffer, const CM_ColorSpaceType& colorSpaceType)
{
    CM_ColorSpaceInfo colorSpaceInfo;
    uint32_t colorSpace = static_cast<uint32_t>(colorSpaceType);
    colorSpaceInfo.primaries = static_cast<CM_ColorPrimaries>(colorSpace & CM_PRIMARIES_MASK);
    colorSpaceInfo.transfunc = static_cast<CM_TransFunc>((colorSpace & CM_TRANSFUNC_MASK) >> TRANSFUNC_OFFSET);
    colorSpaceInfo.matrix = static_cast<CM_Matrix>((colorSpace & CM_MATRIX_MASK) >> MATRIX_OFFSET);
    colorSpaceInfo.range = static_cast<CM_Range>((colorSpace & CM_RANGE_MASK) >> RANGE_OFFSET);
    auto ret = SetColorSpaceInfo(buffer, colorSpaceInfo);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SetColorSpaceInfo GetMetadata failed, return value is %{public}d", ret);
        return false;
    }
    return true;
}

bool VpeUtils::GetSbColorSpaceType(const sptr<SurfaceBuffer>& buffer, CM_ColorSpaceType& colorSpaceType)
{
    CM_ColorSpaceInfo colorSpaceInfo;
    if (!GetColorSpaceInfo(buffer, colorSpaceInfo)) {
        return false;
    }
    uint32_t primaries = static_cast<uint32_t>(colorSpaceInfo.primaries);
    uint32_t transfunc = static_cast<uint32_t>(colorSpaceInfo.transfunc);
    uint32_t matrix = static_cast<uint32_t>(colorSpaceInfo.matrix);
    uint32_t range = static_cast<uint32_t>(colorSpaceInfo.range);
    colorSpaceType = static_cast<CM_ColorSpaceType>(primaries | (transfunc << TRANSFUNC_OFFSET) |
        (matrix << MATRIX_OFFSET) | (range << RANGE_OFFSET));
    return true;
}

bool VpeUtils::SetSbMetadataType(sptr<SurfaceBuffer>& buffer, const CM_HDR_Metadata_Type& metadataType)
{
    std::vector<uint8_t> hdrMetadataTypeVec;
    auto ret = MetadataManager::ConvertMetadataToVec(metadataType, hdrMetadataTypeVec);
    if (ret != GSERROR_OK) {
        return false;
    }
    ret = buffer->SetMetadata(ATTRKEY_HDR_METADATA_TYPE, hdrMetadataTypeVec);
    if (ret != GSERROR_OK) {
        return false;
    }
    return true;
}

bool VpeUtils::GetSbMetadataType(const sptr<SurfaceBuffer>& buffer, CM_HDR_Metadata_Type& metadataType)
{
    std::vector<uint8_t> hdrMetadataTypeVec;
    auto ret = buffer->GetMetadata(ATTRKEY_HDR_METADATA_TYPE, hdrMetadataTypeVec);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("HdrUtils::GetHDRMetadataType GetMetadata failed, return value is %{public}d", ret);
        return false;
    }
    return MetadataManager::ConvertVecToMetadata(hdrMetadataTypeVec, metadataType) == GSERROR_OK;
}

bool VpeUtils::SetSbDynamicMetadata(sptr<SurfaceBuffer>& buffer, const std::vector<uint8_t>& dynamicMetadata)
{
    return buffer->SetMetadata(ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata) == GSERROR_OK;
}

bool VpeUtils::GetSbDynamicMetadata(const sptr<SurfaceBuffer>& buffer, std::vector<uint8_t>& dynamicMetadata)
{
    return buffer->GetMetadata(ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata) == GSERROR_OK;
}

bool VpeUtils::SetSbStaticMetadata(sptr<SurfaceBuffer>& buffer, const std::vector<uint8_t>& staticMetadata)
{
    return buffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, staticMetadata) == GSERROR_OK;
}

bool VpeUtils::GetSbStaticMetadata(const sptr<SurfaceBuffer>& buffer, std::vector<uint8_t>& staticMetadata)
{
    return buffer->GetMetadata(ATTRKEY_HDR_STATIC_METADATA, staticMetadata) == GSERROR_OK;
}

static HDRVividExtendMetadata GetDefaultGainmapMetadata()
{
    const float gainmapMax = 1.0f;
    const float gainmapMin = 0.0f;
    const float gamma = 1.0f;
    const float offsetDenominator = 64.0;
    const float baseOffset = 1.0 / offsetDenominator;
    const float alternateOffset = 1.0 / offsetDenominator;
    HDRVividExtendMetadata extendMetadata;
    extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] = gainmapMax;
    extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ONE] = gainmapMax;
    extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_TWO] = gainmapMax;
    extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO] = gainmapMin;
    extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ONE] = gainmapMin;
    extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_TWO] = gainmapMin;
    extendMetadata.metaISO.enhanceMappingGamma[INDEX_ZERO] = gamma;
    extendMetadata.metaISO.enhanceMappingGamma[INDEX_ONE] = gamma;
    extendMetadata.metaISO.enhanceMappingGamma[INDEX_TWO] = gamma;
    extendMetadata.metaISO.enhanceMappingBaselineOffset[INDEX_ZERO] = baseOffset;
    extendMetadata.metaISO.enhanceMappingBaselineOffset[INDEX_ONE] = baseOffset;
    extendMetadata.metaISO.enhanceMappingBaselineOffset[INDEX_TWO] = baseOffset;
    extendMetadata.metaISO.enhanceMappingAlternateOffset[INDEX_ZERO] = alternateOffset;
    extendMetadata.metaISO.enhanceMappingAlternateOffset[INDEX_ONE] = alternateOffset;
    extendMetadata.metaISO.enhanceMappingAlternateOffset[INDEX_TWO] = alternateOffset;
    extendMetadata.metaISO.gainmapChannelNum = 0x01;
    extendMetadata.metaISO.useBaseColorFlag = 0x00;
    extendMetadata.baseColorMeta.baseColorPrimary = COLORPRIMARIES_SRGB;
    extendMetadata.gainmapColorMeta.combineColorPrimary = COLORPRIMARIES_BT2020;
    extendMetadata.gainmapColorMeta.enhanceDataColorModel = COLORPRIMARIES_BT2020;
    extendMetadata.gainmapColorMeta.alternateColorPrimary = COLORPRIMARIES_BT2020;
    return extendMetadata;
}

static CM_HDR_Metadata_Type ConvertHdrType(ImageHdrType hdrType, bool isGainmap)
{
    switch (hdrType) {
        case ImageHdrType::HDR_VIVID_DUAL :
        case ImageHdrType::HDR_CUVA :
            return CM_IMAGE_HDR_VIVID_DUAL;
        case ImageHdrType::HDR_ISO_DUAL :
            return CM_IMAGE_HDR_ISO_DUAL;
        default:
            return CM_METADATA_NONE;
    }
    return CM_METADATA_NONE;
}

void VpeUtils::SetSurfaceBufferInfo(sptr<SurfaceBuffer>& buffer, bool isGainmap, ImageHdrType type,
    CM_ColorSpaceType color, HdrMetadata& metadata)
{
    CM_HDR_Metadata_Type cmHdrType = ConvertHdrType(type, isGainmap);
    VpeUtils::SetSbMetadataType(buffer, cmHdrType);
    VpeUtils::SetSbColorSpaceType(buffer, color);
    if (type == ImageHdrType::HDR_CUVA) {
        return;
    }
    if (!isGainmap) {
        VpeUtils::SetSbDynamicMetadata(buffer, metadata.dynamicMetadata);
        VpeUtils::SetSbStaticMetadata(buffer, metadata.staticMetadata);
        return;
    }
    std::vector<uint8_t> extendMetadataVec(sizeof(HDRVividExtendMetadata));
    if (metadata.extendMetaFlag) {
        memcpy_s(extendMetadataVec.data(), extendMetadataVec.size(),
            &metadata.extendMeta, sizeof(HDRVividExtendMetadata));
    } else {
        HDRVividExtendMetadata defaultExtendMetadata = GetDefaultGainmapMetadata();
        memcpy_s(extendMetadataVec.data(), extendMetadataVec.size(),
            &defaultExtendMetadata, sizeof(HDRVividExtendMetadata));
    }
    VpeUtils::SetSbDynamicMetadata(buffer, extendMetadataVec);
}

int32_t VpeUtils::ColorSpaceConverterImageProcess(sptr<SurfaceBuffer> &input, sptr<SurfaceBuffer> &output)
{
    std::lock_guard<std::mutex> lock(vpeMtx_);
    if (dlHandler_ == nullptr) {
        return VPE_ERROR_FAILED;
    }

    int32_t res;
    int32_t instanceId;
    res = ColorSpaceConverterCreate(dlHandler_, &instanceId);
    if (instanceId == VPE_ERROR_FAILED || res != VPE_ERROR_OK) {
        return VPE_ERROR_FAILED;
    }

    HdrProcessImageT hdrProcessImage = (HdrProcessImageT)dlsym(dlHandler_, "ColorSpaceConverterProcessImage");
    if (!hdrProcessImage) {
        return VPE_ERROR_FAILED;
    }
    if (input == nullptr || output == nullptr) {
        return VPE_ERROR_FAILED;
    }
    OHNativeWindowBuffer* sdr = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&input);
    OHNativeWindowBuffer* hdr = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&output);
    res = hdrProcessImage(instanceId, sdr, hdr);
    OH_NativeWindow_DestroyNativeWindowBuffer(sdr);
    OH_NativeWindow_DestroyNativeWindowBuffer(hdr);
    ColorSpaceConverterDestory(dlHandler_, &instanceId);
    return res;
}

int32_t VpeUtils::DetailEnhancerImageProcess(sptr<SurfaceBuffer> &input, sptr<SurfaceBuffer> &output, int32_t level)
{
    std::lock_guard<std::mutex> lock(vpeMtx_);
    if (dlHandler_ == nullptr) {
        return VPE_ERROR_FAILED;
    }

    int32_t res;
    int32_t instanceId;
    res = DetailEnhancerCreate(dlHandler_, &instanceId);
    if (instanceId == VPE_ERROR_FAILED || res != VPE_ERROR_OK) {
        return VPE_ERROR_FAILED;
    }

    SrProcessImageT srProcessImage = (SrProcessImageT)dlsym(dlHandler_, "DetailEnhancerProcessImage");
    if (!srProcessImage) {
        return VPE_ERROR_FAILED;
    }
    if (input == nullptr || output == nullptr) {
        return VPE_ERROR_FAILED;
    }
    OHNativeWindowBuffer* inBuffer = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&input);
    OHNativeWindowBuffer* outBuffer = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&output);
    res = srProcessImage(instanceId, inBuffer, outBuffer, level);
    OH_NativeWindow_DestroyNativeWindowBuffer(inBuffer);
    OH_NativeWindow_DestroyNativeWindowBuffer(outBuffer);
    DetailEnhancerDestory(dlHandler_, &instanceId);
    return res;
}

bool VpeUtils::SetSbColorSpaceDefault(sptr<SurfaceBuffer>& buffer)
{
    constexpr CM_ColorSpaceInfo outputColorSpaceInfo = {
        COLORPRIMARIES_BT2020, TRANSFUNC_HLG, MATRIX_BT2020, RANGE_LIMITED
    };
    auto ret = SetColorSpaceInfo(buffer, outputColorSpaceInfo);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SetSbColorSpaceDefault GetMetadata failed, return value is %{public}d", ret);
        return false;
    }
    return true;
}

void VpeUtils::SetSurfaceBufferInfo(sptr<SurfaceBuffer>& buffer, CM_ColorSpaceType color)
{
    VpeUtils::SetSbColorSpaceType(buffer, color);
}
#endif
}
}