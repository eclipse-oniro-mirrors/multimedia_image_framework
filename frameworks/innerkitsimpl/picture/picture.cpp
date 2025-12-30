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

#include <memory>
#include "exif_metadata.h"
#include "xtstyle_metadata.h"
#include "rfdatab_metadata.h"
#include "picture.h"
#include "pixel_yuv.h"
#include "pixel_yuv_ext.h"
#include "image_trace.h"
#include "image_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "media_errors.h"                                                // Operation success
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#include "surface_buffer.h"
#include "securec.h"
#include "tiff_parser.h"
#include "metadata_helper.h"
#include "v1_0/cm_color_space.h"
#include "vpe_utils.h"
#include "image_system_properties.h"
#include "color_utils.h"

namespace OHOS {
namespace Media {
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
namespace {
    static const std::map<int32_t, PixelFormat> PIXEL_FORMAT_MAP = {
        { GRAPHIC_PIXEL_FMT_RGBA_8888, PixelFormat::RGBA_8888 },
        { GRAPHIC_PIXEL_FMT_YCBCR_420_SP, PixelFormat::NV12 },
        { GRAPHIC_PIXEL_FMT_YCRCB_420_SP, PixelFormat::NV21 },
        { GRAPHIC_PIXEL_FMT_RGBA_1010102, PixelFormat::RGBA_1010102 },
        { GRAPHIC_PIXEL_FMT_BGRA_8888, PixelFormat::BGRA_8888 },
        { GRAPHIC_PIXEL_FMT_RGB_888, PixelFormat::RGB_888 },
        { GRAPHIC_PIXEL_FMT_RGB_565, PixelFormat::RGB_565 },
        { GRAPHIC_PIXEL_FMT_RGBA16_FLOAT, PixelFormat::RGBA_F16 },
        { GRAPHIC_PIXEL_FMT_YCBCR_P010, PixelFormat::YCBCR_P010 },
        { GRAPHIC_PIXEL_FMT_YCRCB_P010, PixelFormat::YCRCB_P010 },
    };

    static const std::map<CM_ColorSpaceType, ColorSpace> CM_COLORSPACE_MAP = {
        { CM_COLORSPACE_NONE, ColorSpace::UNKNOWN },
        { CM_BT709_FULL, ColorSpace::ITU_709 },
        { CM_BT2020_HLG_FULL, ColorSpace::ITU_2020 },
        { CM_BT2020_PQ_FULL, ColorSpace::ITU_2020 },
        { CM_BT709_LIMIT, ColorSpace::ITU_709 },
        { CM_BT2020_HLG_LIMIT, ColorSpace::ITU_2020 },
        { CM_BT2020_PQ_LIMIT, ColorSpace::ITU_2020 },
        { CM_SRGB_FULL, ColorSpace::SRGB },
        { CM_P3_FULL, ColorSpace::DISPLAY_P3 },
        { CM_P3_HLG_FULL, ColorSpace::DISPLAY_P3 },
        { CM_P3_PQ_FULL, ColorSpace::DISPLAY_P3 },
        { CM_ADOBERGB_FULL, ColorSpace::ADOBE_RGB_1998 },
        { CM_SRGB_LIMIT, ColorSpace::SRGB },
        { CM_P3_LIMIT, ColorSpace::DISPLAY_P3 },
        { CM_P3_HLG_LIMIT, ColorSpace::DISPLAY_P3 },
        { CM_P3_PQ_LIMIT, ColorSpace::DISPLAY_P3 },
        { CM_ADOBERGB_LIMIT, ColorSpace::ADOBE_RGB_1998 },
        { CM_LINEAR_SRGB, ColorSpace::LINEAR_SRGB },
        { CM_LINEAR_BT709, ColorSpace::ITU_709 },
        { CM_LINEAR_P3, ColorSpace::DISPLAY_P3 },
        { CM_LINEAR_BT2020, ColorSpace::ITU_2020 },
        { CM_DISPLAY_SRGB, ColorSpace::SRGB },
        { CM_DISPLAY_P3_SRGB, ColorSpace::DISPLAY_P3 },
        { CM_DISPLAY_P3_HLG, ColorSpace::DISPLAY_P3 },
        { CM_DISPLAY_P3_PQ, ColorSpace::DISPLAY_P3 },
        { CM_DISPLAY_BT2020_SRGB, ColorSpace::ITU_2020 },
        { CM_DISPLAY_BT2020_HLG, ColorSpace::ITU_2020 },
        { CM_DISPLAY_BT2020_PQ, ColorSpace::ITU_2020 },
    };

#ifdef IMAGE_COLORSPACE_FLAG
    static const std::map<CM_ColorSpaceType, ColorManager::ColorSpaceName> CM_COLORSPACE_NAME_MAP = {
        { CM_COLORSPACE_NONE, ColorManager::NONE },
        { CM_BT601_EBU_FULL, ColorManager::BT601_EBU },
        { CM_BT601_SMPTE_C_FULL, ColorManager::BT601_SMPTE_C },
        { CM_BT709_FULL, ColorManager::BT709 },
        { CM_BT2020_HLG_FULL, ColorManager::BT2020_HLG },
        { CM_BT2020_PQ_FULL, ColorManager::BT2020_PQ },
        { CM_BT601_EBU_LIMIT, ColorManager::BT601_EBU_LIMIT },
        { CM_BT601_SMPTE_C_LIMIT, ColorManager::BT601_SMPTE_C_LIMIT },
        { CM_BT709_LIMIT, ColorManager::BT709_LIMIT },
        { CM_BT2020_HLG_LIMIT, ColorManager::BT2020_HLG_LIMIT },
        { CM_BT2020_PQ_LIMIT, ColorManager::BT2020_PQ_LIMIT },
        { CM_SRGB_FULL, ColorManager::SRGB },
        { CM_P3_FULL, ColorManager::DISPLAY_P3 },
        { CM_P3_HLG_FULL, ColorManager::P3_HLG },
        { CM_P3_PQ_FULL, ColorManager::P3_PQ },
        { CM_ADOBERGB_FULL, ColorManager::ADOBE_RGB },
        { CM_SRGB_LIMIT, ColorManager::SRGB_LIMIT },
        { CM_P3_LIMIT, ColorManager::DISPLAY_P3_LIMIT },
        { CM_P3_HLG_LIMIT, ColorManager::P3_HLG_LIMIT },
        { CM_P3_PQ_LIMIT, ColorManager::P3_PQ_LIMIT },
        { CM_ADOBERGB_LIMIT, ColorManager::ADOBE_RGB_LIMIT },
        { CM_LINEAR_SRGB, ColorManager::LINEAR_SRGB },
        { CM_LINEAR_BT709, ColorManager::LINEAR_BT709 },
        { CM_LINEAR_P3, ColorManager::LINEAR_P3 },
        { CM_LINEAR_BT2020, ColorManager::LINEAR_BT2020 },
        { CM_DISPLAY_SRGB, ColorManager::DISPLAY_SRGB },
        { CM_DISPLAY_P3_SRGB, ColorManager::DISPLAY_P3_SRGB },
        { CM_DISPLAY_P3_HLG, ColorManager::DISPLAY_P3_HLG },
        { CM_DISPLAY_P3_PQ, ColorManager::DISPLAY_P3_PQ },
        { CM_DISPLAY_BT2020_SRGB, ColorManager::DISPLAY_BT2020_SRGB },
        { CM_DISPLAY_BT2020_HLG, ColorManager::DISPLAY_BT2020_HLG },
        { CM_DISPLAY_BT2020_PQ, ColorManager::DISPLAY_BT2020_PQ },
    };
#endif
}
const static uint64_t MAX_AUXILIARY_PICTURE_COUNT = 32;
const static uint64_t MAX_PICTURE_META_TYPE_COUNT = 64;

const static int32_t HDR_ALLOC_FORMAT_INVALID = -1;

// Define ExifData malloc max size 1MB
const static uint64_t MAX_EXIFMETADATA_SIZE = 1024 * 1024;
static const uint8_t NUM_0 = 0;
static const uint8_t NUM_1 = 1;
static const uint8_t NUM_2 = 2;
static const std::string EXIF_DATA_SIZE_TAG = "exifDataSize";

static bool IsYuvFormat(PixelFormat format)
{
    return format == PixelFormat::NV21 || format == PixelFormat::NV12 ||
        format == PixelFormat::YCRCB_P010 || format == PixelFormat::YCBCR_P010;
}

static bool IsAlphaFormat(PixelFormat format)
{
    return format == PixelFormat::RGBA_8888 || format == PixelFormat::BGRA_8888 ||
        format == PixelFormat::RGBA_1010102 || format == PixelFormat::RGBA_F16;
}

static PixelFormat SbFormat2PixelFormat(int32_t sbFormat)
{
    auto iter = PIXEL_FORMAT_MAP.find(sbFormat);
    if (iter == PIXEL_FORMAT_MAP.end()) {
        return PixelFormat::UNKNOWN;
    }
    return iter->second;
}

static CM_ColorSpaceType GetCMColorSpaceType(sptr<SurfaceBuffer> buffer)
{
    CHECK_ERROR_RETURN_RET(buffer == nullptr, CM_ColorSpaceType::CM_COLORSPACE_NONE);
    CM_ColorSpaceType type;
    MetadataHelper::GetColorSpaceType(buffer, type);
    return type;
}

static ColorSpace CMColorSpaceType2ColorSpace(CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_MAP.find(type);
    CHECK_ERROR_RETURN_RET(iter == CM_COLORSPACE_MAP.end(), ColorSpace::UNKNOWN);
    return iter->second;
}

#ifdef IMAGE_COLORSPACE_FLAG
static ColorManager::ColorSpaceName CMColorSpaceType2ColorSpaceName(CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_NAME_MAP.find(type);
    CHECK_ERROR_RETURN_RET(iter == CM_COLORSPACE_NAME_MAP.end(), ColorManager::NONE);
    return iter->second;
}
#endif

static ImageInfo MakeImageInfo(int width, int height, PixelFormat pf, AlphaType at, ColorSpace cs)
{
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = pf;
    info.alphaType = at;
    info.colorSpace = cs;
    return info;
}

static void SetImageInfoToHdr(std::shared_ptr<PixelMap> &mainPixelMap, std::unique_ptr<PixelMap> &hdrPixelMap)
{
    bool cond = mainPixelMap != nullptr && hdrPixelMap != nullptr;
    if (cond) {
        ImageInfo mainInfo;
        mainPixelMap->GetImageInfo(mainInfo);
        ImageInfo hdrInfo;
        hdrPixelMap->GetImageInfo(hdrInfo);
        hdrInfo.size = mainInfo.size;
        hdrInfo.encodedFormat = mainInfo.encodedFormat;
        hdrPixelMap->SetImageInfo(hdrInfo, true);
    }
}

Picture::~Picture() {}

std::unique_ptr<Picture> Picture::Create(std::shared_ptr<PixelMap> &pixelMap)
{
    if (pixelMap == nullptr) {
        return nullptr;
    }
    std::unique_ptr<Picture> dstPicture = std::make_unique<Picture>();
    if (pixelMap->GetExifMetadata() != nullptr) {
        dstPicture->SetExifMetadata(pixelMap->GetExifMetadata());
    }
    dstPicture->mainPixelMap_ = pixelMap;
    return dstPicture;
}

std::unique_ptr<Picture> Picture::Create(sptr<SurfaceBuffer> &surfaceBuffer)
{
    std::shared_ptr<PixelMap> pixelmap = SurfaceBuffer2PixelMap(surfaceBuffer);
    return Create(pixelmap);
}

std::unique_ptr<PixelMap> Picture::SurfaceBuffer2PixelMap(sptr<OHOS::SurfaceBuffer> &surfaceBuffer)
{
    if (surfaceBuffer == nullptr) {
        return nullptr;
    }
    PixelFormat pixelFormat = SbFormat2PixelFormat(surfaceBuffer->GetFormat());
    ColorSpace colorSpace = CMColorSpaceType2ColorSpace(GetCMColorSpaceType(surfaceBuffer));
    AlphaType alphaType = IsAlphaFormat(pixelFormat) ?
             AlphaType::IMAGE_ALPHA_TYPE_PREMUL : AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    CHECK_ERROR_RETURN_RET_LOG(err != OHOS::GSERROR_OK, nullptr, "NativeBufferReference failed");

    std::unique_ptr<PixelMap> pixelMap;
    if (IsYuvFormat(pixelFormat)) {
#ifdef EXT_PIXEL
        pixelMap = std::make_unique<PixelYuvExt>();
#else
        pixelMap = std::make_unique<PixelYuv>();
#endif
    } else {
        pixelMap = std::make_unique<PixelMap>();
    }
    CHECK_ERROR_RETURN_RET(pixelMap == nullptr, nullptr);

    ImageInfo imageInfo = MakeImageInfo(surfaceBuffer->GetWidth(),
                                        surfaceBuffer->GetHeight(), pixelFormat, alphaType, colorSpace);
    pixelMap->SetImageInfo(imageInfo, true);
    pixelMap->SetPixelsAddr(surfaceBuffer->GetVirAddr(),
                            nativeBuffer, pixelMap->GetRowBytes() * pixelMap->GetHeight(),
                            AllocatorType::DMA_ALLOC, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    ColorManager::ColorSpaceName colorSpaceName =
        CMColorSpaceType2ColorSpaceName(GetCMColorSpaceType(surfaceBuffer));
    pixelMap->InnerSetColorSpace(ColorManager::ColorSpace(colorSpaceName));
#endif
    if (IsYuvFormat(pixelFormat)) {
        ImageUtils::SetYuvDataInfo(pixelMap, surfaceBuffer);
    }
    return pixelMap;
}

std::shared_ptr<PixelMap> Picture::GetMainPixel()
{
    return mainPixelMap_;
}

void Picture::SetMainPixel(std::shared_ptr<PixelMap> PixelMap)
{
    mainPixelMap_ = PixelMap;
}

static int32_t GetHdrAllocFormat(PixelFormat pixelFormat)
{
    int32_t hdrAllocFormat = HDR_ALLOC_FORMAT_INVALID;
    switch (pixelFormat) {
        case PixelFormat::RGBA_8888:
            hdrAllocFormat = GRAPHIC_PIXEL_FMT_RGBA_1010102;
            break;
        case PixelFormat::NV21:
            hdrAllocFormat = GRAPHIC_PIXEL_FMT_YCRCB_P010;
            break;
        case PixelFormat::NV12:
            hdrAllocFormat = GRAPHIC_PIXEL_FMT_YCBCR_P010;
            break;
        case PixelFormat::RGBA_1010102:
            hdrAllocFormat = GRAPHIC_PIXEL_FMT_RGBA_1010102;
            break;
        case PixelFormat::YCRCB_P010:
            hdrAllocFormat = GRAPHIC_PIXEL_FMT_YCRCB_P010;
            break;
        case PixelFormat::YCBCR_P010:
            hdrAllocFormat = GRAPHIC_PIXEL_FMT_YCBCR_P010;
            break;
        default:
            IMAGE_LOGW("%{public}s no corresponding hdrAllocFormat for format: %{public}d", __func__, pixelFormat);
            break;
    }
    IMAGE_LOGD("%{public}s use hdrAllocFormat: %{public}d for format: %{public}d",
        __func__, hdrAllocFormat, pixelFormat);
    return hdrAllocFormat;
}

static void ConvertGainmapHdrMetadata(sptr<SurfaceBuffer> &gainmapSptr, bool convertToHDI)
{
    std::vector<uint8_t> gainmapDynamicMetadata;
    VpeUtils::GetSbDynamicMetadata(gainmapSptr, gainmapDynamicMetadata);
    int32_t memCpyRes = 0;
    HDRVividExtendMetadata extendMetadata = {};
    uint16_t combineColorPrimary = 0;

    IMAGE_LOGI("%{public}s need to fix gainmap dynamic metadata from camera", __func__);
    memCpyRes = memcpy_s(&extendMetadata, sizeof(HDRVividExtendMetadata),
        gainmapDynamicMetadata.data(), gainmapDynamicMetadata.size());
    CHECK_ERROR_RETURN_LOG(memCpyRes != EOK,
        "%{public}s memcpy_s ISOMetadata fail, error: %{public}d", __func__, memCpyRes);
    if (convertToHDI) {
        combineColorPrimary = ColorUtils::ConvertCicpToCMColor(
            extendMetadata.gainmapColorMeta.combineColorPrimary);
    } else  {
        combineColorPrimary = ColorUtils::ConvertCMColorToCicp(
            extendMetadata.gainmapColorMeta.combineColorPrimary);
    }

    if (extendMetadata.metaISO.useBaseColorFlag != 0) {
        extendMetadata.baseColorMeta.baseColorPrimary = combineColorPrimary;
        extendMetadata.gainmapColorMeta.combineColorPrimary = combineColorPrimary;
    } else {
        extendMetadata.gainmapColorMeta.combineColorPrimary = combineColorPrimary;
        extendMetadata.gainmapColorMeta.alternateColorPrimary = combineColorPrimary;
    }

    std::vector<uint8_t> extendMetadataVec(sizeof(HDRVividExtendMetadata));
    memCpyRes = memcpy_s(extendMetadataVec.data(), extendMetadataVec.size(),
        &extendMetadata, sizeof(HDRVividExtendMetadata));
    CHECK_ERROR_RETURN_LOG(memCpyRes != EOK,
        "%{public}s memcpy_s HDRVividExtendMetadata fail, error: %{public}d", __func__, memCpyRes);
    VpeUtils::SetSbDynamicMetadata(gainmapSptr, extendMetadataVec);
}

static void TryFixGainmapHdrMetadata(sptr<SurfaceBuffer> &gainmapSptr)
{
    std::vector<uint8_t> gainmapDynamicMetadata;
    VpeUtils::GetSbDynamicMetadata(gainmapSptr, gainmapDynamicMetadata);
    if (gainmapDynamicMetadata.size() != sizeof(ISOMetadata)) {
        IMAGE_LOGI("%{public}s no need to fix gainmap dynamic metadata, size: %{public}zu",
            __func__, gainmapDynamicMetadata.size());
        return;
    }

    HDRVividExtendMetadata extendMetadata = {};
    int32_t memCpyRes = memcpy_s(&extendMetadata.metaISO, sizeof(ISOMetadata),
        gainmapDynamicMetadata.data(), gainmapDynamicMetadata.size());
    CHECK_ERROR_RETURN_LOG(memCpyRes != EOK,
        "%{public}s memcpy_s ISOMetadata fail, error: %{public}d", __func__, memCpyRes);
    if (extendMetadata.metaISO.useBaseColorFlag != 0) {
        extendMetadata.baseColorMeta.baseColorPrimary = COLORPRIMARIES_SRGB;
        extendMetadata.gainmapColorMeta.combineColorPrimary = COLORPRIMARIES_SRGB;
    } else {
        extendMetadata.gainmapColorMeta.combineColorPrimary = COLORPRIMARIES_BT2020;
        extendMetadata.gainmapColorMeta.alternateColorPrimary = COLORPRIMARIES_BT2020;
    }
    std::vector<uint8_t> extendMetadataVec(sizeof(HDRVividExtendMetadata));
    memCpyRes = memcpy_s(extendMetadataVec.data(), extendMetadataVec.size(),
        &extendMetadata, sizeof(HDRVividExtendMetadata));
    CHECK_ERROR_RETURN_LOG(memCpyRes != EOK,
        "%{public}s memcpy_s HDRVividExtendMetadata fail, error: %{public}d", __func__, memCpyRes);
    VpeUtils::SetSbDynamicMetadata(gainmapSptr, extendMetadataVec);
}

sptr<SurfaceBuffer> CreateGainmapByHdrAndSdr(std::shared_ptr<PixelMap> &hdrPixelMap,
                                             std::shared_ptr<PixelMap> &sdrPixelMap)
{
    sptr<SurfaceBuffer> gainmapSptr = SurfaceBuffer::Create();
    ImageInfo imageInfo;
    sdrPixelMap->GetImageInfo(imageInfo);
    BufferRequestConfig requestConfig = {
        .width = imageInfo.size.width / 2,
        .height = imageInfo.size.height / 2,
        .strideAlignment = imageInfo.size.width / 2,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError error = gainmapSptr->Alloc(requestConfig);
    CHECK_ERROR_RETURN_RET_LOG(error != GSERROR_OK, nullptr,
        "HDR-IMAGE SurfaceBuffer Alloc failed, error : %{public}s", GSErrorStr(error).c_str());
    sptr<SurfaceBuffer> hdrSptr(reinterpret_cast<SurfaceBuffer*>(hdrPixelMap->GetFd()));
    sptr<SurfaceBuffer> sdrSptr(reinterpret_cast<SurfaceBuffer*>(sdrPixelMap->GetFd()));
    VpeSurfaceBuffers buffers = {
        .sdr = sdrSptr,
        .gainmap = gainmapSptr,
        .hdr = hdrSptr,
    };
    ImageUtils::DumpHdrBufferEnabled(buffers.sdr, "Calgainmap-sdr");
    ImageUtils::DumpHdrBufferEnabled(buffers.hdr, "Calgainmap-hdr");
    int32_t res = VpeUtils().ColorSpaceCalGainmap(buffers);
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("HDR-IMAGE CalGainmap failed, res: %{public}d", res);
        return nullptr;
    }
    ImageUtils::DumpHdrBufferEnabled(buffers.gainmap, "Calgainmap-gainmap");
    ImageUtils::DumpHdrExtendMetadataEnabled(buffers.gainmap, "Calgainmap-ExtendMetadata-gainmap");
    ImageUtils::DumpSurfaceBufferAllKeysEnabled(buffers.gainmap, "Calgainmap-AllKeys-gainmap");
    return gainmapSptr;
}

std::unique_ptr<Picture> Picture::CreatePictureByHdrAndSdrPixelMap(std::shared_ptr<PixelMap> &hdrPixelMap,
    std::shared_ptr<PixelMap> &sdrPixelMap)
{
    bool cond = hdrPixelMap == nullptr || sdrPixelMap == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "HDR-IMAGE do calgainmap input null error");
    cond = (hdrPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) ||
           (sdrPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "HDR-IMAGE calgainmap input AllocatorType type error");
    std::unique_ptr<Picture> dstPicture = Create(sdrPixelMap);
    sptr<SurfaceBuffer> gainmapSptr = CreateGainmapByHdrAndSdr(hdrPixelMap, sdrPixelMap);
    CHECK_ERROR_RETURN_RET_LOG(gainmapSptr == nullptr, nullptr, "HDR-IMAGE CreateGainmapByHdrAndSdr failed");
    Media::Size size = {gainmapSptr->GetWidth(), gainmapSptr->GetHeight()};
    std::unique_ptr<AuxiliaryPicture> gainmap = AuxiliaryPicture::Create(gainmapSptr,
        AuxiliaryPictureType::GAINMAP, size);
    cond = dstPicture == nullptr || gainmap == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "HDR-IMAGE calgainmap install output error");
    std::shared_ptr<AuxiliaryPicture> gainmapPtr = std::move(gainmap);
    dstPicture->SetAuxiliaryPicture(gainmapPtr);
    return dstPicture;
}

static bool ShouldComposeAsCuva(const sptr<SurfaceBuffer> &baseSptr, const sptr<SurfaceBuffer> &gainmapSptr)
{
    std::vector<uint8_t> baseStaticMetadata;
    VpeUtils::GetSbStaticMetadata(baseSptr, baseStaticMetadata);
    std::vector<uint8_t> baseDynamicMetadata;
    VpeUtils::GetSbDynamicMetadata(gainmapSptr, baseDynamicMetadata);
    CHECK_ERROR_RETURN_RET(baseStaticMetadata.size() == 0 || baseDynamicMetadata.size() == 0, true);
    std::vector<uint8_t> gainmapDynamicMetadata;
    VpeUtils::GetSbDynamicMetadata(gainmapSptr, gainmapDynamicMetadata);
    CHECK_ERROR_RETURN_RET(gainmapDynamicMetadata.size() != sizeof(HDRVividExtendMetadata), true);
    return false;
}

static std::unique_ptr<PixelMap> ComposeHdrPixelMap(std::shared_ptr<PixelMap> &mainPixelMap,
    sptr<SurfaceBuffer> &baseSptr, sptr<SurfaceBuffer> &gainmapSptr, PixelFormat pixelFormat)
{
    sptr<SurfaceBuffer> hdrSptr = SurfaceBuffer::Create();
    ImageInfo imageInfo;
    mainPixelMap->GetImageInfo(imageInfo);
    if (pixelFormat == PixelFormat::UNKNOWN) {
        IMAGE_LOGI("Using mainPixelMap imageInfo format");
        pixelFormat = imageInfo.pixelFormat;
    }

    int32_t hdrAllocFormat = GetHdrAllocFormat(pixelFormat);
    if (hdrAllocFormat == HDR_ALLOC_FORMAT_INVALID) {
        IMAGE_LOGE("%{public}s unsupported pixelFormat: %{public}d", __func__, pixelFormat);
        return nullptr;
    }

    BufferRequestConfig requestConfig = {
        .width = imageInfo.size.width,
        .height = imageInfo.size.height,
        .strideAlignment = imageInfo.size.width,
        .format = hdrAllocFormat,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };

    GSError error = hdrSptr->Alloc(requestConfig);
    CHECK_ERROR_RETURN_RET_LOG(error != GSERROR_OK, nullptr,
        "HDR SurfaceBuffer Alloc failed, error: %{public}s", GSErrorStr(error).c_str());
    VpeUtils::SetSbMetadataType(hdrSptr, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbColorSpaceType(hdrSptr, CM_BT2020_HLG_FULL);

    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .gainmap = gainmapSptr,
        .hdr = hdrSptr,
    };
    bool isCuva = ShouldComposeAsCuva(baseSptr, gainmapSptr);
    IMAGE_LOGD("HDR-IMAGE Compose image, isCuva: %{public}d", isCuva);
    ImageUtils::DumpHdrBufferEnabled(baseSptr, "Picture-SDR-tobeComposed");
    ImageUtils::DumpHdrBufferEnabled(gainmapSptr, "Picture-GAINMAP-tobeComposed");
    ImageUtils::DumpHdrExtendMetadataEnabled(gainmapSptr, "Picture-GAINMAP-ExtendMetadata-tobeComposed");
    ImageUtils::DumpSurfaceBufferAllKeysEnabled(gainmapSptr, "Picture-GAINMAP-AllKeys-tobeComposed");
    int32_t res = VpeUtils().ColorSpaceConverterComposeImage(buffers, isCuva);
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("Compose HDR image failed, res: %{public}d", res);
        return nullptr;
    }
    ImageUtils::DumpHdrBufferEnabled(hdrSptr, "Picture-HDR-Composed");
    return Picture::SurfaceBuffer2PixelMap(hdrSptr);
}

std::unique_ptr<PixelMap> Picture::GetHdrComposedPixelMap()
{
    return GetHdrComposedPixelMap(PixelFormat::UNKNOWN);
}

std::unique_ptr<PixelMap> Picture::GetHdrComposedPixelMap(PixelFormat pixelFormat)
{
    ImageTrace imageTrace("Picture::GetHdrComposedPixelMap pixelFormat is %d", pixelFormat);
    std::shared_ptr<PixelMap> gainmap = GetGainmapPixelMap();
    bool cond = mainPixelMap_ == nullptr || gainmap == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "picture mainPixelMap_ or gainmap is empty.");
    cond = mainPixelMap_->GetAllocatorType() != AllocatorType::DMA_ALLOC || mainPixelMap_->GetFd() == nullptr ||
           gainmap->GetAllocatorType() != AllocatorType::DMA_ALLOC || gainmap->GetFd() == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Unsupport HDR compose, only support the DMA allocation.");
    sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(mainPixelMap_->GetFd()));
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    sptr<SurfaceBuffer> gainmapSptr(reinterpret_cast<SurfaceBuffer*>(gainmap->GetFd()));
    VpeUtils::SetSbMetadataType(gainmapSptr, CM_METADATA_NONE);
    TryFixGainmapHdrMetadata(gainmapSptr);

    if (GetMaintenanceData()) {
        auto exifMetadata = GetExifMetadata();
        if (exifMetadata) {
            XmageCoordinateMetadata coordMetadata = {};
            if (exifMetadata->ExtractXmageCoordinates(coordMetadata)) {
                std::vector<uint8_t> metaDataVec(sizeof(XmageCoordinateMetadata));
                int32_t memCpyRes = memcpy_s(metaDataVec.data(), metaDataVec.size(),
                    &coordMetadata, sizeof(XmageCoordinateMetadata));
                CHECK_ERROR_RETURN_RET_LOG(memCpyRes != EOK, nullptr, "copy xmage coordinate metadata failed");
                bool setMetaRes = VpeUtils::SetSbStaticMetadata(gainmapSptr, metaDataVec);
                CHECK_ERROR_RETURN_RET_LOG(!setMetaRes, nullptr, "Set xmage coordinate metadata failed");
            }
        }
        ConvertGainmapHdrMetadata(gainmapSptr, true);
    }
    auto hdrPixelMap = ComposeHdrPixelMap(mainPixelMap_, baseSptr, gainmapSptr, pixelFormat);
    SetImageInfoToHdr(mainPixelMap_, hdrPixelMap);

    if (GetMaintenanceData()) {
        ConvertGainmapHdrMetadata(gainmapSptr, false);
    }
    return hdrPixelMap;
}

std::shared_ptr<PixelMap> Picture::GetAuxPicturePixelMap(const AuxiliaryPictureType &type)
{
    CHECK_ERROR_RETURN_RET_LOG(!HasAuxiliaryPicture(type), nullptr,
        "%{public}s AuxiliaryPicture(type: %{public}d) not found in picture", __func__, static_cast<int32_t>(type));
    auto auxiliaryPicture = GetAuxiliaryPicture(type);
    CHECK_ERROR_RETURN_RET_LOG(auxiliaryPicture == nullptr, nullptr,
        "%{public}s Failed to GetAuxiliaryPicture: %{public}d", __func__, static_cast<int32_t>(type));
    return auxiliaryPicture->GetContentPixel();
}

std::shared_ptr<PixelMap> Picture::GetGainmapPixelMap()
{
    return GetAuxPicturePixelMap(AuxiliaryPictureType::GAINMAP);
}

std::shared_ptr<PixelMap> Picture::GetThumbnailPixelMap()
{
    return GetAuxPicturePixelMap(AuxiliaryPictureType::THUMBNAIL);
}

bool Picture::SetThumbnailPixelMap(std::shared_ptr<PixelMap> &thumbnailPixelMap)
{
    CHECK_ERROR_RETURN_RET_LOG(thumbnailPixelMap == nullptr, false,
        "%{public}s set null thumbnail pixelmap", __func__);

    std::shared_ptr<AuxiliaryPicture> auxPicture =
        AuxiliaryPicture::Create(thumbnailPixelMap, AuxiliaryPictureType::THUMBNAIL);
    CHECK_ERROR_RETURN_RET_LOG(auxPicture == nullptr || auxPicture->GetContentPixel() == nullptr, false,
        "%{public}s Failed to create auxiliary picture.", __func__);
    SetAuxiliaryPicture(auxPicture);
    IMAGE_LOGD("%{public}s Set thumbnail pixelMap success.", __func__);
    return true;
}

std::shared_ptr<AuxiliaryPicture> Picture::GetAuxiliaryPicture(AuxiliaryPictureType type)
{
    auto iter = auxiliaryPictures_.find(type);
    if (iter == auxiliaryPictures_.end()) {
        return nullptr;
    }
    return iter->second;
}

void Picture::SetAuxiliaryPicture(std::shared_ptr<AuxiliaryPicture> &picture)
{
    if (picture == nullptr) {
        IMAGE_LOGE("Auxiliary picture is nullptr.");
        return;
    }
    CHECK_ERROR_RETURN_LOG(auxiliaryPictures_.size() >= MAX_AUXILIARY_PICTURE_COUNT,
        "The size of auxiliary picture exceeds the maximum limit %{public}llu.",
        static_cast<unsigned long long>(MAX_AUXILIARY_PICTURE_COUNT));
    AuxiliaryPictureType type = picture->GetType();
    auxiliaryPictures_[type] = picture;
}

bool Picture::HasAuxiliaryPicture(AuxiliaryPictureType type)
{
    auto item = auxiliaryPictures_.find(type);
    return item != auxiliaryPictures_.end() && item->second != nullptr;
}

void Picture::DropAuxiliaryPicture(AuxiliaryPictureType type)
{
    auto it = auxiliaryPictures_.find(type);
    if (it == auxiliaryPictures_.end()) {
        IMAGE_LOGE("%{public}s Failed to drop auxiliary picture, because type: %{public}d is not found.",
            __func__, static_cast<int32_t>(type));
        return;
    }

    auxiliaryPictures_.erase(it);
    if (type == AuxiliaryPictureType::THUMBNAIL) {
        std::shared_ptr<ExifMetadata> exifMetadata = GetExifMetadata();
        if (exifMetadata != nullptr) {
            exifMetadata->DropThumbnail();
        }
    }
}

bool Picture::MarshalMetadata(Parcel &data) const
{
    if (!data.WriteBool(maintenanceData_ != nullptr)) {
        IMAGE_LOGE("Failed to write maintenance data existence value.");
        return false;
    }

    if (maintenanceData_ != nullptr &&
        (maintenanceData_->WriteToMessageParcel(reinterpret_cast<MessageParcel&>(data)) != GSError::GSERROR_OK)) {
        IMAGE_LOGE("Failed to write maintenance data content.");
        return false;
    }

    if (metadatas_.size() > MAX_PICTURE_META_TYPE_COUNT) {
        IMAGE_LOGE("The number of metadatas exceeds the maximum limit.");
        return false;
    }
    if (!data.WriteUint64(static_cast<uint64_t>(metadatas_.size()))) {
        return false;
    }

    for (const auto &[type, metadata] : metadatas_) {
        int32_t typeInt32 = static_cast<int32_t>(type);
        if (metadata == nullptr) {
            IMAGE_LOGE("Metadata %{public}d is nullptr.", typeInt32);
            return false;
        }
        if (!(data.WriteInt32(typeInt32) && metadata->Marshalling(data))) {
            IMAGE_LOGE("Failed to marshal metadata: %{public}d.", typeInt32);
            return false;
        }
    }

    return true;
}

bool Picture::Marshalling(Parcel &data) const
{
    CHECK_ERROR_RETURN_RET_LOG(!mainPixelMap_, false, "Main PixelMap is null.");
    bool cond = !mainPixelMap_->Marshalling(data);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Failed to marshal main PixelMap.");

    size_t numAuxiliaryPictures = auxiliaryPictures_.size();
    cond = numAuxiliaryPictures > MAX_AUXILIARY_PICTURE_COUNT;
    CHECK_ERROR_RETURN_RET(cond, false);
    cond = !data.WriteUint64(numAuxiliaryPictures);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Failed to write number of auxiliary pictures.");

    for (const auto &auxiliaryPicture : auxiliaryPictures_) {
        AuxiliaryPictureType type =  auxiliaryPicture.first;
        cond = !data.WriteInt32(static_cast<int32_t>(type));
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "Failed to write auxiliary picture type.");
        cond = !auxiliaryPicture.second || !auxiliaryPicture.second->Marshalling(data);
        CHECK_ERROR_RETURN_RET_LOG(cond, false,
            "Failed to marshal auxiliary picture of type %{public}d.", static_cast<int>(type));
    }
    cond = !MarshalMetadata(data);
    CHECK_ERROR_RETURN_RET(cond, false);
    return true;
}

Picture *Picture::Unmarshalling(Parcel &data)
{
    PICTURE_ERR error;
    Picture* dstPicture = Picture::Unmarshalling(data, error);
    CHECK_ERROR_RETURN_RET_LOG(dstPicture == nullptr || error.errorCode != SUCCESS, dstPicture,
        "unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
        error.errorCode, error.errorInfo.c_str());
    return dstPicture;
}

bool Picture::UnmarshalMetadata(Parcel &parcel, Picture &picture, PICTURE_ERR &error)
{
    bool hasMaintenanceData = parcel.ReadBool();
    if (hasMaintenanceData) {
        sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
        CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, false, "SurfaceBuffer failed to be created.");
        CHECK_ERROR_RETURN_RET_LOG(
            surfaceBuffer->ReadFromMessageParcel(reinterpret_cast<MessageParcel &>(parcel)) != GSError::GSERROR_OK,
            false, "Failed to unmarshal maintenance data");
        picture.maintenanceData_ = surfaceBuffer;
    }

    uint64_t size = parcel.ReadUint64();
    if (size > MAX_PICTURE_META_TYPE_COUNT) {
        return false;
    }
    for (size_t i = 0; i < size; ++i) {
        MetadataType type = static_cast<MetadataType>(parcel.ReadInt32());
        std::shared_ptr<ImageMetadata> imagedataPtr(nullptr);
        if (type == MetadataType::EXIF) {
            imagedataPtr.reset(ExifMetadata::Unmarshalling(parcel));
        } else if (type == MetadataType::GIF) {
            imagedataPtr.reset(GifMetadata::Unmarshalling(parcel));
        } else if (type == MetadataType::XTSTYLE) {
            imagedataPtr.reset(XtStyleMetadata::Unmarshalling(parcel));
        } else if (type == MetadataType::RFDATAB) {
            imagedataPtr.reset(RfDataBMetadata::Unmarshalling(parcel));
        } else if (type == MetadataType::HEIFS) {
            imagedataPtr.reset(HeifsMetadata::Unmarshalling(parcel));
        } else {
            IMAGE_LOGE("Unsupported metadata type: %{public}d in picture", static_cast<int32_t>(type));
        }
        if (imagedataPtr == nullptr) {
            return false;
        }
        if (picture.SetMetadata(type, imagedataPtr) != SUCCESS) {
            IMAGE_LOGE("SetMetadata %{public}d in picture failed", static_cast<int32_t>(type));
            return false;
        }
    }
    return true;
}

Picture *Picture::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    std::unique_ptr<Picture> picture = std::make_unique<Picture>();
    std::shared_ptr<PixelMap> pixelmapPtr(PixelMap::Unmarshalling(parcel));

    CHECK_ERROR_RETURN_RET_LOG(!pixelmapPtr, nullptr, "Failed to unmarshal main PixelMap.");
    picture->SetMainPixel(pixelmapPtr);
    uint64_t numAuxiliaryPictures = parcel.ReadUint64();
    CHECK_ERROR_RETURN_RET(numAuxiliaryPictures > MAX_AUXILIARY_PICTURE_COUNT, nullptr);

    for (size_t i = NUM_0; i < numAuxiliaryPictures; ++i) {
        int32_t type = parcel.ReadInt32();
        std::shared_ptr<AuxiliaryPicture> auxPtr(AuxiliaryPicture::Unmarshalling(parcel));
        CHECK_ERROR_RETURN_RET_LOG(!auxPtr, nullptr, "Failed to unmarshal auxiliary picture of type %d.", type);
        picture->SetAuxiliaryPicture(auxPtr);
    }
    CHECK_ERROR_RETURN_RET_LOG(!UnmarshalMetadata(parcel, *picture, error), nullptr, "Failed to unmarshal metadata.");
    return picture.release();
}

uint32_t Picture::CreateExifMetadata()
{
    if (GetExifMetadata() != nullptr) {
        IMAGE_LOGE("exifMetadata is already created");
        return SUCCESS;
    }
    auto exifMetadata = std::make_shared<OHOS::Media::ExifMetadata>();
    if (exifMetadata == nullptr) {
        IMAGE_LOGE("Failed to create ExifMetadata object");
        return ERR_IMAGE_MALLOC_ABNORMAL;
    }
    if (!exifMetadata->CreateExifdata()) {
        IMAGE_LOGE("Failed to create exif metadata data");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return SetExifMetadata(exifMetadata);
}

uint32_t Picture::SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer)
{
    if (surfaceBuffer == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    auto extraData = surfaceBuffer->GetExtraData();
    CHECK_ERROR_RETURN_RET(extraData == nullptr, ERR_IMAGE_INVALID_PARAMETER);

    int32_t size = NUM_0;
    GSError ret = extraData->ExtraGet(EXIF_DATA_SIZE_TAG, size);
    CHECK_ERROR_RETURN_RET_LOG(ret != GSError::GSERROR_OK, ERR_IMAGE_SOURCE_DATA, "Failed to get exif data.");
    bool cond = size <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "Invalid buffer size: %d.", size);

    size_t tiffHeaderPos = TiffParser::FindTiffPos(reinterpret_cast<const byte *>(surfaceBuffer->GetVirAddr()), size);
    cond = tiffHeaderPos == std::numeric_limits<size_t>::max();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_SOURCE_DATA, "Input image stream is not tiff type.");

    cond = static_cast<uint32_t>(size) > surfaceBuffer->GetSize() || tiffHeaderPos > surfaceBuffer->GetSize();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
                               "The size of exif metadata exceeds the buffer size.");

    cond = static_cast<uint32_t>(size) < tiffHeaderPos;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
                               "Tiff header position exceeds the size of exif metadata.");

    cond = static_cast<uint32_t>(size) - tiffHeaderPos > MAX_EXIFMETADATA_SIZE;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
                               "Failed to set exif metadata,"
                               "the size of exif metadata exceeds the maximum limit %{public}llu.",
                               static_cast<unsigned long long>(MAX_EXIFMETADATA_SIZE));
    ExifData *exifData;
    TiffParser::Decode(static_cast<const unsigned char *>(surfaceBuffer->GetVirAddr()) + tiffHeaderPos,
        size - tiffHeaderPos, &exifData);
    cond = exifData == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_EXIF_DECODE_FAILED, "Failed to decode EXIF data from image stream.");

    auto exifMetadata = std::make_shared<OHOS::Media::ExifMetadata>(exifData);
    return SetExifMetadata(exifMetadata);
}

uint32_t Picture::SetExifMetadata(std::shared_ptr<ExifMetadata> exifMetadata)
{
    return SetMetadata(MetadataType::EXIF, exifMetadata);
}

std::shared_ptr<ExifMetadata> Picture::GetExifMetadata()
{
    auto exifMetadata = GetMetadata(MetadataType::EXIF);
    if (exifMetadata == nullptr) {
        return nullptr;
    }
    return std::reinterpret_pointer_cast<ExifMetadata>(exifMetadata);
}

bool Picture::SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer)
{
    if (surfaceBuffer == nullptr) {
        return false;
    }
    maintenanceData_ = surfaceBuffer;
    return true;
}

sptr<SurfaceBuffer> Picture::GetMaintenanceData() const
{
    return maintenanceData_;
}

uint32_t Picture::SetXtStyleMetadata(std::shared_ptr<BlobMetadata> xtStyleMetadata)
{
    return SetMetadata(MetadataType::XTSTYLE, xtStyleMetadata);
}

std::shared_ptr<XtStyleMetadata> Picture::GetXtStyleMetadata()
{
    auto xtStyleMetadata = GetMetadata(MetadataType::XTSTYLE);
    if (xtStyleMetadata == nullptr) {
        return nullptr;
    }
    return std::reinterpret_pointer_cast<XtStyleMetadata>(xtStyleMetadata);
}

uint32_t Picture::SetRfDataBMetadata(std::shared_ptr<BlobMetadata> rfDataBMetadata)
{
    return SetMetadata(MetadataType::RFDATAB, rfDataBMetadata);
}

std::shared_ptr<RfDataBMetadata> Picture::GetRfDataBMetadata()
{
    auto rfDataBMetadata = GetMetadata(MetadataType::RFDATAB);
    if (rfDataBMetadata == nullptr) {
        return nullptr;
    }
    return std::reinterpret_pointer_cast<RfDataBMetadata>(rfDataBMetadata);
}

std::shared_ptr<ImageMetadata> Picture::GetMetadata(MetadataType type)
{
    if (metadatas_.find(type) == metadatas_.end()) {
        IMAGE_LOGD("metadata type(%{public}d) not exist.", static_cast<int32_t>(type));
        return nullptr;
    }
    return metadatas_[type];
}

uint32_t Picture::SetMetadata(MetadataType type, std::shared_ptr<ImageMetadata> pictureMetadata)
{
    if (pictureMetadata == nullptr) {
        IMAGE_LOGE("pictureMetadata is null");
        return ERR_MEDIA_NULL_POINTER;
    }
    if (type != pictureMetadata->GetType()) {
        IMAGE_LOGE("pictureMetadata type dismatch, %{public}d vs %{public}d",
            static_cast<int>(type), static_cast<int>(pictureMetadata->GetType()));
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!Picture::IsValidPictureMetadataType(type)) {
        IMAGE_LOGE("Unsupported pictureMetadata type: %{public}d", static_cast<int32_t>(type));
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (metadatas_.size() >= MAX_PICTURE_META_TYPE_COUNT) {
        IMAGE_LOGE("Failed to set metadata, the size of metadata exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_PICTURE_META_TYPE_COUNT));
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    metadatas_[type] = pictureMetadata;
    if (type == MetadataType::EXIF && mainPixelMap_ != nullptr) {
        auto exifMetadata = std::reinterpret_pointer_cast<ExifMetadata>(pictureMetadata);
        mainPixelMap_->SetExifMetadata(exifMetadata);
    }
    return SUCCESS;
}

uint32_t Picture::SetBlobMetadataByType(const std::vector<uint8_t>& metadata, MetadataType type)
{
    std::shared_ptr<BlobMetadata> blobMetadata = std::make_shared<BlobMetadata>(type);
    blobMetadata->SetBlob(metadata.data(), metadata.size());
    return SetMetadata(type, blobMetadata);
}

void Picture::DumpPictureIfDumpEnabled(Picture& picture, std::string dumpType)
{
    CHECK_ERROR_RETURN(!ImageSystemProperties::GetDumpPictureEnabled());
    CHECK_ERROR_RETURN_LOG(picture.GetMainPixel() == nullptr, "DumpPictureIfDumpEnabled mainPixelmap is null");
    ImageUtils::DumpPixelMap(picture.GetMainPixel().get(), dumpType + "_MainPixelmap");
    auto auxTypes = ImageUtils::GetAllAuxiliaryPictureType();
    for (AuxiliaryPictureType auxType : auxTypes) {
        auto auxPicture = picture.GetAuxiliaryPicture(auxType);
        if (auxPicture == nullptr) {
            continue;
        }
        auto pixelMap = auxPicture->GetContentPixel();
        if (pixelMap != nullptr) {
            ImageUtils::DumpPixelMap(pixelMap.get(), dumpType + "_AuxiliaryType", static_cast<uint64_t>(auxType));
        }
    }
    auto rfDataBMetadata = picture.GetRfDataBMetadata();
    if (rfDataBMetadata != nullptr && rfDataBMetadata->GetBlobPtr() != nullptr) {
        ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<char*>(rfDataBMetadata->GetBlobPtr()),
            rfDataBMetadata->GetBlobSize(), dumpType + "_RfDataB", static_cast<uint64_t>(MetadataType::RFDATAB));
    }
}

bool Picture::IsValidPictureMetadataType(MetadataType metadataType)
{
    const static std::set<MetadataType> pictureMetadataTypes = {
        MetadataType::EXIF,
        MetadataType::XTSTYLE,
        MetadataType::RFDATAB,
        MetadataType::GIF,
        MetadataType::STDATA,
        MetadataType::HEIFS,
    };
    return pictureMetadataTypes.find(metadataType) != pictureMetadataTypes.end();
}
} // namespace Media
} // namespace OHOS
