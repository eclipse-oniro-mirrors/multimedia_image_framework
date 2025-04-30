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
#include "picture.h"
#include "pixel_yuv.h"
#include "pixel_yuv_ext.h"
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
    if (buffer == nullptr) {
        return CM_ColorSpaceType::CM_COLORSPACE_NONE;
    }
    CM_ColorSpaceType type;
    MetadataHelper::GetColorSpaceType(buffer, type);
    return type;
}

static ColorSpace CMColorSpaceType2ColorSpace(CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_MAP.find(type);
    if (iter == CM_COLORSPACE_MAP.end()) {
        return ColorSpace::UNKNOWN;
    }
    return iter->second;
}

#ifdef IMAGE_COLORSPACE_FLAG
static ColorManager::ColorSpaceName CMColorSpaceType2ColorSpaceName(CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_NAME_MAP.find(type);
    if (iter == CM_COLORSPACE_NAME_MAP.end()) {
        return ColorManager::NONE;
    }
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

static void SetYuvDataInfo(std::unique_ptr<PixelMap> &pixelMap, sptr<OHOS::SurfaceBuffer> &sBuffer)
{
    bool cond = pixelMap == nullptr || sBuffer == nullptr;
    CHECK_ERROR_RETURN(cond);
    int32_t width = sBuffer->GetWidth();
    int32_t height = sBuffer->GetHeight();
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = sBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    YUVDataInfo info;
    info.imageSize = { width, height };
    if (retVal != OHOS::GSERROR_OK || planes == nullptr || planes->planeCount <= NUM_1) {
        IMAGE_LOGE("Get planesInfo failed, retVal:%{public}d", retVal);
        return;
    } else if (planes->planeCount >= NUM_2) {
        info.yStride = planes->planes[NUM_0].columnStride;
        info.uvStride = planes->planes[NUM_1].columnStride;
        info.yOffset = planes->planes[NUM_0].offset;
        info.uvOffset = planes->planes[NUM_1].offset - NUM_1;
    }
    pixelMap->SetImageYUVInfo(info);
}

static void SetImageInfoToHdr(std::shared_ptr<PixelMap> &mainPixelMap, std::unique_ptr<PixelMap> &hdrPixelMap)
{
    if (mainPixelMap != nullptr && hdrPixelMap != nullptr) {
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
    if (err != OHOS::GSERROR_OK) {
        IMAGE_LOGE("NativeBufferReference failed");
        return nullptr;
    }

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
    if (pixelMap == nullptr) {
        return nullptr;
    }

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
        SetYuvDataInfo(pixelMap, surfaceBuffer);
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
    int32_t hdrAllocFormat = GRAPHIC_PIXEL_FMT_RGBA_1010102;
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
        default:
            IMAGE_LOGW("%{public}s no corresponding hdrAllocFormat for format: %{public}d", __func__, pixelFormat);
            break;
    }
    IMAGE_LOGD("%{public}s use hdrAllocFormat: %{public}d for format: %{public}d",
        __func__, hdrAllocFormat, pixelFormat);
    return hdrAllocFormat;
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
    if (memCpyRes != EOK) {
        IMAGE_LOGE("%{public}s memcpy_s ISOMetadata fail, error: %{public}d", __func__, memCpyRes);
        return;
    }
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
    if (memCpyRes != EOK) {
        IMAGE_LOGE("%{public}s memcpy_s HDRVividExtendMetadata fail, error: %{public}d", __func__, memCpyRes);
        return;
    }
    VpeUtils::SetSbDynamicMetadata(gainmapSptr, extendMetadataVec);
}

static bool ShouldComposeAsCuva(const sptr<SurfaceBuffer> &baseSptr, const sptr<SurfaceBuffer> &gainmapSptr)
{
    std::vector<uint8_t> baseStaticMetadata;
    VpeUtils::GetSbStaticMetadata(baseSptr, baseStaticMetadata);
    std::vector<uint8_t> baseDynamicMetadata;
    VpeUtils::GetSbDynamicMetadata(gainmapSptr, baseDynamicMetadata);
    if (baseStaticMetadata.size() == 0 || baseDynamicMetadata.size() == 0) {
        return true;
    }

    std::vector<uint8_t> gainmapDynamicMetadata;
    VpeUtils::GetSbDynamicMetadata(gainmapSptr, gainmapDynamicMetadata);
    if (gainmapDynamicMetadata.size() != sizeof(HDRVividExtendMetadata)) {
        return true;
    }
    return false;
}

static std::unique_ptr<PixelMap> ComposeHdrPixelMap(
    std::shared_ptr<PixelMap> &mainPixelMap, sptr<SurfaceBuffer> &baseSptr, sptr<SurfaceBuffer> &gainmapSptr)
{
    sptr<SurfaceBuffer> hdrSptr = SurfaceBuffer::Create();
    ImageInfo imageInfo;
    mainPixelMap->GetImageInfo(imageInfo);
    BufferRequestConfig requestConfig = {
        .width = imageInfo.size.width,
        .height = imageInfo.size.height,
        .strideAlignment = imageInfo.size.width,
        .format = GetHdrAllocFormat(imageInfo.pixelFormat),
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };

    GSError error = hdrSptr->Alloc(requestConfig);
    if (error != GSERROR_OK) {
        IMAGE_LOGE("HDR SurfaceBuffer Alloc failed, error: %{public}s", GSErrorStr(error).c_str());
        return nullptr;
    }
    VpeUtils::SetSbMetadataType(hdrSptr, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbColorSpaceType(hdrSptr, CM_BT2020_HLG_FULL);

    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .gainmap = gainmapSptr,
        .hdr = hdrSptr,
    };
    bool isCuva = ShouldComposeAsCuva(baseSptr, gainmapSptr);
    IMAGE_LOGD("HDR Compose image, isCuva: %{public}d", isCuva);
    int32_t res = VpeUtils().ColorSpaceConverterComposeImage(buffers, isCuva);
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("Compose HDR image failed, res: %{public}d", res);
        return nullptr;
    }
    return Picture::SurfaceBuffer2PixelMap(hdrSptr);
}

std::unique_ptr<PixelMap> Picture::GetHdrComposedPixelMap()
{
    std::shared_ptr<PixelMap> gainmap = GetGainmapPixelMap();
    if (mainPixelMap_ == nullptr || gainmap == nullptr) {
        IMAGE_LOGE("picture mainPixelMap_ or gainmap is empty.");
        return nullptr;
    }
    if (mainPixelMap_->GetAllocatorType() != AllocatorType::DMA_ALLOC || mainPixelMap_->GetFd() == nullptr ||
        gainmap->GetAllocatorType() != AllocatorType::DMA_ALLOC || gainmap->GetFd() == nullptr) {
        IMAGE_LOGE("Unsupport HDR compose, only support the DMA allocation.");
        return nullptr;
    }
    sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(mainPixelMap_->GetFd()));
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    sptr<SurfaceBuffer> gainmapSptr(reinterpret_cast<SurfaceBuffer*>(gainmap->GetFd()));
    VpeUtils::SetSbMetadataType(gainmapSptr, CM_METADATA_NONE);
    TryFixGainmapHdrMetadata(gainmapSptr);
    auto hdrPixelMap = ComposeHdrPixelMap(mainPixelMap_, baseSptr, gainmapSptr);
    SetImageInfoToHdr(mainPixelMap_, hdrPixelMap);
    return hdrPixelMap;
}

std::shared_ptr<PixelMap> Picture::GetGainmapPixelMap()
{
    if (!HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP)) {
        IMAGE_LOGE("Unsupport gain map.");
        return nullptr;
    } else {
        auto auxiliaryPicture = GetAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
        if (auxiliaryPicture == nullptr) {
            return nullptr;
        }
        return auxiliaryPicture->GetContentPixel();
    }
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
    if (auxiliaryPictures_.size() >= MAX_AUXILIARY_PICTURE_COUNT) {
        IMAGE_LOGE("The size of auxiliary picture exceeds the maximum limit %{public}llu.",
            static_cast<unsigned long long>(MAX_AUXILIARY_PICTURE_COUNT));
        return;
    }
    AuxiliaryPictureType type = picture->GetType();
    auxiliaryPictures_[type] = picture;
}

bool Picture::HasAuxiliaryPicture(AuxiliaryPictureType type)
{
    auto item = auxiliaryPictures_.find(type);
    return item != auxiliaryPictures_.end() && item->second != nullptr;
}

bool Picture::Marshalling(Parcel &data) const
{
    if (!mainPixelMap_) {
        IMAGE_LOGE("Main PixelMap is null.");
        return false;
    }
    if (!mainPixelMap_->Marshalling(data)) {
        IMAGE_LOGE("Failed to marshal main PixelMap.");
        return false;
    }

    size_t numAuxiliaryPictures = auxiliaryPictures_.size();
    if (numAuxiliaryPictures > MAX_AUXILIARY_PICTURE_COUNT) {
        return false;
    }
    if (!data.WriteUint64(numAuxiliaryPictures)) {
        IMAGE_LOGE("Failed to write number of auxiliary pictures.");
        return false;
    }

    for (const auto &auxiliaryPicture : auxiliaryPictures_) {
        AuxiliaryPictureType type =  auxiliaryPicture.first;

        if (!data.WriteInt32(static_cast<int32_t>(type))) {
            IMAGE_LOGE("Failed to write auxiliary picture type.");
            return false;
        }

        if (!auxiliaryPicture.second || !auxiliaryPicture.second->Marshalling(data)) {
            IMAGE_LOGE("Failed to marshal auxiliary picture of type %d.", static_cast<int>(type));
            return false;
        }
    }

    if (!data.WriteBool(maintenanceData_ != nullptr)) {
        IMAGE_LOGE("Failed to write maintenance data existence value.");
        return false;
    }

    if (maintenanceData_ != nullptr) {
        if (maintenanceData_->WriteToMessageParcel(reinterpret_cast<MessageParcel&>(data)) != GSError::GSERROR_OK) {
            IMAGE_LOGE("Failed to write maintenance data content.");
            return false;
        }
    }

    if (!data.WriteBool(exifMetadata_ != nullptr)) {
        IMAGE_LOGE("Failed to write exif data existence value.");
        return false;
    }

    if (exifMetadata_ != nullptr) {
        if (!exifMetadata_->Marshalling(data)) {
            IMAGE_LOGE("Failed to marshal exif metadata.");
            return false;
        }
    }

    return true;
}

Picture *Picture::Unmarshalling(Parcel &data)
{
    PICTURE_ERR error;
    Picture* dstPicture = Picture::Unmarshalling(data, error);
    if (dstPicture == nullptr || error.errorCode != SUCCESS) {
        IMAGE_LOGE("unmarshalling failed errorCode:%{public}d, errorInfo:%{public}s",
            error.errorCode, error.errorInfo.c_str());
    }
    return dstPicture;
}

Picture *Picture::Unmarshalling(Parcel &parcel, PICTURE_ERR &error)
{
    std::unique_ptr<Picture> picture = std::make_unique<Picture>();
    std::shared_ptr<PixelMap> pixelmapPtr(PixelMap::Unmarshalling(parcel));

    if (!pixelmapPtr) {
        IMAGE_LOGE("Failed to unmarshal main PixelMap.");
        return nullptr;
    }
    picture->SetMainPixel(pixelmapPtr);
    uint64_t numAuxiliaryPictures = parcel.ReadUint64();
    if (numAuxiliaryPictures > MAX_AUXILIARY_PICTURE_COUNT) {
        return nullptr;
    }

    for (size_t i = NUM_0; i < numAuxiliaryPictures; ++i) {
        int32_t type = parcel.ReadInt32();
        std::shared_ptr<AuxiliaryPicture> auxPtr(AuxiliaryPicture::Unmarshalling(parcel));
        if (!auxPtr) {
            IMAGE_LOGE("Failed to unmarshal auxiliary picture of type %d.", type);
            return nullptr;
        }
        picture->SetAuxiliaryPicture(auxPtr);
    }

    bool hasMaintenanceData = parcel.ReadBool();
    if (hasMaintenanceData) {
        sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
        if (surfaceBuffer == nullptr) {
            IMAGE_LOGE("SurfaceBuffer failed to be created.");
            return nullptr;
        }
        if (surfaceBuffer->ReadFromMessageParcel(reinterpret_cast<MessageParcel&>(parcel)) != GSError::GSERROR_OK) {
            IMAGE_LOGE("Failed to unmarshal maintenance data");
            return nullptr;
        }
        picture->maintenanceData_ = surfaceBuffer;
    }

    bool hasExifData = parcel.ReadBool();
    if (hasExifData) {
        picture->exifMetadata_ = std::shared_ptr<ExifMetadata>(ExifMetadata::Unmarshalling(parcel));
        if (picture->GetMainPixel() != nullptr) {
            picture->GetMainPixel()->SetExifMetadata(picture->exifMetadata_);
        }
    }

    return picture.release();
}

int32_t Picture::CreateExifMetadata()
{
    if (exifMetadata_ != nullptr) {
        IMAGE_LOGE("exifMetadata is already created");
        return SUCCESS;
    }
    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>();
    if (exifMetadata_ == nullptr) {
        IMAGE_LOGE("Failed to create ExifMetadata object");
        return ERR_IMAGE_MALLOC_ABNORMAL;
    }
    if (!exifMetadata_->CreateExifdata()) {
        IMAGE_LOGE("Failed to create exif metadata data");
        exifMetadata_ = nullptr;
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return SUCCESS;
}

int32_t Picture::SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer)
{
    if (surfaceBuffer == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    auto extraData = surfaceBuffer->GetExtraData();
    if (extraData == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    int32_t size = NUM_0;
    extraData->ExtraGet(EXIF_DATA_SIZE_TAG, size);
    bool cond = size <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "Invalid buffer size: %d.", size);

    size_t tiffHeaderPos = TiffParser::FindTiffPos(reinterpret_cast<const byte *>(surfaceBuffer->GetVirAddr()), size);
    cond = tiffHeaderPos == std::numeric_limits<size_t>::max();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_SOURCE_DATA, "Input image stream is not tiff type.");

    cond = static_cast<uint32_t>(size) > surfaceBuffer->GetSize() || tiffHeaderPos > surfaceBuffer->GetSize();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
                               "The size of exif metadata exceeds the buffer size.");

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

    exifMetadata_ = std::make_shared<OHOS::Media::ExifMetadata>(exifData);
    if (mainPixelMap_ != nullptr) {
        mainPixelMap_->SetExifMetadata(exifMetadata_);
    }
    return SUCCESS;
}

int32_t Picture::SetExifMetadata(std::shared_ptr<ExifMetadata> exifMetadata)
{
    if (exifMetadata == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    exifMetadata_ = exifMetadata;
    if (mainPixelMap_ != nullptr) {
        mainPixelMap_->SetExifMetadata(exifMetadata_);
    }
    return SUCCESS;
}

std::shared_ptr<ExifMetadata> Picture::GetExifMetadata()
{
    return exifMetadata_;
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

void Picture::DumpPictureIfDumpEnabled(Picture& picture, std::string dumpType)
{
    if (!ImageSystemProperties::GetDumpPictureEnabled()) {
        return;
    }
    if (picture.GetMainPixel() == nullptr) {
        IMAGE_LOGE("DumpPictureIfDumpEnabled mainPixelmap is null");
        return;
    }
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
}
} // namespace Media
} // namespace OHOS
