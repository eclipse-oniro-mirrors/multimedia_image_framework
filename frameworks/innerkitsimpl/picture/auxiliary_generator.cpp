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

#include "auxiliary_generator.h"
#include "abs_image_decoder.h"
#include "fragment_metadata.h"
#include "hdr_type.h"
#include "image_log.h"
#include "image_utils.h"
#include "image_mime_type.h"
#include "image_source.h"
#include "jpeg_mpf_parser.h"
#include "metadata.h"
#include "pixel_map.h"
#include "pixel_map_utils.h"
#include "pixel_yuv.h"
#ifdef EXT_PIXEL
#include "pixel_yuv_ext.h"
#endif
#include "securec.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {
using namespace ImagePlugin;

static constexpr uint32_t FIRST_FRAME = 0;
static constexpr int32_t DEFAULT_SCALE_DENOMINATOR = 1;
static constexpr int32_t DEPTH_SCALE_DENOMINATOR = 4;
static constexpr int32_t LINEAR_SCALE_DENOMINATOR = 4;
static constexpr uint32_t NV12_PLANE_UV_INDEX = 1;
static constexpr uint32_t NV21_PLANE_UV_INDEX = 2;

static inline bool IsSizeVailed(const Size &size)
{
    return (size.width != 0 && size.height != 0);
}

static int32_t GetAuxiliaryPictureDenominator(AuxiliaryPictureType type)
{
    int32_t denominator = DEFAULT_SCALE_DENOMINATOR;
    switch (type) {
        case AuxiliaryPictureType::DEPTH_MAP:
            denominator = DEPTH_SCALE_DENOMINATOR;
            break;
        case AuxiliaryPictureType::LINEAR_MAP:
            denominator = LINEAR_SCALE_DENOMINATOR;
            break;
        default:
            break;
    }
    return denominator;
}

static uint32_t SetAuxiliaryDecodeOption(std::unique_ptr<AbsImageDecoder> &decoder, PixelFormat mainPixelFormat,
    PlImageInfo &plInfo, AuxiliaryPictureType type)
{
    Size size;
    uint32_t errorCode = decoder->GetImageSize(FIRST_FRAME, size);
    if (errorCode != SUCCESS || !IsSizeVailed(size)) {
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    PixelDecodeOptions plOptions;
    plOptions.desiredSize = size;
    bool useF16Format = (type == AuxiliaryPictureType::LINEAR_MAP || type == AuxiliaryPictureType::DEPTH_MAP);
    plOptions.desiredPixelFormat = useF16Format ? PixelFormat::RGBA_F16 : mainPixelFormat;
    IMAGE_LOGI("%{public}s desiredPixelFormat is %{public}d", __func__, plOptions.desiredPixelFormat);
    errorCode = decoder->SetDecodeOptions(FIRST_FRAME, plOptions, plInfo);
    return errorCode;
}

static void FreeContextBuffer(const Media::CustomFreePixelMap &func, AllocatorType allocType, PlImageBuffer &buffer)
{
    if (func != nullptr) {
        func(buffer.buffer, buffer.context, buffer.bufferSize);
        return;
    }

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (allocType == AllocatorType::SHARE_MEM_ALLOC) {
        int *fd = static_cast<int *>(buffer.context);
        if (buffer.buffer != nullptr) {
            ::munmap(buffer.buffer, buffer.bufferSize);
        }
        if (fd != nullptr) {
            ::close(*fd);
        }
        return;
    } else if (allocType == AllocatorType::DMA_ALLOC) {
        if (buffer.buffer != nullptr) {
            ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer *>(buffer.context));
            buffer.context = nullptr;
        }
    } else if (allocType == AllocatorType::HEAP_ALLOC) {
        if (buffer.buffer != nullptr) {
            free(buffer.buffer);
            buffer.buffer = nullptr;
        }
    }
#else
    if (buffer.buffer != nullptr) {
        free(buffer.buffer);
        buffer.buffer = nullptr;
    }
#endif
}

ImageInfo AuxiliaryGenerator::MakeImageInfo(const Size &size, PixelFormat format, AlphaType alphaType,
    ColorSpace colorSpace, const std::string &encodedFormat)
{
    ImageInfo info;
    info.size.width = size.width;
    info.size.height = size.height;
    info.pixelFormat = format;
    info.alphaType = alphaType;
    info.colorSpace = colorSpace;
    info.encodedFormat = encodedFormat;
    return info;
}

static AuxiliaryPictureInfo MakeAuxiliaryPictureInfo(AuxiliaryPictureType type,
    const Size &size, uint32_t rowStride, PixelFormat format, ColorSpace colorSpace)
{
    AuxiliaryPictureInfo info;
    info.auxiliaryPictureType = type;
    info.size.width = size.width;
    info.size.height = size.height;
    info.rowStride = rowStride;
    info.pixelFormat = format;
    info.colorSpace = colorSpace;
    return info;
}

static void SetDmaYuvInfo(SurfaceBuffer *&surfaceBuffer, PixelFormat format, YUVDataInfo &yuvInfo)
{
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGE("%{public}s: surfacebuffer is nullptr", __func__);
        return;
    }
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void **>(&planes));
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        IMAGE_LOGE("%{public}s: GetPlanesInfo failed retVal: %{public}d", __func__, retVal);
        return;
    }
    const OH_NativeBuffer_Plane &planeY = planes->planes[0];
    bool isNV21 = (format == PixelFormat::NV21 || format == PixelFormat::YCRCB_P010);
    const OH_NativeBuffer_Plane &planeUV = planes->planes[isNV21 ? NV21_PLANE_UV_INDEX : NV12_PLANE_UV_INDEX];
    if (format == PixelFormat::YCRCB_P010 || format == PixelFormat::YCBCR_P010) {
        yuvInfo.yStride = planeY.columnStride / 2;
        yuvInfo.uvStride = planeUV.columnStride / 2;
        yuvInfo.yOffset = planeY.offset / 2;
        yuvInfo.uvOffset = planeUV.offset / 2;
    } else {
        yuvInfo.yStride = planeY.columnStride;
        yuvInfo.uvStride = planeUV.columnStride;
        yuvInfo.yOffset = planeY.offset;
        yuvInfo.uvOffset = planeUV.offset;
    }
}

static void SetNonDmaYuvInfo(int32_t width, int32_t height, YUVDataInfo &yuvInfo)
{
    yuvInfo.yWidth = static_cast<uint32_t>(width);
    yuvInfo.yHeight = static_cast<uint32_t>(height);
    yuvInfo.uvWidth = static_cast<uint32_t>((width + 1) / 2);
    yuvInfo.uvHeight = static_cast<uint32_t>((height + 1) / 2);
    yuvInfo.yStride = static_cast<uint32_t>(width);
    yuvInfo.uvStride = static_cast<uint32_t>(((width + 1) / 2) * 2);
    yuvInfo.uvOffset = static_cast<uint32_t>(width) * static_cast<uint32_t>(height);
}

static void TrySetYUVDataInfo(std::unique_ptr<PixelMap> &pixelMap)
{
    if (pixelMap == nullptr) {
        IMAGE_LOGE("%{public}s pixelMap is nullptr", __func__);
        return;
    }
    PixelFormat format = pixelMap->GetPixelFormat();
    if (!ImageSource::IsYuvFormat(format)) {
        IMAGE_LOGI("%{public}s pixelMap is not YUV format", __func__);
        return;
    }

    YUVDataInfo info;
    if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC && pixelMap->GetFd() != nullptr) {
        SurfaceBuffer *surfaceBuffer = reinterpret_cast<SurfaceBuffer *>(pixelMap->GetFd());
        SetDmaYuvInfo(surfaceBuffer, format, info);
    } else {
        SetNonDmaYuvInfo(pixelMap->GetWidth(), pixelMap->GetHeight(), info);
    }
    pixelMap->SetImageYUVInfo(info);
}

std::unique_ptr<PixelMap> AuxiliaryGenerator::CreatePixelMapByContext(DecodeContext &context,
    std::unique_ptr<AbsImageDecoder> &decoder, const std::string &encodedFormat, uint32_t &errorCode)
{
    std::unique_ptr<PixelMap> pixelMap;
    if (ImageSource::IsYuvFormat(context.info.pixelFormat)) {
#ifdef EXT_PIXEL
        pixelMap = std::make_unique<PixelYuvExt>();
#else
        pixelMap = std::make_unique<PixelYuv>();
#endif
    } else {
        pixelMap = std::make_unique<PixelMap>();
    }
    if (pixelMap == nullptr) {
        errorCode = ERR_IMAGE_ADD_PIXEL_MAP_FAILED;
        return nullptr;
    }

    ImageInfo imageinfo = AuxiliaryGenerator::MakeImageInfo(context.outInfo.size, context.info.pixelFormat,
        context.info.alphaType, context.colorSpace, encodedFormat);
    pixelMap->SetImageInfo(imageinfo, true);

    PixelMapAddrInfos addrInfos;
    ImageSource::ContextToAddrInfos(context, addrInfos);
    pixelMap->SetPixelsAddr(addrInfos.addr, addrInfos.context, addrInfos.size, addrInfos.type, addrInfos.func);
    TrySetYUVDataInfo(pixelMap);

#ifdef IMAGE_COLORSPACE_FLAG
    if (context.hdrType > ImageHdrType::SDR) {
        pixelMap->InnerSetColorSpace(ColorManager::ColorSpace(context.grColorSpaceName));
    } else if (decoder->IsSupportICCProfile()) {
        pixelMap->InnerSetColorSpace(decoder->GetPixelMapColorSpace());
    }
#endif
    return pixelMap;
}

static uint32_t DecodeHdrMetadata(ImageHdrType hdrType, std::unique_ptr<AbsImageDecoder> &extDecoder,
    std::unique_ptr<AuxiliaryPicture> &auxPicture)
{
    std::shared_ptr<HdrMetadata> hdrMetadata = std::make_shared<HdrMetadata>(extDecoder->GetHdrMetadata(hdrType));
    std::shared_ptr<PixelMap> pixelMap = auxPicture->GetContentPixel();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("Get invalid content pixel map for hdr metadata");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    pixelMap->SetHdrMetadata(hdrMetadata);
    pixelMap->SetHdrType(hdrType);
    return SUCCESS;
}

static uint32_t DecodeHeifFragmentMetadata(std::unique_ptr<AbsImageDecoder> &extDecoder,
    std::unique_ptr<AuxiliaryPicture> &auxPicture)
{
    Rect fragmentRect;
    if (!extDecoder->GetHeifFragmentMetadata(fragmentRect)) {
        IMAGE_LOGE("Heif parsing fragment metadata failed");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    std::shared_ptr<ImageMetadata> fragmentMetadata = std::make_shared<FragmentMetadata>();
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_X, std::to_string(fragmentRect.left));
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_Y, std::to_string(fragmentRect.top));
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_WIDTH, std::to_string(fragmentRect.width));
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_HEIGHT, std::to_string(fragmentRect.height));
    auxPicture->SetMetadata(MetadataType::FRAGMENT, fragmentMetadata);
    return SUCCESS;
}

static uint32_t DecodeJpegFragmentMetadata(std::unique_ptr<InputDataStream> &auxStream,
    std::unique_ptr<AuxiliaryPicture> &auxPicture)
{
    uint8_t *data = auxStream->GetDataPtr();
    uint32_t size = auxStream->GetStreamSize();
    Rect fragmentRect;
    if (!JpegMpfParser::ParsingFragmentMetadata(data, size, fragmentRect)) {
        IMAGE_LOGE("Jpeg parsing fragment metadata failed");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    std::shared_ptr<ImageMetadata> fragmentMetadata = std::make_shared<FragmentMetadata>();
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_X, std::to_string(fragmentRect.left));
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_Y, std::to_string(fragmentRect.top));
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_WIDTH, std::to_string(fragmentRect.width));
    fragmentMetadata->SetValue(FRAGMENT_METADATA_KEY_HEIGHT, std::to_string(fragmentRect.height));
    auxPicture->SetMetadata(MetadataType::FRAGMENT, fragmentMetadata);
    return SUCCESS;
}

static sptr<SurfaceBuffer> AllocSurfaceBuffer(Size &size, int32_t format, uint32_t &errorCode)
{
    IMAGE_LOGD("SurfaceBuffer alloc width: %{public}d, height: %{public}d, format: %{public}d",
        size.width, size.height, format);
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = size.width,
        .height = size.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = format,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SurfaceBuffer alloc failed, %{public}s", GSErrorStr(ret).c_str());
        errorCode = ERR_DMA_NOT_EXIST;
        return nullptr;
    }
    errorCode = SUCCESS;
    return sb;
}

static uint32_t CopyToSurfaceBuffer(std::unique_ptr<InputDataStream> &stream, sptr<SurfaceBuffer> &surfaceBuffer)
{
    uint8_t *src = stream->GetDataPtr();
    uint32_t srcSize = stream->GetStreamSize();
    uint8_t *dst = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr());
    uint32_t dstSize = surfaceBuffer->GetSize();
    if (src == nullptr || dst == nullptr || srcSize == 0 || dstSize == 0) {
        IMAGE_LOGE("%{public}s: invalid input data", __func__);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    IMAGE_LOGD("SurfaceBuffer size: %{public}u, stream size: %{public}u", dstSize, srcSize);
    if (memcpy_s(dst, dstSize, src, srcSize) != EOK) {
        IMAGE_LOGE("%{public}s: memcpy failed", __func__);
        return ERR_MEMORY_COPY_FAILED;
    }
    return SUCCESS;
}

static void SetUncodedAuxilaryPictureInfo(std::unique_ptr<AuxiliaryPicture> &auxPicture)
{
    if (auxPicture == nullptr || auxPicture->GetContentPixel() == nullptr) {
        IMAGE_LOGE("%{public}s auxPicture or auxPixelMap is nullptr", __func__);
        return;
    }
    auto auxPixelMap = auxPicture->GetContentPixel();
    ImageInfo imageInfo;
    auxPixelMap->GetImageInfo(imageInfo);
    auto auxInfo = MakeAuxiliaryPictureInfo(auxPicture->GetType(), imageInfo.size, auxPixelMap->GetRowStride(),
        imageInfo.pixelFormat, imageInfo.colorSpace);
    auxPicture->SetAuxiliaryPictureInfo(auxInfo);
}

static std::unique_ptr<AuxiliaryPicture> GenerateAuxiliaryPicture(MainPictureInfo &mainInfo,
    AuxiliaryPictureType type, const std::string &format,
    std::unique_ptr<AbsImageDecoder> &extDecoder, uint32_t &errorCode)
{
    IMAGE_LOGI("Generate by decoder, type: %{public}d, format: %{public}s", static_cast<int>(type), format.c_str());
    if (mainInfo.imageInfo.pixelFormat == PixelFormat::ARGB_8888) {
        IMAGE_LOGW("The auxiliaryPicture cannot use ARGB_8888, convert to RGBA_8888");
        mainInfo.imageInfo.pixelFormat = PixelFormat::RGBA_8888;
    }
    DecodeContext context;
    context.allocatorType = AllocatorType::DMA_ALLOC;
    errorCode = SetAuxiliaryDecodeOption(extDecoder, mainInfo.imageInfo.pixelFormat, context.info, type);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Set auxiliary decode option failed! errorCode: %{public}u", errorCode);
        return nullptr;
    }
    if (format == IMAGE_HEIF_FORMAT) {
#ifdef HEIF_HW_DECODE_ENABLE
        if (type == AuxiliaryPictureType::LINEAR_MAP || type == AuxiliaryPictureType::DEPTH_MAP) {
            context.pixelFormat = PixelFormat::RGBA_F16;
            context.info.pixelFormat = PixelFormat::RGBA_F16;
        }
        if (!extDecoder->DecodeHeifAuxiliaryMap(context, type)) {
            errorCode = ERR_IMAGE_DECODE_FAILED;
        }
#else
        errorCode = ERR_IMAGE_HW_DECODE_UNSUPPORT;
#endif
    } else if (format == IMAGE_JPEG_FORMAT) {
        errorCode = extDecoder->Decode(FIRST_FRAME, context);
        context.hdrType = mainInfo.hdrType;
    } else {
        errorCode = ERR_MEDIA_DATA_UNSUPPORT;
    }
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Decode failed! Format: %{public}s, errorCode: %{public}u", format.c_str(), errorCode);
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        return nullptr;
    }

    std::string encodedFormat = ImageUtils::IsAuxiliaryPictureEncoded(type) ? format : "";
    std::shared_ptr<PixelMap> pixelMap = AuxiliaryGenerator::CreatePixelMapByContext(
        context, extDecoder, encodedFormat, errorCode);
    bool cond = pixelMap == nullptr || errorCode != SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "%{public}s CreatePixelMapByContext failed!", __func__);
    auto auxPicture = AuxiliaryPicture::Create(pixelMap, type, context.outInfo.size);
    auxPicture->SetAuxiliaryPictureInfo(
        MakeAuxiliaryPictureInfo(type, context.outInfo.size, pixelMap->GetRowStride(),
                                 context.pixelFormat, context.outInfo.colorSpace));
    return auxPicture;
}

std::shared_ptr<AuxiliaryPicture> AuxiliaryGenerator::GenerateHeifAuxiliaryPicture(MainPictureInfo &mainInfo,
    AuxiliaryPictureType type, std::unique_ptr<AbsImageDecoder> &extDecoder, uint32_t &errorCode)
{
    IMAGE_LOGI("Generate heif auxiliary picture, type: %{public}d", static_cast<int>(type));
    if (!ImageUtils::IsAuxiliaryPictureTypeSupported(type) || extDecoder == nullptr) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }

    auto auxPicture = GenerateAuxiliaryPicture(mainInfo, type, IMAGE_HEIF_FORMAT, extDecoder, errorCode);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Generate heif auxiliary picture failed! errorCode: %{public}u", errorCode);
        return nullptr;
    }
    if (type == AuxiliaryPictureType::GAINMAP) {
        errorCode = DecodeHdrMetadata(mainInfo.hdrType, extDecoder, auxPicture);
    } else if (type == AuxiliaryPictureType::FRAGMENT_MAP) {
        errorCode = DecodeHeifFragmentMetadata(extDecoder, auxPicture);
    }
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Decode heif metadata failed! errorCode: %{public}u", errorCode);
        return nullptr;
    }
    return std::move(auxPicture);
}

std::shared_ptr<AuxiliaryPicture> AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(
    MainPictureInfo &mainInfo, AuxiliaryPictureType type, std::unique_ptr<InputDataStream> &auxStream,
    std::unique_ptr<AbsImageDecoder> &extDecoder, uint32_t &errorCode)
{
    IMAGE_LOGI("Generate jpeg auxiliary picture, type: %{public}d", static_cast<int>(type));
    if (!ImageUtils::IsAuxiliaryPictureTypeSupported(type) || auxStream == nullptr || extDecoder == nullptr) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }

    if (ImageUtils::IsAuxiliaryPictureEncoded(type)) {
        auto auxPicture = GenerateAuxiliaryPicture(mainInfo, type, IMAGE_JPEG_FORMAT, extDecoder, errorCode);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("Generate jpeg auxiliary picture failed! errorCode: %{public}u", errorCode);
            return nullptr;
        }
        if (type == AuxiliaryPictureType::GAINMAP) {
            errorCode = DecodeHdrMetadata(mainInfo.hdrType, extDecoder, auxPicture);
        } else if (type == AuxiliaryPictureType::FRAGMENT_MAP) {
            errorCode = DecodeJpegFragmentMetadata(auxStream, auxPicture);
        }
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("Decode jpeg metadata failed! errorCode: %{public}u", errorCode);
            return nullptr;
        }
        return auxPicture;
    }

    int32_t denominator = GetAuxiliaryPictureDenominator(type);
    denominator = (denominator == 0) ? DEFAULT_SCALE_DENOMINATOR : denominator;
    Size size = {mainInfo.imageInfo.size.width / denominator, mainInfo.imageInfo.size.height / denominator};
    sptr<SurfaceBuffer> surfaceBuffer = AllocSurfaceBuffer(size, GRAPHIC_PIXEL_FMT_RGBA16_FLOAT, errorCode);
    if (errorCode != SUCCESS || surfaceBuffer == nullptr) {
        IMAGE_LOGE("Alloc surface buffer failed! errorCode: %{public}u", errorCode);
        return nullptr;
    }
    errorCode = CopyToSurfaceBuffer(auxStream, surfaceBuffer);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Convert stream to surface buffer failed! errorCode: %{public}u", errorCode);
        return nullptr;
    }
    auto auxPicture = AuxiliaryPicture::Create(surfaceBuffer, type, size);
    SetUncodedAuxilaryPictureInfo(auxPicture);
    return auxPicture;
}

} // namespace Media
} // namespace OHOS
