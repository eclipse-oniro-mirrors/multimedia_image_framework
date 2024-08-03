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
#include "hdr_type.h"
#include "image_log.h"
#include "image_utils.h"
#include "image_mime_type.h"
#include "image_source.h"
#include "metadata.h"
#include "pixel_map.h"
#include "pixel_yuv.h"
#ifdef EXT_PIXEL
#include "pixel_yuv_ext.h"
#endif
#include "securec.h"
#include "surface_buffer.h"

namespace OHOS {
namespace Media {
using namespace ImagePlugin;

static const uint32_t FIRST_FRAME = 0;

static inline bool IsSizeVailed(const Size &size)
{
    return (size.width != 0 && size.height != 0);
}

static uint32_t SetAuxiliaryDecodeOption(std::unique_ptr<AbsImageDecoder> &decoder, PlImageInfo &plInfo)
{
    Size size;
    uint32_t errorCode = decoder->GetImageSize(FIRST_FRAME, size);
    if (errorCode != SUCCESS || !IsSizeVailed(size)) {
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    PixelDecodeOptions plOptions;
    plOptions.desiredSize = size;
    plOptions.desiredPixelFormat = PixelFormat::RGBA_8888;
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

static ImageInfo MakeImageInfo(int width, int height, PixelFormat format, AlphaType alphaType, ColorSpace colorSpace)
{
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = format;
    info.alphaType = alphaType;
    info.colorSpace = colorSpace;
    return info;
}

static AuxiliaryPictureInfo MakeAuxiliaryPictureInfo(AuxiliaryPictureType type,
    const Size &size, int32_t rowStride, PixelFormat format, ColorSpace colorSpace)
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

static std::shared_ptr<PixelMap> CreatePixelMapByContext(DecodeContext &context,
    std::unique_ptr<AbsImageDecoder> &decoder, uint32_t &errorCode)
{
    std::shared_ptr<PixelMap> pixelMap;
    if (ImageSource::IsYuvFormat(context.pixelFormat)) {
#ifdef EXT_PIXEL
        pixelMap = std::make_shared<PixelYuvExt>();
#else
        pixelMap = std::make_shared<PixelYuv>();
#endif
    } else {
        pixelMap = std::make_shared<PixelMap>();
    }
    if (pixelMap == nullptr) {
        errorCode = ERR_IMAGE_ADD_PIXEL_MAP_FAILED;
        return nullptr;
    }

    ImageInfo imageinfo = MakeImageInfo(context.outInfo.size.width, context.outInfo.size.height,
                                        context.pixelFormat, context.outInfo.alphaType, context.colorSpace);
    pixelMap->SetImageInfo(imageinfo, true);

    PixelMapAddrInfos addrInfos;
    ImageSource::ContextToAddrInfos(context, addrInfos);
    pixelMap->SetPixelsAddr(addrInfos.addr, addrInfos.context, addrInfos.size, addrInfos.type, addrInfos.func);

#ifdef IMAGE_COLORSPACE_FLAG
    if (context.hdrType > ImageHdrType::SDR) {
        pixelMap->InnerSetColorSpace(ColorManager::ColorSpace(context.grColorSpaceName));
    } else if (decoder->IsSupportICCProfile()) {
        pixelMap->InnerSetColorSpace(decoder->getGrColorSpace());
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

static uint32_t DecodeMetadata(ImageHdrType hdrType, std::unique_ptr<AbsImageDecoder> &extDecoder,
    AuxiliaryPictureType type, std::unique_ptr<AuxiliaryPicture> &auxPicture)
{
    IMAGE_LOGD("Decode metadata entry, auxiliary picture type: %{public}d", type);
    uint32_t errorCode = ERROR;
    switch (type) {
        case AuxiliaryPictureType::GAINMAP:
            errorCode = DecodeHdrMetadata(hdrType, extDecoder, auxPicture);
            break;
        case AuxiliaryPictureType::DEPTH_MAP:
        case AuxiliaryPictureType::UNREFOCUS_MAP:
        case AuxiliaryPictureType::LINEAR_MAP:
        case AuxiliaryPictureType::FRAGMENT_MAP:
            break;
        default:
            errorCode = ERR_MEDIA_DATA_UNSUPPORT;
            break;
    }
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Decode hdr metadata failed! errorCode: %{public}u", errorCode);
    }
    return errorCode;
}

std::shared_ptr<AuxiliaryPicture> AuxiliaryGenerator::GenerateAuxiliaryPicture(
    ImageHdrType hdrType, AuxiliaryPictureType type, const std::string &format,
    std::unique_ptr<AbsImageDecoder> &extDecoder, uint32_t &errorCode)
{
    IMAGE_LOGI("AuxiliaryPictureType: %{public}d, format: %{public}s", static_cast<int>(type), format.c_str());
    if (!ImageUtils::IsAuxiliaryPictureTypeSupported(type) || extDecoder == nullptr) {
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }

    DecodeContext context;
    context.allocatorType = AllocatorType::DMA_ALLOC;
    errorCode = SetAuxiliaryDecodeOption(extDecoder, context.info);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Set auxiliary decode option failed! errorCode: %{public}d", errorCode);
        return nullptr;
    }
    if (format == IMAGE_HEIF_FORMAT) {
#ifdef HEIF_HW_DECODE_ENABLE
        if (!extDecoder->DecodeHeifAuxiliaryMap(context, type)) {
            errorCode = ERR_IMAGE_DECODE_FAILED;
        }
#else
        errorCode = ERR_IMAGE_HW_DECODE_UNSUPPORT;
#endif
    } else if (format == IMAGE_JPEG_FORMAT) {
        errorCode = extDecoder->Decode(FIRST_FRAME, context);
        if (errorCode != SUCCESS) {
            FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        }
        context.hdrType = hdrType;
    } else {
        errorCode = ERR_MEDIA_DATA_UNSUPPORT;
    }
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Decode failed! Format: %{public}s, errorCode: %{public}d", format.c_str(), errorCode);
        return nullptr;
    }

    std::shared_ptr<PixelMap> pixelMap = CreatePixelMapByContext(context, extDecoder, errorCode);
    auto auxPicture = AuxiliaryPicture::Create(pixelMap, type, context.outInfo.size);
    auxPicture->SetAuxiliaryPictureInfo(
        MakeAuxiliaryPictureInfo(type, context.outInfo.size, pixelMap->GetRowStride(),
                                 context.pixelFormat, context.outInfo.colorSpace));
    errorCode = DecodeMetadata(hdrType, extDecoder, type, auxPicture);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Decode metadata failed! errorCode: %{public}d", errorCode);
        return nullptr;
    }
    return std::move(auxPicture);
}

} // namespace Media
} // namespace OHOS
