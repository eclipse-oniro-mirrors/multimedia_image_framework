/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "ext_encoder.h"
#include <algorithm>
#include <map>

#include "include/core/SkImageEncoder.h"
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "astc_codec.h"
#endif

#include "ext_pixel_convert.h"
#include "ext_wstream.h"
#include "metadata_accessor_factory.h"
#include "metadata_accessor.h"
#include "image_log.h"
#include "image_type_converter.h"
#include "image_utils.h"
#include "media_errors.h"
#include "string_ex.h"
#include "image_data_statistics.h"
#include "image_dfx.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#include "v1_0/buffer_handle_meta_key_type.h"
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "vpe_utils.h"
#include "hdr_helper.h"
#endif
#include "color_utils.h"
#include "tiff_parser.h"
#include "image_mime_type.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ExtEncoder"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
#endif

static const std::map<SkEncodedImageFormat, std::string> FORMAT_NAME = {
    {SkEncodedImageFormat::kBMP, IMAGE_BMP_FORMAT},
    {SkEncodedImageFormat::kGIF, IMAGE_GIF_FORMAT},
    {SkEncodedImageFormat::kICO, IMAGE_ICO_FORMAT},
    {SkEncodedImageFormat::kJPEG, IMAGE_JPEG_FORMAT},
    {SkEncodedImageFormat::kPNG, IMAGE_PNG_FORMAT},
    {SkEncodedImageFormat::kWBMP, IMAGE_BMP_FORMAT},
    {SkEncodedImageFormat::kWEBP, IMAGE_WEBP_FORMAT},
    {SkEncodedImageFormat::kPKM, ""},
    {SkEncodedImageFormat::kKTX, ""},
    {SkEncodedImageFormat::kASTC, ""},
    {SkEncodedImageFormat::kDNG, ""},
    {SkEncodedImageFormat::kHEIF, IMAGE_HEIF_FORMAT},
};

ExtEncoder::ExtEncoder()
{
}

ExtEncoder::~ExtEncoder()
{
}

uint32_t ExtEncoder::StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option)
{
    output_ = &outputStream;
    opts_ = option;
    return SUCCESS;
}

uint32_t ExtEncoder::AddImage(PixelMap &pixelMap)
{
    pixelmap_ = &pixelMap;
    return SUCCESS;
}

struct TmpBufferHolder {
    std::unique_ptr<uint8_t[]> buf = nullptr;
};

static SkImageInfo ToSkInfo(PixelMap *pixelMap)
{
    ImageInfo info;
    pixelMap->GetImageInfo(info);
    SkColorType colorType = ImageTypeConverter::ToSkColorType(info.pixelFormat);
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    sk_sp<SkColorSpace> colorSpace = SkColorSpace::MakeSRGB();
#ifdef IMAGE_COLORSPACE_FLAG
    if (pixelMap->InnerGetGrColorSpacePtr() != nullptr) {
        colorSpace = pixelMap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
    }
#endif
    return SkImageInfo::Make(info.size.width, info.size.height, colorType, alphaType, colorSpace);
}

static uint32_t RGBToRGBx(PixelMap *pixelMap, SkImageInfo &skInfo, TmpBufferHolder &holder)
{
    holder.buf = std::make_unique<uint8_t[]>(skInfo.computeMinByteSize());
    ExtPixels src = {
        static_cast<uint8_t*>(pixelMap->GetWritablePixels()),
        pixelMap->GetCapacity(), pixelMap->GetWidth()*pixelMap->GetHeight(),
    };
    ExtPixels dst = {
        holder.buf.get(), skInfo.computeMinByteSize(), skInfo.width()*skInfo.height(),
    };
    return ExtPixelConvert::RGBToRGBx(src, dst);
}

bool IsAstc(const std::string &format)
{
    return format.find("image/astc") == 0;
}

static uint32_t CreateAndWriteBlob(MetadataWStream &tStream, PixelMap *pixelmap, SkWStream& outStream,
    ImageInfo &imageInfo, PlEncodeOptions &opts)
{
    auto metadataAccessor =
        MetadataAccessorFactory::Create(tStream.GetAddr(), tStream.bytesWritten(), BufferMetadataStream::Dynamic);
    if (metadataAccessor != nullptr) {
        auto metadataPtr = pixelmap->GetExifMetadata();
        metadataAccessor->Set(metadataPtr);
        if (metadataAccessor->Write() == SUCCESS) {
            if (metadataAccessor->WriteToOutput(outStream)) {
                return SUCCESS;
            }
        }
    }
    if (!outStream.write(tStream.GetAddr(), tStream.bytesWritten())) {
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts.format, "Failed to encode image");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

uint32_t ExtEncoder::FinalizeEncode()
{
    if (pixelmap_ == nullptr || output_ == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageDataStatistics imageDataStatistics("[ExtEncoder]FinalizeEncode imageFormat = %s, quality = %d",
        opts_.format.c_str(), opts_.quality);
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (IsAstc(opts_.format)) {
        AstcCodec astcEncoder;
        astcEncoder.SetAstcEncode(output_, opts_, pixelmap_);
        return astcEncoder.ASTCEncode();
    }
#endif
    auto iter = std::find_if(FORMAT_NAME.begin(), FORMAT_NAME.end(),
        [this](const std::map<SkEncodedImageFormat, std::string>::value_type item) {
            return IsSameTextStr(item.second, opts_.format);
    });
    if (iter == FORMAT_NAME.end()) {
        IMAGE_LOGE("ExtEncoder::FinalizeEncode unsupported format %{public}s", opts_.format.c_str());
        ReportEncodeFault(0, 0, opts_.format, "Unsupported format:" + opts_.format);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    ImageInfo imageInfo;
    pixelmap_->GetImageInfo(imageInfo);
    imageDataStatistics.AddTitle("width = %d, height =%d", imageInfo.size.width, imageInfo.size.height);
    encodeFormat_ = iter->first;
    ExtWStream wStream(output_);
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return EncodeImageByPixelMap(pixelmap_, true, wStream);
#else
    switch (opts_.desiredDynamicRange) {
        case PlEncodeDynamicRange::AUTO:
            if (pixelmap_->IsHdr() &&
                (encodeFormat_ == SkEncodedImageFormat::kJPEG || encodeFormat_ == SkEncodedImageFormat::kHEIF)) {
                return EncodeDualVivid(wStream);
            }
            return EncodeSdrImage(wStream);
        case PlEncodeDynamicRange::SDR:
            return EncodeSdrImage(wStream);
        case PlEncodeDynamicRange::HDR_VIVID_DUAL:
            return EncodeDualVivid(wStream);
        case PlEncodeDynamicRange::HDR_VIVID_SINGLE:
            return EncodeSingleVivid(wStream);
    }
    return ERR_IMAGE_ENCODE_FAILED;
#endif
}

uint32_t ExtEncoder::EncodeImageByBitmap(SkBitmap& bitmap, bool needExif, SkWStream& outStream)
{
    ImageInfo imageInfo;
    pixelmap_->GetImageInfo(imageInfo);
    if (!needExif || pixelmap_->GetExifMetadata() == nullptr ||
        pixelmap_->GetExifMetadata()->GetExifData() == nullptr) {
        if (!SkEncodeImage(&outStream, bitmap, encodeFormat_, opts_.quality)) {
            IMAGE_LOGE("Failed to encode image");
            ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to encode image");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        return SUCCESS;
    }

    MetadataWStream tStream;
    if (!SkEncodeImage(&tStream, bitmap, encodeFormat_, opts_.quality)) {
        IMAGE_LOGE("Failed to encode image");
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to encode image");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return CreateAndWriteBlob(tStream, pixelmap_, outStream, imageInfo, opts_);
}

uint32_t ExtEncoder::EncodeImageByPixelMap(PixelMap* pixelMap, bool needExif, SkWStream& outputStream)
{
    SkBitmap bitmap;
    TmpBufferHolder holder;
    SkImageInfo skInfo = ToSkInfo(pixelMap);
    auto pixels = pixelMap->GetWritablePixels();
    if (encodeFormat_ == SkEncodedImageFormat::kJPEG &&
        skInfo.colorType() == SkColorType::kRGB_888x_SkColorType &&
        pixelMap->GetCapacity() < skInfo.computeMinByteSize()) {
        uint32_t res = RGBToRGBx(pixelMap, skInfo, holder);
        if (res != SUCCESS) {
            IMAGE_LOGE("ExtEncoder::EncodeImageByPixelMap pixel convert failed %{public}d", res);
            return res;
        }
        pixels = holder.buf.get();
        skInfo = skInfo.makeColorType(SkColorType::kRGBA_8888_SkColorType);
    }
    uint64_t rowStride = skInfo.minRowBytes64();

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (pixelMap->GetFd());
        rowStride = sbBuffer->GetStride();
    }
#endif
    if (!bitmap.installPixels(skInfo, pixels, rowStride)) {
        IMAGE_LOGE("ExtEncoder::EncodeImageByPixelMap to SkBitmap failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return EncodeImageByBitmap(bitmap, needExif, outputStream);
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static sptr<SurfaceBuffer> AllocSurfaceBuffer(SkImageInfo info, CM_HDR_Metadata_Type type, CM_ColorSpaceType color)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem alloc");
    return nullptr;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = info.width(),
        .height = info.height(),
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        return nullptr;
    }
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        return nullptr;
    }
    VpeUtils::SetSbMetadataType(sb, type);
    VpeUtils::SetSbColorSpaceType(sb, color);
    return sb;
#endif
}

static void FreeBaseAndGainMapSurfaceBuffer(sptr<SurfaceBuffer>& base, sptr<SurfaceBuffer>& gainMap)
{
    ImageUtils::SurfaceBuffer_Unreference(base.GetRefPtr());
    ImageUtils::SurfaceBuffer_Unreference(gainMap.GetRefPtr());
}

static HdrMetadata GetHdrMetadata(sptr<SurfaceBuffer>& hdr, sptr<SurfaceBuffer>& gainmap)
{
    std::vector<uint8_t> dynamicMetadata = {};
    VpeUtils::GetSbDynamicMetadata(hdr, dynamicMetadata);
    std::vector<uint8_t> staticMetadata = {};
    VpeUtils::GetSbStaticMetadata(hdr, staticMetadata);
    HdrMetadata metadata = {
        .staticMetadata = staticMetadata,
        .dynamicMetadata = dynamicMetadata
    };
    std::vector<uint8_t> extendMetadataVec = {};
    VpeUtils::GetSbDynamicMetadata(gainmap, extendMetadataVec);
    if (extendMetadataVec.size() != sizeof(HDRVividExtendMetadata)) {
        metadata.extendMetaFlag = false;
        return metadata;
    }
    if (memcpy_s(&metadata.extendMeta, sizeof(HDRVividExtendMetadata),
        extendMetadataVec.data(), extendMetadataVec.size()) != EOK) {
        metadata.extendMetaFlag = false;
    } else {
        metadata.extendMetaFlag = true;
    }
    return metadata;
}

uint32_t ExtEncoder::EncodeImageBySurfaceBuffer(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info,
    bool needExif, SkWStream& outputStream)
{
    SkBitmap bitmap;
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGE("EncodeImageBySurfaceBuffer failed, surfaceBuffer is nullptr");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto pixels = surfaceBuffer->GetVirAddr();
    if (pixels == nullptr) {
        IMAGE_LOGE("EncodeImageBySurfaceBuffer failed, pixels is nullptr");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint64_t rowStride = surfaceBuffer->GetStride();
    if (!bitmap.installPixels(info, pixels, rowStride)) {
        IMAGE_LOGE("ExtEncoder::EncodeImageBySurfaceBuffer to SkBitmap failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return EncodeImageByBitmap(bitmap, needExif, outputStream);
}

sk_sp<SkData> ExtEncoder::GetImageEncodeData(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info, bool needExif)
{
    SkDynamicMemoryWStream stream;
    if (EncodeImageBySurfaceBuffer(surfaceBuffer, info, needExif, stream) != SUCCESS) {
        return nullptr;
    }
    return stream.detachAsData();
}

static uint32_t DecomposeImage(PixelMap* pixelMap, sptr<SurfaceBuffer>& base, sptr<SurfaceBuffer>& gainmap,
    ImagePlugin::HdrMetadata& metadata)
{
    if (pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (pixelMap->GetFd()));
    VpeUtils::SetSbMetadataType(hdrSurfaceBuffer, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbDynamicMetadata(hdrSurfaceBuffer, std::vector<uint8_t>(0));
    VpeUtils::SetSbStaticMetadata(hdrSurfaceBuffer, std::vector<uint8_t>(0));
    VpeSurfaceBuffers buffers = {
        .sdr = base,
        .gainmap = gainmap,
        .hdr = hdrSurfaceBuffer,
    };
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res = utils->ColorSpaceConverterDecomposeImage(buffers);
    if (res != VPE_ERROR_OK || base == nullptr || gainmap == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    metadata = GetHdrMetadata(hdrSurfaceBuffer, gainmap);
    return SUCCESS;
}

static SkImageInfo GetSkInfo(PixelMap* pixelMap, bool isGainmap)
{
    ImageInfo info;
    pixelMap->GetImageInfo(info);
    SkColorType colorType = kRGBA_8888_SkColorType;
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    sk_sp<SkColorSpace> colorSpace = nullptr;
    int32_t width = info.size.width;
    int32_t height = info.size.height;
    if (isGainmap) {
        colorSpace = SkColorSpace::MakeSRGB();
        const int halfSizeDenominator = 2;
        width = width / halfSizeDenominator;
        height = height / halfSizeDenominator;
#ifdef IMAGE_COLORSPACE_FLAG
        if (pixelMap->InnerGetGrColorSpacePtr() != nullptr) {
            colorSpace = pixelMap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
        }
        skcms_CICP cicp;
        ColorUtils::ColorSpaceGetCicp(pixelMap->InnerGetGrColorSpace().GetColorSpaceName(),
            cicp.colour_primaries, cicp.transfer_characteristics, cicp.matrix_coefficients, cicp.full_range_flag);
        colorSpace->SetIccCicp(cicp);
#endif
    } else {
        colorSpace = SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kSRGB);
    }
    return SkImageInfo::Make(width, height, colorType, alphaType, colorSpace);
}

uint32_t ExtEncoder::EncodeSingleVivid(ExtWStream& outputStream)
{
    return ERR_IMAGE_INVALID_PARAMETER;
}

uint32_t ExtEncoder::EncodeDualVivid(ExtWStream& outputStream)
{
    if (pixelmap_->GetPixelFormat() != PixelFormat::RGBA_1010102 ||
        (encodeFormat_ != SkEncodedImageFormat::kJPEG && encodeFormat_ != SkEncodedImageFormat::kHEIF)) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    SkImageInfo baseInfo = GetSkInfo(pixelmap_, false);
    SkImageInfo gainmapInfo = GetSkInfo(pixelmap_, true);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo, CM_IMAGE_HDR_VIVID_DUAL, CM_SRGB_FULL);
    sptr<SurfaceBuffer> gainMapSptr = AllocSurfaceBuffer(gainmapInfo, CM_METADATA_NONE, CM_SRGB_FULL);
    if (baseSptr == nullptr || gainMapSptr == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    HdrMetadata metadata;
    uint32_t error = DecomposeImage(pixelmap_, baseSptr, gainMapSptr, metadata);
    if (error != SUCCESS) {
        FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
        return error;
    }
    sk_sp<SkData> baseImageData = GetImageEncodeData(baseSptr, baseInfo, true);
    sk_sp<SkData> gainMapImageData = GetImageEncodeData(gainMapSptr, gainmapInfo, false);
    FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
    if (encodeFormat_ == SkEncodedImageFormat::kJPEG) {
        error = HdrJpegPackerHelper::SpliceHdrStream(baseImageData, gainMapImageData, outputStream, metadata);
    } else {
        error = ERR_IMAGE_INVALID_PARAMETER;
    }
    return error;
}

uint32_t ExtEncoder::EncodeSdrImage(ExtWStream& outputStream)
{
    if (pixelmap_->GetPixelFormat() != PixelFormat::RGBA_1010102) {
        return EncodeImageByPixelMap(pixelmap_, true, outputStream);
    }
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
    SkImageInfo baseInfo = GetSkInfo(pixelmap_, false);
    SkImageInfo gainmapInfo = GetSkInfo(pixelmap_, true);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo, CM_IMAGE_HDR_VIVID_DUAL, CM_SRGB_FULL);
    sptr<SurfaceBuffer> gainMapSptr = AllocSurfaceBuffer(gainmapInfo, CM_METADATA_NONE, CM_SRGB_FULL);
    if (baseSptr == nullptr || gainMapSptr == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    HdrMetadata metadata;
    uint32_t error = DecomposeImage(pixelmap_, baseSptr, gainMapSptr, metadata);
    if (error != SUCCESS) {
        FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
        return error;
    }
    error = EncodeImageBySurfaceBuffer(baseSptr, baseInfo, true, outputStream);
    FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
    return error;
}
#endif
} // namespace ImagePlugin
} // namespace OHOS
