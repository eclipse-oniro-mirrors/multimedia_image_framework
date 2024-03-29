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

#include "buffer_metadata_stream.h"
#include "SkBitmap.h"
#include "SkImageEncoder.h"
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "astc_codec.h"
#endif

#include "data_buf.h"
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
#endif
#include "tiff_parser.h"
#ifdef IMAGE_HDR_CONVERTER_FLAG
#include "colorspace_converter.h"
#endif
#include "hdr_helper.h"
#include "vpe_utils.h"
#include "image_mime_type.h"
#include "v1_0/buffer_handle_meta_key_type.h"
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ExtEncoder"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
using namespace HDI::Display::Graphic::Common::V1_0;
#ifdef IMAGE_HDR_CONVERTER_FLAG
using namespace VideoProcessingEngine;
#endif

constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_SOI = 0xD8;
constexpr uint8_t JPEG_SOI_SIZE = 2;

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
    {SkEncodedImageFormat::kHEIF, IMAGE_HEIC_FORMAT},
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

uint32_t ExtEncoder::AddImage(Media::PixelMap &pixelMap)
{
    pixelmap_ = &pixelMap;
    return SUCCESS;
}

struct TmpBufferHolder {
    std::unique_ptr<uint8_t[]> buf = nullptr;
};

static SkImageInfo ToSkInfo(Media::PixelMap *pixelMap)
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

static uint32_t RGBToRGBx(Media::PixelMap *pixelMap, SkImageInfo &skInfo, TmpBufferHolder &holder)
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

static uint32_t BuildSkBitmap(Media::PixelMap *pixelMap, SkBitmap &bitmap,
    SkEncodedImageFormat format, TmpBufferHolder &holder)
{
    uint32_t res = SUCCESS;
    SkImageInfo skInfo = ToSkInfo(pixelMap);
    auto pixels = pixelMap->GetWritablePixels();
    if (format == SkEncodedImageFormat::kJPEG &&
        skInfo.colorType() == SkColorType::kRGB_888x_SkColorType &&
        pixelMap->GetCapacity() < skInfo.computeMinByteSize()) {
        res = RGBToRGBx(pixelMap, skInfo, holder);
        if (res != SUCCESS) {
            IMAGE_LOGE("ExtEncoder::BuildSkBitmap pixel convert failed %{public}d", res);
            return res;
        }
        pixels = holder.buf.get();
        skInfo = skInfo.makeColorType(SkColorType::kRGBA_8888_SkColorType);
    }

    uint64_t rowStride = skInfo.minRowBytes64();

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (pixelMap->GetAllocatorType() == Media::AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (pixelMap->GetFd());
        rowStride = sbBuffer->GetStride();
    }
#endif

    if (!bitmap.installPixels(skInfo, pixels, rowStride)) {
        IMAGE_LOGE("ExtEncoder::BuildSkBitmap to skbitmap failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return res;
}

static uint32_t BuildSkBitmap(sptr<SurfaceBuffer>& buffer, SkImageInfo info,
    SkBitmap bitmap, SkEncodedImageFormat format)
{
    uint8_t* pixels = static_cast<uint8_t*>(buffer->GetVirAddr());
    if (pixels == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint64_t rowStride = buffer->GetStride();
    if (!bitmap.installPixels(info, pixels, rowStride)) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return SUCCESS;
}

bool IsAstc(const std::string &format)
{
    return format.find("image/astc") == 0;
}

static uint32_t CreateAndWriteBlob(MetadataWStream &tStream, DataBuf &exifBlob, OutputDataStream* output,
    ImageInfo &imageInfo, PlEncodeOptions &opts)
{
    if (output == nullptr) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    auto metadataAccessor =
        MetadataAccessorFactory::Create(tStream.GetAddr(), tStream.bytesWritten(), BufferMetadataStream::Dynamic);
    if (metadataAccessor != nullptr) {
        if (metadataAccessor->WriteBlob(exifBlob) == SUCCESS) {
            if (metadataAccessor->WriteToOutput(*output)) {
                return SUCCESS;
            }
        }
    }
    if (!output->Write(tStream.GetAddr(), tStream.bytesWritten())) {
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts.format, "Failed to encode image");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

uint32_t ExtEncoder::DoFinalizeEncode()
{
    ImageDataStatistics imageDataStatistics("[ExtEncoder]FinalizeEncode imageFormat = %s, quality = %d",
        opts_.format.c_str(), opts_.quality);
    auto iter = std::find_if(FORMAT_NAME.begin(), FORMAT_NAME.end(),
        [this](const std::map<SkEncodedImageFormat, std::string>::value_type item) {
            return IsSameTextStr(item.second, opts_.format);
        });
    if (iter == FORMAT_NAME.end()) {
        IMAGE_LOGE("Unsupported format: %{public}s", opts_.format.c_str());
        ReportEncodeFault(0, 0, opts_.format, "Unsupported format:" + opts_.format);
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    SkBitmap bitmap;
    TmpBufferHolder holder;
    ImageInfo imageInfo;
    pixelmap_->GetImageInfo(imageInfo);
    imageDataStatistics.AddTitle("width = %d, height =%d", imageInfo.size.width, imageInfo.size.height);
    auto errorCode = BuildSkBitmap(pixelmap_, bitmap, iter->first, holder);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Failed to build SkBitmap");
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to build SkBitmap");
        return errorCode;
    }

    if (pixelmap_->GetExifMetadata() == nullptr ||
        pixelmap_->GetExifMetadata()->GetExifData() == nullptr) {
        ExtWStream wStream(output_);
        if (!SkEncodeImage(&wStream, bitmap, iter->first, opts_.quality)) {
            IMAGE_LOGE("Failed to encode image");
            ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to encode image");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        return SUCCESS;
    }

    unsigned char *dataPtr;
    uint32_t datSize = 0;
    auto exifData = pixelmap_->GetExifMetadata()->GetExifData();
    TiffParser::Encode(&dataPtr, datSize, exifData);
    DataBuf exifBlob(dataPtr, datSize);
    MetadataWStream tStream;
    if (!SkEncodeImage(&tStream, bitmap, iter->first, opts_.quality)) {
        IMAGE_LOGE("Failed to encode image");
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to encode image");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    return CreateAndWriteBlob(tStream, exifBlob, output_, imageInfo, opts_);
}

uint32_t ExtEncoder::FinalizeEncode()
{
    if (pixelmap_ == nullptr || output_ == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (IsAstc(opts_.format)) {
        ImageDataStatistics imageDataStatistics("[ExtEncoder]FinalizeEncode imageFormat = %s, quality = %d",
            opts_.format.c_str(), opts_.quality);
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
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto encodeFormat = iter->first;
    ExtWStream wStream(output_);
#ifdef IMAGE_HDR_CONVERTER_FLAG
    switch (opts_.desiredDynamicRange) {
        case PlEncodeDynamicRange::DEFAULT:
            if (pixelmap_->IsHdr() &&
                (encodeFormat == SkEncodedImageFormat::kJPEG || encodeFormat == SkEncodedImageFormat::kHEIF)) {
                return EncodeDualVivid(encodeFormat, wStream);
            }
            return EncodeSdrImage(encodeFormat, wStream);
        case PlEncodeDynamicRange::SDR:
            return EncodeSdrImage(encodeFormat, wStream);
        case PlEncodeDynamicRange::HDR_VIVID_DUAL:
            return EncodeDualVivid(encodeFormat, wStream);
        case PlEncodeDynamicRange::HDR_VIVID_SINGLE:
            return EncodeSingleVivid(encodeFormat, wStream);
    }
    return ERR_IMAGE_ENCODE_FAILED;
#else
    return EncodeBaseImageByPixelMap(encodeFormat, wStream);
#endif
}

static uint32_t EncodeImage(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info, SkEncodedImageFormat format,
    int quality, SkWStream& stream)
{
    SkBitmap bitmap;
    uint32_t errorCode = BuildSkBitmap(surfaceBuffer, info, bitmap, format);
    if (errorCode != SUCCESS) {
        return errorCode;
    }
    if (!SkEncodeImage(&stream, bitmap, format, quality)) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

static sk_sp<SkData> GetImageEncodeData(sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo info,
    SkEncodedImageFormat format, int quality)
{
    SkDynamicMemoryWStream stream;
    if (EncodeImage(surfaceBuffer, info, format, quality, stream) != SUCCESS) {
        return nullptr;
    }
    return stream.detachAsData();
}

static sptr<SurfaceBuffer> AllocSurfaceBuffer(SkImageInfo info, CM_HDR_Metadata_Type type, CM_ColorSpaceType color)
{
#if defined(_WIN32) || defined(_APPLE) || defined(A_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = info.width(),
        .height = info.height(),
        .strideAlignment = 0x8,
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_DISPLAY_P3,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
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

#ifdef IMAGE_HDR_CONVERTER_FLAG
static HdrMetadata GetHdrMetadata(sptr<SurfaceBuffer>& sb)
{
    std::vector<uint8_t> dynamicMetadata = {};
    VpeUtils::GetSbDynamicMetadata(sb, dynamicMetadata);
    std::vector<uint8_t> staticMetadata = {};
    VpeUtils::GetSbStaticMetadata(sb, staticMetadata);
    HdrMetadata metadata = {
        .staticMetadata = staticMetadata,
        .dynamicMetadata = dynamicMetadata
    };
    return metadata;
}
#endif

static uint32_t DecomposeImage(Media::PixelMap* pixelMap, sptr<SurfaceBuffer>& base, sptr<SurfaceBuffer>& gainMap,
    ImagePlugin::HdrMetadata& metadata)
{
    if (pixelMap->GetAllocatorType() != Media::AllocatorType::DMA_ALLOC) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (pixelMap->GetFd()));
    VpeUtils::SetSbMetadataType(hdrSurfaceBuffer, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbColorSpaceType(hdrSurfaceBuffer, CM_BT2020_HLG_LIMIT);
    VpeUtils::SetSbDynamicMetadata(hdrSurfaceBuffer, std::vector<uint8_t>());
    VpeUtils::SetSbStaticMetadata(hdrSurfaceBuffer, std::vector<uint8_t>());
#ifdef IMAGE_HDR_CONVERTER_FLAG
    auto convert = VpeUtils::GetColorSpaceConverter();
    int error = convert->DecomposeImage(hdrSurfaceBuffer, base, gainMap);
    if (error != VPE_ALGO_ERR_OK || base == nullptr || gainMap == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    metadata = GetHdrMetadata(hdrSurfaceBuffer);
    return SUCCESS:
#else
    return IMAGE_RESULT_CREATE_SURFAC_FAILED;
#endif
}

uint32_t ExtEncoder::EncodeSingleVivid(SkEncodedImageFormat format, ExtWStream& outputStream)
{
    if (pixelmap_->GetPixelFormat() != Media::PixelFormat::RGBA_1010102 || format != SkEncodedImageFormat::kHEIF) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return EncodeBaseImageByPixelMap(format, outputStream);
}

static uint32_t SpliceJpegMultiPictureStream(sk_sp<SkData> baseImage, sk_sp<SkData> gainMapImage,
    SkWStream& outputStream, HdrMetadata metadata)
{
    if (baseImage == nullptr || gainMapImage == nullptr) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    const uint8_t* baseBytes = reinterpret_cast<const uint8_t*>(baseImage->data());
    if (*baseBytes != JPEG_MARKER_PREFIX || *(baseBytes + 1) != JPEG_SOI) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    const uint8_t* gainMapBytes = reinterpret_cast<const uint8_t*>(gainMapImage->data());
    if (*baseBytes != JPEG_MARKER_PREFIX || *(baseBytes + 1) != JPEG_SOI) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    std::vector<uint8_t> metadataPack = HdrHelper::PackJpegVividMetadata(metadata);
    uint32_t gainMapSize = gainMapImage->size() + metadataPack.size();
    std::vector<uint8_t> baseInfo = HdrHelper::PackJpegVividBaseInfo(baseImage->size(), gainMapSize);
    // write base image stream
    outputStream.write(baseBytes, JPEG_SOI_SIZE);
    outputStream.write(baseInfo.data(), baseInfo.size());
    outputStream.write(baseBytes + JPEG_SOI_SIZE, baseImage->size() - JPEG_SOI_SIZE);
    // write gainmap stream
    outputStream.write(gainMapBytes, JPEG_SOI_SIZE);
    outputStream.write(metadataPack.data(), metadataPack.size());
    outputStream.write(gainMapBytes + JPEG_SOI_SIZE, gainMapImage->size() - JPEG_SOI_SIZE);
    outputStream.bytesWritten();
    return SUCCESS;
}

uint32_t ExtEncoder::EncodeDualVivid(SkEncodedImageFormat format, ExtWStream& outputStream)
{
    if (pixelmap_->GetPixelFormat() != Media::PixelFormat::RGBA_1010102 ||
        (format != SkEncodedImageFormat::kJPEG && format != SkEncodedImageFormat::kHEIF)) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
    SkColorType colorType = kRGBA_8888_SkColorType;
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    sk_sp<SkColorSpace> p3 = SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kDisplayP3);
    SkImageInfo baseInfo = SkImageInfo::Make(info.size.width, info.size.height, colorType, alphaType, p3);
    SkImageInfo gainMapInfo = SkImageInfo::Make(info.size.width/2, info.size.height/2, colorType, alphaType, p3);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo, CM_METADATA_NONE, CM_P3_LIMIT);
    sptr<SurfaceBuffer> gainMapSptr = AllocSurfaceBuffer(gainMapInfo, CM_METADATA_NONE, CM_P3_LIMIT);
    if (baseSptr == nullptr || gainMapSptr == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    HdrMetadata metadata;
    uint32_t error = DecomposeImage(pixelmap_, baseSptr, gainMapSptr, metadata);
    if (error != SUCCESS) {
        FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
        return error;
    }
    sk_sp<SkData> baseImageData = GetImageEncodeData(baseSptr, baseInfo, format, opts_.quality);
    sk_sp<SkData> gainMapImageData = GetImageEncodeData(gainMapSptr, gainMapInfo, format, opts_.quality);
    FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
    if (format == SkEncodedImageFormat::kJPEG) {
        error = SpliceJpegMultiPictureStream(baseImageData, gainMapImageData, outputStream, metadata);
    } else {
        error = ERR_IMAGE_INVALID_PARAMETER;
    }
    return error;
}

uint32_t ExtEncoder::EncodeSdrImage(SkEncodedImageFormat format, ExtWStream& outputStream)
{
    if (pixelmap_->GetPixelFormat() != Media::PixelFormat::RGBA_1010102) {
        return EncodeBaseImageByPixelMap(format, outputStream);
    }
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
    SkColorType colorType = kRGBA_8888_SkColorType;
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    sk_sp<SkColorSpace> p3 = SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, SkNamedGamut::kDisplayP3);
    SkImageInfo baseInfo = SkImageInfo::Make(info.size.width, info.size.height, colorType, alphaType, p3);
    SkImageInfo gainMapInfo = SkImageInfo::Make(info.size.width/2, info.size.height/2, colorType, alphaType, p3);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo, CM_METADATA_NONE, CM_P3_LIMIT);
    sptr<SurfaceBuffer> gainMapSptr = AllocSurfaceBuffer(gainMapInfo, CM_METADATA_NONE, CM_P3_LIMIT);
    if (baseSptr == nullptr || gainMapSptr == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    HdrMetadata metadata;
    uint32_t error = DecomposeImage(pixelmap_, baseSptr, gainMapSptr, metadata);
    if (error != SUCCESS) {
        FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
        return error;
    }
    error = EncodeImage(baseSptr, baseInfo, format, opts_.quality, outputStream);
    FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
    return error;
}

uint32_t ExtEncoder::EncodeBaseImageByPixelMap(SkEncodedImageFormat format, ExtWStream& outputStream)
{
    SkBitmap bitmap;
    TmpBufferHolder holder;
    auto errorCode = BuildSkBitmap(pixelmap_, bitmap, format, holder);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("ExtEncoder::EncodeBaseImageByPixelMap BuildSkBitmap failed");
        return errorCode;
    }
    if (!SkEncodeImage(&outputStream, bitmap, format, opts_.quality)) {
        IMAGE_LOGE("ExtEncoder::EncodeBaseImageByPixelMap encode failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

} // namespace ImagePlugin
} // namespace OHOS
