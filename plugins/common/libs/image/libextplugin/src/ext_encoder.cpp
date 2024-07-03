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
#include "include/core/SkBitmap.h"
#include "pixel_yuv_utils.h"
#ifdef IMAGE_COLORSPACE_FLAG
#include "color_space.h"
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "astc_codec.h"
#endif

#include "ext_pixel_convert.h"
#include "ext_wstream.h"
#include "image_data_statistics.h"
#include "image_dfx.h"
#include "image_func_timer.h"
#include "image_fwk_ext_manager.h"
#include "image_log.h"
#include "image_system_properties.h"
#include "image_type_converter.h"
#include "image_utils.h"
#include "media_errors.h"
#include "metadata_accessor.h"
#include "metadata_accessor_factory.h"
#include "pixel_convert_adapter.h"
#include "string_ex.h"
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

static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;

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

struct ImageData {
    uint8_t *dst;
    uint8_t *pixels;
    ImageInfo info;
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

static bool IsYuvImage(PixelFormat format)
{
    return format == PixelFormat::NV21 || format == PixelFormat::NV12;
}

static uint32_t pixelToSkInfo(ImageData &image, SkImageInfo &skInfo, Media::PixelMap *pixelMap,
    TmpBufferHolder &holder, SkEncodedImageFormat format)
{
    uint32_t res = SUCCESS;
    uint32_t width  = image.info.size.width;
    uint32_t height = image.info.size.height;
    uint8_t *srcData = static_cast<uint8_t*>(pixelMap->GetWritablePixels());

    if (IsYuvImage(image.info.pixelFormat)) {
        YUVDataInfo yuvInfo;
        pixelMap->GetImageYUVInfo(yuvInfo);
        YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(image.info.pixelFormat),
            width, height, image.info.pixelFormat, yuvInfo};
        YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(PixelFormat::RGB_888), width, height};
        if (!PixelConvertAdapter::YUV420ToRGB888(srcData, srcInfo, image.dst, dstInfo)) {
            IMAGE_LOGE("ExtEncoder::BuildSkBitmap Support YUV format RGB convert failed ");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        holder.buf = std::make_unique<uint8_t[]>(width * height * NUM_4);
        SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN);
        skInfo = SkImageInfo::Make(width, height, SkColorType::kRGBA_8888_SkColorType, alphaType, nullptr);
        ExtPixels src = {
            image.dst, width * height, width * height * NUM_3,
        };
        ExtPixels dst = {
            holder.buf.get(), width * height, width * height * NUM_4,
        };
        res = ExtPixelConvert::RGBToRGBx(src, dst);
        if (res != SUCCESS) {
            IMAGE_LOGE("ExtEncoder::BuildSkBitmap Support YUV format RGB convert failed %{public}d", res);
            return res;
        }
        image.pixels = holder.buf.get();
    } else {
        skInfo = ToSkInfo(pixelMap);
        image.pixels = static_cast<uint8_t*>(pixelMap->GetWritablePixels());
        if (format == SkEncodedImageFormat::kJPEG &&
            skInfo.colorType() == SkColorType::kRGB_888x_SkColorType &&
            pixelMap->GetCapacity() < skInfo.computeMinByteSize()) {
            res = RGBToRGBx(pixelMap, skInfo, holder);
            if (res != SUCCESS) {
                IMAGE_LOGE("ExtEncoder::BuildSkBitmap RGB convert failed %{public}d", res);
                return res;
            }
            image.pixels = holder.buf.get();
            skInfo = skInfo.makeColorType(SkColorType::kRGBA_8888_SkColorType);
        }
    }
    return SUCCESS;
}

bool IsAstc(const std::string &format)
{
    return format.find("image/astc") == 0;
}

static uint32_t CreateAndWriteBlob(MetadataWStream &tStream, PixelMap *pixelmap, SkWStream& outStream,
    ImageInfo &imageInfo, PlEncodeOptions &opts)
{
    ImageFuncTimer imageFuncTimer("insert exit data (%d, %d)", imageInfo.size.width, imageInfo.size.height);
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
    imageDataStatistics.AddTitle(", width = %d, height =%d", imageInfo.size.width, imageInfo.size.height);
    encodeFormat_ = iter->first;
    ExtWStream wStream(output_);
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return EncodeImageByPixelMap(pixelmap_, opts_.needsPackProperties, wStream);
#else
    switch (opts_.desiredDynamicRange) {
        case EncodeDynamicRange::AUTO:
            if (pixelmap_->IsHdr() &&
                (encodeFormat_ == SkEncodedImageFormat::kJPEG || encodeFormat_ == SkEncodedImageFormat::kHEIF)) {
                return EncodeDualVivid(wStream);
            }
            return EncodeSdrImage(wStream);
        case EncodeDynamicRange::SDR:
            return EncodeSdrImage(wStream);
        case EncodeDynamicRange::HDR_VIVID_DUAL:
            return EncodeDualVivid(wStream);
        case EncodeDynamicRange::HDR_VIVID_SINGLE:
            return EncodeSingleVivid(wStream);
    }
    return ERR_IMAGE_ENCODE_FAILED;
#endif
}

bool ExtEncoder::IsHardwareEncodeSupported(const PlEncodeOptions &opts, Media::PixelMap* pixelMap)
{
    if (pixelMap == nullptr) {
        IMAGE_LOGE("pixelMap is nullptr");
        return false;
    }
    static const int32_t maxImageSize = 8196;
    static const int32_t minImageSize = 128;
    bool isSupport = ImageSystemProperties::GetHardWareEncodeEnabled() && opts.format == "image/jpeg" &&
        (pixelMap->GetWidth() % 2 == 0) && (pixelMap->GetHeight() % 2 == 0) &&
        (pixelMap->GetPixelFormat() == PixelFormat::NV12 || pixelMap->GetPixelFormat() == PixelFormat::NV21) &&
        pixelMap->GetWidth() <= maxImageSize && pixelMap->GetHeight() <= maxImageSize &&
        pixelMap->GetWidth() >= minImageSize && pixelMap->GetHeight() >= minImageSize;
    if (!isSupport) {
        IMAGE_LOGI("hardware encode is not support, dstEncodeFormat:%{public}s, pixelWidth:%{public}d, "
            "pixelHeight:%{public}d, pixelFormat:%{public}d", opts.format.c_str(), pixelMap->GetWidth(),
            pixelMap->GetHeight(), pixelMap->GetPixelFormat());
    }
    return isSupport;
}

uint32_t ExtEncoder::DoHardWareEncode(SkWStream* skStream)
{
    static ImageFwkExtManager imageFwkExtManager;
    if (imageFwkExtManager.doHardWareEncodeFunc_ != nullptr || imageFwkExtManager.LoadImageFwkExtNativeSo()) {
        int32_t retCode = imageFwkExtManager.doHardWareEncodeFunc_(skStream, opts_, pixelmap_);
        if (retCode == SUCCESS) {
            return SUCCESS;
        }
        IMAGE_LOGE("hardware encode failed, retCode is %{public}d", retCode);
        ImageInfo imageInfo;
        pixelmap_->GetImageInfo(imageInfo);
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "hardware encode failed");
    } else {
        IMAGE_LOGE("hardware encode failed because of load native so failed");
    }
    return ERR_IMAGE_ENCODE_FAILED;
}

uint32_t ExtEncoder::DoEncode(SkWStream* skStream, const SkBitmap& src, const SkEncodedImageFormat& skFormat)
{
    ImageFuncTimer imageFuncTimer("%s:(%d, %d)", __func__, pixelmap_->GetWidth(), pixelmap_->GetHeight());
    ImageInfo imageInfo;
    pixelmap_->GetImageInfo(imageInfo);
    if (IsHardwareEncodeSupported(opts_, pixelmap_)) {
        return DoHardWareEncode(skStream);
    }
    if (!SkEncodeImage(skStream, src, skFormat, opts_.quality)) {
        IMAGE_LOGE("Failed to encode image without exif data");
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to encode image");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

uint32_t ExtEncoder::EncodeImageByBitmap(SkBitmap& bitmap, bool needExif, SkWStream& outStream)
{
    ImageInfo imageInfo;
    pixelmap_->GetImageInfo(imageInfo);
    if (!needExif || pixelmap_->GetExifMetadata() == nullptr ||
        pixelmap_->GetExifMetadata()->GetExifData() == nullptr) {
            return DoEncode(&outStream, bitmap, encodeFormat_);
    }

    MetadataWStream tStream;
    uint32_t errCode = DoEncode(&tStream, bitmap, encodeFormat_);
    if (errCode != SUCCESS) {
        return errCode;
    }
    return CreateAndWriteBlob(tStream, pixelmap_, outStream, imageInfo, opts_);
}

uint32_t ExtEncoder::EncodeImageByPixelMap(PixelMap* pixelMap, bool needExif, SkWStream& outputStream)
{
    SkBitmap bitmap;
    TmpBufferHolder holder;
    SkImageInfo skInfo;
    ImageData imageData;
    pixelMap->GetImageInfo(imageData.info);
    uint32_t width  = imageData.info.size.width;
    uint32_t height = imageData.info.size.height;
    std::unique_ptr<uint8_t[]> dstData = std::make_unique<uint8_t[]>(width * height * NUM_3);
    imageData.dst = dstData.get();
    if (pixelToSkInfo(imageData, skInfo, pixelMap, holder, encodeFormat_) != SUCCESS) {
        IMAGE_LOGE("ExtEncoder::EncodeImageByPixelMap pixel convert failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    uint64_t rowStride = skInfo.minRowBytes64();

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (pixelMap->GetFd());
        rowStride = sbBuffer->GetStride();
    }
#endif
    if (!bitmap.installPixels(skInfo, imageData.pixels, rowStride)) {
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
    sk_sp<SkData> baseImageData = GetImageEncodeData(baseSptr, baseInfo, opts_.needsPackProperties);
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
        return EncodeImageByPixelMap(pixelmap_, opts_.needsPackProperties, outputStream);
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
    error = EncodeImageBySurfaceBuffer(baseSptr, baseInfo, opts_.needsPackProperties, outputStream);
    FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
    return error;
}
#endif
} // namespace ImagePlugin
} // namespace OHOS
