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
#include "src/images/SkImageEncoderFns.h"
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
#include "file_packer_stream.h"
#include "memory_manager.h"
#ifdef HEIF_HW_ENCODE_ENABLE
#include "v1_0/icodec_image.h"
#include "iremote_object.h"
#include "iproxy_broker.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ExtEncoder"

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
const std::map<PixelFormat, GraphicPixelFormat> SURFACE_FORMAT_MAP = {
    { PixelFormat::RGBA_8888, GRAPHIC_PIXEL_FMT_RGBA_8888 },
    { PixelFormat::NV21, GRAPHIC_PIXEL_FMT_YCRCB_420_SP },
    { PixelFormat::NV12, GRAPHIC_PIXEL_FMT_YCBCR_420_SP },
};
#endif

namespace {
    constexpr static uint32_t PRIMARY_IMAGE_ITEM_ID = 1;
    constexpr static uint32_t GAINMAP_IMAGE_ITEM_ID = 2;
    constexpr static uint32_t TMAP_IMAGE_ITEM_ID = 3;
    constexpr static uint32_t EXIF_META_ITEM_ID = 4;
    const static std::string COMPRESS_TYPE_TMAP = "tmap";
    const static std::string COMPRESS_TYPE_HEVC = "hevc";
    const static std::string DEFAULT_ASHMEM_TAG = "Heif Encoder Default";
    const static std::string ICC_ASHMEM_TAG = "Heif Encoder Property";
    const static std::string IT35_ASHMEM_TAG = "Heif Encoder IT35";
    const static std::string OUTPUT_ASHMEM_TAG = "Heif Encoder Output";
    const static std::string IMAGE_DATA_TAG = "Heif Encoder Image";
    const static std::string HDR_GAINMAP_TAG = "Heif Encoder Gainmap";
    const static std::string EXIF_ASHMEM_TAG = "Heif Encoder Exif";
    const static size_t DEFAULT_OUTPUT_SIZE = 25 * 1024 * 1024; // 25M
    const static uint16_t STATIC_METADATA_COLOR_SCALE = 50000;
    const static uint16_t STATIC_METADATA_LUM_SCALE = 10000;
    const static uint8_t INDEX_ZERO = 0;
    const static uint8_t INDEX_ONE = 1;
    const static uint8_t INDEX_TWO = 2;
    constexpr uint32_t DEFAULT_DENOMINATOR = 1000000;
    constexpr uint8_t GAINMAP_CHANNEL_MULTI = 3;
    constexpr uint8_t GAINMAP_CHANNEL_SINGLE = 1;
    constexpr uint8_t EXIF_PRE_SIZE = 6;

    // exif/0/0
    constexpr uint8_t EXIF_PRE_TAG[EXIF_PRE_SIZE] = {
        0x45, 0x78, 0x69, 0x66, 0x00, 0x00
    };
}
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

#ifdef HEIF_HW_ENCODE_ENABLE
using namespace OHOS::HDI::Codec::Image::V1_0;
static std::mutex g_codecMtx;
static sptr<ICodecImage> g_codecMgr;
class CodecHeifDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    void OnRemoteDied(const wptr<OHOS::IRemoteObject>& object) override
    {
        IMAGE_LOGW("codec_image_service died");
        std::lock_guard<std::mutex> lk(g_codecMtx);
        g_codecMgr = nullptr;
    }
};

static sptr<ICodecImage> GetCodecManager()
{
    std::lock_guard<std::mutex> lk(g_codecMtx);
    if (g_codecMgr) {
        return g_codecMgr;
    }
    IMAGE_LOGI("need to get ICodecImage");
    g_codecMgr = ICodecImage::Get();
    if (g_codecMgr == nullptr) {
        IMAGE_LOGE("ICodecImage get failed");
        return nullptr;
    }
    bool isDeathRecipientAdded = false;
    const sptr<OHOS::IRemoteObject> &remote = OHOS::HDI::hdi_objcast<ICodecImage>(g_codecMgr);
    if (remote) {
        sptr<CodecHeifDeathRecipient> deathCallBack(new CodecHeifDeathRecipient());
        isDeathRecipientAdded = remote->AddDeathRecipient(deathCallBack);
    }
    if (!isDeathRecipientAdded) {
        IMAGE_LOGI("failed to add deathRecipient for ICodecImage!");
    }
    return g_codecMgr;
}
#endif

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

static sk_sp<SkColorSpace> ToSkColorSpace(PixelMap *pixelmap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (pixelmap->InnerGetGrColorSpacePtr() == nullptr) {
        return nullptr;
    }
    return pixelmap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
#else
    return nullptr;
#endif
}

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

static uint32_t YuvToRgbaSkInfo(ImageInfo info, SkImageInfo &skInfo, uint8_t * dstData, Media::PixelMap *pixelMap)
{
    uint8_t *srcData = static_cast<uint8_t*>(pixelMap->GetWritablePixels());
    YUVDataInfo yuvInfo;
    pixelMap->GetImageYUVInfo(yuvInfo);
    YuvImageInfo srcInfo = {PixelYuvUtils::ConvertFormat(info.pixelFormat),
        info.size.width, info.size.height, info.pixelFormat, yuvInfo};
    YuvImageInfo dstInfo = {PixelYuvUtils::ConvertFormat(PixelFormat::RGBA_8888), info.size.width, info.size.height};
    if (!PixelConvertAdapter::YUV420ToRGB888(srcData, srcInfo, dstData, dstInfo)) {
        IMAGE_LOGE("YuvToSkInfo Support YUV format RGB convert failed ");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    auto alpha = pixelMap->GetAlphaType();
    if (alpha == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN)
        alpha = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(alpha);
    auto cs = ToSkColorSpace(pixelMap);
    skInfo = SkImageInfo::Make(info.size.width, info.size.height, SkColorType::kRGBA_8888_SkColorType, alphaType, cs);
    IMAGE_LOGD(" YuvToSkInfo: width:%{public}d, height:%{public}d, alpha:%{public}d \n ",
        info.size.width, info.size.height, (int32_t)alphaType);
    return SUCCESS;
}

static uint32_t pixelToSkInfo(ImageData &image, SkImageInfo &skInfo, Media::PixelMap *pixelMap,
    TmpBufferHolder &holder, SkEncodedImageFormat format)
{
    skInfo = ToSkInfo(pixelMap);
    image.pixels = static_cast<uint8_t*>(pixelMap->GetWritablePixels());
    if (format == SkEncodedImageFormat::kJPEG &&
        skInfo.colorType() == SkColorType::kRGB_888x_SkColorType &&
        pixelMap->GetCapacity() < skInfo.computeMinByteSize()) {
        uint32_t res = RGBToRGBx(pixelMap, skInfo, holder);
        if (res != SUCCESS) {
            IMAGE_LOGE("ExtEncoder::BuildSkBitmap RGB convert failed %{public}d", res);
            return res;
        }
        image.pixels = holder.buf.get();
        skInfo = skInfo.makeColorType(SkColorType::kRGBA_8888_SkColorType);
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

uint32_t ExtEncoder::PixelmapEncode(ExtWStream& wStream)
{
    uint32_t error;
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    error = EncodeImageByPixelMap(pixelmap_, opts_.needsPackProperties, wStream);
#else
    switch (opts_.desiredDynamicRange) {
        case EncodeDynamicRange::AUTO:
            if (pixelmap_->IsHdr() &&
                (encodeFormat_ == SkEncodedImageFormat::kJPEG || encodeFormat_ == SkEncodedImageFormat::kHEIF)) {
                error = EncodeDualVivid(wStream);
            } else {
                error = EncodeSdrImage(wStream);
            }
            break;
        case EncodeDynamicRange::SDR:
            error = EncodeSdrImage(wStream);
            break;
        case EncodeDynamicRange::HDR_VIVID_DUAL:
            error = EncodeDualVivid(wStream);
            break;
        case EncodeDynamicRange::HDR_VIVID_SINGLE:
            error = EncodeSingleVivid(wStream);
            break;
        default:
            error = ERR_IMAGE_ENCODE_FAILED;
            break;
    }
#endif
    RecycleResources();
    return error;
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
    return PixelmapEncode(wStream);
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
    if (!SkEncodeImage(skStream, src, skFormat, opts_.quality)) {
        IMAGE_LOGE("Failed to encode image without exif data");
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "Failed to encode image");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

bool ExtEncoder::HardwareEncode(SkWStream &skStream, bool needExif)
{
    uint32_t retCode = ERR_IMAGE_ENCODE_FAILED;
    if (IsHardwareEncodeSupported(opts_, pixelmap_)) {
        if (!needExif || pixelmap_->GetExifMetadata() == nullptr ||
            pixelmap_->GetExifMetadata()->GetExifData() == nullptr) {
                retCode = DoHardWareEncode(&skStream);
                IMAGE_LOGD("HardwareEncode retCode:%{public}d", retCode);
                return (retCode == SUCCESS);
        }
        MetadataWStream tStream;
        retCode = DoHardWareEncode(&tStream);
        if (retCode != SUCCESS) {
            IMAGE_LOGD("HardwareEncode failed");
            return false;
        }
        ImageInfo imageInfo;
        pixelmap_->GetImageInfo(imageInfo);
        retCode = CreateAndWriteBlob(tStream, pixelmap_, skStream, imageInfo, opts_);
        IMAGE_LOGD("HardwareEncode retCode :%{public}d", retCode);
        return (retCode == SUCCESS);
    }
    return (retCode == SUCCESS);
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
    if (encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        return EncodeHeifByPixelmap(pixelMap, opts_);
    }
    SkBitmap bitmap;
    TmpBufferHolder holder;
    SkImageInfo skInfo;
    ImageData imageData;
    pixelMap->GetImageInfo(imageData.info);
    uint32_t width  = static_cast<uint32_t>(imageData.info.size.width);
    uint32_t height = static_cast<uint32_t>(imageData.info.size.height);

    if (HardwareEncode(outputStream, needExif) == true) {
        IMAGE_LOGD("HardwareEncode Success return");
        return SUCCESS;
    }
    IMAGE_LOGD("HardwareEncode failed or not Supported");

    std::unique_ptr<uint8_t[]> dstData;
    uint64_t rowStride = 0;
    if (IsYuvImage(imageData.info.pixelFormat)) {
        IMAGE_LOGD("YUV format, convert to RGB");
        dstData = std::make_unique<uint8_t[]>(width * height * NUM_4);
        if (YuvToRgbaSkInfo(imageData.info, skInfo, dstData.get(), pixelMap) != SUCCESS) {
            IMAGE_LOGD("YUV format, convert to RGB fail");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        imageData.pixels = dstData.get();
        rowStride = skInfo.minRowBytes64();
    } else {
        dstData = std::make_unique<uint8_t[]>(width * height * NUM_3);
        imageData.dst = dstData.get();
        if (pixelToSkInfo(imageData, skInfo, pixelMap, holder, encodeFormat_) != SUCCESS) {
            IMAGE_LOGE("ExtEncoder::EncodeImageByPixelMap pixel convert failed");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        rowStride = skInfo.minRowBytes64();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
            SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (pixelMap->GetFd());
            rowStride = sbBuffer->GetStride();
            IMAGE_LOGD("rowStride DMA: %{public}llu", static_cast<unsigned long long>(rowStride));
        }
#endif
    }
    if (!bitmap.installPixels(skInfo, imageData.pixels, rowStride)) {
        IMAGE_LOGE("ExtEncoder::EncodeImageByPixelMap to SkBitmap failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return EncodeImageByBitmap(bitmap, needExif, outputStream);
}

uint32_t ExtEncoder::EncodeHeifByPixelmap(PixelMap* pixelmap, const PlEncodeOptions& opts)
{
#ifdef HEIF_HW_ENCODE_ENABLE
    if (output_ == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    Media::PixelFormat format = pixelmap->GetPixelFormat();
    if (format != PixelFormat::RGBA_8888 && format != PixelFormat::NV12 && format != PixelFormat::NV21) {
        IMAGE_LOGE("EncodeHeifByPixelmap, invalid format:%{public}d", format);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    sptr<SurfaceBuffer> surfaceBuffer;
    bool needConvertToSurfaceBuffer = pixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC;
    if (needConvertToSurfaceBuffer) {
        surfaceBuffer = ConvertToSurfaceBuffer(pixelmap);
        if (surfaceBuffer == nullptr) {
            IMAGE_LOGE("EncodeHeifByPixelmap ConvertToSurfaceBuffer failed");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
    } else {
        if (pixelmap->GetFd() == nullptr) {
            IMAGE_LOGE("EncodeHeifByPixelmap pixelmap get fd failed");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
        surfaceBuffer = reinterpret_cast<SurfaceBuffer*>(pixelmap->GetFd());
    }
    std::vector<ImageItem> inputImgs;
    std::shared_ptr<ImageItem> primaryItem = AssemblePrimaryImageItem(surfaceBuffer, opts);
    if (primaryItem == nullptr) {
        if (needConvertToSurfaceBuffer) {
            ImageUtils::SurfaceBuffer_Unreference(surfaceBuffer.GetRefPtr());
        }
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    inputImgs.push_back(*primaryItem);
    std::vector<MetaItem> inputMetas;
    std::vector<ItemRef> refs;
    if (AssembleExifMetaItem(inputMetas)) {
        AssembleExifRefItem(refs);
    }
    uint32_t result = DoHeifEncode(inputImgs, inputMetas, refs);
    if (needConvertToSurfaceBuffer) {
        ImageUtils::SurfaceBuffer_Unreference(surfaceBuffer.GetRefPtr());
    }
    return result;
#endif
#else
    return ERR_IMAGE_INVALID_PARAMETER;
#endif
}

void ExtEncoder::RecycleResources()
{
    for (std::shared_ptr<AbsMemory> &memory: tmpMemoryList_) {
        if (memory == nullptr) {
            continue;
        }
        memory->Release();
    }
    tmpMemoryList_.clear();
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static sptr<SurfaceBuffer> AllocSurfaceBuffer(int32_t width, int32_t height,
    uint32_t format = GRAPHIC_PIXEL_FMT_RGBA_8888)
{
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = width,
        .height = height,
        .strideAlignment = 0x8,
        .format = format,
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
    return sb;
}

sptr<SurfaceBuffer> ExtEncoder::ConvertToSurfaceBuffer(PixelMap* pixelmap)
{
    if (pixelmap->GetHeight() <= 0 || pixelmap->GetWidth() <= 0) {
        IMAGE_LOGE("pixelmap height:%{public}d or width:%{public}d error", pixelmap->GetHeight(), pixelmap->GetWidth());
        return nullptr;
    }
    uint32_t height = static_cast<uint32_t>(pixelmap->GetHeight());
    uint32_t width = static_cast<uint32_t>(pixelmap->GetWidth());
    PixelFormat format = pixelmap->GetPixelFormat();
    auto formatSearch = SURFACE_FORMAT_MAP.find(format);
    if (formatSearch == SURFACE_FORMAT_MAP.end()) {
        IMAGE_LOGE("format:[%{public}d] is not in SURFACE_FORMAT_MAP", format);
        return nullptr;
    }
    uint32_t graphicFormat = formatSearch->second;
    sptr<SurfaceBuffer> surfaceBuffer = AllocSurfaceBuffer(width, height, graphicFormat);
    if (surfaceBuffer == nullptr || surfaceBuffer->GetStride() < 0) {
        IMAGE_LOGE("ConvertToSurfaceBuffer surfaceBuffer is nullptr failed");
        return nullptr;
    }
    uint32_t dstStride = static_cast<uint32_t>(surfaceBuffer->GetStride());
    uint8_t* src = const_cast<uint8_t*>(pixelmap->GetPixels());
    uint8_t* dst = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
    uint32_t dstSize = surfaceBuffer->GetSize();
    uint32_t copyHeight = height;
    if (format == PixelFormat::NV12 || format == PixelFormat::NV21) {
        const int32_t NUM_2 = 2;
        copyHeight = height + height / NUM_2;
    } else if (format == PixelFormat::RGBA_8888) {
        copyHeight = height;
    }
    for (uint32_t i = 0; i < copyHeight; i++) {
        if (memcpy_s(dst, dstSize, src, width) != EOK) {
            IMAGE_LOGE("ConvertToSurfaceBuffer memcpy failed");
            ImageUtils::SurfaceBuffer_Unreference(surfaceBuffer.GetRefPtr());
            return nullptr;
        }
        dst += dstStride;
        dstSize -= dstStride;
        src += width;
    }
    return surfaceBuffer;
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
    ImageInfo imageInfo;
    uint64_t rowStride = 0;
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGE("EncodeImageBySurfaceBuffer failed, surfaceBuffer is nullptr");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto pixels = surfaceBuffer->GetVirAddr();
    if (pixels == nullptr) {
        IMAGE_LOGE("EncodeImageBySurfaceBuffer failed, pixels is nullptr");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    /* do hardwareEncode first, if fail then soft encode*/
    if (HardwareEncode(outputStream, needExif)) {
        IMAGE_LOGD("HardwareEncode Success return");
        return SUCCESS;
    }
    IMAGE_LOGD("HardwareEncode failed or not Supported");

    pixelmap_->GetImageInfo(imageInfo);
    std::unique_ptr<uint8_t[]> dstData;
    if (IsYuvImage(imageInfo.pixelFormat)) {
        IMAGE_LOGD("EncodeImageBySurfaceBuffer: YUV format, convert to RGB first");
        dstData = std::make_unique<uint8_t[]>(imageInfo.size.width * imageInfo.size.height * NUM_4);
        if (dstData == nullptr) {
            IMAGE_LOGE("Memory allocate fail");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        if (YuvToRgbaSkInfo(imageInfo, info, dstData.get(), pixelmap_) != SUCCESS) {
            IMAGE_LOGD("YUV format, convert to RGB fail");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        pixels = dstData.get();
        rowStride = info.minRowBytes64();
    } else {
        rowStride = surfaceBuffer->GetStride();
    }

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

static bool DecomposeImage(VpeSurfaceBuffers& buffers, HdrMetadata& metadata, bool onlySdr)
{
    VpeUtils::SetSbMetadataType(buffers.sdr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(buffers.sdr, CM_SRGB_FULL);
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res;
    if (onlySdr) {
        if (buffers.hdr == nullptr || buffers.sdr == nullptr) {
            return false;
        }
        res = utils->ColorSpaceConverterImageProcess(buffers.hdr, buffers.sdr);
    } else {
        VpeUtils::SetSbMetadataType(buffers.gainmap, CM_METADATA_NONE);
        VpeUtils::SetSbColorSpaceType(buffers.gainmap, CM_SRGB_FULL);
        res = utils->ColorSpaceConverterDecomposeImage(buffers);
    }
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("DecomposeImage [%{public}d] failed, res = %{public}d", onlySdr, res);
        return false;
    }
    if (!onlySdr) {
        metadata = GetHdrMetadata(buffers.hdr, buffers.gainmap);
    }
    return true;
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

#ifdef HEIF_HW_ENCODE_ENABLE
// format: enum + struct
static bool FillLitePropertyItem(std::vector<uint8_t>& properties, size_t& offset, PropertyType type,
    const void* payloadData, size_t payloadSize)
{
    uint8_t* memData = properties.data();
    size_t memSize = properties.size();
    if (offset > memSize) {
        IMAGE_LOGE("FillLitePropertyItem failed, offset[%{public}ld] over memSize[%{public}ld]", offset, memSize);
        return false;
    }
    size_t typeSize = sizeof(type);
    bool res = memcpy_s(memData + offset, memSize - offset, &type, typeSize) == EOK &&
        memcpy_s(memData + offset + typeSize, memSize - offset - typeSize, payloadData, payloadSize) == EOK;
    if (res) {
        offset += (typeSize + payloadSize);
    }
    return res;
}

std::shared_ptr<ImageItem> ExtEncoder::AssembleHdrBaseImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
    ColorManager::ColorSpaceName color, HdrMetadata& metadata, const PlEncodeOptions& opts)
{
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGI("AssembleHdrBaseImageItem surfaceBuffer is nullptr");
        return nullptr;
    }
    auto item = std::make_shared<ImageItem>();
    item->id = PRIMARY_IMAGE_ITEM_ID;
    item->isPrimary = true;
    item->isHidden = false;
    item->compressType = COMPRESS_TYPE_HEVC;
    item->quality = opts.quality;
    item->pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    item->sharedProperties.fd = -1;
    ColourInfo colorInfo;
    GetColourInfo(color, colorInfo);
    ContentLightLevel light;
    MasteringDisplayColourVolume colour;
    bool hasLight = GetStaticMetadata(metadata, colour, light);
    uint32_t propertiesSize = 0;
    propertiesSize +=
        (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType) + sizeof(PropertyType::COLOR_INFO) + sizeof(ColourInfo));
    if (hasLight) {
        propertiesSize += (sizeof(PropertyType::CONTENT_LIGHT_LEVEL) + sizeof(ContentLightLevel));
    }
    item->liteProperties.resize(propertiesSize);
    size_t offset = 0;
    if (!FillNclxColorProperty(item, offset, colorInfo)) {
        return nullptr;
    }
    if (hasLight && (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::CONTENT_LIGHT_LEVEL, &colour, sizeof(ContentLightLevel)))) {
        return nullptr;
    }
    return item;
}

std::shared_ptr<ImageItem> ExtEncoder::AssembleGainmapImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
    ColorManager::ColorSpaceName color, const PlEncodeOptions &opts)
{
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGI("AssembleGainmapImageItem surfacebuffer is nullptr");
        return nullptr;
    }
    auto item = std::make_shared<ImageItem>();
    item->id = GAINMAP_IMAGE_ITEM_ID;
    item->itemName = "Gain Map Image";
    item->isPrimary = false;
    item->isHidden = true;
    item->compressType = COMPRESS_TYPE_HEVC;
    item->quality = opts.quality;
    item->sharedProperties.fd = -1;
    item->pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    ColourInfo colorInfo;
    GetColourInfo(color, colorInfo);
    uint32_t propertiesSize = 0;
    propertiesSize +=
        (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType) + sizeof(PropertyType::COLOR_INFO) + sizeof(ColourInfo));
    item->liteProperties.resize(propertiesSize);
    size_t offset = 0;
    if (!FillNclxColorProperty(item, offset, colorInfo)) {
        return nullptr;
    }
    return item;
}
#endif

uint32_t ExtEncoder::EncodeDualVivid(ExtWStream& outputStream)
{
    if (!pixelmap_->IsHdr() ||
        pixelmap_->GetAllocatorType() != AllocatorType::DMA_ALLOC ||
        (encodeFormat_ != SkEncodedImageFormat::kJPEG && encodeFormat_ != SkEncodedImageFormat::kHEIF)) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    SkImageInfo baseInfo = GetSkInfo(pixelmap_, false);
    SkImageInfo gainmapInfo = GetSkInfo(pixelmap_, true);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo.width(), baseInfo.height());
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(baseSptr, CM_SRGB_FULL);
    sptr<SurfaceBuffer> gainMapSptr = AllocSurfaceBuffer(gainmapInfo.width(), gainmapInfo.height());
    VpeUtils::SetSbMetadataType(gainMapSptr, CM_METADATA_NONE);
    VpeUtils::SetSbColorSpaceType(gainMapSptr, CM_SRGB_FULL);
    if (baseSptr == nullptr || gainMapSptr == nullptr) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    HdrMetadata metadata;
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (pixelmap_->GetFd()));
    VpeUtils::SetSbMetadataType(hdrSurfaceBuffer, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .gainmap = gainMapSptr,
        .hdr = hdrSurfaceBuffer,
    };
    if (!DecomposeImage(buffers, metadata, false)) {
        IMAGE_LOGE("EncodeDualVivid decomposeImage failed");
        FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    uint32_t error;
    if (encodeFormat_ == SkEncodedImageFormat::kJPEG) {
        sk_sp<SkData> baseImageData = GetImageEncodeData(baseSptr, baseInfo, opts_.needsPackProperties);
        sk_sp<SkData> gainMapImageData = GetImageEncodeData(gainMapSptr, gainmapInfo, false);
        error = HdrJpegPackerHelper::SpliceHdrStream(baseImageData, gainMapImageData, outputStream, metadata);
    } else if (encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        error = EncodeHeifDualHdrImage(baseSptr, gainMapSptr, metadata);
    } else {
        error = ERR_IMAGE_INVALID_PARAMETER;
    }
    FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainMapSptr);
    return error;
}

uint32_t ExtEncoder::EncodeSdrImage(ExtWStream& outputStream)
{
    if (!pixelmap_->IsHdr()) {
        return EncodeImageByPixelMap(pixelmap_, opts_.needsPackProperties, outputStream);
    }
    if (pixelmap_->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        IMAGE_LOGE("pixelmap is 10bit, but not dma buffer");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
    SkImageInfo baseInfo = GetSkInfo(pixelmap_, false);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo.width(), baseInfo.height());
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(baseSptr, CM_SRGB_FULL);
    if (baseSptr == nullptr) {
        IMAGE_LOGE("EncodeSdrImage sdr buffer alloc failed");
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(pixelmap_->GetFd()));
    VpeUtils::SetSbMetadataType(hdrSurfaceBuffer, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .hdr = hdrSurfaceBuffer,
    };
    HdrMetadata metadata;
    if (!DecomposeImage(buffers, metadata, true)) {
        IMAGE_LOGE("EncodeSdrImage decomposeImage failed");
        ImageUtils::SurfaceBuffer_Unreference(baseSptr.GetRefPtr());
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    uint32_t error;
    if (encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        error = EncodeHeifSdrImage(baseSptr, baseInfo);
    } else {
        error = EncodeImageBySurfaceBuffer(baseSptr, baseInfo, opts_.needsPackProperties, outputStream);
    }
    ImageUtils::SurfaceBuffer_Unreference(baseSptr.GetRefPtr());
    return error;
}

uint32_t ExtEncoder::EncodeHeifDualHdrImage(sptr<SurfaceBuffer>& sdr, sptr<SurfaceBuffer>& gainmap,
    Media::HdrMetadata& metadata)
{
#ifdef HEIF_HW_ENCODE_ENABLE
    std::vector<ImageItem> inputImgs;
    std::shared_ptr<ImageItem> primaryItem =
        AssembleHdrBaseImageItem(sdr, ColorManager::ColorSpaceName::SRGB, metadata, opts_);
    if (primaryItem == nullptr) {
        IMAGE_LOGE("AssmbleHeifDualHdrImage, get primary image failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    inputImgs.push_back(*primaryItem);
    std::shared_ptr<ImageItem> gainmapItem =
        AssembleGainmapImageItem(gainmap, ColorManager::ColorSpaceName::SRGB, opts_);
    if (gainmapItem == nullptr) {
        IMAGE_LOGE("AssembleDualHdrImage, get gainmap image item failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    inputImgs.push_back(*gainmapItem);
    ColorManager::ColorSpaceName tmapColor = pixelmap_->InnerGetGrColorSpace().GetColorSpaceName();
    std::shared_ptr<ImageItem> tmapItem = AssembleTmapImageItem(tmapColor, metadata, opts_);
    if (tmapItem == nullptr) {
        IMAGE_LOGE("AssembleDualHdrImage, get tmap image item failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    inputImgs.push_back(*tmapItem);
    std::vector<MetaItem> inputMetas;
    std::vector<ItemRef> refs;
    if (AssembleExifMetaItem(inputMetas)) {
        AssembleExifRefItem(refs);
    }
    AssembleDualHdrRefItem(refs);
    return DoHeifEncode(inputImgs, inputMetas, refs);
#else
    return ERR_IMAGE_INVALID_PARAMETER;
#endif
}

uint32_t ExtEncoder::EncodeHeifSdrImage(sptr<SurfaceBuffer>& sdr, SkImageInfo sdrInfo)
{
#ifdef HEIF_HW_ENCODE_ENABLE
    if (sdr == nullptr) {
        IMAGE_LOGE("EncodeHeifSdrImage, sdr surfacebuffer is nullptr");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    ImageItem item;
    item.id = PRIMARY_IMAGE_ITEM_ID;
    item.pixelBuffer = sptr<NativeBuffer>::MakeSptr(sdr->GetBufferHandle());
    item.isPrimary = true;
    item.isHidden = false;
    item.compressType = COMPRESS_TYPE_HEVC;
    item.quality = opts_.quality;
    item.sharedProperties.fd = -1;
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
    sk_sp<SkData> iccProfile = icc_from_color_space(sdrInfo);
    bool tempRes = AssembleICCImageProperty(iccProfile, item.sharedProperties);
    if (!tempRes) {
        IMAGE_LOGE("EncodeSdrImage AssembleICCImageProperty failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t litePropertiesSize = (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item.liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    ColorType colorType = ColorType::RICC;
    if (!FillLitePropertyItem(item.liteProperties, offset, PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType))) {
        IMAGE_LOGE("EncodeHeifSdrImage Fill color type failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    std::vector<ImageItem> inputImgs;
    inputImgs.push_back(item);
    std::vector<MetaItem> inputMetas;
    std::vector<ItemRef> refs;
    if (AssembleExifMetaItem(inputMetas)) {
        AssembleExifRefItem(refs);
    }
    return DoHeifEncode(inputImgs, inputMetas, refs);
#else
    return ERR_IMAGE_INVALID_PARAMETER;
#endif
}
#endif

#ifdef HEIF_HW_ENCODE_ENABLE
static size_t GetBufferSize(size_t contentSize)
{
    return sizeof(PropertyType) + sizeof(int) + contentSize;
}

// format: enum + int buffersize + buffer
static bool FillImagePropertyItem(const std::shared_ptr<AbsMemory> &mem, const size_t offset,
    PropertyType type, const void* payloadData, size_t payloadSize)
{
    uint8_t* memData = reinterpret_cast<uint8_t*>(mem->data.data);
    size_t memSize = mem->data.size;
    IMAGE_LOGD("FileImagePropertyItem memSize is %{public}ld, payloadSize is %{public}ld", memSize, payloadSize);
    IMAGE_LOGD("FileImagePropertyItem sizeof(type) is %{public}ld, sizeof(payloadSize) %{public}ld",
        sizeof(type), sizeof(payloadSize));
    if (payloadSize > INT32_MAX) {
        IMAGE_LOGI("payloadSize is over INT32_MAX");
        return false;
    }
    int payloadIntSize = static_cast<int>(payloadSize);
    size_t typeSize = sizeof(type);
    size_t intSize = sizeof(int);
    bool res = (memcpy_s(memData + offset, memSize - offset, &type, typeSize) == EOK) &&
        (memcpy_s(memData + offset + typeSize, memSize - offset - typeSize, &payloadIntSize, intSize) == EOK) &&
        (memcpy_s(memData + offset + typeSize + intSize, memSize - offset - typeSize - intSize,
        payloadData, payloadSize) == EOK);
    return res;
}

std::shared_ptr<AbsMemory> ExtEncoder::AllocateNewSharedMem(size_t memorySize, std::string tag)
{
    MemoryData memoryData;
    memoryData.size = memorySize;
    memoryData.tag = tag.empty() ? DEFAULT_ASHMEM_TAG.c_str() : tag.c_str();
    std::unique_ptr<AbsMemory> memory =
        MemoryManager::CreateMemory(AllocatorType::SHARE_MEM_ALLOC, memoryData);
    std::shared_ptr<AbsMemory> res = std::move(memory);
    return res;
}

bool ExtEncoder::GetStaticMetadata(HdrMetadata& metadata, MasteringDisplayColourVolume& color, ContentLightLevel& light)
{
    HdrStaticMetadata staticMetadata;
    size_t staticMetadataSize = sizeof(HdrStaticMetadata);
    if (metadata.staticMetadata.size() < staticMetadataSize) {
        IMAGE_LOGI("GetStaticMetadata failed");
        return false;
    }
    if (memcpy_s(&staticMetadata, staticMetadataSize,
        metadata.staticMetadata.data(), metadata.staticMetadata.size()) != EOK) {
        IMAGE_LOGI("GetStaticMetadata failed, memcpy_s failed");
        return false;
    }
    color.displayPrimariesRX =
        (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.displayPrimaryRed.x);
    color.displayPrimariesRY =
        (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.displayPrimaryRed.y);
    color.displayPrimariesGX =
        (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.displayPrimaryGreen.x);
    color.displayPrimariesGY =
        (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.displayPrimaryGreen.y);
    color.displayPrimariesBX =
        (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.displayPrimaryBlue.x);
    color.displayPrimariesBY =
        (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.displayPrimaryBlue.y);
    color.whitePointX = (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.whitePoint.x);
    color.whitePointY = (uint16_t)(STATIC_METADATA_COLOR_SCALE * staticMetadata.smpte2086.whitePoint.y);
    color.maxDisplayMasteringLuminance = (uint32_t)staticMetadata.smpte2086.maxLuminance;
    color.minDisplayMasteringLuminance = (uint32_t)(STATIC_METADATA_LUM_SCALE * staticMetadata.smpte2086.minLuminance);
    light.maxContentLightLevel = (uint16_t)staticMetadata.cta861.maxContentLightLevel;
    light.maxPicAverageLightLevel = (uint16_t)staticMetadata.cta861.maxFrameAverageLightLevel;
    return true;
}

bool ExtEncoder::GetToneMapChannel(ISOMetadata& metadata, ToneMapChannel& channel, uint8_t index)
{
    if (index > GAINMAP_CHANNEL_MULTI - 1) {
        IMAGE_LOGE("GetToneMapChannel index:[%{public}d] unsupported", index);
        return false;
    }
    channel.gainMapMin.numerator = DEFAULT_DENOMINATOR * metadata.enhanceClippedThreholdMinGainmap[index];
    channel.gainMapMin.denominator = DEFAULT_DENOMINATOR;
    channel.gainMapMax.numerator = DEFAULT_DENOMINATOR * metadata.enhanceClippedThreholdMaxGainmap[index];
    channel.gainMapMax.denominator = DEFAULT_DENOMINATOR;
    if (metadata.enhanceMappingGamma[index] > 0.0f) {
        channel.gamma.numerator = DEFAULT_DENOMINATOR * metadata.enhanceMappingGamma[index];
    } else {
        channel.gamma.numerator = 0;
    }
    channel.gamma.denominator = DEFAULT_DENOMINATOR;
    channel.baseOffset.numerator = DEFAULT_DENOMINATOR * metadata.enhanceMappingBaselineOffset[index];
    channel.baseOffset.denominator = DEFAULT_DENOMINATOR;
    channel.alternateOffset.numerator = DEFAULT_DENOMINATOR * metadata.enhanceMappingAlternateOffset[index];
    channel.alternateOffset.denominator = DEFAULT_DENOMINATOR;
    IMAGE_LOGD("GetToneMapChannel [%{public}d],gainmapMin:%{public}f, gainmapMax:%{public}f,"
        "gamma:%{public}f,baseOffset:%{public}f, alternateOffset:%{public}f", index,
        metadata.enhanceClippedThreholdMinGainmap[index], metadata.enhanceClippedThreholdMaxGainmap[index],
        metadata.enhanceMappingGamma[index],
        metadata.enhanceMappingBaselineOffset[index], metadata.enhanceMappingAlternateOffset[index]);
    return true;
}

bool ExtEncoder::GetToneMapMetadata(HdrMetadata& metadata, ToneMapMetadata& toneMapMetadata)
{
    ISOMetadata isoMeta = metadata.extendMeta.metaISO;
    toneMapMetadata.useBaseColorSpace = (isoMeta.useBaseColorFlag == 1) ? true : false;
    toneMapMetadata.channelCnt = (isoMeta.gainmapChannelNum == 0) ? GAINMAP_CHANNEL_SINGLE : GAINMAP_CHANNEL_MULTI;
    toneMapMetadata.baseHdrHeadroom.denominator = DEFAULT_DENOMINATOR;
    if (isoMeta.baseHeadroom > 0.0f) {
        toneMapMetadata.baseHdrHeadroom.numerator = (uint32_t)(isoMeta.baseHeadroom * DEFAULT_DENOMINATOR);
    } else {
        toneMapMetadata.baseHdrHeadroom.numerator = 0;
    }
    toneMapMetadata.alternateHdrHeadroom.denominator = DEFAULT_DENOMINATOR;
    if (isoMeta.alternateHeadroom > 0.0f) {
        toneMapMetadata.alternateHdrHeadroom.numerator = (uint32_t)(isoMeta.alternateHeadroom * DEFAULT_DENOMINATOR);
    } else {
        toneMapMetadata.alternateHdrHeadroom.numerator = 0;
    }
    GetToneMapChannel(isoMeta, toneMapMetadata.channels1, INDEX_ZERO);
    if (toneMapMetadata.channelCnt == GAINMAP_CHANNEL_MULTI) {
        GetToneMapChannel(isoMeta, toneMapMetadata.channels2, INDEX_ONE);
        GetToneMapChannel(isoMeta, toneMapMetadata.channels3, INDEX_TWO);
    }
    IMAGE_LOGD("GetToneMapMetadata useBaseColorSpace:%{public}d, gainmapChannelNum:%{public}d,"
        "baseHeadroom:%{public}f,alternateHeadroom:%{public}f", isoMeta.useBaseColorFlag, isoMeta.gainmapChannelNum,
        isoMeta.baseHeadroom, isoMeta.alternateHeadroom);
    return true;
}

void ExtEncoder::GetColourInfo(ColorManager::ColorSpaceName color, ColourInfo& info)
{
    uint8_t fullRangeFlag;
    ColorUtils::ColorSpaceGetCicp(color, info.colourPrimaries, info.transferCharacteristics, info.matrixCoefficients,
        fullRangeFlag);
    // 1 : full range ; 0 : limit range.
    info.fullRangeFlag = (fullRangeFlag == 1);
}

bool ExtEncoder::AssembleIT35SharedBuffer(HdrMetadata metadata, SharedBuffer& outBuffer)
{
    std::vector<uint8_t> it35Info;
    if (!HdrHeifPackerHelper::PackIT35Info(metadata, it35Info)) {
        IMAGE_LOGE("get it35 info failed");
        return false;
    }
    std::shared_ptr<AbsMemory> propertyAshmem =
        AllocateNewSharedMem(GetBufferSize(it35Info.size()), IT35_ASHMEM_TAG);
    if (propertyAshmem == nullptr) {
        IMAGE_LOGE("AssembleIT35SharedBuffer it35 alloc failed");
        return false;
    };
    tmpMemoryList_.push_back(propertyAshmem);
    if (!FillImagePropertyItem(propertyAshmem, 0, PropertyType::IT35_INFO, it35Info.data(), it35Info.size())) {
        IMAGE_LOGE("AssembleIT35SharedBuffer fill failed");
        return false;
    }
    outBuffer.fd = *static_cast<int *>(propertyAshmem->extend.data);
    outBuffer.capacity = propertyAshmem->data.size;
    outBuffer.filledLen = propertyAshmem->data.size;
    return true;
}

bool ExtEncoder::AssembleICCImageProperty(sk_sp<SkData>& iccProfile, SharedBuffer& outBuffer)
{
    if (iccProfile == nullptr || iccProfile->size() == 0) {
        IMAGE_LOGI("AssembleICCImageProperty iccprofile is nullptr");
        return false;
    }
    std::shared_ptr<AbsMemory> propertyAshmem =
        AllocateNewSharedMem(GetBufferSize(iccProfile->size()), ICC_ASHMEM_TAG);
    if (propertyAshmem == nullptr) {
        IMAGE_LOGE("AssembleICCImageProperty alloc failed");
        return false;
    }
    tmpMemoryList_.push_back(propertyAshmem);
    bool fillRes = FillImagePropertyItem(propertyAshmem, 0, PropertyType::ICC_PROFILE,
        iccProfile->data(), iccProfile->size());
    if (fillRes) {
        outBuffer.fd = *static_cast<int *>(propertyAshmem->extend.data);
        outBuffer.capacity = propertyAshmem->data.size;
        outBuffer.filledLen = propertyAshmem->data.size;
    }
    return fillRes;
}

bool ExtEncoder::FillNclxColorProperty(std::shared_ptr<ImageItem>& item, size_t& offset, ColourInfo& colorInfo)
{
    ColorType colorType = ColorType::NCLX;
    if (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType))) {
        IMAGE_LOGE("Fill colorType failed");
        return false;
    }
    if (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::COLOR_INFO, &colorInfo, sizeof(ColourInfo))) {
        IMAGE_LOGI("Fill colorInfo failed");
        return false;
    }
    return true;
}

bool ExtEncoder::AssembleOutputSharedBuffer(SharedBuffer& outBuffer, std::shared_ptr<AbsMemory>& outMem)
{
    if (output_ == nullptr) {
        IMAGE_LOGE("AssembleOutputSharedBuffer output_ is nullptr");
        return false;
    }
    OutputStreamType outType = output_->GetType();
    if (outType == OutputStreamType::FILE_PACKER) {
        auto fileOutput = reinterpret_cast<FilePackerStream*>(output_);
        outBuffer.fd = fileOutput->GetFd();
        return true;
    }
    size_t outputCapacity = DEFAULT_OUTPUT_SIZE;
    output_->GetCapicity(outputCapacity);
    std::shared_ptr<AbsMemory> mem = AllocateNewSharedMem(outputCapacity, OUTPUT_ASHMEM_TAG);
    if (mem == nullptr) {
        IMAGE_LOGE("AssembleOutputSharedBuffer alloc out sharemem failed");
        return false;
    }
    outMem = mem;
    tmpMemoryList_.push_back(mem);
    outBuffer.fd = *static_cast<int *>(mem->extend.data);
    outBuffer.capacity = outputCapacity;
    return true;
}

void ExtEncoder::AssembleDualHdrRefItem(std::vector<ItemRef>& refs)
{
    auto item = std::make_shared<ItemRef>();
    item->type = ReferenceType::DIMG;
    item->from = TMAP_IMAGE_ITEM_ID;
    item->to.resize(INDEX_TWO);
    item->to[INDEX_ZERO] = PRIMARY_IMAGE_ITEM_ID;
    item->to[INDEX_ONE] = GAINMAP_IMAGE_ITEM_ID;
    refs.push_back(*item);
}

uint32_t ExtEncoder::DoHeifEncode(std::vector<ImageItem>& inputImgs, std::vector<MetaItem>& inputMetas,
    std::vector<ItemRef>& refs)
{
    SharedBuffer outputBuffer {};
    std::shared_ptr<AbsMemory> outputAshmem;
    bool tempRes = AssembleOutputSharedBuffer(outputBuffer, outputAshmem);
    if (!tempRes) {
        IMAGE_LOGE("ExtEncoder::DoHeifEncode alloc sharedbuffer failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    sptr<ICodecImage> codec = GetCodecManager();
    if (codec == nullptr) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    uint32_t outSize = DEFAULT_OUTPUT_SIZE;
    int32_t encodeRes = codec->DoHeifEncode(inputImgs, inputMetas, refs, outputBuffer, outSize);
    if (encodeRes != HDF_SUCCESS) {
        IMAGE_LOGE("ExtEncoder::DoHeifEncode DoHeifEncode failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    if (output_->GetType() != OutputStreamType::FILE_PACKER) {
        bool writeRes = output_->Write(reinterpret_cast<uint8_t *>(outputAshmem->data.data), outSize);
        if (!writeRes) {
            IMAGE_LOGE("ExtEncoder:;DoHeifEncode Write failed");
            return ERR_IMAGE_ENCODE_FAILED;
        }
    }
    IMAGE_LOGI("ExtEncoder::DoHeifEncode output type is %{public}d", output_->GetType());
    return SUCCESS;
}

std::shared_ptr<ImageItem> ExtEncoder::AssembleTmapImageItem(ColorManager::ColorSpaceName color,
    HdrMetadata metadata, const PlEncodeOptions &opts)
{
    auto item = std::make_shared<ImageItem>();
    item->id = TMAP_IMAGE_ITEM_ID;
    item->itemName = "Tone-mapped representation";
    item->isPrimary = false;
    item->isHidden = false;
    item->compressType = COMPRESS_TYPE_TMAP;
    item->quality = opts.quality;
    item->sharedProperties.fd = -1;
    ColourInfo colorInfo;
    GetColourInfo(color, colorInfo);
    ContentLightLevel light;
    MasteringDisplayColourVolume colour;
    bool hasLight = GetStaticMetadata(metadata, colour, light);
    uint32_t propertiesSize = 0;
    propertiesSize +=
        (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType) + sizeof(PropertyType::COLOR_INFO) + sizeof(ColourInfo));
    if (hasLight) {
        propertiesSize += (sizeof(PropertyType::CONTENT_LIGHT_LEVEL) + sizeof(ContentLightLevel));
    }
    ToneMapMetadata toneMap;
    bool hasToneMap = GetToneMapMetadata(metadata, toneMap);
    if (hasToneMap) {
        propertiesSize += (sizeof(PropertyType::TONE_MAP_METADATA) + sizeof(ToneMapMetadata));
    }
    item->liteProperties.resize(propertiesSize);
    size_t offset = 0;
    if (!FillNclxColorProperty(item, offset, colorInfo)) {
        return nullptr;
    }
    if (hasLight && (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::CONTENT_LIGHT_LEVEL, &colour, sizeof(ContentLightLevel)))) {
        IMAGE_LOGE("AssembleTmapImageItem fill CONTENT_LIGHT_LEVEL failed");
        return nullptr;
    }
    if (hasToneMap && (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::TONE_MAP_METADATA, &toneMap, sizeof(ToneMapMetadata)))) {
        IMAGE_LOGE("AssembleTmapImageItem fill toneMap failed");
        return nullptr;
    }
    if (!AssembleIT35SharedBuffer(metadata, item->sharedProperties)) {
        IMAGE_LOGE("AssembleTmapImageItem fill it35 failed");
        return nullptr;
    }
    return item;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
std::shared_ptr<ImageItem> ExtEncoder::AssemblePrimaryImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
    const PlEncodeOptions &opts)
{
    if (pixelmap_ == nullptr || surfaceBuffer == nullptr) {
        IMAGE_LOGE("AssemblePrimaryImageItem surfaceBuffer is nullptr");
        return nullptr;
    }
    auto item = std::make_shared<ImageItem>();
    item->id = PRIMARY_IMAGE_ITEM_ID;
    item->pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    item->isPrimary = true;
    item->isHidden = false;
    item->compressType = COMPRESS_TYPE_HEVC;
    item->quality = opts.quality;
    item->sharedProperties.fd = -1;
    sk_sp<SkData> iccProfile = icc_from_color_space(ToSkInfo(pixelmap_));
    bool tempRes = AssembleICCImageProperty(iccProfile, item->sharedProperties);
    if (!tempRes) {
        return nullptr;
    }
    uint32_t litePropertiesSize = 0;
    litePropertiesSize += (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item->liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    ColorType colorType = ColorType::RICC;
    if (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType))) {
        IMAGE_LOGE("AssemblePrimaryImageItem Fill color type failed");
        return nullptr;
    }
    return item;
}
#endif

void ExtEncoder::AssembleExifRefItem(std::vector<ItemRef>& refs)
{
    auto item = std::make_shared<ItemRef>();
    item->type = ReferenceType::CDSC;
    item->from = EXIF_META_ITEM_ID;
    item->to.resize(INDEX_ONE);
    item->to[INDEX_ZERO] = PRIMARY_IMAGE_ITEM_ID;
    refs.push_back(*item);
}

bool ExtEncoder::AssembleExifMetaItem(std::vector<MetaItem>& metaItems)
{
    if (!opts_.needsPackProperties) {
        IMAGE_LOGD("no need encode exif");
        return false;
    }
    if (pixelmap_ == nullptr || pixelmap_->GetExifMetadata() == nullptr ||
        pixelmap_->GetExifMetadata()->GetExifData() == nullptr) {
        IMAGE_LOGD("no exif");
        return false;
    }
    ExifData* exifData = pixelmap_->GetExifMetadata()->GetExifData();
    uint8_t* exifBlob = nullptr;
    uint32_t exifSize = 0;
    TiffParser::Encode(&exifBlob, exifSize, exifData);
    if (exifBlob == nullptr) {
        IMAGE_LOGE("Encode exif data failed");
        return false;
    }
    auto item = std::make_shared<MetaItem>();
    item->id = EXIF_META_ITEM_ID;
    item->itemName = "exif";
    item->data.fd = -1;
    std::shared_ptr<AbsMemory> propertyAshmem = AllocateNewSharedMem(exifSize + EXIF_PRE_SIZE, EXIF_ASHMEM_TAG);
    if (propertyAshmem == nullptr) {
        if (exifBlob != nullptr) {
            free(exifBlob);
            exifBlob = nullptr;
        }
        IMAGE_LOGE("AssembleExifMetaItem alloc propertyAshmem failed");
        return false;
    }
    tmpMemoryList_.push_back(propertyAshmem);
    uint8_t* memData = reinterpret_cast<uint8_t*>(propertyAshmem->data.data);
    size_t memSize = propertyAshmem->data.size;
    bool fillRes = (memcpy_s(memData, memSize, EXIF_PRE_TAG, EXIF_PRE_SIZE) == EOK) &&
        (memcpy_s(memData + EXIF_PRE_SIZE, memSize - EXIF_PRE_SIZE, exifBlob, exifSize) == EOK);
    if (fillRes) {
        item->data.fd = *static_cast<int *>(propertyAshmem->extend.data);
        item->data.capacity = propertyAshmem->data.size;
        item->data.filledLen = propertyAshmem->data.size;
        metaItems.push_back(*item);
    }
    if (exifBlob != nullptr) {
        free(exifBlob);
        exifBlob = nullptr;
    }
    return fillRes;
}
#endif
} // namespace ImagePlugin
} // namespace OHOS
