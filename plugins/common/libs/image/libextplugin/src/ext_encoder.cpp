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

#ifdef USE_M133_SKIA
#include "include/encode/SkJpegEncoder.h"
#include "include/encode/SkPngEncoder.h"
#include "include/encode/SkWebpEncoder.h"
#include "src/encode/SkImageEncoderFns.h"
#else
#include "include/core/SkImageEncoder.h"
#include "src/images/SkImageEncoderFns.h"
#endif
#include "include/core/SkBitmap.h"
#include "pixel_yuv.h"
#include "pixel_yuv_ext.h"
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
#include "image_format_convert.h"
#include "image_func_timer.h"
#include "image_fwk_ext_manager.h"
#include "hispeed_image_manager.h"
#include "image_log.h"
#include "image_system_properties.h"
#include "image_trace.h"
#include "image_type_converter.h"
#include "image_utils.h"
#include "jpeg_mpf_parser.h"
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
#include "v2_1/cm_color_space.h"
#include "vpe_utils.h"
#include "hdr_helper.h"
#include "metadata_helper.h"
#include "metadata_convertor.h"
#endif
#include "color_utils.h"
#include "tiff_parser.h"
#include "image_mime_type.h"
#include "securec.h"
#include "buffer_packer_stream.h"
#include "file_packer_stream.h"
#include "memory_manager.h"
#ifdef HEIF_HW_ENCODE_ENABLE
#include "v2_1/icodec_image.h"
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
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;
const std::map<PixelFormat, GraphicPixelFormat> SURFACE_FORMAT_MAP = {
    { PixelFormat::RGBA_8888, GRAPHIC_PIXEL_FMT_RGBA_8888 },
    { PixelFormat::NV21, GRAPHIC_PIXEL_FMT_YCRCB_420_SP },
    { PixelFormat::NV12, GRAPHIC_PIXEL_FMT_YCBCR_420_SP },
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

#endif

namespace {
    constexpr static uint32_t PRIMARY_IMAGE_ITEM_ID = 1;
    constexpr static uint32_t GAINMAP_IMAGE_ITEM_ID = 2;
    constexpr static uint32_t TMAP_IMAGE_ITEM_ID = 3;
    constexpr static uint32_t EXIF_META_ITEM_ID = 4;
    constexpr static uint32_t DEPTH_MAP_ITEM_ID = 5;
    constexpr static uint32_t UNREFOCUS_MAP_ITEM_ID = 6;
    constexpr static uint32_t LINEAR_MAP_ITEM_ID = 7;
    constexpr static uint32_t FRAGMENT_MAP_ITEM_ID = 8;
    constexpr static uint32_t XTSTYLE_META_ITEM_ID = 9;
    constexpr static uint32_t RFDATAB_META_ITEM_ID = 10;
    constexpr static uint32_t STDATA_META_ITEM_ID = 11;
    constexpr static uint32_t THUMBNAIL_ITEM_ID = 22;
    const static std::string COMPRESS_TYPE_TMAP = "tmap";
    const static std::string COMPRESS_TYPE_HEVC = "hevc";
    const static std::string COMPRESS_TYPE_NONE = "none";
    const static std::string DEFAULT_ASHMEM_TAG = "Heif Encoder Default";
    const static std::string ICC_ASHMEM_TAG = "Heif Encoder Property";
    const static std::string IT35_ASHMEM_TAG = "Heif Encoder IT35";
    const static std::string OUTPUT_ASHMEM_TAG = "Heif Encoder Output";
    const static std::string IMAGE_DATA_TAG = "Heif Encoder Image";
    const static std::string HDR_GAINMAP_TAG = "Heif Encoder Gainmap";
    const static std::string EXIF_ASHMEM_TAG = "Heif Encoder Exif";
    const static std::string XTSTYLE_ASHMEM_TAG = "Heif Encoder XtStyle";
    const static std::string RFDATAB_ASHMEM_TAG = "Heif Encoder RfDataB";
    const static std::string STDATA_ASHMEM_TAG = "Heif Encoder STData";
    const static std::string GAINMAP_IMAGE_ITEM_NAME = "Gain map Image";
    const static std::string DEPTH_MAP_ITEM_NAME =  "Depth Map Image";
    const static std::string UNREFOCUS_MAP_ITEM_NAME = "Unrefocus Map Image";
    const static std::string LINEAR_MAP_ITEM_NAME = "Linear Map Image";
    const static std::string FRAGMENT_MAP_ITEM_NAME = "Fragment Map Image";
    const static std::string THUMBNAIL_ITEM_NAME = "Thumbnail Image";
    const static std::string XTSTYLE_METADATA_ITEM_NAME = "urn:com:huawei:photo:5:1:0:meta:xtstyle";
    const static std::string RFDATAB_METADATA_ITEM_NAME = "RfDataB\0";
    const static std::string STDATA_METADATA_ITEM_NAME = "STData\0";
    const static size_t DEFAULT_OUTPUT_SIZE = 35 * 1024 * 1024; // 35M
    const static uint16_t STATIC_METADATA_COLOR_SCALE = 50000;
    const static uint16_t STATIC_METADATA_LUM_SCALE = 10000;
    const static uint8_t INDEX_ZERO = 0;
    const static uint8_t INDEX_ONE = 1;
    const static uint8_t INDEX_TWO = 2;
    const static int32_t INVALID_FD = -1;
    constexpr uint32_t DEFAULT_DENOMINATOR = 1000000;
    constexpr uint8_t GAINMAP_CHANNEL_MULTI = 3;
    constexpr uint8_t GAINMAP_CHANNEL_SINGLE = 1;
    constexpr uint8_t EXIF_PRE_SIZE = 6;
    constexpr uint32_t JPEG_MARKER_TAG_SIZE = 2;
    constexpr uint32_t DEPTH_MAP_BYTES = sizeof(float); // float16
    constexpr uint32_t LINEAR_MAP_BYTES = sizeof(short) * 3 / 2; // 16bit yuv420
    constexpr uint32_t PLACE_HOLDER_LENGTH = 1;
    constexpr uint32_t LOW_QUALITY_BOUNDARY = 50;
    constexpr uint32_t RGBA8888_PIXEL_BYTES = 4;
    static constexpr uint32_t TRANSFUNC_OFFSET = 8;
    static constexpr uint32_t MATRIX_OFFSET = 8;
    static constexpr uint32_t RANGE_OFFSET = 8;
    constexpr uint32_t HIGHEST_QUALITY = 100;
    constexpr uint32_t DEFAULT_QUALITY = 75;

    const static std::map<MetadataType, std::tuple<uint32_t, std::string, std::string>>
    HEIF_METADATA_MAPPING = {
        {MetadataType::XTSTYLE, std::make_tuple(XTSTYLE_META_ITEM_ID, XTSTYLE_ASHMEM_TAG, XTSTYLE_METADATA_ITEM_NAME)},
        {MetadataType::RFDATAB, std::make_tuple(RFDATAB_META_ITEM_ID, RFDATAB_ASHMEM_TAG, RFDATAB_METADATA_ITEM_NAME)},
        {MetadataType::STDATA, std::make_tuple(STDATA_META_ITEM_ID, STDATA_ASHMEM_TAG, STDATA_METADATA_ITEM_NAME)}
    };

    // exif/0/0
    constexpr uint8_t EXIF_PRE_TAG[EXIF_PRE_SIZE] = {
        0x45, 0x78, 0x69, 0x66, 0x00, 0x00
    };
}

struct HeifEncodeItemInfo {
    uint32_t itemId = 0;
    std::string itemName = "";
    std::string itemType = "";
};

static const std::map<std::string, SkEncodedImageFormat> FORMAT_NAME = {
    {IMAGE_BMP_FORMAT, SkEncodedImageFormat::kBMP},
    {IMAGE_GIF_FORMAT, SkEncodedImageFormat::kGIF},
    {IMAGE_ICO_FORMAT, SkEncodedImageFormat::kICO},
    {IMAGE_JPEG_FORMAT, SkEncodedImageFormat::kJPEG},
    {IMAGE_PNG_FORMAT, SkEncodedImageFormat::kPNG},
    {IMAGE_WBMP_FORMAT, SkEncodedImageFormat::kWBMP},
    {IMAGE_WEBP_FORMAT, SkEncodedImageFormat::kWEBP},
    {IMAGE_HEIF_FORMAT, SkEncodedImageFormat::kHEIF},
    {IMAGE_HEIC_FORMAT, SkEncodedImageFormat::kHEIF},
};

static const std::map<AuxiliaryPictureType, std::string> DEFAULT_AUXILIARY_TAG_MAP = {
    {AuxiliaryPictureType::GAINMAP, AUXILIARY_TAG_GAINMAP},
    {AuxiliaryPictureType::DEPTH_MAP, AUXILIARY_TAG_DEPTH_MAP_BACK},
    {AuxiliaryPictureType::UNREFOCUS_MAP, AUXILIARY_TAG_UNREFOCUS_MAP},
    {AuxiliaryPictureType::LINEAR_MAP, AUXILIARY_TAG_LINEAR_MAP},
    {AuxiliaryPictureType::FRAGMENT_MAP, AUXILIARY_TAG_FRAGMENT_MAP},
    {AuxiliaryPictureType::THUMBNAIL, AUXILIARY_TAG_THUMBNAIL},
};

static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;
static const uint8_t RGBA_BIT_DEPTH = 4;

static const int32_t PLANE_Y = 0;
static const int32_t PLANE_U = 1;
static const int32_t PLANE_V = 2;

static constexpr int32_t MAX_IMAGE_SIZE = 32768;
static constexpr int32_t MIN_IMAGE_SIZE = 128;
static constexpr int32_t MIN_RGBA_IMAGE_SIZE = 1024;
static constexpr uint32_t EXIF_MAX_SIZE = 64 * 1024; // 64K

#ifdef HEIF_HW_ENCODE_ENABLE
using namespace OHOS::HDI::Codec::Image::V2_1;
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
    bool cond = g_codecMgr == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "ICodecImage get failed");
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

uint32_t ExtEncoder::AddPicture(Media::Picture &picture)
{
    picture_ = &picture;
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
    bool cond = pixelmap->InnerGetGrColorSpacePtr() == nullptr;
    CHECK_ERROR_RETURN_RET(cond, nullptr);

    cond = pixelmap->InnerGetGrColorSpace().GetColorSpaceName() == ColorManager::ColorSpaceName::NONE;
    CHECK_ERROR_RETURN_RET(cond, SkColorSpace::MakeSRGB());
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
    if (pixelMap->InnerGetGrColorSpacePtr() != nullptr &&
        pixelMap->InnerGetGrColorSpace().GetColorSpaceName() != ColorManager::ColorSpaceName::NONE) {
        colorSpace = pixelMap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
    }
#endif
    return SkImageInfo::Make(info.size.width, info.size.height, colorType, alphaType, colorSpace);
}

static sk_sp<SkColorSpace> ToHdrEncodeSkColorSpace(Media::PixelMap *pixelmap,
    sptr<SurfaceBuffer>& buffer, bool sdrIsSRGB, bool isGainmap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    // get graphic colorspace
    ColorManager::ColorSpaceName graphicColorSpaceName = ColorManager::ColorSpaceName::SRGB;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    CM_ColorSpaceType color;
    VpeUtils::GetSbColorSpaceType(buffer, color);
    auto iter = CM_COLORSPACE_NAME_MAP.find(color);
    if (iter != CM_COLORSPACE_NAME_MAP.end()) {
        graphicColorSpaceName = iter->second;
    }
#endif
    skcms_CICP cicp;
    ColorUtils::ColorSpaceGetCicp(graphicColorSpaceName,
    #ifdef USE_M133_SKIA
        cicp.color_primaries, cicp.transfer_characteristics, cicp.matrix_coefficients, cicp.video_full_range_flag);
#else
        cicp.colour_primaries, cicp.transfer_characteristics, cicp.matrix_coefficients, cicp.full_range_flag);
#endif
    sk_sp<SkColorSpace> colorSpace =
        SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, sdrIsSRGB? SkNamedGamut::kSRGB : SkNamedGamut::kDisplayP3);
    colorSpace->SetIccCicp(cicp);
    return colorSpace;
#endif
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
    ConvertDataInfo srcDataInfo = {srcData, static_cast<size_t>(pixelMap->GetByteCount()), info.size,
                                   info.pixelFormat, pixelMap->GetColorSpace(), yuvInfo};
    DestConvertInfo dstDataInfo;
    dstDataInfo.format = PixelFormat::RGBA_8888;
    dstDataInfo.allocType = AllocatorType::HEAP_ALLOC;
    IMAGE_LOGD("HDR-IMAGE yuvToRgba width : %{public}d, height : %{public}d",
               srcDataInfo.imageSize.width, srcDataInfo.imageSize.height);
    ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<const char*>(srcDataInfo.buffer), srcDataInfo.bufferSize,
                                      "beforeConvert");
    bool cond = ImageFormatConvert::ConvertImageFormat(srcDataInfo, dstDataInfo) != SUCCESS;
    ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<const char*>(dstDataInfo.buffer), dstDataInfo.bufferSize,
                                      "afterConvert");
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "YuvToSkInfo Support YUV format RGB convert failed ");
    cond  = memcpy_s(dstData, info.size.width * info.size.height * RGBA8888_PIXEL_BYTES,
        dstDataInfo.buffer, dstDataInfo.bufferSize) != 0;
    delete dstDataInfo.buffer;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "YuvToSkInfo memcpy failed ");
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
    if (skInfo.colorType() == SkColorType::kRGB_888x_SkColorType &&
        pixelMap->GetCapacity() < skInfo.computeMinByteSize()) {
        uint32_t res = RGBToRGBx(pixelMap, skInfo, holder);
        bool cond = res != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond, res, "ExtEncoder::BuildSkBitmap RGB convert failed %{public}d", res);
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
    ImageFuncTimer imageFuncTimer("insert exif data (%d, %d)", imageInfo.size.width, imageInfo.size.height);
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

bool IsWideGamutSdrPixelMap(Media::PixelMap* pixelmap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    return pixelmap->InnerGetGrColorSpace().GetColorSpaceName() ==
        OHOS::ColorManager::ColorSpaceName::DISPLAY_BT2020_SRGB ? true : false;
#else
    return false;
#endif
}

bool IsHdrColorSpace(Media::PixelMap* pixelmap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace colorSpace = pixelmap->InnerGetGrColorSpace();
    if (colorSpace.GetColorSpaceName() != ColorManager::BT2020 &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_HLG &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_PQ &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_HLG_LIMIT &&
        colorSpace.GetColorSpaceName() != ColorManager::BT2020_PQ_LIMIT) {
        return false;
    }
#endif
    return true;
}

uint32_t ExtEncoder::PixelmapEncode(ExtWStream& wStream)
{
    uint32_t error;
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGD("pixelmapEncode EncodeImageByPixelMap");
    error = EncodeImageByPixelMap(pixelmap_, opts_.needsPackProperties, wStream);
#else
    switch (opts_.desiredDynamicRange) {
        case EncodeDynamicRange::AUTO:
            if ((pixelmap_->IsHdr() || IsWideGamutSdrPixelMap(pixelmap_)) &&
                (encodeFormat_ == SkEncodedImageFormat::kJPEG || encodeFormat_ == SkEncodedImageFormat::kHEIF)) {
                error = EncodeDualVivid(wStream);
            } else if (pixelmap_->GetAllocatorType() == AllocatorType::DMA_ALLOC &&
                ImageUtils::Is10Bit(pixelmap_->GetPixelFormat()) && !IsHdrColorSpace(pixelmap_)) {
                error = Encode10bitSdrPixelMap(pixelmap_, wStream);
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
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
bool IsSuperFastEncode(const std::string &format)
{
    return SUT_FORMAT_MAP.find(format) != SUT_FORMAT_MAP.end() ||
        ASTC_FORMAT_MAP.find(format) != ASTC_FORMAT_MAP.end();
}
#endif

uint32_t ExtEncoder::FinalizeEncode()
{
    bool isParameterInvalid = (picture_ == nullptr && pixelmap_ == nullptr) || output_ == nullptr;
    CHECK_ERROR_RETURN_RET(isParameterInvalid, ERR_IMAGE_INVALID_PARAMETER);
    ImageDataStatistics imageDataStatistics("[ExtEncoder]FinalizeEncode imageFormat = %s, quality = %d",
        opts_.format.c_str(), opts_.quality);
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (IsAstc(opts_.format) || IsSuperFastEncode(opts_.format)) {
        AstcCodec astcEncoder;
        astcEncoder.SetAstcEncode(output_, opts_, pixelmap_);
        return astcEncoder.ASTCEncode();
    }
#endif
    auto iter = FORMAT_NAME.find(LowerStr(opts_.format));
    if (iter == FORMAT_NAME.end()) {
        IMAGE_LOGE("ExtEncoder::FinalizeEncode unsupported format %{public}s", opts_.format.c_str());
        ReportEncodeFault(0, 0, opts_.format, "Unsupported format:" + opts_.format);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (picture_ != nullptr) {
        encodeFormat_ = iter->second;
        return EncodePicture();
    }
#endif
    ImageInfo imageInfo;
    pixelmap_->GetImageInfo(imageInfo);
    imageDataStatistics.AddTitle(", width = %d, height =%d", imageInfo.size.width, imageInfo.size.height);
    encodeFormat_ = iter->second;
    ExtWStream wStream(output_);
    return PixelmapEncode(wStream);
}

bool ExtEncoder::IsHardwareEncodeSupported(const PlEncodeOptions &opts, Media::PixelMap* pixelMap)
{
    CHECK_ERROR_RETURN_RET_LOG(pixelMap == nullptr, false, "pixelMap is nullptr");
    bool cond = opts.quality < LOW_QUALITY_BOUNDARY;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s Low quality use software encode", __func__);
    bool isSupportedWithRgba = ImageSystemProperties::GetGenThumbWithGpu() &&
        pixelMap->GetPixelFormat() == PixelFormat::RGBA_8888;
    bool isSupport = ImageSystemProperties::GetHardWareEncodeEnabled() && opts.format == "image/jpeg" &&
        (pixelMap->GetWidth() % 2 == 0) && (pixelMap->GetHeight() % 2 == 0) &&
        (pixelMap->GetPixelFormat() == PixelFormat::NV12 || pixelMap->GetPixelFormat() == PixelFormat::NV21 ||
        isSupportedWithRgba) &&
        pixelMap->GetWidth() <= MAX_IMAGE_SIZE && pixelMap->GetHeight() <= MAX_IMAGE_SIZE &&
        pixelMap->GetWidth() >= MIN_RGBA_IMAGE_SIZE && pixelMap->GetHeight() >= MIN_RGBA_IMAGE_SIZE;
    CHECK_DEBUG_PRINT_LOG(!isSupport,
        "hardware encode is not support, dstEncodeFormat:%{public}s, pixelWidth:%{public}d, pixelHeight:%{public}d, "
        "pixelFormat:%{public}d",
        opts.format.c_str(), pixelMap->GetWidth(), pixelMap->GetHeight(), pixelMap->GetPixelFormat());
    return isSupport;
}

uint32_t ExtEncoder::DoHardWareEncode(SkWStream* skStream)
{
    static ImageFwkExtManager imageFwkExtManager;
    if (imageFwkExtManager.doHardWareEncodeFunc_ != nullptr || imageFwkExtManager.LoadImageFwkExtNativeSo()) {
        int32_t retCode = imageFwkExtManager.doHardWareEncodeFunc_(skStream, opts_, pixelmap_);
        CHECK_DEBUG_RETURN_RET_LOG(retCode == SUCCESS, SUCCESS, "DoHardWareEncode Success return");
        IMAGE_LOGE("hardware encode failed, retCode is %{public}d", retCode);
        ImageInfo imageInfo;
        pixelmap_->GetImageInfo(imageInfo);
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, "hardware encode failed");
    } else {
        IMAGE_LOGE("hardware encode failed because of load native so failed");
    }
    return ERR_IMAGE_ENCODE_FAILED;
}

#ifdef USE_M133_SKIA
bool ExtEncoder::SkEncodeImage(SkWStream* dst, const SkBitmap& src, SkEncodedImageFormat format, int quality)
{
    SkPixmap pixmap;
    if (!src.peekPixels(&pixmap)) {
        return false;
    }
    switch (format) {
        case SkEncodedImageFormat::kJPEG: {
            SkJpegEncoder::Options opts;
            opts.fQuality = quality;
            return SkJpegEncoder::Encode(dst, pixmap, opts);
        }
        case SkEncodedImageFormat::kPNG: {
            SkPngEncoder::Options opts;
            return SkPngEncoder::Encode(dst, pixmap, opts);
        }
        case SkEncodedImageFormat::kWEBP: {
            SkWebpEncoder::Options opts;
            if (quality == HIGHEST_QUALITY) {
                opts.fCompression = SkWebpEncoder::Compression::kLossless;
                // Note: SkEncodeImage treats 0 quality as the lowest quality
                // (greatest compression) and 100 as the highest quality (least
                // compression). For kLossy, this matches libwebp's
                // interpretation, so it is passed directly to libwebp. But
                // with kLossless, libwebp always creates the highest quality
                // image. In this case, fQuality is reinterpreted as how much
                // effort (time) to put into making a smaller file. This API
                // does not provide a way to specify this value (though it can
                // be specified by using SkWebpEncoder::Encode) so we have to
                // pick one arbitrarily. This value matches that chosen by
                // blink::ImageEncoder::ComputeWebpOptions as well
                // WebPConfigInit.
                opts.fQuality = DEFAULT_QUALITY;
            } else {
                opts.fCompression = SkWebpEncoder::Compression::kLossy;
                opts.fQuality = quality;
            }
            return SkWebpEncoder::Encode(dst, pixmap, opts);
        }
        default:
            return false;
    }
}
#endif

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

bool ExtEncoder::HispeedEncode(SkWStream &skStream, Media::PixelMap *pixelMap, bool needExif, SkImageInfo info)
{
    CHECK_ERROR_RETURN_RET_LOG(pixelMap == nullptr, false, "pixelMap is nullptr");
    uint32_t retCode = ERR_IMAGE_ENCODE_FAILED;
    if (!needExif || pixelMap->GetExifMetadata() == nullptr || pixelMap->GetExifMetadata()->GetExifData() == nullptr) {
        retCode = HispeedImageManager::GetInstance().DoEncodeJpeg(&skStream, pixelmap_, opts_.quality, info);
        IMAGE_LOGD("HispeedEncode retCode:%{public}d", retCode);
        return (retCode == SUCCESS);
    }
    MetadataWStream tStream;
    retCode = HispeedImageManager::GetInstance().DoEncodeJpeg(&tStream, pixelmap_, opts_.quality, info);
    bool cond = retCode != SUCCESS;
    CHECK_DEBUG_RETURN_RET_LOG(cond, false, "HispeedEncode failed, retCode:%{public}d", retCode);
    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    retCode = CreateAndWriteBlob(tStream, pixelMap, skStream, imageInfo, opts_);
    IMAGE_LOGD("HispeedEncode retCode:%{public}d", retCode);
    return (retCode == SUCCESS);
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
        bool cond = retCode != SUCCESS;
        CHECK_DEBUG_RETURN_RET_LOG(cond, false, "HardwareEncode failed, retCode:%{public}d", retCode);
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
    bool cond = errCode != SUCCESS;
    CHECK_ERROR_RETURN_RET(cond, errCode);
    return CreateAndWriteBlob(tStream, pixelmap_, outStream, imageInfo, opts_);
}

uint32_t ExtEncoder::EncodeImageByPixelMap(PixelMap* pixelmap, bool needExif, SkWStream& outputStream)
{
    if (encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        return EncodeHeifByPixelmap(pixelmap, opts_);
    }
    SkBitmap bitmap;
    TmpBufferHolder holder;
    SkImageInfo skInfo;
    ImageData imageData;
    pixelmap->GetImageInfo(imageData.info);
    uint32_t width  = static_cast<uint32_t>(imageData.info.size.width);
    uint32_t height = static_cast<uint32_t>(imageData.info.size.height);
    bool cond = HardwareEncode(outputStream, needExif) == true;
    CHECK_DEBUG_RETURN_RET_LOG(cond, SUCCESS, "HardwareEncode Success return");
    IMAGE_LOGD("HardwareEncode failed or not Supported");
    std::unique_ptr<uint8_t[]> dstData;
    uint64_t rowStride = 0;
    if (IsYuvImage(imageData.info.pixelFormat)) {
        IMAGE_LOGD("YUV format, convert to RGB");
        dstData = std::make_unique<uint8_t[]>(width * height * NUM_4);
        if (YuvToRgbaSkInfo(imageData.info, skInfo, dstData.get(), pixelmap) != SUCCESS) {
            IMAGE_LOGD("YUV format, convert to RGB fail");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        imageData.pixels = dstData.get();
        rowStride = skInfo.minRowBytes64();
    } else {
        dstData = std::make_unique<uint8_t[]>(width * height * NUM_3);
        imageData.dst = dstData.get();
        cond = pixelToSkInfo(imageData, skInfo, pixelmap, holder, encodeFormat_) != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED,
            "ExtEncoder::EncodeImageByPixelMap pixel convert failed");
        rowStride = skInfo.minRowBytes64();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        if (pixelmap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
            SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (pixelmap->GetFd());
            rowStride = static_cast<uint64_t>(sbBuffer->GetStride());
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
    CHECK_ERROR_RETURN_RET(output_ == nullptr, ERR_IMAGE_INVALID_PARAMETER);
    Media::PixelFormat format = pixelmap->GetPixelFormat();
    bool cond = format != PixelFormat::RGBA_8888 && format != PixelFormat::NV12 && format != PixelFormat::NV21;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "EncodeHeifByPixelmap, invalid format:%{public}d", format);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM) && \
    defined(HEIF_HW_ENCODE_ENABLE)
    sptr<SurfaceBuffer> surfaceBuffer;
    bool needConvertToSurfaceBuffer = pixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC;
    if (needConvertToSurfaceBuffer) {
        surfaceBuffer = ConvertToSurfaceBuffer(pixelmap);
        cond = surfaceBuffer == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
            "EncodeHeifByPixelmap ConvertToSurfaceBuffer failed");
    } else {
        cond = pixelmap->GetFd() == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "EncodeHeifByPixelmap pixelmap get fd failed");
        surfaceBuffer = sptr<SurfaceBuffer>(reinterpret_cast<SurfaceBuffer*>(pixelmap->GetFd()));
        ImageUtils::FlushSurfaceBuffer(surfaceBuffer);
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
    return ERR_IMAGE_INVALID_PARAMETER;
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
    bool cond = err != OHOS::GSERROR_OK;
    CHECK_ERROR_RETURN_RET(cond, nullptr);
    return sb;
}

sptr<SurfaceBuffer> ExtEncoder::ConvertToSurfaceBuffer(PixelMap* pixelmap)
{
    bool cond = pixelmap->GetHeight() <= 0 || pixelmap->GetWidth() <= 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr,
        "pixelmap height:%{public}d or width:%{public}d error", pixelmap->GetHeight(), pixelmap->GetWidth());
    uint32_t height = static_cast<uint32_t>(pixelmap->GetHeight());
    uint32_t width = static_cast<uint32_t>(pixelmap->GetWidth());
    PixelFormat format = pixelmap->GetPixelFormat();
    IMAGE_LOGD("ExtEncoder::ConvertToSurfaceBuffer format is %{public}d", format);
    auto formatSearch = SURFACE_FORMAT_MAP.find(format);
    cond = formatSearch == SURFACE_FORMAT_MAP.end();
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "format:[%{public}d] is not in SURFACE_FORMAT_MAP", format);
    uint32_t graphicFormat = formatSearch->second;
    sptr<SurfaceBuffer> surfaceBuffer = AllocSurfaceBuffer(width, height, graphicFormat);
    cond = surfaceBuffer == nullptr || surfaceBuffer->GetStride() < 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "ConvertToSurfaceBuffer surfaceBuffer is nullptr failed");

    if (format == PixelFormat::NV12 || format == PixelFormat::NV21) {
        if (!ImageUtils::CopyYuvPixelMapToSurfaceBuffer(pixelmap, surfaceBuffer)) {
            IMAGE_LOGE("ConvertToSurfaceBuffer memcpy failed");
            ImageUtils::SurfaceBuffer_Unreference(surfaceBuffer.GetRefPtr());
            return nullptr;
        }
    } else if (format == PixelFormat::RGBA_8888) {
        uint32_t dstStride = static_cast<uint32_t>(surfaceBuffer->GetStride());
        uint8_t* src = const_cast<uint8_t*>(pixelmap->GetPixels());
        uint8_t* dst = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
        uint32_t dstSize = surfaceBuffer->GetSize();
        uint64_t srcStride = static_cast<uint64_t>(width * NUM_4);
        
        for (uint32_t i = 0; i < height; i++) {
            if (memcpy_s(dst, dstSize, src, srcStride) != EOK) {
                IMAGE_LOGE("ConvertToSurfaceBuffer memcpy failed");
                ImageUtils::SurfaceBuffer_Unreference(surfaceBuffer.GetRefPtr());
                return nullptr;
            }
            dst += dstStride;
            dstSize -= dstStride;
            src += srcStride;
        }
    }

    ImageUtils::FlushSurfaceBuffer(surfaceBuffer);
    return surfaceBuffer;
}

sptr<SurfaceBuffer> ExtEncoder::ConvertPixelMapToDmaBuffer(std::shared_ptr<PixelMap> pixelmap)
{
    sptr<SurfaceBuffer> surfaceBuffer;
    if (pixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        surfaceBuffer = ConvertToSurfaceBuffer(pixelmap.get());
    } else {
        surfaceBuffer = sptr<SurfaceBuffer>(reinterpret_cast<SurfaceBuffer*>(pixelmap->GetFd()));
        ImageUtils::FlushSurfaceBuffer(surfaceBuffer);
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
    CHECK_ERROR_RETURN_RET_LOG(surfaceBuffer == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "EncodeImageBySurfaceBuffer failed, surfaceBuffer is nullptr");
    auto pixels = surfaceBuffer->GetVirAddr();
    CHECK_ERROR_RETURN_RET_LOG(pixels == nullptr, ERR_IMAGE_INVALID_PARAMETER,
        "EncodeImageBySurfaceBuffer failed, pixels is nullptr");
    /* do hardwareEncode first, if fail then soft encode*/
    bool cond = HardwareEncode(outputStream, needExif);
    CHECK_DEBUG_RETURN_RET_LOG(cond, SUCCESS, "HardwareEncode Success return");
    IMAGE_LOGD("HardwareEncode failed or not Supported");

    pixelmap_->GetImageInfo(imageInfo);
    cond = !PixelYuvUtils::CheckWidthAndHeightMult(imageInfo.size.width, imageInfo.size.height, RGBA_BIT_DEPTH);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "EncodeImageBySurfaceBuffer size overflow width(%{public}d), height(%{public}d)",
        imageInfo.size.width, imageInfo.size.height);
    std::unique_ptr<uint8_t[]> dstData;
    if (IsYuvImage(imageInfo.pixelFormat)) {
        IMAGE_LOGD("EncodeImageBySurfaceBuffer: YUV format, convert to RGB first");
        dstData = std::make_unique<uint8_t[]>(imageInfo.size.width * imageInfo.size.height * NUM_4);
        cond = dstData == nullptr;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "Memory allocate fail");
        cond = YuvToRgbaSkInfo(imageInfo, info, dstData.get(), pixelmap_) != SUCCESS;
        CHECK_DEBUG_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "YUV format, convert to RGB fail");
        pixels = dstData.get();
        rowStride = info.minRowBytes64();
    } else {
        rowStride = static_cast<uint64_t>(surfaceBuffer->GetStride());
    }
    cond = !bitmap.installPixels(info, pixels, rowStride);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED,
        "ExtEncoder::EncodeImageBySurfaceBuffer to SkBitmap failed");
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

void ExtEncoder::SetHdrColorSpaceType(sptr<SurfaceBuffer>& surfaceBuffer)
{
    if (pixelmap_ == nullptr) {
        IMAGE_LOGI("SetHdrColorSpaceType pixelmap_ is nullptr");
        return;
    }
    CM_ColorSpaceType colorspaceType;
    VpeUtils::GetSbColorSpaceType(surfaceBuffer, colorspaceType);
    if ((colorspaceType & CM_PRIMARIES_MASK) != COLORPRIMARIES_BT2020) {
#ifdef IMAGE_COLORSPACE_FLAG
        ColorManager::ColorSpaceName colorspace = pixelmap_->InnerGetGrColorSpace().GetColorSpaceName();
        IMAGE_LOGI("ExtEncoder SetHdrColorSpaceType, color is %{public}d", colorspace);
        colorspaceType = ColorUtils::ConvertToCMColor(colorspace);
        VpeUtils::SetSbColorSpaceType(surfaceBuffer, colorspaceType);
#endif
    }
}

static bool DecomposeImage(VpeSurfaceBuffers& buffers, HdrMetadata& metadata, bool onlySdr, bool sdrIsSRGB = false)
{
    VpeUtils::SetSbMetadataType(buffers.sdr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(buffers.sdr, sdrIsSRGB ? CM_SRGB_FULL : CM_P3_FULL);
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res;
    if (onlySdr) {
        bool cond = buffers.hdr == nullptr || buffers.sdr == nullptr;
        CHECK_ERROR_RETURN_RET(cond, false);
        res = utils->ColorSpaceConverterImageProcess(buffers.hdr, buffers.sdr);
    } else {
        VpeUtils::SetSbMetadataType(buffers.gainmap, CM_METADATA_NONE);
        VpeUtils::SetSbColorSpaceType(buffers.gainmap, sdrIsSRGB ? CM_SRGB_FULL : CM_P3_FULL);
        res = utils->ColorSpaceConverterDecomposeImage(buffers);
    }
    bool cond = res != VPE_ERROR_OK;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "DecomposeImage [%{public}d] failed, res = %{public}d", onlySdr, res);
    if (!onlySdr) {
        metadata = GetHdrMetadata(buffers.hdr, buffers.gainmap);
    }
    return true;
}

static SkImageInfo GetSkInfo(PixelMap* pixelMap, bool isGainmap, bool isSRGB = false)
{
    ImageInfo info;
    pixelMap->GetImageInfo(info);
    SkColorType colorType = kRGBA_8888_SkColorType;
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    if (alphaType == SkAlphaType::kUnknown_SkAlphaType) {
        alphaType = SkAlphaType::kOpaque_SkAlphaType;
    }
    sk_sp<SkColorSpace> colorSpace =
        SkColorSpace::MakeRGB(SkNamedTransferFn::kSRGB, isSRGB ? SkNamedGamut::kSRGB : SkNamedGamut::kDisplayP3);
    int32_t width = info.size.width;
    int32_t height = info.size.height;
    if (isGainmap) {
        const int halfSizeDenominator = 2;
        width = width / halfSizeDenominator;
        height = height / halfSizeDenominator;
#ifdef IMAGE_COLORSPACE_FLAG
        if (pixelMap->InnerGetGrColorSpacePtr() != nullptr &&
            pixelMap->InnerGetGrColorSpace().GetColorSpaceName() != ColorManager::ColorSpaceName::NONE) {
            colorSpace = pixelMap->InnerGetGrColorSpacePtr()->ToSkColorSpace();
            skcms_CICP cicp;
            ColorUtils::ColorSpaceGetCicp(pixelMap->InnerGetGrColorSpace().GetColorSpaceName(),
#ifdef USE_M133_SKIA
            cicp.color_primaries, cicp.transfer_characteristics, cicp.matrix_coefficients, cicp.video_full_range_flag);
#else
            cicp.colour_primaries, cicp.transfer_characteristics, cicp.matrix_coefficients, cicp.full_range_flag);
#endif
            colorSpace->SetIccCicp(cicp);
        }
#endif
    }
    return SkImageInfo::Make(width, height, colorType, alphaType, colorSpace);
}

static SkImageInfo GetSkInfo(PixelMap* pixelMap, bool isGainmap, sk_sp<SkColorSpace>& colorSpace)
{
    ImageInfo info;
    pixelMap->GetImageInfo(info);
    SkColorType colorType = kRGBA_8888_SkColorType;
    SkAlphaType alphaType = ImageTypeConverter::ToSkAlphaType(info.alphaType);
    if (alphaType == SkAlphaType::kUnknown_SkAlphaType) {
        alphaType = SkAlphaType::kOpaque_SkAlphaType;
    }
    int32_t width = info.size.width;
    int32_t height = info.size.height;
    if (isGainmap) {
        const int halfSizeDenominator = 2;
        width = width / halfSizeDenominator;
        height = height / halfSizeDenominator;
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
    bool cond = memData == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "FillLitePropertyItem memData is nullptr");
    size_t memSize = properties.size();
    size_t typeSize = sizeof(type);
    size_t endOffset = offset + typeSize + payloadSize;
    cond = endOffset > memSize;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "FillLitePropertyItem, endOffset[%{public}ld] over memSize[%{public}ld]", endOffset, memSize);
    bool res = memcpy_s(memData + offset, memSize - offset, &type, typeSize) == EOK &&
        memcpy_s(memData + offset + typeSize, memSize - offset - typeSize, payloadData, payloadSize) == EOK;
    if (res) {
        offset = endOffset;
    }
    return res;
}

// format: enum + strlen + str
static bool FillLitePropertyItemByString(std::vector<uint8_t>& properties, size_t& offset, PropertyType type,
    std::string& payloadString)
{
    uint8_t* memData = properties.data();
    bool cond = memData == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s memData is nullptr", __func__);
    size_t memSize = properties.size();
    cond = payloadString == "";
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s failed, payloadString is Null", __func__);
    size_t lenSize = UINT32_BYTES_NUM;
    size_t strLen = payloadString.length();
    size_t typeSize = sizeof(type);
    size_t endOffset = offset + typeSize + lenSize + strLen;
    cond = endOffset >= memSize;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s failed, offset[%{public}ld] over memSize[%{public}ld]", __func__, offset, memSize);
    size_t capacitySize = memSize - offset;
    const char* payloadData = payloadString.data();
    bool res = memcpy_s(memData + offset, capacitySize, &type, typeSize) == EOK &&
        memcpy_s(memData + offset + typeSize, capacitySize - typeSize, &strLen, lenSize) == EOK &&
        memcpy_s(memData + offset + typeSize + lenSize, capacitySize - typeSize - lenSize, payloadData, strLen) == EOK;
    properties[endOffset] = '\0';

    if (res) {
        offset = endOffset + PLACE_HOLDER_LENGTH;
    }
    return res;
}

std::shared_ptr<ImageItem> ExtEncoder::AssembleHdrBaseImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
    ColorManager::ColorSpaceName color, HdrMetadata& metadata, const PlEncodeOptions& opts)
{
    bool cond = surfaceBuffer == nullptr;
    CHECK_INFO_RETURN_RET_LOG(cond, nullptr, "AssembleHdrBaseImageItem surfaceBuffer is nullptr");
    auto item = std::make_shared<ImageItem>();
    item->id = PRIMARY_IMAGE_ITEM_ID;
    item->isPrimary = true;
    item->isHidden = false;
    item->compressType = COMPRESS_TYPE_HEVC;
    item->quality = opts.quality;
    item->pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    item->sharedProperties.fd = INVALID_FD;
    item->pixelSharedBuffer.fd = INVALID_FD;
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
    bool cond = surfaceBuffer == nullptr;
    CHECK_INFO_RETURN_RET_LOG(cond, nullptr, "AssembleGainmapImageItem surfacebuffer is nullptr");
    auto item = std::make_shared<ImageItem>();
    item->id = GAINMAP_IMAGE_ITEM_ID;
    item->itemName = GAINMAP_IMAGE_ITEM_NAME;
    item->isPrimary = false;
    item->isHidden = true;
    item->compressType = COMPRESS_TYPE_HEVC;
    item->quality = opts.quality;
    item->sharedProperties.fd = INVALID_FD;
    item->pixelSharedBuffer.fd = INVALID_FD;
    item->pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    ColourInfo colorInfo;
    GetColourInfo(color, colorInfo);
    uint32_t propertiesSize = 0;
    propertiesSize +=
        (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType) + sizeof(PropertyType::COLOR_INFO) + sizeof(ColourInfo));
    item->liteProperties.resize(propertiesSize);
    size_t offset = 0;
    cond = !FillNclxColorProperty(item, offset, colorInfo);
    CHECK_ERROR_RETURN_RET(cond, nullptr);
    return item;
}

uint32_t ExtEncoder::AssembleHeifHdrPicture(
    sptr<SurfaceBuffer>& mainSptr, bool sdrIsSRGB, std::vector<ImageItem>& inputImgs)
{
    auto gainPixelMap = picture_->GetGainmapPixelMap();
    bool cond = gainPixelMap == nullptr || gainPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s, the gainPixelMap is nullptr or gainPixelMap is nonDMA", __func__);
    sptr<SurfaceBuffer> gainMapSptr(reinterpret_cast<SurfaceBuffer*>(gainPixelMap->GetFd()));
    ImageUtils::FlushSurfaceBuffer(gainMapSptr);
    HdrMetadata metadata = GetHdrMetadata(mainSptr, gainMapSptr);

    ColorManager::ColorSpaceName colorspaceName =
        sdrIsSRGB ? ColorManager::ColorSpaceName::SRGB : ColorManager::ColorSpaceName::DISPLAY_P3;
    std::shared_ptr<ImageItem> primaryItem = AssembleHdrBaseImageItem(mainSptr, colorspaceName, metadata, opts_);
    cond = primaryItem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s, get primary image failed", __func__);
    inputImgs.push_back(*primaryItem);
    std::shared_ptr<ImageItem> gainmapItem = AssembleGainmapImageItem(gainMapSptr, colorspaceName, opts_);
    cond = gainmapItem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s, get gainmap image item failed", __func__);
    inputImgs.push_back(*gainmapItem);
    ColorManager::ColorSpaceName tmapColor = picture_->GetMainPixel()->InnerGetGrColorSpace().GetColorSpaceName();
    std::shared_ptr<ImageItem> tmapItem = AssembleTmapImageItem(tmapColor, metadata, opts_);
    cond = tmapItem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s, get tmap image item failed", __func__);
    inputImgs.push_back(*tmapItem);
    return SUCCESS;
}

GSError ExtEncoder::HwSetColorSpaceData(Media::PixelMap* pixelmap, sptr<SurfaceBuffer>& buffer)
{
    bool cond = (buffer == nullptr || pixelmap == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, GSERROR_NO_BUFFER, "HwSetColorSpaceData buffer or pixelmap is nullptr");
    auto colorSpacename = pixelmap->InnerGetGrColorSpacePtr()->GetColorSpaceName();
    auto colorSpaceSearch = ColorUtils::COLORSPACE_NAME_TO_COLORINFO_MAP.find(colorSpacename);
    CM_ColorSpaceInfo colorSpaceInfo =
        (colorSpaceSearch != ColorUtils::COLORSPACE_NAME_TO_COLORINFO_MAP.end()) ? colorSpaceSearch->second :
        CM_ColorSpaceInfo {COLORPRIMARIES_BT601_P, TRANSFUNC_BT709, MATRIX_BT601_P, RANGE_FULL};
    std::vector<uint8_t> colorSpaceInfoVec;
    auto ret = MetadataManager::ConvertMetadataToVec(colorSpaceInfo, colorSpaceInfoVec);
    cond = ret != GSERROR_OK;
    CHECK_ERROR_RETURN_RET(cond, ret);

    IMAGE_LOGI("Encode colorspace, Primaries:%{public}d, TransFunc:%{public}d, Matrix:%{public}d, Range:%{public}d",
        colorSpaceInfo.primaries, colorSpaceInfo.transfunc,
        colorSpaceInfo.matrix, colorSpaceInfo.range);
    return buffer->SetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec);
}

uint32_t ExtEncoder::AssembleSdrImageItem(
    sptr<SurfaceBuffer>& surfaceBuffer, SkImageInfo sdrInfo, std::vector<ImageItem>& inputImgs)
{
    bool cond = surfaceBuffer == nullptr;
    CHECK_INFO_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s surfaceBuffer is nullptr", __func__);
    ImageItem item;
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(sdrInfo, nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(sdrInfo);
#endif
    cond = !AssembleICCImageProperty(iccProfile, item.sharedProperties);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s AssembleICCImageProperty failed", __func__);
    item.id = PRIMARY_IMAGE_ITEM_ID;
    auto mainPixelMap = picture_->GetMainPixel();
    cond = !mainPixelMap;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DATA_ABNORMAL, "MainPixelMap is nullptr");
    auto ret = HwSetColorSpaceData(mainPixelMap.get(), surfaceBuffer);
    cond = (ret != GSERROR_OK);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "HwSetColorSpaceInfo GetMetadata failed");
    item.pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    item.isPrimary = true;
    item.isHidden = false;
    item.compressType = COMPRESS_TYPE_HEVC;
    item.quality = opts_.quality;
    uint32_t litePropertiesSize = (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item.liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    ColorType colorType = ColorType::RICC;
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_INFO_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill color type failed", __func__);
    inputImgs.push_back(item);
    return SUCCESS;
}

uint32_t ExtEncoder::AssembleHeifThumbnail(std::vector<ImageItem>& inputImgs)
{
    bool cond = picture_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s picture_ is nullptr", __func__);
    auto thumbnail = picture_->GetAuxiliaryPicture(AuxiliaryPictureType::THUMBNAIL);
    cond = !thumbnail || !thumbnail->GetContentPixel();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s The thumbnail is nullptr", __func__);
    HeifEncodeItemInfo itemInfo = GetHeifEncodeItemInfo(AuxiliaryPictureType::THUMBNAIL);

    auto item = InitAuxiliaryImageItem(itemInfo.itemId, itemInfo.itemName);
    bool sdrIsSRGB = thumbnail->GetContentPixel()->GetToSdrColorSpaceIsSRGB();
    SkImageInfo thumbnailInfo = GetSkInfo(thumbnail->GetContentPixel().get(), false, sdrIsSRGB);
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(thumbnailInfo, nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(thumbnailInfo);
#endif
    cond = !AssembleICCImageProperty(iccProfile, item.sharedProperties);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s AssembleICCImageProperty failed", __func__);
    sptr<SurfaceBuffer> thumbnailSptr = ConvertPixelMapToDmaBuffer(thumbnail->GetContentPixel());
    cond = thumbnailSptr == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s thumbnailSptr is nullptr", __func__);
    item.pixelBuffer = sptr<NativeBuffer>::MakeSptr(thumbnailSptr->GetBufferHandle());
    std::string auxTypeStr = itemInfo.itemType;

    uint32_t litePropertiesSize =
        sizeof(PropertyType::AUX_TYPE) + UINT32_BYTES_NUM + auxTypeStr.length() + PLACE_HOLDER_LENGTH;
    litePropertiesSize += (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item.liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    cond = !FillLitePropertyItemByString(item.liteProperties, offset, PropertyType::AUX_TYPE, auxTypeStr);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill auxiliary type failed", __func__);
    ColorType colorType = ColorType::RICC;
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill color type failed", __func__);
    inputImgs.push_back(item);
    return SUCCESS;
}

uint32_t ExtEncoder::AssembleHeifAuxiliaryPicture(std::vector<ImageItem>& inputImgs, std::vector<ItemRef>& refs)
{
    bool cond = !picture_;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "picture_ is nullptr");
    if (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::DEPTH_MAP) &&
        AssembleHeifAuxiliaryNoncodingMap(inputImgs, AuxiliaryPictureType::DEPTH_MAP) == SUCCESS) {
        AssembleAuxiliaryRefItem(AuxiliaryPictureType::DEPTH_MAP, refs);
    }
    if (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::UNREFOCUS_MAP) &&
        AssembleHeifUnrefocusMap(inputImgs) == SUCCESS) {
        AssembleAuxiliaryRefItem(AuxiliaryPictureType::UNREFOCUS_MAP, refs);
    }
    if (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::LINEAR_MAP) &&
        AssembleHeifAuxiliaryNoncodingMap(inputImgs, AuxiliaryPictureType::LINEAR_MAP) == SUCCESS) {
        AssembleAuxiliaryRefItem(AuxiliaryPictureType::LINEAR_MAP, refs);
    }
    if (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP) &&
        AssembleHeifFragmentMap(inputImgs) == SUCCESS) {
        AssembleAuxiliaryRefItem(AuxiliaryPictureType::FRAGMENT_MAP, refs);
    }
    if (opts_.needsPackProperties != false || (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::THUMBNAIL) &&
        AssembleHeifThumbnail(inputImgs) == SUCCESS)) {
        AssembleAuxiliaryRefItem(AuxiliaryPictureType::THUMBNAIL, refs);
    }
    return SUCCESS;
}

ImageItem ExtEncoder::InitAuxiliaryImageItem(uint32_t id, std::string itemName)
{
    ImageItem item;
    item.id = id;
    item.itemName = itemName;
    item.isPrimary = false;
    item.isHidden = true;
    item.quality = opts_.quality;
    item.sharedProperties.fd = INVALID_FD;
    item.pixelSharedBuffer.fd = INVALID_FD;
    if (id == DEPTH_MAP_ITEM_ID || id == LINEAR_MAP_ITEM_ID) {
        item.compressType = COMPRESS_TYPE_NONE;
    } else {
        item.compressType = COMPRESS_TYPE_HEVC;
    }
    return item;
}

HeifEncodeItemInfo GetHeifEncodeItemInfo(AuxiliaryPictureType auxType)
{
    HeifEncodeItemInfo itemInfo;
    switch (auxType) {
        case AuxiliaryPictureType::GAINMAP:
            itemInfo.itemId = GAINMAP_IMAGE_ITEM_ID;
            itemInfo.itemName = GAINMAP_IMAGE_ITEM_NAME;
            itemInfo.itemType = HEIF_AUXTTYPE_ID_GAINMAP;
            break;
        case AuxiliaryPictureType::DEPTH_MAP:
            itemInfo.itemId = DEPTH_MAP_ITEM_ID;
            itemInfo.itemName = DEPTH_MAP_ITEM_NAME;
            itemInfo.itemType = HEIF_AUXTTYPE_ID_DEPTH_MAP;
            break;
        case AuxiliaryPictureType::UNREFOCUS_MAP:
            itemInfo.itemId = UNREFOCUS_MAP_ITEM_ID;
            itemInfo.itemName = UNREFOCUS_MAP_ITEM_NAME;
            itemInfo.itemType = HEIF_AUXTTYPE_ID_UNREFOCUS_MAP;
            break;
        case AuxiliaryPictureType::LINEAR_MAP:
            itemInfo.itemId = LINEAR_MAP_ITEM_ID;
            itemInfo.itemName = LINEAR_MAP_ITEM_NAME;
            itemInfo.itemType = HEIF_AUXTTYPE_ID_LINEAR_MAP;
            break;
        case AuxiliaryPictureType::FRAGMENT_MAP:
            itemInfo.itemId = FRAGMENT_MAP_ITEM_ID;
            itemInfo.itemName = FRAGMENT_MAP_ITEM_NAME;
            itemInfo.itemType = HEIF_AUXTTYPE_ID_FRAGMENT_MAP;
            break;
        case AuxiliaryPictureType::THUMBNAIL:
            itemInfo.itemId = THUMBNAIL_ITEM_ID;
            itemInfo.itemName = THUMBNAIL_ITEM_NAME;
            itemInfo.itemType = HEIF_AUXTTYPE_ID_THUMBNAIL;
            break;
        default:
            break;
    }
    return itemInfo;
}

uint32_t ExtEncoder::AssembleHeifAuxiliaryNoncodingMap(std::vector<ImageItem>& inputImgs, AuxiliaryPictureType auxType)
{
    auto auxMap = picture_->GetAuxiliaryPicture(auxType);
    if (!auxMap || !auxMap->GetContentPixel() ||
        auxMap->GetContentPixel()->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        IMAGE_LOGE("%{public}s The auxMap is nullptr or allocator type is not DMA_ALLOC", __func__);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    sptr<SurfaceBuffer> auxMapSptr(reinterpret_cast<SurfaceBuffer*>(auxMap->GetContentPixel()->GetFd()));
    bool cond = !auxMapSptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s auxMapSptr is nullptr", __func__);

    HeifEncodeItemInfo itemInfo = GetHeifEncodeItemInfo(auxType);
    auto item = InitAuxiliaryImageItem(itemInfo.itemId, itemInfo.itemName);
    std::string auxTypeStr = itemInfo.itemType;
    Resolution resolution = {
        auxMap->GetContentPixel()->GetWidth(),
        auxMap->GetContentPixel()->GetHeight()
    };
    uint32_t litePropertiesSize =
        sizeof(PropertyType::AUX_TYPE) + UINT32_BYTES_NUM + auxTypeStr.length() + PLACE_HOLDER_LENGTH;
    litePropertiesSize += (sizeof(PropertyType::IMG_RESOLUTION) + sizeof(Resolution));
    size_t offset = 0;
    item.liteProperties.resize(litePropertiesSize);
    cond = !FillLitePropertyItemByString(item.liteProperties, offset, PropertyType::AUX_TYPE, auxTypeStr);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill auxiliary type failed", __func__);
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::IMG_RESOLUTION, &resolution,
        sizeof(Resolution));
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill color type failed", __func__);
    uint32_t capacity = auxMap->GetContentPixel()->GetCapacity();
    cond = !FillPixelSharedBuffer(auxMapSptr, capacity, item.pixelSharedBuffer);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s Fill pixel shared buffer failed", __func__);
    inputImgs.push_back(item);
    return SUCCESS;
}

uint32_t ExtEncoder::AssembleHeifUnrefocusMap(std::vector<ImageItem>& inputImgs)
{
    auto unrefocusMap = picture_->GetAuxiliaryPicture(AuxiliaryPictureType::UNREFOCUS_MAP);
    bool cond = !unrefocusMap || !unrefocusMap->GetContentPixel();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s The unrefocusMap is nullptr", __func__);
    HeifEncodeItemInfo itemInfo = GetHeifEncodeItemInfo(AuxiliaryPictureType::UNREFOCUS_MAP);
    auto item = InitAuxiliaryImageItem(itemInfo.itemId, itemInfo.itemName);
    bool sdrIsSRGB = unrefocusMap->GetContentPixel()->GetToSdrColorSpaceIsSRGB();
    SkImageInfo unrefocusInfo = GetSkInfo(unrefocusMap->GetContentPixel().get(), false, sdrIsSRGB);
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(unrefocusInfo, nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(unrefocusInfo);
#endif
    cond = !AssembleICCImageProperty(iccProfile, item.sharedProperties);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s AssembleICCImageProperty failed", __func__);
    sptr<SurfaceBuffer> unrefocusMapSptr = ConvertPixelMapToDmaBuffer(unrefocusMap->GetContentPixel());
    cond = !unrefocusMapSptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s unrefocusMapSptr is nullptr", __func__);
    item.pixelBuffer = sptr<NativeBuffer>::MakeSptr(unrefocusMapSptr->GetBufferHandle());
    std::string auxTypeStr = itemInfo.itemType;

    uint32_t litePropertiesSize =
        sizeof(PropertyType::AUX_TYPE) + UINT32_BYTES_NUM + auxTypeStr.length() + PLACE_HOLDER_LENGTH;
    litePropertiesSize += (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item.liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    cond = !FillLitePropertyItemByString(item.liteProperties, offset, PropertyType::AUX_TYPE, auxTypeStr);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill auxiliary type failed", __func__);
    ColorType colorType = ColorType::RICC;
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill color type failed", __func__);
    inputImgs.push_back(item);
    return SUCCESS;
}

RelativeLocation GetFragmentRelLocation(std::shared_ptr<AuxiliaryPicture> &fragmentMap)
{
    RelativeLocation loc;
    auto fragmentMeta = fragmentMap->GetMetadata(MetadataType::FRAGMENT);
    bool cond = fragmentMeta == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, loc, "The fragmentMap has not fragmentMap");
    std::string loc_x = "";
    std::string loc_y = "";
    uint32_t horizontalOffset = 0;
    uint32_t verticalOffset = 0;
    fragmentMeta->GetValue(FRAGMENT_METADATA_KEY_X, loc_x);
    fragmentMeta->GetValue(FRAGMENT_METADATA_KEY_Y, loc_y);
    ImageUtils::StrToUint32(loc_x, horizontalOffset);
    ImageUtils::StrToUint32(loc_y, verticalOffset);
    loc.horizontalOffset = horizontalOffset;
    loc.verticalOffset = verticalOffset;
    return loc;
}

uint32_t ExtEncoder::AssembleHeifFragmentMap(std::vector<ImageItem>& inputImgs)
{
    auto fragmentMap = picture_->GetAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    bool cond = !fragmentMap || !fragmentMap->GetContentPixel();
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s The fragmentMap is nullptr", __func__);
    sptr<SurfaceBuffer> fragmentMapSptr = ConvertPixelMapToDmaBuffer(fragmentMap->GetContentPixel());
    cond = !fragmentMapSptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s fragmentMapSptr is nullptr", __func__);
    HeifEncodeItemInfo itemInfo = GetHeifEncodeItemInfo(AuxiliaryPictureType::FRAGMENT_MAP);
    auto item = InitAuxiliaryImageItem(itemInfo.itemId, itemInfo.itemName);
    bool sdrIsSRGB = fragmentMap->GetContentPixel()->GetToSdrColorSpaceIsSRGB();
    SkImageInfo fragmentInfo = GetSkInfo(fragmentMap->GetContentPixel().get(), false, sdrIsSRGB);
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(fragmentInfo, nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(fragmentInfo);
#endif
    cond = !AssembleICCImageProperty(iccProfile, item.sharedProperties);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s AssembleICCImageProperty failed", __func__);
    item.pixelBuffer = sptr<NativeBuffer>::MakeSptr(fragmentMapSptr->GetBufferHandle());
    std::string auxTypeStr = itemInfo.itemType;
    uint32_t litePropertiesSize =
        sizeof(PropertyType::AUX_TYPE) + UINT32_BYTES_NUM + auxTypeStr.length() + PLACE_HOLDER_LENGTH;
    litePropertiesSize += (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    litePropertiesSize += (sizeof(PropertyType::RLOC_INFO) + sizeof(RelativeLocation));
    item.liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    ColorType colorType = ColorType::RICC;
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill color type failed", __func__);
    cond = !FillLitePropertyItemByString(item.liteProperties, offset, PropertyType::AUX_TYPE, auxTypeStr);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill auxiliary type failed", __func__);
    RelativeLocation loc = GetFragmentRelLocation(fragmentMap);
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::RLOC_INFO, &loc, sizeof(RelativeLocation));
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s Fill auxiliary type failed", __func__);
    inputImgs.push_back(item);
    return SUCCESS;
}
#endif

uint32_t DecomposeDualVivid(VpeSurfaceBuffers& buffers, Media::PixelMap* pixelmap,
    SkEncodedImageFormat format, HdrMetadata& metadata)
{
    if (pixelmap == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if ((!pixelmap->IsHdr() && !IsWideGamutSdrPixelMap(pixelmap)) ||
        pixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC ||
        (format != SkEncodedImageFormat::kJPEG && format != SkEncodedImageFormat::kHEIF)) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    bool sdrIsSRGB = pixelmap->GetToSdrColorSpaceIsSRGB();
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (pixelmap->GetFd()));
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(hdrSurfaceBuffer->GetWidth(),
        hdrSurfaceBuffer->GetHeight());
    const int halfSizeDenominator = 2;
    sptr<SurfaceBuffer> gainmapSptr = AllocSurfaceBuffer(hdrSurfaceBuffer->GetWidth() / halfSizeDenominator,
        hdrSurfaceBuffer->GetHeight() / halfSizeDenominator);
    bool cond = baseSptr == nullptr || gainmapSptr == nullptr;
    CHECK_ERROR_RETURN_RET(cond, IMAGE_RESULT_CREATE_SURFAC_FAILED);
    CM_ColorSpaceType colorspaceType;
    VpeUtils::GetSbColorSpaceType(hdrSurfaceBuffer, colorspaceType);
    if ((colorspaceType & CM_PRIMARIES_MASK) != COLORPRIMARIES_BT2020) {
#ifdef IMAGE_COLORSPACE_FLAG
        ColorManager::ColorSpaceName colorspace = pixelmap->InnerGetGrColorSpace().GetColorSpaceName();
        IMAGE_LOGI("ExtEncoder SetHdrColorSpaceType, color is %{public}d", colorspace);
        colorspaceType = ColorUtils::ConvertToCMColor(colorspace);
        VpeUtils::SetSbColorSpaceType(hdrSurfaceBuffer, colorspaceType);
#endif
    }
    CM_HDR_Metadata_Type hdrMetadataType;
    VpeUtils::GetSbMetadataType(hdrSurfaceBuffer, hdrMetadataType);
    VpeUtils::SetSbMetadataType(hdrSurfaceBuffer, CM_IMAGE_HDR_VIVID_SINGLE);
    buffers.sdr = baseSptr;
    buffers.gainmap = gainmapSptr;
    buffers.hdr = hdrSurfaceBuffer;
    if (!DecomposeImage(buffers, metadata, false, sdrIsSRGB)) {
        IMAGE_LOGE("HDR-IMAGE EncodeDualVivid decomposeImage failed");
        FreeBaseAndGainMapSurfaceBuffer(baseSptr, gainmapSptr);
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    metadata.hdrMetadataType = static_cast<int32_t>(hdrMetadataType);
    return SUCCESS;
}

static bool GetDstTruncatePixelFormat(GraphicPixelFormat srcFormat, GraphicPixelFormat& dstFormat)
{
    switch (srcFormat) {
        case GRAPHIC_PIXEL_FMT_RGBA_1010102 : {
            dstFormat = GRAPHIC_PIXEL_FMT_RGBA_8888;
            break;
        }
        case GRAPHIC_PIXEL_FMT_YCBCR_P010 : {
            dstFormat = GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
            break;
        }
        case GRAPHIC_PIXEL_FMT_YCRCB_P010 : {
            dstFormat = GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
            break;
        }
        default: {
            IMAGE_LOGE("pixel format: [%{public}d] not surpport.", srcFormat);
            return false;
        }
    }
    return true;
}

uint32_t Truncate10bBitTo8bit(VpeSurfaceBuffers& buffers, Media::PixelMap* pixelmap,
    SkEncodedImageFormat format)
{
    IMAGE_LOGD("HDR-IMAGE Splice10bitTo8bit");
    bool cond = pixelmap == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    if (!ImageUtils::Is10Bit(pixelmap->GetPixelFormat()) ||
        pixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        IMAGE_LOGE("HDR-IMAGE Splice10bBitSdrTo8bit condition error");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*> (pixelmap->GetFd()));
    GraphicPixelFormat srcPixelFormat = static_cast<GraphicPixelFormat>(hdrSurfaceBuffer->GetFormat());
    GraphicPixelFormat dstPixelFormat;
    cond = !GetDstTruncatePixelFormat(srcPixelFormat, dstPixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "HDR-IMAGE Splice10bitTo8bit"
        "pixel format :[%{public}d] not support", format);
    
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(hdrSurfaceBuffer->GetWidth(),
        hdrSurfaceBuffer->GetHeight(), dstPixelFormat);
    cond = baseSptr == nullptr;
    CHECK_ERROR_RETURN_RET(cond, IMAGE_RESULT_CREATE_SURFAC_FAILED);
    buffers.sdr = baseSptr;
    buffers.hdr = hdrSurfaceBuffer;
    IMAGE_LOGD("src buffer alloc pixelFormat is : %{public}d", buffers.sdr->GetFormat());
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    ImageUtils::DumpHdrBufferEnabled(hdrSurfaceBuffer, "SpliceInput-10-bit");
    int32_t res = utils->TruncateBuffer(buffers, false);
    if (res != SUCCESS) {
        IMAGE_LOGE("HDR-IMAGE Convert10bBitSdrToDual decomposeImage failed");
        ImageUtils::SurfaceBuffer_Unreference(baseSptr.GetRefPtr());
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    ImageUtils::DumpHdrBufferEnabled(baseSptr, "SpliceInput-8-bit");
    return SUCCESS;
}

uint32_t ExtEncoder::Encode10bitSdrPixelMap(Media::PixelMap* pixelmap, ExtWStream& outputStream)
{
    IMAGE_LOGD("HDR-IMAGE Encode10bitRGBAToSdr");
    if (pixelmap == nullptr) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    VpeSurfaceBuffers buffers;
    HdrMetadata metadata;
    uint32_t error = Truncate10bBitTo8bit(buffers, pixelmap, encodeFormat_);
    if (error != SUCCESS) {
        IMAGE_LOGE("HDR-IMAGE EncodeRGBA1010102SdrPixelMap failed");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    PixelFormat pixelFormat = ImageUtils::SbFormat2PixelFormat(buffers.hdr->GetFormat());
    std::unique_ptr<PixelMap> encodePixelmap;
    if (ImageUtils::IsYuvFormat(pixelFormat)) {
#ifdef EXT_PIXEL
        encodePixelmap = std::make_unique<PixelYuvExt>();
#else
        encodePixelmap = std::make_unique<PixelYuv>();
#endif
    } else {
        encodePixelmap = std::make_unique<PixelMap>();
    }
    CHECK_ERROR_RETURN_RET(encodePixelmap == nullptr, ERR_IMAGE_ENCODE_FAILED);
    if (!ImageUtils::SurfaceBuffer2PixelMap(buffers.sdr, encodePixelmap)) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    encodePixelmap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(
        OHOS::ColorManager::ColorSpaceName::SRGB));
    error = EncodeImageByPixelMap(encodePixelmap.get(), opts_.needsPackProperties, outputStream);
    ImageUtils::SurfaceBuffer_Unreference(buffers.sdr);
    return error;
}

uint32_t ExtEncoder::EncodeDualVivid(ExtWStream& outputStream)
{
    IMAGE_LOGD("ExtEncoder::EncodeDualVivid");
    VpeSurfaceBuffers buffers;
    HdrMetadata metadata;
    if (DecomposeDualVivid(buffers, pixelmap_, encodeFormat_, metadata) != SUCCESS) {
        return IMAGE_RESULT_CREATE_SURFAC_FAILED;
    }
    // get sdr baseInfo
    bool sdrIsSRGB = pixelmap_->GetToSdrColorSpaceIsSRGB();
    sk_sp<SkColorSpace> colorSpace = ToHdrEncodeSkColorSpace(pixelmap_, buffers.sdr, sdrIsSRGB, false);
    SkImageInfo baseInfo = GetSkInfo(pixelmap_, false, colorSpace);
    // get gainmap baseInfo
    sk_sp<SkColorSpace> gainmapColorSpace = ToHdrEncodeSkColorSpace(pixelmap_, buffers.gainmap, sdrIsSRGB, true);
    SkImageInfo gainmapInfo = GetSkInfo(pixelmap_, true, gainmapColorSpace);
    uint32_t error;
    if (encodeFormat_ == SkEncodedImageFormat::kJPEG) {
        sk_sp<SkData> baseImageData = GetImageEncodeData(buffers.sdr, baseInfo, opts_.needsPackProperties);
        sk_sp<SkData> gainMapImageData = GetImageEncodeData(buffers.gainmap, gainmapInfo, false);
        error = HdrJpegPackerHelper::SpliceHdrStream(baseImageData, gainMapImageData, outputStream, metadata);
    } else if (encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        error = EncodeHeifDualHdrImage(buffers.sdr, buffers.gainmap, metadata);
    } else {
        error = ERR_IMAGE_INVALID_PARAMETER;
    }
    FreeBaseAndGainMapSurfaceBuffer(buffers.sdr, buffers.gainmap);
    return error;
}

uint32_t ExtEncoder::EncodeSdrImage(ExtWStream& outputStream)
{
    IMAGE_LOGD("ExtEncoder EncodeSdrImage");
    if (pixelmap_->GetAllocatorType() == AllocatorType::DMA_ALLOC && ImageUtils::Is10Bit(pixelmap_->GetPixelFormat())
        && !IsHdrColorSpace(pixelmap_) && !IsWideGamutSdrPixelMap(pixelmap_)) {
        IMAGE_LOGD("HDR-IMAGE do Encode10bitSdrPixelMap");
        return Encode10bitSdrPixelMap(pixelmap_, outputStream);
    }
    if (!pixelmap_->IsHdr() && !IsWideGamutSdrPixelMap(pixelmap_)) {
        return EncodeImageByPixelMap(pixelmap_, opts_.needsPackProperties, outputStream);
    }
    bool cond = pixelmap_->GetAllocatorType() != AllocatorType::DMA_ALLOC;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "pixelmap is 10bit, but not dma buffer");
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
    bool sdrIsSRGB = pixelmap_->GetToSdrColorSpaceIsSRGB();
    SkImageInfo baseInfo = GetSkInfo(pixelmap_, false, sdrIsSRGB);
    sptr<SurfaceBuffer> baseSptr = AllocSurfaceBuffer(baseInfo.width(), baseInfo.height());
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(baseSptr, CM_SRGB_FULL);
    cond = baseSptr == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, IMAGE_RESULT_CREATE_SURFAC_FAILED, "EncodeSdrImage sdr buffer alloc failed");
    sptr<SurfaceBuffer> hdrSurfaceBuffer(reinterpret_cast<SurfaceBuffer*>(pixelmap_->GetFd()));
    ImageUtils::FlushSurfaceBuffer(hdrSurfaceBuffer);
    VpeUtils::SetSbMetadataType(hdrSurfaceBuffer, CM_IMAGE_HDR_VIVID_SINGLE);
    SetHdrColorSpaceType(hdrSurfaceBuffer);
    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .hdr = hdrSurfaceBuffer,
    };
    HdrMetadata metadata;
    if (!DecomposeImage(buffers, metadata, true, sdrIsSRGB)) {
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
    Media::HdrMetadata& metadata, bool sdrIsSRGB)
{
#ifdef HEIF_HW_ENCODE_ENABLE
    std::vector<ImageItem> inputImgs;
    ColorSpaceManager colorspaceName =
        sdrIsSRGB ? ColorManager::ColorSpaceName::SRGB : ColorManager::ColorSpaceName::DISPLAY_P3;
    std::shared_ptr<ImageItem> primaryItem =
        AssembleHdrBaseImageItem(sdr, colorspaceName, metadata, opts_);
    bool cond = primaryItem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "AssmbleHeifDualHdrImage, get primary image failed");
    inputImgs.push_back(*primaryItem);
    std::shared_ptr<ImageItem> gainmapItem =
        AssembleGainmapImageItem(gainmap, colorspaceName, opts_);
    cond = gainmapItem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "AssembleDualHdrImage, get gainmap image item failed");
    inputImgs.push_back(*gainmapItem);
    ColorManager::ColorSpaceName tmapColor = pixelmap_->InnerGetGrColorSpace().GetColorSpaceName();
    std::shared_ptr<ImageItem> tmapItem = AssembleTmapImageItem(tmapColor, metadata, opts_);
    cond = tmapItem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "AssembleDualHdrImage, get tmap image item failed");
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
    bool cond = sdr == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "EncodeHeifSdrImage, sdr surfacebuffer is nullptr");
    ImageItem item;
    item.id = PRIMARY_IMAGE_ITEM_ID;
    item.pixelBuffer = sptr<NativeBuffer>::MakeSptr(sdr->GetBufferHandle());
    item.isPrimary = true;
    item.isHidden = false;
    item.compressType = COMPRESS_TYPE_HEVC;
    item.quality = opts_.quality;
    item.sharedProperties.fd = INVALID_FD;
    item.pixelSharedBuffer.fd = INVALID_FD;
    ImageInfo info;
    pixelmap_->GetImageInfo(info);
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(sdrInfo, nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(sdrInfo);
#endif
    bool tempRes = AssembleICCImageProperty(iccProfile, item.sharedProperties);
    cond = !tempRes;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "EncodeSdrImage AssembleICCImageProperty failed");
    uint32_t litePropertiesSize = (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item.liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    ColorType colorType = ColorType::RICC;
    cond = !FillLitePropertyItem(item.liteProperties, offset, PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "EncodeHeifSdrImage Fill color type failed");
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

static bool CheckThumbnailCanSet(std::shared_ptr<ExifMetadata> &exifMetadata, uint8_t *data, const uint32_t &thumbSize)
{
    CHECK_ERROR_RETURN_RET_LOG(exifMetadata == nullptr, false,
        "%{public}s: exifMetadata is nullptr", __func__);
    
    ExifData *exifData = exifMetadata->GetExifData();
    CHECK_ERROR_RETURN_RET_LOG(exifData == nullptr, false, "%{public}s: exifData is nullptr", __func__);

    uint32_t totalSize = 0;
    {
        // set new thumbnail data temporarily to get total exif size
        ScopeRestorer<unsigned char*> thumbDataRestorer(exifData->data, data);
        ScopeRestorer<unsigned int> thumbSizeRestorer(exifData->size, thumbSize);
        exifMetadata->GetDataSize(totalSize, true, true);
    }

    if (totalSize > EXIF_MAX_SIZE) {
        IMAGE_LOGE("%{public}s: total exif size %{public}u exceed max size %{public}u, cannot set thumbnail",
            __func__, totalSize, EXIF_MAX_SIZE);
        exifMetadata->DropThumbnail();
        return false;
    }
    return true;
}

static uint32_t FillExifThumbnail(PixelMap *pixelMap, uint8_t *data, const uint32_t &size)
{
    CHECK_ERROR_RETURN_RET_LOG(pixelMap == nullptr || data == nullptr, ERR_IMAGE_DATA_ABNORMAL,
        "%{public}s: pixelMap is nullptr", __func__);
    std::shared_ptr<ExifMetadata> exifMetadata = pixelMap->GetExifMetadata();
    if (exifMetadata == nullptr) {
        IMAGE_LOGI("%{public}s: exifMetadata is nullptr. Try to create a new exifMetadata", __func__);
        exifMetadata = std::make_shared<ExifMetadata>();
        CHECK_ERROR_RETURN_RET_LOG(!exifMetadata->CreateExifdata(), ERR_MEDIA_NO_EXIF_DATA,
            "%{public}s: try to create new exifMetadata failed!", __func__);
        pixelMap->SetExifMetadata(exifMetadata);
    }
    CHECK_ERROR_RETURN_RET_LOG(exifMetadata == nullptr, ERR_MEDIA_NO_EXIF_DATA,
        "%{public}s: exifMetadata is nullptr", __func__);

    CHECK_ERROR_RETURN_RET_LOG(!CheckThumbnailCanSet(exifMetadata, data, size), ERR_IMAGE_DATA_ABNORMAL,
        "%{public}s: check thumbnail can set failed", __func__);

    exifMetadata->SetThumbnail(data, size);
    return SUCCESS;
}

uint32_t ExtEncoder::ProcessJpegThumbnail()
{
    if (opts_.needsPackProperties == false) {
        IMAGE_LOGI("%{public}s: needsPackProperties is false, skip process jpeg thumbnail", __func__);
        return SUCCESS;
    }

    CHECK_ERROR_RETURN_RET_LOG(picture_ == nullptr, ERR_IMAGE_DATA_ABNORMAL,
        "%{public}s: picture is nullptr", __func__);
    std::shared_ptr<PixelMap> pixelMap = picture_->GetMainPixel();
    std::shared_ptr<PixelMap> thumbnailPixelMap = picture_->GetThumbnailPixelMap();
    CHECK_ERROR_RETURN_RET_LOG(pixelMap == nullptr || thumbnailPixelMap == nullptr, ERR_IMAGE_DATA_ABNORMAL,
        "%{public}s: mainPixelMap or thumbnailPixelMap is nullptr, stop process jpeg thumbnail", __func__);

    // Encode thumbnail
    ImageTrace imageTrace("%{publics}: size:(%d, %d)", __func__,
        thumbnailPixelMap->GetWidth(), thumbnailPixelMap->GetHeight());
    uint32_t errorCode = ERR_IMAGE_ENCODE_FAILED;
    std::vector<uint8_t> packedData(EXIF_MAX_SIZE);
    auto stream = std::make_unique<BufferPackerStream>(packedData.data(), packedData.size());
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, ERR_MEDIA_MALLOC_FAILED,
        "%{public}s: buffer packer stream is nullptr", __func__);

    ExtWStream wStream(stream.get());
    // thumbnail always use JPEG format
    ScopeRestorer<SkEncodedImageFormat> encodeFormatRestorer(encodeFormat_, SkEncodedImageFormat::kJPEG);
    ScopeRestorer<PixelMap*> pixelmapRestorer(pixelmap_, thumbnailPixelMap.get());
    errorCode = EncodeImageByPixelMap(thumbnailPixelMap.get(), false, wStream);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("%{public}s: encode Picture's thumbnail failed, errorCode: %{public}d", __func__, errorCode);
        std::shared_ptr<ExifMetadata> exifMetadata = pixelMap->GetExifMetadata();
        if (exifMetadata != nullptr) {
            exifMetadata->DropThumbnail();
        }
        return errorCode;
    }

    // Fill Exif with encoded thumbnail data
    return FillExifThumbnail(pixelMap.get(), packedData.data(), wStream.bytesWritten());
}

uint32_t ExtEncoder::EncodePicture()
{
    bool cond = (encodeFormat_ != SkEncodedImageFormat::kJPEG && encodeFormat_ != SkEncodedImageFormat::kHEIF);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s: unsupported encode format: %{public}s", __func__, opts_.format.c_str());
    if (opts_.isEditScene && encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        return EncodeEditScenePicture();
    }
    if (encodeFormat_ == SkEncodedImageFormat::kJPEG) {
        CheckJpegAuxiliaryTagName();
        ProcessJpegThumbnail();
    }
    ExtWStream wStream(output_);
    return EncodeCameraScenePicture(wStream);
}

static bool IsValidSizeForHardwareEncode(int32_t width, int32_t height)
{
    if (ImageUtils::IsEven(width) && ImageUtils::IsInRange(width, MIN_IMAGE_SIZE, MAX_IMAGE_SIZE) &&
        ImageUtils::IsEven(height) && ImageUtils::IsInRange(height, MIN_IMAGE_SIZE, MAX_IMAGE_SIZE)) {
        return true;
    }
    IMAGE_LOGD("%{public}s hardware encode is not support, width: %{public}d, height: %{public}d",
        __func__, width, height);
    return false;
}

bool ExtEncoder::IsPictureSupportHardwareEncode()
{
    bool cond = !ImageSystemProperties::GetHardWareEncodeEnabled();
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s hardware encode disabled", __func__);
    cond = picture_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s picture is null", __func__);

    if (opts_.quality < LOW_QUALITY_BOUNDARY) {
        IMAGE_LOGE("%{public}s Low quality use jpeg software encode", __func__);
        return false;
    }
    auto mainPixelMap = picture_->GetMainPixel();
    if (mainPixelMap == nullptr ||
        !IsValidSizeForHardwareEncode(mainPixelMap->GetWidth(), mainPixelMap->GetHeight())) {
        IMAGE_LOGI("%{public}s MainPixelMap not support hardware encode", __func__);
        return false;
    }

    const auto& auxTypes = ImageUtils::GetAllAuxiliaryPictureType();
    for (const auto& auxType : auxTypes) {
        auto auxPicture = picture_->GetAuxiliaryPicture(auxType);
        if (auxPicture == nullptr) {
            continue;
        }
        auto auxPixelMap = auxPicture->GetContentPixel();
        if (auxPixelMap == nullptr) {
            continue;
        }
        cond = !IsValidSizeForHardwareEncode(auxPixelMap->GetWidth(), auxPixelMap->GetHeight());
        CHECK_INFO_RETURN_RET_LOG(cond, false,
            "%{public}s auxType: %{public}d not support hardware encode", __func__, auxType);
    }
    return true;
}

uint32_t ExtEncoder::TryHardwareEncodePicture(SkWStream& skStream, std::string& errorMsg)
{
    errorMsg = "Hardware encode picture failed";
    if (picture_ == nullptr) {
        errorMsg = "picture is nullptr";
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    static ImageFwkExtManager imageFwkExtManager;
    if (!imageFwkExtManager.LoadImageFwkExtNativeSo() || imageFwkExtManager.doHardwareEncodePictureFunc_ == nullptr) {
        errorMsg = "Load hardware encode library failed";
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return imageFwkExtManager.doHardwareEncodePictureFunc_(&skStream, opts_, picture_);
}

uint32_t ExtEncoder::EncodeCameraScenePicture(SkWStream& skStream)
{
    uint32_t retCode = ERR_IMAGE_ENCODE_FAILED;
    std::string errorMsg = "Unknown encode failed";
    if (encodeFormat_ == SkEncodedImageFormat::kHEIF) {
        retCode = TryHardwareEncodePicture(skStream, errorMsg);
    } else if (encodeFormat_ == SkEncodedImageFormat::kJPEG) {
        if (IsPictureSupportHardwareEncode()) {
            retCode = TryHardwareEncodePicture(skStream, errorMsg);
        } else {
            errorMsg = "Not support hardware encode";
        }
        if (retCode != SUCCESS) {
            IMAGE_LOGW("%{public}s, retCode is: %{public}d, try jpeg software encode", errorMsg.c_str(), retCode);
            retCode = EncodeJpegPicture(skStream);
            errorMsg = "Jpeg software encode picture failed";
        }
    }
    if (retCode != SUCCESS) {
        ImageInfo imageInfo;
        picture_->GetMainPixel()->GetImageInfo(imageInfo);
        IMAGE_LOGE("%{public}s, retCode is: %{public}d", errorMsg.c_str(), retCode);
        ReportEncodeFault(imageInfo.size.width, imageInfo.size.height, opts_.format, errorMsg);
    }
    return retCode;
}

uint32_t ExtEncoder::EncodeEditScenePicture()
{
    bool cond = !picture_;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DATA_ABNORMAL, "picture_ is nullptr");
    auto mainPixelMap = picture_->GetMainPixel();
    cond = !mainPixelMap || mainPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DATA_ABNORMAL,
        "MainPixelMap is nullptr or mainPixelMap is not DMA buffer");

    bool sdrIsSRGB = mainPixelMap->GetToSdrColorSpaceIsSRGB();
    SkImageInfo baseInfo = GetSkInfo(mainPixelMap.get(), false, false);
    sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(mainPixelMap->GetFd()));
    cond = !baseSptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, IMAGE_RESULT_CREATE_SURFAC_FAILED, "creat main pixels surfaceBuffer error");
    ImageUtils::FlushSurfaceBuffer(baseSptr);
    uint32_t errorCode = EncodeHeifPicture(baseSptr, baseInfo, sdrIsSRGB);
    RecycleResources();
    return errorCode;
}

#ifdef HEIF_HW_ENCODE_ENABLE
void ExtEncoder::EncodeHeifMetadata(std::vector<ItemRef> &refs, std::vector<MetaItem> &inputMetas)
{
    if (AssembleExifMetaItem(inputMetas)) {
        AssembleExifRefItem(refs);
    }
    for (const auto& iter : HEIF_METADATA_MAPPING) {
        if (AssembleBlobMetaItem(iter.first, inputMetas)) {
            AssembleBlobRefItem(iter.first, refs);
        }
    }
}
#endif

uint32_t ExtEncoder::EncodeHeifPicture(sptr<SurfaceBuffer>& mainSptr, SkImageInfo mainInfo, bool sdrIsSRGB)
{
#ifdef HEIF_HW_ENCODE_ENABLE
    uint32_t error = SUCCESS;
    std::vector<ImageItem> inputImgs;
    std::vector<MetaItem> inputMetas;
    std::vector<ItemRef> refs;
    switch (opts_.desiredDynamicRange) {
        case EncodeDynamicRange::AUTO:
            if (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP) &&
                AssembleHeifHdrPicture(mainSptr, sdrIsSRGB, inputImgs) == SUCCESS) {
                AssembleDualHdrRefItem(refs);
            } else {
                inputImgs.clear();
                error = AssembleSdrImageItem(mainSptr, mainInfo, inputImgs);
            }
            break;
        case EncodeDynamicRange::SDR:
            error = AssembleSdrImageItem(mainSptr, mainInfo, inputImgs);
            break;
        case EncodeDynamicRange::HDR_VIVID_DUAL:
            if (picture_->HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP)) {
                error = AssembleHeifHdrPicture(mainSptr, sdrIsSRGB, inputImgs);
                AssembleDualHdrRefItem(refs);
            } else {
                IMAGE_LOGE("Picture don't has GAINMAP pixels");
                error = ERR_IMAGE_ENCODE_FAILED;
            }
            break;
        case EncodeDynamicRange::HDR_VIVID_SINGLE:
            IMAGE_LOGE("Heif picture not support HDR_VIVID_SINGLE");
            return ERR_IMAGE_ENCODE_FAILED;
        default:
            return ERR_IMAGE_INVALID_PARAMETER;
    }
    bool cond = error != SUCCESS;
    CHECK_ERROR_RETURN_RET(cond, error);
    EncodeHeifMetadata(refs, inputMetas);
    error = AssembleHeifAuxiliaryPicture(inputImgs, refs);
    cond = error != SUCCESS;
    CHECK_ERROR_RETURN_RET(cond, error);
    return DoHeifEncode(inputImgs, inputMetas, refs);
#else
    return ERR_IMAGE_INVALID_PARAMETER;
#endif
}

void ExtEncoder::CheckJpegAuxiliaryTagName()
{
    CHECK_ERROR_RETURN(picture_ == nullptr);
    auto auxTypes = ImageUtils::GetAllAuxiliaryPictureType();
    for (AuxiliaryPictureType auxType : auxTypes) {
        auto auxPicture = picture_->GetAuxiliaryPicture(auxType);
        if (auxPicture == nullptr) {
            continue;
        }
        AuxiliaryPictureInfo auxInfo = auxPicture->GetAuxiliaryPictureInfo();
        auto iter = DEFAULT_AUXILIARY_TAG_MAP.find(auxType);
        if (auxInfo.jpegTagName.size() == 0 && iter != DEFAULT_AUXILIARY_TAG_MAP.end()) {
            auxInfo.jpegTagName = iter->second;
            auxPicture->SetAuxiliaryPictureInfo(auxInfo);
        }
    }
}

uint32_t ExtEncoder::EncodeJpegPicture(SkWStream& skStream)
{
    uint32_t error = ERR_IMAGE_ENCODE_FAILED;
    switch (opts_.desiredDynamicRange) {
        case EncodeDynamicRange::AUTO:
            error = EncodeJpegPictureDualVivid(skStream);
            if (error != SUCCESS) {
                IMAGE_LOGI("%{public}s jpeg picture encode dual vivid failed, try encode sdr", __func__);
                error = EncodeJpegPictureSdr(skStream);
            }
            break;
        case EncodeDynamicRange::SDR:
            error = EncodeJpegPictureSdr(skStream);
            break;
        case EncodeDynamicRange::HDR_VIVID_DUAL:
            error = EncodeJpegPictureDualVivid(skStream);
            break;
        case EncodeDynamicRange::HDR_VIVID_SINGLE:
            error = ERR_IMAGE_DECODE_FAILED;
            break;
        default:
            error = ERR_IMAGE_INVALID_PARAMETER;
            break;
    }
    return error;
}

uint32_t ExtEncoder::EncodeJpegPictureDualVividInner(SkWStream& skStream, std::shared_ptr<PixelMap>& mainPixelmap,
    std::shared_ptr<PixelMap>& gainmapPixelmap)
{
    bool mainIsSRGB = mainPixelmap->GetToSdrColorSpaceIsSRGB();
    SkImageInfo baseInfo = GetSkInfo(mainPixelmap.get(), false, mainIsSRGB);
    sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(mainPixelmap->GetFd()));
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(baseSptr, mainIsSRGB ? CM_SRGB_FULL : CM_P3_FULL);
    pixelmap_ = mainPixelmap.get();
    sk_sp<SkData> baseImageData = GetImageEncodeData(baseSptr, baseInfo, opts_.needsPackProperties);

    bool gainmapIsSRGB = gainmapPixelmap->GetToSdrColorSpaceIsSRGB();
    SkImageInfo gainmapInfo = GetSkInfo(gainmapPixelmap.get(), true, gainmapIsSRGB);
    ImageInfo tempInfo;
    gainmapPixelmap->GetImageInfo(tempInfo);
    gainmapInfo = gainmapInfo.makeWH(tempInfo.size.width, tempInfo.size.height);
    sptr<SurfaceBuffer> gainMapSptr(reinterpret_cast<SurfaceBuffer*>(gainmapPixelmap->GetFd()));
    VpeUtils::SetSbMetadataType(gainMapSptr, CM_METADATA_NONE);
    VpeUtils::SetSbColorSpaceType(gainMapSptr, gainmapIsSRGB ? CM_SRGB_FULL : CM_P3_FULL);
    pixelmap_ = gainmapPixelmap.get();
    sk_sp<SkData> gainMapImageData = GetImageEncodeData(gainMapSptr, gainmapInfo, false);

    HdrMetadata hdrMetadata = GetHdrMetadata(baseSptr, gainMapSptr);
    SkDynamicMemoryWStream hdrStream;
    uint32_t error = HdrJpegPackerHelper::SpliceHdrStream(baseImageData, gainMapImageData, hdrStream, hdrMetadata);
    IMAGE_LOGD("%{public}s splice hdr stream result is: %{public}u", __func__, error);
    if (error == SUCCESS) {
        sk_sp<SkData> hdrSkData = hdrStream.detachAsData();
        skStream.write(hdrSkData->data(), hdrSkData->size());
        EncodeJpegAllBlobMetadata(skStream);
        EncodeJpegAuxiliaryPictures(skStream);
    }
    return error;
}

uint32_t ExtEncoder::EncodeJpegPictureDualVivid(SkWStream& skStream)
{
    ImageFuncTimer imageFuncTimer("%s enter", __func__);
    bool cond = picture_->HasAuxiliaryPicture(AuxiliaryPictureType::GAINMAP);
    CHECK_ERROR_RETURN_RET_LOG(!cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s no gainmap in picture", __func__);
    auto mainPixelmap = picture_->GetMainPixel();
    auto gainmapPixelmap = picture_->GetGainmapPixelMap();
    cond = !mainPixelmap || !gainmapPixelmap;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "%{public}s mainPixelmap or gainmapPixelmap is null", __func__);
    AllocatorType mainAllocType = mainPixelmap->GetAllocatorType();
    AllocatorType gainmapAllocType = gainmapPixelmap->GetAllocatorType();
    cond = mainAllocType != AllocatorType::DMA_ALLOC || gainmapAllocType != AllocatorType::DMA_ALLOC;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED,
        "%{public}s AllocatorType is not DMA, mainAllocType: %{public}d, gainmapAllocType: %{public}d",
        __func__, mainAllocType, gainmapAllocType);
    return EncodeJpegPictureDualVividInner(skStream, mainPixelmap, gainmapPixelmap);
}

uint32_t ExtEncoder::EncodeJpegPictureSdr(SkWStream& skStream)
{
    ImageFuncTimer imageFuncTimer("%s enter", __func__);
    auto mainPixelmap = picture_->GetMainPixel();
    bool cond = !mainPixelmap;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "%{public}s mainPixelmap is null", __func__);
    pixelmap_ = mainPixelmap.get();
    uint32_t error = ERR_IMAGE_ENCODE_FAILED;
    if (!mainPixelmap->IsHdr()) {
        error = EncodeImageByPixelMap(mainPixelmap.get(), opts_.needsPackProperties, skStream);
        IMAGE_LOGD("%{public}s encode sdr picture result is: %{public}u", __func__, error);
    } else {
        cond = mainPixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC;
        CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER, "pixelmap is 10bit, but not dma buffer");
        bool mainIsSRGB = mainPixelmap->GetToSdrColorSpaceIsSRGB();
        SkImageInfo baseInfo = GetSkInfo(mainPixelmap.get(), false, mainIsSRGB);
        sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(mainPixelmap->GetFd()));
        VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
        VpeUtils::SetSbColorSpaceType(baseSptr, mainIsSRGB ? CM_SRGB_FULL : CM_P3_FULL);
        error = EncodeImageBySurfaceBuffer(baseSptr, baseInfo, opts_.needsPackProperties, skStream);
        IMAGE_LOGD("%{public}s encode hdr picture result is: %{public}u", __func__, error);
    }
    if (error == SUCCESS) {
        EncodeJpegAllBlobMetadata(skStream);
        EncodeJpegAuxiliaryPictures(skStream);
    }
    return error;
}

static bool GetMetadataValueInt32(const std::shared_ptr<ImageMetadata>& metadata, const std::string& key,
    int32_t& outVal)
{
    std::string strVal("");
    uint32_t u32Val = 0;
    bool cond = metadata == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s: metadata is nullptr!", __func__);
    cond = metadata->GetValue(key, strVal) != SUCCESS || !ImageUtils::StrToUint32(strVal, u32Val);
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s: get metadata key[%{public}s]'s value failed!", __func__, key.c_str());
    outVal = static_cast<int32_t>(u32Val);
    return true;
}

static bool CheckFragmentMetadata(Picture* picture, Media::Rect& outData)
{
    bool cond = !picture || !picture->GetMainPixel() ||
        !picture->HasAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s: picture or mainPixelMap or fragment picture does not exist!", __func__);
    int32_t mainW = picture->GetMainPixel()->GetWidth();
    int32_t mainH = picture->GetMainPixel()->GetHeight();

    auto fragmentPicture = picture->GetAuxiliaryPicture(AuxiliaryPictureType::FRAGMENT_MAP);
    auto fragmentMetadata = fragmentPicture->GetMetadata(MetadataType::FRAGMENT);
    cond = fragmentMetadata == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s: fragmentMetadata is nullptr!", __func__);
    cond = !GetMetadataValueInt32(fragmentMetadata, FRAGMENT_METADATA_KEY_X, outData.left) ||
        !GetMetadataValueInt32(fragmentMetadata, FRAGMENT_METADATA_KEY_Y, outData.top) ||
        !GetMetadataValueInt32(fragmentMetadata, FRAGMENT_METADATA_KEY_WIDTH, outData.width) ||
        !GetMetadataValueInt32(fragmentMetadata, FRAGMENT_METADATA_KEY_HEIGHT, outData.height);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s: GetMetadataValueInt32 failed!", __func__);
    if (!ImageUtils::IsInRange(outData.left, 0, mainW) || !ImageUtils::IsInRange(outData.top, 0, mainH) ||
        !ImageUtils::IsInRange(outData.width, 0, mainW) || !ImageUtils::IsInRange(outData.height, 0, mainH) ||
        !ImageUtils::IsInRange(outData.left + outData.width, 0, mainW) ||
        !ImageUtils::IsInRange(outData.top + outData.height, 0, mainH)) {
        IMAGE_LOGW("%{public}s: Fragment Rect is not in main Rect!", __func__);
        return false;
    }
    return true;
}

void ExtEncoder::EncodeJpegAuxiliaryPictures(SkWStream& skStream)
{
    ImageFuncTimer imageFuncTimer("%s enter", __func__);
    auto auxTypes = ImageUtils::GetAllAuxiliaryPictureType();
    for (AuxiliaryPictureType auxType : auxTypes) {
        auto auxPicture = picture_->GetAuxiliaryPicture(auxType);
        // Gainmap has been encoded before
        if (auxPicture == nullptr || auxType == AuxiliaryPictureType::GAINMAP ||
            auxType == AuxiliaryPictureType::THUMBNAIL) {
            continue;
        }
        IMAGE_LOGI("%{public}s try to encode auxiliary picture type: %{public}d", __func__, auxType);
        uint32_t error = ERR_IMAGE_ENCODE_FAILED;
        size_t writtenSize = skStream.bytesWritten();
        if (ImageUtils::IsAuxiliaryPictureEncoded(auxType)) {
            error = WriteJpegCodedData(auxPicture, skStream);
        } else {
            error = WriteJpegUncodedData(auxPicture, skStream);
        }
        if (error != SUCCESS) {
            IMAGE_LOGE("%{public}s encode auxiliary picture type [%{public}d] failed, error: %{public}u",
                __func__, auxType, error);
        } else {
            uint32_t currentDataSize = static_cast<uint32_t>(skStream.bytesWritten() - writtenSize);
            WriteJpegAuxiliarySizeAndTag(currentDataSize, auxPicture, skStream);
        }
    }
}

void ExtEncoder::EncodeJpegAllBlobMetadata(SkWStream& skStream)
{
    ImageFuncTimer imageFuncTimer("%s enter", __func__);
    if (picture_ == nullptr || opts_.needsPackProperties == false) {
        return;
    }
    for (const auto& iter : BLOB_METADATA_TAG_MAP) {
        auto metadataPtr = picture_->GetMetadata(iter.first);
        if (metadataPtr == nullptr) {
            continue;
        }
        uint8_t* bytes = metadataPtr->GetBlobPtr();
        uint32_t writeSize = metadataPtr->GetBlobSize();
        if (bytes == nullptr || writeSize == 0) {
            continue;
        }
        IMAGE_LOGI("%{public}s try to encode blob metadata, type is: %{public}d, datasize : %{public}u",
            __func__, iter.first, writeSize);
        skStream.write(bytes, writeSize);
        std::vector<uint8_t> dataSize = JpegMpfPacker::PackDataSize(writeSize, false);
        skStream.write(dataSize.data(), dataSize.size());
        std::string tagName = iter.second;
        std::vector<uint8_t> dataTag(tagName.begin(), tagName.end());
        dataTag.push_back(0);
        skStream.write(dataTag.data(), dataTag.size());
    }
}

bool ConvertBufferToData(sptr<SurfaceBuffer>& surfaceBuffer, std::vector<uint8_t>& pixels)
{
    if (surfaceBuffer == nullptr) {
        return false;
    }
    uint32_t width = static_cast<uint32_t>(surfaceBuffer->GetWidth());
    uint32_t height = static_cast<uint32_t>(surfaceBuffer->GetHeight());
    uint32_t stride = static_cast<uint32_t>(surfaceBuffer->GetStride());
    uint32_t dstStride = width * RGBA8888_PIXEL_BYTES;
    uint32_t bufferSize = height * dstStride;
    uint8_t *srcBuf = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr());
    pixels.resize(bufferSize);
    uint8_t *dstBuf = pixels.data();
    for (uint32_t i = 0; i < height; ++i) {
        if (memcpy_s(dstBuf + i * dstStride, dstStride, srcBuf + i * stride, dstStride) != EOK) {
            IMAGE_LOGE("HDR-IMAGE ConvertBufferToData copy memory failed");
            return false;
        }
    }
    return true;
}

void SetLogResMapColorSpaceType(CM_ColorSpaceType& colorSpaceType, LogResMapMetadata& colorData)
{
    uint32_t colorSpace = static_cast<uint32_t>(colorSpaceType);
    colorData.primaries = static_cast<CM_ColorPrimaries>(colorSpace & CM_PRIMARIES_MASK);
    colorData.transfunc = static_cast<CM_TransFunc>((colorSpace & CM_TRANSFUNC_MASK) >> TRANSFUNC_OFFSET);
    colorData.matrix = static_cast<CM_Matrix>((colorSpace & CM_MATRIX_MASK) >> MATRIX_OFFSET);
    colorData.range = static_cast<CM_Range>((colorSpace & CM_RANGE_MASK) >> RANGE_OFFSET);
}

void ExtEncoder::EncodeLogVideoDataToBlobMetadata(sptr<SurfaceBuffer>& surfaceBuffer, SkWStream& skStream)
{
    // write version
    const char version[] = RFIMAGE_ID;
    std::string versionTag(version, sizeof(version) - 1);
    std::vector<uint8_t> versionDataTag(versionTag.begin(), versionTag.end());
    skStream.write(versionDataTag.data(), versionDataTag.size());
    // write colors
    LogResMapMetadata colorData;
    CM_ColorSpaceType colorSpaceType;
    VpeUtils::GetSbColorSpaceType(surfaceBuffer, colorSpaceType);
    SetLogResMapColorSpaceType(colorSpaceType, colorData);
    colorData.width = static_cast<uint16_t>(surfaceBuffer->GetWidth());
    colorData.height = static_cast<uint16_t>(surfaceBuffer->GetHeight());
    colorData.pixelFormat = static_cast<uint16_t>(surfaceBuffer->GetFormat());
    if (surfaceBuffer->GetFormat() != GRAPHIC_PIXEL_FMT_RGBA_8888) {
        IMAGE_LOGE("HDR-IMAGE encode res-map unsupported format");
        return;
    }
    size_t colorDataSize = sizeof(colorData);
    skStream.write(&colorData, colorDataSize);
    // write pixels
    std::vector<uint8_t> pixels;
    if (!ConvertBufferToData(surfaceBuffer, pixels)) {
        return;
    }
    size_t pixelSize = pixels.size();
    skStream.write(pixels.data(), pixelSize);
    // write size
    size_t writeSize = versionDataTag.size() + colorDataSize + pixelSize;
    IMAGE_LOGI("HDR-IMAGE try to encode Log-video metadata, datasize %{public}zu", writeSize);
    std::vector<uint8_t> dataSize = JpegMpfPacker::PackDataSize(writeSize, false);
    skStream.write(dataSize.data(), dataSize.size());
    // write tag
    const char rawTagName[] = "Res-Map\0";
    std::string tagName(rawTagName, sizeof(rawTagName) - 1);
    std::vector<uint8_t> dataTag(tagName.begin(), tagName.end());
    skStream.write(dataTag.data(), dataTag.size());
}

uint32_t ExtEncoder::WriteJpegCodedData(std::shared_ptr<AuxiliaryPicture>& auxPicture, SkWStream& skStream)
{
    auto pixelMap = auxPicture->GetContentPixel();
    bool cond = pixelMap == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DATA_ABNORMAL);
    pixelmap_ = pixelMap.get();
    sk_sp<SkData> skData = nullptr;
    if (pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC || pixelMap->GetFd() == nullptr) {
        SkDynamicMemoryWStream nonDMAStream;
        uint32_t error = EncodeImageByPixelMap(pixelmap_, false, nonDMAStream);
        IMAGE_LOGD("%{public}s EncodeImageByPixelMap result: %{public}u", __func__, error);
        skData = nonDMAStream.detachAsData();
    } else {
        sptr<SurfaceBuffer> auxSptr(reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd()));
        bool isSRGB = pixelMap->GetToSdrColorSpaceIsSRGB();
        SkImageInfo skInfo = GetSkInfo(pixelmap_, false, isSRGB);
        skData = GetImageEncodeData(auxSptr, skInfo, false);
    }
    cond = skData == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_ENCODE_FAILED);
    cond = auxPicture->GetType() == AuxiliaryPictureType::FRAGMENT_MAP;
    CHECK_ERROR_RETURN_RET(cond, SpliceFragmentStream(skStream, skData));
    skStream.write(skData->data(), skData->size());
    return SUCCESS;
}

uint32_t ExtEncoder::SpliceFragmentStream(SkWStream& skStream, sk_sp<SkData>& skData)
{
    Media::Rect fragmentMetadata;
    bool cond = !CheckFragmentMetadata(picture_, fragmentMetadata);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_PROPERTY_NOT_EXIST,
        "%{public}s: CheckFragmentMetadata failed!", __func__);
    const uint8_t* dataBytes = reinterpret_cast<const uint8_t*>(skData->data());
    // write JPEG SOI(0xFFD8)
    skStream.write(dataBytes, JPEG_MARKER_TAG_SIZE);
    std::vector<uint8_t> packedFragmentMetadata = JpegMpfPacker::PackFragmentMetadata(fragmentMetadata);
    // write fragment metadata
    skStream.write(packedFragmentMetadata.data(), packedFragmentMetadata.size());
    // write fragment auxiliary image data
    skStream.write(dataBytes + JPEG_MARKER_TAG_SIZE, skData->size() - JPEG_MARKER_TAG_SIZE);
    return SUCCESS;
}

uint32_t ExtEncoder::WriteJpegUncodedData(std::shared_ptr<AuxiliaryPicture>& auxPicture, SkWStream& skStream)
{
    auto pixelMap = auxPicture->GetContentPixel();
    bool cond = pixelMap == nullptr;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DATA_ABNORMAL);
    void* bytes = nullptr;
    uint32_t size = 0;
    Size imageSize;
    if (pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC || pixelMap->GetFd() == nullptr) {
        bytes = pixelMap->GetWritablePixels();
        size = pixelMap->GetCapacity();
        imageSize.width = pixelMap->GetWidth();
        imageSize.height = pixelMap->GetHeight();
    } else {
        auto surfaceBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
        bytes = surfaceBuffer->GetVirAddr();
        size = surfaceBuffer->GetSize();
        imageSize.width = surfaceBuffer->GetWidth();
        imageSize.height = surfaceBuffer->GetHeight();
    }
    uint32_t writeSize = (uint32_t)imageSize.width * (uint32_t)imageSize.height;
    AuxiliaryPictureInfo auxInfo = auxPicture->GetAuxiliaryPictureInfo();
    if (auxInfo.auxiliaryPictureType == AuxiliaryPictureType::DEPTH_MAP) {
        writeSize *= DEPTH_MAP_BYTES;
    } else if (auxInfo.auxiliaryPictureType == AuxiliaryPictureType::LINEAR_MAP) {
        writeSize *= LINEAR_MAP_BYTES;
    }
    IMAGE_LOGD("%{public}s auxType: %{public}d, width: %{public}d, height: %{public}d, buffer size: %{public}u,"
        " write size: %{public}u", __func__, auxInfo.auxiliaryPictureType, imageSize.width, imageSize.height,
        size, writeSize);
    skStream.write(bytes, std::min(size, writeSize));
    return SUCCESS;
}

void ExtEncoder::WriteJpegAuxiliarySizeAndTag(uint32_t size, std::shared_ptr<AuxiliaryPicture>& auxPicture,
    SkWStream& skStream)
{
    // Write auxiliary image size(little endian)
    std::vector<uint8_t> auxSize = JpegMpfPacker::PackDataSize(size, false);
    skStream.write(auxSize.data(), auxSize.size());

    // Write auxiliary tag name
    AuxiliaryPictureInfo auxInfo = auxPicture->GetAuxiliaryPictureInfo();
    std::vector<uint8_t> tagName = JpegMpfPacker::PackAuxiliaryTagName(auxInfo.jpegTagName);
    skStream.write(tagName.data(), tagName.size());
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
    bool cond = payloadSize > INT32_MAX;
    CHECK_INFO_RETURN_RET_LOG(cond, false, "payloadSize is over INT32_MAX");
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
    bool cond = metadata.staticMetadata.size() < staticMetadataSize;
    CHECK_INFO_RETURN_RET_LOG(cond, false, "GetStaticMetadata failed");
    cond = memcpy_s(&staticMetadata, staticMetadataSize,
        metadata.staticMetadata.data(), metadata.staticMetadata.size()) != EOK;
    CHECK_INFO_RETURN_RET_LOG(cond, false, "GetStaticMetadata failed, memcpy_s failed");
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
    bool cond = index > GAINMAP_CHANNEL_MULTI - 1;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "GetToneMapChannel index:[%{public}d] unsupported", index);
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
    toneMapMetadata.channelCnt = (isoMeta.gainmapChannelNum == GAINMAP_CHANNEL_MULTI) ?
        GAINMAP_CHANNEL_MULTI : GAINMAP_CHANNEL_SINGLE;
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
    bool cond = !HdrHeifPackerHelper::PackIT35Info(metadata, it35Info);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "get it35 info failed");
    std::shared_ptr<AbsMemory> propertyAshmem =
        AllocateNewSharedMem(GetBufferSize(it35Info.size()), IT35_ASHMEM_TAG);
    cond = propertyAshmem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "AssembleIT35SharedBuffer it35 alloc failed");
    tmpMemoryList_.push_back(propertyAshmem);
    cond = !FillImagePropertyItem(propertyAshmem, 0, PropertyType::IT35_INFO, it35Info.data(), it35Info.size());
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "AssembleIT35SharedBuffer fill failed");
    outBuffer.fd = *static_cast<int *>(propertyAshmem->extend.data);
    outBuffer.capacity = propertyAshmem->data.size;
    outBuffer.filledLen = propertyAshmem->data.size;
    return true;
}

bool ExtEncoder::AssembleICCImageProperty(sk_sp<SkData>& iccProfile, SharedBuffer& outBuffer)
{
    bool cond = iccProfile == nullptr || iccProfile->size() == 0;
    CHECK_INFO_RETURN_RET_LOG(cond, false, "AssembleICCImageProperty iccprofile is nullptr");
    std::shared_ptr<AbsMemory> propertyAshmem =
        AllocateNewSharedMem(GetBufferSize(iccProfile->size()), ICC_ASHMEM_TAG);
    cond = propertyAshmem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "AssembleICCImageProperty alloc failed");
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
    bool cond = !FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Fill colorType failed");
    cond = !FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::COLOR_INFO, &colorInfo, sizeof(ColourInfo));
    CHECK_INFO_RETURN_RET_LOG(cond, false, "Fill colorInfo failed");
    return true;
}

bool ExtEncoder::AssembleOutputSharedBuffer(SharedBuffer& outBuffer, std::shared_ptr<AbsMemory>& outMem)
{
    bool cond = output_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "AssembleOutputSharedBuffer output_ is nullptr");
    OutputStreamType outType = output_->GetType();
    size_t outputCapacity = DEFAULT_OUTPUT_SIZE;
    if (outType != OutputStreamType::FILE_PACKER) {
        output_->GetCapicity(outputCapacity);
    }
    std::shared_ptr<AbsMemory> mem = AllocateNewSharedMem(outputCapacity, OUTPUT_ASHMEM_TAG);
    cond = mem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "AssembleOutputSharedBuffer alloc out sharemem failed");
    outMem = mem;
    tmpMemoryList_.push_back(mem);
    if (mem->extend.data != nullptr) {
        outBuffer.fd = *static_cast<int *>(mem->extend.data);
    }
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
    bool cond = !tempRes;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
        "ExtEncoder::DoHeifEncode alloc sharedbuffer failed");

    sptr<ICodecImage> codec = GetCodecManager();
    CHECK_ERROR_RETURN_RET(codec == nullptr, ERR_IMAGE_ENCODE_FAILED);
    uint32_t outSize = DEFAULT_OUTPUT_SIZE;
    int32_t encodeRes = codec->DoHeifEncode(inputImgs, inputMetas, refs, outputBuffer, outSize);
    cond = encodeRes != HDF_SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "ExtEncoder::DoHeifEncode DoHeifEncode failed");
    IMAGE_LOGI("ExtEncoder::DoHeifEncode output type is %{public}d", output_->GetType());
    bool writeRes = output_->Write(reinterpret_cast<uint8_t *>(outputAshmem->data.data), outSize);
    cond = !writeRes;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_ENCODE_FAILED, "ExtEncoder::DoHeifEncode Write failed");
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
    item->sharedProperties.fd = INVALID_FD;
    item->pixelSharedBuffer.fd = INVALID_FD;
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
    bool cond = hasLight && (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::CONTENT_LIGHT_LEVEL, &colour, sizeof(ContentLightLevel)));
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "AssembleTmapImageItem fill CONTENT_LIGHT_LEVEL failed");
    cond = hasToneMap && (!FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::TONE_MAP_METADATA, &toneMap, sizeof(ToneMapMetadata)));
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "AssembleTmapImageItem fill toneMap failed");
    cond = !AssembleIT35SharedBuffer(metadata, item->sharedProperties);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "AssembleTmapImageItem fill it35 failed");
    return item;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
std::shared_ptr<ImageItem> ExtEncoder::AssemblePrimaryImageItem(sptr<SurfaceBuffer>& surfaceBuffer,
    const PlEncodeOptions &opts)
{
    bool cond = pixelmap_ == nullptr || surfaceBuffer == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "AssemblePrimaryImageItem surfaceBuffer is nullptr");
    auto item = std::make_shared<ImageItem>();
    item->id = PRIMARY_IMAGE_ITEM_ID;
    auto ret = HwSetColorSpaceData(pixelmap_, surfaceBuffer);
    cond = (ret != GSERROR_OK);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "HwSetColorSpaceInfo GetMetadata failed");
    item->pixelBuffer = sptr<NativeBuffer>::MakeSptr(surfaceBuffer->GetBufferHandle());
    item->isPrimary = true;
    item->isHidden = false;
    item->compressType = COMPRESS_TYPE_HEVC;
    item->quality = opts.quality;
    item->sharedProperties.fd = INVALID_FD;
    item->pixelSharedBuffer.fd = INVALID_FD;
#ifdef USE_M133_SKIA
    sk_sp<SkData> iccProfile = icc_from_color_space(ToSkInfo(pixelmap_), nullptr, nullptr);
#else
    sk_sp<SkData> iccProfile = icc_from_color_space(ToSkInfo(pixelmap_));
#endif
    bool tempRes = AssembleICCImageProperty(iccProfile, item->sharedProperties);
    CHECK_ERROR_RETURN_RET(!tempRes, nullptr);
    uint32_t litePropertiesSize = 0;
    litePropertiesSize += (sizeof(PropertyType::COLOR_TYPE) + sizeof(ColorType));
    item->liteProperties.resize(litePropertiesSize);
    size_t offset = 0;
    ColorType colorType = ColorType::RICC;
    cond = !FillLitePropertyItem(item->liteProperties, offset,
        PropertyType::COLOR_TYPE, &colorType, sizeof(ColorType));
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "AssemblePrimaryImageItem Fill color type failed");
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

void inline FreeBlob(uint8_t** Blob)
{
    if (Blob != nullptr && *Blob != nullptr) {
        free(*Blob);
        *Blob = nullptr;
    }
}

bool ExtEncoder::AssembleExifMetaItem(std::vector<MetaItem>& metaItems)
{
    if (!opts_.needsPackProperties) {
        IMAGE_LOGD("no need encode exif");
        return false;
    }
    ExifData* exifData = nullptr;
    if (picture_ != nullptr && picture_->GetExifMetadata() != nullptr &&
        picture_->GetExifMetadata()->GetExifData() != nullptr) {
        exifData = picture_->GetExifMetadata()->GetExifData();
    } else if (pixelmap_ != nullptr && pixelmap_->GetExifMetadata() != nullptr &&
        pixelmap_->GetExifMetadata()->GetExifData() != nullptr) {
        exifData = pixelmap_->GetExifMetadata()->GetExifData();
    } else {
        IMAGE_LOGD("no exif");
        return false;
    }
    uint8_t* exifBlob = nullptr;
    uint32_t exifSize = 0;
    TiffParser::Encode(&exifBlob, exifSize, exifData);
    CHECK_ERROR_RETURN_RET_LOG(exifBlob == nullptr, false, "Encode exif data failed");
    auto item = std::make_shared<MetaItem>();
    item->id = EXIF_META_ITEM_ID;
    item->itemName = "exif";
    item->data.fd = INVALID_FD;
    std::shared_ptr<AbsMemory> propertyAshmem = AllocateNewSharedMem(exifSize + EXIF_PRE_SIZE, EXIF_ASHMEM_TAG);
    if (propertyAshmem == nullptr) {
        FreeBlob(&exifBlob);
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
    FreeBlob(&exifBlob);
    return fillRes;
}

bool ExtEncoder::FillPixelSharedBuffer(sptr<SurfaceBuffer> sbBuffer, uint32_t capacity, SharedBuffer& outBuffer)
{
    bool cond = sbBuffer == nullptr || capacity == 0;
    CHECK_INFO_RETURN_RET_LOG(cond, false, "%{public}s iccprofile is nullptr", __func__);
    std::shared_ptr<AbsMemory> sharedMem = AllocateNewSharedMem(capacity, IMAGE_DATA_TAG);
    cond = sharedMem == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s alloc failed", __func__);
    tmpMemoryList_.push_back(sharedMem);
    uint8_t* memData = reinterpret_cast<uint8_t*>(sharedMem->data.data);
    size_t memSize = sharedMem->data.size;
    cond = capacity > memSize;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s shared capacity[%{public}d] over memSize[%{public}ld]", __func__, capacity, memSize);
    cond = sharedMem->extend.data == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s sharedMem's extend data is nullptr", __func__);
    if (memcpy_s(memData, memSize, sbBuffer->GetVirAddr(), capacity) == EOK) {
        outBuffer.fd = *static_cast<int *>(sharedMem->extend.data);
        outBuffer.capacity = memSize;
        outBuffer.filledLen = memSize;
    } else {
        IMAGE_LOGE("%{public}s memcpy failed", __func__);
        return false;
    }
    return true;
}

void ExtEncoder::AssembleAuxiliaryRefItem(AuxiliaryPictureType type, std::vector<ItemRef>& refs)
{
    auto item = std::make_shared<ItemRef>();
    item->type = ReferenceType::AUXL;
    item->to.resize(INDEX_ONE);
    item->to[INDEX_ZERO] = PRIMARY_IMAGE_ITEM_ID;
    switch (type) {
        case AuxiliaryPictureType::DEPTH_MAP:
            item->from = DEPTH_MAP_ITEM_ID;
            break;
        case AuxiliaryPictureType::UNREFOCUS_MAP:
            item->from = UNREFOCUS_MAP_ITEM_ID;
            break;
        case AuxiliaryPictureType::LINEAR_MAP:
            item->from = LINEAR_MAP_ITEM_ID;
            break;
        case AuxiliaryPictureType::FRAGMENT_MAP:
            item->from = FRAGMENT_MAP_ITEM_ID;
            break;
        case AuxiliaryPictureType::THUMBNAIL:
            item->type = ReferenceType::THMB;
            item->from = THUMBNAIL_ITEM_ID;
            break;
        default:
            break;
    }
    refs.push_back(*item);
}

void ExtEncoder::AssembleBlobRefItem(MetadataType type, std::vector<ItemRef>& refs)
{
    auto metadataTuple = HEIF_METADATA_MAPPING.at(type);
    auto item = std::make_shared<ItemRef>();
    item->type = ReferenceType::CDSC;
    item->from = std::get<0>(metadataTuple);
    item->to.resize(INDEX_ONE);
    item->to[INDEX_ZERO] = PRIMARY_IMAGE_ITEM_ID;
    refs.push_back(*item);
}
 
bool ExtEncoder::AssembleBlobMetaItem(MetadataType type, std::vector<MetaItem>& metaItems)
{
    auto metadataTuple = HEIF_METADATA_MAPPING.at(type);
    if (!opts_.needsPackProperties) {
        IMAGE_LOGD("no need encode blob: %{public}d", type);
        return false;
    }
    if (picture_ == nullptr || picture_->GetMetadata(type) == nullptr) {
        IMAGE_LOGE("fail to get picture or fail to get blob");
        return false;
    }
    auto blobMetadata = picture_->GetMetadata(type);
    uint32_t blobDataSize = blobMetadata->GetBlobSize();
    if (blobDataSize == 0) {
        IMAGE_LOGE("blob size is 0");
        return false;
    }
    auto blobDataPtr = blobMetadata->GetBlobPtr();
    if (blobDataPtr == nullptr) {
        IMAGE_LOGE("AssembleBlobMetaItem getBlob is nullptr");
        return false;
    }
 
    auto item = std::make_shared<MetaItem>();
    item->id = std::get<0>(metadataTuple);
    item->itemName = std::get<NUM_2>(metadataTuple);
    item->data.fd = INVALID_FD;
    std::shared_ptr<AbsMemory> propertyAshmem = AllocateNewSharedMem(blobDataSize, std::get<1>(metadataTuple));
    if (propertyAshmem == nullptr) {
        IMAGE_LOGE("AssembleBlobMetaItem alloc propertyAshmem failed");
        return false;
    }
    tmpMemoryList_.push_back(propertyAshmem);
    uint8_t* memData = reinterpret_cast<uint8_t*>(propertyAshmem->data.data);
    size_t memSize = propertyAshmem->data.size;
    bool fillRes = (memcpy_s(memData, memSize, blobDataPtr, blobDataSize) == EOK);
    if (fillRes) {
        item->data.fd = *static_cast<int *>(propertyAshmem->extend.data);
        item->data.capacity = propertyAshmem->data.size;
        item->data.filledLen = propertyAshmem->data.size;
        metaItems.push_back(*item);
    }
    return fillRes;
}
#endif
} // namespace ImagePlugin
} // namespace OHOS
