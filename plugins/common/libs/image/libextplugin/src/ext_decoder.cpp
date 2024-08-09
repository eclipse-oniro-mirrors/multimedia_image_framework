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

#include "ext_decoder.h"

#include <algorithm>
#include <map>
#include <sstream>

#include "src/codec/SkJpegCodec.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "ext_pixel_convert.h"
#include "image_log.h"
#include "image_format_convert.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "ffrt.h"
#include "hisysevent.h"
#endif
#include "image_system_properties.h"
#include "image_utils.h"
#include "media_errors.h"
#include "native_buffer.h"
#include "securec.h"
#include "string_ex.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#include "hdr_helper.h"
#endif
#ifdef HEIF_HW_DECODE_ENABLE
#include "heif_impl/HeifDecoder.h"
#include "heif_impl/HeifDecoderImpl.h"
#include "hardware/heif_hw_decoder.h"
#endif
#include "color_utils.h"
#include "heif_parser.h"
#include "heif_format_agent.h"
#include "heif_type.h"
#include "image/image_plugin_type.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "ExtDecoder"

namespace {
    constexpr static int32_t ZERO = 0;
    constexpr static int32_t NUM_2 = 2;
    constexpr static int32_t NUM_3 = 3;
    constexpr static int32_t NUM_4 = 4;
    constexpr static int32_t OFFSET = 1;
    constexpr static size_t SIZE_ZERO = 0;
    constexpr static uint32_t DEFAULT_SAMPLE_SIZE = 1;
    constexpr static uint32_t NO_EXIF_TAG = 1;
    constexpr static uint32_t OFFSET_0 = 0;
    constexpr static uint32_t OFFSET_1 = 1;
    constexpr static uint32_t OFFSET_2 = 2;
    constexpr static uint32_t OFFSET_3 = 3;
    constexpr static uint32_t OFFSET_5 = 5;
    constexpr static uint32_t SHIFT_BITS_8 = 8;
    constexpr static uint32_t SHIFT_BITS_16 = 16;
    constexpr static uint32_t SHIFT_BITS_24 = 24;
    constexpr static uint32_t DESC_SIGNATURE = 0x64657363;
    constexpr static size_t SIZE_1 = 1;
    constexpr static size_t SIZE_4 = 4;
    constexpr static int HARDWARE_MIN_DIM = 1024;
    constexpr static int HARDWARE_MAX_DIM = 8192;
    constexpr static float HALF = 0.5;
    constexpr static float QUARTER = 0.25;
    constexpr static float ONE_EIGHTH = 0.125;
    constexpr static uint64_t ICC_HEADER_SIZE = 132;
    constexpr static size_t SMALL_FILE_SIZE = 1000 * 1000 * 10;
    constexpr static int32_t LOOP_COUNT_INFINITE = 0;
    constexpr static int32_t SK_REPETITION_COUNT_INFINITE = -1;
    constexpr static int32_t SK_REPETITION_COUNT_ERROR_VALUE = -2;
}

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace OHOS::HDI::Base;
#endif
using namespace std;
const static string DEFAULT_EXIF_VALUE = "default_exif_value";
const static string CODEC_INITED_KEY = "CodecInited";
const static string ENCODED_FORMAT_KEY = "EncodedFormat";
const static string SUPPORT_SCALE_KEY = "SupportScale";
const static string SUPPORT_CROP_KEY = "SupportCrop";
const static string EXT_SHAREMEM_NAME = "EXT RawData";
const static string TAG_ORIENTATION_STRING = "Orientation";
const static string TAG_ORIENTATION_INT = "OrientationInt";
const static string IMAGE_DELAY_TIME = "DelayTime";
const static string IMAGE_DISPOSAL_TYPE = "DisposalType";
const static string IMAGE_LOOP_COUNT = "GIFLoopCount";
const static std::string HW_MNOTE_TAG_HEADER = "HwMnote";
const static std::string HW_MNOTE_CAPTURE_MODE = "HwMnoteCaptureMode";
const static std::string HW_MNOTE_PHYSICAL_APERTURE = "HwMnotePhysicalAperture";
const static std::string HW_MNOTE_TAG_ROLL_ANGLE = "HwMnoteRollAngle";
const static std::string HW_MNOTE_TAG_PITCH_ANGLE = "HwMnotePitchAngle";
const static std::string HW_MNOTE_TAG_SCENE_FOOD_CONF = "HwMnoteSceneFoodConf";
const static std::string HW_MNOTE_TAG_SCENE_STAGE_CONF = "HwMnoteSceneStageConf";
const static std::string HW_MNOTE_TAG_SCENE_BLUE_SKY_CONF = "HwMnoteSceneBlueSkyConf";
const static std::string HW_MNOTE_TAG_SCENE_GREEN_PLANT_CONF = "HwMnoteSceneGreenPlantConf";
const static std::string HW_MNOTE_TAG_SCENE_BEACH_CONF = "HwMnoteSceneBeachConf";
const static std::string HW_MNOTE_TAG_SCENE_SNOW_CONF = "HwMnoteSceneSnowConf";
const static std::string HW_MNOTE_TAG_SCENE_SUNSET_CONF = "HwMnoteSceneSunsetConf";
const static std::string HW_MNOTE_TAG_SCENE_FLOWERS_CONF = "HwMnoteSceneFlowersConf";
const static std::string HW_MNOTE_TAG_SCENE_NIGHT_CONF = "HwMnoteSceneNightConf";
const static std::string HW_MNOTE_TAG_SCENE_TEXT_CONF = "HwMnoteSceneTextConf";
const static std::string HW_MNOTE_TAG_FACE_COUNT = "HwMnoteFaceCount";
const static std::string HW_MNOTE_TAG_FOCUS_MODE = "HwMnoteFocusMode";
// SUCCESS is existed in both OHOS::HiviewDFX and OHOS::Media
#define SUCCESS OHOS::Media::SUCCESS
const static std::string DEFAULT_PACKAGE_NAME = "entry";
const static std::string DEFAULT_VERSION_ID = "1";
const static std::string UNKNOWN_IMAGE = "unknown";
constexpr static int NUM_ONE = 1;
#ifdef JPEG_HW_DECODE_ENABLE
const static uint32_t PLANE_COUNT_TWO = 2;
#endif

struct ColorTypeOutput {
    PixelFormat outFormat;
    SkColorType skFormat;
};

static const map<PixelFormat, ColorTypeOutput> COLOR_TYPE_MAP = {
    { PixelFormat::UNKNOWN, { PixelFormat::RGBA_8888, kRGBA_8888_SkColorType } },
    { PixelFormat::RGBA_8888, { PixelFormat::RGBA_8888, kRGBA_8888_SkColorType } },
    { PixelFormat::BGRA_8888, { PixelFormat::BGRA_8888, kBGRA_8888_SkColorType } },
    { PixelFormat::ALPHA_8, { PixelFormat::ALPHA_8, kAlpha_8_SkColorType } },
    { PixelFormat::RGB_565, { PixelFormat::RGB_565, kRGB_565_SkColorType } },
    { PixelFormat::RGB_888, { PixelFormat::RGB_888, kRGB_888x_SkColorType } },
};

static const map<AlphaType, SkAlphaType> ALPHA_TYPE_MAP = {
    { AlphaType::IMAGE_ALPHA_TYPE_OPAQUE, kOpaque_SkAlphaType },
    { AlphaType::IMAGE_ALPHA_TYPE_PREMUL, kPremul_SkAlphaType },
    { AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL, kUnpremul_SkAlphaType },
};

static const map<SkEncodedImageFormat, string> FORMAT_NAME = {
    { SkEncodedImageFormat::kBMP, "image/bmp" },
    { SkEncodedImageFormat::kGIF, "image/gif" },
    { SkEncodedImageFormat::kICO, "image/x-ico" },
    { SkEncodedImageFormat::kJPEG, "image/jpeg" },
    { SkEncodedImageFormat::kPNG, "image/png" },
    { SkEncodedImageFormat::kWBMP, "image/bmp" },
    { SkEncodedImageFormat::kWEBP, "image/webp" },
    { SkEncodedImageFormat::kPKM, "" },
    { SkEncodedImageFormat::kKTX, "" },
    { SkEncodedImageFormat::kASTC, "" },
    { SkEncodedImageFormat::kDNG, "image/raw" },
    { SkEncodedImageFormat::kHEIF, "image/heif" },
};

#ifdef HEIF_HW_DECODE_ENABLE
static const map<PixelFormat, SkHeifColorFormat> HEIF_FORMAT_MAP = {
    { PixelFormat::RGBA_1010102, kHeifColorFormat_RGBA_1010102 },
    { PixelFormat::YCBCR_P010, kHeifColorFormat_P010_NV12 },
    { PixelFormat::YCRCB_P010, kHeifColorFormat_P010_NV21 },
};
#endif

static const map<PixelFormat, JpegYuvFmt> PLPIXEL_FORMAT_YUV_JPG_MAP = {
    { PixelFormat::NV21, JpegYuvFmt::OutFmt_NV21 }, { PixelFormat::NV12, JpegYuvFmt::OutFmt_NV12 }
};

// LCOV_EXCL_START
static void SetDecodeContextBuffer(DecodeContext &context,
    AllocatorType type, uint8_t* ptr, uint64_t count, void* fd)
{
    context.allocatorType = type;
    context.freeFunc = nullptr;
    context.pixelsBuffer.buffer = ptr;
    context.pixelsBuffer.bufferSize = count;
    context.pixelsBuffer.context = fd;
}

static uint32_t ShareMemAlloc(DecodeContext &context, uint64_t count)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport share mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    auto fd = make_unique<int32_t>();
    *fd = AshmemCreate(EXT_SHAREMEM_NAME.c_str(), count);
    if (*fd < 0) {
        IMAGE_LOGE("AshmemCreate failed");
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    int result = AshmemSetProt(*fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        ::close(*fd);
        IMAGE_LOGE("AshmemSetProt failed");
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    void* ptr = ::mmap(nullptr, count, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, ZERO);
    if (ptr == MAP_FAILED) {
        ::close(*fd);
        IMAGE_LOGE("::mmap failed");
        return ERR_SHAMEM_DATA_ABNORMAL;
    }
    SetDecodeContextBuffer(context,
        AllocatorType::SHARE_MEM_ALLOC, static_cast<uint8_t*>(ptr), count, fd.release());
    return SUCCESS;
#endif
}

uint32_t ExtDecoder::DmaMemAlloc(DecodeContext &context, uint64_t count, SkImageInfo &dstInfo)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = dstInfo.width(),
        .height = dstInfo.height(),
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // hardware decode only support rgba8888
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    if (context.info.pixelFormat == PixelFormat::RGBA_1010102) {
        requestConfig.format = GRAPHIC_PIXEL_FMT_RGBA_1010102;
    } else if (context.info.pixelFormat == PixelFormat::YCRCB_P010) {
        requestConfig.format = GRAPHIC_PIXEL_FMT_YCRCB_P010;
    } else if (context.info.pixelFormat == PixelFormat::YCBCR_P010) {
        requestConfig.format = GRAPHIC_PIXEL_FMT_YCBCR_P010;
    } else if (outputColorFmt_ == PIXEL_FMT_YCRCB_420_SP) {
        requestConfig.format = GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
        requestConfig.usage |= BUFFER_USAGE_VENDOR_PRI16; // height is 64-bytes aligned
        IMAGE_LOGD("ExtDecoder::DmaMemAlloc desiredFormat is NV21");
    }
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        IMAGE_LOGE("SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
        return ERR_DMA_NOT_EXIST;
    }
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        IMAGE_LOGE("NativeBufferReference failed");
        return ERR_DMA_DATA_ABNORMAL;
    }

    IMAGE_LOGD("ExtDecoder::DmaMemAlloc sb stride is %{public}d, height is %{public}d, size is %{public}d",
        sb->GetStride(), sb->GetHeight(), sb->GetSize());
    SetDecodeContextBuffer(context,
        AllocatorType::DMA_ALLOC, static_cast<uint8_t*>(sb->GetVirAddr()), count, nativeBuffer);
    return SUCCESS;
#endif
}

static uint32_t HeapMemAlloc(DecodeContext &context, uint64_t count)
{
    if (count == 0 || count > PIXEL_MAP_MAX_RAM_SIZE) {
        IMAGE_LOGE("HeapMemAlloc Invalid value of bufferSize");
        return ERR_IMAGE_DATA_ABNORMAL;
    }
    auto out = static_cast<uint8_t *>(malloc(count));
#ifdef _WIN32
    if (memset_s(out, ZERO, count) != EOK) {
#else
    if (memset_s(out, count, ZERO, count) != EOK) {
#endif
        IMAGE_LOGE("Decode failed, memset buffer failed");
        free(out);
        return ERR_IMAGE_DECODE_FAILED;
    }
    SetDecodeContextBuffer(context, AllocatorType::HEAP_ALLOC, out, count, nullptr);
    return SUCCESS;
}

uint32_t ExtDecoder::HeifYUVMemAlloc(OHOS::ImagePlugin::DecodeContext &context)
{
#ifdef HEIF_HW_DECODE_ENABLE
    HeifHardwareDecoder decoder;
    GraphicPixelFormat graphicPixelFormat = GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
    if (context.info.pixelFormat == PixelFormat::NV12) {
        graphicPixelFormat = GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    } else if (context.info.pixelFormat == PixelFormat::YCRCB_P010) {
        graphicPixelFormat = GRAPHIC_PIXEL_FMT_YCRCB_P010;
    } else if (context.info.pixelFormat == PixelFormat::YCBCR_P010) {
        graphicPixelFormat = GRAPHIC_PIXEL_FMT_YCBCR_P010;
    }
    sptr<SurfaceBuffer> hwBuffer
            = decoder.AllocateOutputBuffer(info_.width(), info_.height(), graphicPixelFormat);
    if (hwBuffer == nullptr) {
        IMAGE_LOGE("HeifHardwareDecoder AllocateOutputBuffer return null");
        return ERR_DMA_NOT_EXIST;
    }

    void* nativeBuffer = hwBuffer.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        IMAGE_LOGE("HeifYUVMemAlloc Reference failed");
        return ERR_DMA_DATA_ABNORMAL;
    }

    IMAGE_LOGI("ExtDecoder::HeifYUVMemAlloc sb stride is %{public}d, height is %{public}d, size is %{public}d",
               hwBuffer->GetStride(), hwBuffer->GetHeight(), hwBuffer->GetSize());
    uint64_t yuvBufferSize = JpegDecoderYuv::GetYuvOutSize(info_.width(), info_.height());
    SetDecodeContextBuffer(context, AllocatorType::DMA_ALLOC,
                           static_cast<uint8_t*>(hwBuffer->GetVirAddr()), yuvBufferSize, nativeBuffer);
    return SUCCESS;
#else
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}
// LCOV_EXCL_STOP

ExtDecoder::ExtDecoder() : codec_(nullptr), frameCount_(ZERO)
{
}

ExtDecoder::~ExtDecoder()
{
    if (gifCache_ != nullptr) {
        free(gifCache_);
        gifCache_ = nullptr;
    }
}

void ExtDecoder::SetSource(InputDataStream &sourceStream)
{
    stream_ = &sourceStream;
    streamOff_ = sourceStream.Tell();
    if (streamOff_ >= sourceStream.GetStreamSize()) {
        streamOff_ = ZERO;
    }
}

void ExtDecoder::Reset()
{
    stream_ = nullptr;
    codec_ = nullptr;
    dstInfo_.reset();
    dstSubset_ = SkIRect::MakeEmpty();
    info_.reset();
}

static inline float Max(float a, float b)
{
    return (a > b) ? a : b;
}

// LCOV_EXCL_START
bool ExtDecoder::GetScaledSize(int &dWidth, int &dHeight, float &scale)
{
    if (info_.isEmpty() && !DecodeHeader()) {
        IMAGE_LOGE("DecodeHeader failed in GetScaledSize!");
        return false;
    }
    if (info_.isEmpty()) {
        IMAGE_LOGE("empty image info in GetScaledSize!");
        return false;
    }
    float finalScale = scale;
    if (scale == ZERO) {
        finalScale = Max(static_cast<float>(dWidth) / info_.width(),
            static_cast<float>(dHeight) / info_.height());
    }
    auto scaledDimension = codec_->getScaledDimensions(finalScale);
    dWidth = scaledDimension.width();
    dHeight = scaledDimension.height();
    scale = finalScale;
    IMAGE_LOGD("IsSupportScaleOnDecode info [%{public}d x %{public}d]", info_.width(), info_.height());
    IMAGE_LOGD("IsSupportScaleOnDecode [%{public}d x %{public}d]", dWidth, dHeight);
    IMAGE_LOGD("IsSupportScaleOnDecode [%{public}f]", scale);
    return true;
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
bool ExtDecoder::GetHardwareScaledSize(int &dWidth, int &dHeight, float &scale) {
    if (info_.isEmpty() && !DecodeHeader()) {
        IMAGE_LOGE("DecodeHeader failed in GetHardwareScaledSize!");
        return false;
    }
    if (info_.isEmpty()) {
        IMAGE_LOGE("empty image info in GetHardwareScaledSize!");
        return false;
    }
    float finalScale = scale;
    int oriWidth = info_.width();
    int oriHeight = info_.height();
    if (scale == ZERO) {
        finalScale = Max(static_cast<float>(dWidth) / oriWidth,
                         static_cast<float>(dHeight) / oriHeight);
    }
    // calculate sample size and dst size for hardware decode
    if (finalScale > HALF) {
        sampleSize_ = 1;
    } else if (finalScale > QUARTER) {
        sampleSize_ = 2;
    } else if (finalScale > ONE_EIGHTH) {
        sampleSize_ = 4;
    } else {
        sampleSize_ = 8;
    }
    dWidth = (oriWidth + sampleSize_ - NUM_ONE) / sampleSize_;
    dHeight = (oriHeight + sampleSize_ - NUM_ONE) / sampleSize_;
    return true;
}
#endif

bool ExtDecoder::IsSupportScaleOnDecode()
{
    constexpr float HALF_SCALE = 0.5f;
    int w = ZERO;
    int h = ZERO;
    float scale = HALF_SCALE;
    return GetScaledSize(w, h, scale);
}
// LCOV_EXCL_STOP

bool ExtDecoder::IsSupportCropOnDecode()
{
    if (info_.isEmpty() && !DecodeHeader()) {
        return false;
    }
    SkIRect innerRect = info_.bounds().makeInset(OFFSET, OFFSET);
    return IsSupportCropOnDecode(innerRect);
}

bool ExtDecoder::IsSupportCropOnDecode(SkIRect &target)
{
    if (info_.isEmpty() && !DecodeHeader()) {
        return false;
    }
    SkIRect orgbounds = info_.bounds();
    SkIRect source = target;
    if (orgbounds.contains(target) && codec_->getValidSubset(&target)) {
        return source == target;
    }
    return false;
}

// LCOV_EXCL_START
bool ExtDecoder::HasProperty(string key)
{
    if (CODEC_INITED_KEY.compare(key) == ZERO) {
        return CheckCodec();
    } else if (ENCODED_FORMAT_KEY.compare(key) == ZERO) {
        return true;
    } else if (SUPPORT_SCALE_KEY.compare(key) == ZERO) {
        return IsSupportScaleOnDecode();
    } else if (SUPPORT_CROP_KEY.compare(key) == ZERO) {
        return IsSupportCropOnDecode();
    }
    return false;
}

uint32_t ExtDecoder::GetImageSize(uint32_t index, Size &size)
{
    IMAGE_LOGD("GetImageSize index:%{public}u", index);
    if (!CheckIndexValied(index)) {
        IMAGE_LOGE("Invalid index:%{public}u, range:%{public}d", index, frameCount_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    IMAGE_LOGD("GetImageSize index:%{public}u, range:%{public}d", index, frameCount_);
    // Info has been get in check process, or empty on get failed.
    if (info_.isEmpty()) {
        IMAGE_LOGE("GetImageSize failed, decode header failed.");
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }
    size.width = static_cast<uint32_t>(info_.width());
    size.height = static_cast<uint32_t>(info_.height());
    return SUCCESS;
}
// LCOV_EXCL_STOP

static inline bool IsLowDownScale(const Size &size, SkImageInfo &info)
{
    return size.width < info.width() &&
        size.height < info.height();
}

// LCOV_EXCL_START
static inline bool IsValidCrop(const OHOS::Media::Rect &crop, SkImageInfo &info, SkIRect &out)
{
    out = SkIRect::MakeXYWH(crop.left, crop.top, crop.width, crop.height);
    if (out.fLeft < ZERO || out.fTop < ZERO) {
        return false;
    }
    if (out.fRight > info.width()) {
        out.fRight = info.width();
    }
    if (out.fBottom > info.height()) {
        out.fBottom = info.height();
    }
    return true;
}
// LCOV_EXCL_STOP

static sk_sp<SkColorSpace> getDesiredColorSpace(SkImageInfo &srcInfo, const PixelDecodeOptions &opts)
{
    if (opts.plDesiredColorSpace == nullptr) {
        return srcInfo.refColorSpace();
    }
    return opts.plDesiredColorSpace->ToSkColorSpace();
}

// LCOV_EXCL_START
uint32_t ExtDecoder::CheckDecodeOptions(uint32_t index, const PixelDecodeOptions &opts)
{
    if (ImageUtils::CheckMulOverflow(dstInfo_.width(), dstInfo_.height(), dstInfo_.bytesPerPixel())) {
        IMAGE_LOGE("SetDecodeOptions failed, width:%{public}d, height:%{public}d is too large",
                     dstInfo_.width(), dstInfo_.height());
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!IsValidCrop(opts.CropRect, info_, dstSubset_)) {
        IMAGE_LOGE("Invalid crop rect xy [%{public}d x %{public}d], wh [%{public}d x %{public}d]",
            dstSubset_.left(), dstSubset_.top(), dstSubset_.width(), dstSubset_.height());
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    dstOptions_.fFrameIndex = static_cast<int>(index);
#ifdef IMAGE_COLORSPACE_FLAG
    dstColorSpace_ = opts.plDesiredColorSpace;
#endif
    return SUCCESS;
}

uint32_t ExtDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    if (!CheckIndexValied(index)) {
        IMAGE_LOGE("Invalid index:%{public}u, range:%{public}d", index, frameCount_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (opts.sampleSize != DEFAULT_SAMPLE_SIZE) {
        IMAGE_LOGE("Do not support sample size now!");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    auto desireColor = ConvertToColorType(opts.desiredPixelFormat, info.pixelFormat);
    auto desireAlpha = ConvertToAlphaType(opts.desireAlphaType, info.alphaType);
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    outputColorFmt_ = (opts.desiredPixelFormat == PixelFormat::NV21 ? PIXEL_FMT_YCRCB_420_SP : PIXEL_FMT_RGBA_8888);
#endif

    if (codec_) {
        SkEncodedImageFormat skEncodeFormat = codec_->getEncodedFormat();
        if (skEncodeFormat == SkEncodedImageFormat::kJPEG && IsYuv420Format(opts.desiredPixelFormat)) {
            info.pixelFormat = opts.desiredPixelFormat;
            desiredSizeYuv_.width = opts.desiredSize.width;
            desiredSizeYuv_.height = opts.desiredSize.height;
        }
        if (skEncodeFormat == SkEncodedImageFormat::kHEIF && IsYuv420Format(opts.desiredPixelFormat)) {
            info.pixelFormat = opts.desiredPixelFormat;
        }
    }
    // SK only support low down scale
    int dstWidth = opts.desiredSize.width;
    int dstHeight = opts.desiredSize.height;
    float scale = ZERO;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (IsSupportHardwareDecode()) {
        // get dstInfo for hardware decode
        if (IsLowDownScale(opts.desiredSize, info_) && GetHardwareScaledSize(dstWidth, dstHeight, scale)) {
            hwDstInfo_ = SkImageInfo::Make(dstWidth, dstHeight, desireColor, desireAlpha, info_.refColorSpace());
        } else {
            hwDstInfo_ = SkImageInfo::Make(info_.width(), info_.height(),
                                           desireColor, desireAlpha, info_.refColorSpace());
        }
        // restore dstWidth and dstHeight
        dstWidth = opts.desiredSize.width;
        dstHeight = opts.desiredSize.height;
    }
#endif
    if (IsLowDownScale(opts.desiredSize, info_) && GetScaledSize(dstWidth, dstHeight, scale)) {
        dstInfo_ = SkImageInfo::Make(dstWidth, dstHeight, desireColor, desireAlpha,
            getDesiredColorSpace(info_, opts));
    } else {
        dstInfo_ = SkImageInfo::Make(info_.width(), info_.height(),
            desireColor, desireAlpha, getDesiredColorSpace(info_, opts));
    }
    auto resCode = CheckDecodeOptions(index, opts);
    if (resCode != SUCCESS) {
        return resCode;
    }

    info.size.width = static_cast<uint32_t>(dstInfo_.width());
    info.size.height = static_cast<uint32_t>(dstInfo_.height());
    return SUCCESS;
}

uint32_t ExtDecoder::SetContextPixelsBuffer(uint64_t byteCount, DecodeContext &context)
{
    if (byteCount == ZERO) {
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
        return ShareMemAlloc(context, byteCount);
    } else if (context.allocatorType == Media::AllocatorType::DMA_ALLOC) {
        return DmaMemAlloc(context, byteCount, dstInfo_);
    }
    return HeapMemAlloc(context, byteCount);
}

static void DebugInfo(SkImageInfo &info, SkImageInfo &dstInfo, SkCodec::Options &opts)
{
    IMAGE_LOGD("Decode source info: WH[%{public}d x %{public}d], A %{public}d, C %{public}d.",
        info.width(), info.height(),
        info.alphaType(), info.colorType());
    IMAGE_LOGD("Decode dst info: WH[%{public}d x %{public}d], A %{public}d, C %{public}d.",
        dstInfo.width(), dstInfo.height(), dstInfo.alphaType(), dstInfo.colorType());
    if (opts.fSubset != nullptr) {
        IMAGE_LOGD("Decode dstOpts sub: (%{public}d, %{public}d), WH[%{public}d x %{public}d]",
            opts.fSubset->fLeft, opts.fSubset->fTop,
            opts.fSubset->width(), opts.fSubset->height());
    }
}
// LCOV_EXCL_STOP

static uint64_t GetByteSize(int32_t width, int32_t height)
{
    return static_cast<uint64_t>(width * height + ((width + 1) / NUM_2) * ((height + 1) / NUM_2) * NUM_2);
}

static void UpdateContextYuvInfo(DecodeContext &context, DestConvertInfo &destInfo)
{
    context.yuvInfo.yWidth = static_cast<uint32_t>(destInfo.width);
    context.yuvInfo.yHeight = static_cast<uint32_t>(destInfo.height);
    context.yuvInfo.yStride = destInfo.yStride;
    context.yuvInfo.uvWidth = static_cast<uint32_t>((destInfo.width + 1) / NUM_2);
    context.yuvInfo.uvHeight = static_cast<uint32_t>((destInfo.height + 1) / NUM_2);
    context.yuvInfo.uvStride = destInfo.uvStride;
    context.yuvInfo.yOffset = destInfo.yOffset;
    context.yuvInfo.uvOffset = destInfo.uvOffset;
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

uint32_t ExtDecoder::ConvertFormatToYUV(DecodeContext &context, SkImageInfo &skInfo,
    uint64_t byteCount, PixelFormat format)
{
    ConvertDataInfo srcDataInfo;
    srcDataInfo.buffer = static_cast<uint8_buffer_type>(context.pixelsBuffer.buffer);
    srcDataInfo.bufferSize = byteCount;
    srcDataInfo.imageSize = {skInfo.width(), skInfo.height()};
    srcDataInfo.pixelFormat = context.pixelFormat;
    srcDataInfo.colorSpace = static_cast<ColorSpace>(context.colorSpace);

    DestConvertInfo destInfo = {skInfo.width(), skInfo.height()};
    destInfo.format = format;
    destInfo.allocType = context.allocatorType;
    auto ret = Media::ImageFormatConvert::ConvertImageFormat(srcDataInfo, destInfo);
    if (ret != SUCCESS) {
        IMAGE_LOGE("Decode convert failed , ret=%{public}d", ret);
        return ret;
    }
    FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
    SetDecodeContextBuffer(context, context.allocatorType, static_cast<uint8_t *>(destInfo.buffer),
        destInfo.bufferSize, destInfo.context);
    context.info.pixelFormat = format;
    UpdateContextYuvInfo(context, destInfo);
    return SUCCESS;
}

static uint32_t RGBxToRGB(uint8_t* srcBuffer, size_t srsSize,
    uint8_t* dstBuffer, size_t dstSize, size_t pixelCount)
{
    ExtPixels src = {srcBuffer, srsSize, pixelCount};
    ExtPixels dst = {dstBuffer, dstSize, pixelCount};
    auto res = ExtPixelConvert::RGBxToRGB(src, dst);
    if (res != SUCCESS) {
        IMAGE_LOGE("RGBxToRGB failed %{public}d", res);
    }
    return res;
}

// LCOV_EXCL_START
uint32_t ExtDecoder::PreDecodeCheck(uint32_t index)
{
    if (!CheckIndexValied(index)) {
        IMAGE_LOGE("Decode failed, invalid index:%{public}u, range:%{public}d", index, frameCount_);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (codec_ == nullptr) {
        IMAGE_LOGE("Decode failed, codec is null");
        return ERR_IMAGE_DECODE_FAILED;
    }
    if (dstInfo_.isEmpty()) {
        IMAGE_LOGE("Decode failed, dst info is empty");
        return ERR_IMAGE_DECODE_FAILED;
    }
        return SUCCESS;
}
// LCOV_EXCL_STOP

static bool IsColorSpaceSupport(SkJpegCodec* codec)
{
    if (codec == nullptr || codec->decoderMgr() == nullptr || codec->decoderMgr()->dinfo() == nullptr) {
        IMAGE_LOGE("SkJpegCodec is null");
        return false;
    }
    struct jpeg_decompress_struct* pCinfo = codec->decoderMgr()->dinfo();
    if (pCinfo->jpeg_color_space == JCS_YCbCr || pCinfo->jpeg_color_space == JCS_GRAYSCALE) {
        return true;
    }
    IMAGE_LOGE("unsupported in color: %{public}d", pCinfo->jpeg_color_space);
    return false;
}

// LCOV_EXCL_START
uint32_t ExtDecoder::PreDecodeCheckYuv(uint32_t index, PixelFormat desiredFormat)
{
    uint32_t ret = PreDecodeCheck(index);
    if (ret != SUCCESS) {
        return ret;
    }
    SkEncodedImageFormat skEncodeFormat = codec_->getEncodedFormat();
    if (skEncodeFormat != SkEncodedImageFormat::kJPEG) {
        IMAGE_LOGE("PreDecodeCheckYuv, not support to create 420 data from not jpeg");
        return ERR_IMAGE_DESIRED_PIXELFORMAT_UNSUPPORTED;
    }
    if (stream_ == nullptr) {
        return ERR_IMAGE_SOURCE_DATA;
    }
    auto iter = PLPIXEL_FORMAT_YUV_JPG_MAP.find(desiredFormat);
    if (iter == PLPIXEL_FORMAT_YUV_JPG_MAP.end()) {
        IMAGE_LOGE("PreDecodeCheckYuv desiredFormat format not valid");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t jpegBufferSize = stream_->GetStreamSize();
    if (jpegBufferSize == 0) {
        IMAGE_LOGE("PreDecodeCheckYuv jpegBufferSize 0");
        return ERR_IMAGE_SOURCE_DATA;
    }
    if (!IsColorSpaceSupport(static_cast<SkJpegCodec*>(codec_.get()))) {
        return ERR_IMAGE_SOURCE_DATA;
    }
    return SUCCESS;
}
// LCOV_EXCL_STOP

bool ExtDecoder::ResetCodec()
{
    codec_ = nullptr;
    stream_->Seek(streamOff_);
    return ExtDecoder::CheckCodec();
}

#ifdef JPEG_HW_DECODE_ENABLE
uint32_t ExtDecoder::DoHardWareDecode(DecodeContext &context)
{
    if (HardWareDecode(context) == SUCCESS) {
        return SUCCESS;
    }
    return ERROR;
}
#endif

uint32_t ExtDecoder::Decode(uint32_t index, DecodeContext &context)
{
#ifdef JPEG_HW_DECODE_ENABLE
    if (IsSupportHardwareDecode() && DoHardWareDecode(context) == SUCCESS) {
        context.isHardDecode = true;
        return SUCCESS;
    }
#endif
    context.outInfo.size.width = static_cast<uint32_t>(dstInfo_.width());
    context.outInfo.size.height = static_cast<uint32_t>(dstInfo_.height());
    if (IsHeifToYuvDecode(context)) {
        context.isHardDecode = true;
        return DoHeifToYuvDecode(context);
    }
    if (IsHeifToSingleHdrDecode(context)) {
        context.isHardDecode = true;
        return DoHeifToSingleHdrDecode(context);
    }
    uint32_t res = PreDecodeCheck(index);
    if (res != SUCCESS) {
        return res;
    }
    SkEncodedImageFormat skEncodeFormat = codec_->getEncodedFormat();
    PixelFormat format = context.info.pixelFormat;
    bool isOutputYuv420Format = IsYuv420Format(context.info.pixelFormat);
    uint32_t result = 0;
    if (isOutputYuv420Format && skEncodeFormat == SkEncodedImageFormat::kJPEG) {
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
        return 0;
#else
        result = DecodeToYuv420(index, context);
        if (result != JpegYuvDecodeError_SubSampleNotSupport) {
            return result;
        }
        IMAGE_LOGI("Decode sample not support, apply rgb decode");
        context.pixelsBuffer.buffer = nullptr;
#endif
    }
    if (skEncodeFormat == SkEncodedImageFormat::kHEIF) {
        context.isHardDecode = true;
    }
    uint64_t byteCount = static_cast<uint64_t>(dstInfo_.computeMinByteSize());
    uint8_t *dstBuffer = nullptr;
    std::unique_ptr<uint8_t[]> tmpBuffer;
    if (dstInfo_.colorType() == SkColorType::kRGB_888x_SkColorType) {
        tmpBuffer = make_unique<uint8_t[]>(byteCount);
        dstBuffer = tmpBuffer.get();
        byteCount = byteCount / NUM_4 * NUM_3;
    }
    if (context.pixelsBuffer.buffer == nullptr) {
        res = SetContextPixelsBuffer(byteCount, context);
        if (res != SUCCESS) {
            return res;
        }
        if (dstBuffer == nullptr) {
            dstBuffer = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
        }
    }
    dstOptions_.fFrameIndex = static_cast<int>(index);
    DebugInfo(info_, dstInfo_, dstOptions_);
    uint64_t rowStride = dstInfo_.minRowBytes64();
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (context.allocatorType == Media::AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*> (context.pixelsBuffer.context);
        rowStride = static_cast<uint64_t>(sbBuffer->GetStride());
    }
    ffrt::submit([skEncodeFormat] {
        ReportImageType(skEncodeFormat);
    }, {}, {});
#endif
    IMAGE_LOGD("decode format %{public}d", skEncodeFormat);
    if (skEncodeFormat == SkEncodedImageFormat::kGIF || skEncodeFormat == SkEncodedImageFormat::kWEBP) {
        return GifDecode(index, context, rowStride);
    }
    SkCodec::Result ret = codec_->getPixels(dstInfo_, dstBuffer, rowStride, &dstOptions_);
    if (ret != SkCodec::kSuccess && ResetCodec()) {
        ret = codec_->getPixels(dstInfo_, dstBuffer, rowStride, &dstOptions_); // Try again
    }
    if (ret != SkCodec::kSuccess) {
        IMAGE_LOGE("Decode failed, get pixels failed, ret=%{public}d", ret);
        SetHeifDecodeError(context);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    if (dstInfo_.colorType() == SkColorType::kRGB_888x_SkColorType) {
        res = RGBxToRGB(dstBuffer, dstInfo_.computeMinByteSize(), static_cast<uint8_t*>(context.pixelsBuffer.buffer),
            byteCount, dstInfo_.width() * dstInfo_.height());
        if (res != SUCCESS) {
            IMAGE_LOGE("Decode failed, RGBxToRGB failed, res=%{public}d", res);
            return res;
        }
    }
    if (result == JpegYuvDecodeError_SubSampleNotSupport) {
        res = ConvertFormatToYUV(context, dstInfo_, byteCount, format);
        if (res != SUCCESS) {
            IMAGE_LOGE("Decode failed, ConvertFormatToYUV failed, res=%{public}d", res);
            return res;
        }
    }
    return SUCCESS;
}

uint32_t ExtDecoder::ReadJpegData(uint8_t* jpegBuffer, uint32_t jpegBufferSize)
{
    if (stream_ == nullptr) {
        return ERR_IMAGE_SOURCE_DATA;
    }
    if (jpegBuffer == nullptr || jpegBufferSize == 0) {
        IMAGE_LOGE("ExtDecoder::ReadJpegData wrong parameter");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    uint32_t savedPosition = stream_->Tell();
    if (!stream_->Seek(0)) {
        IMAGE_LOGE("ExtDecoder::ReadJpegData seek stream failed");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    uint32_t readSize = 0;
    bool result = stream_->Read(jpegBufferSize, jpegBuffer, jpegBufferSize, readSize);
    if (!stream_->Seek(savedPosition)) {
        IMAGE_LOGE("ExtDecoder::ReadJpegData seek stream failed");
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    if (!result || readSize != jpegBufferSize) {
        IMAGE_LOGE("ReadJpegData read image data failed");
        return ERR_IMAGE_SOURCE_DATA;
    }
    return SUCCESS;
}

// LCOV_EXCL_START
JpegYuvFmt ExtDecoder::GetJpegYuvOutFmt(PixelFormat desiredFormat)
{
    auto iter = PLPIXEL_FORMAT_YUV_JPG_MAP.find(desiredFormat);
    if (iter == PLPIXEL_FORMAT_YUV_JPG_MAP.end()) {
        return JpegYuvFmt::OutFmt_NV12;
    } else {
        return iter->second;
    }
}
// LCOV_EXCL_STOP

uint32_t ExtDecoder::DecodeToYuv420(uint32_t index, DecodeContext &context)
{
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    return 0;
#endif
    uint32_t res = PreDecodeCheckYuv(index, context.info.pixelFormat);
    if (res != SUCCESS) {
        return res;
    }
    uint32_t jpegBufferSize = stream_->GetStreamSize();
    if (jpegBufferSize == 0) {
        IMAGE_LOGE("DecodeToYuv420 jpegBufferSize 0");
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint8_t* jpegBuffer = NULL;
    if (stream_->GetStreamType() == ImagePlugin::BUFFER_SOURCE_TYPE) {
        jpegBuffer = stream_->GetDataPtr();
    }
    std::unique_ptr<uint8_t[]> jpegBufferPtr;
    if (jpegBuffer == nullptr) {
        jpegBufferPtr = std::make_unique<uint8_t[]>(jpegBufferSize);
        jpegBuffer = jpegBufferPtr.get();
        res = ReadJpegData(jpegBuffer, jpegBufferSize);
        if (res != SUCCESS) {
            return res;
        }
    }
    JpegYuvFmt decodeOutFormat = GetJpegYuvOutFmt(context.info.pixelFormat);
    Size jpgSize = {static_cast<uint32_t>(info_.width()), static_cast<uint32_t>(info_.height())};
    Size desiredSize = desiredSizeYuv_;
    bool bRet = JpegDecoderYuv::GetScaledSize(jpgSize.width, jpgSize.height, desiredSize.width, desiredSize.height);
    if (!bRet || desiredSize.width == 0 || desiredSize.height == 0) {
        IMAGE_LOGE("DecodeToYuv420 GetScaledSize failed");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint64_t yuvBufferSize = JpegDecoderYuv::GetYuvOutSize(desiredSize.width, desiredSize.height);
    res = SetContextPixelsBuffer(yuvBufferSize, context);
    if (res != SUCCESS) {
        IMAGE_LOGE("ExtDecoder::DecodeToYuv420 SetContextPixelsBuffer failed");
        return res;
    }
    uint8_t *yuvBuffer = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    std::unique_ptr<JpegDecoderYuv> jpegYuvDecoder_ = std::make_unique<JpegDecoderYuv>();
    JpegDecoderYuvParameter para = {jpgSize.width, jpgSize.height, jpegBuffer, jpegBufferSize,
        yuvBuffer, yuvBufferSize, decodeOutFormat, desiredSize.width, desiredSize.height};
    int retDecode = jpegYuvDecoder_->DoDecode(context, para);
    if (retDecode != JpegYuvDecodeError_Success) {
        IMAGE_LOGE("DecodeToYuv420 DoDecode return %{public}d", retDecode);
    } else {
        // update yuv outInfo if decode success, same as jpeg hardware decode
        context.outInfo.size = desiredSize;
    }
    return retDecode;
}

// LCOV_EXCL_START
static std::string GetFormatStr(SkEncodedImageFormat format)
{
    switch (format) {
        case SkEncodedImageFormat::kBMP:
            return "bmp";
        case SkEncodedImageFormat::kGIF:
            return "gif";
        case SkEncodedImageFormat::kICO:
            return "ico";
        case SkEncodedImageFormat::kJPEG:
            return "jpeg";
        case SkEncodedImageFormat::kPNG:
            return "png";
        case SkEncodedImageFormat::kWBMP:
            return "wbmp";
        case SkEncodedImageFormat::kWEBP:
            return "webp";
        case SkEncodedImageFormat::kPKM:
            return "pkm";
        case SkEncodedImageFormat::kKTX:
            return "ktx";
        case SkEncodedImageFormat::kASTC:
            return "astc";
        case SkEncodedImageFormat::kDNG:
            return "dng";
        case SkEncodedImageFormat::kHEIF:
            return "heif";
        case SkEncodedImageFormat::kAVIF:
            return "avif";
        default:
            return UNKNOWN_IMAGE;
    }
}

void ExtDecoder::ReportImageType(SkEncodedImageFormat skEncodeFormat)
{
    IMAGE_LOGD("ExtDecoder::ReportImageType format %{public}d start", skEncodeFormat);
    static constexpr char IMAGE_FWK_UE[] = "IMAGE_FWK_UE";
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    int32_t ret = HiSysEventWrite(
            IMAGE_FWK_UE,
            "DECODED_IMAGE_TYPE_STATISTICS",
            HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "PNAMEID", DEFAULT_PACKAGE_NAME,
            "PVERSIONID", DEFAULT_VERSION_ID,
            "IMAGE_TYPE", GetFormatStr(skEncodeFormat)
    );
    if (SUCCESS != ret) {
        IMAGE_LOGD("ExtDecoder::ReportImageType failed, ret = %{public}d", ret);
        return;
    }
#endif
    IMAGE_LOGD("ExtDecoder::ReportImageType format %{public}d success", skEncodeFormat);
}
#ifdef JPEG_HW_DECODE_ENABLE
uint32_t ExtDecoder::AllocOutputBuffer(DecodeContext &context,
    OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer& outputBuffer)
{
    uint64_t byteCount = static_cast<uint64_t>(hwDstInfo_.height() * hwDstInfo_.width() * hwDstInfo_.bytesPerPixel());
    uint32_t ret = DmaMemAlloc(context, byteCount, hwDstInfo_);
    if (ret != SUCCESS) {
        IMAGE_LOGE("Alloc OutputBuffer failed, ret=%{public}d", ret);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    BufferHandle *handle = (static_cast<SurfaceBuffer*>(context.pixelsBuffer.context))->GetBufferHandle();
    if (outputColorFmt_ == PIXEL_FMT_RGBA_8888) {
        outputBufferSize_.width = static_cast<uint32_t>(handle->stride) / NUM_4;
    } else {
        outputBufferSize_.width = static_cast<uint32_t>(handle->stride);
    }
    outputBufferSize_.height = static_cast<uint32_t>(handle->height);
    outputBuffer.buffer = new NativeBuffer(handle);
    outputBuffer.fenceFd = -1;
    return SUCCESS;
}

bool ExtDecoder::CheckContext(const DecodeContext &context)
{
    if (IsYuv420Format(context.info.pixelFormat)) {
        if (outputColorFmt_ == PIXEL_FMT_YCRCB_420_SP) {
            return true;
        }
        IMAGE_LOGI("yuv hardware decode only support NV21 format");
        return false;
    }
    if (dstInfo_.colorType() != kRGBA_8888_SkColorType) {
        IMAGE_LOGI("jpeg hardware decode only support rgba_8888 format");
        return false;
    }
    return true;
}
// LCOV_EXCL_STOP

void ExtDecoder::ReleaseOutputBuffer(DecodeContext &context, Media::AllocatorType allocatorType)
{
    ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(context.pixelsBuffer.context));
    context.pixelsBuffer.buffer = nullptr;
    context.allocatorType = allocatorType;
    context.freeFunc = nullptr;
    context.pixelsBuffer.bufferSize = 0;
    context.pixelsBuffer.context = nullptr;
}

uint32_t ExtDecoder::HardWareDecode(DecodeContext &context)
{
    JpegHardwareDecoder hwDecoder;
    orgImgSize_.width = static_cast<uint32_t>(info_.width());
    orgImgSize_.height = static_cast<uint32_t>(info_.height());

    if (!CheckContext(context)) {
        return ERROR;
    }

    Media::AllocatorType tmpAllocatorType = context.allocatorType;
    OHOS::HDI::Codec::Image::V1_0::CodecImageBuffer outputBuffer;
    uint32_t ret = AllocOutputBuffer(context, outputBuffer);
    if (ret != SUCCESS) {
        IMAGE_LOGE("Decode failed, Alloc OutputBuffer failed, ret=%{public}d", ret);
        context.hardDecodeError = "Decode failed, Alloc OutputBuffer failed, ret=" + std::to_string(ret);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    ret = hwDecoder.Decode(codec_.get(), stream_, orgImgSize_, sampleSize_, outputBuffer);
    if (ret != SUCCESS) {
        IMAGE_LOGE("failed to do jpeg hardware decode, err=%{public}d", ret);
        context.hardDecodeError = "failed to do jpeg hardware decode, err=" + std::to_string(ret);
        ReleaseOutputBuffer(context, tmpAllocatorType);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }

    SurfaceBuffer* sbuffer = static_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    if (sbuffer) {
        OH_NativeBuffer_Planes *planes = nullptr;
        GSError retVal = sbuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
        if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
            IMAGE_LOGE("jpeg hardware decode, Get planesInfo failed, retVal:%{public}d", retVal);
        } else if (planes->planeCount >= PLANE_COUNT_TWO) {
            context.yuvInfo.yStride = planes->planes[0].columnStride;
            context.yuvInfo.uvStride = planes->planes[1].columnStride;
            context.yuvInfo.yOffset = planes->planes[0].offset;
            context.yuvInfo.uvOffset = planes->planes[1].offset - 1;
        }
    }

    context.outInfo.size.width = static_cast<uint32_t>(hwDstInfo_.width());
    context.outInfo.size.height = static_cast<uint32_t>(hwDstInfo_.height());
    if (outputColorFmt_ == PIXEL_FMT_YCRCB_420_SP) {
        context.yuvInfo.imageSize = {hwDstInfo_.width(), hwDstInfo_.height()};
    }
    return SUCCESS;
}
#endif

uint32_t ExtDecoder::HandleGifCache(uint8_t* src, uint8_t* dst, uint64_t rowStride, int dstHeight)
{
    if (src == nullptr || dst == nullptr) {
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    uint8_t* srcRow = src;
    uint8_t* dstRow = dst;
    for (int i = 0; i < dstHeight; i++) {
        errno_t err = memcpy_s(dstRow, rowStride, srcRow, rowStride);
        if (err != EOK) {
            IMAGE_LOGE("handle gif memcpy failed. errno:%{public}d", err);
            return ERR_IMAGE_DECODE_ABNORMAL;
        }
        if (i != (dstHeight - 1)) {
            srcRow += rowStride;
            dstRow += rowStride;
        }
    }
    return SUCCESS;
}

ExtDecoder::FrameCacheInfo ExtDecoder::InitFrameCacheInfo(const uint64_t rowStride, SkImageInfo info)
{
    FrameCacheInfo cacheInfo = {0, 0, 0, 0};
    int width = info.width();
    int height = info.height();
    if (width < 0 || height < 0) {
        IMAGE_LOGI("InitFrameCacheInfo failed, width:[%{public}d<0], height:[%{public}d<0]", width, height);
        return cacheInfo;
    }
    cacheInfo.width = width;
    cacheInfo.height = height;
    cacheInfo.rowStride = rowStride;
    cacheInfo.byteCount = rowStride * static_cast<uint64_t>(cacheInfo.height);
    return cacheInfo;
}

bool ExtDecoder::FrameCacheInfoIsEqual(ExtDecoder::FrameCacheInfo& src, ExtDecoder::FrameCacheInfo& dst)
{
    if (src.byteCount == 0 || src.rowStride == 0 || src.height == 0 || src.width == 0) {
        IMAGE_LOGE("FrameCacheInfoIsEqual, incorrect info");
        return false;
    }
    return (src.byteCount == dst.byteCount) && (src.rowStride == dst.rowStride) &&
        (src.height == dst.height) && (src.width == dst.width);
}

uint32_t ExtDecoder::GetFramePixels(SkImageInfo& info, uint8_t* buffer, uint64_t rowStride, SkCodec::Options options)
{
    if (buffer == nullptr) {
        IMAGE_LOGE("get pixels failed, buffer is nullptr");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    SkCodec::Result ret = codec_->getPixels(info, buffer, rowStride, &options);
    if (ret != SkCodec::kSuccess && ResetCodec()) {
        // Try again
        ret = codec_->getPixels(info, buffer, rowStride, &options);
    }
    if (ret != SkCodec::kSuccess) {
        IMAGE_LOGE("Gif decode failed, get pixels failed, ret=%{public}d", ret);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    return SUCCESS;
}

uint32_t ExtDecoder::GifDecode(uint32_t index, DecodeContext &context, const uint64_t rowStride)
{
    IMAGE_LOGD("In GifDecoder, frame index %{public}d", index);
    SkCodec::FrameInfo curInfo {};
    int signedIndex = static_cast<int>(index);
    codec_->getFrameInfo(signedIndex, &curInfo);
    if (signedIndex == 0 || gifCache_ == nullptr) {
        dstOptions_.fPriorFrame = SkCodec::kNoFrame;
    } else {
        int preIndex = signedIndex - 1;
        SkCodec::FrameInfo preInfo {};
        codec_->getFrameInfo(preIndex, &preInfo);
        if (preInfo.fDisposalMethod == SkCodecAnimation::DisposalMethod::kRestorePrevious) {
            dstOptions_.fPriorFrame = gifCacheIndex_;
        } else {
            dstOptions_.fPriorFrame = gifCacheIndex_ == preIndex ? preIndex : SkCodec::kNoFrame;
        }
    }
    ExtDecoder::FrameCacheInfo dstFrameCacheInfo = InitFrameCacheInfo(rowStride, dstInfo_);
    uint8_t* dstBuffer = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    if (curInfo.fDisposalMethod != SkCodecAnimation::DisposalMethod::kRestorePrevious) {
        if (gifCache_ == nullptr) {
            frameCacheInfo_ = InitFrameCacheInfo(rowStride, dstInfo_);
            if (frameCacheInfo_.byteCount == 0) {
                return ERR_IMAGE_DECODE_ABNORMAL;
            }
            gifCache_ = static_cast<uint8_t *>(calloc(frameCacheInfo_.byteCount, 1));
        }
        if (!FrameCacheInfoIsEqual(frameCacheInfo_, dstFrameCacheInfo)) {
            IMAGE_LOGE("Frame info is not equal");
            return ERR_IMAGE_DECODE_ABNORMAL;
        }
        uint32_t ret = GetFramePixels(dstInfo_, gifCache_, rowStride, dstOptions_);
        if (ret != SUCCESS) {
            return ret;
        }
        gifCacheIndex_ = signedIndex;
        return HandleGifCache(gifCache_, dstBuffer, dstFrameCacheInfo.rowStride, dstFrameCacheInfo.height);
    }
    if (gifCache_ != nullptr && FrameCacheInfoIsEqual(frameCacheInfo_, dstFrameCacheInfo)) {
        HandleGifCache(gifCache_, dstBuffer, dstFrameCacheInfo.rowStride, dstFrameCacheInfo.height);
    } else {
        dstOptions_.fPriorFrame = SkCodec::kNoFrame;
    }
    return GetFramePixels(dstInfo_, dstBuffer, rowStride, dstOptions_);
}

uint32_t ExtDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &context)
{
    // currently not support increment decode
    return ERR_IMAGE_DATA_UNSUPPORT;
}

// LCOV_EXCL_START
bool ExtDecoder::CheckCodec()
{
    if (codec_ != nullptr) {
        return true;
    } else if (stream_ == nullptr) {
        IMAGE_LOGE("create codec: input stream is nullptr.");
        return false;
    } else if (stream_->GetStreamSize() == SIZE_ZERO) {
        IMAGE_LOGE("create codec: input stream size is zero.");
        return false;
    }
    uint32_t src_offset = stream_->Tell();
    codec_ = SkCodec::MakeFromStream(make_unique<ExtStream>(stream_));
    if (codec_ == nullptr) {
        stream_->Seek(src_offset);
        IMAGE_LOGE("create codec from stream failed");
        SetHeifParseError();
        return false;
    }
    return codec_ != nullptr;
}
// LCOV_EXCL_STOP

bool ExtDecoder::DecodeHeader()
{
    if (!CheckCodec()) {
        IMAGE_LOGE("Check codec failed");
        return false;
    }
    info_ = codec_->getInfo();
    frameCount_ = codec_->getFrameCount();
    IMAGE_LOGD("DecodeHeader: get frame count %{public}d.", frameCount_);
    return true;
}

bool ExtDecoder::CheckIndexValied(uint32_t index)
{
    if (frameCount_ == ZERO && !DecodeHeader()) {
        return false;
    }
    return static_cast<int32_t>(index) >= ZERO && static_cast<int32_t>(index) < frameCount_;
}

static uint32_t GetFormatName(SkEncodedImageFormat format, std::string &name)
{
    auto formatNameIter = FORMAT_NAME.find(format);
    if (formatNameIter != FORMAT_NAME.end() && !formatNameIter->second.empty()) {
        name = formatNameIter->second;
        IMAGE_LOGD("GetFormatName: get encoded format name (%{public}d)=>[%{public}s].",
            format, name.c_str());
        return SUCCESS;
    }
    IMAGE_LOGE("GetFormatName: get encoded format name failed %{public}d.", format);
    return ERR_IMAGE_DATA_UNSUPPORT;
}

// LCOV_EXCL_START
bool ExtDecoder::ConvertInfoToAlphaType(SkAlphaType &alphaType, AlphaType &outputType)
{
    if (info_.isEmpty()) {
        return false;
    }
    alphaType = info_.alphaType();
    auto findItem = std::find_if(ALPHA_TYPE_MAP.begin(), ALPHA_TYPE_MAP.end(),
        [alphaType](const map<AlphaType, SkAlphaType>::value_type item) {
        return item.second == alphaType;
    });
    if (findItem == ALPHA_TYPE_MAP.end()) {
        return false;
    }
    outputType = findItem->first;
    alphaType = findItem->second;
    return true;
}

bool ExtDecoder::ConvertInfoToColorType(SkColorType &format, PixelFormat &outputFormat)
{
    if (info_.isEmpty()) {
        return false;
    }
    auto colorType = info_.colorType();
    auto findItem = std::find_if(COLOR_TYPE_MAP.begin(), COLOR_TYPE_MAP.end(),
        [colorType](const map<PixelFormat, ColorTypeOutput>::value_type item) {
        return item.second.skFormat == colorType;
    });
    if (findItem == COLOR_TYPE_MAP.end()) {
        return false;
    }
    format = findItem->second.skFormat;
    outputFormat = findItem->second.outFormat;
    return true;
}

SkAlphaType ExtDecoder::ConvertToAlphaType(AlphaType desiredType, AlphaType &outputType)
{
    if (desiredType != AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        auto alphaType = ALPHA_TYPE_MAP.find(desiredType);
        if (alphaType != ALPHA_TYPE_MAP.end()) {
            outputType = alphaType->first;
            return alphaType->second;
        }
    }
    IMAGE_LOGD("Unknown alpha type:%{public}d", desiredType);
    SkAlphaType res;
    if (ConvertInfoToAlphaType(res, outputType)) {
        IMAGE_LOGD("Using alpha type:%{public}d", outputType);
        return res;
    }
    IMAGE_LOGD("Using default alpha type:%{public}d", AlphaType::IMAGE_ALPHA_TYPE_PREMUL);
    outputType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    return SkAlphaType::kPremul_SkAlphaType;
}

SkColorType ExtDecoder::ConvertToColorType(PixelFormat format, PixelFormat &outputFormat)
{
    if (format != PixelFormat::UNKNOWN) {
        auto colorType = COLOR_TYPE_MAP.find(format);
        if (colorType != COLOR_TYPE_MAP.end()) {
            outputFormat = colorType->second.outFormat;
            return colorType->second.skFormat;
        }
    }
    IMAGE_LOGD("Unknown pixel format:%{public}d", format);
    SkColorType res;
    if (ConvertInfoToColorType(res, outputFormat)) {
        IMAGE_LOGD("Using pixel format:%{public}d", outputFormat);
        return res;
    }
    IMAGE_LOGD("Using default pixel format:%{public}d", PixelFormat::RGBA_8888);
    outputFormat = PixelFormat::RGBA_8888;
    return kRGBA_8888_SkColorType;
}
// LCOV_EXCL_STOP

#ifdef IMAGE_COLORSPACE_FLAG
static uint32_t u8ToU32(const uint8_t* p)
{
    return (p[OFFSET_0] << SHIFT_BITS_24) | (p[OFFSET_1] << SHIFT_BITS_16) |
        (p[OFFSET_2] << SHIFT_BITS_8) | p[OFFSET_3];
}

struct ICCTag {
    uint8_t signature[SIZE_4];
    uint8_t offset[SIZE_4];
    uint8_t size[SIZE_4];
};

struct ColorSpaceNameEnum {
    std::string desc;
    OHOS::ColorManager::ColorSpaceName name;
};

static std::vector<ColorSpaceNameEnum> sColorSpaceNamedMap = {
    {"Display P3", OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {"sRGB EOTF with DCI-P3 Color Gamut", OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {"DCI-P3 D65 Gamut with sRGB Transfer", OHOS::ColorManager::ColorSpaceName::DISPLAY_P3},
    {"Adobe RGB (1998)", OHOS::ColorManager::ColorSpaceName::ADOBE_RGB},
    {"DCI P3", OHOS::ColorManager::ColorSpaceName::DCI_P3},
    {"sRGB", OHOS::ColorManager::ColorSpaceName::SRGB}
    /*{"BT.2020", OHOS::ColorManager::ColorSpaceName::BT2020}*/
};

static bool MatchColorSpaceName(const uint8_t* buf, uint32_t size, OHOS::ColorManager::ColorSpaceName &name)
{
    if (buf == nullptr || size <= OFFSET_5) {
        return false;
    }
    std::vector<char> desc;
    // We need skip desc type
    for (uint32_t i = OFFSET_5; i < size; i++) {
        if (buf[i] != '\0') {
            desc.push_back(buf[i]);
        }
    }
    if (desc.size() <= SIZE_1) {
        IMAGE_LOGI("empty buffer");
        return false;
    }
    std::string descText(desc.begin() + OFFSET_1, desc.end());
    for (auto nameEnum : sColorSpaceNamedMap) {
        if (descText.find(nameEnum.desc) == std::string::npos) {
            continue;
        }
        name = nameEnum.name;
        return true;
    }
    IMAGE_LOGE("Failed to match desc");
    return false;
}

static bool GetColorSpaceName(const skcms_ICCProfile* profile, OHOS::ColorManager::ColorSpaceName &name)
{
    if (profile == nullptr || profile->buffer == nullptr) {
        IMAGE_LOGD("profile is nullptr");
        return false;
    }
    auto tags = reinterpret_cast<const ICCTag*>(profile->buffer + ICC_HEADER_SIZE);
    for (uint32_t i = SIZE_ZERO; i < profile->tag_count; i++) {
        auto signature = u8ToU32(tags[i].signature);
        if (signature != DESC_SIGNATURE) {
            continue;
        }
        auto size = u8ToU32(tags[i].size);
        auto offset = u8ToU32(tags[i].offset);
        if (size == SIZE_ZERO || offset >= profile->size) {
            continue;
        }
        auto buffer = u8ToU32(tags[i].offset) + profile->buffer;
        if (MatchColorSpaceName(buffer, size, name)) {
            return true;
        }
    }
    return false;
}

static OHOS::ColorManager::ColorSpaceName GetHeifNclxColor(SkCodec* codec)
{
#ifdef HEIF_HW_DECODE_ENABLE
    auto decoder = reinterpret_cast<HeifDecoder *>(codec->getHeifContext());
    if (decoder == nullptr) {
        return ColorManager::NONE;
    }
    HeifFrameInfo info;
    if (!decoder->getImageInfo(&info)) {
        return ColorManager::NONE;
    }
    if (info.hasNclxColor) {
        return ColorUtils::CicpToColorSpace(info.nclxColor.colorPrimaries, info.nclxColor.transferCharacteristics,
            info.nclxColor.matrixCoefficients, info.nclxColor.fullRangeFlag);
    }
#endif
    return ColorManager::NONE;
}

OHOS::ColorManager::ColorSpace ExtDecoder::getGrColorSpace()
{
    if (dstColorSpace_ != nullptr) {
        return *dstColorSpace_;
    }
    auto skColorSpace = dstInfo_.isEmpty() ? info_.refColorSpace() : dstInfo_.refColorSpace();
    OHOS::ColorManager::ColorSpaceName name = OHOS::ColorManager::ColorSpaceName::CUSTOM;
    if (codec_ != nullptr) {
        auto profile = codec_->getICCProfile();
        if (profile != nullptr) {
            IMAGE_LOGD("profile got !!!!");
            GetColorSpaceName(profile, name);
        }
        if (profile != nullptr && profile->has_CICP) {
            ColorManager::ColorSpaceName cName = Media::ColorUtils::CicpToColorSpace(profile->cicp.colour_primaries,
                profile->cicp.transfer_characteristics, profile->cicp.matrix_coefficients,
                profile->cicp.full_range_flag);
            if (cName != ColorManager::NONE) {
                return ColorManager::ColorSpace(skColorSpace, cName);
            }
        }
        if (codec_->getEncodedFormat() == SkEncodedImageFormat::kHEIF) {
            ColorManager::ColorSpaceName cName = GetHeifNclxColor(codec_.get());
            if (cName != ColorManager::NONE) {
                return ColorManager::ColorSpace(skColorSpace, cName);
            }
        }
    }
    return OHOS::ColorManager::ColorSpace(skColorSpace, name);
}

bool ExtDecoder::IsSupportICCProfile()
{
    if (dstColorSpace_ != nullptr) {
        return true;
    }
    if (info_.isEmpty()) {
        return false;
    }
    return info_.refColorSpace() != nullptr;
}
#endif

static uint32_t ProcessWithStreamData(InputDataStream *input,
    std::function<uint32_t(uint8_t*, size_t)> process)
{
    size_t inputSize = input->GetStreamSize();
    if (inputSize == SIZE_ZERO) {
        return Media::ERR_MEDIA_INVALID_VALUE;
    }

    size_t copySize = std::min(inputSize, SMALL_FILE_SIZE);
    auto tmpBuffer = std::make_unique<uint8_t[]>(copySize);
    auto savePos = input->Tell();
    input->Seek(SIZE_ZERO);
    uint32_t readSize = 0;
    bool ret = input->Read(copySize, tmpBuffer.get(), copySize, readSize);
    input->Seek(savePos);
    if (!ret) {
        IMAGE_LOGE("InputDataStream read failed.");
        return Media::ERR_IMAGE_DATA_ABNORMAL;
    }
    return process(tmpBuffer.get(), copySize);
}

static bool ParseExifData(InputDataStream *input, EXIFInfo &info)
{
    if (info.IsExifDataParsed()) {
        return true;
    }
    IMAGE_LOGD("ParseExifData enter");
    auto code = ProcessWithStreamData(input, [&info](uint8_t* buffer, size_t size) {
        return info.ParseExifData(buffer, size);
    });
    if (code != SUCCESS) {
        IMAGE_LOGE("Error parsing EXIF: code %{public}d", code);
    }
    return code == SUCCESS;
}

bool ExtDecoder::GetPropertyCheck(uint32_t index, const std::string &key, uint32_t &res)
{
    if (IsSameTextStr(key, ACTUAL_IMAGE_ENCODED_FORMAT)) {
        res = Media::ERR_MEDIA_VALUE_INVALID;
        return false;
    }
    if (!CheckIndexValied(index)) {
        res = Media::ERR_IMAGE_DECODE_HEAD_ABNORMAL;
        return false;
    }
    SkEncodedImageFormat format = codec_->getEncodedFormat();
    if (format != SkEncodedImageFormat::kJPEG) {
        res = Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
        return true;
    }
    if (ENCODED_FORMAT_KEY.compare(key) == ZERO) {
        res = Media::ERR_MEDIA_VALUE_INVALID;
        return true;
    }
    auto result = ParseExifData(stream_, exifInfo_);
    if (!result) {
        res = Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    return result;
}

// LCOV_EXCL_START
static uint32_t GetDelayTime(SkCodec * codec, uint32_t index, int32_t &value)
{
    if (codec->getEncodedFormat() != SkEncodedImageFormat::kGIF &&
        codec->getEncodedFormat() != SkEncodedImageFormat::kWEBP) {
        IMAGE_LOGE("[GetDelayTime] Should not get delay time in %{public}d", codec->getEncodedFormat());
        return ERR_MEDIA_INVALID_PARAM;
    }
    auto frameInfos = codec->getFrameInfo();
    if (index > frameInfos.size() - 1) {
        IMAGE_LOGE("[GetDelayTime] frame size %{public}zu, index:%{public}d", frameInfos.size(), index);
        return ERR_MEDIA_INVALID_PARAM;
    }
    value = frameInfos[index].fDuration;
    IMAGE_LOGD("[GetDelayTime] index[%{public}d]:%{public}d", index, value);
    return SUCCESS;
}

static uint32_t GetDisposalType(SkCodec * codec, uint32_t index, int32_t &value)
{
    if (codec->getEncodedFormat() != SkEncodedImageFormat::kGIF) {
        IMAGE_LOGE("[GetDisposalType] Should not get disposal type in %{public}d", codec->getEncodedFormat());
        return ERR_MEDIA_INVALID_PARAM;
    }
    auto frameInfos = codec->getFrameInfo();
    if (index > frameInfos.size() - 1) {
        IMAGE_LOGE("[GetDisposalType] frame size %{public}zu, index:%{public}d", frameInfos.size(), index);
        return ERR_MEDIA_INVALID_PARAM;
    }
    value = static_cast<int>(frameInfos[index].fDisposalMethod);
    IMAGE_LOGD("[GetDisposalType] index[%{public}d]:%{public}d", index, value);
    return SUCCESS;
}
// LCOV_EXCL_STOP

static uint32_t GetLoopCount(SkCodec *codec, int32_t &value)
{
    if (codec->getEncodedFormat() != SkEncodedImageFormat::kGIF) {
        IMAGE_LOGE("[GetLoopCount] Should not get loop count in %{public}d", codec->getEncodedFormat());
        return ERR_MEDIA_INVALID_PARAM;
    }
    auto count = codec->getRepetitionCount();
    if (count == LOOP_COUNT_INFINITE || count <= SK_REPETITION_COUNT_ERROR_VALUE) {
        IMAGE_LOGE("[GetLoopCount] getRepetitionCount error");
        return ERR_IMAGE_SOURCE_DATA;
    }
    if (count == SK_REPETITION_COUNT_INFINITE) {
        count = LOOP_COUNT_INFINITE;
    }
    value = static_cast<int>(count);
    return SUCCESS;
}

// LCOV_EXCL_START
uint32_t ExtDecoder::GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value)
{
    IMAGE_LOGD("[GetImagePropertyInt] enter ExtDecoder plugin, key:%{public}s", key.c_str());
    uint32_t res = Media::ERR_IMAGE_DATA_ABNORMAL;
    if (!GetPropertyCheck(index, key, res)) {
        return res;
    }
    if (IMAGE_DELAY_TIME.compare(key) == ZERO) {
        return GetDelayTime(codec_.get(), index, value);
    }
    if (IMAGE_DISPOSAL_TYPE.compare(key) == ZERO) {
        return GetDisposalType(codec_.get(), index, value);
    }
    if (IMAGE_LOOP_COUNT.compare(key) == ZERO) {
        return GetLoopCount(codec_.get(), value);
    }
    // There can add some not need exif property
    if (res == Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
        return res;
    }
    // Need exif property following
    if (IsSameTextStr(key, TAG_ORIENTATION_STRING)) {
        std::string strValue;
        res = exifInfo_.GetExifData(TAG_ORIENTATION_INT, strValue);
        if (res != SUCCESS) {
            return res;
        }
        value = atoi(strValue.c_str());
        return res;
    }
    IMAGE_LOGE("[GetImagePropertyInt] The key:%{public}s is not supported int32_t", key.c_str());
    return Media::ERR_MEDIA_VALUE_INVALID;
}

uint32_t ExtDecoder::GetImagePropertyString(uint32_t index, const std::string &key, std::string &value)
{
    IMAGE_LOGD("[GetImagePropertyString] enter jpeg plugin, key:%{public}s", key.c_str());
    uint32_t res = Media::ERR_IMAGE_DATA_ABNORMAL;
    if (!GetPropertyCheck(index, key, res)) {
        return res;
    }
    // There can add some not need exif property
    if (ENCODED_FORMAT_KEY.compare(key) == ZERO) {
        SkEncodedImageFormat format = codec_->getEncodedFormat();
        return GetFormatName(format, value);
    } else if (IMAGE_DELAY_TIME.compare(key) == ZERO) {
        int delayTime = ZERO;
        res = GetDelayTime(codec_.get(), index, delayTime);
        value = std::to_string(delayTime);
        return res;
    } else if (IMAGE_DISPOSAL_TYPE.compare(key) == ZERO) {
        int disposalType = ZERO;
        res = GetDisposalType(codec_.get(), index, disposalType);
        value = std::to_string(disposalType);
        return res;
    } else if (IMAGE_LOOP_COUNT.compare(key) == ZERO) {
        int loopCount = ZERO;
        res = GetLoopCount(codec_.get(), loopCount);
        value = std::to_string(loopCount);
        return res;
    }
    if (res == Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
        return res;
    }
    // Need exif property following
    if (key.find(HW_MNOTE_TAG_HEADER) != std::string::npos) {
        res = GetMakerImagePropertyString(key, value);
        if (value.length() == 0) {
            value = DEFAULT_EXIF_VALUE;
            IMAGE_LOGE("[GetImagePropertyString]The image does not contain the %{public}s  tag ", key.c_str());
        }
        return res;
    }
    res = exifInfo_.GetExifData(key, value);
    IMAGE_LOGD("[GetImagePropertyString] enter jpeg plugin, value:%{public}s", value.c_str());
    return res;
}
// LCOV_EXCL_STOP

uint32_t ExtDecoder::GetMakerImagePropertyString(const std::string &key, std::string &value)
{
    if (exifInfo_.makerInfoTagValueMap.find(key) != exifInfo_.makerInfoTagValueMap.end()) {
        value = exifInfo_.makerInfoTagValueMap[key];
        return SUCCESS;
    }
    return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
}

uint32_t ExtDecoder::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const std::string &path)
{
    IMAGE_LOGD("[ModifyImageProperty] with path:%{public}s, key:%{public}s, value:%{public}s",
        path.c_str(), key.c_str(), value.c_str());
    return exifInfo_.ModifyExifData(key, value, path);
}

uint32_t ExtDecoder::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const int fd)
{
    IMAGE_LOGD("[ModifyImageProperty] with fd:%{public}d, key:%{public}s, value:%{public}s",
        fd, key.c_str(), value.c_str());
    return exifInfo_.ModifyExifData(key, value, fd);
}

uint32_t ExtDecoder::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, uint8_t *data, uint32_t size)
{
    IMAGE_LOGD("[ModifyImageProperty] with key:%{public}s, value:%{public}s",
        key.c_str(), value.c_str());
    return exifInfo_.ModifyExifData(key, value, data, size);
}

uint32_t ExtDecoder::GetFilterArea(const int &privacyType, std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    IMAGE_LOGD("[GetFilterArea] with privacyType:%{public}d ", privacyType);
    if (!CheckCodec()) {
        IMAGE_LOGE("Check codec failed");
        return NO_EXIF_TAG;
    }
    SkEncodedImageFormat format = codec_->getEncodedFormat();
    if (format != SkEncodedImageFormat::kJPEG) {
        return NO_EXIF_TAG;
    }
    constexpr size_t APP1_SIZE_H_OFF = 4;
    constexpr size_t APP1_SIZE_L_OFF = 5;
    constexpr size_t U8_SHIFT = 8;
    return ProcessWithStreamData(stream_, [this, &privacyType, &ranges](uint8_t* buffer, size_t size) {
        size_t appSize = (static_cast<size_t>(buffer[APP1_SIZE_H_OFF]) << U8_SHIFT) | buffer[APP1_SIZE_L_OFF];
        IMAGE_LOGD("[GetFilterArea]: get app1 area size");
        appSize += APP1_SIZE_H_OFF;
        auto ret = exifInfo_.GetFilterArea(buffer, (appSize < size) ? appSize : size, privacyType, ranges);
        if (ret != SUCCESS) {
            IMAGE_LOGE("[GetFilterArea]: failed to get area %{public}d", ret);
        }
        return ret;
    });
}

uint32_t ExtDecoder::GetTopLevelImageNum(uint32_t &num)
{
    if (!CheckIndexValied(SIZE_ZERO) && frameCount_ <= ZERO) {
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }
    num = static_cast<uint32_t>(frameCount_);
    return SUCCESS;
}

// LCOV_EXCL_START
bool ExtDecoder::IsSupportHardwareDecode() {
    if (info_.isEmpty() && !DecodeHeader()) {
        return false;
    }
    if (!(ImageSystemProperties::GetHardWareDecodeEnabled()
        && codec_->getEncodedFormat() == SkEncodedImageFormat::kJPEG)) {
        return false;
    }
    int width = info_.width();
    int height = info_.height();
    return width >= HARDWARE_MIN_DIM && width <= HARDWARE_MAX_DIM
        && height >= HARDWARE_MIN_DIM && height <= HARDWARE_MAX_DIM;
}
// LCOV_EXCL_STOP

bool ExtDecoder::IsYuv420Format(PixelFormat format) const
{
    if (format == PixelFormat::NV12 || format == PixelFormat::NV21) {
        return true;
    }
    return false;
}

bool ExtDecoder::IsHeifToYuvDecode(const DecodeContext &context) const
{
    return codec_->getEncodedFormat() == SkEncodedImageFormat::kHEIF && IsYuv420Format(context.info.pixelFormat);
}

uint32_t ExtDecoder::DoHeifToYuvDecode(OHOS::ImagePlugin::DecodeContext &context)
{
#ifdef HEIF_HW_DECODE_ENABLE
    auto decoder = reinterpret_cast<HeifDecoder*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        IMAGE_LOGE("YUV Decode HeifDecoder is nullptr");
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    uint32_t allocRet = HeifYUVMemAlloc(context);
    if (allocRet != SUCCESS) {
        return allocRet;
    }
    auto dstBuffer = reinterpret_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    decoder->setOutputColor(context.info.pixelFormat
        == PixelFormat::NV12 ? kHeifColorFormat_NV12 : kHeifColorFormat_NV21);
    decoder->setDstBuffer(reinterpret_cast<uint8_t *>(context.pixelsBuffer.buffer),
                          dstBuffer->GetStride(), context.pixelsBuffer.context);
    bool decodeRet = decoder->decode(nullptr);
    if (!decodeRet) {
        decoder->getErrMsg(context.hardDecodeError);
    }
    return decodeRet ? SUCCESS : ERR_IMAGE_DATA_UNSUPPORT;
#else
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

bool ExtDecoder::IsHeifToSingleHdrDecode(const DecodeContext& context) const
{
    return codec_->getEncodedFormat() == SkEncodedImageFormat::kHEIF &&
        (context.info.pixelFormat == PixelFormat::RGBA_1010102 ||
         context.info.pixelFormat == PixelFormat::YCBCR_P010 ||
         context.info.pixelFormat == PixelFormat::YCRCB_P010);
}

uint32_t ExtDecoder::DoHeifToSingleHdrDecode(DecodeContext &context)
{
#ifdef HEIF_HW_DECODE_ENABLE
    auto decoder = reinterpret_cast<HeifDecoder*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        IMAGE_LOGE("SingleHdrDecode, HeifDecoder is nullptr");
        return ERR_IMAGE_DATA_UNSUPPORT;
    }

    uint64_t byteCount = static_cast<uint64_t>(info_.computeMinByteSize());
    if (context.info.pixelFormat == PixelFormat::YCBCR_P010 || context.info.pixelFormat == PixelFormat::YCRCB_P010) {
        uint32_t allocRet = HeifYUVMemAlloc(context);
        if (allocRet != SUCCESS) {
            return allocRet;
        }
    } else {
        if (DmaMemAlloc(context, byteCount, info_) != SUCCESS) {
            return ERR_IMAGE_DATA_UNSUPPORT;
        }
    }

    auto dstBuffer = reinterpret_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    SkHeifColorFormat heifFormat = kHeifColorFormat_RGBA_1010102;
    auto formatSearch = HEIF_FORMAT_MAP.find(context.info.pixelFormat);
    heifFormat = (formatSearch != HEIF_FORMAT_MAP.end()) ? formatSearch->second : kHeifColorFormat_RGBA_1010102;
    decoder->setOutputColor(heifFormat);
    decoder->setDstBuffer(reinterpret_cast<uint8_t*>(context.pixelsBuffer.buffer),
        dstBuffer->GetStride(), context.pixelsBuffer.context);
    bool decodeRet = decoder->decode(nullptr);
    if (!decodeRet) {
        decoder->getErrMsg(context.hardDecodeError);
    }
    return decodeRet ? SUCCESS : ERR_IMAGE_DATA_UNSUPPORT;
#else
    return ERR_IMAGE_DATA_UNSUPPORT;
#endif
}

ImageHdrType ExtDecoder::CheckHdrType()
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return Media::ImageHdrType::SDR;
#else
    if (!CheckCodec()) {
        return Media::ImageHdrType::UNKNOWN;
    }
    SkEncodedImageFormat format = codec_->getEncodedFormat();
    if (format != SkEncodedImageFormat::kJPEG && format != SkEncodedImageFormat::kHEIF) {
        hdrType_ = Media::ImageHdrType::SDR;
        gainMapOffset_ = 0;
        return hdrType_;
    }
    hdrType_ = HdrHelper::CheckHdrType(codec_.get(), gainMapOffset_);
    return hdrType_;
#endif
}

uint32_t ExtDecoder::GetGainMapOffset()
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return OFFSET_0;
#else
    if (codec_ == nullptr || codec_->getEncodedFormat() != SkEncodedImageFormat::kJPEG) {
        return 0;
    }
    if (hdrType_ == Media::ImageHdrType::UNKNOWN) {
        hdrType_ = HdrHelper::CheckHdrType(codec_.get(), gainMapOffset_);
    }
    return gainMapOffset_;
#endif
}

HdrMetadata ExtDecoder::GetHdrMetadata(Media::ImageHdrType type)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return {};
#else
    HdrMetadata metadata = {};
    if (type > Media::ImageHdrType::SDR && HdrHelper::GetMetadata(codec_.get(), type, metadata)) {
        return metadata;
    }
    IMAGE_LOGD("get hdr metadata failed, type is %{public}d, flag is %{public}d", type, metadata.extendMetaFlag);
    return {};
#endif
}

bool ExtDecoder::DecodeHeifGainMap(DecodeContext& context)
{
#ifdef HEIF_HW_DECODE_ENABLE
    if (codec_ == nullptr || codec_->getEncodedFormat() != SkEncodedImageFormat::kHEIF) {
        IMAGE_LOGE("decode heif gainmap, codec error");
        return false;
    }
    auto decoder = reinterpret_cast<HeifDecoder*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        IMAGE_LOGE("decode heif gainmap, decoder error");
        return false;
    }
    HeifFrameInfo gainmapInfo;
    decoder->getGainmapInfo(&gainmapInfo);
    uint32_t width = gainmapInfo.mWidth;
    uint32_t height = gainmapInfo.mHeight;
    if (width > INT_MAX || height > INT_MAX) {
        IMAGE_LOGI("DecodeHeifGainmap size exceeds the maximum value");
        return false;
    }
    IMAGE_LOGD("DecodeHeifGainmap size:%{public}d-%{public}d", width, height);
    SkImageInfo dstInfo = SkImageInfo::Make(static_cast<int>(width), static_cast<int>(height),
        dstInfo_.colorType(), dstInfo_.alphaType(), dstInfo_.refColorSpace());
    uint64_t byteCount = static_cast<uint64_t>(dstInfo.computeMinByteSize());
    context.info.size.width = width;
    context.info.size.height = height;
    if (DmaMemAlloc(context, byteCount, dstInfo) != SUCCESS) {
        return false;
    }
    auto* dstBuffer = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    auto* sbBuffer = reinterpret_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    int32_t rowStride = sbBuffer->GetStride();
    if (rowStride <= 0) {
        return false;
    }
    decoder->setGainmapDstBuffer(dstBuffer, static_cast<size_t>(rowStride));
    if (!decoder->decodeGainmap()) {
        return false;
    }
    return true;
#endif
    return false;
}

bool ExtDecoder::GetHeifHdrColorSpace(ColorManager::ColorSpaceName& gainmap, ColorManager::ColorSpaceName& hdr)
{
#ifdef HEIF_HW_DECODE_ENABLE
    if (codec_ == nullptr || codec_->getEncodedFormat() != SkEncodedImageFormat::kHEIF) {
        return false;
    }
    auto decoder = reinterpret_cast<HeifDecoder*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        return false;
    }
    HeifFrameInfo gainmapInfo;
    decoder->getGainmapInfo(&gainmapInfo);
    if (gainmapInfo.hasNclxColor) {
        gainmap = ColorUtils::CicpToColorSpace(gainmapInfo.nclxColor.colorPrimaries,
            gainmapInfo.nclxColor.transferCharacteristics, gainmapInfo.nclxColor.matrixCoefficients,
            gainmapInfo.nclxColor.fullRangeFlag);
    }
    HeifFrameInfo tmapInfo;
    decoder->getTmapInfo(&tmapInfo);
    if (tmapInfo.hasNclxColor) {
        hdr = ColorUtils::CicpToColorSpace(tmapInfo.nclxColor.colorPrimaries,
            tmapInfo.nclxColor.transferCharacteristics, tmapInfo.nclxColor.matrixCoefficients,
            tmapInfo.nclxColor.fullRangeFlag);
    }
    return true;
#endif
    return false;
}

uint32_t ExtDecoder::GetHeifParseErr()
{
    return heifParseErr_;
}

void ExtDecoder::SetHeifDecodeError(OHOS::ImagePlugin::DecodeContext &context)
{
#ifdef HEIF_HW_DECODE_ENABLE
    if (codec_ == nullptr || codec_->getEncodedFormat() != SkEncodedImageFormat::kHEIF) {
        return;
    }
    auto decoder = reinterpret_cast<HeifDecoder*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        return;
    }
    decoder->getErrMsg(context.hardDecodeError);
#endif
}

void ExtDecoder::SetHeifParseError()
{
    if (stream_ == nullptr) {
        return;
    }
    uint32_t originOffset = stream_->Tell();
    stream_->Seek(0);

    uint32_t readSize = 0;
    HeifFormatAgent agent;
    uint32_t headerSize = agent.GetHeaderSize();
    uint8_t headerBuf[headerSize];
    bool readRet = stream_->Peek(headerSize, headerBuf, headerSize, readSize);
    if (!readRet || readSize != headerSize) {
        stream_->Seek(originOffset);
        return;
    }

    if (!agent.CheckFormat(headerBuf, headerSize)) {
        stream_->Seek(originOffset);
        return;
    }

    size_t fileLength = stream_->GetStreamSize();
    if (fileLength <= 0) {
        return;
    }
    uint8_t *fileMem = reinterpret_cast<uint8_t*>(malloc(fileLength));
    if (fileMem == nullptr) {
        return;
    }
    readRet = stream_->Read(fileLength, fileMem, fileLength, readSize);
    if (!readRet || readSize != fileLength) {
        stream_->Seek(originOffset);
        free(fileMem);
        return;
    }

    std::shared_ptr<HeifParser> parser;
    heif_error parseRet = HeifParser::MakeFromMemory(fileMem, fileLength, false, &parser);
    if (parseRet != heif_error_ok) {
        heifParseErr_ = static_cast<uint32_t>(parseRet);
    }

    stream_->Seek(originOffset);
    free(fileMem);
}

bool ExtDecoder::CheckAuxiliaryMap(AuxiliaryPictureType type)
{
#ifdef HEIF_HW_DECODE_ENABLE
    if (codec_ == nullptr || codec_->getEncodedFormat() != SkEncodedImageFormat::kHEIF) {
        IMAGE_LOGE("Check heif auxiliaryMap failed! Invalid parameter, type %{public}d.", type);
        return false;
    }

    auto decoder = reinterpret_cast<HeifDecoderImpl*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        IMAGE_LOGE("Get heif context failed, type %{public}d.", type);
        return false;
    }

    if (!decoder->CheckAuxiliaryMap(type)) {
        IMAGE_LOGE("Get heif auxiliary type %{public}d, decoder error", type);
        return false;
    }
    return true;
#endif
    return false;
}

bool ExtDecoder::DecodeHeifAuxiliaryMap(DecodeContext& context, AuxiliaryPictureType type)
{
#ifdef HEIF_HW_DECODE_ENABLE
    if (codec_ == nullptr || codec_->getEncodedFormat() != SkEncodedImageFormat::kHEIF) {
        IMAGE_LOGE("decode heif auxiliaryMap type %{public}d, codec error", type);
        return false;
    }

    auto decoder = reinterpret_cast<HeifDecoderImpl*>(codec_->getHeifContext());
    if (decoder == nullptr) {
        IMAGE_LOGE("decode heif auxiliaryMap %{public}d, decoder error", type);
        return false;
    }
    if (!decoder->setAuxiliaryMap(type)) {
        IMAGE_LOGE("set auxiliary map type failed, type is %{public}d", type);
        return false;
    }
    HeifFrameInfo auxiliaryMapInfo;
    decoder->getAuxiliaryMapInfo(&auxiliaryMapInfo);
    uint32_t width = auxiliaryMapInfo.mWidth;
    uint32_t height = auxiliaryMapInfo.mHeight;
    if (width > INT_MAX || height > INT_MAX) {
        IMAGE_LOGI("DecodeHeifAuxiliaryMap size exceeds the maximum value");
        return false;
    }
    IMAGE_LOGD("DecodeHeifAuxiliaryMap size:%{public}d-%{public}d", width, height);
    SkImageInfo dstInfo = SkImageInfo::Make(static_cast<int>(width), static_cast<int>(height), dstInfo_.colorType(),
        dstInfo_.alphaType(), dstInfo_.refColorSpace());
    uint64_t byteCount = static_cast<uint64_t>(dstInfo.computeMinByteSize());
    context.info.size.width = width;
    context.info.size.height = height;
    if (DmaMemAlloc(context, byteCount, dstInfo) != SUCCESS) {
        IMAGE_LOGI("DmaMemAlloc execution failed.");
        return false;
    }
    auto* dstBuffer = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    auto* sbBuffer = reinterpret_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    int32_t rowStride = sbBuffer->GetStride();
    if (rowStride <= 0) {
        return false;
    }
    decoder->setAuxiliaryDstBuffer(dstBuffer, static_cast<size_t>(rowStride));
    if (!decoder->decodeAuxiliaryMap()) {
        IMAGE_LOGE("Decoded auxiliary map type is not supported, or decoded failed. Type: %{public}d", type);
        return false;
    }
    context.outInfo.size.width = width;
    context.outInfo.size.height = height;
    return true;
#endif
    return false;
}
} // namespace ImagePlugin
} // namespace OHOS
