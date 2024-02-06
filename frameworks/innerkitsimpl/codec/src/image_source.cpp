/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "image_source.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>
#include "buffer_source_stream.h"
#if !defined(_WIN32) && !defined(_APPLE)
#include "hitrace_meter.h"
#include "image_trace.h"
#endif
#include "file_source_stream.h"
#include "image/abs_image_decoder.h"
#include "image/abs_image_format_agent.h"
#include "image/image_plugin_type.h"
#include "image_log.h"
#include "image_system_properties.h"
#include "image_utils.h"
#include "incremental_source_stream.h"
#include "istream_source_stream.h"
#include "media_errors.h"
#include "pixel_astc.h"
#include "pixel_map.h"
#include "plugin_server.h"
#include "post_proc.h"
#include "securec.h"
#include "source_stream.h"
#if defined(A_PLATFORM) || defined(IOS_PLATFORM)
#include "include/jpeg_decoder.h"
#else
#include "surface_buffer.h"
#endif
#include "include/utils/SkBase64.h"
#if defined(NEW_SKIA)
#include "include/core/SkData.h"
#endif
#include "string_ex.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSource"

namespace OHOS {
namespace Media {
using namespace std;
using namespace ImagePlugin;
using namespace MultimediaPlugin;

static const map<PixelFormat, PlPixelFormat> PIXEL_FORMAT_MAP = {
    { PixelFormat::UNKNOWN, PlPixelFormat::UNKNOWN },     { PixelFormat::ARGB_8888, PlPixelFormat::ARGB_8888 },
    { PixelFormat::ALPHA_8, PlPixelFormat::ALPHA_8 },     { PixelFormat::RGB_565, PlPixelFormat::RGB_565 },
    { PixelFormat::RGBA_F16, PlPixelFormat::RGBA_F16 },   { PixelFormat::RGBA_8888, PlPixelFormat::RGBA_8888 },
    { PixelFormat::BGRA_8888, PlPixelFormat::BGRA_8888 }, { PixelFormat::RGB_888, PlPixelFormat::RGB_888 },
    { PixelFormat::NV21, PlPixelFormat::NV21 },           { PixelFormat::NV12, PlPixelFormat::NV12 },
    { PixelFormat::CMYK, PlPixelFormat::CMYK },           { PixelFormat::ASTC_4x4, PlPixelFormat::ASTC_4X4},
    { PixelFormat::ASTC_6x6, PlPixelFormat::ASTC_6X6},    { PixelFormat::ASTC_8x8, PlPixelFormat::ASTC_8X8}
};

static const map<ColorSpace, PlColorSpace> COLOR_SPACE_MAP = {
    { ColorSpace::UNKNOWN, PlColorSpace::UNKNOWN },
    { ColorSpace::DISPLAY_P3, PlColorSpace::DISPLAY_P3 },
    { ColorSpace::SRGB, PlColorSpace::SRGB },
    { ColorSpace::LINEAR_SRGB, PlColorSpace::LINEAR_SRGB },
    { ColorSpace::EXTENDED_SRGB, PlColorSpace::EXTENDED_SRGB },
    { ColorSpace::LINEAR_EXTENDED_SRGB, PlColorSpace::LINEAR_EXTENDED_SRGB },
    { ColorSpace::GENERIC_XYZ, PlColorSpace::GENERIC_XYZ },
    { ColorSpace::GENERIC_LAB, PlColorSpace::GENERIC_LAB },
    { ColorSpace::ACES, PlColorSpace::ACES },
    { ColorSpace::ACES_CG, PlColorSpace::ACES_CG },
    { ColorSpace::ADOBE_RGB_1998, PlColorSpace::ADOBE_RGB_1998 },
    { ColorSpace::DCI_P3, PlColorSpace::DCI_P3 },
    { ColorSpace::ITU_709, PlColorSpace::ITU_709 },
    { ColorSpace::ITU_2020, PlColorSpace::ITU_2020 },
    { ColorSpace::ROMM_RGB, PlColorSpace::ROMM_RGB },
    { ColorSpace::NTSC_1953, PlColorSpace::NTSC_1953 },
    { ColorSpace::SMPTE_C, PlColorSpace::SMPTE_C }
};

namespace InnerFormat {
    const string RAW_FORMAT = "image/x-raw";
    const string ASTC_FORMAT = "image/astc";
    const string EXTENDED_FORMAT = "image/x-skia";
    const string IMAGE_EXTENDED_CODEC = "image/extended";
    const string RAW_EXTENDED_FORMATS[] = {
        "image/x-sony-arw",
        "image/x-canon-cr2",
        "image/x-adobe-dng",
        "image/x-nikon-nef",
        "image/x-nikon-nrw",
        "image/x-olympus-orf",
        "image/x-fuji-raf",
        "image/x-panasonic-rw2",
        "image/x-pentax-pef",
        "image/x-samsung-srw",
    };
} // namespace InnerFormat
// BASE64 image prefix type data:image/<type>;base64,<data>
static const std::string IMAGE_URL_PREFIX = "data:image/";
static const std::string BASE64_URL_PREFIX = ";base64,";
static const uint32_t FIRST_FRAME = 0;
static const int INT_ZERO = 0;
static const int INT_255 = 255;
static const size_t SIZE_ZERO = 0;
static const uint8_t NUM_0 = 0;
static const uint8_t NUM_1 = 1;
static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;
static const uint8_t NUM_6 = 6;
static const uint8_t NUM_8 = 8;
static const uint8_t NUM_16 = 16;
static const int DMA_SIZE = 512;
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
static const size_t ASTC_HEADER_SIZE = 16;
static const uint8_t ASTC_HEADER_BLOCK_X = 4;
static const uint8_t ASTC_HEADER_BLOCK_Y = 5;
static const uint8_t ASTC_HEADER_DIM_X = 7;
static const uint8_t ASTC_HEADER_DIM_Y = 10;

PluginServer &ImageSource::pluginServer_ = ImageUtils::GetPluginServer();
ImageSource::FormatAgentMap ImageSource::formatAgentMap_ = InitClass();

uint32_t ImageSource::GetSupportedFormats(set<string> &formats)
{
    IMAGE_LOGD("[ImageSource]get supported image type.");

    formats.clear();
    vector<ClassInfo> classInfos;
    uint32_t ret = pluginServer_.PluginServerGetClassInfo<AbsImageDecoder>(AbsImageDecoder::SERVICE_DEFAULT,
                                                                           classInfos);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource]get class info from plugin server failed, ret:%{public}u.", ret);
        return ret;
    }

    for (auto &info : classInfos) {
        map<string, AttrData> &capbility = info.capabilities;
        auto iter = capbility.find(IMAGE_ENCODE_FORMAT);
        if (iter == capbility.end()) {
            continue;
        }

        AttrData &attr = iter->second;
        const string *format = nullptr;
        if (attr.GetValue(format) != SUCCESS) {
            IMAGE_LOGE("[ImageSource]attr data get format failed.");
            continue;
        }

        if (*format == InnerFormat::RAW_FORMAT) {
            formats.insert(std::begin(InnerFormat::RAW_EXTENDED_FORMATS), std::end(InnerFormat::RAW_EXTENDED_FORMATS));
        } else {
            formats.insert(*format);
        }
    }
    return SUCCESS;
}

unique_ptr<ImageSource> ImageSource::DoImageSourceCreate(
    std::function<unique_ptr<SourceStream>(void)> stream,
    const SourceOptions &opts, uint32_t &errorCode, const string traceName)
{
    ImageTrace imageTrace(traceName);
    IMAGE_LOGD("[ImageSource]DoImageSourceCreate IN.");
    errorCode = ERR_IMAGE_SOURCE_DATA;
    auto streamPtr = stream();
    if (streamPtr == nullptr) {
        return nullptr;
    }

    auto sourcePtr = new (std::nothrow) ImageSource(std::move(streamPtr), opts);
    if (sourcePtr == nullptr) {
        IMAGE_LOGE("[ImageSource]failed to create ImageSource.");
        return nullptr;
    }
    errorCode = SUCCESS;
    return unique_ptr<ImageSource>(sourcePtr);
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(unique_ptr<istream> is,
    const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with stream.");
    return DoImageSourceCreate([&is]() {
        auto stream = IstreamSourceStream::CreateSourceStream(move(is));
        if (stream == nullptr) {
            IMAGE_LOGE("[ImageSource]failed to create istream source stream.");
        }
        return stream;
        }, opts, errorCode, "CreateImageSource by istream");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const uint8_t *data, uint32_t size,
    const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with buffer.");

    if (data == nullptr || size == 0) {
        IMAGE_LOGE("[ImageSource]parameter error.");
        errorCode = ERR_MEDIA_INVALID_PARAM;
        return nullptr;
    }
    return DoImageSourceCreate([&data, &size]() {
        auto streamPtr = DecodeBase64(data, size);
        if (streamPtr == nullptr) {
            streamPtr = BufferSourceStream::CreateSourceStream(data, size);
        }
        if (streamPtr == nullptr) {
            IMAGE_LOGE("[ImageSource]failed to create buffer source stream.");
        }
        return streamPtr;
        }, opts, errorCode, "CreateImageSource by data");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const std::string &pathName, const SourceOptions &opts,
                                                       uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with pathName.");
    if (pathName.size() == SIZE_ZERO) {
        IMAGE_LOGE("[ImageSource]parameter error.");
        return nullptr;
    }
    return DoImageSourceCreate([&pathName]() {
        auto streamPtr = DecodeBase64(pathName);
        if (streamPtr == nullptr) {
            streamPtr = FileSourceStream::CreateSourceStream(pathName);
        }
        if (streamPtr == nullptr) {
            IMAGE_LOGE("[ImageSource]failed to create file path source stream. pathName=%{public}s",
                pathName.c_str());
        }
        return streamPtr;
        }, opts, errorCode, "CreateImageSource by path");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, const SourceOptions &opts,
                                                       uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with fd.");
    return DoImageSourceCreate([&fd]() {
        auto streamPtr = FileSourceStream::CreateSourceStream(fd);
        if (streamPtr == nullptr) {
            IMAGE_LOGE("[ImageSource]failed to create file fd source stream.");
        }
        return streamPtr;
        }, opts, errorCode, "CreateImageSource by fd");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, int32_t offset,
    int32_t length, const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with fd offset and length.");
    return DoImageSourceCreate([&fd, offset, length]() {
        auto streamPtr = FileSourceStream::CreateSourceStream(fd, offset, length);
        if (streamPtr == nullptr) {
            IMAGE_LOGE("[ImageSource]failed to create file fd source stream.");
        }
        return streamPtr;
        }, opts, errorCode, "CreateImageSource by fd offset and length");
}

unique_ptr<ImageSource> ImageSource::CreateIncrementalImageSource(const IncrementalSourceOptions &opts,
                                                                  uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create incremental ImageSource.");
    auto sourcePtr = DoImageSourceCreate([&opts]() {
        auto streamPtr = IncrementalSourceStream::CreateSourceStream(opts.incrementalMode);
        if (streamPtr == nullptr) {
            IMAGE_LOGE("[ImageSource]failed to create incremental source stream.");
        }
        return streamPtr;
    }, opts.sourceOptions, errorCode, "CreateImageSource by fd");
    if (sourcePtr != nullptr) {
        sourcePtr->SetIncrementalSource(true);
    }
    return sourcePtr;
}

void ImageSource::Reset()
{
    // if use skia now, no need reset
    if (mainDecoder_ != nullptr && mainDecoder_->HasProperty(SKIA_DECODER)) {
        return;
    }
    imageStatusMap_.clear();
    decodeState_ = SourceDecodingState::UNRESOLVED;
    sourceStreamPtr_->Seek(0);
    mainDecoder_ = nullptr;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapEx(uint32_t index, const DecodeOptions &opts, uint32_t &errorCode)
{
    ImageTrace imageTrace("ImageSource::CreatePixelMapEx, index:%u, desiredSize:(%d, %d)", index,
        opts.desiredSize.width, opts.desiredSize.height);
    IMAGE_LOGD(
        "CreatePixelMapEx imageId_: %{public}lu, desiredPixelFormat: %{public}d,"
        "desiredSize: (%{public}d, %{public}d)", static_cast<unsigned long>(imageId_), opts.desiredPixelFormat,
        opts.desiredSize.width, opts.desiredSize.height);

#if !defined(A_PLATFORM) || !defined(IOS_PLATFORM)
    if (!isAstc_.has_value()) {
        ImagePlugin::DataStreamBuffer outData;
        uint32_t res = GetData(outData, ASTC_HEADER_SIZE);
        if (res == SUCCESS) {
            isAstc_ = IsASTC(outData.inputStreamBuffer, outData.dataSize);
        }
    }
    if (isAstc_.has_value() && isAstc_.value()) {
        return CreatePixelMapForASTC(errorCode);
    }
#endif

    if (IsSpecialYUV()) {
        return CreatePixelMapForYUV(errorCode);
    }

    DumpInputData();
    return CreatePixelMap(index, opts, errorCode);
}

static bool IsExtendedCodec(AbsImageDecoder* decoder)
{
    const static string ENCODED_FORMAT_KEY = "EncodedFormat";
    if (decoder != nullptr && decoder->HasProperty(ENCODED_FORMAT_KEY)) {
        return true;
    }
    return false;
}

static inline bool IsSizeVailed(const Size &size)
{
    return (size.width != INT_ZERO && size.height != INT_ZERO);
}

static inline void CopySize(const Size &src, Size &dst)
{
    dst.width = src.width;
    dst.height = src.height;
}

static inline bool IsDensityChange(int32_t srcDensity, int32_t wantDensity)
{
    return (srcDensity != 0 && wantDensity != 0 && srcDensity != wantDensity);
}

static inline int32_t GetScalePropByDensity(int32_t prop, int32_t srcDensity, int32_t wantDensity)
{
    if (srcDensity != 0) {
        return (prop * wantDensity + (srcDensity >> 1)) / srcDensity;
    }
    return prop;
}

static void TransformSizeWithDensity(const Size &srcSize, int32_t srcDensity, const Size &wantSize,
    int32_t wantDensity, Size &dstSize)
{
    if (IsSizeVailed(wantSize)) {
        CopySize(wantSize, dstSize);
    } else {
        CopySize(srcSize, dstSize);
    }
    if (IsDensityChange(srcDensity, wantDensity)) {
        dstSize.width = GetScalePropByDensity(dstSize.width, srcDensity, wantDensity);
        dstSize.height = GetScalePropByDensity(dstSize.height, srcDensity, wantDensity);
    }
}

static void NotifyDecodeEvent(set<DecodeListener *> &listeners, DecodeEvent event,
    std::unique_lock<std::mutex>* guard)
{
    if (listeners.size() == SIZE_ZERO) {
        return;
    }
    for (auto listener : listeners) {
        if (guard != nullptr) {
            guard->unlock();
        }
        listener->OnEvent(static_cast<int>(event));
        if (guard != nullptr) {
            guard->lock();
        }
    }
}

static void FreeContextBuffer(const Media::CustomFreePixelMap &func,
    AllocatorType allocType, PlImageBuffer &buffer)
{
    if (func != nullptr) {
        func(buffer.buffer, buffer.context, buffer.bufferSize);
        return;
    }

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) &&!defined(A_PLATFORM)
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
            ImageUtils::SurfaceBuffer_Unreference(static_cast<SurfaceBuffer*>(buffer.context));
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

static void ContextToAddrInfos(DecodeContext &context, PixelMapAddrInfos &addrInfos)
{
    addrInfos.addr = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    addrInfos.context =static_cast<uint8_t*>(context.pixelsBuffer.context);
    addrInfos.size =context.pixelsBuffer.bufferSize;
    addrInfos.type =context.allocatorType;
    addrInfos.func =context.freeFunc;
}

bool IsSupportFormat(const PixelFormat &format)
{
    return format == PixelFormat::UNKNOWN || format == PixelFormat::RGBA_8888;
}

bool IsSupportSize(const Size &size)
{
    return size.width >= DMA_SIZE && size.height >= DMA_SIZE;
}

bool IsWidthAligned(const int32_t &width)
{
    return ((width * NUM_4) & INT_255) == 0;
}

bool IsPreferDma(bool perferDma)
{
    static bool isSceneBoard = ImageSystemProperties::IsPreferDma();
    return perferDma && !isSceneBoard;
}

bool IsSupportDma(const DecodeOptions &opts, const ImageInfo &info, bool hasDesiredSizeOptions)
{
#if defined(_WIN32) || defined(_APPLE) || defined(A_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem alloc");
    return false;
#else
    // used for test surfacebuffer
    if (ImageSystemProperties::GetSurfaceBufferEnabled() &&
        IsSupportSize(hasDesiredSizeOptions ? opts.desiredSize : info.size)) {
        return true;
    }

    if (ImageSystemProperties::GetDmaEnabled() && IsSupportFormat(opts.desiredPixelFormat)) {
        return IsSupportSize(hasDesiredSizeOptions ? opts.desiredSize : info.size) &&
            (IsWidthAligned(opts.desiredSize.width) || IsPreferDma(opts.preferDma));
    }
    return false;
#endif
}

DecodeContext InitDecodeContext(const DecodeOptions &opts, const ImageInfo &info,
    const MemoryUsagePreference &preference, bool hasDesiredSizeOptions)
{
    DecodeContext context;
    if (opts.allocatorType != AllocatorType::DEFAULT) {
        context.allocatorType = opts.allocatorType;
    } else {
        if (preference == MemoryUsagePreference::DEFAULT && IsSupportDma(opts, info, hasDesiredSizeOptions)) {
            IMAGE_LOGD("[ImageSource] allocatorType is DMA_ALLOC");
            context.allocatorType = AllocatorType::DMA_ALLOC;
        } else {
            context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
        }
    }
    return context;
}

uint64_t ImageSource::GetNowTimeMicroSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapExtended(uint32_t index,
    const DecodeOptions &opts, uint32_t &errorCode)
{
    uint64_t decodeStartTime = GetNowTimeMicroSeconds();
    opts_ = opts;
    ImageInfo info;
    errorCode = GetImageInfo(FIRST_FRAME, info);
    ImageTrace imageTrace("CreatePixelMapExtended, info.size:(%d, %d)", info.size.width, info.size.height);
    if (errorCode != SUCCESS || !IsSizeVailed(info.size)) {
        IMAGE_LOGE("[ImageSource]get image info failed, ret:%{public}u.", errorCode);
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return nullptr;
    }
    std::unique_lock<std::mutex> guard(decodingMutex_);
    hasDesiredSizeOptions = IsSizeVailed(opts_.desiredSize);
    TransformSizeWithDensity(info.size, sourceInfo_.baseDensity, opts_.desiredSize, opts_.fitDensity,
        opts_.desiredSize);
    ImagePlugin::PlImageInfo plInfo;
    errorCode = SetDecodeOptions(mainDecoder_, index, opts_, plInfo);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]set decode options error (index:%{public}u), ret:%{public}u.", index, errorCode);
        return nullptr;
    }
    NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_HEADER_DECODE, &guard);
    DecodeContext context = InitDecodeContext(opts_, info, preference_, hasDesiredSizeOptions);

    errorCode = mainDecoder_->Decode(index, context);
    if (context.ifPartialOutput) {
        NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_PARTIAL_DECODE, &guard);
    }
    ninePatchInfo_.ninePatch = context.ninePatchContext.ninePatch;
    ninePatchInfo_.patchSize = context.ninePatchContext.patchSize;
    guard.unlock();
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decode source fail, ret:%{public}u.", errorCode);
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        return nullptr;
    }
    PixelMapAddrInfos addrInfos;
    ContextToAddrInfos(context, addrInfos);
    auto pixelMap = CreatePixelMapByInfos(plInfo, addrInfos, errorCode);
    if (pixelMap == nullptr) {
        return nullptr;
    }
    if (!context.ifPartialOutput) {
        NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_COMPLETE_DECODE, nullptr);
    }
    IMAGE_LOGI("CreatePixelMapExtended success, imageId:%{public}lu, desiredSize: (%{public}d, %{public}d),"
        "imageSize: (%{public}d, %{public}d), cost %{public}lu us", static_cast<unsigned long>(imageId_),
        opts.desiredSize.width, opts.desiredSize.height, info.size.width, info.size.height,
        static_cast<unsigned long>(GetNowTimeMicroSeconds() - decodeStartTime));
    return pixelMap;
}

static void GetValidCropRect(const Rect &src, ImagePlugin::PlImageInfo &plInfo, Rect &dst)
{
    dst.top = src.top;
    dst.left = src.left;
    dst.width = src.width;
    dst.height = src.height;
    int32_t dstBottom = dst.top + dst.height;
    int32_t dstRight = dst.left + dst.width;
    if (dst.top >= 0 && dstBottom > 0 && static_cast<uint32_t>(dstBottom) > plInfo.size.height) {
        dst.height = plInfo.size.height - dst.top;
    }
    if (dst.left >= 0 && dstRight > 0 && static_cast<uint32_t>(dstRight) > plInfo.size.width) {
        dst.width = plInfo.size.width - dst.left;
    }
}

static void ResizeCropPixelmap(PixelMap &pixelmap, int32_t srcDensity, int32_t wantDensity, Size &dstSize)
{
    ImageInfo info;
    pixelmap.GetImageInfo(info);
    if (!IsDensityChange(srcDensity, wantDensity)) {
        dstSize.width = info.size.width;
        dstSize.height = info.size.height;
    } else {
        dstSize.width = GetScalePropByDensity(info.size.width, srcDensity, wantDensity);
        dstSize.height = GetScalePropByDensity(info.size.height, srcDensity, wantDensity);
    }
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapByInfos(ImagePlugin::PlImageInfo &plInfo,
    PixelMapAddrInfos &addrInfos, uint32_t &errorCode)
{
    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
#ifdef IMAGE_COLORSPACE_FLAG
    // add graphic colorspace object to pixelMap.
    bool isSupportICCProfile = mainDecoder_->IsSupportICCProfile();
    if (isSupportICCProfile) {
        OHOS::ColorManager::ColorSpace grColorSpace = mainDecoder_->getGrColorSpace();
        pixelMap->InnerSetColorSpace(grColorSpace);
    }
#endif
    pixelMap->SetPixelsAddr(addrInfos.addr, addrInfos.context, addrInfos.size, addrInfos.type, addrInfos.func);
    errorCode = UpdatePixelMapInfo(opts_, plInfo, *(pixelMap.get()), opts_.fitDensity, true);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]update pixelmap info error ret:%{public}u.", errorCode);
        return nullptr;
    }
    auto saveEditable = pixelMap->IsEditable();
    pixelMap->SetEditable(true);
    // Need check pixel change:
    // 1. pixel size
    // 2. crop
    // 3. density
    // 4. rotate
    // 5. format
    const static string SUPPORT_CROP_KEY = "SupportCrop";
    if (!mainDecoder_->HasProperty(SUPPORT_CROP_KEY) &&
        opts_.CropRect.width > INT_ZERO && opts_.CropRect.height > INT_ZERO) {
        Rect crop;
        GetValidCropRect(opts_.CropRect, plInfo, crop);
        errorCode = pixelMap->crop(crop);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("[ImageSource]CropRect pixelmap fail, ret:%{public}u.", errorCode);
            return nullptr;
        }
        if (!hasDesiredSizeOptions) {
            ResizeCropPixelmap(*pixelMap, sourceInfo_.baseDensity, opts_.fitDensity, opts_.desiredSize);
        }
    }
    // rotateDegrees and rotateNewDegrees
    if (!ImageUtils::FloatCompareZero(opts_.rotateDegrees)) {
        pixelMap->rotate(opts_.rotateDegrees);
    } else if (opts_.rotateNewDegrees != INT_ZERO) {
        pixelMap->rotate(opts_.rotateNewDegrees);
    }
    ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId_);
    if (opts_.desiredSize.height != pixelMap->GetHeight() ||
        opts_.desiredSize.width != pixelMap->GetWidth()) {
        float xScale = static_cast<float>(opts_.desiredSize.width)/pixelMap->GetWidth();
        float yScale = static_cast<float>(opts_.desiredSize.height)/pixelMap->GetHeight();
        if (!pixelMap->resize(xScale, yScale)) {
            return nullptr;
        }
        // dump pixelMap after resize
        ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId_);
    }
    pixelMap->SetEditable(saveEditable);
    return pixelMap;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMap(uint32_t index, const DecodeOptions &opts, uint32_t &errorCode)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    opts_ = opts;
    bool useSkia = opts_.sampleSize != 1;
    if (useSkia) {
        // we need reset to initial state to choose correct decoder
        Reset();
    }
    auto iter = GetValidImageStatus(index, errorCode);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on create pixel map, ret:%{public}u.", errorCode);
        return nullptr;
    }
    if (ImageSystemProperties::GetSkiaEnabled()) {
        if (IsExtendedCodec(mainDecoder_.get())) {
            guard.unlock();
            return CreatePixelMapExtended(index, opts, errorCode);
        }
    }

    // the mainDecoder_ may be borrowed by Incremental decoding, so needs to be checked.
    if (InitMainDecoder() != SUCCESS) {
        IMAGE_LOGE("[ImageSource]image decode plugin is null.");
        errorCode = ERR_IMAGE_PLUGIN_CREATE_FAILED;
        return nullptr;
    }
    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
    if (pixelMap == nullptr || pixelMap.get() == nullptr) {
        IMAGE_LOGE("[ImageSource]create the pixel map unique_ptr fail.");
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }

    ImagePlugin::PlImageInfo plInfo;
    errorCode = SetDecodeOptions(mainDecoder_, index, opts_, plInfo);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]set decode options error (index:%{public}u), ret:%{public}u.", index,
            errorCode);
        return nullptr;
    }

    for (auto listener : decodeListeners_) {
        guard.unlock();
        listener->OnEvent((int)DecodeEvent::EVENT_HEADER_DECODE);
        guard.lock();
    }

    Size size = {
        .width = plInfo.size.width,
        .height = plInfo.size.height
    };
    PostProc::ValidCropValue(opts_.CropRect, size);
    errorCode = UpdatePixelMapInfo(opts_, plInfo, *(pixelMap.get()));
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]update pixelmap info error ret:%{public}u.", errorCode);
        return nullptr;
    }

    DecodeContext context;
    FinalOutputStep finalOutputStep = FinalOutputStep::NO_CHANGE;
    context.pixelmapUniqueId_ = pixelMap->GetUniqueId();
    if (!useSkia) {
        bool hasNinePatch = mainDecoder_->HasProperty(NINE_PATCH);
        finalOutputStep = GetFinalOutputStep(opts_, *(pixelMap.get()), hasNinePatch);
        IMAGE_LOGD("[ImageSource]finalOutputStep:%{public}d. opts.allocatorType %{public}d",
            finalOutputStep, opts_.allocatorType);

        if (finalOutputStep == FinalOutputStep::NO_CHANGE) {
            context.allocatorType = opts_.allocatorType;
        } else {
            context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
        }
    }

    errorCode = mainDecoder_->Decode(index, context);
    if (context.ifPartialOutput) {
        for (auto partialListener : decodeListeners_) {
            guard.unlock();
            partialListener->OnEvent((int)DecodeEvent::EVENT_PARTIAL_DECODE);
            guard.lock();
        }
    }
    if (!useSkia) {
        ninePatchInfo_.ninePatch = context.ninePatchContext.ninePatch;
        ninePatchInfo_.patchSize = context.ninePatchContext.patchSize;
    }
    guard.unlock();
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decode source fail, ret:%{public}u.", errorCode);
        if (context.pixelsBuffer.buffer != nullptr) {
            if (context.freeFunc != nullptr) {
                context.freeFunc(context.pixelsBuffer.buffer, context.pixelsBuffer.context,
                                 context.pixelsBuffer.bufferSize);
            } else {
                PixelMap::ReleaseMemory(context.allocatorType, context.pixelsBuffer.buffer,
                                        context.pixelsBuffer.context, context.pixelsBuffer.bufferSize);
            }
        }
        return nullptr;
    }

#ifdef IMAGE_COLORSPACE_FLAG
    // add graphic colorspace object to pixelMap.
    bool isSupportICCProfile = mainDecoder_->IsSupportICCProfile();
    if (isSupportICCProfile) {
        OHOS::ColorManager::ColorSpace grColorSpace = mainDecoder_->getGrColorSpace();
        pixelMap->InnerSetColorSpace(grColorSpace);
    }
#endif

    pixelMap->SetPixelsAddr(context.pixelsBuffer.buffer, context.pixelsBuffer.context, context.pixelsBuffer.bufferSize,
                            context.allocatorType, context.freeFunc);
    DecodeOptions procOpts;
    CopyOptionsToProcOpts(opts_, procOpts, *(pixelMap.get()));
    PostProc postProc;
    errorCode = postProc.DecodePostProc(procOpts, *(pixelMap.get()), finalOutputStep);
    if (errorCode != SUCCESS) {
        return nullptr;
    }

    if (!context.ifPartialOutput) {
        for (auto listener : decodeListeners_) {
            listener->OnEvent((int)DecodeEvent::EVENT_COMPLETE_DECODE);
        }
    }
    // not ext decode, dump pixelMap while decoding svg here
    ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId_);
    return pixelMap;
}

unique_ptr<IncrementalPixelMap> ImageSource::CreateIncrementalPixelMap(uint32_t index, const DecodeOptions &opts,
                                                                       uint32_t &errorCode)
{
    IncrementalPixelMap *incPixelMapPtr = new (std::nothrow) IncrementalPixelMap(index, opts, this);
    if (incPixelMapPtr == nullptr) {
        IMAGE_LOGE("[ImageSource]create the incremental pixel map unique_ptr fail.");
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }
    errorCode = SUCCESS;
    return unique_ptr<IncrementalPixelMap>(incPixelMapPtr);
}

uint32_t ImageSource::PromoteDecoding(uint32_t index, const DecodeOptions &opts, PixelMap &pixelMap,
                                      ImageDecodingState &state, uint8_t &decodeProgress)
{
    state = ImageDecodingState::UNRESOLVED;
    decodeProgress = 0;
    uint32_t ret = SUCCESS;
    std::unique_lock<std::mutex> guard(decodingMutex_);
    opts_ = opts;
    auto imageStatusIter = GetValidImageStatus(index, ret);
    if (imageStatusIter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on promote decoding, ret:%{public}u.", ret);
        return ret;
    }
    auto incrementalRecordIter = incDecodingMap_.find(&pixelMap);
    if (incrementalRecordIter == incDecodingMap_.end()) {
        ret = AddIncrementalContext(pixelMap, incrementalRecordIter);
        if (ret != SUCCESS) {
            IMAGE_LOGE("[ImageSource]failed to add context on incremental decoding, ret:%{public}u.", ret);
            return ret;
        }
    }
    if (incrementalRecordIter->second.IncrementalState == ImageDecodingState::BASE_INFO_PARSED) {
        IMAGE_LOGD("[ImageSource]promote decode : set decode options.");
        ImagePlugin::PlImageInfo plInfo;
        ret = SetDecodeOptions(incrementalRecordIter->second.decoder, index, opts_, plInfo);
        if (ret != SUCCESS) {
            IMAGE_LOGE("[ImageSource]set decode options error (image index:%{public}u), ret:%{public}u.",
                index, ret);
            return ret;
        }

        auto iterator = decodeEventMap_.find((int)DecodeEvent::EVENT_HEADER_DECODE);
        if (iterator == decodeEventMap_.end()) {
            decodeEventMap_.insert(std::pair<int32_t, int32_t>((int)DecodeEvent::EVENT_HEADER_DECODE, 1));
            for (auto callback : decodeListeners_) {
                guard.unlock();
                callback->OnEvent((int)DecodeEvent::EVENT_HEADER_DECODE);
                guard.lock();
            }
        }
        Size size = {
            .width = plInfo.size.width,
            .height = plInfo.size.height
        };
        PostProc::ValidCropValue(opts_.CropRect, size);
        ret = UpdatePixelMapInfo(opts_, plInfo, pixelMap);
        if (ret != SUCCESS) {
            IMAGE_LOGE("[ImageSource]update pixelmap info error (image index:%{public}u), ret:%{public}u.",
                index, ret);
            return ret;
        }
        incrementalRecordIter->second.IncrementalState = ImageDecodingState::IMAGE_DECODING;
    }
    if (incrementalRecordIter->second.IncrementalState == ImageDecodingState::IMAGE_DECODING) {
        ret = DoIncrementalDecoding(index, opts_, pixelMap, incrementalRecordIter->second);
        decodeProgress = incrementalRecordIter->second.decodingProgress;
        state = incrementalRecordIter->second.IncrementalState;
        if (isIncrementalCompleted_) {
            PostProc postProc;
            ret = postProc.DecodePostProc(opts_, pixelMap);
            if (state == ImageDecodingState::IMAGE_DECODED) {
                auto iter = decodeEventMap_.find((int)DecodeEvent::EVENT_COMPLETE_DECODE);
                if (iter == decodeEventMap_.end()) {
                    decodeEventMap_.insert(std::pair<int32_t, int32_t>((int)DecodeEvent::EVENT_COMPLETE_DECODE, 1));
                    for (auto listener : decodeListeners_) {
                        guard.unlock();
                        listener->OnEvent((int)DecodeEvent::EVENT_COMPLETE_DECODE);
                        guard.lock();
                    }
                }
            }
        }
        return ret;
    }

    // IMAGE_ERROR or IMAGE_DECODED.
    state = incrementalRecordIter->second.IncrementalState;
    decodeProgress = incrementalRecordIter->second.decodingProgress;
    if (incrementalRecordIter->second.IncrementalState == ImageDecodingState::IMAGE_ERROR) {
        IMAGE_LOGE("[ImageSource]invalid imageState %{public}d on incremental decoding.",
            incrementalRecordIter->second.IncrementalState);
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    return SUCCESS;
}

void ImageSource::DetachIncrementalDecoding(PixelMap &pixelMap)
{
    std::lock_guard<std::mutex> guard(decodingMutex_);
    auto iter = incDecodingMap_.find(&pixelMap);
    if (iter == incDecodingMap_.end()) {
        return;
    }

    if (mainDecoder_ == nullptr) {
        // return back the decoder to mainDecoder_.
        mainDecoder_ = std::move(iter->second.decoder);
        iter->second.decoder = nullptr;
    }
    incDecodingMap_.erase(iter);
}

uint32_t ImageSource::UpdateData(const uint8_t *data, uint32_t size, bool isCompleted)
{
    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGE("[ImageSource]image source update data, source stream is null.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> guard(decodingMutex_);
    if (isCompleted) {
        isIncrementalCompleted_ = isCompleted;
    }
    return sourceStreamPtr_->UpdateData(data, size, isCompleted);
}

DecodeEvent ImageSource::GetDecodeEvent()
{
    return decodeEvent_;
}

uint32_t ImageSource::GetImageInfo(uint32_t index, ImageInfo &imageInfo)
{
    ImageTrace imageTrace("GetImageInfo by index");
    uint32_t ret = SUCCESS;
    std::unique_lock<std::mutex> guard(decodingMutex_);
    auto iter = GetValidImageStatus(index, ret);
    if (iter == imageStatusMap_.end()) {
        guard.unlock();
        IMAGE_LOGE("[ImageSource]get valid image status fail on get image info, ret:%{public}u.", ret);
        return ret;
    }
    ImageInfo &info = (iter->second).imageInfo;
    if (info.size.width == 0 || info.size.height == 0) {
        IMAGE_LOGE("[ImageSource]get the image size fail on get image info, width:%{public}d,"
            "height:%{public}d.", info.size.width, info.size.height);
        return ERR_IMAGE_DECODE_FAILED;
    }

    imageInfo = info;
    return SUCCESS;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const std::string &path)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on modify image property, ret:%{public}u.", ret);
        return ret;
    }
    ret = mainDecoder_->ModifyImageProperty(index, key, value, path);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource] ModifyImageProperty fail, ret:%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const int fd)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on modify image property, ret:%{public}u.", ret);
        return ret;
    }
    ret = mainDecoder_->ModifyImageProperty(index, key, value, fd);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource] ModifyImageProperty fail, ret:%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, uint8_t *data, uint32_t size)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on modify image property, ret:%{public}u.", ret);
        return ret;
    }
    ret = mainDecoder_->ModifyImageProperty(index, key, value, data, size);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource] ModifyImageProperty fail, ret:%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}

uint32_t ImageSource::GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on get image property, ret:%{public}u.", ret);
        return ret;
    }

    ret = mainDecoder_->GetImagePropertyInt(index, key, value);
    if (ret != SUCCESS) {
        IMAGE_LOGD("[ImageSource] GetImagePropertyInt fail, ret:%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}

uint32_t ImageSource::GetImagePropertyString(uint32_t index, const std::string &key, std::string &value)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on get image property, ret:%{public}u.", ret);
        return ret;
    }
    ret = mainDecoder_->GetImagePropertyString(index, key, value);
    if (ret != SUCCESS) {
        IMAGE_LOGD("[ImageSource] GetImagePropertyString fail, ret:%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}
const SourceInfo &ImageSource::GetSourceInfo(uint32_t &errorCode)
{
    std::lock_guard<std::mutex> guard(decodingMutex_);
    if (IsSpecialYUV()) {
        return sourceInfo_;
    }
    errorCode = DecodeSourceInfo(true);
    return sourceInfo_;
}

void ImageSource::RegisterListener(PeerListener *listener)
{
    if (listener == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> guard(listenerMutex_);
    listeners_.insert(listener);
}

void ImageSource::UnRegisterListener(PeerListener *listener)
{
    if (listener == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> guard(listenerMutex_);
    auto iter = listeners_.find(listener);
    if (iter != listeners_.end()) {
        listeners_.erase(iter);
    }
}

void ImageSource::AddDecodeListener(DecodeListener *listener)
{
    if (listener == nullptr) {
        IMAGE_LOGE("AddDecodeListener listener null");
        return;
    }
    std::lock_guard<std::mutex> guard(listenerMutex_);
    decodeListeners_.insert(listener);
}

void ImageSource::RemoveDecodeListener(DecodeListener *listener)
{
    if (listener == nullptr) {
        IMAGE_LOGE("RemoveDecodeListener listener null");
        return;
    }
    std::lock_guard<std::mutex> guard(listenerMutex_);
    auto iter = decodeListeners_.find(listener);
    if (iter != decodeListeners_.end()) {
        decodeListeners_.erase(iter);
    }
}

ImageSource::~ImageSource()
{
    IMAGE_LOGD("ImageSource destructor enter");
    std::lock_guard<std::mutex> guard(listenerMutex_);
    for (const auto &listener : listeners_) {
        listener->OnPeerDestory();
    }
}

bool ImageSource::IsStreamCompleted()
{
    std::lock_guard<std::mutex> guard(decodingMutex_);
    return sourceStreamPtr_->IsStreamCompleted();
}

// ------------------------------- private method -------------------------------
ImageSource::ImageSource(unique_ptr<SourceStream> &&stream, const SourceOptions &opts)
    : sourceStreamPtr_(stream.release())
{
    sourceInfo_.baseDensity = opts.baseDensity;
    sourceOptions_.baseDensity = opts.baseDensity;
    sourceOptions_.pixelFormat = opts.pixelFormat;
    sourceOptions_.size.width = opts.size.width;
    sourceOptions_.size.height = opts.size.height;
    imageId_ = GetNowTimeMicroSeconds();
}

ImageSource::FormatAgentMap ImageSource::InitClass()
{
    vector<ClassInfo> classInfos;
    pluginServer_.PluginServerGetClassInfo<AbsImageFormatAgent>(AbsImageFormatAgent::SERVICE_DEFAULT, classInfos);
    set<string> formats;
    for (auto &info : classInfos) {
        auto &capabilities = info.capabilities;
        auto iter = capabilities.find(IMAGE_ENCODE_FORMAT);
        if (iter == capabilities.end()) {
            continue;
        }

        AttrData &attr = iter->second;
        string format;
        if (SUCCESS != attr.GetValue(format)) {
            IMAGE_LOGE("[ImageSource]attr data get format:[%{public}s] failed.", format.c_str());
            continue;
        }
        formats.insert(move(format));
    }

    FormatAgentMap tempAgentMap;
    AbsImageFormatAgent *formatAgent = nullptr;
    for (auto format : formats) {
        map<string, AttrData> capabilities = { { IMAGE_ENCODE_FORMAT, AttrData(format) } };
        formatAgent =
            pluginServer_.CreateObject<AbsImageFormatAgent>(AbsImageFormatAgent::SERVICE_DEFAULT, capabilities);
        if (formatAgent == nullptr) {
            continue;
        }
        tempAgentMap.insert(FormatAgentMap::value_type(std::move(format), formatAgent));
    }
    return tempAgentMap;
}

uint32_t ImageSource::CheckEncodedFormat(AbsImageFormatAgent &agent)
{
    uint32_t size = agent.GetHeaderSize();
    ImagePlugin::DataStreamBuffer outData;
    uint32_t res = GetData(outData, size);
    if (res != SUCCESS) {
        return res;
    }
    if (!agent.CheckFormat(outData.inputStreamBuffer, size)) {
        IMAGE_LOGE("[ImageSource]check mismatched format :%{public}s.", agent.GetFormatType().c_str());
        return ERR_IMAGE_MISMATCHED_FORMAT;
    }
    return SUCCESS;
}

uint32_t ImageSource::GetData(ImagePlugin::DataStreamBuffer &outData, size_t size)
{
    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGE("[ImageSource]check image format, source stream is null.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!sourceStreamPtr_->Peek(size, outData)) {
        IMAGE_LOGE("[ImageSource]stream peek the data fail, desiredSize:%{public}zu", size);
        return ERR_IMAGE_SOURCE_DATA;
    }
    if (outData.inputStreamBuffer == nullptr || outData.dataSize < size) {
        IMAGE_LOGE("[ImageSource]the outData is incomplete.");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    }
    return SUCCESS;
}

uint32_t ImageSource::CheckFormatHint(const string &formatHint, FormatAgentMap::iterator &formatIter)
{
    uint32_t ret = ERROR;
    formatIter = formatAgentMap_.find(formatHint);
    if (formatIter == formatAgentMap_.end()) {
        IMAGE_LOGE("[ImageSource]check input format fail.");
        return ret;
    }
    AbsImageFormatAgent *agent = formatIter->second;
    ret = CheckEncodedFormat(*agent);
    if (ret != SUCCESS) {
        if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
            IMAGE_LOGE("[ImageSource]image source incomplete.");
        }
        return ret;
    }
    return SUCCESS;
}

AbsImageDecoder *DoCreateDecoder(std::string codecFormat,
    PluginServer &pluginServer, InputDataStream &sourceData, uint32_t &errorCode)
{
    map<string, AttrData> capabilities = { { IMAGE_ENCODE_FORMAT, AttrData(codecFormat) } };
    for (const auto &capability : capabilities) {
        std::string x = "undefined";
        capability.second.GetValue(x);
        IMAGE_LOGD("[ImageSource] capabilities [%{public}s],[%{public}s]",
            capability.first.c_str(), x.c_str());
    }
    auto decoder = pluginServer.CreateObject<AbsImageDecoder>(AbsImageDecoder::SERVICE_DEFAULT, capabilities);
    if (decoder == nullptr) {
        IMAGE_LOGE("[ImageSource]failed to create decoder object.");
        errorCode = ERR_IMAGE_PLUGIN_CREATE_FAILED;
        return nullptr;
    }
    errorCode = SUCCESS;
    decoder->SetSource(sourceData);
    return decoder;
}

uint32_t ImageSource::GetFormatExtended(string &format)
{
    if (mainDecoder_ != nullptr) {
        format = sourceInfo_.encodedFormat;
        return SUCCESS;
    }

    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGE("[ImageSource]sourceStreamPtr_ is null");
        return ERR_MEDIA_NULL_POINTER;
    }

    auto imageType = sourceStreamPtr_->Tell();
    uint32_t errorCode = ERR_IMAGE_DECODE_ABNORMAL;
    auto codec = DoCreateDecoder(InnerFormat::IMAGE_EXTENDED_CODEC, pluginServer_, *sourceStreamPtr_,
        errorCode);
    if (errorCode != SUCCESS || codec == nullptr) {
        IMAGE_LOGE("[ImageSource]No extended decoder.");
        return errorCode;
    }
    const static string EXT_ENCODED_FORMAT_KEY = "EncodedFormat";
    auto decoderPtr = unique_ptr<AbsImageDecoder>(codec);
    if (decoderPtr == nullptr) {
        IMAGE_LOGE("[ImageSource]decoderPtr null");
        return ERR_MEDIA_NULL_POINTER;
    }
    ProgDecodeContext context;
    if (IsIncrementalSource() &&
        decoderPtr->PromoteIncrementalDecode(UINT32_MAX, context) == ERR_IMAGE_DATA_UNSUPPORT) {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    errorCode = decoderPtr->GetImagePropertyString(FIRST_FRAME, EXT_ENCODED_FORMAT_KEY, format);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]Extended get format failed %{public}d.", errorCode);
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }
    
    if (!ImageSystemProperties::GetSkiaEnabled()) {
        IMAGE_LOGD("[ImageSource]Extended close SK decode");
        if (format != "image/gif") {
            sourceStreamPtr_->Seek(imageType);
            return ERR_MEDIA_DATA_UNSUPPORT;
        }
    }
    mainDecoder_ = std::move(decoderPtr);
    return errorCode;
}

uint32_t ImageSource::GetEncodedFormat(const string &formatHint, string &format)
{
    uint32_t ret;
    auto hintIter = formatAgentMap_.end();
    if (!formatHint.empty()) {
        ret = CheckFormatHint(formatHint, hintIter);
        if (ret == SUCCESS) {
            format = hintIter->first;
            IMAGE_LOGD("[ImageSource]check input image format success, format:%{public}s.", format.c_str());
            return SUCCESS;
        } else {
            IMAGE_LOGE("[ImageSource]checkFormatHint error, type: %{public}d", ret);
            return ret;
        }
    }

    if (GetFormatExtended(format) == SUCCESS) {
        return SUCCESS;
    }

    for (auto iter = formatAgentMap_.begin(); iter != formatAgentMap_.end(); ++iter) {
        string curFormat = iter->first;
        if (iter == hintIter || curFormat == InnerFormat::RAW_FORMAT) {
            continue;  // has been checked before.
        }
        AbsImageFormatAgent *agent = iter->second;
        ret = CheckEncodedFormat(*agent);
        if (ret == ERR_IMAGE_MISMATCHED_FORMAT) {
            continue;
        } else if (ret == SUCCESS) {
            IMAGE_LOGI("[ImageSource]GetEncodedFormat success format :%{public}s.", iter->first.c_str());
            format = iter->first;
            return SUCCESS;
        } else {
            IMAGE_LOGE("[ImageSource]checkEncodedFormat error, type: %{public}d", ret);
            return ret;
        }
    }

    // default return raw image, ERR_IMAGE_MISMATCHED_FORMAT case
    format = InnerFormat::RAW_FORMAT;
    IMAGE_LOGI("[ImageSource]image default to raw format.");
    return SUCCESS;
}

uint32_t ImageSource::OnSourceRecognized(bool isAcquiredImageNum)
{
    uint32_t ret = InitMainDecoder();
    if (ret != SUCCESS) {
        sourceInfo_.state = SourceInfoState::UNSUPPORTED_FORMAT;
        decodeState_ = SourceDecodingState::UNSUPPORTED_FORMAT;
        IMAGE_LOGE("[ImageSource]image decode error, ret:[%{public}u].", ret);
        return ret;
    }

    // for raw image, we need check the original format after decoder initialzation
    string value;
    ret = mainDecoder_->GetImagePropertyString(0, ACTUAL_IMAGE_ENCODED_FORMAT, value);
    if (ret == SUCCESS) {
        // update new format
        sourceInfo_.encodedFormat = value;
        IMAGE_LOGI("[ImageSource] update new format, value:%{public}s", value.c_str());
    }

    if (isAcquiredImageNum) {
        ret = mainDecoder_->GetTopLevelImageNum(sourceInfo_.topLevelImageNum);
        if (ret != SUCCESS) {
            if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
                sourceInfo_.state = SourceInfoState::SOURCE_INCOMPLETE;
                IMAGE_LOGE("[ImageSource]image source data incomplete.");
                return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            }
            sourceInfo_.state = SourceInfoState::FILE_INFO_ERROR;
            decodeState_ = SourceDecodingState::FILE_INFO_ERROR;
            IMAGE_LOGE("[ImageSource]image source error.");
            return ret;
        }
    }
    sourceInfo_.state = SourceInfoState::FILE_INFO_PARSED;
    decodeState_ = SourceDecodingState::FILE_INFO_DECODED;
    return SUCCESS;
}

uint32_t ImageSource::OnSourceUnresolved()
{
    string formatResult;
    if (!isAstc_.has_value()) {
        ImagePlugin::DataStreamBuffer outData;
        uint32_t res = GetData(outData, ASTC_HEADER_SIZE);
        if (res == SUCCESS) {
            isAstc_ = IsASTC(outData.inputStreamBuffer, outData.dataSize);
        }
    }
    if (isAstc_.has_value() && isAstc_.value()) {
        formatResult = InnerFormat::ASTC_FORMAT;
    } else {
        auto ret = GetEncodedFormat(sourceInfo_.encodedFormat, formatResult);
        if (ret != SUCCESS) {
            if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
                IMAGE_LOGE("[ImageSource]image source incomplete.");
                sourceInfo_.state = SourceInfoState::SOURCE_INCOMPLETE;
                return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            } else if (ret == ERR_IMAGE_UNKNOWN_FORMAT) {
                IMAGE_LOGE("[ImageSource]image unknown format.");
                sourceInfo_.state = SourceInfoState::UNKNOWN_FORMAT;
                decodeState_ = SourceDecodingState::UNKNOWN_FORMAT;
                return ERR_IMAGE_UNKNOWN_FORMAT;
            }
            sourceInfo_.state = SourceInfoState::SOURCE_ERROR;
            decodeState_ = SourceDecodingState::SOURCE_ERROR;
            IMAGE_LOGE("[ImageSource]image source error.");
            return ret;
        }
    }
    sourceInfo_.encodedFormat = formatResult;
    decodeState_ = SourceDecodingState::FORMAT_RECOGNIZED;
    return SUCCESS;
}

uint32_t GetSourceDecodingState(SourceDecodingState decodeState_)
{
    uint32_t ret = SUCCESS;
    switch (decodeState_) {
        case SourceDecodingState::SOURCE_ERROR: {
            ret = ERR_IMAGE_SOURCE_DATA;
            break;
        }
        case SourceDecodingState::UNKNOWN_FORMAT: {
            ret = ERR_IMAGE_UNKNOWN_FORMAT;
            break;
        }
        case SourceDecodingState::UNSUPPORTED_FORMAT: {
            ret = ERR_IMAGE_PLUGIN_CREATE_FAILED;
            break;
        }
        case SourceDecodingState::FILE_INFO_ERROR: {
            ret = ERR_IMAGE_DECODE_FAILED;
            break;
        }
        default: {
            ret = ERROR;
            break;
        }
    }
    return ret;
}

uint32_t ImageSource::DecodeSourceInfo(bool isAcquiredImageNum)
{
    uint32_t ret = SUCCESS;
    if (decodeState_ >= SourceDecodingState::FILE_INFO_DECODED) {
        if (isAcquiredImageNum) {
            decodeState_ = SourceDecodingState::FORMAT_RECOGNIZED;
        } else {
            return SUCCESS;
        }
    }
    if (decodeState_ == SourceDecodingState::UNRESOLVED) {
        ret = OnSourceUnresolved();
        if (ret != SUCCESS) {
            IMAGE_LOGE("[ImageSource]unresolved source: check format failed, ret:[%{public}d].", ret);
            return ret;
        }
    }
    if (decodeState_ == SourceDecodingState::FORMAT_RECOGNIZED) {
        if (sourceInfo_.encodedFormat == InnerFormat::ASTC_FORMAT) {
            sourceInfo_.state = SourceInfoState::FILE_INFO_PARSED;
            decodeState_ = SourceDecodingState::FILE_INFO_DECODED;
        } else {
            ret = OnSourceRecognized(isAcquiredImageNum);
            if (ret != SUCCESS) {
                IMAGE_LOGE("[ImageSource]recognized source: get source info failed, ret:[%{public}d].", ret);
                return ret;
            }
        }
        return SUCCESS;
    }
    IMAGE_LOGE("[ImageSource]invalid source state %{public}d on decode source info.", decodeState_);
    ret = GetSourceDecodingState(decodeState_);
    return ret;
}

uint32_t ImageSource::DecodeImageInfo(uint32_t index, ImageStatusMap::iterator &iter)
{
    uint32_t ret = DecodeSourceInfo(false);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decode the image fail, ret:%{public}d.", ret);
        return ret;
    }
    if (sourceInfo_.encodedFormat == InnerFormat::ASTC_FORMAT) {
        ASTCInfo astcInfo;
        if (GetASTCInfo(sourceStreamPtr_->GetDataPtr(), sourceStreamPtr_->GetStreamSize(), astcInfo)) {
            ImageDecodingStatus imageStatus;
            imageStatus.imageInfo.size = astcInfo.size;
            imageStatus.imageState = ImageDecodingState::BASE_INFO_PARSED;
            auto result = imageStatusMap_.insert(ImageStatusMap::value_type(index, imageStatus));
            iter = result.first;
            return SUCCESS;
        } else {
            IMAGE_LOGE("[ImageSource] decode astc image info failed.");
            return ERR_IMAGE_DECODE_FAILED;
        }
    }
    if (mainDecoder_ == nullptr) {
        IMAGE_LOGE("[ImageSource]get image size, image decode plugin is null.");
        return ERR_IMAGE_PLUGIN_CREATE_FAILED;
    }
    ImagePlugin::PlSize size;
    ret = mainDecoder_->GetImageSize(index, size);
    if (ret == SUCCESS) {
        ImageDecodingStatus imageStatus;
        imageStatus.imageInfo.size.width = size.width;
        imageStatus.imageInfo.size.height = size.height;
        imageStatus.imageState = ImageDecodingState::BASE_INFO_PARSED;
        auto result = imageStatusMap_.insert(ImageStatusMap::value_type(index, imageStatus));
        iter = result.first;
        return SUCCESS;
    } else if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
        IMAGE_LOGE("[ImageSource]source data incomplete.");
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    } else {
        ImageDecodingStatus status;
        status.imageState = ImageDecodingState::BASE_INFO_ERROR;
        auto errorResult = imageStatusMap_.insert(ImageStatusMap::value_type(index, status));
        iter = errorResult.first;
        IMAGE_LOGE("[ImageSource]decode the image info fail.");
        return ERR_IMAGE_DECODE_FAILED;
    }
}

uint32_t ImageSource::InitMainDecoder()
{
    if (mainDecoder_ != nullptr) {
        return SUCCESS;
    }
    uint32_t result = SUCCESS;
    mainDecoder_ = std::unique_ptr<ImagePlugin::AbsImageDecoder>(CreateDecoder(result));
    return result;
}

AbsImageDecoder *ImageSource::CreateDecoder(uint32_t &errorCode)
{
    // in normal mode, we can get actual encoded format to the user
    // but we need transfer to skia codec for adaption, "image/x-skia"
    std::string encodedFormat = sourceInfo_.encodedFormat;
    if (opts_.sampleSize != 1) {
        encodedFormat = InnerFormat::EXTENDED_FORMAT;
    }
    return DoCreateDecoder(encodedFormat, pluginServer_, *sourceStreamPtr_, errorCode);
}

static void GetDefaultPixelFormat(const PixelFormat desired, PlPixelFormat& out,
    MemoryUsagePreference preference)
{
    if (desired != PixelFormat::UNKNOWN) {
        auto formatPair = PIXEL_FORMAT_MAP.find(desired);
        if (formatPair != PIXEL_FORMAT_MAP.end() && formatPair->second != PlPixelFormat::UNKNOWN) {
            out = formatPair->second;
            return;
        }
    }
    out = (preference == MemoryUsagePreference::LOW_RAM)?PlPixelFormat::RGB_565:PlPixelFormat::RGBA_8888;
}

uint32_t ImageSource::SetDecodeOptions(std::unique_ptr<AbsImageDecoder> &decoder,
    uint32_t index, const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo)
{
    PlPixelFormat plDesiredFormat;
    GetDefaultPixelFormat(opts.desiredPixelFormat, plDesiredFormat, preference_);
    PixelDecodeOptions plOptions;
    CopyOptionsToPlugin(opts, plOptions);
    plOptions.desiredPixelFormat = plDesiredFormat;
    uint32_t ret = decoder->SetDecodeOptions(index, plOptions, plInfo);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decoder plugin set decode options fail (image index:%{public}u),"
            "ret:%{public}u.", index, ret);
        return ret;
    }
    auto iter = imageStatusMap_.find(index);
    if (iter != imageStatusMap_.end()) {
        ImageInfo &info = (iter->second).imageInfo;
        IMAGE_LOGD("[ImageSource]SetDecodeOptions plInfo.pixelFormat %{public}d", plInfo.pixelFormat);

        PlPixelFormat format = plInfo.pixelFormat;
        auto find_item = std::find_if(PIXEL_FORMAT_MAP.begin(), PIXEL_FORMAT_MAP.end(),
            [format](const std::map<PixelFormat, PlPixelFormat>::value_type item) {
            return item.second == format;
        });
        if (find_item != PIXEL_FORMAT_MAP.end()) {
            info.pixelFormat = (*find_item).first;
        }
        IMAGE_LOGD("[ImageSource]SetDecodeOptions info.pixelFormat %{public}d", info.pixelFormat);
    }
    return SUCCESS;
}

uint32_t ImageSource::UpdatePixelMapInfo(const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo,
                                         PixelMap &pixelMap)
{
    return UpdatePixelMapInfo(opts, plInfo, pixelMap, INT_ZERO);
}
uint32_t ImageSource::UpdatePixelMapInfo(const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo,
                                         PixelMap &pixelMap, int32_t fitDensity, bool isReUsed)
{
    pixelMap.SetEditable(opts.editable);

    ImageInfo info;
    info.baseDensity = sourceInfo_.baseDensity;
    if (fitDensity != INT_ZERO) {
        info.baseDensity = fitDensity;
    }
    info.size.width = plInfo.size.width;
    info.size.height = plInfo.size.height;
    info.pixelFormat = static_cast<PixelFormat>(plInfo.pixelFormat);
    info.alphaType = static_cast<AlphaType>(plInfo.alphaType);
    return pixelMap.SetImageInfo(info, isReUsed);
}

void ImageSource::CopyOptionsToPlugin(const DecodeOptions &opts, PixelDecodeOptions &plOpts)
{
    plOpts.CropRect.left = opts.CropRect.left;
    plOpts.CropRect.top = opts.CropRect.top;
    plOpts.CropRect.width = opts.CropRect.width;
    plOpts.CropRect.height = opts.CropRect.height;
    plOpts.desiredSize.width = opts.desiredSize.width;
    plOpts.desiredSize.height = opts.desiredSize.height;
    plOpts.rotateDegrees = opts.rotateDegrees;
    plOpts.sampleSize = opts.sampleSize;
    auto formatSearch = PIXEL_FORMAT_MAP.find(opts.desiredPixelFormat);
    plOpts.desiredPixelFormat =
        (formatSearch != PIXEL_FORMAT_MAP.end()) ? formatSearch->second : PlPixelFormat::RGBA_8888;
    auto colorSearch = COLOR_SPACE_MAP.find(opts.desiredColorSpace);
    plOpts.desiredColorSpace = (colorSearch != COLOR_SPACE_MAP.end()) ? colorSearch->second : PlColorSpace::UNKNOWN;
    plOpts.allowPartialImage = opts.allowPartialImage;
    plOpts.editable = opts.editable;
    if (opts.SVGOpts.fillColor.isValidColor) {
        plOpts.plFillColor.isValidColor = opts.SVGOpts.fillColor.isValidColor;
        plOpts.plFillColor.color = opts.SVGOpts.fillColor.color;
    }
    if (opts.SVGOpts.SVGResize.isValidPercentage) {
        plOpts.plSVGResize.isValidPercentage = opts.SVGOpts.SVGResize.isValidPercentage;
        plOpts.plSVGResize.resizePercentage = opts.SVGOpts.SVGResize.resizePercentage;
    }
    plOpts.plDesiredColorSpace = opts.desiredColorSpaceInfo;
}

void ImageSource::CopyOptionsToProcOpts(const DecodeOptions &opts, DecodeOptions &procOpts, PixelMap &pixelMap)
{
    procOpts.fitDensity = opts.fitDensity;
    procOpts.CropRect.left = opts.CropRect.left;
    procOpts.CropRect.top = opts.CropRect.top;
    procOpts.CropRect.width = opts.CropRect.width;
    procOpts.CropRect.height = opts.CropRect.height;
    procOpts.desiredSize.width = opts.desiredSize.width;
    procOpts.desiredSize.height = opts.desiredSize.height;
    procOpts.rotateDegrees = opts.rotateDegrees;
    procOpts.sampleSize = opts.sampleSize;
    procOpts.desiredPixelFormat = opts.desiredPixelFormat;
    if (opts.allocatorType == AllocatorType::DEFAULT) {
        procOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    } else {
        procOpts.allocatorType = opts.allocatorType;
    }
    procOpts.desiredColorSpace = opts.desiredColorSpace;
    procOpts.allowPartialImage = opts.allowPartialImage;
    procOpts.editable = opts.editable;
    // we need preference_ when post processing
    procOpts.preference = preference_;
}

ImageSource::ImageStatusMap::iterator ImageSource::GetValidImageStatus(uint32_t index, uint32_t &errorCode)
{
    auto iter = imageStatusMap_.find(index);
    if (iter == imageStatusMap_.end()) {
        errorCode = DecodeImageInfo(index, iter);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("[ImageSource]image info decode fail, ret:%{public}u.", errorCode);
            return imageStatusMap_.end();
        }
    } else if (iter->second.imageState < ImageDecodingState::BASE_INFO_PARSED) {
        IMAGE_LOGE("[ImageSource]invalid imageState %{public}d on get image status.", iter->second.imageState);
        errorCode = ERR_IMAGE_DECODE_FAILED;
        return imageStatusMap_.end();
    }
    errorCode = SUCCESS;
    return iter;
}

uint32_t ImageSource::AddIncrementalContext(PixelMap &pixelMap, IncrementalRecordMap::iterator &iterator)
{
    uint32_t ret = SUCCESS;
    IncrementalDecodingContext context;
    if (mainDecoder_ != nullptr) {
        // borrowed decoder from the mainDecoder_.
        context.decoder = std::move(mainDecoder_);
    } else {
        context.decoder = std::unique_ptr<ImagePlugin::AbsImageDecoder>(CreateDecoder(ret));
    }
    if (context.decoder == nullptr) {
        IMAGE_LOGE("[ImageSource]failed to create decoder on add incremental context, ret:%{public}u.", ret);
        return ret;
    }
    // mainDecoder has parsed base info in DecodeImageInfo();
    context.IncrementalState = ImageDecodingState::BASE_INFO_PARSED;
    auto result = incDecodingMap_.insert(IncrementalRecordMap::value_type(&pixelMap, std::move(context)));
    iterator = result.first;
    return SUCCESS;
}

uint32_t ImageSource::DoIncrementalDecoding(uint32_t index, const DecodeOptions &opts, PixelMap &pixelMap,
                                            IncrementalDecodingContext &recordContext)
{
    IMAGE_LOGD("[ImageSource]do incremental decoding: begin.");
    uint8_t *pixelAddr = static_cast<uint8_t *>(pixelMap.GetWritablePixels());
    ProgDecodeContext context;
    context.decodeContext.pixelsBuffer.buffer = pixelAddr;
    uint32_t ret = recordContext.decoder->PromoteIncrementalDecode(index, context);
    if (context.decodeContext.pixelsBuffer.buffer != nullptr && pixelAddr == nullptr) {
        pixelMap.SetPixelsAddr(context.decodeContext.pixelsBuffer.buffer, context.decodeContext.pixelsBuffer.context,
                               context.decodeContext.pixelsBuffer.bufferSize, context.decodeContext.allocatorType,
                               context.decodeContext.freeFunc);
    }
    IMAGE_LOGD("[ImageSource]do incremental decoding progress:%{public}u.", context.totalProcessProgress);
    recordContext.decodingProgress = context.totalProcessProgress;
    if (ret != SUCCESS && ret != ERR_IMAGE_SOURCE_DATA_INCOMPLETE) {
        recordContext.IncrementalState = ImageDecodingState::IMAGE_ERROR;
        IMAGE_LOGE("[ImageSource]do incremental decoding source fail, ret:%{public}u.", ret);
        return ret;
    }
    if (ret == SUCCESS) {
        recordContext.IncrementalState = ImageDecodingState::IMAGE_DECODED;
        IMAGE_LOGI("[ImageSource]do incremental decoding success.");
    }
    return ret;
}

const NinePatchInfo &ImageSource::GetNinePatchInfo() const
{
    return ninePatchInfo_;
}

void ImageSource::SetMemoryUsagePreference(const MemoryUsagePreference preference)
{
    preference_ = preference;
}

MemoryUsagePreference ImageSource::GetMemoryUsagePreference()
{
    return preference_;
}

uint32_t ImageSource::GetFilterArea(const int &privacyType, std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource]get valid image status fail on get filter area, ret:%{public}u.", ret);
        return ret;
    }
    ret = mainDecoder_->GetFilterArea(privacyType, ranges);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource] GetFilterArea fail, ret:%{public}u", ret);
        return ret;
    }
    return SUCCESS;
}

void ImageSource::SetIncrementalSource(const bool isIncrementalSource)
{
    isIncrementalSource_ = isIncrementalSource;
}

bool ImageSource::IsIncrementalSource()
{
    return isIncrementalSource_;
}

FinalOutputStep ImageSource::GetFinalOutputStep(const DecodeOptions &opts, PixelMap &pixelMap, bool hasNinePatch)
{
    ImageInfo info;
    pixelMap.GetImageInfo(info);
    ImageInfo dstImageInfo;
    dstImageInfo.size = opts.desiredSize;
    dstImageInfo.pixelFormat = opts.desiredPixelFormat;
    if (opts.desiredPixelFormat == PixelFormat::UNKNOWN) {
        if (preference_ == MemoryUsagePreference::LOW_RAM && info.alphaType == AlphaType::IMAGE_ALPHA_TYPE_OPAQUE) {
            dstImageInfo.pixelFormat = PixelFormat::RGB_565;
        } else {
            dstImageInfo.pixelFormat = PixelFormat::RGBA_8888;
        }
    }
    // decode use, this value may be changed by real pixelFormat
    if (pixelMap.GetAlphaType() == AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL) {
        dstImageInfo.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
    } else {
        dstImageInfo.alphaType = pixelMap.GetAlphaType();
    }
    bool densityChange = HasDensityChange(opts, info, hasNinePatch);
    bool sizeChange = ImageSizeChange(pixelMap.GetWidth(), pixelMap.GetHeight(),
                                      opts.desiredSize.width, opts.desiredSize.height);
    bool rotateChange = !ImageUtils::FloatCompareZero(opts.rotateDegrees);
    bool convertChange = ImageConverChange(opts.CropRect, dstImageInfo, info);
    if (sizeChange) {
        return FinalOutputStep::SIZE_CHANGE;
    }
    if (densityChange) {
        return FinalOutputStep::DENSITY_CHANGE;
    }
    if (rotateChange) {
        return FinalOutputStep::ROTATE_CHANGE;
    }
    if (convertChange) {
        return FinalOutputStep::CONVERT_CHANGE;
    }
    return FinalOutputStep::NO_CHANGE;
}

bool ImageSource::HasDensityChange(const DecodeOptions &opts, ImageInfo &srcImageInfo, bool hasNinePatch)
{
    return !hasNinePatch && (srcImageInfo.baseDensity > 0) &&
           (opts.fitDensity > 0) && (srcImageInfo.baseDensity != opts.fitDensity);
}

bool ImageSource::ImageSizeChange(int32_t width, int32_t height, int32_t desiredWidth, int32_t desiredHeight)
{
    bool sizeChange = false;
    if (desiredWidth > 0 && desiredHeight > 0 && width > 0 && height > 0) {
        float scaleX = static_cast<float>(desiredWidth) / static_cast<float>(width);
        float scaleY = static_cast<float>(desiredHeight) / static_cast<float>(height);
        if ((fabs(scaleX - 1.0f) >= EPSILON) && (fabs(scaleY - 1.0f) >= EPSILON)) {
            sizeChange = true;
        }
    }
    return sizeChange;
}

bool ImageSource::ImageConverChange(const Rect &cropRect, ImageInfo &dstImageInfo, ImageInfo &srcImageInfo)
{
    bool hasPixelConvert = false;
    dstImageInfo.alphaType = ImageUtils::GetValidAlphaTypeByFormat(dstImageInfo.alphaType, dstImageInfo.pixelFormat);
    if (dstImageInfo.pixelFormat != srcImageInfo.pixelFormat || dstImageInfo.alphaType != srcImageInfo.alphaType) {
        hasPixelConvert = true;
    }
    CropValue value = PostProc::GetCropValue(cropRect, srcImageInfo.size);
    if (value == CropValue::NOCROP && !hasPixelConvert) {
        IMAGE_LOGD("[ImageSource]no need crop and pixel convert.");
        return false;
    } else if (value == CropValue::INVALID) {
        IMAGE_LOGE("[ImageSource]invalid corp region, top:%{public}d, left:%{public}d, "
            "width:%{public}d, height:%{public}d", cropRect.top, cropRect.left, cropRect.width, cropRect.height);
        return false;
    }
    return true;
}
unique_ptr<SourceStream> ImageSource::DecodeBase64(const uint8_t *data, uint32_t size)
{
    if (size < IMAGE_URL_PREFIX.size() ||
        ::memcmp(data, IMAGE_URL_PREFIX.c_str(), IMAGE_URL_PREFIX.size()) != INT_ZERO) {
        IMAGE_LOGD("[ImageSource]Base64 image header mismatch.");
        return nullptr;
    }
    const char* data1 = reinterpret_cast<const char*>(data);
    auto sub = ::strstr(data1, BASE64_URL_PREFIX.c_str());
    if (sub == nullptr) {
        IMAGE_LOGI("[ImageSource]Base64 mismatch.");
        return nullptr;
    }
    sub = sub + BASE64_URL_PREFIX.size();
    uint32_t subSize = size - (sub - data1);
    IMAGE_LOGD("[ImageSource]Base64 image input: %{public}p, data: %{public}p, size %{public}u.",
        data, sub, subSize);
#ifdef NEW_SKIA
    size_t outputLen = 0;
    SkBase64::Error error = SkBase64::Decode(sub, subSize, nullptr, &outputLen);
    if (error != SkBase64::Error::kNoError) {
        IMAGE_LOGE("[ImageSource]Base64 decode get out size failed.");
        return nullptr;
    }

    sk_sp<SkData> resData = SkData::MakeUninitialized(outputLen);
    error = SkBase64::Decode(sub, subSize, resData->writable_data(), &outputLen);
    if (error != SkBase64::Error::kNoError) {
        IMAGE_LOGE("[ImageSource]Base64 decode get data failed.");
        return nullptr;
    }
    IMAGE_LOGD("[ImageSource][NewSkia]Create BufferSource from decoded base64 string.");
    auto imageData = static_cast<const uint8_t*>(resData->data());
    return BufferSourceStream::CreateSourceStream(imageData, resData->size());
#else
    SkBase64 base64Decoder;
    if (base64Decoder.decode(sub, subSize) != SkBase64::kNoError) {
        IMAGE_LOGE("[ImageSource]base64 image decode failed!");
        return nullptr;
    }
    auto base64Data = base64Decoder.getData();
    const uint8_t* imageData = reinterpret_cast<uint8_t*>(base64Data);
    IMAGE_LOGD("[ImageSource]Create BufferSource from decoded base64 string.");
    auto result = BufferSourceStream::CreateSourceStream(imageData, base64Decoder.getDataSize());
    if (base64Data != nullptr) {
        delete[] base64Data;
        base64Data = nullptr;
    }
    return result;
#endif
}

unique_ptr<SourceStream> ImageSource::DecodeBase64(const string &data)
{
    return DecodeBase64(reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
}

bool ImageSource::IsSpecialYUV()
{
    const bool isBufferSource = (sourceStreamPtr_ != nullptr)
        && (sourceStreamPtr_->GetStreamType() == ImagePlugin::BUFFER_SOURCE_TYPE);
    const bool isSizeValid = (sourceOptions_.size.width > 0) && (sourceOptions_.size.height > 0);
    const bool isYUV = (sourceOptions_.pixelFormat == PixelFormat::NV12)
        || (sourceOptions_.pixelFormat == PixelFormat::NV21);
    return (isBufferSource && isSizeValid && isYUV);
}

static inline uint8_t FloatToUint8(float f)
{
    int data = static_cast<int>(f + 0.5f);
    if (data < 0) {
        data = 0;
    } else if (data > UINT8_MAX) {
        data = UINT8_MAX;
    }
    return static_cast<uint8_t>(data);
}

bool ImageSource::ConvertYUV420ToRGBA(uint8_t *data, uint32_t size,
    bool isSupportOdd, bool isAddUV, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]ConvertYUV420ToRGBA IN srcPixelFormat:%{public}d, srcSize:(%{public}d,"
        "%{public}d)", sourceOptions_.pixelFormat, sourceOptions_.size.width, sourceOptions_.size.height);
    if ((!isSupportOdd) && (sourceOptions_.size.width & 1) == 1) {
        IMAGE_LOGE("[ImageSource]ConvertYUV420ToRGBA odd width, %{public}d", sourceOptions_.size.width);
        errorCode = ERR_IMAGE_DATA_UNSUPPORT;
        return false;
    }

    const size_t width = sourceOptions_.size.width;
    const size_t height = sourceOptions_.size.height;
    const size_t uvwidth = (isSupportOdd && isAddUV) ? (width + (width & 1)) : width;
    const uint8_t *yuvPlane = sourceStreamPtr_->GetDataPtr();
    const size_t yuvSize = sourceStreamPtr_->GetStreamSize();
    const size_t ubase = width * height + ((sourceOptions_.pixelFormat == PixelFormat::NV12) ? 0 : 1);
    const size_t vbase = width * height + ((sourceOptions_.pixelFormat == PixelFormat::NV12) ? 1 : 0);
    IMAGE_LOGD("[ImageSource]ConvertYUV420ToRGBA uvbase:(%{public}zu, %{public}zu),"
        "width:(%{public}zu, %{public}zu)", ubase, vbase, width, uvwidth);

    for (size_t h = 0; h < height; h++) {
        const size_t yline = h * width;
        const size_t uvline = (h >> 1) * uvwidth;

        for (size_t w = 0; w < width; w++) {
            const size_t ypos = yline + w;
            const size_t upos = ubase + uvline + (w & (~1));
            const size_t vpos = vbase + uvline + (w & (~1));
            const uint8_t y = (ypos < yuvSize) ? yuvPlane[ypos] : 0;
            const uint8_t u = (upos < yuvSize) ? yuvPlane[upos] : 0;
            const uint8_t v = (vpos < yuvSize) ? yuvPlane[vpos] : 0;
            // jpeg
            const uint8_t r = FloatToUint8((1.0f * y) + (1.402f * v) - (0.703749f * UINT8_MAX));
            const uint8_t g = FloatToUint8((1.0f * y) - (0.344136f * u) - (0.714136f * v) + (0.531211f * UINT8_MAX));
            const uint8_t b = FloatToUint8((1.0f * y) + (1.772f * u) - (0.889475f * UINT8_MAX));

            const size_t rgbpos = ypos << 2;
            if ((rgbpos + NUM_3) < size) {
                data[rgbpos + NUM_0] = r;
                data[rgbpos + NUM_1] = g;
                data[rgbpos + NUM_2] = b;
                data[rgbpos + NUM_3] = UINT8_MAX;
            }
        }
    }
    IMAGE_LOGD("[ImageSource]ConvertYUV420ToRGBA OUT");
    return true;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapForYUV(uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]CreatePixelMapForYUV IN srcPixelFormat:%{public}d, srcSize:(%{public}d,"
        "%{public}d)", sourceOptions_.pixelFormat, sourceOptions_.size.width, sourceOptions_.size.height);
    DumpInputData("yuv");

    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("[ImageSource]create the pixel map unique_ptr fail.");
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }

    ImageInfo info;
    info.baseDensity = sourceOptions_.baseDensity;
    info.size.width = sourceOptions_.size.width;
    info.size.height = sourceOptions_.size.height;
    info.pixelFormat = PixelFormat::RGBA_8888;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    errorCode = pixelMap->SetImageInfo(info);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]update pixelmap info error ret:%{public}u.", errorCode);
        return nullptr;
    }

    size_t bufferSize = static_cast<size_t>(pixelMap->GetWidth() * pixelMap->GetHeight() * pixelMap->GetPixelBytes());
    auto buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        IMAGE_LOGE("allocate memory size %{public}zu fail", bufferSize);
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }

    pixelMap->SetEditable(false);
    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

    if (!ConvertYUV420ToRGBA(static_cast<uint8_t *>(buffer), bufferSize, false, false, errorCode)) {
        IMAGE_LOGE("convert yuv420 to rgba issue, errorCode=%{public}u", errorCode);
        errorCode = ERROR;
        return nullptr;
    }

    IMAGE_LOGD("[ImageSource]CreatePixelMapForYUV OUT");
    return pixelMap;
}

bool ImageSource::IsASTC(const uint8_t *fileData, size_t fileSize)
{
    if (fileData == nullptr || fileSize < ASTC_HEADER_SIZE) {
        IMAGE_LOGE("[ImageSource]IsASTC fileData incorrect.");
        return false;
    }
    unsigned int magicVal = static_cast<unsigned int>(fileData[0]) + (static_cast<unsigned int>(fileData[1]) << 8) +
        (static_cast<unsigned int>(fileData[2]) << 16) + (static_cast<unsigned int>(fileData[3]) << 24);
    return magicVal == ASTC_MAGIC_ID;
}

bool ImageSource::GetImageInfoForASTC(ImageInfo& imageInfo)
{
    ASTCInfo astcInfo;
    if (!GetASTCInfo(sourceStreamPtr_->GetDataPtr(), sourceStreamPtr_->GetStreamSize(), astcInfo)) {
        IMAGE_LOGE("[ImageSource] get astc image info failed.");
        return false;
    }
    imageInfo.size = astcInfo.size;
    switch (astcInfo.blockFootprint.width) {
        case NUM_4: {
            imageInfo.pixelFormat = PixelFormat::ASTC_4x4;
            break;
        }
        case NUM_6: {
            imageInfo.pixelFormat = PixelFormat::ASTC_6x6;
            break;
        }
        case NUM_8: {
            imageInfo.pixelFormat = PixelFormat::ASTC_8x8;
            break;
        }
        default:
            IMAGE_LOGE("[ImageSource]GetImageInfoForASTC pixelFormat is unknown.");
            imageInfo.pixelFormat = PixelFormat::UNKNOWN;
    }
    return true;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapForASTC(uint32_t &errorCode)
#if defined(A_PLATFORM) || defined(IOS_PLATFORM)
{
    errorCode = ERROR;
    return nullptr;
}
#else
{
    ImageTrace imageTrace("CreatePixelMapForASTC");
    unique_ptr<PixelAstc> pixelAstc = make_unique<PixelAstc>();

    ImageInfo info;
    if (!GetImageInfoForASTC(info)) {
        IMAGE_LOGE("[ImageSource] get astc image info failed.");
        return nullptr;
    }
    errorCode = pixelAstc->SetImageInfo(info);
    pixelAstc->SetAstcRealSize(info.size);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]update pixelmap info error ret:%{public}u.", errorCode);
        return nullptr;
    }
    pixelAstc->SetEditable(false);
    size_t fileSize = sourceStreamPtr_->GetStreamSize();
    int fd = AshmemCreate("CreatePixelMapForASTC Data", fileSize);
    if (fd < 0) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapForASTC AshmemCreate fd < 0.");
        return nullptr;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapForASTC AshmemSetPort error.");
        ::close(fd);
        return nullptr;
    }
    void* ptr = ::mmap(nullptr, fileSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED || ptr == nullptr) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapForASTC data is nullptr.");
        ::close(fd);
        return nullptr;
    }
    auto data = static_cast<uint8_t*>(ptr);
    void* fdPtr = new int32_t();
    *static_cast<int32_t*>(fdPtr) = fd;
    pixelAstc->SetPixelsAddr(data, fdPtr, fileSize, Media::AllocatorType::SHARE_MEM_ALLOC, nullptr);
    memcpy_s(data, fileSize, sourceStreamPtr_->GetDataPtr(), fileSize);
    pixelAstc->SetAstc(true);
    return pixelAstc;
}
#endif

bool ImageSource::GetASTCInfo(const uint8_t *fileData, size_t fileSize, ASTCInfo& astcInfo)
{
    if (fileData == nullptr || fileSize < ASTC_HEADER_SIZE) {
        IMAGE_LOGE("[ImageSource]GetASTCInfo fileData incorrect.");
        return false;
    }
    astcInfo.size.width = static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X]) +
                          (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X + 1]) << NUM_8) +
                          (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X + NUM_2]) << NUM_16);
    astcInfo.size.height = static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y]) +
                           (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y + 1]) << NUM_8) +
                           (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y + NUM_2]) << NUM_16);
    astcInfo.blockFootprint.width = fileData[ASTC_HEADER_BLOCK_X];
    astcInfo.blockFootprint.height = fileData[ASTC_HEADER_BLOCK_Y];
    return true;
}

unique_ptr<vector<unique_ptr<PixelMap>>> ImageSource::CreatePixelMapList(const DecodeOptions &opts,
    uint32_t &errorCode)
{
    DumpInputData();
    auto frameCount = GetFrameCount(errorCode);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapList get frame count error.");
        return nullptr;
    }

    auto pixelMaps = std::make_unique<vector<unique_ptr<PixelMap>>>();
    for (uint32_t index = 0; index < frameCount; index++) {
        auto pixelMap = CreatePixelMap(index, opts, errorCode);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("[ImageSource]CreatePixelMapList create PixelMap error. index=%{public}u", index);
            return nullptr;
        }
        pixelMaps->push_back(std::move(pixelMap));
    }

    errorCode = SUCCESS;

    return pixelMaps;
}

unique_ptr<vector<int32_t>> ImageSource::GetDelayTime(uint32_t &errorCode)
{
    auto frameCount = GetFrameCount(errorCode);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]GetDelayTime get frame sum error.");
        return nullptr;
    }

    auto delayTimes = std::make_unique<vector<int32_t>>();
    const string GIF_IMAGE_DELAY_TIME = "GIFDelayTime";
    for (uint32_t index = 0; index < frameCount; index++) {
        string delayTimeStr;
        errorCode = mainDecoder_->GetImagePropertyString(index, GIF_IMAGE_DELAY_TIME, delayTimeStr);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("[ImageSource]GetDelayTime get delay time issue. index=%{public}u", index);
            return nullptr;
        }
        if (!IsNumericStr(delayTimeStr)) {
            IMAGE_LOGE("[ImageSource]GetDelayTime not a numeric string. delayTimeStr=%{public}s",
                delayTimeStr.c_str());
            return nullptr;
        }
        int delayTime = 0;
        if (!StrToInt(delayTimeStr, delayTime)) {
            IMAGE_LOGE("[ImageSource]GetDelayTime to int fail. delayTimeStr=%{public}s", delayTimeStr.c_str());
            return nullptr;
        }
        delayTimes->push_back(delayTime);
    }

    errorCode = SUCCESS;

    return delayTimes;
}

uint32_t ImageSource::GetFrameCount(uint32_t &errorCode)
{
    uint32_t frameCount = GetSourceInfo(errorCode).topLevelImageNum;
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]GetFrameCount get source info error.");
        return 0;
    }

    if (InitMainDecoder() != SUCCESS) {
        IMAGE_LOGE("[ImageSource]GetFrameCount image decode plugin is null.");
        errorCode = ERR_IMAGE_PLUGIN_CREATE_FAILED;
        return 0;
    }

    return frameCount;
}

void ImageSource::DumpInputData(const std::string& fileSuffix)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }

    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGI("ImageSource::DumpInputData failed, streamPtr is null");
        return;
    }

    uint8_t* data = sourceStreamPtr_->GetDataPtr();
    size_t size = sourceStreamPtr_->GetStreamSize();

    ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<const char*>(data), size, fileSuffix, imageId_);
}

#ifdef IMAGE_PURGEABLE_PIXELMAP
size_t ImageSource::GetSourceSize() const
{
    return sourceStreamPtr_ ? sourceStreamPtr_->GetStreamSize() : 0;
}
#endif

bool ImageSource::IsSupportGenAstc()
{
    return ImageSystemProperties::GetMediaLibraryAstcEnabled();
}
} // namespace Media
} // namespace OHOS
