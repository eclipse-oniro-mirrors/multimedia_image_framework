/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "image_source.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <vector>

#include "buffer_source_stream.h"
#if !defined(_WIN32) && !defined(_APPLE)
#include "hitrace_meter.h"
#include "image_trace.h"
#include "image_data_statistics.h"
#endif
#include "exif_metadata.h"
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
#include "metadata_accessor.h"
#include "metadata_accessor_factory.h"
#include "pixel_astc.h"
#include "pixel_map.h"
#include "plugin_server.h"
#include "post_proc.h"
#include "securec.h"
#include "source_stream.h"
#include "image_dfx.h"
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
#include "include/jpeg_decoder.h"
#else
#include "surface_buffer.h"
#include "v1_0/buffer_handle_meta_key_type.h"
#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "vpe_utils.h"
#endif
#include "include/utils/SkBase64.h"
#if defined(NEW_SKIA)
#include "include/core/SkData.h"
#endif
#include "string_ex.h"
#include "hdr_type.h"
#include "image_mime_type.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "ImageSource"

namespace OHOS {
namespace Media {
using namespace std;
using namespace ImagePlugin;
using namespace MultimediaPlugin;
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace HDI::Display::Graphic::Common::V1_0;
#endif

static const map<PixelFormat, PlPixelFormat> PIXEL_FORMAT_MAP = {
    { PixelFormat::UNKNOWN, PlPixelFormat::UNKNOWN },     { PixelFormat::ARGB_8888, PlPixelFormat::ARGB_8888 },
    { PixelFormat::ALPHA_8, PlPixelFormat::ALPHA_8 },     { PixelFormat::RGB_565, PlPixelFormat::RGB_565 },
    { PixelFormat::RGBA_F16, PlPixelFormat::RGBA_F16 },   { PixelFormat::RGBA_8888, PlPixelFormat::RGBA_8888 },
    { PixelFormat::BGRA_8888, PlPixelFormat::BGRA_8888 }, { PixelFormat::RGB_888, PlPixelFormat::RGB_888 },
    { PixelFormat::NV21, PlPixelFormat::NV21 },           { PixelFormat::NV12, PlPixelFormat::NV12 },
    { PixelFormat::CMYK, PlPixelFormat::CMYK },           { PixelFormat::ASTC_4x4, PlPixelFormat::ASTC_4X4 },
    { PixelFormat::ASTC_6x6, PlPixelFormat::ASTC_6X6 },   { PixelFormat::ASTC_8x8, PlPixelFormat::ASTC_8X8 }
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
const string SVG_FORMAT = "image/svg+xml";
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
static const int DMA_SIZE = 512 * 512 * 4; // DMA limit size
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
static const uint32_t SUT_MAGIC_ID = 0x5CA1AB14;
static const size_t ASTC_HEADER_SIZE = 16;
static const uint8_t ASTC_HEADER_BLOCK_X = 4;
static const uint8_t ASTC_HEADER_BLOCK_Y = 5;
static const uint8_t ASTC_HEADER_DIM_X = 7;
static const uint8_t ASTC_HEADER_DIM_Y = 10;
#ifdef SUT_DECODE_ENABLE
constexpr uint8_t ASTC_HEAD_BYTES = 16;
constexpr uint8_t ASTC_MAGIC_0 = 0x13;
constexpr uint8_t ASTC_MAGIC_1 = 0xAB;
constexpr uint8_t ASTC_MAGIC_2 = 0xA1;
constexpr uint8_t ASTC_MAGIC_3 = 0x5C;
constexpr uint8_t BYTE_POS_0 = 0;
constexpr uint8_t BYTE_POS_1 = 1;
constexpr uint8_t BYTE_POS_2 = 2;
constexpr uint8_t BYTE_POS_3 = 3;
static const std::string g_textureSuperDecSo = "/system/lib64/module/hms/graphic/libtextureSuperDecompress.z.so";

using GetSuperCompressAstcSize = size_t (*)(const uint8_t *, size_t);
using SuperDecompressTexture = bool (*)(const uint8_t *, size_t, uint8_t *, size_t &);

class SutDecSoManager {
public:
    SutDecSoManager();
    ~SutDecSoManager();
    bool LoadSutDecSo();
    GetSuperCompressAstcSize sutDecSoGetSizeFunc_;
    SuperDecompressTexture sutDecSoDecFunc_;
private:
    bool sutDecSoOpened_;
    void *textureDecSoHandle_;
};

static SutDecSoManager g_sutDecSoManager;

SutDecSoManager::SutDecSoManager()
{
    sutDecSoOpened_ = false;
    textureDecSoHandle_ = nullptr;
    sutDecSoGetSizeFunc_ = nullptr;
    sutDecSoDecFunc_ = nullptr;
}

SutDecSoManager::~SutDecSoManager()
{
    if (!sutDecSoOpened_ || textureDecSoHandle_ == nullptr) {
        IMAGE_LOGD("[ImageSource] astcenc dec so is not be opened when dlclose!");
        return;
    }
    if (dlclose(textureDecSoHandle_) != 0) {
        IMAGE_LOGD("[ImageSource] astcenc dlclose failed: %{public}s!", g_textureSuperDecSo.c_str());
        return;
    } else {
        IMAGE_LOGD("[ImageSource] astcenc dlclose success: %{public}s!", g_textureSuperDecSo.c_str());
        return;
    }
}

static bool CheckClBinIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}

bool SutDecSoManager::LoadSutDecSo()
{
    if (!sutDecSoOpened_) {
        if (!CheckClBinIsExist(g_textureSuperDecSo)) {
            IMAGE_LOGE("[ImageSource] %{public}s! is not found", g_textureSuperDecSo.c_str());
            return false;
        }
        textureDecSoHandle_ = dlopen(g_textureSuperDecSo.c_str(), 1);
        if (textureDecSoHandle_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc libtextureSuperDecompress dlopen failed!");
            return false;
        }
        sutDecSoGetSizeFunc_ =
            reinterpret_cast<GetSuperCompressAstcSize>(dlsym(textureDecSoHandle_, "GetSuperCompressAstcSize"));
        if (sutDecSoGetSizeFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetSuperCompressAstcSize dlsym failed!");
            dlclose(textureDecSoHandle_);
            textureDecSoHandle_ = nullptr;
            return false;
        }
        sutDecSoDecFunc_ =
            reinterpret_cast<SuperDecompressTexture>(dlsym(textureDecSoHandle_, "SuperDecompressTexture"));
        if (sutDecSoDecFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc SuperDecompressTexture dlsym failed!");
            dlclose(textureDecSoHandle_);
            textureDecSoHandle_ = nullptr;
            return false;
        }
        IMAGE_LOGD("[ImageSource] astcenc dlopen success: %{public}s!", g_textureSuperDecSo.c_str());
        sutDecSoOpened_ = true;
    }
    return true;
}
#endif

const auto KEY_SIZE = 2;
const static std::string DEFAULT_EXIF_VALUE = "default_exif_value";
const static std::map<std::string, uint32_t> ORIENTATION_INT_MAP = {
    {"Top-left", 0},
    {"Bottom-right", 180},
    {"Right-top", 90},
    {"Left-bottom", 270},
};
const static string IMAGE_DELAY_TIME = "DelayTime";
const static string IMAGE_DISPOSAL_TYPE = "DisposalType";
const static string IMAGE_GIFLOOPCOUNT_TYPE = "GIFLoopCount";
const static int32_t ZERO = 0;

static void UpdatepPlImageInfo(DecodeContext context, bool isHdr, ImagePlugin::PlImageInfo &plInfo);

PluginServer &ImageSource::pluginServer_ = ImageUtils::GetPluginServer();
ImageSource::FormatAgentMap ImageSource::formatAgentMap_ = InitClass();

uint32_t ImageSource::GetSupportedFormats(set<string> &formats)
{
    IMAGE_LOGD("[ImageSource]get supported image type.");
    formats.clear();
    vector<ClassInfo> classInfos;
    uint32_t ret =
        pluginServer_.PluginServerGetClassInfo<AbsImageDecoder>(AbsImageDecoder::SERVICE_DEFAULT, classInfos);
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

unique_ptr<ImageSource> ImageSource::DoImageSourceCreate(std::function<unique_ptr<SourceStream>(void)> stream,
    const SourceOptions &opts, uint32_t &errorCode, const string traceName)
{
    ImageTrace imageTrace(traceName);
    IMAGE_LOGD("[ImageSource]DoImageSourceCreate IN.");
    errorCode = ERR_IMAGE_SOURCE_DATA;
    auto streamPtr = stream();
    if (streamPtr == nullptr) {
        IMAGE_LOGD("[ImageSource]failed to create source stream.");
        ReportCreateImageSourceFault(opts.size.width, opts.size.height, traceName, "stream failed");
        return nullptr;
    }

    auto sourcePtr = new (std::nothrow) ImageSource(std::move(streamPtr), opts);
    if (sourcePtr == nullptr) {
        IMAGE_LOGE("[ImageSource]failed to create ImageSource.");
        ReportCreateImageSourceFault(opts.size.width, opts.size.height, traceName, "failed to create ImageSource");
        return nullptr;
    }
    sourcePtr->SetSource(traceName);
    errorCode = SUCCESS;
    return unique_ptr<ImageSource>(sourcePtr);
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(unique_ptr<istream> is, const SourceOptions &opts,
    uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with stream.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with stream.");
    return DoImageSourceCreate(
        [&is]() {
            auto stream = IstreamSourceStream::CreateSourceStream(move(is));
            if (stream == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create istream source stream.");
            }
            return stream;
        },
        opts, errorCode, "CreateImageSource by istream");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const uint8_t *data, uint32_t size, const SourceOptions &opts,
    uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with buffer.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with buffer.");
    if (data == nullptr || size == 0) {
        IMAGE_LOGE("[ImageSource]parameter error.");
        errorCode = ERR_MEDIA_INVALID_PARAM;
        return nullptr;
    }
    return DoImageSourceCreate(
        [&data, &size]() {
            auto streamPtr = DecodeBase64(data, size);
            if (streamPtr == nullptr) {
                streamPtr = BufferSourceStream::CreateSourceStream(data, size);
            }
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create buffer source stream.");
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by data");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const std::string &pathName, const SourceOptions &opts,
    uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with pathName.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with pathName.");
    if (pathName.size() == SIZE_ZERO) {
        IMAGE_LOGE("[ImageSource]parameter error.");
        return nullptr;
    }
    return DoImageSourceCreate(
        [&pathName]() {
            auto streamPtr = DecodeBase64(pathName);
            if (streamPtr == nullptr) {
                streamPtr = FileSourceStream::CreateSourceStream(pathName);
            }
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create file path source stream. pathName=%{public}s",
                    pathName.c_str());
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by path");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with fd.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with fd.");
    return DoImageSourceCreate(
        [&fd]() {
            auto streamPtr = FileSourceStream::CreateSourceStream(fd);
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create file fd source stream.");
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by fd");
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, int32_t offset, int32_t length,
    const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with fd offset and length.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with offset.");
    return DoImageSourceCreate(
        [&fd, offset, length]() {
            auto streamPtr = FileSourceStream::CreateSourceStream(fd, offset, length);
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create file fd source stream.");
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by fd offset and length");
}

unique_ptr<ImageSource> ImageSource::CreateIncrementalImageSource(const IncrementalSourceOptions &opts,
    uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create incremental ImageSource.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateIncrementalImageSource width = %d, height = %d," \
        "format = %d", opts.sourceOptions.size.width, opts.sourceOptions.size.height, opts.sourceOptions.pixelFormat);
    auto sourcePtr = DoImageSourceCreate(
        [&opts]() {
            auto streamPtr = IncrementalSourceStream::CreateSourceStream(opts.incrementalMode);
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create incremental source stream.");
            }
            return streamPtr;
        },
        opts.sourceOptions, errorCode, "CreateImageSource by fd");
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
    IMAGE_LOGD("CreatePixelMapEx imageId_: %{public}lu, desiredPixelFormat: %{public}d,"
        "desiredSize: (%{public}d, %{public}d)",
        static_cast<unsigned long>(imageId_), opts.desiredPixelFormat, opts.desiredSize.width, opts.desiredSize.height);

#if !defined(ANDROID_PLATFORM) || !defined(IOS_PLATFORM)
    if (!isAstc_.has_value()) {
        ImagePlugin::DataStreamBuffer outData;
        uint32_t res = GetData(outData, ASTC_HEADER_SIZE);
        if (res == SUCCESS) {
            isAstc_ = IsASTC(outData.inputStreamBuffer, outData.dataSize);
        }
    }
    if (isAstc_.has_value() && isAstc_.value()) {
        return CreatePixelMapForASTC(errorCode, opts.fastAstc);
    }
#endif

    if (IsSpecialYUV()) {
        return CreatePixelMapForYUV(errorCode);
    }

    DumpInputData();
    return CreatePixelMap(index, opts, errorCode);
}

static bool IsExtendedCodec(AbsImageDecoder *decoder)
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

void ImageSource::TransformSizeWithDensity(const Size &srcSize, int32_t srcDensity, const Size &wantSize,
    int32_t wantDensity, Size &dstSize)
{
    if (IsSizeVailed(wantSize) && ((opts_.resolutionQuality == ResolutionQuality::LOW) ||
                                    (opts_.resolutionQuality == ResolutionQuality::MEDIUM))) {
        CopySize(wantSize, dstSize);
    } else {
        CopySize(srcSize, dstSize);
    }

    if (IsDensityChange(srcDensity, wantDensity)) {
        dstSize.width = GetScalePropByDensity(dstSize.width, srcDensity, wantDensity);
        dstSize.height = GetScalePropByDensity(dstSize.height, srcDensity, wantDensity);
    }
}

static void NotifyDecodeEvent(set<DecodeListener *> &listeners, DecodeEvent event, std::unique_lock<std::mutex> *guard)
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

static void ContextToAddrInfos(DecodeContext &context, PixelMapAddrInfos &addrInfos)
{
    addrInfos.addr = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    addrInfos.context = static_cast<uint8_t *>(context.pixelsBuffer.context);
    addrInfos.size = context.pixelsBuffer.bufferSize;
    addrInfos.type = context.allocatorType;
    addrInfos.func = context.freeFunc;
}

bool IsSupportFormat(const PixelFormat &format)
{
    return format == PixelFormat::UNKNOWN || format == PixelFormat::RGBA_8888;
}

bool IsSupportSize(const Size &size)
{
    // Check for overflow risk
    if (size.width > 0 && size.height > INT_MAX / size.width) {
        return false;
    }
    return size.width * size.height >= DMA_SIZE;
}

bool IsWidthAligned(const int32_t &width)
{
    return ((width * NUM_4) & INT_255) == 0;
}

bool IsPhotosLcd()
{
    static bool isPhotos = ImageSystemProperties::IsPhotos();
    return isPhotos;
}

bool IsSupportDma(const DecodeOptions &opts, const ImageInfo &info, bool hasDesiredSizeOptions)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
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
            (IsWidthAligned(opts.desiredSize.width)
            || opts.preferDma
            || IsPhotosLcd());
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

unique_ptr<PixelMap> ImageSource::CreatePixelMapExtended(uint32_t index, const DecodeOptions &opts, uint32_t &errorCode)
{
    ImageEvent imageEvent;
    ImageDataStatistics imageDataStatistics("[ImageSource] CreatePixelMapExtended.");
    uint64_t decodeStartTime = GetNowTimeMicroSeconds();
    opts_ = opts;
    ImageInfo info;
    errorCode = GetImageInfo(FIRST_FRAME, info);
    SetDecodeInfoOptions(index, opts, info, imageEvent);
    ImageTrace imageTrace("CreatePixelMapExtended, info.size:(%d, %d)", info.size.width, info.size.height);
    if (errorCode != SUCCESS || !IsSizeVailed(info.size)) {
        IMAGE_LOGE("[ImageSource]get image info failed, ret:%{public}u.", errorCode);
        imageEvent.SetDecodeErrorMsg("get image info failed, ret:" + std::to_string(errorCode));
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return nullptr;
    }
    ImagePlugin::PlImageInfo plInfo;
    DecodeContext context = DecodeImageDataToContextExtended(index, info, plInfo, imageEvent, errorCode);
    imageDataStatistics.AddTitle("imageSize: [%d, %d], desireSize: [%d, %d], imageFormat: %s, desirePixelFormat: %d,"
        "memorySize: %d, memoryType: %d", info.size.width, info.size.height, opts.desiredSize.width,
        opts.desiredSize.height, sourceInfo_.encodedFormat.c_str(), opts.desiredPixelFormat,
        context.pixelsBuffer.bufferSize, context.allocatorType);
    imageDataStatistics.SetRequestMemory(context.pixelsBuffer.bufferSize);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decode source fail, ret:%{public}u.", errorCode);
        imageEvent.SetDecodeErrorMsg("decode source fail, ret:" + std::to_string(errorCode));
        return nullptr;
    }
    bool isHdr = context.hdrType > Media::ImageHdrType::SDR;
    auto res = ImageAiProcess(info.size, opts, isHdr, context);
    if (res != SUCCESS) {
        IMAGE_LOGD("[ImageSource] ImageAiProcess fail, isHdr%{public}d, ret:%{public}u.", isHdr, res);
    }
    UpdatepPlImageInfo(context, isHdr, plInfo);

    auto pixelMap = CreatePixelMapByInfos(plInfo, context, errorCode);
    if (pixelMap == nullptr) {
        return nullptr;
    }
    if (!context.ifPartialOutput) {
        NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_COMPLETE_DECODE, nullptr);
    }
    if ("image/gif" != sourceInfo_.encodedFormat) {
        IMAGE_LOGD("CreatePixelMapExtended success, imageId:%{public}lu, desiredSize: (%{public}d, %{public}d),"
            "imageSize: (%{public}d, %{public}d), hdrType : %{public}d, cost %{public}lu us",
            static_cast<unsigned long>(imageId_), opts.desiredSize.width, opts.desiredSize.height, info.size.width,
            info.size.height, context.hdrType, static_cast<unsigned long>(GetNowTimeMicroSeconds() - decodeStartTime));
    }

    if (CreatExifMetadataByImageSource() == SUCCESS) {
        auto metadataPtr = exifMetadata_->Clone();
        pixelMap->SetExifMetadata(metadataPtr);
    }
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

// add graphic colorspace object to pixelMap.
static void SetPixelMapColorSpace(ImagePlugin::DecodeContext context, unique_ptr<PixelMap>& pixelMap,
    std::unique_ptr<ImagePlugin::AbsImageDecoder>& decoder)
{
#ifdef IMAGE_COLORSPACE_FLAG
    if (context.hdrType > ImageHdrType::SDR) {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(context.grColorSpaceName));
        return ;
    }
    bool isSupportICCProfile = decoder->IsSupportICCProfile();
    if (isSupportICCProfile) {
        OHOS::ColorManager::ColorSpace grColorSpace = decoder->getGrColorSpace();
        pixelMap->InnerSetColorSpace(grColorSpace);
    }
#endif
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapByInfos(ImagePlugin::PlImageInfo &plInfo,
    ImagePlugin::DecodeContext& context, uint32_t &errorCode)
{
    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
    PixelMapAddrInfos addrInfos;
    ContextToAddrInfos(context, addrInfos);
    // add graphic colorspace object to pixelMap.
    SetPixelMapColorSpace(context, pixelMap, mainDecoder_);
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
    if (!mainDecoder_->HasProperty(SUPPORT_CROP_KEY) && opts_.CropRect.width > INT_ZERO &&
        opts_.CropRect.height > INT_ZERO) {
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
    if ((opts_.desiredSize.height != pixelMap->GetHeight() || opts_.desiredSize.width != pixelMap->GetWidth()) &&
        (context.hdrType < ImageHdrType::HDR_ISO_DUAL) && !context.isAisr) {
        float xScale = static_cast<float>(opts_.desiredSize.width) / pixelMap->GetWidth();
        float yScale = static_cast<float>(opts_.desiredSize.height) / pixelMap->GetHeight();
        if (!pixelMap->resize(xScale, yScale)) {
            return nullptr;
        }
        // dump pixelMap after resize
        ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId_);
    }
    pixelMap->SetEditable(saveEditable);
    return pixelMap;
}

void ImageSource::SetDecodeInfoOptions(uint32_t index, const DecodeOptions &opts, const ImageInfo &info,
    ImageEvent &imageEvent)
{
    DecodeInfoOptions options;
    options.sampleSize = opts.sampleSize;
    options.rotate = opts.rotateDegrees;
    options.editable = opts.editable;
    options.sourceWidth = info.size.width;
    options.sourceHeight = info.size.height;
    options.desireSizeWidth = opts.desiredSize.width;
    options.desireSizeHeight = opts.desiredSize.height;
    options.desireRegionWidth = opts.CropRect.width;
    options.desireRegionHeight = opts.CropRect.height;
    options.desireRegionX = opts.CropRect.left;
    options.desireRegionY = opts.CropRect.top;
    options.desirePixelFormat = static_cast<int32_t>(opts.desiredPixelFormat);
    options.index = index;
    options.fitDensity = opts.fitDensity;
    options.desireColorSpace = static_cast<int32_t>(opts.desiredColorSpace);
    options.mimeType = sourceInfo_.encodedFormat;
    options.invokeType = opts.invokeType;
    options.imageSource = source_;
    imageEvent.SetDecodeInfoOptions(options);
}

void ImageSource::SetDecodeInfoOptions(uint32_t index, const DecodeOptions &opts,
    const ImagePlugin::PlImageInfo &plInfo, ImageEvent &imageEvent)
{
    DecodeInfoOptions options;
    options.sampleSize = opts.sampleSize;
    options.rotate = opts.rotateDegrees;
    options.editable = opts.editable;
    options.sourceWidth = plInfo.size.width;
    options.sourceHeight = plInfo.size.height;
    options.desireSizeWidth = opts.desiredSize.width;
    options.desireSizeHeight = opts.desiredSize.height;
    options.desireRegionWidth = opts.CropRect.width;
    options.desireRegionHeight = opts.CropRect.height;
    options.desireRegionX = opts.CropRect.left;
    options.desireRegionY = opts.CropRect.top;
    options.desirePixelFormat = static_cast<int32_t>(opts.desiredPixelFormat);
    options.index = index;
    options.fitDensity = opts.fitDensity;
    options.desireColorSpace = static_cast<int32_t>(opts.desiredColorSpace);
    options.mimeType = sourceInfo_.encodedFormat;
    options.invokeType = opts.invokeType;
    options.imageSource = source_;
    imageEvent.SetDecodeInfoOptions(options);
}

void ImageSource::UpdateDecodeInfoOptions(const ImagePlugin::DecodeContext &context, ImageEvent &imageEvent)
{
    DecodeInfoOptions &options = imageEvent.GetDecodeInfoOptions();
    options.memorySize = context.pixelsBuffer.bufferSize;
    options.memoryType = static_cast<int32_t>(context.allocatorType);
    options.isHardDecode = context.isHardDecode;
    options.hardDecodeError = context.hardDecodeError;
}

void ImageSource::SetImageEventHeifParseErr(ImageEvent &event)
{
    if (heifParseErr_ == 0) {
        return;
    }
    event.GetDecodeInfoOptions().isHardDecode = true;
    event.GetDecodeInfoOptions().hardDecodeError
        = std::string("parse heif file failed, err: ") + std::to_string(heifParseErr_);
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
        ImageEvent imageEvent;
        imageEvent.SetDecodeErrorMsg("[ImageSource]get valid image status fail on create pixel map, ret: "
                                     + std::to_string(errorCode));
        SetImageEventHeifParseErr(imageEvent);
        return nullptr;
    }
    if (ImageSystemProperties::GetSkiaEnabled()) {
        if (IsExtendedCodec(mainDecoder_.get())) {
            guard.unlock();
            return CreatePixelMapExtended(index, opts, errorCode);
        }
    }

    ImageEvent imageEvent;
    if (opts.desiredPixelFormat == PixelFormat::NV12 || opts.desiredPixelFormat == PixelFormat::NV21) {
        IMAGE_LOGE("[ImageSource] get YUV420 not support without going through CreatePixelMapExtended");
        imageEvent.SetDecodeErrorMsg("get YUV420 not support without going through CreatePixelMapExtended");
        return nullptr;
    }
    // the mainDecoder_ may be borrowed by Incremental decoding, so needs to be checked.
    if (InitMainDecoder() != SUCCESS) {
        IMAGE_LOGE("[ImageSource]image decode plugin is null.");
        imageEvent.SetDecodeErrorMsg("image decode plugin is null.");
        errorCode = ERR_IMAGE_PLUGIN_CREATE_FAILED;
        return nullptr;
    }
    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
    if (pixelMap == nullptr || pixelMap.get() == nullptr) {
        IMAGE_LOGE("[ImageSource]create the pixel map unique_ptr fail.");
        imageEvent.SetDecodeErrorMsg("create the pixel map unique_ptr fail.");
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }

    ImagePlugin::PlImageInfo plInfo;
    errorCode = SetDecodeOptions(mainDecoder_, index, opts_, plInfo);
    SetDecodeInfoOptions(index, opts, plInfo, imageEvent);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]set decode options error (index:%{public}u), ret:%{public}u.", index, errorCode);
        imageEvent.SetDecodeErrorMsg("set decode options error, ret:." + std::to_string(errorCode));
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
        imageEvent.SetDecodeErrorMsg("update pixelmap info error, ret:." + std::to_string(errorCode));
        return nullptr;
    }

    DecodeContext context;
    FinalOutputStep finalOutputStep = FinalOutputStep::NO_CHANGE;
    context.pixelmapUniqueId_ = pixelMap->GetUniqueId();
    if (!useSkia) {
        bool hasNinePatch = mainDecoder_->HasProperty(NINE_PATCH);
        finalOutputStep = GetFinalOutputStep(opts_, *(pixelMap.get()), hasNinePatch);
        IMAGE_LOGD("[ImageSource]finalOutputStep:%{public}d. opts.allocatorType %{public}d", finalOutputStep,
            opts_.allocatorType);

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
    UpdateDecodeInfoOptions(context, imageEvent);
    if (!useSkia) {
        ninePatchInfo_.ninePatch = context.ninePatchContext.ninePatch;
        ninePatchInfo_.patchSize = context.ninePatchContext.patchSize;
    }
    guard.unlock();
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decode source fail, ret:%{public}u.", errorCode);
        imageEvent.SetDecodeErrorMsg("decode source fail, ret:." + std::to_string(errorCode));
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

    if (CreatExifMetadataByImageSource() == SUCCESS) {
        auto metadataPtr = exifMetadata_->Clone();
        pixelMap->SetExifMetadata(metadataPtr);
    }

    // not ext decode, dump pixelMap while decoding svg here
    ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId_);
    return pixelMap;
}

unique_ptr<IncrementalPixelMap> ImageSource::CreateIncrementalPixelMap(uint32_t index, const DecodeOptions &opts,
    uint32_t &errorCode)
{
    ImageDataStatistics imageDataStatistics("[ImageSource] CreateIncrementalPixelMap width = %d, height = %d," \
        "pixelformat = %d", opts.desiredSize.width, opts.desiredSize.height, opts.desiredPixelFormat);
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
            IMAGE_LOGE("[ImageSource]set decode options error (image index:%{public}u), ret:%{public}u.", index, ret);
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
            IMAGE_LOGE("[ImageSource]update pixelmap info error (image index:%{public}u), ret:%{public}u.", index, ret);
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
    ImageDataStatistics imageDataStatistics("[ImageSource]UpdateData");
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
            "height:%{public}d.",
            info.size.width, info.size.height);
        return ERR_IMAGE_DECODE_FAILED;
    }
    imageInfo = info;
    return SUCCESS;
}

uint32_t ImageSource::ModifyImageProperty(const std::string &key, const std::string &value)
{
    uint32_t ret = CreatExifMetadataByImageSource(true);
    if (ret != SUCCESS) {
        IMAGE_LOGD("Failed to create Exif metadata "
            "when attempting to modify property.");
        return ret;
    }

    if (!exifMetadata_->SetValue(key, value)) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    return SUCCESS;
}

uint32_t ImageSource::ModifyImageProperty(std::shared_ptr<MetadataAccessor> metadataAccessor,
    const std::string &key, const std::string &value)
{
    uint32_t ret = ModifyImageProperty(key, value);
    if (ret != SUCCESS) {
        IMAGE_LOGE("Failed to create ExifMetadata.");
        return ret;
    }

    if (metadataAccessor == nullptr) {
        IMAGE_LOGE("Failed to create image accessor when attempting to modify image property.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    metadataAccessor->Set(exifMetadata_);
    return metadataAccessor->Write();
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    return ModifyImageProperty(key, value);
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
    const std::string &path)
{
    ImageDataStatistics imageDataStatistics("[ImageSource]ModifyImageProperty by path.");

#if !defined(IOS_PLATFORM)
    if (!std::filesystem::exists(path)) {
        return ERR_IMAGE_SOURCE_DATA;
    }
#endif

    std::unique_lock<std::mutex> guard(decodingMutex_);
    auto metadataAccessor = MetadataAccessorFactory::Create(path);
    return ModifyImageProperty(metadataAccessor, key, value);
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
    const int fd)
{
    ImageDataStatistics imageDataStatistics("[ImageSource]ModifyImageProperty by fd.");
    if (fd <= STDERR_FILENO) {
        IMAGE_LOGD("Invalid file descriptor.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    std::unique_lock<std::mutex> guard(decodingMutex_);

    auto metadataAccessor = MetadataAccessorFactory::Create(fd);
    return ModifyImageProperty(metadataAccessor, key, value);
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
    uint8_t *data, uint32_t size)
{
    return ERR_MEDIA_WRITE_PARCEL_FAIL;
}

uint32_t ImageSource::CreatExifMetadataByImageSource(bool addFlag)
{
    IMAGE_LOGD("CreatExifMetadataByImageSource");
    if (exifMetadata_ != nullptr) {
        IMAGE_LOGD("exifMetadata_ exist return SUCCESS");
        return SUCCESS;
    }

    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGD("sourceStreamPtr_ not exist return ERR");
        return ERR_IMAGE_SOURCE_DATA;
    }

    IMAGE_LOGD("sourceStreamPtr create metadataACCessor");
    uint32_t bufferSize = sourceStreamPtr_->GetStreamSize();
    auto bufferPtr = sourceStreamPtr_->GetDataPtr();
    if (bufferPtr != nullptr) {
        return SetExifMetadata(bufferPtr, bufferSize, addFlag);
    }

    uint32_t readSize = 0;
    if (bufferSize == 0) {
        IMAGE_LOGE("Invalid buffer size. It's zero. Please check the buffer size.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    
    if (bufferSize > MAX_BUFFER_SIZE) {
        IMAGE_LOGE("Invalid buffer size. It's too big. Please check the buffer size.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    uint8_t* tmpBuffer = new (std::nothrow) uint8_t[bufferSize];
    if (tmpBuffer == nullptr) {
        IMAGE_LOGE("Allocate buffer failed, tmpBuffer is nullptr.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    uint32_t savedPosition = sourceStreamPtr_->Tell();
    sourceStreamPtr_->Seek(0);
    bool retRead = sourceStreamPtr_->Read(bufferSize, tmpBuffer, bufferSize, readSize);
    sourceStreamPtr_->Seek(savedPosition);
    if (!retRead) {
        IMAGE_LOGE("sourceStream read failed.");
        delete[] tmpBuffer; // Don't forget to delete tmpBuffer if read failed
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint32_t result = SetExifMetadata(tmpBuffer, bufferSize, addFlag);
    delete[] tmpBuffer; // Don't forget to delete tmpBuffer after using it
    return result;
}
uint32_t ImageSource::SetExifMetadata(uint8_t *buffer, const uint32_t size, bool addFlag)
{
    auto metadataAccessor = MetadataAccessorFactory::Create(buffer, size);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGD("metadataAccessor nullptr return ERR");
        return ERR_IMAGE_SOURCE_DATA;
    }

    uint32_t ret = metadataAccessor->Read();
    if (ret != SUCCESS && !addFlag) {
        IMAGE_LOGD("get metadataAccessor ret %{public}d", ret);
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    if (metadataAccessor->Get() == nullptr) {
        if (!metadataAccessor->Create()) {
            IMAGE_LOGD("metadataAccessor create failed.");
            return ERR_IMAGE_SOURCE_DATA;
        }
    }

    exifMetadata_ = metadataAccessor->Get();
    return SUCCESS;
}

uint32_t ImageSource::GetImagePropertyCommon(uint32_t index, const std::string &key, std::string &value)
{
    if (isExifReadFailed && exifMetadata_ == nullptr) {
        IMAGE_LOGD("There is no exif in picture!");
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    uint32_t ret = CreatExifMetadataByImageSource();
    if (ret != SUCCESS) {
        if (key.substr(0, KEY_SIZE) == "Hw") {
            value = DEFAULT_EXIF_VALUE;
            return SUCCESS;
        }
        IMAGE_LOGD("Failed to create Exif metadata "
            "when attempting to get property.");
        isExifReadFailed = true;
        return ret;
    }

    return exifMetadata_->GetValue(key, value);
}

uint32_t ImageSource::GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);

    if (key.empty()) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    // keep aline with previous logical for delay time and disposal type
    if (IMAGE_DELAY_TIME.compare(key) == ZERO || IMAGE_DISPOSAL_TYPE.compare(key) == ZERO) {
        IMAGE_LOGD("GetImagePropertyInt special key: %{public}s", key.c_str());
        uint32_t ret = mainDecoder_->GetImagePropertyInt(index, key, value);
        return ret;
    }
    std::string strValue;
    uint32_t ret = GetImagePropertyCommon(index, key, strValue);
    if (key == "Orientation") {
        if (ORIENTATION_INT_MAP.count(strValue) == 0) {
            IMAGE_LOGD("ORIENTATION_INT_MAP not find %{public}s", strValue.c_str());
            return ERR_IMAGE_SOURCE_DATA;
        }
        strValue = std::to_string(ORIENTATION_INT_MAP.at(strValue));
    }
    IMAGE_LOGD("convert string to int %{public}s", strValue.c_str());
    std::from_chars_result res = std::from_chars(strValue.data(), strValue.data() + strValue.size(), value);
    if (res.ec != std::errc()) {
        IMAGE_LOGD("convert string to int failed");
        return ERR_IMAGE_SOURCE_DATA;
    }

    return ret;
}

uint32_t ImageSource::GetImagePropertyString(uint32_t index, const std::string &key, std::string &value)
{
    if (key.empty()) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }
    uint32_t ret = SUCCESS;
    if (IMAGE_GIFLOOPCOUNT_TYPE.compare(key) == ZERO) {
        IMAGE_LOGD("GetImagePropertyString special key: %{public}s", key.c_str());
        (void)GetFrameCount(ret);
        if (ret != SUCCESS || mainDecoder_ == nullptr) {
            IMAGE_LOGE("[ImageSource]GetFrameCount get frame sum error.");
            return ret;
        } else {
            ret = mainDecoder_->GetImagePropertyString(index, key, value);
            if (ret != SUCCESS) {
                IMAGE_LOGE("[ImageSource]GetLoopCount get loop count issue. errorCode=%{public}u", ret);
                return ret;
            }
        }
        return ret;
    }

    std::unique_lock<std::mutex> guard(decodingMutex_);
    return GetImagePropertyCommon(index, key, value);
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
        IMAGE_LOGE("Attempted to remove a null listener "
            "from decode listeners.");
        return;
    }
    std::lock_guard<std::mutex> guard(listenerMutex_);
    auto iter = decodeListeners_.find(listener);
    if (iter != decodeListeners_.end()) {
        decodeListeners_.erase(iter);
    }
}

ImageSource::~ImageSource() __attribute__((no_sanitize("cfi")))
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

bool ImageSource::IsHdrImage()
{
    if (sourceHdrType_ != ImageHdrType::UNKNOWN) {
        return sourceHdrType_ > ImageHdrType::SDR;
    }

    if (InitMainDecoder() != SUCCESS) {
        return false;
    }
    sourceHdrType_ = mainDecoder_->CheckHdrType();
    return sourceHdrType_ > ImageHdrType::SDR;
}

uint32_t ImageSource::RemoveImageProperties(uint32_t index, const std::set<std::string> &keys, const std::string &path)
{
#if !defined(IOS_PLATFORM)
    if (!std::filesystem::exists(path)) {
        return ERR_IMAGE_SOURCE_DATA;
    }
#endif

    std::unique_lock<std::mutex> guard(decodingMutex_);
    auto metadataAccessor = MetadataAccessorFactory::Create(path);
    return RemoveImageProperties(metadataAccessor, keys);
}

uint32_t ImageSource::RemoveImageProperties(uint32_t index, const std::set<std::string> &keys, const int fd)
{
    if (fd <= STDERR_FILENO) {
        return ERR_IMAGE_SOURCE_DATA;
    }

    std::unique_lock<std::mutex> guard(decodingMutex_);
    auto metadataAccessor = MetadataAccessorFactory::Create(fd);
    return RemoveImageProperties(metadataAccessor, keys);
}

uint32_t ImageSource::RemoveImageProperties(uint32_t index, const std::set<std::string> &keys,
                                            uint8_t *data, uint32_t size)
{
    return ERR_MEDIA_WRITE_PARCEL_FAIL;
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

    // use format hint in svg format for the performance purpose
    if (opts.formatHint == InnerFormat::SVG_FORMAT) {
        sourceInfo_.encodedFormat = opts.formatHint;
        sourceOptions_.formatHint = opts.formatHint;
    }
    imageId_ = GetNowTimeMicroSeconds();
    sourceHdrType_ = ImageHdrType::UNKNOWN;
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

uint32_t ImageSource::GetData(ImagePlugin::DataStreamBuffer &outData, size_t size) __attribute__((no_sanitize("cfi")))
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

AbsImageDecoder *DoCreateDecoder(std::string codecFormat, PluginServer &pluginServer, InputDataStream &sourceData,
    uint32_t &errorCode) __attribute__((no_sanitize("cfi")))
{
    map<string, AttrData> capabilities = { { IMAGE_ENCODE_FORMAT, AttrData(codecFormat) } };
    for (const auto &capability : capabilities) {
        std::string x = "undefined";
        capability.second.GetValue(x);
        IMAGE_LOGD("[ImageSource] capabilities [%{public}s],[%{public}s]", capability.first.c_str(), x.c_str());
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
        IMAGE_LOGE("Source stream pointer is null.");
        return ERR_MEDIA_NULL_POINTER;
    }

    auto imageType = sourceStreamPtr_->Tell();
    uint32_t errorCode = ERR_IMAGE_DECODE_ABNORMAL;
    auto codec = DoCreateDecoder(InnerFormat::IMAGE_EXTENDED_CODEC, pluginServer_, *sourceStreamPtr_, errorCode);
    if (errorCode != SUCCESS || codec == nullptr) {
        IMAGE_LOGE("No extended decoder available.");
        return errorCode;
    }
    const static string EXT_ENCODED_FORMAT_KEY = "EncodedFormat";
    auto decoderPtr = unique_ptr<AbsImageDecoder>(codec);
    if (decoderPtr == nullptr) {
        IMAGE_LOGE("Decoder pointer is null.");
        return ERR_MEDIA_NULL_POINTER;
    }
    ProgDecodeContext context;
    if (IsIncrementalSource() &&
        decoderPtr->PromoteIncrementalDecode(UINT32_MAX, context) == ERR_IMAGE_DATA_UNSUPPORT) {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    errorCode = decoderPtr->GetImagePropertyString(FIRST_FRAME, EXT_ENCODED_FORMAT_KEY, format);
    if (errorCode != SUCCESS) {
        if (decoderPtr->GetHeifParseErr() != 0) {
            heifParseErr_ = decoderPtr->GetHeifParseErr();
        }
        IMAGE_LOGE("Failed to get extended format. Error code: %{public}d.", errorCode);
        return ERR_IMAGE_DECODE_HEAD_ABNORMAL;
    }

    if (!ImageSystemProperties::GetSkiaEnabled()) {
        IMAGE_LOGD("Extended SK decode is closed.");
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
            continue; // has been checked before.
        }
        AbsImageFormatAgent *agent = iter->second;
        ret = CheckEncodedFormat(*agent);
        if (ret == ERR_IMAGE_MISMATCHED_FORMAT) {
            continue;
        } else if (ret == SUCCESS) {
            IMAGE_LOGD("[ImageSource]GetEncodedFormat success format :%{public}s.", iter->first.c_str());
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
            IMAGE_LOGD("[ImageSource]source error.");
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
            imageStatus.imageInfo.encodedFormat = sourceInfo_.encodedFormat;
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
        imageStatus.imageInfo.encodedFormat = sourceInfo_.encodedFormat;
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
        status.imageInfo.encodedFormat = "none";
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

static void GetDefaultPixelFormat(const PixelFormat desired, PlPixelFormat &out, MemoryUsagePreference preference)
{
    if (desired != PixelFormat::UNKNOWN) {
        auto formatPair = PIXEL_FORMAT_MAP.find(desired);
        if (formatPair != PIXEL_FORMAT_MAP.end() && formatPair->second != PlPixelFormat::UNKNOWN) {
            out = formatPair->second;
            return;
        }
    }
    out = (preference == MemoryUsagePreference::LOW_RAM) ? PlPixelFormat::RGB_565 : PlPixelFormat::RGBA_8888;
}

uint32_t ImageSource::SetDecodeOptions(std::unique_ptr<AbsImageDecoder> &decoder, uint32_t index,
    const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo)
{
    PlPixelFormat plDesiredFormat;
    GetDefaultPixelFormat(opts.desiredPixelFormat, plDesiredFormat, preference_);
    PixelDecodeOptions plOptions;
    CopyOptionsToPlugin(opts, plOptions);
    plOptions.desiredPixelFormat = plDesiredFormat;
    if (IsHdrImage() && opts.desiredDynamicRange != DecodeDynamicRange::SDR) {
        plOptions.desiredPixelFormat = PlPixelFormat::RGBA_8888;
    }
    uint32_t ret = decoder->SetDecodeOptions(index, plOptions, plInfo);
    if (ret != SUCCESS) {
        IMAGE_LOGE("[ImageSource]decoder plugin set decode options fail (image index:%{public}u),"
            "ret:%{public}u.",
            index, ret);
        return ret;
    }
    auto iter = imageStatusMap_.find(index);
    if (iter != imageStatusMap_.end()) {
        ImageInfo &info = (iter->second).imageInfo;
        IMAGE_LOGD("[ImageSource]SetDecodeOptions plInfo.pixelFormat %{public}d", plInfo.pixelFormat);

        PlPixelFormat format = plInfo.pixelFormat;
        auto find_item = std::find_if(PIXEL_FORMAT_MAP.begin(), PIXEL_FORMAT_MAP.end(),
            [format](const std::map<PixelFormat, PlPixelFormat>::value_type item) { return item.second == format; });
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
    info.encodedFormat = sourceInfo_.encodedFormat;

    if (info.pixelFormat == PixelFormat::NV12 || info.pixelFormat == PixelFormat::NV21) {
        YUVDataInfo yuvInfo;
        yuvInfo.y_width = plInfo.yuvDataInfo.y_width;
        yuvInfo.y_height = plInfo.yuvDataInfo.y_height;
        yuvInfo.uv_width = plInfo.yuvDataInfo.uv_width;
        yuvInfo.uv_height = plInfo.yuvDataInfo.uv_height;
        yuvInfo.y_stride = plInfo.yuvDataInfo.y_stride;
        yuvInfo.u_stride = plInfo.yuvDataInfo.u_stride;
        yuvInfo.v_stride = plInfo.yuvDataInfo.v_stride;
        yuvInfo.uv_stride = plInfo.yuvDataInfo.uv_stride;
        pixelMap.SetImageYUVInfo(yuvInfo);
    }

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
    if (opts.SVGOpts.strokeColor.isValidColor) {
        plOpts.plStrokeColor.isValidColor = opts.SVGOpts.strokeColor.isValidColor;
        plOpts.plStrokeColor.color = opts.SVGOpts.strokeColor.color;
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
    ImageEvent imageEvent;
    imageEvent.SetIncrementalDecode();
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
        imageEvent.SetDecodeErrorMsg("do incremental decoding source fail, ret:" + std::to_string(ret));
        return ret;
    }
    if (ret == SUCCESS) {
        recordContext.IncrementalState = ImageDecodingState::IMAGE_DECODED;
        IMAGE_LOGD("[ImageSource]do incremental decoding success.");
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
    bool sizeChange =
        ImageSizeChange(pixelMap.GetWidth(), pixelMap.GetHeight(), opts.desiredSize.width, opts.desiredSize.height);
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
    return !hasNinePatch && (srcImageInfo.baseDensity > 0) && (opts.fitDensity > 0) &&
        (srcImageInfo.baseDensity != opts.fitDensity);
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
            "width:%{public}d, height:%{public}d",
            cropRect.top, cropRect.left, cropRect.width, cropRect.height);
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
    const char *data1 = reinterpret_cast<const char *>(data);
    auto sub = ::strstr(data1, BASE64_URL_PREFIX.c_str());
    if (sub == nullptr) {
        IMAGE_LOGI("[ImageSource]Base64 mismatch.");
        return nullptr;
    }
    sub = sub + BASE64_URL_PREFIX.size();
    uint32_t subSize = size - (sub - data1);
    IMAGE_LOGD("[ImageSource]Base64 image input: %{public}p, data: %{public}p, size %{public}u.", data, sub, subSize);
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
    auto imageData = static_cast<const uint8_t *>(resData->data());
    return BufferSourceStream::CreateSourceStream(imageData, resData->size());
#else
    SkBase64 base64Decoder;
    if (base64Decoder.decode(sub, subSize) != SkBase64::kNoError) {
        IMAGE_LOGE("[ImageSource]base64 image decode failed!");
        return nullptr;
    }
    auto base64Data = base64Decoder.getData();
    const uint8_t *imageData = reinterpret_cast<uint8_t *>(base64Data);
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
    return DecodeBase64(reinterpret_cast<const uint8_t *>(data.c_str()), data.size());
}

bool ImageSource::IsSpecialYUV()
{
    const bool isBufferSource =
        (sourceStreamPtr_ != nullptr) && (sourceStreamPtr_->GetStreamType() == ImagePlugin::BUFFER_SOURCE_TYPE);
    const bool isSizeValid = (sourceOptions_.size.width > 0) && (sourceOptions_.size.height > 0);
    const bool isYUV =
        (sourceOptions_.pixelFormat == PixelFormat::NV12) || (sourceOptions_.pixelFormat == PixelFormat::NV21);
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

bool ImageSource::ConvertYUV420ToRGBA(uint8_t *data, uint32_t size, bool isSupportOdd, bool isAddUV,
    uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]ConvertYUV420ToRGBA IN srcPixelFormat:%{public}d, srcSize:(%{public}d,"
        "%{public}d)",
        sourceOptions_.pixelFormat, sourceOptions_.size.width, sourceOptions_.size.height);
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
        "width:(%{public}zu, %{public}zu)",
        ubase, vbase, width, uvwidth);

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
    IMAGE_LOGD("Starting the creation of PixelMap for YUV. Source pixel format: %{public}d, "
        "Source size: (%{public}d, %{public}d)",
        sourceOptions_.pixelFormat, sourceOptions_.size.width, sourceOptions_.size.height);
    DumpInputData("yuv");

    unique_ptr<PixelMap> pixelMap = make_unique<PixelMap>();
    if (pixelMap == nullptr) {
        IMAGE_LOGE("Failed to create the pixel map unique_ptr.");
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
        IMAGE_LOGE("Error updating pixelmap info. Return code: %{public}u.", errorCode);
        return nullptr;
    }

    size_t bufferSize = static_cast<size_t>(pixelMap->GetWidth() * pixelMap->GetHeight() * pixelMap->GetPixelBytes());
    auto buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        IMAGE_LOGE("Failed to allocate memory of size %{public}zu", bufferSize);
        errorCode = ERR_IMAGE_MALLOC_ABNORMAL;
        return nullptr;
    }

    pixelMap->SetEditable(false);
    pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize, AllocatorType::HEAP_ALLOC, nullptr);

    if (!ConvertYUV420ToRGBA(static_cast<uint8_t *>(buffer), bufferSize, false, false, errorCode)) {
        IMAGE_LOGE("Issue converting yuv420 to rgba, errorCode=%{public}u", errorCode);
        errorCode = ERROR;
        return nullptr;
    }

    IMAGE_LOGD("CreatePixelMapForYUV operation completed.");

    if (CreatExifMetadataByImageSource() == SUCCESS) {
        auto metadataPtr = exifMetadata_->Clone();
        pixelMap->SetExifMetadata(metadataPtr);
    }

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
    return ((magicVal == ASTC_MAGIC_ID) || (magicVal == SUT_MAGIC_ID));
}

bool ImageSource::GetImageInfoForASTC(ImageInfo &imageInfo)
{
    ASTCInfo astcInfo;
    if (!sourceStreamPtr_) {
        IMAGE_LOGE("[ImageSource] get astc image info null.");
        return false;
    }
    if (!GetASTCInfo(sourceStreamPtr_->GetStreamType() == ImagePlugin::FILE_STREAM_TYPE ?
        sourceStreamPtr_->GetDataPtr(true) : sourceStreamPtr_->GetDataPtr(),
        sourceStreamPtr_->GetStreamSize(), astcInfo)) {
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

#ifdef SUT_DECODE_ENABLE
static size_t GetAstcSizeBytes(const uint8_t *fileBuf, size_t fileSize)
{
    if ((fileBuf == nullptr) || (fileSize <= ASTC_HEAD_BYTES)) {
        IMAGE_LOGE("astc GetAstcSizeBytes input is nullptr or fileSize is smaller than ASTC HEADER");
        return 0;
    }
    if ((fileBuf[BYTE_POS_0] == ASTC_MAGIC_0) && (fileBuf[BYTE_POS_1] == ASTC_MAGIC_1) &&
        (fileBuf[BYTE_POS_2] == ASTC_MAGIC_2) && (fileBuf[BYTE_POS_3] == ASTC_MAGIC_3)) {
        IMAGE_LOGI("astc GetAstcSizeBytes input is pure astc!");
        return fileSize;
    }
    if (!g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.sutDecSoGetSizeFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT dec so dlopen failed or sutDecSoGetSizeFunc_ is nullptr!");
        return 0;
    }
    return g_sutDecSoManager.sutDecSoGetSizeFunc_(fileBuf, fileSize);
}

static bool TextureSuperCompressDecode(const uint8_t *inData, size_t inBytes, uint8_t *outData, size_t outBytes)
{
    size_t preOutBytes = outBytes;
    if ((inData == nullptr) || (outData == nullptr) || (inBytes >= outBytes)) {
        IMAGE_LOGE("astc TextureSuperCompressDecode input check failed!");
        return false;
    }
    if (!g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.sutDecSoDecFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT dec so dlopen failed or sutDecSoDecFunc_ is nullptr!");
        return false;
    }
    if (!g_sutDecSoManager.sutDecSoDecFunc_(inData, inBytes, outData, outBytes)) {
        IMAGE_LOGE("astc SuperDecompressTexture process failed!");
        return false;
    }
    if (outBytes != preOutBytes) {
        IMAGE_LOGE("astc SuperDecompressTexture Dec size is predicted failed!");
        return false;
    }
    return true;
}
#endif

static bool ReadFileAndResoveAstc(size_t fileSize, size_t astcSize, unique_ptr<PixelAstc> &pixelAstc,
    std::unique_ptr<SourceStream> &sourceStreamPtr)
{
#if !(defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM))
    int fd = AshmemCreate("CreatePixelMapForASTC Data", astcSize);
    if (fd < 0) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapForASTC AshmemCreate fd < 0.");
        return false;
    }
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapForASTC AshmemSetPort error.");
        ::close(fd);
        return false;
    }
    void *ptr = ::mmap(nullptr, astcSize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED || ptr == nullptr) {
        IMAGE_LOGE("[ImageSource]CreatePixelMapForASTC data is nullptr.");
        ::close(fd);
        return false;
    }
    auto data = static_cast<uint8_t *>(ptr);
    void *fdPtr = new int32_t();
    *static_cast<int32_t *>(fdPtr) = fd;
    pixelAstc->SetPixelsAddr(data, fdPtr, astcSize, Media::AllocatorType::SHARE_MEM_ALLOC, nullptr);
    bool successMemCpyOrDec = true;
#ifdef SUT_DECODE_ENABLE
    if (fileSize < astcSize) {
        if (TextureSuperCompressDecode(sourceStreamPtr->GetDataPtr(), fileSize, data, astcSize) != true) {
            IMAGE_LOGE("[ImageSource] astc SuperDecompressTexture failed!");
            successMemCpyOrDec = false;
        }
    } else {
#endif
        if (memcpy_s(data, fileSize, sourceStreamPtr->GetDataPtr(), fileSize) != 0) {
            IMAGE_LOGE("[ImageSource] astc memcpy_s failed!");
            successMemCpyOrDec = false;
        }
#ifdef SUT_DECODE_ENABLE
    }
#endif
    if (!successMemCpyOrDec) {
        int32_t *fdPtrInt = static_cast<int32_t *>(fdPtr);
        delete[] fdPtrInt;
        munmap(ptr, astcSize);
        ::close(fd);
        return false;
    }
#endif
    return true;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapForASTC(uint32_t &errorCode, bool fastAstc)
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
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
#ifdef SUT_DECODE_ENABLE
    size_t astcSize = GetAstcSizeBytes(sourceStreamPtr_->GetDataPtr(), fileSize);
    if (astcSize == 0) {
        IMAGE_LOGE("[ImageSource] astc GetAstcSizeBytes failed.");
        return nullptr;
    }
#else
    size_t astcSize = fileSize;
#endif
    if (fastAstc && sourceStreamPtr_->GetStreamType() == ImagePlugin::FILE_STREAM_TYPE && fileSize == astcSize) {
        void *fdBuffer = new int32_t();
        *static_cast<int32_t *>(fdBuffer) = static_cast<FileSourceStream *>(sourceStreamPtr_.get())->GetMMapFd();
        pixelAstc->SetPixelsAddr(sourceStreamPtr_->GetDataPtr(), fdBuffer, fileSize,
            AllocatorType::SHARE_MEM_ALLOC, nullptr);
    } else {
        if (!ReadFileAndResoveAstc(fileSize, astcSize, pixelAstc, sourceStreamPtr_)) {
            IMAGE_LOGE("[ImageSource] astc ReadFileAndResoveAstc failed.");
            return nullptr;
        }
    }
    pixelAstc->SetAstc(true);

    if (CreatExifMetadataByImageSource() == SUCCESS) {
        auto metadataPtr = exifMetadata_->Clone();
        pixelAstc->SetExifMetadata(metadataPtr);
    }

    return pixelAstc;
}
#endif

bool ImageSource::GetASTCInfo(const uint8_t *fileData, size_t fileSize, ASTCInfo &astcInfo)
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

unique_ptr<vector<unique_ptr<PixelMap>>> ImageSource::CreatePixelMapList(const DecodeOptions &opts, uint32_t &errorCode)
{
    ImageDataStatistics imageDataStatistics("[ImageSource]CreatePixelMapList.");
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
        IMAGE_LOGE("Failed to get frame count in GetDelayTime.");
        return nullptr;
    }

    auto delayTimes = std::make_unique<vector<int32_t>>();
    if (sourceInfo_.encodedFormat == "image/webp" && frameCount == 1) {
        errorCode = SUCCESS;
        return delayTimes;
    }
    const string IMAGE_DELAY_TIME = "DelayTime";
    for (uint32_t index = 0; index < frameCount; index++) {
        string delayTimeStr;
        errorCode = mainDecoder_->GetImagePropertyString(index, IMAGE_DELAY_TIME, delayTimeStr);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("Issue getting delay time in GetDelayTime. "
                "Index: %{public}u",
                index);
            return nullptr;
        }
        if (!IsNumericStr(delayTimeStr)) {
            IMAGE_LOGE("Delay time string is not numeric in GetDelayTime. "
                "Delay time string: %{public}s",
                delayTimeStr.c_str());
            return nullptr;
        }
        int delayTime = 0;
        if (!StrToInt(delayTimeStr, delayTime)) {
            IMAGE_LOGE("Failed to convert delay time string to int in GetDelayTime. "
                "Delay time string: %{public}s",
                delayTimeStr.c_str());
            return nullptr;
        }
        delayTimes->push_back(delayTime);
    }

    errorCode = SUCCESS;

    return delayTimes;
}

unique_ptr<vector<int32_t>> ImageSource::GetDisposalType(uint32_t &errorCode)
{
    auto frameCount = GetFrameCount(errorCode);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]GetDisposalType get frame sum error.");
        return nullptr;
    }

    auto disposalTypes = std::make_unique<vector<int32_t>>();
    const string IMAGE_DISPOSAL_TYPE = "DisposalType";
    for (uint32_t index = 0; index < frameCount; index++) {
        int disposalType = 0;
        errorCode = mainDecoder_->GetImagePropertyInt(index, IMAGE_DISPOSAL_TYPE, disposalType);
        if (errorCode != SUCCESS) {
            IMAGE_LOGE("[ImageSource]GetDisposalType get delay time issue. index=%{public}u", index);
            return nullptr;
        }
        disposalTypes->push_back(disposalType);
    }

    errorCode = SUCCESS;

    return disposalTypes;
}

int32_t ImageSource::GetLoopCount(uint32_t &errorCode)
{
    (void)GetFrameCount(errorCode);
    if (errorCode != SUCCESS || mainDecoder_ == nullptr) {
        IMAGE_LOGE("[ImageSource]GetLoopCount get frame sum error.");
        return errorCode;
    }

    int32_t loopCount = 0;
    const string IMAGE_LOOP_COUNT = "GIFLoopCount";
    errorCode = mainDecoder_->GetImagePropertyInt(0, IMAGE_LOOP_COUNT, loopCount);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("[ImageSource]GetLoopCount get loop count issue. errorCode=%{public}u", errorCode);
        return errorCode;
    }

    errorCode = SUCCESS;

    return loopCount;
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

void ImageSource::SetSource(const std::string &source)
{
    source_ = source;
}

void ImageSource::DumpInputData(const std::string &fileSuffix)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }

    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGI("ImageSource::DumpInputData failed, streamPtr is null");
        return;
    }

    uint8_t *data = sourceStreamPtr_->GetDataPtr();
    size_t size = sourceStreamPtr_->GetStreamSize();

    ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<const char *>(data), size, fileSuffix, imageId_);
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

static string GetExtendedCodecMimeType(AbsImageDecoder* decoder)
{
    const static string ENCODED_FORMAT_KEY = "EncodedFormat";
    string format;
    if (decoder != nullptr && decoder->GetImagePropertyString(FIRST_FRAME, ENCODED_FORMAT_KEY, format) == SUCCESS) {
        return format;
    }
    return string();
}

static float GetScaleSize(ImageInfo info, DecodeOptions opts)
{
    if (info.size.width == 0 || info.size.height == 0) {
        return 1.0;
    }
    float scale = max(static_cast<float>(opts.desiredSize.width) / info.size.width,
                      static_cast<float>(opts.desiredSize.height) / info.size.height);
    return scale;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static void SetHdrContext(DecodeContext& context, sptr<SurfaceBuffer>& sb, void* fd)
{
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.freeFunc = nullptr;
    context.pixelsBuffer.buffer = static_cast<uint8_t*>(sb->GetVirAddr());
    context.pixelsBuffer.bufferSize = sb->GetSize();
    context.pixelsBuffer.context = fd;
    context.pixelFormat = ImagePlugin::PlPixelFormat::RGBA_1010102;
    context.info.pixelFormat = ImagePlugin::PlPixelFormat::RGBA_1010102;
    context.info.alphaType = ImagePlugin::PlAlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
}
#endif

DecodeContext ImageSource::DecodeImageDataToContext(uint32_t index, ImageInfo info, ImagePlugin::PlImageInfo& plInfo,
                                                    uint32_t& errorCode)
{
    DecodeContext context = InitDecodeContext(opts_, info, preference_, hasDesiredSizeOptions);
    context.info.pixelFormat = plInfo.pixelFormat;
    ImageHdrType decodedHdrType = ImageHdrType::UNKNOWN;
    if (opts_.desiredDynamicRange != DecodeDynamicRange::SDR) {
        decodedHdrType = IsHdrImage() ? sourceHdrType_ : ImageHdrType::SDR;
        if (!ImageSystemProperties::GetDmaEnabled()) {
            decodedHdrType = ImageHdrType::SDR;
            IMAGE_LOGI("[ImageSource]DecodeImageDataToContext imageId_: %{public}lu don't support dma.",
                static_cast<unsigned long>(imageId_));
        } else if (decodedHdrType > ImageHdrType::SDR) {
            context.allocatorType = AllocatorType::DMA_ALLOC;
        }
    }
    errorCode = mainDecoder_->Decode(index, context);
    context.grColorSpaceName = mainDecoder_->getGrColorSpace().GetColorSpaceName();
    if (plInfo.size.width != context.outInfo.size.width || plInfo.size.height != context.outInfo.size.height) {
        // hardware decode success, update plInfo.size
        IMAGE_LOGI("hardware decode success, soft decode dstInfo:(%{public}u, %{public}u), use hardware dstInfo:"
            "(%{public}u, %{public}u)", plInfo.size.width, plInfo.size.height, context.outInfo.size.width,
            context.outInfo.size.height);
        plInfo.size = context.outInfo.size;
    }
    context.info = plInfo;
    context.hdrType = ImageHdrType::SDR;
    ninePatchInfo_.ninePatch = context.ninePatchContext.ninePatch;
    ninePatchInfo_.patchSize = context.ninePatchContext.patchSize;
    if (errorCode != SUCCESS) {
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        return context;
    }
    DecodeContext hdrContext;
    hdrContext.hdrType = decodedHdrType;
    hdrContext.info.size = plInfo.size;
    hdrContext.allocatorType = AllocatorType::DMA_ALLOC;
    float scale = GetScaleSize(info, opts_);
    if (decodedHdrType > ImageHdrType::SDR && ApplyGainMap(decodedHdrType, context, hdrContext, scale)) {
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        plInfo = hdrContext.info;
        hdrContext.outInfo.size = hdrContext.info.size;
        return hdrContext;
    }
    return context;
}

uint32_t ImageSource::SetGainMapDecodeOption(std::unique_ptr<AbsImageDecoder>& decoder, PlImageInfo& plInfo,
                                             float scale)
{
    ImageInfo info;
    ImagePlugin::PlSize size;
    uint32_t errorCode = decoder->GetImageSize(FIRST_FRAME, size);
    info.size.width = size.width;
    info.size.height = size.height;
    if (errorCode != SUCCESS || !IsSizeVailed({static_cast<int32_t>(size.width), static_cast<int32_t>(size.height)})) {
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return errorCode;
    }
    Size wantSize = info.size;
    if (scale > 0 && scale < 1.0) {
        wantSize.width = info.size.width * scale;
        wantSize.height = info.size.height * scale;
    }
    DecodeOptions opts;
    TransformSizeWithDensity(info.size, sourceInfo_.baseDensity, wantSize, opts_.fitDensity, opts.desiredSize);
    PixelDecodeOptions plOptions;
    CopyOptionsToPlugin(opts, plOptions);
    plOptions.desiredPixelFormat = ImagePlugin::PlPixelFormat::RGBA_8888;
    errorCode = decoder->SetDecodeOptions(FIRST_FRAME, plOptions, plInfo);
    return errorCode;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static CM_ColorSpaceType ConvertColorSpaceType(ColorManager::ColorSpaceName colorSpace, bool base)
{
    switch (colorSpace) {
        case ColorManager::ColorSpaceName::SRGB :
            return CM_SRGB_FULL;
        case ColorManager::ColorSpaceName::SRGB_LIMIT :
            return CM_SRGB_LIMIT;
        case ColorManager::ColorSpaceName::DISPLAY_P3 :
            return CM_P3_FULL;
        case ColorManager::ColorSpaceName::DISPLAY_P3_LIMIT :
            return CM_P3_LIMIT;
        case ColorManager::ColorSpaceName::BT2020 :
        case ColorManager::ColorSpaceName::BT2020_HLG :
            return CM_BT2020_HLG_FULL;
        case ColorManager::ColorSpaceName::BT2020_HLG_LIMIT :
            return CM_BT2020_HLG_LIMIT;
        case ColorManager::ColorSpaceName::BT2020_PQ :
            return CM_BT2020_PQ_FULL;
        case ColorManager::ColorSpaceName::BT2020_PQ_LIMIT :
            return CM_BT2020_PQ_LIMIT;
        default:
            return base ? CM_SRGB_FULL : CM_BT2020_HLG_FULL;
    }
    return base ? CM_SRGB_FULL : CM_BT2020_HLG_FULL;
}

static ColorManager::ColorSpaceName ConvertColorSpaceName(CM_ColorSpaceType colorSpace, bool base)
{
    switch (colorSpace) {
        case CM_SRGB_FULL :
            return ColorManager::SRGB;
        case CM_SRGB_LIMIT :
            return ColorManager::SRGB_LIMIT;
        case CM_P3_FULL :
            return ColorManager::DISPLAY_P3;
        case CM_P3_LIMIT :
            return ColorManager::DISPLAY_P3_LIMIT;
        case CM_BT2020_HLG_FULL :
            return ColorManager::BT2020_HLG;
        case CM_BT2020_HLG_LIMIT :
            return ColorManager::BT2020_HLG_LIMIT;
        case CM_BT2020_PQ_FULL :
            return ColorManager::BT2020_PQ;
        case CM_BT2020_PQ_LIMIT :
            return ColorManager::BT2020_PQ_LIMIT;
        default:
            return base ? ColorManager::SRGB : ColorManager::BT2020_HLG;
    }
    return base ? ColorManager::SRGB : ColorManager::BT2020_HLG;
}
#endif

bool ImageSource::DecodeJpegGainMap(ImageHdrType hdrType, float scale, DecodeContext& gainMapCtx, HdrMetadata& metadata)
{
    ImageTrace imageTrace("ImageSource::DecodeJpegGainMap hdrType:%{public}d, scale:%{public}d", hdrType, scale);
    uint32_t gainMapOffset = mainDecoder_->GetGainMapOffset();
    if (gainMapOffset == 0 || gainMapOffset > sourceStreamPtr_->GetStreamSize()) {
        return false;
    }
    uint8_t* gainMapData = sourceStreamPtr_->GetDataPtr() + gainMapOffset;
    uint32_t dataSize = sourceStreamPtr_->GetStreamSize() - gainMapOffset;
    std::unique_ptr<InputDataStream> gainMapStream = BufferSourceStream::CreateSourceStream(gainMapData, dataSize);
    if (gainMapStream == nullptr) {
        IMAGE_LOGE("[ImageSource] create gainmap stream fail, gainmap offset is %{public}d", gainMapOffset);
        return false;
    }
    uint32_t errorCode;
    jpegGainmapDecoder_ = std::unique_ptr<AbsImageDecoder>(
        DoCreateDecoder(InnerFormat::IMAGE_EXTENDED_CODEC, pluginServer_, *gainMapStream, errorCode));
    if (jpegGainmapDecoder_ == nullptr) {
        IMAGE_LOGE("[ImageSource] create gainmap decoder fail, gainmap offset is %{public}d", gainMapOffset);
        return false;
    }
    PlImageInfo gainMapInfo;
    errorCode = SetGainMapDecodeOption(jpegGainmapDecoder_, gainMapInfo, scale);
    if (errorCode != SUCCESS) {
        return false;
    }
    gainMapCtx.allocatorType = AllocatorType::DMA_ALLOC;
    errorCode = jpegGainmapDecoder_->Decode(FIRST_FRAME, gainMapCtx);
    if (gainMapInfo.size.width != gainMapCtx.outInfo.size.width ||
        gainMapInfo.size.height != gainMapCtx.outInfo.size.height) {
        // hardware decode success, update gainMapInfo.size
        gainMapInfo.size = gainMapCtx.outInfo.size;
    }
    gainMapCtx.info = gainMapInfo;
    if (errorCode != SUCCESS) {
        FreeContextBuffer(gainMapCtx.freeFunc, gainMapCtx.allocatorType, gainMapCtx.pixelsBuffer);
        return false;
    }
    metadata = jpegGainmapDecoder_->GetHdrMetadata(hdrType);
    return true;
}

bool ImageSource::ApplyGainMap(ImageHdrType hdrType, DecodeContext& baseCtx, DecodeContext& hdrCtx, float scale)
{
    string format = GetExtendedCodecMimeType(mainDecoder_.get());
    if (format != IMAGE_JPEG_FORMAT && format != IMAGE_HEIF_FORMAT) {
        return false;
    }
    DecodeContext gainMapCtx;
    HdrMetadata metadata;
    if (format == IMAGE_HEIF_FORMAT) {
        ImageTrace imageTrace("ImageSource decode heif gainmap hdrType:%{public}d, scale:%{public}d", hdrType, scale);
        if (!mainDecoder_->DecodeHeifGainMap(gainMapCtx, scale)) {
            IMAGE_LOGI("[ImageSource] heif get gainmap failed");
            return false;
        }
        metadata = mainDecoder_->GetHdrMetadata(hdrType);
    } else if (!DecodeJpegGainMap(hdrType, scale, gainMapCtx, metadata)) {
        IMAGE_LOGI("[ImageSource] jpeg get gainmap failed");
        return false;
    }

    bool result = ComposeHdrImage(hdrType, baseCtx, gainMapCtx, hdrCtx, metadata);
    FreeContextBuffer(gainMapCtx.freeFunc, gainMapCtx.allocatorType, gainMapCtx.pixelsBuffer);
    return result;
}

static void SetVividMetaColor(HdrMetadata& metadata,
    CM_ColorSpaceType base, CM_ColorSpaceType gainmap, CM_ColorSpaceType hdr)
{
    metadata.extendMeta.baseColorMeta.baseColorPrimary = base & 0xFF;
    metadata.extendMeta.gainmapColorMeta.enhanceDataColorPrimary = gainmap & 0xFF;
    metadata.extendMeta.gainmapColorMeta.combineColorPrimary = gainmap & 0xFF;
    metadata.extendMeta.gainmapColorMeta.alternateColorPrimary = hdr & 0xFF;
}

static uint32_t AllocHdrSurfaceBuffer(DecodeContext& context, ImageHdrType hdrType, CM_ColorSpaceType color)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("UnSupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = context.info.size.width,
        .height = context.info.size.height,
        .strideAlignment = context.info.size.width,
        .format = GRAPHIC_PIXEL_FMT_RGBA_1010102,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
    };
    GSError ret = sb->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        return ERR_DMA_NOT_EXIST;
    }
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    if (err != OHOS::GSERROR_OK) {
        return ERR_DMA_DATA_ABNORMAL;
    }
    SetHdrContext(context, sb, nativeBuffer);
    context.grColorSpaceName = ConvertColorSpaceName(color, false);
    CM_HDR_Metadata_Type type;
    if (hdrType == ImageHdrType::HDR_VIVID_DUAL || hdrType == ImageHdrType::HDR_CUVA) {
        type = CM_IMAGE_HDR_VIVID_SINGLE;
    } else if (hdrType == ImageHdrType::HDR_ISO_DUAL) {
        type = CM_IMAGE_HDR_ISO_SINGLE;
    }
    VpeUtils::SetSbMetadataType(sb, type);
    VpeUtils::SetSbColorSpaceType(sb, color);
    return SUCCESS;
#endif
}

bool ImageSource::ComposeHdrImage(ImageHdrType hdrType, DecodeContext& baseCtx, DecodeContext& gainMapCtx,
                                  DecodeContext& hdrCtx, HdrMetadata metadata)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGE("unsupport hdr");
    return false;
#else
    ImageTrace imageTrace("ImageSource::ComposeHdrImage hdr type is %{public}d", hdrType);
    if (baseCtx.allocatorType != AllocatorType::DMA_ALLOC || gainMapCtx.allocatorType != AllocatorType::DMA_ALLOC) {
        return false;
    }
    CM_ColorSpaceType baseCmColor = ConvertColorSpaceType(baseCtx.grColorSpaceName, true);
    // base image
    sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(baseCtx.pixelsBuffer.context));
    VpeUtils::SetSurfaceBufferInfo(baseSptr, false, hdrType, baseCmColor, metadata);
    // gainmap image
    sptr<SurfaceBuffer> gainmapSptr(reinterpret_cast<SurfaceBuffer*>(gainMapCtx.pixelsBuffer.context));
    CM_ColorSpaceType hdrCmColor = CM_BT2020_HLG_FULL;
    CM_ColorSpaceType gainmapCmColor = metadata.extendMeta.metaISO.useBaseColorFlag == 0x01 ? baseCmColor : hdrCmColor;
    SetVividMetaColor(metadata, baseCmColor, gainmapCmColor, hdrCmColor);
    VpeUtils::SetSurfaceBufferInfo(gainmapSptr, true, hdrType, gainmapCmColor, metadata);
    // hdr image
    uint32_t errorCode = AllocHdrSurfaceBuffer(hdrCtx, hdrType, hdrCmColor);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("HDR SurfaceBuffer Alloc failed, %{public}d", errorCode);
        return false;
    }
    sptr<SurfaceBuffer> hdrSptr(reinterpret_cast<SurfaceBuffer*>(hdrCtx.pixelsBuffer.context));
    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .gainmap = gainmapSptr,
        .hdr = hdrSptr,
    };
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    bool legacy = hdrType == ImageHdrType::HDR_CUVA;
    int32_t res = utils->ColorSpaceConverterComposeImage(buffers, legacy);
    if (res != VPE_ERROR_OK) {
        FreeContextBuffer(hdrCtx.freeFunc, hdrCtx.allocatorType, hdrCtx.pixelsBuffer);
        return false;
    }
    return true;
#endif
}

uint32_t ImageSource::RemoveImageProperties(std::shared_ptr<MetadataAccessor> metadataAccessor,
                                            const std::set<std::string> &keys)
{
    if (metadataAccessor == nullptr) {
        IMAGE_LOGE("Failed to create image accessor when attempting to modify image property.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint32_t ret = CreatExifMetadataByImageSource();
    if (ret != SUCCESS) {
        IMAGE_LOGE("Failed to create ExifMetadata.");
        return ret;
    }

    bool deletFlag = false;
    for (auto key: keys) {
        bool result = exifMetadata_->RemoveEntry(key);
        deletFlag |= result;
    }

    if (!deletFlag) {
        return ERR_MEDIA_NO_EXIF_DATA;
    }

    metadataAccessor->Set(exifMetadata_);
    return metadataAccessor->Write();
}

static void SetContext(DecodeContext& context, sptr<SurfaceBuffer>& sb, void* fd)
{
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.freeFunc = nullptr;
    context.pixelsBuffer.buffer = static_cast<uint8_t*>(sb->GetVirAddr());
    context.pixelsBuffer.bufferSize = sb->GetSize();
    context.pixelsBuffer.context = fd;
}

static uint32_t AllocSurfaceBuffer(DecodeContext &context, uint32_t format)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGE("UnSupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    IMAGE_LOGD("[ImageSource]AllocBufferForContext requestConfig, sizeInfo.width:%{public}u,height:%{public}u.",
               context.info.size.width, context.info.size.height);
    BufferRequestConfig requestConfig = {
        .width = context.info.size.width,
        .height = context.info.size.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = format,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
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
    SetContext(context, sb, nativeBuffer);
    if (format == GRAPHIC_PIXEL_FMT_RGBA_1010102) {
        context.pixelFormat = ImagePlugin::PlPixelFormat::RGBA_1010102;
        context.info.pixelFormat = ImagePlugin::PlPixelFormat::RGBA_1010102;
        context.info.alphaType = ImagePlugin::PlAlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    }
    return SUCCESS;
#endif
}

static uint32_t CopyContextIntoSurfaceBuffer(Size dstSize, const DecodeContext &context, DecodeContext &dstCtx)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("UnSupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    IMAGE_LOGD("[ImageSource]CopyContextIntoSurfaceBuffer requestConfig, sizeInfo.width:%{public}u,height:%{public}u.",
        context.info.size.width, context.info.size.height);

    BufferRequestConfig requestConfig = {
        .width = context.info.size.width,
        .height = context.info.size.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
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
    memcpy_s(static_cast<void*>(sb->GetVirAddr()), context.pixelsBuffer.bufferSize, context.pixelsBuffer.buffer,
        context.pixelsBuffer.bufferSize);
    SetContext(dstCtx, sb, nativeBuffer);
    return SUCCESS;
#endif
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static uint32_t DoAiHdrProcess(sptr<SurfaceBuffer> &input, DecodeContext &hdrCtx,
                               CM_ColorSpaceType cmColorSpaceType)
{
    VpeUtils::SetSbMetadataType(input, CM_METADATA_NONE);
    VpeUtils::SetSurfaceBufferInfo(input, cmColorSpaceType);

    uint32_t res = AllocSurfaceBuffer(hdrCtx, GRAPHIC_PIXEL_FMT_RGBA_1010102);
    if (res != SUCCESS) {
        IMAGE_LOGE("HDR SurfaceBuffer Alloc failed, %{public}d", res);
        return res;
    }

    sptr<SurfaceBuffer> output = reinterpret_cast<SurfaceBuffer*>(hdrCtx.pixelsBuffer.context);
    VpeUtils::SetSbMetadataType(output, CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbColorSpaceDefault(output);

    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    res = utils->ColorSpaceConverterImageProcess(input, output);
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("[ImageSource]DoAiHdrProcess ColorSpaceConverterImageProcess failed! %{public}d", res);
        FreeContextBuffer(hdrCtx.freeFunc, hdrCtx.allocatorType, hdrCtx.pixelsBuffer);
    } else {
        IMAGE_LOGD("[ImageSource]DoAiHdrProcess ColorSpaceConverterImageProcess Succ!");
        hdrCtx.hdrType = ImageHdrType::HDR_VIVID_SINGLE;
        hdrCtx.pixelsBuffer.bufferSize = output->GetSize();
        hdrCtx.outInfo.size.width = output->GetSurfaceBufferWidth();
        hdrCtx.outInfo.size.height = output->GetSurfaceBufferHeight();
    }
    return res;
}

static uint32_t AiSrProcess(sptr<SurfaceBuffer> &input, DecodeContext &aisrCtx)
{
    uint32_t res = AllocSurfaceBuffer(aisrCtx, GRAPHIC_PIXEL_FMT_RGBA_8888);
    if (res != SUCCESS) {
        IMAGE_LOGE("HDR SurfaceBuffer Alloc failed, %{public}d", res);
        return res;
    }
    sptr<SurfaceBuffer> output = reinterpret_cast<SurfaceBuffer*>(aisrCtx.pixelsBuffer.context);
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    res = utils->DetailEnhancerImageProcess(input, output, static_cast<int32_t>(aisrCtx.resolutionQuality));
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("[ImageSource]AiSrProcess DetailEnhancerImage Processed failed");
        FreeContextBuffer(aisrCtx.freeFunc, aisrCtx.allocatorType, aisrCtx.pixelsBuffer);
    } else {
        aisrCtx.pixelsBuffer.bufferSize = output->GetSize();
        aisrCtx.outInfo.size.width = output->GetSurfaceBufferWidth();
        aisrCtx.outInfo.size.height = output->GetSurfaceBufferHeight();
        aisrCtx.hdrType = Media::ImageHdrType::SDR;
        IMAGE_LOGD("[ImageSource]AiSrProcess DetailEnhancerImage %{public}d %{public}d %{public}d",
            aisrCtx.outInfo.size.width, aisrCtx.outInfo.size.height, aisrCtx.pixelsBuffer.bufferSize);
    }
    return res;
}

static bool CheckCapacityAi()
{
#ifdef IMAGE_AI_ENABLE
    return true;
#else
    return false;
#endif
}

static bool IsNecessaryAiProcess(const Size &imageSize, const DecodeOptions &opts, bool isHdrImage,
                                 bool &needAisr, bool &needHdr)
{
    auto bRet = CheckCapacityAi();
    if (!bRet) {
        IMAGE_LOGD("[ImageSource] IsNecessaryAiProcess Unsupported sr and hdr");
        return false;
    }
    if ((IsSizeVailed(opts.desiredSize) && (imageSize.height != opts.desiredSize.height
            || imageSize.width != opts.desiredSize.width)) || opts.resolutionQuality == ResolutionQuality::HIGH) {
        IMAGE_LOGE("[ImageSource] IsNecessaryAiProcess imageSize ne opts_.desiredSize");
        needAisr = true;
    }

    if (opts.desiredDynamicRange == DecodeDynamicRange::HDR) {
        IMAGE_LOGD("[ImageSource] IsNecessaryAiProcess desiredDynamicRange is hdr");
        if (!isHdrImage) {
            IMAGE_LOGE("[ImageSource] IsNecessaryAiProcess needHdr = true;");
            needHdr = true;
        }
    }
    if (!needAisr && !needHdr) {
        IMAGE_LOGD("[ImageSource] no need aisr and hdr Process");
        return false;
    }
    IMAGE_LOGD("[ImageSource] need aisr or hdr Process :aisr %{public}d hdr:%{public}d", needAisr, needHdr);
    return true;
}

static void CopySrcInfoOfContext(const DecodeContext &srcCtx, DecodeContext &dstCtx)
{
    dstCtx.info.size.width = srcCtx.info.size.width;
    dstCtx.info.size.height = srcCtx.info.size.height;
    dstCtx.resolutionQuality = srcCtx.resolutionQuality;
    dstCtx.hdrType = srcCtx.hdrType;
    dstCtx.pixelFormat = srcCtx.pixelFormat;
    dstCtx.info.pixelFormat = srcCtx.info.pixelFormat;
    dstCtx.info.alphaType = srcCtx.info.alphaType;
    dstCtx.isAisr = srcCtx.isAisr;
}

static void CopyOutInfoOfContext(const DecodeContext &srcCtx, DecodeContext &dstCtx)
{
    dstCtx.pixelsBuffer.buffer = srcCtx.pixelsBuffer.buffer ;
    dstCtx.pixelsBuffer.bufferSize = srcCtx.pixelsBuffer.bufferSize;
    dstCtx.pixelsBuffer.context = srcCtx.pixelsBuffer.context;
    dstCtx.allocatorType = srcCtx.allocatorType;
    dstCtx.freeFunc = srcCtx.freeFunc;
    dstCtx.outInfo.size.width = srcCtx.outInfo.size.width;
    dstCtx.outInfo.size.height = srcCtx.outInfo.size.height;
    dstCtx.hdrType = srcCtx.hdrType;
    dstCtx.pixelFormat = srcCtx.pixelFormat;
    dstCtx.info.pixelFormat = srcCtx.info.pixelFormat;
    dstCtx.info.alphaType = srcCtx.info.alphaType;
    dstCtx.isAisr = srcCtx.isAisr;
}

static uint32_t AiHdrProcess(const DecodeContext &aisrCtx, DecodeContext &hdrCtx, CM_ColorSpaceType cmColorSpaceType)
{
    hdrCtx.pixelsBuffer.bufferSize = aisrCtx.pixelsBuffer.bufferSize;
    hdrCtx.info.size.width = aisrCtx.outInfo.size.width;
    hdrCtx.info.size.height = aisrCtx.outInfo.size.height;

    sptr<SurfaceBuffer> inputHdr = reinterpret_cast<SurfaceBuffer*> (aisrCtx.pixelsBuffer.context);
    return DoAiHdrProcess(inputHdr, hdrCtx, cmColorSpaceType);
}

static uint32_t DoImageAiProcess(sptr<SurfaceBuffer> &input, DecodeContext &dstCtx,
                                 CM_ColorSpaceType cmColorSpaceType, bool needAisr, bool needHdr)
{
    DecodeContext aiCtx;
    CopySrcInfoOfContext(dstCtx, aiCtx);
    uint32_t res = ERR_IMAGE_AI_UNSUPPORTED;
    if (needAisr) {
        res = AiSrProcess(input, aiCtx);
        if (res != SUCCESS) {
            IMAGE_LOGE("[ImageSource] AiSrProcess fail %{public}u", res);
        } else {
            CopyOutInfoOfContext(aiCtx, dstCtx);
            dstCtx.isAisr = true;
        }
    }
    if (needHdr) {
        sptr<SurfaceBuffer> inputHdr = input;
        DecodeContext hdrCtx;
        if (dstCtx.isAisr) {
            res = AiHdrProcess(aiCtx, hdrCtx, cmColorSpaceType);
            if (res != SUCCESS) {
                res = ERR_IMAGE_AI_ONLY_SR_SUCCESS;
                IMAGE_LOGE("[ImageSource] DoAiHdrProcess fail %{public}u", res);
                FreeContextBuffer(hdrCtx.freeFunc, hdrCtx.allocatorType, hdrCtx.pixelsBuffer);
            } else {
                FreeContextBuffer(aiCtx.freeFunc, aiCtx.allocatorType, aiCtx.pixelsBuffer);
                CopyOutInfoOfContext(hdrCtx, dstCtx);
            }
        } else {
            CopySrcInfoOfContext(dstCtx, hdrCtx);
            res = DoAiHdrProcess(inputHdr, hdrCtx, cmColorSpaceType);
            if (res != SUCCESS) {
                IMAGE_LOGE("[ImageSource] DoAiHdrProcess fail %{public}u", res);
                FreeContextBuffer(hdrCtx.freeFunc, hdrCtx.allocatorType, hdrCtx.pixelsBuffer);
            } else {
                CopyOutInfoOfContext(hdrCtx, dstCtx);
            }
        }
    }
    return res;
}
#endif
uint32_t ImageSource::ImageAiProcess(Size imageSize, const DecodeOptions &opts, bool isHdr, DecodeContext &context)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return ERR_MEDIA_INVALID_OPERATION;
#else
    bool needAisr = false;
    bool needHdr = false;
    auto bRet = IsNecessaryAiProcess(imageSize, opts, isHdr, needAisr, needHdr);
    if (!bRet) {
        return ERR_IMAGE_AI_UNNECESSARY;
    }
    context.resolutionQuality = opts.resolutionQuality;
    DecodeContext srcCtx;
    CopySrcInfoOfContext(context, srcCtx);
    sptr<SurfaceBuffer> input = nullptr;
    IMAGE_LOGD("[ImageSource] ImageAiProcess allocatorType %{public}u", context.allocatorType);
    if (context.allocatorType == AllocatorType::DMA_ALLOC) {
        input = reinterpret_cast<SurfaceBuffer*> (context.pixelsBuffer.context);
    } else {
        auto res = CopyContextIntoSurfaceBuffer(imageSize, context, srcCtx);
        if (res != SUCCESS) {
            IMAGE_LOGE("[ImageSource] ImageAiProcess HDR SurfaceBuffer Alloc failed, %{public}d", res);
            return res;
        }
        input = reinterpret_cast<SurfaceBuffer*>(srcCtx.pixelsBuffer.context);
    }
    DecodeContext dstCtx;
    CopySrcInfoOfContext(context, dstCtx);

    if (IsSizeVailed(opts.desiredSize)) {
        dstCtx.info.size.width = opts.desiredSize.width;
        dstCtx.info.size.height = opts.desiredSize.height;
    }
    CM_ColorSpaceType cmColorSpaceType =
        ConvertColorSpaceType(mainDecoder_->getGrColorSpace().GetColorSpaceName(), true);
    auto res = DoImageAiProcess(input, dstCtx, cmColorSpaceType, needAisr, needHdr);
    if (res == SUCCESS || res == ERR_IMAGE_AI_ONLY_SR_SUCCESS) {
        FreeContextBuffer(srcCtx.freeFunc, srcCtx.allocatorType, srcCtx.pixelsBuffer);
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        CopyOutInfoOfContext(dstCtx, context);
    }
    return res;
#endif
}

static void UpdatepPlImageInfo(DecodeContext context, bool isHdr, ImagePlugin::PlImageInfo &plInfo)
{
    if (isHdr) {
        plInfo.colorSpace = context.colorSpace;
        plInfo.pixelFormat = context.pixelFormat;
    }

    if (plInfo.size.width != context.outInfo.size.width || plInfo.size.height != context.outInfo.size.height) {
        plInfo.size = context.outInfo.size;
    }
    if ((plInfo.pixelFormat == PlPixelFormat::NV12 || plInfo.pixelFormat == PlPixelFormat::NV21) &&
        context.yuvInfo.imageSize.width != 0) {
        plInfo.yuvDataInfo = context.yuvInfo;
        plInfo.size = context.yuvInfo.imageSize;
    }
}

DecodeContext ImageSource::DecodeImageDataToContextExtended(uint32_t index, ImageInfo &info,
    ImagePlugin::PlImageInfo &plInfo, ImageEvent &imageEvent, uint32_t &errorCode)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    hasDesiredSizeOptions = IsSizeVailed(opts_.desiredSize);
    TransformSizeWithDensity(info.size, sourceInfo_.baseDensity, opts_.desiredSize, opts_.fitDensity,
        opts_.desiredSize);
    errorCode = SetDecodeOptions(mainDecoder_, index, opts_, plInfo);
    if (errorCode != SUCCESS) {
        imageEvent.SetDecodeErrorMsg("set decode options error.ret:" + std::to_string(errorCode));
        IMAGE_LOGE("[ImageSource]set decode options error (index:%{public}u), ret:%{public}u.", index, errorCode);
        return {};
    }
    NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_HEADER_DECODE, &guard);
    auto context = DecodeImageDataToContext(index, info, plInfo, errorCode);
    if (context.ifPartialOutput) {
        NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_PARTIAL_DECODE, &guard);
    }
    UpdateDecodeInfoOptions(context, imageEvent);
    guard.unlock();
    return context;
}
} // namespace Media
} // namespace OHOS
