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
#ifdef EXT_PIXEL
#include "pixel_yuv_ext.h"
#endif

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <vector>

#include "auxiliary_generator.h"
#include "auxiliary_picture.h"
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
#include "jpeg_mpf_parser.h"
#include "media_errors.h"
#include "memory_manager.h"
#include "metadata_accessor.h"
#include "metadata_accessor_factory.h"
#include "pixel_astc.h"
#include "pixel_map.h"
#include "pixel_yuv.h"
#include "plugin_server.h"
#include "post_proc.h"
#include "securec.h"
#include "source_stream.h"
#include "image_dfx.h"
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
#include "include/jpeg_decoder.h"
#else
#include "surface_buffer.h"
#include "native_buffer.h"
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
#ifdef IMAGE_QOS_ENABLE
#include "qos.h"
#endif
#ifdef HEIF_HW_DECODE_ENABLE
#include "v3_0/codec_types.h"
#include "v3_0/icodec_component_manager.h"
#endif

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

static const map<PixelFormat, GraphicPixelFormat> SINGLE_HDR_CONVERT_FORMAT_MAP = {
    { PixelFormat::RGBA_8888, GRAPHIC_PIXEL_FMT_RGBA_8888 },
    { PixelFormat::NV21, GRAPHIC_PIXEL_FMT_YCRCB_420_SP },
    { PixelFormat::NV12, GRAPHIC_PIXEL_FMT_YCBCR_420_SP },
    { PixelFormat::YCRCB_P010, GRAPHIC_PIXEL_FMT_YCRCB_420_SP },
    { PixelFormat::YCBCR_P010, GRAPHIC_PIXEL_FMT_YCBCR_420_SP },
};
#endif

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
static const std::string KEY_IMAGE_WIDTH = "ImageWidth";
static const std::string KEY_IMAGE_HEIGHT = "ImageLength";
static const std::string IMAGE_FORMAT_RAW = "image/raw";
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
static const uint8_t NUM_24 = 24;
static const int DMA_SIZE = 512 * 512 * 4; // DMA limit size
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
static const int ASTC_SIZE = 512 * 512;
static const size_t ASTC_HEADER_SIZE = 16;
static const uint8_t ASTC_HEADER_BLOCK_X = 4;
static const uint8_t ASTC_HEADER_BLOCK_Y = 5;
static const uint8_t ASTC_HEADER_DIM_X = 7;
static const uint8_t ASTC_HEADER_DIM_Y = 10;
static const int IMAGE_HEADER_SIZE = 12;
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
constexpr uint32_t SUT_FILE_SIGNATURE = 0x53555401;
static const std::string g_textureSuperDecSo = "/system/lib64/module/hms/graphic/libtextureSuperDecompress.z.so";

using GetSuperCompressAstcSize = size_t (*)(const uint8_t *, size_t);
using SuperDecompressTexture = bool (*)(const uint8_t *, size_t, uint8_t *, size_t &);
using IsSut = bool (*)(const uint8_t *, size_t);
using GetTextureInfoFromSut = bool (*)(const uint8_t *, size_t, uint32_t &, uint32_t &, uint32_t &);

class SutDecSoManager {
public:
    SutDecSoManager();
    ~SutDecSoManager();
    GetSuperCompressAstcSize sutDecSoGetSizeFunc_;
    SuperDecompressTexture sutDecSoDecFunc_;
    IsSut isSutFunc_;
    GetTextureInfoFromSut getTextureInfoFunc_;
private:
    void *textureDecSoHandle_;
    bool LoadSutDecSo();
};

static SutDecSoManager g_sutDecSoManager;

SutDecSoManager::SutDecSoManager()
{
    textureDecSoHandle_ = nullptr;
    sutDecSoGetSizeFunc_ = nullptr;
    sutDecSoDecFunc_ = nullptr;
    isSutFunc_ = nullptr;
    getTextureInfoFunc_ = nullptr;
    if (LoadSutDecSo()) {
        IMAGE_LOGD("[ImageSource] astcenc sut dec so is success to be opened!");
    } else {
        IMAGE_LOGD("[ImageSource] astcenc sut dec so is failed to be opened!");
    }
}

SutDecSoManager::~SutDecSoManager()
{
    if (textureDecSoHandle_ == nullptr) {
        IMAGE_LOGD("[ImageSource] astcenc dec so is not be opened when dlclose!");
        return;
    }
    if (dlclose(textureDecSoHandle_) != 0) {
        IMAGE_LOGE("[ImageSource] astcenc sut dec so dlclose failed: %{public}s!", g_textureSuperDecSo.c_str());
    } else {
        IMAGE_LOGD("[ImageSource] astcenc sut dec so dlclose success: %{public}s!", g_textureSuperDecSo.c_str());
    }
}

static bool CheckClBinIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}

bool SutDecSoManager::LoadSutDecSo()
{
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
    isSutFunc_ = reinterpret_cast<IsSut>(dlsym(textureDecSoHandle_, "IsSut"));
    if (isSutFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] astc IsSut dlsym failed!");
        dlclose(textureDecSoHandle_);
        textureDecSoHandle_ = nullptr;
        return false;
    }
    getTextureInfoFunc_ =
        reinterpret_cast<GetTextureInfoFromSut>(dlsym(textureDecSoHandle_, "GetTextureInfoFromSut"));
    if (getTextureInfoFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] astc GetTextureInfoFromSut dlsym failed!");
        dlclose(textureDecSoHandle_);
        textureDecSoHandle_ = nullptr;
        return false;
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

PluginServer &ImageSource::pluginServer_ = ImageUtils::GetPluginServer();
ImageSource::FormatAgentMap ImageSource::formatAgentMap_ = InitClass();

#ifdef HEIF_HW_DECODE_ENABLE
static bool IsSecureMode(const std::string &name)
{
    std::string prefix = ".secure";
    if (name.length() <= prefix.length()) {
        return false;
    }
    return name.rfind(prefix) == (name.length() - prefix.length());
}
#endif

static bool IsSupportHeif()
{
#ifdef HEIF_HW_DECODE_ENABLE
    sptr<HDI::Codec::V3_0::ICodecComponentManager> manager =
            HDI::Codec::V3_0::ICodecComponentManager::Get(false);
    if (manager == nullptr) {
        return false;
    }
    int32_t compCnt = 0;
    int32_t ret = manager->GetComponentNum(compCnt);
    if (ret != HDF_SUCCESS || compCnt <= 0) {
        return false;
    }
    std::vector<HDI::Codec::V3_0::CodecCompCapability> capList(compCnt);
    ret = manager->GetComponentCapabilityList(capList, compCnt);
    if (ret != HDF_SUCCESS || capList.empty()) {
        return false;
    }
    for (const auto& cap : capList) {
        if (cap.role == HDI::Codec::V3_0::MEDIA_ROLETYPE_VIDEO_HEVC &&
            cap.type == HDI::Codec::V3_0::VIDEO_DECODER && !IsSecureMode(cap.compName)) {
            return true;
        }
    }
#endif
    return false;
}

// LCOV_EXCL_START
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
        if (attr.GetValue(format) != SUCCESS || format == nullptr) {
            IMAGE_LOGE("[ImageSource]attr data get format failed.");
            continue;
        }

        if (*format == InnerFormat::RAW_FORMAT) {
            formats.insert(std::begin(InnerFormat::RAW_EXTENDED_FORMATS), std::end(InnerFormat::RAW_EXTENDED_FORMATS));
        } else {
            formats.insert(*format);
        }
    }

    static bool isSupportHeif = IsSupportHeif();
    if (isSupportHeif) {
        formats.insert(IMAGE_HEIF_FORMAT);
    }
    return SUCCESS;
}
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
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
                IMAGE_LOGE("[ImageSource]failed to create file path source stream");
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
// LCOV_EXCL_STOP

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
    if (opts.desiredSize.width < 0 || opts.desiredSize.height < 0) {
        IMAGE_LOGE("desiredSize is invalid");
        errorCode = ERR_IMAGE_INVALID_PARAMETER;
        return nullptr;
    }
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
        opts_ = opts;
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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

void ImageSource::ContextToAddrInfos(DecodeContext &context, PixelMapAddrInfos &addrInfos)
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

bool IsSupportAstcZeroCopy(const Size &size)
{
    return ImageSystemProperties::GetAstcEnabled() && size.width * size.height >= ASTC_SIZE;
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

bool IsCameraProcess()
{
    static bool isCamera = ImageSystemProperties::IsCamera();
    return isCamera;
}

// LCOV_EXCL_START
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
            || opts.preferDma || IsPhotosLcd() || IsCameraProcess());
    }
    return false;
#endif
}

DecodeContext ImageSource::InitDecodeContext(const DecodeOptions &opts, const ImageInfo &info,
    const MemoryUsagePreference &preference, bool hasDesiredSizeOptions, PlImageInfo& plInfo)
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

    context.info.pixelFormat = plInfo.pixelFormat;
    ImageHdrType hdrType = sourceHdrType_;
    if (opts_.desiredDynamicRange == DecodeDynamicRange::SDR && !IsSingleHdrImage(hdrType)) {
        // If the image is a single-layer HDR, it needs to be decoded into HDR first and then converted into SDR.
        hdrType = ImageHdrType::SDR;
    }
    if (hdrType > ImageHdrType::SDR) {
        // hdr pixelmap need use surfacebuffer.
        context.allocatorType = AllocatorType::DMA_ALLOC;
    }
    context.hdrType = hdrType;
    IMAGE_LOGD("[ImageSource] sourceHdrType_:%{public}d, deocdeHdrType:%{public}d", sourceHdrType_, hdrType);
    if (IsSingleHdrImage(hdrType)) {
        PixelFormat format = PixelFormat::RGBA_1010102;
        if (opts.desiredPixelFormat == PixelFormat::NV12 || opts.desiredPixelFormat == PixelFormat::YCBCR_P010) {
            format = PixelFormat::YCBCR_P010;
        } else if (opts.desiredPixelFormat == PixelFormat::NV21 || opts.desiredPixelFormat == PixelFormat::YCRCB_P010) {
            format = PixelFormat::YCRCB_P010;
        }
        context.pixelFormat = format;
        context.info.pixelFormat = format;
        plInfo.pixelFormat = format;
    }
    return context;
}
// LCOV_EXCL_STOP

uint64_t ImageSource::GetNowTimeMicroSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

static void UpdatePlImageInfo(DecodeContext context, ImagePlugin::PlImageInfo &plInfo)
{
    if (context.hdrType > Media::ImageHdrType::SDR) {
        plInfo.colorSpace = context.colorSpace;
        plInfo.pixelFormat = context.pixelFormat;
    }

    if (plInfo.size.width != context.outInfo.size.width || plInfo.size.height != context.outInfo.size.height) {
        plInfo.size = context.outInfo.size;
    }
    if ((plInfo.pixelFormat == PixelFormat::NV12 || plInfo.pixelFormat == PixelFormat::NV21) &&
        context.yuvInfo.imageSize.width != 0) {
        plInfo.yuvDataInfo = context.yuvInfo;
        plInfo.size = context.yuvInfo.imageSize;
    }
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapExtended(uint32_t index, const DecodeOptions &opts, uint32_t &errorCode)
{
    ImageEvent imageEvent;
    ImageDataStatistics imageDataStatistics("[ImageSource] CreatePixelMapExtended.");
    uint64_t decodeStartTime = GetNowTimeMicroSeconds();
    opts_ = opts;
    ImageInfo info;
    errorCode = GetImageInfo(FIRST_FRAME, info);
    ParseHdrType();
#ifdef IMAGE_QOS_ENABLE
    if (IsSupportSize(info.size) && getpid() != gettid()) {
        OHOS::QOS::SetThreadQos(OHOS::QOS::QosLevel::QOS_USER_INTERACTIVE);
    }
#endif
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
    auto res = ImageAiProcess(info.size, opts, isHdr, context, plInfo);
    if (res != SUCCESS) {
        IMAGE_LOGD("[ImageSource] ImageAiProcess fail, isHdr%{public}d, ret:%{public}u.", isHdr, res);
        if (opts_.resolutionQuality == ResolutionQuality::HIGH && (IsSizeVailed(opts.desiredSize) &&
            (opts_.desiredSize.width != opts.desiredSize.width ||
            opts_.desiredSize.height != opts.desiredSize.height))) {
            opts_.desiredSize.width = opts.desiredSize.width;
            opts_.desiredSize.height = opts.desiredSize.height;
        }
    }
    UpdatePlImageInfo(context, plInfo);

    auto pixelMap = CreatePixelMapByInfos(plInfo, context, errorCode);
    if (pixelMap == nullptr) {
        return nullptr;
    }
    if (!context.ifPartialOutput) {
        NotifyDecodeEvent(decodeListeners_, DecodeEvent::EVENT_COMPLETE_DECODE, nullptr);
    }
    if ("image/gif" != sourceInfo_.encodedFormat && "image/webp" != sourceInfo_.encodedFormat) {
        IMAGE_LOGD("CreatePixelMapExtended success, imageId:%{public}lu, desiredSize: (%{public}d, %{public}d),"
            "imageSize: (%{public}d, %{public}d), hdrType : %{public}d, cost %{public}lu us",
            static_cast<unsigned long>(imageId_), opts.desiredSize.width, opts.desiredSize.height, info.size.width,
            info.size.height, context.hdrType, static_cast<unsigned long>(GetNowTimeMicroSeconds() - decodeStartTime));
    }

    if (CreatExifMetadataByImageSource() == SUCCESS) {
        auto metadataPtr = exifMetadata_->Clone();
        pixelMap->SetExifMetadata(metadataPtr);
    }
    ImageUtils::FlushSurfaceBuffer(pixelMap.get());
    return pixelMap;
}

// LCOV_EXCL_START
static void GetValidCropRect(const Rect &src, ImagePlugin::PlImageInfo &plInfo, Rect &dst)
{
    dst.top = src.top;
    dst.left = src.left;
    dst.width = src.width;
    dst.height = src.height;
    int32_t dstBottom = dst.top + dst.height;
    int32_t dstRight = dst.left + dst.width;
    if (dst.top >= 0 && dstBottom > 0 && dstBottom > plInfo.size.height) {
        dst.height = plInfo.size.height - dst.top;
    }
    if (dst.left >= 0 && dstRight > 0 && dstRight > plInfo.size.width) {
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
// LCOV_EXCL_STOP

bool ImageSource::IsYuvFormat(PixelFormat format)
{
    return format == PixelFormat::NV21 || format == PixelFormat::NV12 ||
        format == PixelFormat::YCRCB_P010 || format == PixelFormat::YCBCR_P010;
}

static void CopyYuvInfo(YUVDataInfo &yuvInfo, ImagePlugin::PlImageInfo &plInfo)
{
    yuvInfo.yWidth = plInfo.yuvDataInfo.yWidth;
    yuvInfo.yHeight = plInfo.yuvDataInfo.yHeight;
    yuvInfo.uvWidth = plInfo.yuvDataInfo.uvWidth;
    yuvInfo.uvHeight = plInfo.yuvDataInfo.uvHeight;
    yuvInfo.yStride = plInfo.yuvDataInfo.yStride;
    yuvInfo.uStride = plInfo.yuvDataInfo.uStride;
    yuvInfo.vStride = plInfo.yuvDataInfo.vStride;
    yuvInfo.uvStride = plInfo.yuvDataInfo.uvStride;
    yuvInfo.yOffset = plInfo.yuvDataInfo.yOffset;
    yuvInfo.uOffset = plInfo.yuvDataInfo.uOffset;
    yuvInfo.vOffset = plInfo.yuvDataInfo.vOffset;
    yuvInfo.uvOffset = plInfo.yuvDataInfo.uvOffset;
}

static bool ResizePixelMap(std::unique_ptr<PixelMap>& pixelMap, uint64_t imageId, DecodeOptions &opts)
{
    ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId);
    if (opts.desiredSize.height != pixelMap->GetHeight() ||
        opts.desiredSize.width != pixelMap->GetWidth()) {
        float xScale = static_cast<float>(opts.desiredSize.width) / pixelMap->GetWidth();
        float yScale = static_cast<float>(opts.desiredSize.height) / pixelMap->GetHeight();
        if (!pixelMap->resize(xScale, yScale)) {
            return false;
        }
        // dump pixelMap after resize
        ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId);
    }
    return true;
}

// LCOV_EXCL_START
// add graphic colorspace object to pixelMap.
void ImageSource::SetPixelMapColorSpace(ImagePlugin::DecodeContext& context, unique_ptr<PixelMap>& pixelMap,
    std::unique_ptr<ImagePlugin::AbsImageDecoder>& decoder)
{
#ifdef IMAGE_COLORSPACE_FLAG
    bool isSupportICCProfile = (decoder == nullptr) ? false : decoder->IsSupportICCProfile();
    if (IsSingleHdrImage(sourceHdrType_)) {
        pixelMap->SetToSdrColorSpaceIsSRGB(false);
    } else {
        if (isSupportICCProfile) {
            pixelMap->SetToSdrColorSpaceIsSRGB(decoder->getGrColorSpace().GetColorSpaceName() == ColorManager::SRGB);
        }
    }
    // If the original image is a single-layer HDR, colorSpace needs to be obtained from the DecodeContext.
    if (context.hdrType > ImageHdrType::SDR || IsSingleHdrImage(sourceHdrType_)) {
        pixelMap->InnerSetColorSpace(OHOS::ColorManager::ColorSpace(context.grColorSpaceName));
        IMAGE_LOGD("hdr set pixelmap colorspace is %{public}d-%{public}d",
            context.grColorSpaceName, pixelMap->InnerGetGrColorSpace().GetColorSpaceName());
        return ;
    }
    if (isSupportICCProfile) {
        OHOS::ColorManager::ColorSpace grColorSpace = decoder->getGrColorSpace();
        pixelMap->InnerSetColorSpace(grColorSpace);
    }
#endif
}
// LCOV_EXCL_STOP

unique_ptr<PixelMap> ImageSource::CreatePixelMapByInfos(ImagePlugin::PlImageInfo &plInfo,
    ImagePlugin::DecodeContext& context, uint32_t &errorCode)
{
    unique_ptr<PixelMap> pixelMap;
    if (IsYuvFormat(plInfo.pixelFormat)) {
#ifdef EXT_PIXEL
        pixelMap = make_unique<PixelYuvExt>();
#else
        pixelMap = make_unique<PixelYuv>();
#endif
    } else {
        pixelMap = make_unique<PixelMap>();
    }
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
    if (!(ResizePixelMap(pixelMap, imageId_, opts_))) {
        IMAGE_LOGE("[ImageSource]Resize pixelmap fail.");
        return nullptr;
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
#if defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    context.allocatorType = AllocatorType::HEAP_ALLOC;
#endif
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
void ImageSource::SetDngImageSize(uint32_t index, ImageInfo &imageInfo)
{
    Size rawSize {0, 0};
    uint32_t exifWidthRet = SUCCESS;
    uint32_t exifHeightRet = SUCCESS;
    if (imageInfo.encodedFormat == IMAGE_FORMAT_RAW) {
        exifWidthRet = GetImagePropertyInt(index, KEY_IMAGE_WIDTH, rawSize.width);
        exifHeightRet = GetImagePropertyInt(index, KEY_IMAGE_HEIGHT, rawSize.height);
    }

    if (rawSize.width != 0 && rawSize.height != 0
        && exifWidthRet == SUCCESS && exifHeightRet == SUCCESS) {
        imageInfo.size.width = rawSize.width;
        imageInfo.size.height = rawSize.height;
    }
}

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

uint32_t ImageSource::GetImageInfoFromExif(uint32_t index, ImageInfo &imageInfo)
{
    ImageTrace imageTrace("GetImageInfoFromExif by index");
    uint32_t ret = SUCCESS;
    std::unique_lock<std::mutex> guard(decodingMutex_);
    auto iter = GetValidImageStatus(index, ret);
    if (iter == imageStatusMap_.end()) {
        guard.unlock();
        IMAGE_LOGE("[ImageSource]get valid image status fail on get image info from exif, ret:%{public}u.", ret);
        return ret;
    }
    ImageInfo &info = (iter->second).imageInfo;
    if (info.size.width == 0 || info.size.height == 0) {
        IMAGE_LOGE("[ImageSource]get the image size fail on get image info from exif, width:%{public}d,"
                   "height:%{public}d.",
                   info.size.width, info.size.height);
        return ERR_IMAGE_DECODE_FAILED;
    }
    imageInfo = info;
    guard.unlock();

    SetDngImageSize(index, imageInfo);
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

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
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

bool ImageSource::PrereadSourceStream()
{
    uint8_t* prereadBuffer = new (std::nothrow) uint8_t[IMAGE_HEADER_SIZE];
    if (prereadBuffer == nullptr) {
        return false;
    }
    uint32_t prereadSize = 0;
    uint32_t savedPosition = sourceStreamPtr_->Tell();
    sourceStreamPtr_->Seek(0);
    bool retRead = sourceStreamPtr_->Read(IMAGE_HEADER_SIZE, prereadBuffer,
                                          IMAGE_HEADER_SIZE, prereadSize);
    sourceStreamPtr_->Seek(savedPosition);
    if (!retRead) {
        IMAGE_LOGE("Preread source stream failed.");
        delete[] prereadBuffer; // Don't forget to delete tmpBuffer if read failed
        return false;
    }
    delete[] prereadBuffer;
    return true;
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

    IMAGE_LOGD("sourceStreamPtr create metadataAccessor");
    if (!PrereadSourceStream()) {
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint32_t bufferSize = sourceStreamPtr_->GetStreamSize();
    auto bufferPtr = sourceStreamPtr_->GetDataPtr();
    if (bufferPtr != nullptr) {
        return CreateExifMetadata(bufferPtr, bufferSize, addFlag);
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
    uint32_t result = CreateExifMetadata(tmpBuffer, bufferSize, addFlag);
    delete[] tmpBuffer; // Don't forget to delete tmpBuffer after using it
    return result;
}

uint32_t ImageSource::CreateExifMetadata(uint8_t *buffer, const uint32_t size, bool addFlag)
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
    if (isExifReadFailed_ && exifMetadata_ == nullptr) {
        return exifReadStatus_;
    }
    uint32_t ret = CreatExifMetadataByImageSource();
    if (ret != SUCCESS) {
        if (key.substr(0, KEY_SIZE) == "Hw") {
            value = DEFAULT_EXIF_VALUE;
            return SUCCESS;
        }
        IMAGE_LOGD("Failed to create Exif metadata "
            "when attempting to get property.");
        isExifReadFailed_ = true;
        exifReadStatus_ = ret;
        return ret;
    }

    return exifMetadata_->GetValue(key, value);
}

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

bool ImageSource::ParseHdrType()
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    uint32_t ret = SUCCESS;
    auto iter = GetValidImageStatus(0, ret);
    if (iter == imageStatusMap_.end()) {
        IMAGE_LOGE("[ImageSource] IsHdrImage, get valid image status fail, ret:%{public}u.", ret);
        return false;
    }
    if (InitMainDecoder() != SUCCESS) {
        IMAGE_LOGE("[ImageSource] IsHdrImage ,get decoder failed");
        return false;
    }
    sourceHdrType_ = mainDecoder_->CheckHdrType();
    return true;
}

bool ImageSource::IsHdrImage()
{
    if (sourceHdrType_ != ImageHdrType::UNKNOWN) {
        return sourceHdrType_ > ImageHdrType::SDR;
    }
    if (!ParseHdrType()) {
        return false;
    }
    return sourceHdrType_ > ImageHdrType::SDR;
}

bool ImageSource::IsSingleHdrImage(ImageHdrType type)
{
    return type == ImageHdrType::HDR_VIVID_SINGLE || type == ImageHdrType::HDR_ISO_SINGLE;
}

bool ImageSource::IsDualHdrImage(ImageHdrType type)
{
    return type == ImageHdrType::HDR_VIVID_DUAL || type == ImageHdrType::HDR_ISO_DUAL || type == ImageHdrType::HDR_CUVA;
}

NATIVEEXPORT std::shared_ptr<ExifMetadata> ImageSource::GetExifMetadata()
{
    if (exifMetadata_ != nullptr) {
        return exifMetadata_;
    }

    if (SUCCESS != CreatExifMetadataByImageSource(false)) {
        return nullptr;
    }

    return exifMetadata_;
}

NATIVEEXPORT void ImageSource::SetExifMetadata(std::shared_ptr<ExifMetadata> &ptr)
{
    exifMetadata_ = ptr;
}

uint32_t ImageSource::RemoveImageProperties(uint32_t index, const std::set<std::string> &keys, const std::string &path)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
uint32_t ImageSource::GetFormatExtended(string &format) __attribute__((no_sanitize("cfi")))
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

uint32_t ImageSource::OnSourceRecognized(bool isAcquiredImageNum) __attribute__((no_sanitize("cfi")))
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
    ret = mainDecoder_->GetImagePropertyString(FIRST_FRAME, ACTUAL_IMAGE_ENCODED_FORMAT, value);
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
// LCOV_EXCL_STOP

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
    Size size;
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

// LCOV_EXCL_START
uint32_t ImageSource::SetDecodeOptions(std::unique_ptr<AbsImageDecoder> &decoder, uint32_t index,
    const DecodeOptions &opts, ImagePlugin::PlImageInfo &plInfo)
{
    PixelDecodeOptions plOptions;
    CopyOptionsToPlugin(opts, plOptions);
    if (opts.desiredPixelFormat == PixelFormat::UNKNOWN) {
        plOptions.desiredPixelFormat = ((preference_ == MemoryUsagePreference::LOW_RAM) ? PixelFormat::RGB_565 : PixelFormat::RGBA_8888);
    } else {
        plOptions.desiredPixelFormat = opts.desiredPixelFormat;
    }

    if ((opts.desiredDynamicRange == DecodeDynamicRange::AUTO && (sourceHdrType_ > ImageHdrType::SDR)) ||
         opts.desiredDynamicRange == DecodeDynamicRange::HDR) {
        plOptions.desiredPixelFormat = PixelFormat::RGBA_8888;
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

        info.pixelFormat = plInfo.pixelFormat;
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
        CopyYuvInfo(yuvInfo, plInfo);
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
    plOpts.desiredPixelFormat = opts.desiredPixelFormat;
    plOpts.desiredColorSpace = opts.desiredColorSpace;
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
// LCOV_EXCL_STOP

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
uint32_t ImageSource::GetFilterArea(const std::vector<std::string> &exifKeys,
                                    std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    if (exifKeys.empty()) {
        IMAGE_LOGD("GetFilterArea failed, exif key is empty.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGD("GetFilterArea failed, sourceStreamPtr is not existed.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint32_t bufferSize = sourceStreamPtr_->GetStreamSize();
    auto bufferPtr = sourceStreamPtr_->GetDataPtr();
    if (bufferPtr != nullptr) {
        auto metadataAccessor = MetadataAccessorFactory::Create(bufferPtr, bufferSize);
        if (metadataAccessor == nullptr) {
            IMAGE_LOGD("Create metadataAccessor failed.");
            return ERR_IMAGE_SOURCE_DATA;
        }
        return metadataAccessor->GetFilterArea(exifKeys, ranges);
    }
    if (bufferSize > MAX_BUFFER_SIZE) {
        IMAGE_LOGE("Invalid buffer size. It's too big. Please check the buffer size.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    auto tmpBuffer = new (std::nothrow) uint8_t[bufferSize];
    if (tmpBuffer == nullptr) {
        IMAGE_LOGE("New buffer failed, bufferSize:%{public}u.", bufferSize);
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint32_t savedPosition = sourceStreamPtr_->Tell();
    sourceStreamPtr_->Seek(0);
    uint32_t readSize = 0;
    bool retRead = sourceStreamPtr_->Read(bufferSize, tmpBuffer, bufferSize, readSize);
    sourceStreamPtr_->Seek(savedPosition);
    if (!retRead) {
        IMAGE_LOGE("SourceStream read failed.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    auto metadataAccessor = MetadataAccessorFactory::Create(tmpBuffer, bufferSize);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGD("Create metadataAccessor failed.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    return metadataAccessor->GetFilterArea(exifKeys, ranges);
}

void ImageSource::SetIncrementalSource(const bool isIncrementalSource)
{
    isIncrementalSource_ = isIncrementalSource;
}

bool ImageSource::IsIncrementalSource()
{
    return isIncrementalSource_;
}

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

bool ImageSource::HasDensityChange(const DecodeOptions &opts, ImageInfo &srcImageInfo, bool hasNinePatch)
{
    return !hasNinePatch && (srcImageInfo.baseDensity > 0) && (opts.fitDensity > 0) &&
        (srcImageInfo.baseDensity != opts.fitDensity);
}

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP
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

// LCOV_EXCL_START
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
    if ((!isSupportOdd) && (static_cast<uint32_t>(sourceOptions_.size.width) & 1) == 1) {
        IMAGE_LOGE("[ImageSource]ConvertYUV420ToRGBA odd width, %{public}d", sourceOptions_.size.width);
        errorCode = ERR_IMAGE_DATA_UNSUPPORT;
        return false;
    }

    const size_t width = static_cast<size_t>(sourceOptions_.size.width);
    const size_t height = static_cast<size_t>(sourceOptions_.size.height);
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
// LCOV_EXCL_STOP

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

    if (!ImageUtils::FloatCompareZero(opts_.rotateDegrees)) {
        pixelMap->rotate(opts_.rotateDegrees);
    } else if (opts_.rotateNewDegrees != INT_ZERO) {
        pixelMap->rotate(opts_.rotateNewDegrees);
    }

    return pixelMap;
}

bool ImageSource::IsASTC(const uint8_t *fileData, size_t fileSize) __attribute__((no_sanitize("cfi")))
{
    if (fileData == nullptr || fileSize < ASTC_HEADER_SIZE) {
        IMAGE_LOGE("[ImageSource]IsASTC fileData incorrect.");
        return false;
    }
    uint32_t magicVal = static_cast<uint32_t>(fileData[NUM_0]) +
        (static_cast<uint32_t>(fileData[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(fileData[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(fileData[NUM_3]) << NUM_24);
    if (magicVal == ASTC_MAGIC_ID) {
        return true;
    }
#ifdef SUT_DECODE_ENABLE
    if (magicVal == SUT_FILE_SIGNATURE) {
        return true;
    }
#endif
    return false;
}

// LCOV_EXCL_START
bool ImageSource::GetImageInfoForASTC(ImageInfo &imageInfo, const uint8_t *sourceFilePtr)
{
    ASTCInfo astcInfo;
    if (!sourceStreamPtr_) {
        IMAGE_LOGE("[ImageSource] get astc image info null.");
        return false;
    }
    if (!GetASTCInfo(sourceFilePtr, sourceStreamPtr_->GetStreamSize(), astcInfo)) {
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
// LCOV_EXCL_STOP

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
    if (g_sutDecSoManager.sutDecSoGetSizeFunc_ != nullptr) {
        return g_sutDecSoManager.sutDecSoGetSizeFunc_(fileBuf, fileSize);
    } else {
        IMAGE_LOGE("sutDecSoGetSizeFunc_ is nullptr!");
        return 0;
    }
}

static bool TextureSuperCompressDecode(const uint8_t *inData, size_t inBytes, uint8_t *outData, size_t outBytes)
{
    size_t preOutBytes = outBytes;
    if ((inData == nullptr) || (outData == nullptr) || (inBytes >= outBytes)) {
        IMAGE_LOGE("astc TextureSuperCompressDecode input check failed!");
        return false;
    }
    if (g_sutDecSoManager.sutDecSoDecFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT dec sutDecSoDecFunc_ is nullptr!");
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
    const uint8_t *sourceFilePtr)
{
#if !(defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM))
    Size desiredSize = {astcSize, 1};
    MemoryData memoryData = {nullptr, astcSize, "CreatePixelMapForASTC Data", desiredSize, pixelAstc->GetPixelFormat()};
    ImageInfo pixelAstcInfo;
    pixelAstc->GetImageInfo(pixelAstcInfo);
    AllocatorType allocatorType = IsSupportAstcZeroCopy(pixelAstcInfo.size) ?
        AllocatorType::DMA_ALLOC : AllocatorType::SHARE_MEM_ALLOC;
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("ReadFileAndResoveAstc CreateMemory failed");
        return false;
    }
    pixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(),
        nullptr);
    bool successMemCpyOrDec = true;
#ifdef SUT_DECODE_ENABLE
    if (fileSize < astcSize) {
        if (TextureSuperCompressDecode(sourceFilePtr, fileSize,
            static_cast<uint8_t*>(dstMemory->data.data), astcSize) != true) {
            IMAGE_LOGE("[ImageSource] astc SuperDecompressTexture failed!");
            successMemCpyOrDec = false;
        }
    } else {
#endif
        if (memcpy_s(dstMemory->data.data, fileSize, sourceFilePtr, fileSize) != 0) {
            IMAGE_LOGE("[ImageSource] astc memcpy_s failed!");
            successMemCpyOrDec = false;
        }
#ifdef SUT_DECODE_ENABLE
    }
#endif
    if (!successMemCpyOrDec) {
        dstMemory->Release();
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
    uint8_t *sourceFilePtr = sourceStreamPtr_->GetDataPtr();
    if (!GetImageInfoForASTC(info, sourceFilePtr)) {
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
    size_t astcSize = GetAstcSizeBytes(sourceFilePtr, fileSize);
    if (astcSize == 0) {
        IMAGE_LOGE("[ImageSource] astc GetAstcSizeBytes failed.");
        return nullptr;
    }
#else
    size_t astcSize = fileSize;
#endif
    if (!ReadFileAndResoveAstc(fileSize, astcSize, pixelAstc, sourceFilePtr)) {
        IMAGE_LOGE("[ImageSource] astc ReadFileAndResoveAstc failed.");
        return nullptr;
    }
    pixelAstc->SetAstc(true);
    ImageUtils::FlushSurfaceBuffer(pixelAstc.get());
    return pixelAstc;
}
#endif

// LCOV_EXCL_START
bool ImageSource::GetASTCInfo(const uint8_t *fileData, size_t fileSize, ASTCInfo &astcInfo)
{
    if (fileData == nullptr || fileSize < ASTC_HEADER_SIZE) {
        IMAGE_LOGE("[ImageSource]GetASTCInfo fileData incorrect.");
        return false;
    }
    uint32_t magicVal = static_cast<uint32_t>(fileData[NUM_0]) +
        (static_cast<uint32_t>(fileData[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(fileData[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(fileData[NUM_3]) << NUM_24);
    if (magicVal == ASTC_MAGIC_ID) {
        unsigned int astcWidth = static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X]) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X + 1]) << NUM_8) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_X + NUM_2]) << NUM_16);
        unsigned int astcHeight = static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y]) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y + 1]) << NUM_8) +
            (static_cast<unsigned int>(fileData[ASTC_HEADER_DIM_Y + NUM_2]) << NUM_16);
        astcInfo.size.width = static_cast<int32_t>(astcWidth);
        astcInfo.size.height = static_cast<int32_t>(astcHeight);
        astcInfo.blockFootprint.width = fileData[ASTC_HEADER_BLOCK_X];
        astcInfo.blockFootprint.height = fileData[ASTC_HEADER_BLOCK_Y];
        return true;
    }
#ifdef SUT_DECODE_ENABLE
    if (g_sutDecSoManager.getTextureInfoFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT dec getTextureInfoFunc_ is nullptr!");
        return false;
    }
    uint32_t blockXY;
    uint32_t width;
    uint32_t height;
    if (g_sutDecSoManager.getTextureInfoFunc_(fileData, fileSize,
        width, height, blockXY)) {
        astcInfo.size.width = width;
        astcInfo.size.height = height;
        astcInfo.blockFootprint.width = blockXY;
        astcInfo.blockFootprint.height = blockXY;
        return true;
    }
#endif
    return false;
}
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

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

// LCOV_EXCL_START
static float GetScaleSize(ImageInfo info, DecodeOptions opts)
{
    if (info.size.width == 0 || info.size.height == 0) {
        return 1.0;
    }
    float scale = max(static_cast<float>(opts.desiredSize.width) / info.size.width,
                      static_cast<float>(opts.desiredSize.height) / info.size.height);
    return scale;
}
// LCOV_EXCL_STOP

static uint32_t GetByteCount(const DecodeContext& context, uint32_t surfaceBufferSize)
{
    uint32_t byteCount = surfaceBufferSize;
    ImageInfo info;
    switch (context.info.pixelFormat) {
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::NV12:
        case PixelFormat::NV21:
        case PixelFormat::RGBA_1010102:
            info.pixelFormat = context.info.pixelFormat;
            break;
        default:
            IMAGE_LOGE("[ImageSource] GetByteCount pixelFormat %{public}u error", context.info.pixelFormat);
            return byteCount;
    }
    info.size.width = context.info.size.width;
    info.size.height = context.info.size.height;
    byteCount = static_cast<uint32_t>(PixelMap::GetAllocatedByteCount(info));
    return byteCount;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool DecomposeImage(sptr<SurfaceBuffer>& hdr, sptr<SurfaceBuffer>& sdr)
{
    ImageTrace iamgeTrace("ImageSource decomposeImage");
    VpeUtils::SetSbMetadataType(hdr, HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbMetadataType(sdr, HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(sdr, HDI::Display::Graphic::Common::V1_0::CM_P3_FULL);
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res = utils->ColorSpaceConverterImageProcess(hdr, sdr);
    if (res != VPE_ERROR_OK || sdr == nullptr) {
        return false;
    }
    return true;
}

// LCOV_EXCL_START
static void SetContext(DecodeContext& context, sptr<SurfaceBuffer>& sb, void* fd, uint32_t format)
{
    context.allocatorType = AllocatorType::DMA_ALLOC;
    context.freeFunc = nullptr;
    context.pixelsBuffer.buffer = static_cast<uint8_t*>(sb->GetVirAddr());
    context.pixelsBuffer.bufferSize = GetByteCount(context, sb->GetSize());
    context.pixelsBuffer.context = fd;
    context.info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    if (format == GRAPHIC_PIXEL_FMT_RGBA_1010102) {
        context.pixelFormat = PixelFormat::RGBA_1010102;
        context.info.pixelFormat = PixelFormat::RGBA_1010102;
        context.grColorSpaceName = ColorManager::BT2020_HLG;
    } else if (format == GRAPHIC_PIXEL_FMT_RGBA_8888) {
        context.pixelFormat = PixelFormat::RGBA_8888;
        context.info.pixelFormat = PixelFormat::RGBA_8888;
        context.grColorSpaceName = ColorManager::DISPLAY_P3;
    } else if (format == GRAPHIC_PIXEL_FMT_YCBCR_420_SP) {
        context.pixelFormat = PixelFormat::NV12;
        context.info.pixelFormat = PixelFormat::NV12;
        context.grColorSpaceName = ColorManager::DISPLAY_P3;
    } else if (format == GRAPHIC_PIXEL_FMT_YCRCB_420_SP) {
        context.pixelFormat = PixelFormat::NV21;
        context.info.pixelFormat = PixelFormat::NV21;
        context.grColorSpaceName = ColorManager::DISPLAY_P3;
    }
}
// LCOV_EXCL_STOP

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
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
        .timeout = 0,
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
    SetContext(context, sb, nativeBuffer, format);
    return SUCCESS;
#endif
}

// LCOV_EXCL_START
CM_ColorSpaceType ImageSource::ConvertColorSpaceType(ColorManager::ColorSpaceName colorSpace, bool base)
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
            return base ? CM_P3_FULL : CM_BT2020_HLG_FULL;
    }
    return base ? CM_P3_FULL : CM_BT2020_HLG_FULL;
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
            return base ? ColorManager::DISPLAY_P3 : ColorManager::BT2020_HLG;
    }
    return base ? ColorManager::DISPLAY_P3 : ColorManager::BT2020_HLG;
}
// LCOV_EXCL_STOP
#endif

void ImageSource::SetDmaContextYuvInfo(DecodeContext& context)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGD("UnSupport SetContextYuvInfo");
    return;
#else
    if (context.allocatorType != AllocatorType::DMA_ALLOC) {
        IMAGE_LOGD("SetDmaContextYuvInfo allocatorType is not dma");
        return;
    }
    PixelFormat format = context.info.pixelFormat;
    if (!IsYuvFormat(format)) {
        IMAGE_LOGI("SetDmaContextYuvInfo format is not yuv");
        return;
    }
    SurfaceBuffer* surfaceBuffer = static_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    if (surfaceBuffer == nullptr) {
        IMAGE_LOGE("SetDmaContextYuvInfo surfacebuffer is nullptr");
        return;
    }
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
        IMAGE_LOGE("SetDmaContextYuvInfo, GetPlanesInfo failed retVal:%{public}d", retVal);
        return;
    }
    const OH_NativeBuffer_Plane &planeY = planes->planes[0];
    const OH_NativeBuffer_Plane &planeUV =
        planes->planes[(format == PixelFormat::NV21 || format == PixelFormat::YCRCB_P010) ? NUM_2 : NUM_1];
    context.yuvInfo.yStride = planeY.columnStride;
    context.yuvInfo.uvStride = planeUV.columnStride;
    context.yuvInfo.yOffset = planeY.offset;
    context.yuvInfo.uvOffset = planeUV.offset;
    context.yuvInfo.imageSize = context.info.size;
#endif
}

DecodeContext ImageSource::HandleSingleHdrImage(ImageHdrType decodedHdrType,
    DecodeContext& context, ImagePlugin::PlImageInfo& plInfo)
{
    SetDmaContextYuvInfo(context);
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGE("UnSupport HandleSingleHdrImage");
    return context;
#else
    if (context.allocatorType != AllocatorType::DMA_ALLOC) {
        return context;
    }
    sptr<SurfaceBuffer> hdrSptr(reinterpret_cast<SurfaceBuffer*>(context.pixelsBuffer.context));
    HdrMetadata metadata = mainDecoder_->GetHdrMetadata(decodedHdrType);
    CM_ColorSpaceType baseCmColor = ConvertColorSpaceType(context.grColorSpaceName, true);
    VpeUtils::SetSurfaceBufferInfo(hdrSptr, false, decodedHdrType, baseCmColor, metadata);
    if (opts_.desiredDynamicRange == DecodeDynamicRange::SDR) {
        DecodeContext sdrCtx;
        sdrCtx.info.size.width = plInfo.size.width;
        sdrCtx.info.size.height = plInfo.size.height;
        sdrCtx.hdrType = ImageHdrType::SDR;
        sdrCtx.outInfo.size = sdrCtx.info.size;
        auto formatSearch = SINGLE_HDR_CONVERT_FORMAT_MAP.find(opts_.desiredPixelFormat);
        auto allocFormat =
            (formatSearch != SINGLE_HDR_CONVERT_FORMAT_MAP.end()) ? formatSearch->second : GRAPHIC_PIXEL_FMT_RGBA_8888;
        uint32_t res = AllocSurfaceBuffer(sdrCtx, allocFormat);
        if (res != SUCCESS) {
            IMAGE_LOGI("single hdr convert to sdr,alloc surfacebuffer failed");
            return context;
        }
        sptr<SurfaceBuffer> sdr(reinterpret_cast<SurfaceBuffer*>(sdrCtx.pixelsBuffer.context));
        if (DecomposeImage(hdrSptr, sdr)) {
            FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
            plInfo = sdrCtx.info;
            SetDmaContextYuvInfo(sdrCtx);
            return sdrCtx;
        }
        FreeContextBuffer(sdrCtx.freeFunc, sdrCtx.allocatorType, sdrCtx.pixelsBuffer);
    }
    return context;
#endif
}

DecodeContext ImageSource::HandleDualHdrImage(ImageHdrType decodedHdrType, ImageInfo info,
    DecodeContext& context, ImagePlugin::PlImageInfo& plInfo)
{
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
    context.hdrType = ImageHdrType::SDR;
    return context;
}

DecodeContext ImageSource::DecodeImageDataToContext(uint32_t index, ImageInfo info, ImagePlugin::PlImageInfo& plInfo,
                                                    uint32_t& errorCode)
{
    DecodeContext context = InitDecodeContext(opts_, info, preference_, hasDesiredSizeOptions, plInfo);
    ImageHdrType decodedHdrType = context.hdrType;
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
    ninePatchInfo_.ninePatch = context.ninePatchContext.ninePatch;
    ninePatchInfo_.patchSize = context.ninePatchContext.patchSize;
    if (errorCode != SUCCESS) {
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        return context;
    }
    if (IsSingleHdrImage(decodedHdrType)) {
        return HandleSingleHdrImage(decodedHdrType, context, plInfo);
    }
    if (IsDualHdrImage(decodedHdrType)) {
        return HandleDualHdrImage(decodedHdrType, info, context, plInfo);
    }
    return context;
}

// LCOV_EXCL_START
uint32_t ImageSource::SetGainMapDecodeOption(std::unique_ptr<AbsImageDecoder>& decoder, PlImageInfo& plInfo,
                                             float scale)
{
    ImageInfo info;
    Size size;
    uint32_t errorCode = decoder->GetImageSize(FIRST_FRAME, size);
    info.size.width = size.width;
    info.size.height = size.height;
    if (errorCode != SUCCESS || !IsSizeVailed({size.width, size.height})) {
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
    plOptions.desiredPixelFormat = PixelFormat::RGBA_8888;
    errorCode = decoder->SetDecodeOptions(FIRST_FRAME, plOptions, plInfo);
    return errorCode;
}
// LCOV_EXCL_STOP

bool GetStreamData(std::unique_ptr<SourceStream>& sourceStream, uint8_t* streamBuffer, uint32_t streamSize)
{
    if (streamBuffer == nullptr) {
        IMAGE_LOGE("GetStreamData streamBuffer is nullptr");
        return false;
    }
    uint32_t readSize = 0;
    uint32_t savedPosition = sourceStream->Tell();
    sourceStream->Seek(0);
    bool result = sourceStream->Read(streamSize, streamBuffer, streamSize, readSize);
    sourceStream->Seek(savedPosition);
    if (!result || (readSize != streamSize)) {
        IMAGE_LOGE("sourceStream read data failed");
        return false;
    }
    return true;
}

bool ImageSource::DecodeJpegGainMap(ImageHdrType hdrType, float scale, DecodeContext& gainMapCtx, HdrMetadata& metadata)
{
    ImageTrace imageTrace("ImageSource::DecodeJpegGainMap hdrType:%d, scale:%d", hdrType, scale);
    uint32_t gainMapOffset = mainDecoder_->GetGainMapOffset();
    uint32_t streamSize = sourceStreamPtr_->GetStreamSize();
    if (gainMapOffset == 0 || gainMapOffset > streamSize || streamSize == 0) {
        return false;
    }
    uint8_t* streamBuffer = sourceStreamPtr_->GetDataPtr();
    if (sourceStreamPtr_->GetStreamType() != ImagePlugin::BUFFER_SOURCE_TYPE) {
        streamBuffer = new (std::nothrow) uint8_t[streamSize];
        if (!GetStreamData(sourceStreamPtr_, streamBuffer, streamSize)) {
            delete[] streamBuffer;
            return false;
        }
    }
    std::unique_ptr<InputDataStream> gainMapStream =
        BufferSourceStream::CreateSourceStream((streamBuffer + gainMapOffset), (streamSize - gainMapOffset));
    if (sourceStreamPtr_->GetStreamType() != ImagePlugin::BUFFER_SOURCE_TYPE) {
        delete[] streamBuffer;
    }
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

// LCOV_EXCL_START
bool ImageSource::ApplyGainMap(ImageHdrType hdrType, DecodeContext& baseCtx, DecodeContext& hdrCtx, float scale)
{
    string format = GetExtendedCodecMimeType(mainDecoder_.get());
    if (format != IMAGE_JPEG_FORMAT && format != IMAGE_HEIF_FORMAT) {
        return false;
    }
    DecodeContext gainMapCtx;
    HdrMetadata metadata;
    if (format == IMAGE_HEIF_FORMAT) {
        ImageTrace imageTrace("ImageSource decode heif gainmap hdrType:%d, scale:%d", hdrType, scale);
        if (!mainDecoder_->DecodeHeifGainMap(gainMapCtx)) {
            IMAGE_LOGI("[ImageSource] heif get gainmap failed");
            return false;
        }
        metadata = mainDecoder_->GetHdrMetadata(hdrType);
    } else if (!DecodeJpegGainMap(hdrType, scale, gainMapCtx, metadata)) {
        IMAGE_LOGI("[ImageSource] jpeg get gainmap failed");
        return false;
    }
    IMAGE_LOGD("get hdr metadata, extend flag is %{public}d, static size is %{public}zu,"
        "dynamic metadata size is %{public}zu",
        metadata.extendMetaFlag, metadata.staticMetadata.size(), metadata.dynamicMetadata.size());
    bool result = ComposeHdrImage(hdrType, baseCtx, gainMapCtx, hdrCtx, metadata);
    FreeContextBuffer(gainMapCtx.freeFunc, gainMapCtx.allocatorType, gainMapCtx.pixelsBuffer);
    return result;
}
// LCOV_EXCL_STOP

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
void ImageSource::SetVividMetaColor(HdrMetadata& metadata,
    CM_ColorSpaceType base, CM_ColorSpaceType gainmap, CM_ColorSpaceType hdr)
{
    metadata.extendMeta.baseColorMeta.baseColorPrimary = base & 0xFF;
    metadata.extendMeta.gainmapColorMeta.enhanceDataColorPrimary = gainmap & 0xFF;
    metadata.extendMeta.gainmapColorMeta.combineColorPrimary = gainmap & 0xFF;
    metadata.extendMeta.gainmapColorMeta.alternateColorPrimary = hdr & 0xFF;
}

// LCOV_EXCL_START
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
    SetContext(context, sb, nativeBuffer, GRAPHIC_PIXEL_FMT_RGBA_1010102);
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
// LCOV_EXCL_STOP
#endif

bool ImageSource::ComposeHdrImage(ImageHdrType hdrType, DecodeContext& baseCtx, DecodeContext& gainMapCtx,
                                  DecodeContext& hdrCtx, HdrMetadata metadata)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    IMAGE_LOGE("unsupport hdr");
    return false;
#else
    ImageTrace imageTrace("ImageSource::ComposeHdrImage hdr type is %d", hdrType);
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
    IMAGE_LOGD("ComposeHdrImage color flag = %{public}d, gainmapChannelNum = %{public}d",
        metadata.extendMeta.metaISO.useBaseColorFlag, metadata.extendMeta.metaISO.gainmapChannelNum);
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
        IMAGE_LOGI("[ImageSource] composeImage failed");
        FreeContextBuffer(hdrCtx.freeFunc, hdrCtx.allocatorType, hdrCtx.pixelsBuffer);
        return false;
    }
    return true;
#endif
}

// LCOV_EXCL_START
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
// LCOV_EXCL_STOP

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool CopyRGBAToSurfaceBuffer(const DecodeContext& context, sptr<SurfaceBuffer>& sb, PlImageInfo plInfo)
{
    if (context.info.pixelFormat != PixelFormat::RGBA_8888 &&
        context.info.pixelFormat != PixelFormat::BGRA_8888) {
        return false;
    }
    uint8_t* srcRow = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    uint8_t* dstRow = static_cast<uint8_t*>(sb->GetVirAddr());
    if (srcRow == nullptr || dstRow == nullptr) {
        return false;
    }
    if (sb->GetStride() < 0) {
        return false;
    }
    uint64_t dstStride = sb->GetStride();
    uint64_t srcStride = static_cast<uint64_t>(plInfo.size.width * NUM_4);
    uint32_t dstHeight = static_cast<uint32_t>(plInfo.size.height);
    for (uint32_t i = 0; i < dstHeight; i++) {
        errno_t err = memcpy_s(dstRow, dstStride, srcRow, srcStride);
        if (err != EOK) {
            IMAGE_LOGE("copy data failed");
            return false;
        }
        srcRow += srcStride;
        dstRow += dstStride;
    }
    return true;
}

static bool CopyYUVToSurfaceBuffer(const DecodeContext& context, sptr<SurfaceBuffer>& buffer, PlImageInfo plInfo)
{
    if (context.info.pixelFormat != PixelFormat::NV12 &&
        context.info.pixelFormat != PixelFormat::NV21) {
        return false;
    }
    uint8_t* srcRow = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    uint8_t* dstRow = static_cast<uint8_t*>(buffer->GetVirAddr());
    size_t dstSize = buffer->GetSize();
    if (buffer->GetStride() < 0) {
        return false;
    }
    YUVDataInfo yuvDataInfo = context.yuvInfo;
    IMAGE_LOGD("[ImageSource] CopyYUVToSurfaceBuffer yHeight = %{public}d, uvHeight = %{public}d,"
        "yStride = %{public}d, uvStride = %{public}d, dstSize = %{public}zu, dstStride = %{public}d",
        yuvDataInfo.yHeight, yuvDataInfo.uvHeight, yuvDataInfo.yStride, yuvDataInfo.uvStride,
        dstSize, buffer->GetStride());
    for (uint32_t i = 0; i < yuvDataInfo.yHeight; ++i) {
        if (memcpy_s(dstRow, dstSize, srcRow, yuvDataInfo.yStride) != EOK) {
            return false;
        }
        dstRow += buffer->GetStride();
        dstSize -= buffer->GetStride();
        srcRow += yuvDataInfo.yStride;
    }
    for (uint32_t i = 0; i < yuvDataInfo.uvHeight; ++i) {
        if (memcpy_s(dstRow, dstSize, srcRow, yuvDataInfo.uvStride) != EOK) {
            return false;
        }
        dstRow += buffer->GetStride();
        dstSize -= buffer->GetStride();
        srcRow += yuvDataInfo.uvStride;
    }
    return true;
}

static uint32_t CopyContextIntoSurfaceBuffer(Size dstSize, const DecodeContext &context, DecodeContext &dstCtx,
    ImagePlugin::PlImageInfo& plInfo)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("UnSupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    IMAGE_LOGD("[ImageSource]CopyContextIntoSurfaceBuffer requestConfig, sizeInfo.width:%{public}u,height:%{public}u.",
        context.info.size.width, context.info.size.height);
    GraphicPixelFormat format = GRAPHIC_PIXEL_FMT_RGBA_8888;
    if (context.info.pixelFormat == PixelFormat::NV21) {
        format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCRCB_420_SP;
    } else if (context.info.pixelFormat == PixelFormat::NV12) {
        format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    } else if (context.info.pixelFormat == PixelFormat::BGRA_8888) {
        format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_BGRA_8888;
    } else if (context.info.pixelFormat != PixelFormat::RGBA_8888) {
        IMAGE_LOGI("CopyContextIntoSurfaceBuffer pixelformat %{public}d is unsupport", context.pixelFormat);
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    BufferRequestConfig requestConfig = {
        .width = context.info.size.width,
        .height = context.info.size.height,
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = format, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_MEM_MMZ_CACHE,
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
    if ((!CopyRGBAToSurfaceBuffer(context, sb, plInfo)) && (!CopyYUVToSurfaceBuffer(context, sb, plInfo))) {
        return ERR_IMAGE_DATA_UNSUPPORT;
    }
    SetContext(dstCtx, sb, nativeBuffer, format);
    return SUCCESS;
#endif
}

static uint32_t DoAiHdrProcess(sptr<SurfaceBuffer> &input, DecodeContext &hdrCtx,
                               CM_ColorSpaceType cmColorSpaceType)
{
    VpeUtils::SetSbMetadataType(input, CM_METADATA_NONE);
    VpeUtils::SetSurfaceBufferInfo(input, cmColorSpaceType);
    hdrCtx.info.size.width = static_cast<uint32_t>(input->GetWidth());
    hdrCtx.info.size.height = static_cast<uint32_t>(input->GetHeight());
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
        hdrCtx.outInfo.size.width = output->GetWidth();
        hdrCtx.outInfo.size.height = output->GetHeight();
        hdrCtx.pixelFormat = PixelFormat::RGBA_1010102;
        hdrCtx.info.pixelFormat = PixelFormat::RGBA_1010102;
        hdrCtx.allocatorType = AllocatorType::DMA_ALLOC;
    }
    return res;
}

static uint32_t AiSrProcess(sptr<SurfaceBuffer> &input, DecodeContext &aisrCtx)
{
    uint32_t res = AllocSurfaceBuffer(aisrCtx, input->GetFormat());
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
        aisrCtx.outInfo.size.width = output->GetSurfaceBufferWidth();
        aisrCtx.outInfo.size.height = output->GetSurfaceBufferHeight();
        aisrCtx.yuvInfo.imageSize.width = aisrCtx.outInfo.size.width;
        aisrCtx.yuvInfo.imageSize.height = aisrCtx.outInfo.size.height;
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
        || imageSize.width != opts.desiredSize.width) && opts.resolutionQuality != ResolutionQuality::UNKNOWN)
        || opts.resolutionQuality == ResolutionQuality::HIGH) {
        IMAGE_LOGD("[ImageSource] IsNecessaryAiProcess needAisr");
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
    dstCtx.grColorSpaceName = srcCtx.grColorSpaceName;
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
    dstCtx.grColorSpaceName = srcCtx.grColorSpaceName;
    dstCtx.yuvInfo.imageSize.width = srcCtx.outInfo.size.width;
    dstCtx.yuvInfo.imageSize.height = srcCtx.outInfo.size.height;
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
    if (needHdr && (dstCtx.info.pixelFormat == PixelFormat::NV12 ||
        dstCtx.info.pixelFormat == PixelFormat::NV21 ||
        dstCtx.info.pixelFormat == PixelFormat::RGBA_8888)) {
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

uint32_t ImageSource::ImageAiProcess(Size imageSize, const DecodeOptions &opts, bool isHdr, DecodeContext &context,
    ImagePlugin::PlImageInfo &plInfo)
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
        auto res = CopyContextIntoSurfaceBuffer(imageSize, context, srcCtx, plInfo);
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
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        CopyOutInfoOfContext(dstCtx, context);
    }
    FreeContextBuffer(srcCtx.freeFunc, srcCtx.allocatorType, srcCtx.pixelsBuffer);
    return res;
#endif
}

DecodeContext ImageSource::DecodeImageDataToContextExtended(uint32_t index, ImageInfo &info,
    ImagePlugin::PlImageInfo &plInfo, ImageEvent &imageEvent, uint32_t &errorCode)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    hasDesiredSizeOptions = IsSizeVailed(opts_.desiredSize);
    TransformSizeWithDensity(info.size, sourceInfo_.baseDensity, opts_.desiredSize, opts_.fitDensity,
        opts_.desiredSize);
    DecodeOptions tmpOpts = opts_;
    if (opts_.resolutionQuality == ResolutionQuality::HIGH) {
        tmpOpts.desiredSize = info.size;
    }
    errorCode = SetDecodeOptions(mainDecoder_, index, tmpOpts, plInfo);
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

std::unique_ptr<Picture> ImageSource::CreatePicture(const DecodingOptionsForPicture &opts, uint32_t &errorCode)
{
    DecodeOptions dopts;
    dopts.desiredPixelFormat = PixelFormat::RGBA_8888;
    dopts.desiredDynamicRange = (ParseHdrType() && IsSingleHdrImage(sourceHdrType_)) ?
        DecodeDynamicRange::HDR : DecodeDynamicRange::SDR;
    std::shared_ptr<PixelMap> mainPixelMap = CreatePixelMap(dopts, errorCode);
    std::unique_ptr<Picture> picture = Picture::Create(mainPixelMap);
    if (picture == nullptr) {
        IMAGE_LOGE("Picture is nullptr");
        errorCode = ERR_IMAGE_PICTURE_CREATE_FAILED;
        return nullptr;
    }

    string format = GetExtendedCodecMimeType(mainDecoder_.get());
    if (format != IMAGE_HEIF_FORMAT && format != IMAGE_JPEG_FORMAT) {
        IMAGE_LOGE("CreatePicture failed, unsupport format: %{public}s", format.c_str());
        errorCode = ERR_IMAGE_MISMATCHED_FORMAT;
        return nullptr;
    }

    std::set<AuxiliaryPictureType> auxTypes = (opts.desireAuxiliaryPictures.size() > 0) ?
            opts.desireAuxiliaryPictures : ImageUtils::GetAllAuxiliaryPictureType();
    if (format == IMAGE_HEIF_FORMAT) {
        DecodeHeifAuxiliaryPictures(auxTypes, picture, errorCode);
    } else if (format == IMAGE_JPEG_FORMAT) {
        DecodeJpegAuxiliaryPicture(auxTypes, picture, errorCode);
    }

    return picture;
}

void ImageSource::DecodeHeifAuxiliaryPictures(
    const std::set<AuxiliaryPictureType> &auxTypes, std::unique_ptr<Picture> &picture, uint32_t &errorCode)
{
    if (mainDecoder_ == nullptr) {
        IMAGE_LOGE("mainDecoder_ is nullptr");
        errorCode = ERR_IMAGE_PLUGIN_CREATE_FAILED;
        return;
    }
    for (auto& auxType : auxTypes) {
        if (!mainDecoder_->CheckAuxiliaryMap(auxType)) {
            IMAGE_LOGE("The auxiliary picture type does not exist! Type: %{public}d", auxType);
            continue;
        }
        auto auxiliaryPicture = AuxiliaryGenerator::GenerateAuxiliaryPicture(
            sourceHdrType_, auxType, IMAGE_HEIF_FORMAT, mainDecoder_, errorCode);
        if (auxiliaryPicture == nullptr) {
            IMAGE_LOGE("Generate heif auxiliary picture failed! Type: %{public}d, errorCode: %{public}d",
                auxType, errorCode);
        } else {
            picture->SetAuxiliaryPicture(auxiliaryPicture);
        }
    }
}

void ImageSource::DecodeJpegAuxiliaryPicture(
    const std::set<AuxiliaryPictureType> &auxTypes, std::unique_ptr<Picture> &picture, uint32_t &errorCode)
{
    uint8_t *streamBuffer = sourceStreamPtr_->GetDataPtr();
    uint32_t streamSize = sourceStreamPtr_->GetStreamSize();
    uint32_t mpfOffset = 0;
    auto jpegMpfParser = std::make_unique<JpegMpfParser>();
    if (!jpegMpfParser->CheckMpfOffset(streamBuffer, streamSize, mpfOffset)) {
        IMAGE_LOGE("Jpeg calculate mpf offset failed! mpfOffset: %{public}u", mpfOffset);
        errorCode = ERR_IMAGE_DECODE_HEAD_ABNORMAL;
        return;
    }
    if (!jpegMpfParser->Parsing(streamBuffer + mpfOffset, streamSize - mpfOffset)) {
        IMAGE_LOGE("Jpeg parse mpf data failed!");
        errorCode = ERR_IMAGE_DECODE_HEAD_ABNORMAL;
        return;
    }

    uint32_t preOffset = mpfOffset + JPEG_MPF_IDENTIFIER_SIZE;
    for (auto &auxInfo : jpegMpfParser->images_) {
        if (auxTypes.find(auxInfo.auxType) != auxTypes.end()) {
            IMAGE_LOGI("Jpeg auxiliary picture has found. Type: %{public}d", auxInfo.auxType);
            std::unique_ptr<InputDataStream> auxStream =
                BufferSourceStream::CreateSourceStream((streamBuffer + preOffset + auxInfo.offset), auxInfo.size);
            if (auxStream == nullptr) {
                IMAGE_LOGE("Create auxiliary stream fail, auxiliary offset is %{public}u", auxInfo.offset);
                continue;
            }
            auto auxDecoder = std::unique_ptr<AbsImageDecoder>(
                DoCreateDecoder(InnerFormat::IMAGE_EXTENDED_CODEC, pluginServer_, *auxStream, errorCode));
            auto auxPicture = AuxiliaryGenerator::GenerateAuxiliaryPicture(
                sourceHdrType_, auxInfo.auxType, IMAGE_JPEG_FORMAT, auxDecoder, errorCode);
            if (auxPicture == nullptr) {
                IMAGE_LOGE("Generate jepg auxiliary picture failed!, errorCode: %{public}d", errorCode);
            } else {
                picture->SetAuxiliaryPicture(auxPicture);
            }
        }
    }
}

} // namespace Media
} // namespace OHOS
