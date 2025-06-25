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
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <mutex>
#include <vector>

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "auxiliary_generator.h"
#include "auxiliary_picture.h"
#endif

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
#include "image_format_convert.h"
#include "image_log.h"
#include "image_packer.h"
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
#include "display/graphic/common/v2_1/cm_color_space.h"
#include "vpe_utils.h"
#endif
#ifdef USE_M133_SKIA
#include "src/base/SkBase64.h"
#else
#include "include/utils/SkBase64.h"
#endif
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
#include "v4_0/codec_types.h"
#include "v4_0/icodec_component_manager.h"
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
using CM_ColorSpaceType_V2_1 = OHOS::HDI::Display::Graphic::Common::V2_1::CM_ColorSpaceType;

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
const string IMAGE_EXTENDED_CODEC = "image/jpeg,image/png,image/webp,image/x-icon,image/gif,image/bmp";
const string SVG_FORMAT = "image/svg+xml";
} // namespace InnerFormat
// BASE64 image prefix type data:image/<type>;base64,<data>
static const std::string IMAGE_URL_PREFIX = "data:image/";
static const std::string BASE64_URL_PREFIX = ";base64,";
static const std::string KEY_IMAGE_WIDTH = "ImageWidth";
static const std::string KEY_IMAGE_HEIGHT = "ImageLength";
static const std::string IMAGE_FORMAT_RAW = "image/raw";
static const std::string DNG_FORMAT = "image/x-adobe-dng";
static const uint32_t FIRST_FRAME = 0;
static const int INT_ZERO = 0;
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
static const uint32_t ASTC_MAGIC_ID = 0x5CA1AB13;
static const int ASTC_SIZE = 512 * 512;
static const size_t ASTC_HEADER_SIZE = 16;
static const uint8_t ASTC_HEADER_BLOCK_X = 4;
static const uint8_t ASTC_HEADER_BLOCK_Y = 5;
static const uint8_t ASTC_HEADER_DIM_X = 7;
static const uint8_t ASTC_HEADER_DIM_Y = 10;
static const int IMAGE_HEADER_SIZE = 12;
static const uint32_t MAX_SOURCE_SIZE = 300 * 1024 * 1024;
constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM = 1; // curren only one group TLV
constexpr uint8_t ASTC_EXTEND_INFO_TLV_NUM6 = 6; // curren only six group TLV
constexpr uint32_t ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH = 4; // 4 bytes to discripte for extend info summary bytes
constexpr uint32_t ASTC_EXTEND_INFO_LENGTH_LENGTH = 4; // 4 bytes to discripte the content bytes for every TLV group
constexpr uint32_t ASTC_EXTEND_INFO_TLV_SUM_BYTES_L1 = 6; // The colorspace TLV length in the astc file stream is 6
constexpr uint32_t ASTC_EXTEND_INFO_TLV_SUM_BYTES_L2 = 12; // The colorspace TLV length in the astc file stream is 12
constexpr uint32_t ASTC_EXTEND_INFO_TLV_NUM6_SUM_BYTES = 32; // 2 sizeof(TLV) + 4 * TLV_LEAST_BYTES
constexpr uint8_t TLV_LEAST_BYTES = 5; // sizeof(uint8_t) + sizeof(uint32_t)
constexpr size_t MAX_INT32 = 2147483647; // int32 max 2147483647
constexpr int32_t ASTC_MAX_SIZE = 8192;
constexpr size_t ASTC_TLV_SIZE = 10; // 10 is tlv size, colorspace size
constexpr uint8_t ASTC_OPTION_QUALITY = 85;
static constexpr uint32_t SINGLE_FRAME_SIZE = 1;
static constexpr uint8_t ISO_USE_BASE_COLOR = 0x01;
constexpr int32_t DEFAULT_DMA_SIZE = 512 * 512;
constexpr int32_t DMA_ALLOC = 1;
constexpr int32_t SHARE_MEMORY_ALLOC = 2;
constexpr int32_t AUTO_ALLOC = 0;
constexpr uint8_t GAINMAP_CHANNEL_NUM_ONE = 0x01;
static constexpr uint8_t JPEG_SOI[] = { 0xFF, 0xD8, 0xFF };
constexpr uint8_t PIXEL_BYTES = 4;

struct StreamInfo {
    uint8_t* buffer = nullptr;
    uint32_t size = 0;
    uint32_t gainmapOffset = 0;
    bool needDelete = false;    // Require the buffer allocation type to be HEAP ALLOC

    uint8_t* GetCurrentAddress()
    {
        return buffer + gainmapOffset;
    }

    uint32_t GetCurrentSize()
    {
        if (size >= gainmapOffset) {
            return size - gainmapOffset;
        } else {
            return 0;
        }
    }

    ~StreamInfo()
    {
        if (needDelete && buffer != nullptr) {
            delete[] buffer;
            buffer = nullptr;
        }
    }
};

#ifdef SUT_DECODE_ENABLE
constexpr uint8_t ASTC_HEAD_BYTES = 16;
constexpr uint8_t SUT_HEAD_BYTES = 16
constexpr uint32_t SUT_FILE_SIGNATURE = 0x5CA1AB13;
#ifdef SUT_PATH_X64
static const std::string g_textureSuperDecSo = "/system/lib64/module/hms/graphic/libtextureSuperDecompress.z.so";
#else
static const std::string g_textureSuperDecSo = "/system/lib/module/hms/graphic/libtextureSuperDecompress.z.so";
#endif
constexpr uint8_t EXPAND_ASTC_INFO_MAX_DEC = 16; // reserve max 16 groups TLV info

struct AstcOutInfo {
    uint8_t *astcBuf;
    int32_t astcBytes;
    uint8_t expandNums; // groupNum of TLV extInfo
    uint8_t expandInfoType[EXPAND_ASTC_INFO_MAX_DEC];
    int32_t expandInfoBytes[EXPAND_ASTC_INFO_MAX_DEC];
    uint8_t *expandInfoBuf[EXPAND_ASTC_INFO_MAX_DEC];
    int32_t expandInfoCapacity[EXPAND_ASTC_INFO_MAX_DEC];
    int32_t expandTotalBytes;
    int32_t pureSutBytes;
};

struct SutInInfo {
    const uint8_t *sutBuf;
    int32_t sutBytes;
};

using GetSuperCompressAstcSize = size_t (*)(const uint8_t *, size_t);
using SuperDecompressTexture = bool (*)(const SutInInfo &, AstcOutInfo &);
using IsSut = bool (*)(const uint8_t *, size_t);
using GetTextureInfoFromSut = bool (*)(const uint8_t *, size_t, uint32_t &, uint32_t &, uint32_t &);
using GetExpandInfoFromSut = bool (*)(const SutInInfo &, AstcOutInfo &, bool);
class SutDecSoManager {
public:
    SutDecSoManager();
    ~SutDecSoManager();
    bool LoadSutDecSo();
    GetSuperCompressAstcSize sutDecSoGetSizeFunc_;
    SuperDecompressTexture sutDecSoDecFunc_;
    GetTextureInfoFromSut getTextureInfoFunc_;
    GetExpandInfoFromSut getExpandInfoFromSutFunc_;
private:
    bool sutDecSoOpened_;
    void *textureDecSoHandle_;
    void DlcloseHandle();
    std::mutex sutDecSoMutex_ = {};
};

static SutDecSoManager g_sutDecSoManager;

SutDecSoManager::SutDecSoManager()
{
    sutDecSoOpened_ = false;
    textureDecSoHandle_ = nullptr;
    sutDecSoGetSizeFunc_ = nullptr;
    sutDecSoDecFunc_ = nullptr;
    getTextureInfoFunc_ = nullptr;
    getExpandInfoFromSutFunc_ = nullptr;
}

SutDecSoManager::~SutDecSoManager()
{
    bool cond = (!sutDecSoOpened_ || textureDecSoHandle_ == nullptr);
    CHECK_DEBUG_RETURN_LOG(cond, "[ImageSource] astcenc dec so is not be opened when dlclose!");
    cond = dlclose(textureDecSoHandle_) != 0;
    CHECK_ERROR_RETURN_LOG(cond, "[ImageSource] astcenc dlclose failed: %{public}s!", g_textureSuperDecSo.c_str());
}

static bool CheckClBinIsExist(const std::string &name)
{
    return (access(name.c_str(), F_OK) != -1); // -1 means that the file is  not exist
}

void SutDecSoManager::DlcloseHandle()
{
    if (textureDecSoHandle_ != nullptr) {
        dlclose(textureDecSoHandle_);
        textureDecSoHandle_ = nullptr;
    }
}

bool SutDecSoManager::LoadSutDecSo()
{
    std::lock_guard<std::mutex> lock(sutDecSoMutex_);
    if (!sutDecSoOpened_) {
        bool cond = CheckClBinIsExist(g_textureSuperDecSo);
        CHECK_ERROR_RETURN_RET_LOG(!cond, false, "[ImageSource] %{public}s! is not found", g_textureSuperDecSo.c_str());
        textureDecSoHandle_ = dlopen(g_textureSuperDecSo.c_str(), 1);
        cond = (textureDecSoHandle_ == nullptr);
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] astc libtextureSuperDecompress dlopen failed!");
        sutDecSoGetSizeFunc_ =
            reinterpret_cast<GetSuperCompressAstcSize>(dlsym(textureDecSoHandle_, "GetSuperCompressAstcSize"));
        if (sutDecSoGetSizeFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetSuperCompressAstcSize dlsym failed!");
            DlcloseHandle();
            return false;
        }
        sutDecSoDecFunc_ =
            reinterpret_cast<SuperDecompressTexture>(dlsym(textureDecSoHandle_, "SuperDecompressTextureTlv"));
        if (sutDecSoDecFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc SuperDecompressTextureTlv dlsym failed!");
            DlcloseHandle();
            return false;
        }
        getTextureInfoFunc_ =
            reinterpret_cast<GetTextureInfoFromSut>(dlsym(textureDecSoHandle_, "GetTextureInfoFromSut"));
        if (getTextureInfoFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetTextureInfoFromSut dlsym failed!");
            DlcloseHandle();
            return false;
        }
        getExpandInfoFromSutFunc_ =
            reinterpret_cast<GetExpandInfoFromSut>(dlsym(textureDecSoHandle_, "GetExpandInfoFromSut"));
        if (getExpandInfoFromSutFunc_ == nullptr) {
            IMAGE_LOGE("[ImageSource] astc GetExpandInfoFromSut dlsym failed!");
            DlcloseHandle();
            return false;
        }
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

PluginServer &ImageSource::pluginServer_ = ImageUtils::GetPluginServer();
ImageSource::FormatAgentMap ImageSource::formatAgentMap_ = InitClass();

#ifdef HEIF_HW_DECODE_ENABLE
static bool IsSecureMode(const std::string &name)
{
    std::string prefix = ".secure";
    bool cond = name.length() <= prefix.length();
    CHECK_ERROR_RETURN_RET(cond, false);
    return name.rfind(prefix) == (name.length() - prefix.length());
}
#endif

static bool IsSupportHeif()
{
#ifdef HEIF_HW_DECODE_ENABLE
    sptr<HDI::Codec::V4_0::ICodecComponentManager> manager =
            HDI::Codec::V4_0::ICodecComponentManager::Get(false);
    bool cond = manager == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    int32_t compCnt = 0;
    int32_t ret = manager->GetComponentNum(compCnt);
    cond = (ret != HDF_SUCCESS || compCnt <= 0);
    CHECK_ERROR_RETURN_RET(cond, false);
    std::vector<HDI::Codec::V4_0::CodecCompCapability> capList(compCnt);
    ret = manager->GetComponentCapabilityList(capList, compCnt);
    cond = (ret != HDF_SUCCESS || capList.empty());
    CHECK_ERROR_RETURN_RET(cond, false);
    for (const auto& cap : capList) {
        if (cap.role == HDI::Codec::V4_0::MEDIA_ROLETYPE_VIDEO_HEVC &&
            cap.type == HDI::Codec::V4_0::VIDEO_DECODER && !IsSecureMode(cap.compName)) {
            return true;
        }
    }
#endif
    return false;
}

void ImageSource::InitDecoderForJpeg()
{
    uint8_t* readBuffer = new (std::nothrow) uint8_t[sizeof(JPEG_SOI)];
    if (readBuffer == nullptr) {
        return;
    }
    uint32_t readSize = 0;
    uint32_t savedPosition = sourceStreamPtr_->Tell();
    sourceStreamPtr_->Seek(0);
    bool retRead = sourceStreamPtr_->Read(sizeof(JPEG_SOI), readBuffer, sizeof(JPEG_SOI), readSize);
    sourceStreamPtr_->Seek(savedPosition);
    if (!retRead) {
        IMAGE_LOGE("Preread source stream failed.");
        delete[] readBuffer;
        readBuffer = nullptr;
        return;
    }
    if (std::memcmp(JPEG_SOI, readBuffer, sizeof(JPEG_SOI)) == 0) {
        IMAGE_LOGI("stream is jpeg stream.");
        delete[] readBuffer;
        mainDecoder_->InitJpegDecoder();
        readBuffer = nullptr;
        return;
    }
    delete[] readBuffer;
    readBuffer = nullptr;
}

uint32_t ImageSource::GetSupportedFormats(set<string> &formats)
{
    IMAGE_LOGD("[ImageSource]get supported image type.");
    formats.clear();
    vector<ClassInfo> classInfos;
    uint32_t ret =
        pluginServer_.PluginServerGetClassInfo<AbsImageDecoder>(AbsImageDecoder::SERVICE_DEFAULT, classInfos);
    bool cond = ret != SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, ret,
                               "[ImageSource]get class info from plugin server failed, ret:%{public}u.", ret);

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
            formats.insert(DNG_FORMAT);
        } else {
            std::vector<std::string> splitedVector;
            SplitStr(*format, ",", splitedVector);
            for (std::string item : splitedVector) {
                formats.insert(item);
            }
        }
    }

    static bool isSupportHeif = IsSupportHeif();
    if (isSupportHeif) {
        formats.insert(ImageUtils::GetEncodedHeifFormat());
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
    uint32_t &errorCode, bool isUserBuffer)
{
    if (size > MAX_SOURCE_SIZE) {
        IMAGE_LOGE("%{public}s input size %{public}u is too large.", __func__, size);
        errorCode = ERR_IMAGE_TOO_LARGE;
        return nullptr;
    }
    IMAGE_LOGD("[ImageSource]create Imagesource with buffer.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with buffer.");
    if (data == nullptr || size == 0) {
        IMAGE_LOGE("[ImageSource]parameter error.");
        errorCode = ERR_MEDIA_INVALID_PARAM;
        return nullptr;
    }
    auto imageSource = DoImageSourceCreate(
        [&data, &size, &isUserBuffer]() {
            auto streamPtr = DecodeBase64(data, size);
            if (streamPtr == nullptr) {
                streamPtr = BufferSourceStream::CreateSourceStream(data, size, isUserBuffer);
            }
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create buffer source stream.");
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by data");
    if (imageSource != nullptr) {
        imageSource->SetSrcBuffer(data, size);
    }
    return imageSource;
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
    auto imageSource = DoImageSourceCreate(
        [&pathName]() {
            auto streamPtr = DecodeBase64(pathName);
            if (streamPtr == nullptr) {
                streamPtr = FileSourceStream::CreateSourceStream(pathName);
            }
            bool cond = (streamPtr == nullptr);
            CHECK_DEBUG_PRINT_LOG(cond, "[ImageSource]failed to create file path source stream");
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by path");
    if (imageSource != nullptr) {
        imageSource->SetSrcFilePath(pathName);
    }
    return imageSource;
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with fd.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with fd.");
    auto imageSource = DoImageSourceCreate(
        [&fd]() {
            auto streamPtr = FileSourceStream::CreateSourceStream(fd);
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create file fd source stream.");
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by fd");
    if (imageSource != nullptr) {
        imageSource->SetSrcFd(fd);
    }
    return imageSource;
}

unique_ptr<ImageSource> ImageSource::CreateImageSource(const int fd, int32_t offset, int32_t length,
    const SourceOptions &opts, uint32_t &errorCode)
{
    IMAGE_LOGD("[ImageSource]create Imagesource with fd offset and length.");
    ImageDataStatistics imageDataStatistics("[ImageSource]CreateImageSource with offset.");
    auto imageSource = DoImageSourceCreate(
        [&fd, offset, length]() {
            auto streamPtr = FileSourceStream::CreateSourceStream(fd, offset, length);
            if (streamPtr == nullptr) {
                IMAGE_LOGE("[ImageSource]failed to create file fd source stream.");
            }
            return streamPtr;
        },
        opts, errorCode, "CreateImageSource by fd offset and length");
    if (imageSource != nullptr) {
        imageSource->SetSrcFd(fd);
    }
    return imageSource;
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
            bool cond = streamPtr == nullptr;
            CHECK_ERROR_PRINT_LOG(cond, "[ImageSource]failed to create incremental source stream.");
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
    bool cond = mainDecoder_ != nullptr && mainDecoder_->HasProperty(SKIA_DECODER);
    CHECK_ERROR_RETURN(cond);
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

#if !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    if (!isAstc_.has_value()) {
        ImagePlugin::DataStreamBuffer outData;
        uint32_t res = GetData(outData, ASTC_HEADER_SIZE);
        if (res == SUCCESS) {
            isAstc_ = IsASTC(outData.inputStreamBuffer, outData.dataSize);
        }
    }
    if (isAstc_.has_value() && isAstc_.value()) {
        return CreatePixelMapForASTC(errorCode, opts);
    }
#endif

    if (opts.desiredPixelFormat == PixelFormat::ASTC_4x4) {
        return CreatePixelAstcFromImageFile(index, opts, errorCode);
    }

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
    bool cond = decoder != nullptr && decoder->HasProperty(ENCODED_FORMAT_KEY);
    CHECK_ERROR_RETURN_RET(cond, true);
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
    bool cond = srcDensity != 0;
    int32_t ret = (prop * wantDensity + (srcDensity >> 1)) / srcDensity;
    CHECK_ERROR_RETURN_RET(cond, ret);
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

bool ImageSource::IsDecodeHdrImage(const DecodeOptions &opts)
{
    ParseHdrType();
    return (opts.desiredDynamicRange == DecodeDynamicRange::AUTO && sourceHdrType_ > ImageHdrType::SDR) ||
        opts.desiredDynamicRange == DecodeDynamicRange::HDR;
}

bool ImageSource::IsSvgUseDma(const DecodeOptions &opts)
{
    ImageInfo info;
    GetImageInfo(FIRST_FRAME, info);
    return info.encodedFormat == IMAGE_SVG_FORMAT && opts.allocatorType == AllocatorType::DMA_ALLOC;
}

AllocatorType ImageSource::ConvertAutoAllocatorType(const DecodeOptions &opts)
{
    ImageInfo info;
    GetImageInfo(FIRST_FRAME, info);
    ParseHdrType();
    if (IsDecodeHdrImage(opts)) {
        return AllocatorType::DMA_ALLOC;
    }
    if (info.encodedFormat == IMAGE_SVG_FORMAT) {
        return AllocatorType::SHARE_MEM_ALLOC;
    }
    if (ImageUtils::IsSizeSupportDma(info.size)) {
        return AllocatorType::DMA_ALLOC;
    }
    return AllocatorType::SHARE_MEM_ALLOC;
}

static AllocatorType ConvertAllocatorType(ImageSource *imageSource, int32_t allocatorType, DecodeOptions& decodeOpts)
{
    switch (allocatorType) {
        case DMA_ALLOC:
            return AllocatorType::DMA_ALLOC;
        case SHARE_MEMORY_ALLOC:
            return AllocatorType::SHARE_MEM_ALLOC;
        case AUTO_ALLOC:
        default:
            return imageSource->ConvertAutoAllocatorType(decodeOpts);
    }
}

bool ImageSource::IsSupportAllocatorType(DecodeOptions& decOps, int32_t allocatorType)
{
    decOps.isAppUseAllocator = true;
    decOps.allocatorType = ConvertAllocatorType(this, allocatorType, decOps);
    if (decOps.allocatorType == AllocatorType::SHARE_MEM_ALLOC && IsDecodeHdrImage(decOps)) {
        IMAGE_LOGE("%{public}s Hdr image can't use share memory allocator", __func__);
        return false;
    } else if (IsSvgUseDma(decOps)) {
        IMAGE_LOGE("%{public}s Svg image can't use dma allocator", __func__);
        return false;
    }
    return true;
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
            buffer.buffer = nullptr;
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

void ImageSource::ContextToAddrInfos(DecodeContext &context, PixelMapAddrInfos &addrInfos)
{
    addrInfos.addr = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    addrInfos.context = static_cast<uint8_t *>(context.pixelsBuffer.context);
    addrInfos.size = context.pixelsBuffer.bufferSize;
    addrInfos.type = context.allocatorType;
    addrInfos.func = context.freeFunc;
}

bool IsSupportAstcZeroCopy(const Size &size)
{
    return ImageSystemProperties::GetAstcEnabled() && size.width * size.height >= ASTC_SIZE;
}

bool IsSupportDma(const DecodeOptions &opts, const ImageInfo &info, bool hasDesiredSizeOptions)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("Unsupport dma mem alloc");
    return false;
#else
    // used for test surfacebuffer
    bool cond = ImageSystemProperties::GetSurfaceBufferEnabled() &&
        ImageUtils::IsSizeSupportDma(hasDesiredSizeOptions ? opts.desiredSize : info.size);
    CHECK_ERROR_RETURN_RET(cond, true);

    if (ImageSystemProperties::GetDmaEnabled() && ImageUtils::IsFormatSupportDma(opts.desiredPixelFormat)) {
        return ImageUtils::IsSizeSupportDma(hasDesiredSizeOptions ? opts.desiredSize : info.size) &&
            (ImageUtils::IsWidthAligned(opts.desiredSize.width)
            || opts.preferDma);
    }
    return false;
#endif
}

DecodeContext ImageSource::InitDecodeContext(const DecodeOptions &opts, const ImageInfo &info,
    const MemoryUsagePreference &preference, bool hasDesiredSizeOptions, PlImageInfo& plInfo)
{
    DecodeContext context;
    context.photoDesiredPixelFormat = opts.photoDesiredPixelFormat;
    context.isCreateWideGamutSdrPixelMap = opts.isCreateWideGamutSdrPixelMap;
    if (opts.allocatorType != AllocatorType::DEFAULT) {
        context.allocatorType = opts.allocatorType;
    } else {
        if ((preference == MemoryUsagePreference::DEFAULT && IsSupportDma(opts, info, hasDesiredSizeOptions)) ||
            info.encodedFormat == IMAGE_HEIF_FORMAT || info.encodedFormat == IMAGE_HEIC_FORMAT ||
            ImageSystemProperties::GetDecodeDmaEnabled()) {
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
    if ((plInfo.pixelFormat == PixelFormat::NV12 || plInfo.pixelFormat == PixelFormat::NV21 ||
         plInfo.pixelFormat == PixelFormat::YCBCR_P010 || plInfo.pixelFormat == PixelFormat::YCRCB_P010) &&
        context.yuvInfo.imageSize.width != 0) {
        plInfo.yuvDataInfo = context.yuvInfo;
        plInfo.size = context.yuvInfo.imageSize;
    }
}

bool NeedConvertToYuv(PixelFormat optsPixelFormat, PixelFormat curPixelFormat)
{
    return (optsPixelFormat == PixelFormat::NV12 || optsPixelFormat == PixelFormat::NV21) && (
        curPixelFormat == PixelFormat::RGBA_8888 || curPixelFormat == PixelFormat::ARGB_8888 ||
        curPixelFormat == PixelFormat::RGB_565 || curPixelFormat == PixelFormat::BGRA_8888 ||
        curPixelFormat == PixelFormat::RGB_888);
}

bool ImageSource::CheckAllocatorTypeValid(const DecodeOptions &opts)
{
    if (opts.isAppUseAllocator && opts.allocatorType == AllocatorType::SHARE_MEM_ALLOC && IsDecodeHdrImage(opts)) {
        IMAGE_LOGE("HDR image can't use SHARE_MEM_ALLOC");
        return false;
    }
    return true;
}

bool IsSrcRectContainsDistRect(const Rect &srcRect, const Rect &dstRect)
{
    if (srcRect.left < 0 || srcRect.top < 0 || srcRect.width <= 0 || srcRect.height <= 0) {
        return false;
    }
    if (dstRect.left < 0 || dstRect.top < 0 || dstRect.width <= 0 || dstRect.height <= 0) {
        return false;
    }
    return srcRect.left <= dstRect.left && srcRect.top <= dstRect.top &&
        (srcRect.left + srcRect.width) >= (dstRect.left + dstRect.width) &&
        (srcRect.top + srcRect.height) >= (dstRect.top + dstRect.height);
}

bool ImageSource::CheckCropRectValid(const DecodeOptions &opts)
{
    Rect srcRect = {0, 0, 0, 0};
    if (opts.cropAndScaleStrategy == CropAndScaleStrategy::DEFAULT) {
        return true;
    }
    ImageInfo info;
    if (GetImageInfo(FIRST_FRAME, info) != SUCCESS) {
        return false;
    }
    srcRect.width = info.size.width;
    srcRect.height = info.size.height;
    if (opts.cropAndScaleStrategy == CropAndScaleStrategy::SCALE_FIRST &&
        (opts.desiredSize.width != 0 || opts.desiredSize.height != 0)) {
        srcRect.width = opts.desiredSize.width;
        srcRect.height = opts.desiredSize.height;
    }
    return IsSrcRectContainsDistRect(srcRect, opts.CropRect);
}

bool ImageSource::CheckDecodeOptions(const DecodeOptions &opts)
{
    return CheckAllocatorTypeValid(opts) && CheckCropRectValid(opts);
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
    if (!CheckDecodeOptions(opts)) {
        IMAGE_LOGI("CheckDecodeOptions failed.");
        errorCode = ERR_MEDIA_INVALID_OPERATION;
        return nullptr;
    }
#ifdef IMAGE_QOS_ENABLE
    if (ImageUtils::IsSizeSupportDma(info.size) && getpid() != gettid()) {
        OHOS::QOS::SetThreadQos(OHOS::QOS::QosLevel::QOS_USER_INTERACTIVE);
    }
#endif
    SetDecodeInfoOptions(index, opts, info, imageEvent);
    std::string pluginType = mainDecoder_->GetPluginType();
    imageEvent.SetPluginType(pluginType);
    Size heifGridTileSize = mainDecoder_->GetHeifGridTileSize();
    imageEvent.SetHeifGridTileSize(heifGridTileSize.width, heifGridTileSize.height);
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

    {
        std::unique_lock<std::mutex> guard(decodingMutex_);
        if (CreatExifMetadataByImageSource() == SUCCESS) {
            auto metadataPtr = exifMetadata_->Clone();
            pixelMap->SetExifMetadata(metadataPtr);
        }
    }
    if (NeedConvertToYuv(opts.desiredPixelFormat, pixelMap->GetPixelFormat())) {
        uint32_t convertRes = ImageFormatConvert::RGBConvertImageFormatOptionUnique(
            pixelMap, plInfo.pixelFormat, opts_.desiredPixelFormat);
        CHECK_ERROR_PRINT_LOG(convertRes != SUCCESS, "convert rgb to yuv failed, return origin rgb!");
    }
    return pixelMap;
}

static void GetValidCropRect(const Rect &src, const Size& size, Rect &dst)
{
    dst.top = src.top;
    dst.left = src.left;
    dst.width = src.width;
    dst.height = src.height;
    int32_t dstBottom = dst.top + dst.height;
    int32_t dstRight = dst.left + dst.width;
    if (dst.top >= 0 && dstBottom > 0 && dstBottom > size.height) {
        dst.height = size.height - dst.top;
    }
    if (dst.left >= 0 && dstRight > 0 && dstRight > size.width) {
        dst.width = size.width - dst.left;
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
        if (ImageSource::IsYuvFormat(pixelMap->GetPixelFormat())) {
#ifdef EXT_PIXEL
            auto pixelYuv = reinterpret_cast<PixelYuvExt *>(pixelMap.get());
            bool cond = !pixelYuv->resize(opts.desiredSize.width, opts.desiredSize.height);
            CHECK_ERROR_RETURN_RET(cond, false);
#else
            auto pixelYuv = reinterpret_cast<PixelYuv *>(pixelMap.get());
            bool cond = !pixelYuv->resize(opts.desiredSize.width, opts.desiredSize.height);
            CHECK_ERROR_RETURN_RET(cond, false);
#endif
        } else {
            float xScale = static_cast<float>(opts.desiredSize.width) / pixelMap->GetWidth();
            float yScale = static_cast<float>(opts.desiredSize.height) / pixelMap->GetHeight();
            bool cond = !pixelMap->resize(xScale, yScale);
            CHECK_ERROR_RETURN_RET(cond, false);
        }
        // dump pixelMap after resize
        ImageUtils::DumpPixelMapIfDumpEnabled(pixelMap, imageId);
    }
    return true;
}

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
            pixelMap->SetToSdrColorSpaceIsSRGB(decoder->GetPixelMapColorSpace().GetColorSpaceName() ==
            ColorManager::SRGB);
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
        OHOS::ColorManager::ColorSpace grColorSpace = decoder->GetPixelMapColorSpace();
        pixelMap->InnerSetColorSpace(grColorSpace);
    }
#endif
}

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
    pixelMap->SetPixelsAddr(addrInfos.addr, addrInfos.context, addrInfos.size, addrInfos.type, addrInfos.func);
    errorCode = UpdatePixelMapInfo(opts_, plInfo, *(pixelMap.get()), opts_.fitDensity, true);
    bool cond = errorCode != SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "[ImageSource]update pixelmap info error ret:%{public}u.", errorCode);
    auto saveEditable = pixelMap->IsEditable();
    pixelMap->SetEditable(true);
    // Need check pixel change:
    // 1. pixel size
    // 2. crop
    // 3. density
    // 4. rotate
    // 5. format
    if (opts_.cropAndScaleStrategy == CropAndScaleStrategy::SCALE_FIRST) {
        if (!(ResizePixelMap(pixelMap, imageId_, opts_))) {
            IMAGE_LOGE("[ImageSource]Resize pixelmap fail.");
            return nullptr;
        }
    }
    const static string SUPPORT_CROP_KEY = "SupportCrop";
    if (opts_.CropRect.width > INT_ZERO && opts_.CropRect.height > INT_ZERO) {
        if (!mainDecoder_->HasProperty(SUPPORT_CROP_KEY)) {
            Rect crop;
            GetValidCropRect(opts_.CropRect, {pixelMap->GetWidth(), pixelMap->GetHeight()}, crop);
            errorCode = pixelMap->crop(crop);
            if (errorCode != SUCCESS) {
                IMAGE_LOGE("[ImageSource]CropRect pixelmap fail, ret:%{public}u.", errorCode);
                return nullptr;
            }
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
    if (opts_.cropAndScaleStrategy != CropAndScaleStrategy::SCALE_FIRST &&
        !(ResizePixelMap(pixelMap, imageId_, opts_))) {
        IMAGE_LOGE("[ImageSource]Resize pixelmap fail.");
        return nullptr;
    }
    pixelMap->SetEditable(saveEditable);
    pixelMap->UpdatePixelsAlphaType(pixelMap);
    // add graphic colorspace object to pixelMap.
    SetPixelMapColorSpace(context, pixelMap, mainDecoder_);
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
    options.photoDesiredPixelFormat = static_cast<int32_t>(opts.photoDesiredPixelFormat);
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
    bool cond = heifParseErr_ == 0;
    CHECK_ERROR_RETURN(cond);
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
            InitDecoderForJpeg();
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
    std::string pluginType = mainDecoder_->GetPluginType();
    imageEvent.SetPluginType(pluginType);
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

    pixelMap->SetPixelsAddr(context.pixelsBuffer.buffer, context.pixelsBuffer.context, context.pixelsBuffer.bufferSize,
        context.allocatorType, context.freeFunc);

#ifdef IMAGE_COLORSPACE_FLAG
    // add graphic colorspace object to pixelMap.
    bool isSupportICCProfile = mainDecoder_->IsSupportICCProfile();
    if (isSupportICCProfile) {
        OHOS::ColorManager::ColorSpace grColorSpace = mainDecoder_->GetPixelMapColorSpace();
        pixelMap->InnerSetColorSpace(grColorSpace);
    }
#endif

    DecodeOptions procOpts;
    CopyOptionsToProcOpts(opts_.cropAndScaleStrategy == CropAndScaleStrategy::DEFAULT ? opts_ : opts, procOpts,
        *(pixelMap.get()));
    if (context.allocatorType != procOpts.allocatorType) {
        procOpts.allocatorType = context.allocatorType;
    }
    PostProc postProc;
    errorCode = postProc.DecodePostProc(procOpts, *(pixelMap.get()), finalOutputStep);
    bool cond = (errorCode != SUCCESS);
    CHECK_ERROR_RETURN_RET(cond, nullptr);

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
    bool cond = (imageStatusIter == imageStatusMap_.end());
    CHECK_ERROR_RETURN_RET_LOG(cond,
        ret, "[ImageSource]get valid image status fail on promote decoding, ret:%{public}u.", ret);
    auto incrementalRecordIter = incDecodingMap_.find(&pixelMap);
    if (incrementalRecordIter == incDecodingMap_.end()) {
        ret = AddIncrementalContext(pixelMap, incrementalRecordIter);
        cond = ret != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond,
            ret, "[ImageSource]failed to add context on incremental decoding, ret:%{public}u.", ret);
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
    cond = incrementalRecordIter->second.IncrementalState == ImageDecodingState::IMAGE_ERROR;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_ABNORMAL,
        "[ImageSource]invalid imageState %{public}d on incremental decoding.",
        incrementalRecordIter->second.IncrementalState);
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
    bool cond = (size > MAX_SOURCE_SIZE);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_TOO_LARGE,
                               "%{public}s input size %{public}u is too large.",  __func__, size);
    ImageDataStatistics imageDataStatistics("[ImageSource]UpdateData");
    cond = sourceStreamPtr_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_INVALID_PARAMETER,
                               "[ImageSource]image source update data, source stream is null.");
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
        IMAGE_LOGD("[ImageSource]get valid image status fail on get image info, ret:%{public}u.", ret);
        return ret;
    }
    ImageInfo &info = (iter->second).imageInfo;
    bool cond = (info.size.width == 0 || info.size.height == 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_DECODE_FAILED,
                               "[ImageSource]get the image size fail on get image info, width:%{public}d,"
                               "height:%{public}d.", info.size.width, info.size.height);
    imageInfo = info;
    return SUCCESS;
}

uint64_t ImageSource::GetImageId()
{
    return imageId_;
}

uint32_t ImageSource::GetImageInfoFromExif(uint32_t index, ImageInfo &imageInfo)
{
    return GetImageInfo(index, imageInfo);
}


uint32_t ImageSource::ModifyImageProperty(const std::string &key, const std::string &value)
{
    uint32_t ret = CreatExifMetadataByImageSource(true);
    bool cond = (ret != SUCCESS);
    CHECK_DEBUG_RETURN_RET_LOG(cond, ret, "Failed to create Exif metadata "
                           "when attempting to modify property.");
    if (!exifMetadata_->SetValue(key, value)) {
        return ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    return SUCCESS;
}

uint32_t ImageSource::ModifyImageProperty(std::shared_ptr<MetadataAccessor> metadataAccessor,
    const std::string &key, const std::string &value)
{
    if (srcFd_ != -1) {
        size_t fileSize = 0;
        if (!ImageUtils::GetFileSize(srcFd_, fileSize)) {
            IMAGE_LOGE("ModifyImageProperty accessor start get file size failed.");
        } else {
            IMAGE_LOGI("ModifyImageProperty accessor start fd file size:%{public}llu",
                static_cast<unsigned long long>(fileSize));
        }
    }
    uint32_t ret = ModifyImageProperty(key, value);
    bool cond = (ret != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, ret, "Failed to create ExifMetadata.");

    cond = metadataAccessor == nullptr;
    ret = ERR_IMAGE_SOURCE_DATA;
    CHECK_ERROR_RETURN_RET_LOG(cond, ret,
                               "Failed to create image accessor when attempting to modify image property.");

    if (srcFd_ != -1) {
        size_t fileSize = 0;
        if (!ImageUtils::GetFileSize(srcFd_, fileSize)) {
            IMAGE_LOGE("ModifyImageProperty accessor end get file size failed.");
        } else {
            IMAGE_LOGI("ModifyImageProperty accessor end fd file size:%{public}llu",
                static_cast<unsigned long long>(fileSize));
        }
    }
    metadataAccessor->Set(exifMetadata_);
    IMAGE_LOGI("ModifyImageProperty accesssor modify start");
    ret = metadataAccessor->Write();
    IMAGE_LOGI("ModifyImageProperty accesssor modify end");
    return ret;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value)
{
    std::unique_lock<std::mutex> guard(decodingMutex_);
    return ModifyImageProperty(key, value);
}

uint32_t ImageSource::ModifyImagePropertyEx(uint32_t index, const std::string &key, const std::string &value)
{
    if (srcFd_ != -1) {
        return ModifyImageProperty(index, key, value, srcFd_);
    }

    if (!srcFilePath_.empty()) {
        return ModifyImageProperty(index, key, value, srcFilePath_);
    }

    if (srcBuffer_ != nullptr && srcBufferSize_ != 0) {
        return ModifyImageProperty(index, key, value, srcBuffer_, srcBufferSize_);
    }
    return ERROR;
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
    const std::string &path)
{
    ImageDataStatistics imageDataStatistics("[ImageSource]ModifyImageProperty by path.");

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::error_code ec;
    bool cond = (!std::filesystem::exists(path, ec));
    CHECK_ERROR_RETURN_RET_LOG(cond,
                               ERR_IMAGE_SOURCE_DATA,
                               "File not exists, error: %{public}d, message: %{public}s",
                               ec.value(), ec.message().c_str());
#endif

    std::unique_lock<std::mutex> guard(decodingMutex_);
    auto metadataAccessor = MetadataAccessorFactory::Create(path);
    return ModifyImageProperty(metadataAccessor, key, value);
}

uint32_t ImageSource::ModifyImageProperty(uint32_t index, const std::string &key, const std::string &value,
    const int fd)
{
    ImageDataStatistics imageDataStatistics("[ImageSource]ModifyImageProperty by fd.");
    bool cond = (fd <= STDERR_FILENO);
    CHECK_DEBUG_RETURN_RET_LOG(cond, ERR_IMAGE_SOURCE_DATA, "Invalid file descriptor.");

    std::unique_lock<std::mutex> guard(decodingMutex_);
    size_t fileSize = 0;
    if (!ImageUtils::GetFileSize(fd, fileSize)) {
        IMAGE_LOGE("ModifyImageProperty get file size failed.");
    }
    IMAGE_LOGI("ModifyImageProperty accesssor create start, fd file size:%{public}llu",
        static_cast<unsigned long long>(fileSize));
    auto metadataAccessor = MetadataAccessorFactory::Create(fd);
    IMAGE_LOGI("ModifyImageProperty accesssor create end");

    auto ret = ModifyImageProperty(metadataAccessor, key, value);
    return ret;
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
        uint32_t ret = CreateExifMetadata(bufferPtr, bufferSize, addFlag, true);
        if (ret != ERR_MEDIA_MMAP_FILE_CHANGED) {
            return ret;
        }
    }

    if (bufferSize == 0) {
        IMAGE_LOGE("Invalid buffer size. It's zero. Please check the buffer size.");
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (bufferSize > MAX_SOURCE_SIZE) {
        IMAGE_LOGE("Invalid buffer size. It's too big. Please check the buffer size.");
        return ERR_IMAGE_SOURCE_DATA;
    }
    uint32_t error = SUCCESS;
    auto tmpBuffer = ReadSourceBuffer(bufferSize, error);
    if (tmpBuffer == nullptr) {
        return error;
    }
    uint32_t result = CreateExifMetadata(tmpBuffer, bufferSize, addFlag);
    if (result == ERR_MEDIA_MMAP_FILE_CHANGED) {
        result = ERR_IMAGE_SOURCE_DATA;
    }
    delete[] tmpBuffer; // Don't forget to delete tmpBuffer after using it
    return result;
}

uint32_t ImageSource::CreateExifMetadata(uint8_t *buffer, const uint32_t size, bool addFlag, bool hasOriginalFd)
{
    uint32_t error = SUCCESS;
    DataInfo dataInfo {buffer, size};
    std::shared_ptr<MetadataAccessor> metadataAccessor;
    if (hasOriginalFd) {
        metadataAccessor = MetadataAccessorFactory::Create(dataInfo, error, BufferMetadataStream::Fix,
                                                           sourceStreamPtr_->GetOriginalFd(),
                                                           sourceStreamPtr_->GetOriginalPath());
    } else {
        metadataAccessor = MetadataAccessorFactory::Create(dataInfo, error, BufferMetadataStream::Fix);
    }

    if (metadataAccessor == nullptr) {
        IMAGE_LOGD("metadataAccessor nullptr return ERR");
        return error == ERR_MEDIA_MMAP_FILE_CHANGED ? error : ERR_IMAGE_SOURCE_DATA;
    }

    uint32_t ret = metadataAccessor->Read();
    if (ret != SUCCESS && !addFlag) {
        IMAGE_LOGD("get metadataAccessor ret %{public}d", ret);
        return metadataAccessor->IsFileSizeChanged() ? ERR_MEDIA_MMAP_FILE_CHANGED : ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
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
    std::unique_lock<std::mutex> guardFile(fileMutex_);
    return GetImagePropertyCommon(index, key, value);
}

uint32_t ImageSource::GetImagePropertyStringBySync(uint32_t index, const std::string &key, std::string &value)
{
    CHECK_ERROR_RETURN_RET(key.empty(), Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT);

    uint32_t ret = SUCCESS;
    if (IMAGE_GIFLOOPCOUNT_TYPE.compare(key) == ZERO) {
        IMAGE_LOGD("GetImagePropertyString special key: %{public}s", key.c_str());
        (void)GetFrameCount(ret);
        if (ret != SUCCESS || mainDecoder_ == nullptr) {
            IMAGE_LOGE("[ImageSource]GetFrameCount get frame sum error.");
            return ret;
        } else {
            ret = mainDecoder_->GetImagePropertyString(index, key, value);
            CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ret,
                "[ImageSource]GetLoopCount get loop count issue. errorCode=%{public}u", ret);
        }
        return ret;
    }

    std::unique_lock<std::mutex> guard(decodingMutex_);
    std::unique_lock<std::mutex> guardFile(fileMutex_);
    bool cond = isExifReadFailed_ && exifMetadata_ == nullptr;
    CHECK_ERROR_RETURN_RET(cond, exifReadStatus_);
    ret = CreatExifMetadataByImageSource();
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

    cond = exifMetadata_->GetValue(key, value) != SUCCESS;
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_PROPERTY_NOT_EXIST);
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
        if (listener == nullptr) {
            IMAGE_LOGE("Attempted to destory a null listener "
                "from decode listeners.");
        } else {
            listener->OnPeerDestory();
        }
    }
    if (srcFd_ != -1) {
        close(srcFd_);
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
    return type == ImageHdrType::HDR_VIVID_DUAL || type == ImageHdrType::HDR_ISO_DUAL || type == ImageHdrType::HDR_CUVA
        || type == ImageHdrType::HDR_LOG_DUAL;
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
        IMAGE_LOGD("[ImageSource]check mismatched format :%{public}s.", agent.GetFormatType().c_str());
        return ERR_IMAGE_MISMATCHED_FORMAT;
    }
    return SUCCESS;
}

uint32_t ImageSource::GetData(ImagePlugin::DataStreamBuffer &outData, size_t size) __attribute__((no_sanitize("cfi")))
{
    std::unique_lock<std::mutex> guard(fileMutex_);
    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGE("[ImageSource]check image format, source stream is null.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (!sourceStreamPtr_->Peek(size, outData)) {
        IMAGE_LOGE("[ImageSource]stream peek the data fail, imageId %{public}" PRIu64 ", desiredSize:%{public}zu",
            imageId_, size);
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
        IMAGE_LOGD("Failed to get extended format. Error code: %{public}d.", errorCode);
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
    if (mainDecoder_ == nullptr) {
        IMAGE_LOGE("MainDecoder is null. errno:%{public}d", errno);
        return ERR_MEDIA_NULL_POINTER;
    }
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
            IMAGE_LOGD("[ImageSource]checkEncodedFormat error, type: %{public}d", ret);
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
            IMAGE_LOGD("[ImageSource]OnSourceRecognized image source error.");
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
            IMAGE_LOGD("[ImageSource]OnSourceUnresolved image source error.");
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
            IMAGE_LOGD("[ImageSource]unresolved source: check format failed, ret:[%{public}d].", ret);
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
        IMAGE_LOGD("[ImageSource]decode the image fail, ret:%{public}d.", ret);
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
    if (decoder == nullptr) {
        IMAGE_LOGE("decoder is nullptr");
        return ERROR;
    }
    
    bool isDecodeHdrImage = (opts.desiredDynamicRange == DecodeDynamicRange::AUTO &&
                            (sourceHdrType_ > ImageHdrType::SDR)) ||
                            opts.desiredDynamicRange == DecodeDynamicRange::HDR;
    bool isVpeSupport10BitOutputFormat = (opts.photoDesiredPixelFormat == PixelFormat::YCBCR_P010 ||
                                          opts.photoDesiredPixelFormat == PixelFormat::RGBA_1010102);
    if (opts.photoDesiredPixelFormat != PixelFormat::UNKNOWN) {
        bool cond = (isDecodeHdrImage && !isVpeSupport10BitOutputFormat) ||
            (!isDecodeHdrImage && isVpeSupport10BitOutputFormat);
        CHECK_ERROR_RETURN_RET_LOG(cond, COMMON_ERR_INVALID_PARAMETER,
            "Photos provided a error parameter");
        plOptions.desiredPixelFormat = opts.photoDesiredPixelFormat;
        if (opts.photoDesiredPixelFormat == PixelFormat::YCBCR_P010) {
            // if need 10bit yuv, set plOptions to nv21
            plOptions.desiredPixelFormat = PixelFormat::NV21;
        }
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

    if (IsYuvFormat(info.pixelFormat)) {
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
    plOpts.plReusePixelmap = opts.reusePixelmap;
    plOpts.cropAndScaleStrategy = opts.cropAndScaleStrategy;
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
    procOpts.cropAndScaleStrategy = opts.cropAndScaleStrategy;
}

ImageSource::ImageStatusMap::iterator ImageSource::GetValidImageStatus(uint32_t index, uint32_t &errorCode)
{
    auto iter = imageStatusMap_.find(index);
    if (iter == imageStatusMap_.end()) {
        errorCode = DecodeImageInfo(index, iter);
        if (errorCode != SUCCESS) {
            IMAGE_LOGD("[ImageSource]image info decode fail, ret:%{public}u.", errorCode);
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
        IMAGE_LOGI("[ImageSource]mainDecoder move to context.");
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
    std::string pluginType = recordContext.decoder->GetPluginType();
    imageEvent.SetPluginType(pluginType);
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

uint8_t* ImageSource::ReadSourceBuffer(uint32_t bufferSize, uint32_t &errorCode)
{
    if (bufferSize > MAX_SOURCE_SIZE) {
        IMAGE_LOGE("Invalid buffer size. It's too big. Please check the buffer size.");
        errorCode = ERR_IMAGE_SOURCE_DATA;
        return nullptr;
    }
    auto tmpBuffer = new (std::nothrow) uint8_t[bufferSize];
    if (tmpBuffer == nullptr) {
        IMAGE_LOGE("New buffer failed, bufferSize:%{public}u.", bufferSize);
        errorCode = ERR_IMAGE_SOURCE_DATA;
        return nullptr;
    }
    uint32_t savedPosition = sourceStreamPtr_->Tell();
    sourceStreamPtr_->Seek(0);
    uint32_t readSize = 0;
    bool retRead = sourceStreamPtr_->Read(bufferSize, tmpBuffer, bufferSize, readSize);
    sourceStreamPtr_->Seek(savedPosition);
    if (!retRead) {
        IMAGE_LOGE("SourceStream read failed.");
        delete[] tmpBuffer;
        errorCode = ERR_IMAGE_SOURCE_DATA;
        return nullptr;
    }
    errorCode = SUCCESS;
    return tmpBuffer;
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
            return E_NO_EXIF_TAG;
        }
        return metadataAccessor->GetFilterArea(exifKeys, ranges);
    }
    uint32_t error = SUCCESS;
    auto tmpBuffer = ReadSourceBuffer(bufferSize, error);
    if (tmpBuffer == nullptr) {
        return error;
    }

    auto metadataAccessor = MetadataAccessorFactory::Create(tmpBuffer, bufferSize);
    if (metadataAccessor == nullptr) {
        IMAGE_LOGD("Create metadataAccessor failed.");
        delete[] tmpBuffer;
        return E_NO_EXIF_TAG;
    }
    auto ret = metadataAccessor->GetFilterArea(exifKeys, ranges);
    delete[] tmpBuffer;
    return ret;
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

char *strnstr(const char *data, const char *base64Url, size_t len)
{
    size_t base64UrlLen = strlen(base64Url);
    while (len >= base64UrlLen) {
        len--;
        if (!memcmp(data, base64Url, base64UrlLen))
            return (char *)data;
        data++;
    }
    return nullptr;
}

unique_ptr<SourceStream> ImageSource::DecodeBase64(const uint8_t *data, uint32_t size)
{
    if (size < IMAGE_URL_PREFIX.size() ||
        ::memcmp(data, IMAGE_URL_PREFIX.c_str(), IMAGE_URL_PREFIX.size()) != INT_ZERO) {
        IMAGE_LOGD("[ImageSource]Base64 image header mismatch.");
        return nullptr;
    }
    if (size > MAX_SOURCE_SIZE) {
        IMAGE_LOGE("%{public}s input size %{public}u is too large.", __func__, size);
        return nullptr;
    }
    const char *data1 = reinterpret_cast<const char *>(data);
    auto sub = strnstr(data1, BASE64_URL_PREFIX.c_str(), static_cast<size_t>(size));
    if (sub == nullptr) {
        IMAGE_LOGI("[ImageSource]Base64 mismatch.");
        return nullptr;
    }
    sub = sub + BASE64_URL_PREFIX.size();
    uint32_t subSize = size - (sub - data1);
    IMAGE_LOGD("[ImageSource]Base64 image input: size %{public}u.", subSize);
    if (subSize == 0) {
        IMAGE_LOGE("%{public}s input subsize is %{public}u.", __func__, subSize);
        return nullptr;
    }

    std::unique_ptr<uint8_t[]> dataCopy;
    if (sub[subSize - 1] != '\0') {
        dataCopy = make_unique<uint8_t[]>(subSize + 1);
        if (dataCopy == nullptr) {
            IMAGE_LOGE("[ImageSource]Base64 malloc data buffer fail.");
            return nullptr;
        }
        errno_t ret = memcpy_s(dataCopy.get(), subSize, sub, subSize);
        dataCopy[subSize] = '\0';
        sub = reinterpret_cast<char *>(dataCopy.get());
        subSize++;
        if (ret != EOK) {
            IMAGE_LOGE("[ImageSource]Base64 copy data fail, ret:%{public}d", ret);
            return nullptr;
        }
    }

    size_t outputLen = 0;
    SkBase64::Error error = SkBase64::Decode(sub, subSize, nullptr, &outputLen);
    bool cond = error != SkBase64::Error::kNoError;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "[ImageSource]Base64 decode get out size failed.");

    sk_sp<SkData> resData = SkData::MakeUninitialized(outputLen);
    error = SkBase64::Decode(sub, subSize, resData->writable_data(), &outputLen);
    cond = error != SkBase64::Error::kNoError;
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "[ImageSource]Base64 decode get data failed.");
    IMAGE_LOGD("[ImageSource][NewSkia]Create BufferSource from decoded base64 string.");
    auto imageData = static_cast<const uint8_t *>(resData->data());
    return BufferSourceStream::CreateSourceStream(imageData, resData->size());
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
    bool cond = ImageUtils::CheckMulOverflow(pixelMap->GetWidth(), pixelMap->GetHeight(), pixelMap->GetPixelBytes());
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "Invalid pixelmap params width:%{public}d, height:%{public}d",
                               pixelMap->GetWidth(), pixelMap->GetHeight());
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

    {
        std::unique_lock<std::mutex> guard(decodingMutex_);
        if (CreatExifMetadataByImageSource() == SUCCESS) {
            auto metadataPtr = exifMetadata_->Clone();
            pixelMap->SetExifMetadata(metadataPtr);
        }
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

#ifdef SUT_DECODE_ENABLE
static size_t GetAstcSizeBytes(const uint8_t *fileBuf, size_t fileSize)
{
    bool cond = (fileBuf == nullptr) || (fileSize <= ASTC_HEAD_BYTES);
    CHECK_ERROR_RETURN_RET_LOG(cond, 0,
                               "astc GetAstcSizeBytes input is nullptr or fileSize is smaller than ASTC HEADER");
    cond = !g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.sutDecSoGetSizeFunc_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, 0,
                               "[ImageSource] SUT dec so dlopen failed or sutDecSoGetSizeFunc_ is nullptr!");
    return g_sutDecSoManager.sutDecSoGetSizeFunc_(fileBuf, fileSize);
}

static void FreeAllExtMemSut(AstcOutInfo &astcInfo)
{
    for (uint8_t idx = 0; idx < astcInfo.expandNums; idx++) {
        if (astcInfo.expandInfoBuf[idx] != nullptr) {
            free(astcInfo.expandInfoBuf[idx]);
        }
    }
}

static bool FillAstcSutExtInfo(AstcOutInfo &astcInfo, SutInInfo &sutInfo)
{
    bool cond = !g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.getExpandInfoFromSutFunc_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] SUT dec getExpandInfoFromSutFunc_ is nullptr!");
    cond = !g_sutDecSoManager.getExpandInfoFromSutFunc_(sutInfo, astcInfo, false);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "[ImageSource] GetExpandInfoFromSut failed!");
    int32_t expandTotalBytes = 0;
    for (uint8_t idx = 0; idx < astcInfo.expandNums; idx++) {
        astcInfo.expandInfoCapacity[idx] = astcInfo.expandInfoBytes[idx];
        astcInfo.expandInfoBuf[idx] = static_cast<uint8_t *>(malloc(astcInfo.expandInfoCapacity[idx]));
        if (astcInfo.expandInfoBuf[idx] == nullptr) {
            IMAGE_LOGE("[ImageSource] astcInfo.expandInfoBuf malloc failed!");
            return false;
        }
        expandTotalBytes += sizeof(uint8_t) + sizeof(int32_t) + astcInfo.expandInfoBytes[idx];
    }
    return astcInfo.expandTotalBytes == expandTotalBytes;
}

static bool CheckExtInfoForPixelmap(AstcOutInfo &astcInfo, unique_ptr<PixelAstc> &pixelAstc)
{
    uint8_t colorSpace = 0;
    for (uint8_t idx = 0; idx < astcInfo.expandNums; idx++) {
        if (astcInfo.expandInfoBuf[idx] != nullptr) {
            switch (static_cast<AstcExtendInfoType>(astcInfo.expandInfoType[idx])) {
                case AstcExtendInfoType::COLOR_SPACE:
                    colorSpace = *astcInfo.expandInfoBuf[idx];
                    break;
                default:
                    return false;
            }
        }
    }
#ifdef IMAGE_COLORSPACE_FLAG
    pixelAstc->InnerSetColorSpace(static_cast<ColorManager::ColorSpaceName>(colorSpace), true);
#endif
    return true;
}

static bool TextureSuperCompressDecodeInit(AstcOutInfo *astcInfo, SutInInfo *sutInfo, size_t inBytes, size_t outBytes)
{
    bool ret = (memset_s(astcInfo, sizeof(AstcOutInfo), 0, sizeof(AstcOutInfo)) == 0) &&
               (memset_s(sutInfo, sizeof(SutInInfo), 0, sizeof(SutInInfo)) == 0);
    if (!ret) {
        IMAGE_LOGE("astc SuperDecompressTexture memset failed!");
        return false;
    }
    bool cond = inBytes > static_cast<size_t>(std::numeric_limits<int32_t>::max());
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture inBytes overflow!");
    sutInfo->sutBytes = static_cast<int32_t>(inBytes);
    cond = outBytes > static_cast<size_t>(std::numeric_limits<int32_t>::max());
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture outBytes overflow!");
    astcInfo->astcBytes = static_cast<int32_t>(outBytes);
    return true;
}

static bool TextureSuperCompressDecode(const uint8_t *inData, size_t inBytes, uint8_t *outData, size_t outBytes,
    unique_ptr<PixelAstc> &pixelAstc)
{
    size_t preOutBytes = outBytes;
    bool cond = (inData == nullptr) || (outData == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc TextureSuperCompressDecode input check failed!");
    cond = !g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.sutDecSoDecFunc_ == nullptr;
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "[ImageSource] SUT dec so dlopen failed or sutDecSoDecFunc_ is nullptr!");
    AstcOutInfo astcInfo = {0};
    SutInInfo sutInfo = {0};
    cond = !TextureSuperCompressDecodeInit(&astcInfo, &sutInfo, inBytes, outBytes);
    CHECK_ERROR_RETURN_RET(cond, false);
    sutInfo.sutBuf = inData;
    astcInfo.astcBuf = outData;
    if (!FillAstcSutExtInfo(astcInfo, sutInfo)) {
        FreeAllExtMemSut(astcInfo);
        IMAGE_LOGE("[ImageSource] SUT dec FillAstcSutExtInfo failed!");
        return false;
    }
    if (!g_sutDecSoManager.sutDecSoDecFunc_(sutInfo, astcInfo)) {
        IMAGE_LOGE("astc SuperDecompressTexture process failed!");
        FreeAllExtMemSut(astcInfo);
        return false;
    }
    if (!CheckExtInfoForPixelmap(astcInfo, pixelAstc)) {
        IMAGE_LOGE("astc SuperDecompressTexture could not get ext info!");
        FreeAllExtMemSut(astcInfo);
        return false;
    }
    FreeAllExtMemSut(astcInfo);
    cond = astcInfo.astcBytes < 0;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture astcInfo.astcBytes sub overflow!");
    outBytes = static_cast<size_t>(astcInfo.astcBytes);
    cond = outBytes != preOutBytes;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "astc SuperDecompressTexture Dec size is predicted failed!");
    return true;
}
#endif

static uint32_t GetDataSize(uint8_t *buf)
{
    return static_cast<uint32_t>(buf[NUM_0]) +
        (static_cast<uint32_t>(buf[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(buf[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(buf[NUM_3]) << NUM_24);
}

void ReleaseExtendInfoMemory(AstcExtendInfo &extendInfo)
{
    for (uint8_t idx = 0; idx < extendInfo.extendNums; idx++) {
        if (extendInfo.extendInfoValue[idx] != nullptr) {
            free(extendInfo.extendInfoValue[idx]);
            extendInfo.extendInfoValue[idx] = nullptr;
        }
    }
}

bool HandleMetadataCopy(std::vector<uint8_t>& dest, const uint8_t *src, size_t length)
{
    dest.resize(length);
    if (memcpy_s(dest.data(), length, src, length) != 0) {
        IMAGE_LOGE("[AstcCodec] WriteAstcExtendInfo memcpy failed!");
        return false;
    }
    return true;
}

bool ProcessAstcMetadata(PixelAstc* pixelAstc, size_t astcSize, const AstcMetadata& astcMetadata)
{
    if (pixelAstc != nullptr && pixelAstc->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        Size desiredSize = { astcSize, 1 };
        MemoryData memoryData = { nullptr, astcSize, "CreatePixelMapForASTC Data", desiredSize,
                                  pixelAstc->GetPixelFormat() };
        auto dstMemory = MemoryManager::CreateMemory(AllocatorType::DMA_ALLOC, memoryData);
        if (!dstMemory || dstMemory->data.data == nullptr) {
            IMAGE_LOGE("%{public}s CreateMemory failed", __func__);
            return false;
        }
        if (memcpy_s(dstMemory->data.data, astcSize, pixelAstc->GetPixels(), astcSize) != 0) {
            IMAGE_LOGE("%{public}s memcpy failed", __func__);
            return false;
        }
        pixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data,
                                 dstMemory->data.size, dstMemory->GetType(), nullptr);
    }
    pixelAstc->SetAstcHdr(true);

    if (pixelAstc->IsHdr() && pixelAstc->GetFd() != nullptr) {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        sptr<SurfaceBuffer> dstBuffer(reinterpret_cast<SurfaceBuffer*>(pixelAstc->GetFd()));
        GSError ret = dstBuffer->SetMetadata(ATTRKEY_HDR_METADATA_TYPE, astcMetadata.hdrMetadataTypeVec);
        CHECK_ERROR_RETURN_RET_LOG(ret != GSERROR_OK, false, "%{public}s METADATA_TYPE set failed", __func__);
        ret = dstBuffer->SetMetadata(ATTRKEY_COLORSPACE_INFO, astcMetadata.colorSpaceInfoVec);
        CHECK_ERROR_RETURN_RET_LOG(ret != GSERROR_OK, false, "%{public}s COLORSPACE_INFO set failed", __func__);
        bool vpeRet = VpeUtils::SetSbStaticMetadata(dstBuffer, astcMetadata.staticData);
        CHECK_ERROR_RETURN_RET_LOG(!vpeRet, false, "%{public}s staticData set failed", __func__);
        vpeRet = VpeUtils::SetSbDynamicMetadata(dstBuffer, astcMetadata.dynamicData);
        CHECK_ERROR_RETURN_RET_LOG(!vpeRet, false, "%{public}s dynamicData set failed", __func__);
#endif
        return true;
    }
    return false;
}

static bool GetExtInfoForPixelAstc(AstcExtendInfo &extInfo, unique_ptr<PixelAstc> &pixelAstc, size_t astcSize)
{
    uint8_t colorSpace = 0;
    uint8_t pixelFmt = 0;
    AstcMetadata astcMetadata;

    for (uint8_t idx = 0; idx < extInfo.extendNums; idx++) {
        AstcExtendInfoType infoType = static_cast<AstcExtendInfoType>(extInfo.extendInfoType[idx]);
        uint8_t* infoValue =  extInfo.extendInfoValue[idx];
        uint32_t infoLength = extInfo.extendInfoLength[idx];

        if (infoValue == nullptr) {
            continue;
        }

        switch (infoType) {
            case AstcExtendInfoType::COLOR_SPACE:
                colorSpace = *infoValue;
                break;
            case AstcExtendInfoType::PIXEL_FORMAT:
                pixelFmt = *infoValue;
                break;
            case AstcExtendInfoType::HDR_METADATA_TYPE:
                HandleMetadataCopy(astcMetadata.hdrMetadataTypeVec, infoValue, infoLength);
                break;
            case AstcExtendInfoType::HDR_COLORSPACE_INFO:
                HandleMetadataCopy(astcMetadata.colorSpaceInfoVec, infoValue, infoLength);
                break;
            case AstcExtendInfoType::HDR_STATIC_DATA:
                HandleMetadataCopy(astcMetadata.staticData, infoValue, infoLength);
                break;
            case AstcExtendInfoType::HDR_DYNAMIC_DATA:
                HandleMetadataCopy(astcMetadata.dynamicData, infoValue, infoLength);
                break;
            default:
                return false;
        }
    }
#ifdef IMAGE_COLORSPACE_FLAG
    ColorManager::ColorSpace grColorspace (static_cast<ColorManager::ColorSpaceName>(colorSpace));
    pixelAstc->InnerSetColorSpace(grColorspace, true);
#endif
    if (static_cast<PixelFormat>(pixelFmt) == PixelFormat::RGBA_1010102 &&
        !ProcessAstcMetadata(pixelAstc.get(), astcSize, astcMetadata)) {
        IMAGE_LOGE("GetExtInfoForPixelAstc ProcessAstcMetadata failed!");
        return false;
    }
    return true;
}

static bool CheckAstcExtInfoBytes(AstcExtendInfo &extInfo, size_t astcSize, size_t fileSize)
{
    if (extInfo.extendBufferSumBytes != ASTC_EXTEND_INFO_TLV_SUM_BYTES_L1 &&
        extInfo.extendBufferSumBytes != ASTC_EXTEND_INFO_TLV_SUM_BYTES_L2 &&
        extInfo.extendBufferSumBytes < ASTC_EXTEND_INFO_TLV_NUM6_SUM_BYTES) {
        IMAGE_LOGE("CheckAstcExtInfoBytes extendBufferSumBytes is invalid: %{public}d", extInfo.extendBufferSumBytes);
        return false;
    }
    if (extInfo.extendBufferSumBytes + astcSize + ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH != fileSize) {
        IMAGE_LOGE("CheckAstcExtInfoBytes extendBufferSumBytes is large than filesize");
        return false;
    }
    return true;
}

static bool ResolveExtInfo(const uint8_t *sourceFilePtr, size_t astcSize, size_t fileSize,
    unique_ptr<PixelAstc> &pixelAstc)
{
    uint8_t *extInfoBuf = const_cast<uint8_t*>(sourceFilePtr) + astcSize;
    /* */
    AstcExtendInfo extInfo = {0};
    bool invalidData = (astcSize + ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH >= fileSize) ||
        (memset_s(&extInfo, sizeof(AstcExtendInfo), 0, sizeof(AstcExtendInfo)) != 0);
    if (invalidData) {
        IMAGE_LOGE("ResolveExtInfo file data is invalid!");
        return false;
    }
    extInfo.extendBufferSumBytes = GetDataSize(extInfoBuf);
    if (!CheckAstcExtInfoBytes(extInfo, astcSize, fileSize)) {
        IMAGE_LOGE("ResolveExtInfo file size is not equal to astc add ext bytes!");
        return false;
    }
    extInfoBuf += ASTC_EXTEND_INFO_SIZE_DEFINITION_LENGTH;
    int32_t leftBytes = static_cast<int32_t>(extInfo.extendBufferSumBytes);
    for (uint8_t idx = 0; leftBytes > 0; idx++) {
        if (idx == ASTC_EXTEND_INFO_TLV_NUM6) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        if (leftBytes < TLV_LEAST_BYTES) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        extInfo.extendInfoType[idx] = *extInfoBuf++; // type
        leftBytes--;
        uint32_t expendInfoBytesUnSign = GetDataSize(extInfoBuf);
        extInfoBuf += sizeof(uint32_t);
        leftBytes -= sizeof(uint32_t);
        if (expendInfoBytesUnSign > MAX_INT32 || static_cast<uint32_t>(leftBytes) < expendInfoBytesUnSign) {
            return false;
        }
        extInfo.extendInfoLength[idx] = expendInfoBytesUnSign;
        extInfo.extendInfoValue[idx] = static_cast<uint8_t *>(malloc(extInfo.extendInfoLength[idx]));
        bool ret = (extInfo.extendInfoValue[idx] != nullptr) && (memcpy_s(extInfo.extendInfoValue[idx],
            extInfo.extendInfoLength[idx], extInfoBuf, extInfo.extendInfoLength[idx]) == 0);
        if (!ret) {
            ReleaseExtendInfoMemory(extInfo);
            return false;
        }
        extInfoBuf += expendInfoBytesUnSign;
        leftBytes -= static_cast<int32_t>(expendInfoBytesUnSign);
        extInfo.extendNums++;
    }
    if (leftBytes != 0) {
        ReleaseExtendInfoMemory(extInfo);
        return false;
    }
    if (!GetExtInfoForPixelAstc(extInfo, pixelAstc, astcSize)) {
        IMAGE_LOGE("ResolveExtInfo Could not get ext info!");
    }
    ReleaseExtendInfoMemory(extInfo);
    return true;
}

#ifdef SUT_DECODE_ENABLE
static bool FormatIsSUT(const uint8_t *fileData, size_t fileSize)
{
    if (fileData == nullptr || fileSize < SUT_HEAD_BYTES) {
        IMAGE_LOGE("FormatIsSUT fileData incorrect.");
        return false;
    }
    uint32_t magicVal = static_cast<uint32_t>(fileData[NUM_0]) +
        (static_cast<uint32_t>(fileData[NUM_1]) << NUM_8) +
        (static_cast<uint32_t>(fileData[NUM_2]) << NUM_16) +
        (static_cast<uint32_t>(fileData[NUM_3]) << NUM_24);
    return magicVal == SUT_FILE_SIGNATURE;
}
#endif

static bool ReadFileAndResoveAstc(size_t fileSize, size_t astcSize, unique_ptr<PixelAstc> &pixelAstc,
    const uint8_t *sourceFilePtr, const DecodeOptions &opts)
{
#if !(defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM))
    Size desiredSize = {astcSize, 1};
    MemoryData memoryData = {nullptr, astcSize, "CreatePixelMapForASTC Data", desiredSize, pixelAstc->GetPixelFormat()};
    ImageInfo pixelAstcInfo;
    pixelAstc->GetImageInfo(pixelAstcInfo);
    AllocatorType allocatorType = (opts.allocatorType == AllocatorType::DEFAULT) ?
        (IsSupportAstcZeroCopy(pixelAstcInfo.size) ? AllocatorType::DMA_ALLOC : AllocatorType::SHARE_MEM_ALLOC) :
        opts.allocatorType;
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("ReadFileAndResoveAstc CreateMemory failed");
        return false;
    }
    pixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size, dstMemory->GetType(),
        nullptr);
    bool successMemCpyOrDec = true;
#ifdef SUT_DECODE_ENABLE
    if (FormatIsSUT(sourceFilePtr, fileSize)) {
        successMemCpyOrDec = TextureSuperCompressDecode(sourceFilePtr, fileSize,
            static_cast<uint8_t *>(dstMemory->data.data), astcSize, pixelAstc);
        IMAGE_LOGD("ReadFileAndResoveAstc colorspace %{public}d",
            pixelAstc->InnerGetGrColorSpace().GetColorSpaceName());
    } else {
#endif
        if (memcpy_s(dstMemory->data.data, astcSize, sourceFilePtr, astcSize) != 0) {
            IMAGE_LOGE("[ImageSource] astc memcpy_s failed!");
            successMemCpyOrDec = false;
        }
        successMemCpyOrDec = successMemCpyOrDec && ((fileSize == astcSize) ||
            ((fileSize > astcSize) && ResolveExtInfo(sourceFilePtr, astcSize, fileSize, pixelAstc)));
#ifdef SUT_DECODE_ENABLE
    }
#endif
    if (!successMemCpyOrDec) {
        return false;
    }
#endif
    return true;
}

unique_ptr<PixelMap> ImageSource::CreatePixelMapForASTC(uint32_t &errorCode, const DecodeOptions &opts)
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
    bool isSUT = false;
#ifdef SUT_DECODE_ENABLE
    isSUT = FormatIsSUT(sourceFilePtr, fileSize);
    size_t astcSize = !isSUT ?
        ImageUtils::GetAstcBytesCount(info) : GetAstcSizeBytes(sourceFilePtr, fileSize);
    if (astcSize == 0) {
        IMAGE_LOGE("[ImageSource] astc GetAstcSizeBytes failed.");
        return nullptr;
    }
#else
    size_t astcSize = ImageUtils::GetAstcBytesCount(info);
#endif
    if (!isSUT && astcSize > fileSize) {
        IMAGE_LOGE("[ImageSource] astcSize > fileSize.");
        return nullptr;
    }
    if (!ReadFileAndResoveAstc(fileSize, astcSize, pixelAstc, sourceFilePtr, opts)) {
        IMAGE_LOGE("[ImageSource] astc ReadFileAndResoveAstc failed.");
        return nullptr;
    }
    pixelAstc->SetAstc(true);
    ImageUtils::FlushSurfaceBuffer(pixelAstc.get());
    return pixelAstc;
}
#endif

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
        if (astcInfo.blockFootprint.width != astcInfo.blockFootprint.height) {
            IMAGE_LOGE("[ImageSource]GetASTCInfo blockFootprint failed");
            return false;
        }
        return true;
    }
#ifdef SUT_DECODE_ENABLE
    if (!g_sutDecSoManager.LoadSutDecSo() || g_sutDecSoManager.getTextureInfoFunc_ == nullptr) {
        IMAGE_LOGE("[ImageSource] SUT dec so dlopen failed or getTextureInfoFunc_ is nullptr!");
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
        case PixelFormat::YCBCR_P010:
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
    ImageTrace imageTrace("ImageSource decomposeImage");
    VpeUtils::SetSbMetadataType(hdr, HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_SINGLE);
    VpeUtils::SetSbMetadataType(sdr, HDI::Display::Graphic::Common::V1_0::CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbColorSpaceType(sdr, HDI::Display::Graphic::Common::V1_0::CM_P3_FULL);
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res = utils->ColorSpaceConverterImageProcess(hdr, sdr);
    bool cond = res != VPE_ERROR_OK || sdr == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    return true;
}

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
    } else if (format == GRAPHIC_PIXEL_FMT_YCBCR_P010) {
        context.pixelFormat = PixelFormat::YCBCR_P010;
        context.info.pixelFormat = PixelFormat::YCBCR_P010;
        context.grColorSpaceName = ColorManager::BT2020_HLG;
    }
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
    if (format == PixelFormat::YCRCB_P010 || format == PixelFormat::YCBCR_P010) {
        context.yuvInfo.yStride = planeY.columnStride / NUM_2;
        context.yuvInfo.uvStride = planeUV.columnStride / NUM_2;
        context.yuvInfo.yOffset = planeY.offset / NUM_2;
        context.yuvInfo.uvOffset = planeUV.offset / NUM_2;
    } else {
        context.yuvInfo.yStride = planeY.columnStride;
        context.yuvInfo.uvStride = planeUV.columnStride;
        context.yuvInfo.yOffset = planeY.offset;
        context.yuvInfo.uvOffset = planeUV.offset;
    }
    context.yuvInfo.imageSize = context.info.size;
    context.yuvInfo.yWidth = static_cast<uint32_t>(context.info.size.width);
    context.yuvInfo.yHeight = static_cast<uint32_t>(context.info.size.height);
    context.yuvInfo.uvWidth = static_cast<uint32_t>((context.info.size.width + 1) / NUM_2);
    context.yuvInfo.uvHeight = static_cast<uint32_t>((context.info.size.height + 1) / NUM_2);
    IMAGE_LOGD("SetDmaContextYuvInfo format:%{public}d, yStride:%{public}d, uvStride:%{public}d, yOffset:%{public}d,"
        "uvOffset:%{public}d, imageSize:%{public}d-%{public}d", format, context.yuvInfo.yStride,
        context.yuvInfo.uvStride, context.yuvInfo.yOffset, context.yuvInfo.uvOffset,
        context.yuvInfo.imageSize.width, context.yuvInfo.imageSize.height);
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
    bool cond = context.allocatorType != AllocatorType::DMA_ALLOC;
    CHECK_ERROR_RETURN_RET(cond, context);
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
        cond = res != SUCCESS;
        CHECK_INFO_RETURN_RET_LOG(cond, context, "single hdr convert to sdr,alloc surfacebuffer failed");
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
    context.isAppUseAllocator = opts_.isAppUseAllocator;
    ImageHdrType decodedHdrType = context.hdrType;
    context.grColorSpaceName = mainDecoder_->GetPixelMapColorSpace().GetColorSpaceName();
    errorCode = mainDecoder_->Decode(index, context);
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

bool ImageSource::ApplyGainMap(ImageHdrType hdrType, DecodeContext& baseCtx, DecodeContext& hdrCtx, float scale)
{
    string format = GetExtendedCodecMimeType(mainDecoder_.get());
    if (format != IMAGE_JPEG_FORMAT && format != IMAGE_HEIF_FORMAT && format != IMAGE_HEIC_FORMAT) {
        return false;
    }
    DecodeContext gainMapCtx;
    HdrMetadata metadata;
    if (format == IMAGE_HEIF_FORMAT || format == IMAGE_HEIC_FORMAT) {
        ImageTrace imageTrace("ImageSource decode heif gainmap hdrType:%d, scale:%d", hdrType, scale);
        bool cond = !mainDecoder_->DecodeHeifGainMap(gainMapCtx);
        CHECK_INFO_RETURN_RET_LOG(cond, false, "[ImageSource] heif get gainmap failed");
        metadata = mainDecoder_->GetHdrMetadata(hdrType);
    } else if (!DecodeJpegGainMap(hdrType, scale, gainMapCtx, metadata)) {
        IMAGE_LOGI("[ImageSource] jpeg get gainmap failed");
        return false;
    }
    if (baseCtx.isCreateWideGamutSdrPixelMap &&
        metadata.extendMeta.metaISO.gainmapChannelNum == GAINMAP_CHANNEL_NUM_ONE) {
        IMAGE_LOGI("HDR-IMAGE wideGamut get one channel gainmap");
        return false;
    }
    IMAGE_LOGD("HDR-IMAGE get hdr metadata, extend flag is %{public}d, static size is %{public}zu,"
        "dynamic metadata size is %{public}zu",
        metadata.extendMetaFlag, metadata.staticMetadata.size(), metadata.dynamicMetadata.size());
    bool result = ComposeHdrImage(hdrType, baseCtx, gainMapCtx, hdrCtx, metadata);
    FreeContextBuffer(gainMapCtx.freeFunc, gainMapCtx.allocatorType, gainMapCtx.pixelsBuffer);
    return result;
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
void ImageSource::SetVividMetaColor(HdrMetadata& metadata,
    CM_ColorSpaceType base, CM_ColorSpaceType gainmap, CM_ColorSpaceType hdr)
{
    metadata.extendMeta.baseColorMeta.baseColorPrimary = base & 0xFF;
    metadata.extendMeta.gainmapColorMeta.enhanceDataColorPrimary = gainmap & 0xFF;
    metadata.extendMeta.gainmapColorMeta.combineColorPrimary = gainmap & 0xFF;
    metadata.extendMeta.gainmapColorMeta.alternateColorPrimary = hdr & 0xFF;
}

static CM_HDR_Metadata_Type GetHdrMediaType(HdrMetadata& metadata)
{
    CM_HDR_Metadata_Type hdrMetadataType = static_cast<CM_HDR_Metadata_Type>(metadata.hdrMetadataType);
    switch (hdrMetadataType) {
        case CM_VIDEO_HLG:
        case CM_VIDEO_HDR10:
        case CM_VIDEO_HDR_VIVID:
            return CM_IMAGE_HDR_VIVID_SINGLE;
        default:
            break;
    }
    return hdrMetadataType;
}

static void ApplyMemoryForHdr(DecodeContext& hdrCtx, CM_ColorSpaceType hdrCmColor,
    ImageHdrType hdrType, const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if !defined(CROSS_PLATFORM)
    hdrCtx.grColorSpaceName = ConvertColorSpaceName(hdrCmColor, false);
    CM_HDR_Metadata_Type type;
    if (hdrType == ImageHdrType::HDR_VIVID_DUAL || hdrType == ImageHdrType::HDR_CUVA) {
        type = CM_IMAGE_HDR_VIVID_SINGLE;
    } else if (hdrType == ImageHdrType::HDR_ISO_DUAL) {
        type = CM_IMAGE_HDR_ISO_SINGLE;
    }
    sptr<SurfaceBuffer> surfaceBuf(reinterpret_cast<SurfaceBuffer*>(reusePixelmap->GetFd()));
    VpeUtils::SetSbMetadataType(surfaceBuf, type);
    VpeUtils::SetSbColorSpaceType(surfaceBuf, hdrCmColor);
#endif
}

static uint32_t AllocHdrSurfaceBuffer(DecodeContext& context, ImageHdrType hdrType, CM_ColorSpaceType color,
                                      const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if defined(_WIN32) || defined(_APPLE) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    IMAGE_LOGE("UnSupport dma mem alloc");
    return ERR_IMAGE_DATA_UNSUPPORT;
#else
    if (ImageUtils::IsHdrPixelMapReuseSuccess(context, context.info.size.width, context.info.size.height,
        reusePixelmap)) {
        ApplyMemoryForHdr(context, color, hdrType, reusePixelmap);
        IMAGE_LOGI("HDR-IMAGE reusePixelmap success");
    }
    sptr<SurfaceBuffer> sb = SurfaceBuffer::Create();
    auto hdrPixelFormat = GRAPHIC_PIXEL_FMT_RGBA_1010102;
    if (context.photoDesiredPixelFormat == PixelFormat::YCBCR_P010) {
        hdrPixelFormat = GRAPHIC_PIXEL_FMT_YCBCR_P010;
    }
    BufferRequestConfig requestConfig = {
        .width = context.info.size.width,
        .height = context.info.size.height,
        .strideAlignment = context.info.size.width,
        .format = hdrPixelFormat,
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
    SetContext(context, sb, nativeBuffer, hdrPixelFormat);
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
    // alloc hdr image
    uint32_t errorCode = AllocHdrSurfaceBuffer(hdrCtx, hdrType, hdrCmColor, opts_.reusePixelmap);
    bool cond = (errorCode != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "HDR SurfaceBuffer Alloc failed, %{public}d", errorCode);
    sptr<SurfaceBuffer> hdrSptr(reinterpret_cast<SurfaceBuffer*>(hdrCtx.pixelsBuffer.context));
    SpecialSetComposeBuffer(baseCtx, baseSptr, gainmapSptr, hdrSptr, metadata);
    VpeSurfaceBuffers buffers = {
        .sdr = baseSptr,
        .gainmap = gainmapSptr,
        .hdr = hdrSptr,
    };
    std::unique_ptr<VpeUtils> utils = std::make_unique<VpeUtils>();
    int32_t res = utils->ColorSpaceConverterComposeImage(buffers, hdrType == ImageHdrType::HDR_CUVA);
    if (res != VPE_ERROR_OK) {
        IMAGE_LOGE("[ImageSource] composeImage failed");
        FreeContextBuffer(hdrCtx.freeFunc, hdrCtx.allocatorType, hdrCtx.pixelsBuffer);
        return false;
    }
    SetDmaContextYuvInfo(hdrCtx);
    if (GetHdrMediaType(metadata) == CM_IMAGE_HDR_VIVID_SINGLE) {
        VpeUtils::SetSbMetadataType(hdrSptr, static_cast<CM_HDR_Metadata_Type>(metadata.hdrMetadataType));
    }
    return true;
#endif
}

uint32_t ImageSource::RemoveImageProperties(std::shared_ptr<MetadataAccessor> metadataAccessor,
                                            const std::set<std::string> &keys)
{
    bool cond = (metadataAccessor == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_IMAGE_SOURCE_DATA,
                               "Failed to create image accessor when attempting to modify image property.");
    uint32_t ret = CreatExifMetadataByImageSource();
    cond = ret != SUCCESS;
    CHECK_ERROR_RETURN_RET_LOG(cond, ret, "Failed to create ExifMetadata.");

    bool deletFlag = false;
    for (auto key: keys) {
        bool result = exifMetadata_->RemoveEntry(key);
        deletFlag |= result;
    }

    cond = !deletFlag;
    ret = ERR_MEDIA_NO_EXIF_DATA;
    CHECK_ERROR_RETURN_RET(cond, ret);

    metadataAccessor->Set(exifMetadata_);
    return metadataAccessor->Write();
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool CopyRGBAToSurfaceBuffer(const DecodeContext& context, sptr<SurfaceBuffer>& sb, PlImageInfo plInfo)
{
    bool cond = (context.info.pixelFormat != PixelFormat::RGBA_8888 &&
        context.info.pixelFormat != PixelFormat::BGRA_8888);
    CHECK_ERROR_RETURN_RET(cond, false);
    uint8_t* srcRow = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    uint8_t* dstRow = static_cast<uint8_t*>(sb->GetVirAddr());
    cond = srcRow == nullptr || dstRow == nullptr;
    CHECK_ERROR_RETURN_RET(cond, false);
    cond = sb->GetStride() < 0;
    CHECK_ERROR_RETURN_RET(cond, false);
    uint64_t dstStride = sb->GetStride();
    uint64_t srcStride = static_cast<uint64_t>(plInfo.size.width * NUM_4);
    uint32_t dstHeight = static_cast<uint32_t>(plInfo.size.height);
    for (uint32_t i = 0; i < dstHeight; i++) {
        errno_t err = memcpy_s(dstRow, dstStride, srcRow, srcStride);
        cond = err != EOK;
        CHECK_ERROR_RETURN_RET_LOG(cond, false, "copy data failed");
        srcRow += srcStride;
        dstRow += dstStride;
    }
    return true;
}

static bool CopyYUVToSurfaceBuffer(const DecodeContext& context, sptr<SurfaceBuffer>& buffer, PlImageInfo plInfo)
{
    bool cond = context.info.pixelFormat != PixelFormat::NV12 &&
        context.info.pixelFormat != PixelFormat::NV21;
    CHECK_ERROR_RETURN_RET(cond, false);
    uint8_t* srcRow = static_cast<uint8_t*>(context.pixelsBuffer.buffer);
    uint8_t* dstRow = static_cast<uint8_t*>(buffer->GetVirAddr());
    size_t dstSize = buffer->GetSize();
    cond = (buffer->GetStride() < 0);
    CHECK_ERROR_RETURN_RET(cond, false);
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

static void SetResLogBuffer(sptr<SurfaceBuffer>& baseSptr, sptr<SurfaceBuffer>& gainmapSptr,
    sptr<SurfaceBuffer>& hdrSptr)
{
    VpeUtils::SetSurfaceBufferInfo(baseSptr, CM_BT709_LIMIT);
    VpeUtils::SetSurfaceBufferInfo(gainmapSptr, CM_BT709_LIMIT);
    VpeUtils::SetSurfaceBufferInfo(hdrSptr, CM_BT709_LIMIT);
    VpeUtils::SetSbMetadataType(baseSptr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbMetadataType(gainmapSptr, CM_IMAGE_HDR_VIVID_DUAL);
    VpeUtils::SetSbMetadataType(hdrSptr, CM_IMAGE_HDR_VIVID_SINGLE);
}

static void SetWideGamutBuffer(sptr<SurfaceBuffer>& baseSptr, sptr<SurfaceBuffer>& gainmapSptr,
    sptr<SurfaceBuffer>& hdrSptr)
{
    VpeUtils::SetSbColorSpaceType(baseSptr, CM_SRGB_FULL);
    VpeUtils::SetSbColorSpaceType(gainmapSptr, CM_SRGB_FULL);
    VpeUtils::SetSbColorSpaceType(hdrSptr, CM_DISPLAY_BT2020_SRGB);
}

void ImageSource::SpecialSetComposeBuffer(DecodeContext &baseCtx, sptr<SurfaceBuffer>& baseSptr,
    sptr<SurfaceBuffer>& gainmapSptr, sptr<SurfaceBuffer>& hdrSptr, HdrMetadata& metadata)
{
    // videoHdrImage special process
    CM_HDR_Metadata_Type videoToImageHdrType = GetHdrMediaType(metadata);
    bool isVideoMetaDataType = videoToImageHdrType == CM_IMAGE_HDR_VIVID_SINGLE;
    if (isVideoMetaDataType) {
        IMAGE_LOGI("HDR-IMAGE set video hdr type");
        VpeUtils::SetSbMetadataType(gainmapSptr, videoToImageHdrType);
    }
    // logHdrImage special process
    if (sourceHdrType_ == ImageHdrType::HDR_LOG_DUAL) {
        SetResLogBuffer(baseSptr, gainmapSptr, hdrSptr);
    }
    // wideGamutSdr special process
    if (baseCtx.isCreateWideGamutSdrPixelMap) {
        SetWideGamutBuffer(baseSptr, gainmapSptr, hdrSptr);
    }
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
    bool cond = (ret != GSERROR_OK);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_DMA_NOT_EXIST,
        "SurfaceBuffer Alloc failed, %{public}s", GSErrorStr(ret).c_str());
    void* nativeBuffer = sb.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    cond = (err != OHOS::GSERROR_OK);
    CHECK_ERROR_RETURN_RET_LOG(cond, ERR_DMA_DATA_ABNORMAL, "NativeBufferReference failed");
    cond = ((!CopyRGBAToSurfaceBuffer(context, sb, plInfo)) && (!CopyYUVToSurfaceBuffer(context, sb, plInfo)));
    CHECK_ERROR_RETURN_RET(cond, ERR_IMAGE_DATA_UNSUPPORT);
    SetContext(dstCtx, sb, nativeBuffer, format);
    return SUCCESS;
#endif
}

static uint32_t DoAiHdrProcess(sptr<SurfaceBuffer> &input, DecodeContext &hdrCtx,
                               CM_ColorSpaceType cmColorSpaceType)
{
    VpeUtils::SetSbMetadataType(input, CM_METADATA_NONE);
    VpeUtils::SetSurfaceBufferInfo(input, cmColorSpaceType);
    hdrCtx.info.size.width = input->GetWidth();
    hdrCtx.info.size.height = input->GetHeight();
    auto hdrPixelFormat = GRAPHIC_PIXEL_FMT_RGBA_1010102;
    if (hdrCtx.photoDesiredPixelFormat == PixelFormat::YCBCR_P010) {
        hdrPixelFormat = GRAPHIC_PIXEL_FMT_YCBCR_P010;
    }
    uint32_t res = AllocSurfaceBuffer(hdrCtx, hdrPixelFormat);
    bool cond = (res != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, res, "HDR SurfaceBuffer Alloc failed, %{public}d", res);

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
        if (hdrCtx.photoDesiredPixelFormat == PixelFormat::YCBCR_P010) {
            hdrCtx.pixelFormat = PixelFormat::YCBCR_P010;
            hdrCtx.info.pixelFormat = PixelFormat::YCBCR_P010;
        } else {
            hdrCtx.pixelFormat = PixelFormat::RGBA_1010102;
            hdrCtx.info.pixelFormat = PixelFormat::RGBA_1010102;
        }
        hdrCtx.allocatorType = AllocatorType::DMA_ALLOC;
    }
    return res;
}

static uint32_t AiSrProcess(sptr<SurfaceBuffer> &input, DecodeContext &aisrCtx)
{
    uint32_t res = AllocSurfaceBuffer(aisrCtx, input->GetFormat());
    bool cond = (res != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, res, "HDR SurfaceBuffer Alloc failed, %{public}d", res);
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
    CHECK_DEBUG_RETURN_RET_LOG(!bRet, false, "[ImageSource] IsNecessaryAiProcess Unsupported sr and hdr");
    if (IsSizeVailed(opts.desiredSize) && (((imageSize.height != opts.desiredSize.height
        || imageSize.width != opts.desiredSize.width) && opts.resolutionQuality != ResolutionQuality::UNKNOWN)
        || opts.resolutionQuality == ResolutionQuality::HIGH)) {
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
    dstCtx.info.size.width = srcCtx.info.size.width;
    dstCtx.info.size.height = srcCtx.info.size.height;
    dstCtx.isAisr = srcCtx.isAisr;
    dstCtx.grColorSpaceName = srcCtx.grColorSpaceName;
    dstCtx.yuvInfo.imageSize.width = srcCtx.outInfo.size.width;
    dstCtx.yuvInfo.imageSize.height = srcCtx.outInfo.size.height;
    dstCtx.photoDesiredPixelFormat = srcCtx.photoDesiredPixelFormat;
}

static uint32_t AiHdrProcess(const DecodeContext &aisrCtx, DecodeContext &hdrCtx, CM_ColorSpaceType cmColorSpaceType)
{
    hdrCtx.pixelsBuffer.bufferSize = aisrCtx.pixelsBuffer.bufferSize;
    hdrCtx.info.size.width = aisrCtx.outInfo.size.width;
    hdrCtx.info.size.height = aisrCtx.outInfo.size.height;
    hdrCtx.photoDesiredPixelFormat = aisrCtx.photoDesiredPixelFormat;

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
        bool cond = res != SUCCESS;
        CHECK_ERROR_RETURN_RET_LOG(cond, res,
                                   "[ImageSource] ImageAiProcess HDR SurfaceBuffer Alloc failed, %{public}d", res);
        input = reinterpret_cast<SurfaceBuffer*>(srcCtx.pixelsBuffer.context);
    }
    DecodeContext dstCtx;
    CopySrcInfoOfContext(context, dstCtx);

    if (IsSizeVailed(opts.desiredSize)) {
        dstCtx.info.size.width = opts.desiredSize.width;
        dstCtx.info.size.height = opts.desiredSize.height;
    }
    CM_ColorSpaceType cmColorSpaceType =
        ConvertColorSpaceType(mainDecoder_->GetPixelMapColorSpace().GetColorSpaceName(), true);
    auto res = DoImageAiProcess(input, dstCtx, cmColorSpaceType, needAisr, needHdr);
    if (res == SUCCESS || res == ERR_IMAGE_AI_ONLY_SR_SUCCESS) {
        FreeContextBuffer(context.freeFunc, context.allocatorType, context.pixelsBuffer);
        CopyOutInfoOfContext(dstCtx, context);
        SetDmaContextYuvInfo(context);
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

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
std::unique_ptr<Picture> ImageSource::CreatePictureAtIndex(uint32_t index, uint32_t &errorCode)
{
    ImageDataStatistics imageDataStatistics("[ImageSource]CreatePictureAtIndex");
    DumpInputData();

    ImageInfo info;
    GetImageInfo(info);
    errorCode = CreatePictureAtIndexPreCheck(index, info);
    CHECK_ERROR_RETURN_RET_LOG(errorCode != SUCCESS, nullptr,
        "[%{public}s] PreCheck failed, index=%{public}u, errorCode=%{public}u", __func__, index, errorCode);

    DecodeOptions opts;
    std::shared_ptr<PixelMap> pixelMap = CreatePixelMap(index, opts, errorCode);
    CHECK_ERROR_RETURN_RET_LOG(errorCode != SUCCESS, nullptr,
        "[%{public}s] create PixelMap error, index=%{public}u, errorCode=%{public}u", __func__, index, errorCode);

    std::unique_ptr<Picture> picture = Picture::Create(pixelMap);
    if (picture == nullptr) {
        IMAGE_LOGE("[%{public}s] create picture error", __func__);
        errorCode = ERR_IMAGE_PICTURE_CREATE_FAILED;
        return nullptr;
    }
    if (info.encodedFormat == IMAGE_GIF_FORMAT) {
        errorCode = SetGifMetadataForPicture(picture, index);
        CHECK_ERROR_RETURN_RET_LOG(errorCode != SUCCESS, nullptr,
            "[%{public}s] SetGifMetadataForPicture failed, index=%{public}u, errorCode=%{public}u",
            __func__, index, errorCode);
    }
    return picture;
}

uint32_t ImageSource::CreatePictureAtIndexPreCheck(uint32_t index, const ImageInfo &info)
{
    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGE("[%{public}s] sourceStreamPtr_ is nullptr", __func__);
        return ERR_IMAGE_SOURCE_DATA;
    }

    if (info.encodedFormat != IMAGE_GIF_FORMAT) {
        IMAGE_LOGE("[%{public}s] unsupport format: %{public}s", __func__, info.encodedFormat.c_str());
        return ERR_IMAGE_MISMATCHED_FORMAT;
    }

    uint32_t error = ERR_MEDIA_INVALID_VALUE;
    uint32_t frameCount = GetFrameCount(error);
    CHECK_ERROR_RETURN_RET_LOG(error != SUCCESS, error, "[%{public}s] get frame count error", __func__);
    if (index >= frameCount) {
        IMAGE_LOGE("[%{public}s] invalid index(%{public}u) for frameCount(%{public}u)", __func__, index, frameCount);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    return SUCCESS;
}

uint32_t ImageSource::SetGifMetadataForPicture(std::unique_ptr<Picture> &picture, uint32_t index)
{
    CHECK_ERROR_RETURN_RET_LOG(picture == nullptr, ERR_IMAGE_PICTURE_CREATE_FAILED,
        "[%{public}s] picture is nullptr", __func__);
    CHECK_ERROR_RETURN_RET_LOG(mainDecoder_ == nullptr, ERR_IMAGE_DECODE_ABNORMAL,
        "[%{public}s] mainDecoder_ is nullptr", __func__);

    int32_t delayTime = 0;
    uint32_t errorCode = mainDecoder_->GetImagePropertyInt(index, IMAGE_DELAY_TIME, delayTime);
    CHECK_ERROR_RETURN_RET_LOG(errorCode != SUCCESS, errorCode,
        "[%{public}s] get delay time failed", __func__);

    int32_t disposalType = 0;
    errorCode = mainDecoder_->GetImagePropertyInt(index, IMAGE_DISPOSAL_TYPE, disposalType);
    CHECK_ERROR_RETURN_RET_LOG(errorCode != SUCCESS, errorCode,
        "[%{public}s] get disposal type failed", __func__);

    std::shared_ptr<ImageMetadata> gifMetadata = std::make_shared<GifMetadata>();
    CHECK_ERROR_RETURN_RET_LOG(gifMetadata == nullptr, ERR_SHAMEM_NOT_EXIST,
        "[%{public}s] make_shared gifMetadata failed", __func__);
    bool result = gifMetadata->SetValue(GIF_METADATA_KEY_DELAY_TIME, std::to_string(delayTime));
    CHECK_ERROR_RETURN_RET_LOG(!result, ERR_IMAGE_DECODE_METADATA_FAILED,
        "[%{public}s] set delay time failed", __func__);
    result = gifMetadata->SetValue(GIF_METADATA_KEY_DISPOSAL_TYPE, std::to_string(disposalType));
    CHECK_ERROR_RETURN_RET_LOG(!result, ERR_IMAGE_DECODE_METADATA_FAILED,
        "[%{public}s] set disposal type failed", __func__);
    uint32_t ret = picture->SetMetadata(MetadataType::GIF, gifMetadata);
    CHECK_ERROR_RETURN_RET_LOG(ret != SUCCESS, ERR_IMAGE_DECODE_METADATA_FAILED,
        "[%{public}s] set gif metadata failed", __func__);
    return SUCCESS;
}

std::unique_ptr<Picture> ImageSource::CreatePicture(const DecodingOptionsForPicture &opts, uint32_t &errorCode)
{
    ImageInfo info;
    GetImageInfo(info);
    if (info.encodedFormat != IMAGE_HEIF_FORMAT && info.encodedFormat != IMAGE_JPEG_FORMAT &&
        info.encodedFormat != IMAGE_HEIC_FORMAT) {
        IMAGE_LOGE("CreatePicture failed, unsupport format: %{public}s", info.encodedFormat.c_str());
        errorCode = ERR_IMAGE_MISMATCHED_FORMAT;
        return nullptr;
    }
    DecodeOptions dopts;
    dopts.desiredPixelFormat = opts.desiredPixelFormat;
    dopts.allocatorType = opts.allocatorType;
    dopts.desiredDynamicRange = (ParseHdrType() && IsSingleHdrImage(sourceHdrType_)) ?
        DecodeDynamicRange::HDR : DecodeDynamicRange::SDR;
    dopts.editable = true;
    IMAGE_LOGI("Decode mainPixelMap: PixelFormat: %{public}d, allocatorType: %{public}d, DynamicRange: %{public}d",
        opts.desiredPixelFormat, dopts.allocatorType, dopts.desiredDynamicRange);
    std::shared_ptr<PixelMap> mainPixelMap = CreatePixelMap(dopts, errorCode);
    std::unique_ptr<Picture> picture = Picture::Create(mainPixelMap);
    if (picture == nullptr) {
        IMAGE_LOGE("Picture is nullptr");
        errorCode = ERR_IMAGE_PICTURE_CREATE_FAILED;
        return nullptr;
    }

    std::set<AuxiliaryPictureType> auxTypes = (opts.desireAuxiliaryPictures.size() > 0) ?
            opts.desireAuxiliaryPictures : ImageUtils::GetAllAuxiliaryPictureType();
    if (info.encodedFormat == IMAGE_HEIF_FORMAT || info.encodedFormat == IMAGE_HEIC_FORMAT) {
        DecodeHeifAuxiliaryPictures(auxTypes, picture, errorCode);
    } else if (info.encodedFormat == IMAGE_JPEG_FORMAT) {
        DecodeJpegAuxiliaryPicture(auxTypes, picture, errorCode);
    }
    SetHdrMetadataForPicture(picture);
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("Decode auxiliary pictures failed, error code: %{public}u", errorCode);
    }
    Picture::DumpPictureIfDumpEnabled(*picture, "picture_decode_after");
    return picture;
}

void ImageSource::SetHdrMetadataForPicture(std::unique_ptr<Picture> &picture)
{
    if (picture == nullptr) {
        IMAGE_LOGE("%{public}s picture is nullptr", __func__);
        return;
    }
    std::shared_ptr<PixelMap> mainPixelMap = picture->GetMainPixel();
    std::shared_ptr<PixelMap> gainmapPixelMap = picture->GetGainmapPixelMap();
    if (mainPixelMap == nullptr || gainmapPixelMap == nullptr || gainmapPixelMap->GetHdrMetadata() == nullptr) {
        IMAGE_LOGW("%{public}s mainPixelMap or gainmapPixelMap or hdrMetadata is nullptr", __func__);
        return;
    }
    if (mainPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC || mainPixelMap->GetFd() == nullptr ||
        gainmapPixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC || gainmapPixelMap->GetFd() == nullptr) {
        IMAGE_LOGW("%{public}s mainPixelMap or gainmapPixelMap is not DMA buffer", __func__);
        return;
    }
    ImageHdrType hdrType = gainmapPixelMap->GetHdrType();
    HdrMetadata metadata = *(gainmapPixelMap->GetHdrMetadata());

    CM_ColorSpaceType baseCmColor =
        ConvertColorSpaceType(mainPixelMap->InnerGetGrColorSpace().GetColorSpaceName(), true);
    // Set hdrMetadata for main
    sptr<SurfaceBuffer> baseSptr(reinterpret_cast<SurfaceBuffer*>(mainPixelMap->GetFd()));
    VpeUtils::SetSurfaceBufferInfo(baseSptr, false, hdrType, baseCmColor, metadata);

    // Set hdrMetadata for gainmap
    sptr<SurfaceBuffer> gainmapSptr(reinterpret_cast<SurfaceBuffer*>(gainmapPixelMap->GetFd()));
    CM_ColorSpaceType hdrCmColor = CM_BT2020_HLG_FULL;
    CM_ColorSpaceType gainmapCmColor =
        metadata.extendMeta.metaISO.useBaseColorFlag == ISO_USE_BASE_COLOR ? baseCmColor : hdrCmColor;
    SetVividMetaColor(metadata, baseCmColor, gainmapCmColor, hdrCmColor);
    VpeUtils::SetSurfaceBufferInfo(gainmapSptr, true, hdrType, gainmapCmColor, metadata);
}

void ImageSource::DecodeHeifAuxiliaryPictures(
    const std::set<AuxiliaryPictureType> &auxTypes, std::unique_ptr<Picture> &picture, uint32_t &errorCode)
{
    if (mainDecoder_ == nullptr) {
        IMAGE_LOGE("mainDecoder_ is nullptr");
        errorCode = ERR_IMAGE_PLUGIN_CREATE_FAILED;
        return;
    }
    if (picture == nullptr || picture->GetMainPixel() == nullptr) {
        IMAGE_LOGE("%{public}s: picture or mainPixelMap is nullptr", __func__);
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return;
    }
    MainPictureInfo mainInfo;
    mainInfo.hdrType = sourceHdrType_;
    picture->GetMainPixel()->GetImageInfo(mainInfo.imageInfo);
    for (auto& auxType : auxTypes) {
        if (!mainDecoder_->CheckAuxiliaryMap(auxType)) {
            IMAGE_LOGE("The auxiliary picture type does not exist! Type: %{public}d", auxType);
            continue;
        }
        auto auxiliaryPicture = AuxiliaryGenerator::GenerateHeifAuxiliaryPicture(
            mainInfo, auxType, mainDecoder_, errorCode);
        if (auxiliaryPicture == nullptr) {
            IMAGE_LOGE("Generate heif auxiliary picture failed! Type: %{public}d, errorCode: %{public}d",
                auxType, errorCode);
        } else {
            auxiliaryPicture->GetContentPixel()->SetEditable(true);
            picture->SetAuxiliaryPicture(auxiliaryPicture);
        }
    }
}

static bool OnlyDecodeGainmap(std::set<AuxiliaryPictureType> &auxTypes)
{
    return auxTypes.size() == SINGLE_FRAME_SIZE && auxTypes.find(AuxiliaryPictureType::GAINMAP) != auxTypes.end();
}

static std::vector<SingleJpegImage> ParsingJpegAuxiliaryPictures(uint8_t *stream, uint32_t streamSize,
    std::set<AuxiliaryPictureType> &auxTypes, ImageHdrType hdrType)
{
    ImageTrace imageTrace("%s", __func__);
    if (stream == nullptr || streamSize == 0) {
        IMAGE_LOGE("No source stream when parsing auxiliary pictures");
        return {};
    }
    auto jpegMpfParser = std::make_unique<JpegMpfParser>();
    if (!OnlyDecodeGainmap(auxTypes) && !jpegMpfParser->ParsingAuxiliaryPictures(stream, streamSize, false)) {
        IMAGE_LOGE("JpegMpfParser parse auxiliary pictures failed!");
        jpegMpfParser->images_.clear();
    }
    if (hdrType > ImageHdrType::SDR) {
        uint32_t gainmapStreamSize = streamSize;
        for (auto &image : jpegMpfParser->images_) {
            gainmapStreamSize = std::min(gainmapStreamSize, image.offset);
        }
        SingleJpegImage gainmapImage = {
            .offset = 0,
            .size = gainmapStreamSize,
            .auxType = AuxiliaryPictureType::GAINMAP,
            .auxTagName = AUXILIARY_TAG_GAINMAP,
        };
        jpegMpfParser->images_.push_back(gainmapImage);
    }
    return jpegMpfParser->images_;
}

bool ImageSource::CheckJpegSourceStream(StreamInfo &streamInfo)
{
    if (sourceStreamPtr_ == nullptr) {
        IMAGE_LOGE("%{public}s sourceStreamPtr_ is nullptr!", __func__);
        return false;
    }
    streamInfo.size = sourceStreamPtr_->GetStreamSize();
    bool cond = (streamInfo.size == 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s source stream size from sourceStreamPtr_ is invalid!", __func__);
    streamInfo.buffer = sourceStreamPtr_->GetDataPtr();
    if (streamInfo.buffer == nullptr) {
        streamInfo.buffer = new (std::nothrow) uint8_t[streamInfo.size];
        streamInfo.needDelete = true;
        if (!GetStreamData(sourceStreamPtr_, streamInfo.buffer, streamInfo.size)) {
            IMAGE_LOGE("%{public}s GetStreamData failed!", __func__);
            return false;
        }
    }
    cond = (streamInfo.buffer == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s source stream is still nullptr!", __func__);
    if (sourceHdrType_ > ImageHdrType::SDR) {
        uint32_t gainmapOffset = mainDecoder_->GetGainMapOffset();
        if (gainmapOffset >= streamInfo.size) {
            IMAGE_LOGW("%{public}s skip invalid gainmapOffset: %{public}u, streamSize: %{public}u",
                __func__, gainmapOffset, streamInfo.size);
            sourceHdrType_ = ImageHdrType::SDR;
            return true;
        }
        streamInfo.gainmapOffset = gainmapOffset;
    }
    return true;
}

void ImageSource::DecodeJpegAuxiliaryPicture(
    std::set<AuxiliaryPictureType> &auxTypes, std::unique_ptr<Picture> &picture, uint32_t &errorCode)
{
    StreamInfo streamInfo;
    if (!CheckJpegSourceStream(streamInfo) || streamInfo.buffer == nullptr || streamInfo.GetCurrentSize() == 0) {
        IMAGE_LOGE("Jpeg source stream is invalid!");
        errorCode = ERR_IMAGE_DATA_ABNORMAL;
        return;
    }
    auto auxInfos = ParsingJpegAuxiliaryPictures(streamInfo.GetCurrentAddress(), streamInfo.GetCurrentSize(),
        auxTypes, sourceHdrType_);
    MainPictureInfo mainInfo;
    mainInfo.hdrType = sourceHdrType_;
    picture->GetMainPixel()->GetImageInfo(mainInfo.imageInfo);
    for (auto &auxInfo : auxInfos) {
        if (auxTypes.find(auxInfo.auxType) == auxTypes.end()) {
            continue;
        }
        if (ImageUtils::HasOverflowed(auxInfo.offset, auxInfo.size)
            || auxInfo.offset + auxInfo.size > streamInfo.GetCurrentSize()) {
            IMAGE_LOGW("Invalid auxType: %{public}d, offset: %{public}u, size: %{public}u, streamSize: %{public}u",
                auxInfo.auxType, auxInfo.offset, auxInfo.size, streamInfo.GetCurrentSize());
            continue;
        }
        IMAGE_LOGI("Jpeg auxiliary picture has found. Type: %{public}d", auxInfo.auxType);
        std::unique_ptr<InputDataStream> auxStream =
            BufferSourceStream::CreateSourceStream((streamInfo.GetCurrentAddress() + auxInfo.offset), auxInfo.size);
        if (auxStream == nullptr) {
            IMAGE_LOGE("Create auxiliary stream fail, auxiliary offset is %{public}u", auxInfo.offset);
            continue;
        }
        auto auxDecoder = std::unique_ptr<AbsImageDecoder>(
            DoCreateDecoder(InnerFormat::IMAGE_EXTENDED_CODEC, pluginServer_, *auxStream, errorCode));
        uint32_t auxErrorCode = ERROR;
        auto auxPicture = AuxiliaryGenerator::GenerateJpegAuxiliaryPicture(
            mainInfo, auxInfo.auxType, auxStream, auxDecoder, auxErrorCode);
        if (auxPicture != nullptr) {
            AuxiliaryPictureInfo auxPictureInfo = auxPicture->GetAuxiliaryPictureInfo();
            auxPictureInfo.jpegTagName = auxInfo.auxTagName;
            auxPicture->SetAuxiliaryPictureInfo(auxPictureInfo);
            auxPicture->GetContentPixel()->SetEditable(true);
            picture->SetAuxiliaryPicture(auxPicture);
        } else {
            IMAGE_LOGE("Generate jpeg auxiliary picture failed!, error: %{public}d", auxErrorCode);
        }
    }
}
#endif

bool ImageSource::CompressToAstcFromPixelmap(const DecodeOptions &opts, unique_ptr<PixelMap> &rgbaPixelmap,
    unique_ptr<AbsMemory> &dstMemory)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    ImageInfo rgbaInfo;
    rgbaPixelmap->GetImageInfo(rgbaInfo);
    rgbaInfo.pixelFormat = PixelFormat::ASTC_4x4;
    size_t allocMemSize = ImageUtils::GetAstcBytesCount(rgbaInfo) + ASTC_TLV_SIZE;

    OHOS::Media::ImagePacker imagePacker;
    OHOS::Media::PackOption option;
    option.format = "image/sdr_astc_4x4";
    option.quality = ASTC_OPTION_QUALITY;

    Size desiredSize = {allocMemSize, 1};
    MemoryData memoryData = {nullptr, allocMemSize, "CompressToAstcFromPixelmap Data", desiredSize,
        opts.desiredPixelFormat};
    AllocatorType allocatorType = (opts.allocatorType == AllocatorType::DEFAULT) ?
        (IsSupportAstcZeroCopy(rgbaInfo.size) ? AllocatorType::DMA_ALLOC : AllocatorType::SHARE_MEM_ALLOC) :
        opts.allocatorType;
    dstMemory = MemoryManager::CreateMemory(allocatorType, memoryData);
    bool cond = (dstMemory == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CompressToAstcFromPixelmap CreateMemory failed");

    uint32_t ret = imagePacker.StartPacking(reinterpret_cast<uint8_t *>(dstMemory->data.data), allocMemSize, option);
    cond = (ret != 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CompressToAstcFromPixelmap failed to start packing");
    ret = imagePacker.AddImage(*(rgbaPixelmap.get()));
    cond = (ret != 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CompressToAstcFromPixelmap failed to add image");
    int64_t packedSize = 0;
    ret = imagePacker.FinalizePacking(packedSize);
    cond = (ret != 0);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "CompressToAstcFromPixelmap failed to finalize packing");
    return true;
#else
    return false;
#endif
}

unique_ptr<PixelMap> ImageSource::CreatePixelAstcFromImageFile(uint32_t index, const DecodeOptions &opts,
    uint32_t &errorCode)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    ImageInfo originInfo;
    uint32_t ret = GetImageInfo(originInfo);
    bool cond = (ret != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "CreatePixelAstcFromImageFile GetImageInfo failed");
    cond = ((originInfo.size.width > ASTC_MAX_SIZE || originInfo.size.height > ASTC_MAX_SIZE) ||
        (opts.desiredSize.width > ASTC_MAX_SIZE || opts.desiredSize.height > ASTC_MAX_SIZE));
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "CreatePixelAstcFromImageFile imageInfo size is too large");
    DecodeOptions modifiableOpts = opts;
    modifiableOpts.desiredPixelFormat = PixelFormat::RGBA_8888;
    unique_ptr<PixelMap> rgbaPixelmap = CreatePixelMap(index, modifiableOpts, errorCode);
    cond = (rgbaPixelmap == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr, "CreatePixelAstcFromImageFile pixelMap is nullptr");
    unique_ptr<AbsMemory> dstMemory = nullptr;
    cond = CompressToAstcFromPixelmap(opts, rgbaPixelmap, dstMemory);
    CHECK_ERROR_RETURN_RET_LOG(!cond, nullptr, "CreatePixelAstcFromImageFile CompressToAstcFromPixelmap failed");
    unique_ptr<PixelAstc> dstPixelAstc = make_unique<PixelAstc>();
    ImageInfo info;
    cond = GetImageInfoForASTC(info, reinterpret_cast<uint8_t *>(dstMemory->data.data));
    CHECK_ERROR_RETURN_RET_LOG(!cond, nullptr, "CreatePixelAstcFromImageFile get astc image info failed.");
    ret = dstPixelAstc->SetImageInfo(info);
    dstPixelAstc->SetAstcRealSize(info.size);
    cond = (ret != SUCCESS);
    CHECK_ERROR_RETURN_RET_LOG(cond, nullptr,
        "CreatePixelAstcFromImageFile update pixelmap info error ret:%{public}u.", ret);
    dstPixelAstc->SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data, dstMemory->data.size,
        dstMemory->GetType(), nullptr);
    dstPixelAstc->SetAstc(true);
    dstPixelAstc->SetEditable(false);
    ImageUtils::FlushSurfaceBuffer(dstPixelAstc.get());
    return dstPixelAstc;
#else
    return nullptr;
#endif
}

void ImageSource::SetSrcFd(const int& fd)
{
    srcFd_ = dup(fd);
}

void ImageSource::SetSrcFilePath(const std::string& pathName)
{
    srcFilePath_ = pathName;
}

void ImageSource::SetSrcBuffer(const uint8_t* buffer, uint32_t size)
{
    srcBuffer_ = const_cast<uint8_t*>(buffer);
    srcBufferSize_ = size;
}

} // namespace Media
} // namespace OHOS
