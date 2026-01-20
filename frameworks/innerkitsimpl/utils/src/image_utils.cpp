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

#include "image_utils.h"

#include <sys/stat.h>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <atomic>

#include "__config"
#include "image_log.h"
#include "ios"
#include "istream"
#include "media_errors.h"
#include "memory_manager.h"
#include "new"
#include "plugin_server.h"
#include "securec.h"
#include "singleton.h"
#include "string"
#include "type_traits"
#include "vector"
#include "image_trace.h"
#include "hitrace_meter.h"
#include "image_system_properties.h"
#include "image/abs_image_decoder.h"
#include "pixel_map.h"
#ifdef IOS_PLATFORM
#include <sys/syscall.h>
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "bundle_mgr_interface.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"
#include "os_account_manager.h"
#include "v1_0/cm_color_space.h"
#include "v1_0/buffer_handle_meta_key_type.h"
#include "metadata_helper.h"
#include "v1_0/hdr_static_metadata.h"
#include "vpe_utils.h"
#else
#include "refbase.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "libswscale/swscale.h"
#include "libavutil/opt.h"
#include "libavutil/imgutils.h"
#include "libavcodec/avcodec.h"
#ifdef __cplusplus
}
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "imageUtils"

namespace OHOS {
namespace Media {
using namespace std;
using namespace MultimediaPlugin;
#if !defined(CROSS_PLATFORM)
#define GET_VAR_NAME(var) #var
using namespace HDI::Display::Graphic::Common::V1_0;
#endif

constexpr int32_t ALPHA8_BYTES = 1;
constexpr int32_t RGB565_BYTES = 2;
constexpr int32_t RGB888_BYTES = 3;
constexpr int32_t ARGB8888_BYTES = 4;
constexpr int32_t RGBA_F16_BYTES = 8;
constexpr int32_t NV21_BYTES = 2;  // Each pixel is sorted on 3/2 bytes.
constexpr uint8_t MOVE_BITS_8 = 8;
constexpr uint8_t MOVE_BITS_16 = 16;
constexpr uint8_t MOVE_BITS_24 = 24;
constexpr int32_t NV21P010_BYTES = 3;
constexpr int32_t ASTC_4X4_BYTES = 1;
constexpr int32_t ASTC_4X4_BLOCK = 4;
constexpr int32_t ASTC_6X6_BLOCK = 6;
constexpr int32_t ASTC_8X8_BLOCK = 8;
constexpr int32_t ASTC_BLOCK_SIZE = 16;
constexpr int32_t ASTC_HEADER_SIZE = 16;
constexpr uint8_t FILL_NUMBER = 3;
constexpr uint8_t ALIGN_NUMBER = 4;
constexpr int32_t DMA_SIZE = 512 * 512; // DMA minimum effective size
constexpr int32_t FAULT_API_VERSION = -1;
constexpr int32_t BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
constexpr int32_t BASE_EVEN_DIVISOR = 2;
constexpr float EPSILON = 1e-6;
constexpr float FLOAT_1 = 1.0f;
constexpr int MAX_DIMENSION = INT32_MAX >> 2;
static bool g_pluginRegistered = false;
static const uint8_t NUM_0 = 0;
static const uint8_t NUM_1 = 1;
static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;
static const uint8_t NUM_5 = 5;
static const uint8_t NUM_6 = 6;
static const uint8_t NUM_7 = 7;
static const uint8_t INT_255 = 255;
static const string FILE_DIR_IN_THE_SANDBOX = "/data/storage/el2/base/files/";
static constexpr int32_t PLANE_Y = 0;
static constexpr int32_t PLANE_U = 1;
static constexpr int32_t PLANE_V = 2;
constexpr int32_t MEM_DMA = 1;
constexpr int32_t MEM_SHARE = 2;
constexpr uint32_t RGBA1010102_RGB_MASK = 0x3FF;
constexpr uint32_t RGBA1010102_ALPHA_MASK = 0x03;

constexpr uint32_t RGBA1010102_R_SHIFT = 0;
constexpr uint32_t RGBA1010102_G_SHIFT = 10;
constexpr uint32_t RGBA1010102_B_SHIFT = 20;
constexpr uint32_t RGBA1010102_A_SHIFT = 30;
const std::map<PixelFormat, AVPixelFormat> FFMPEG_PIXEL_FORMAT_MAP = {
    {PixelFormat::UNKNOWN, AV_PIX_FMT_NONE},
    {PixelFormat::NV12, AV_PIX_FMT_NV12},
    {PixelFormat::NV21, AV_PIX_FMT_NV21},
    {PixelFormat::RGB_565, AV_PIX_FMT_RGB565},
    {PixelFormat::RGBA_8888, AV_PIX_FMT_RGBA},
    {PixelFormat::BGRA_8888, AV_PIX_FMT_BGRA},
    {PixelFormat::ARGB_8888, AV_PIX_FMT_ARGB},
    {PixelFormat::RGBA_F16, AV_PIX_FMT_RGBA64},
    {PixelFormat::RGB_888, AV_PIX_FMT_RGB24},
    {PixelFormat::YCRCB_P010, AV_PIX_FMT_P010LE},
    {PixelFormat::YCBCR_P010, AV_PIX_FMT_P010LE},
};

#if !defined(CROSS_PLATFORM)
static const std::map<int32_t, PixelFormat> PIXEL_FORMAT_MAP = {
    { GRAPHIC_PIXEL_FMT_RGBA_8888, PixelFormat::RGBA_8888 },
    { GRAPHIC_PIXEL_FMT_YCBCR_420_SP, PixelFormat::NV12 },
    { GRAPHIC_PIXEL_FMT_YCRCB_420_SP, PixelFormat::NV21 },
    { GRAPHIC_PIXEL_FMT_RGBA_1010102, PixelFormat::RGBA_1010102 },
    { GRAPHIC_PIXEL_FMT_BGRA_8888, PixelFormat::BGRA_8888 },
    { GRAPHIC_PIXEL_FMT_RGB_888, PixelFormat::RGB_888 },
    { GRAPHIC_PIXEL_FMT_RGB_565, PixelFormat::RGB_565 },
    { GRAPHIC_PIXEL_FMT_RGBA16_FLOAT, PixelFormat::RGBA_F16 },
    { GRAPHIC_PIXEL_FMT_YCBCR_P010, PixelFormat::YCBCR_P010 },
    { GRAPHIC_PIXEL_FMT_YCRCB_P010, PixelFormat::YCRCB_P010 },
};

static const std::map<CM_ColorSpaceType, ColorSpace> CM_COLORSPACE_MAP = {
    { CM_COLORSPACE_NONE, ColorSpace::UNKNOWN },
    { CM_BT709_FULL, ColorSpace::ITU_709 },
    { CM_BT2020_HLG_FULL, ColorSpace::ITU_2020 },
    { CM_BT2020_PQ_FULL, ColorSpace::ITU_2020 },
    { CM_BT709_LIMIT, ColorSpace::ITU_709 },
    { CM_BT2020_HLG_LIMIT, ColorSpace::ITU_2020 },
    { CM_BT2020_PQ_LIMIT, ColorSpace::ITU_2020 },
    { CM_SRGB_FULL, ColorSpace::SRGB },
    { CM_P3_FULL, ColorSpace::DISPLAY_P3 },
    { CM_P3_HLG_FULL, ColorSpace::DISPLAY_P3 },
    { CM_P3_PQ_FULL, ColorSpace::DISPLAY_P3 },
    { CM_ADOBERGB_FULL, ColorSpace::ADOBE_RGB_1998 },
    { CM_SRGB_LIMIT, ColorSpace::SRGB },
    { CM_P3_LIMIT, ColorSpace::DISPLAY_P3 },
    { CM_P3_HLG_LIMIT, ColorSpace::DISPLAY_P3 },
    { CM_P3_PQ_LIMIT, ColorSpace::DISPLAY_P3 },
    { CM_ADOBERGB_LIMIT, ColorSpace::ADOBE_RGB_1998 },
    { CM_LINEAR_SRGB, ColorSpace::LINEAR_SRGB },
    { CM_LINEAR_BT709, ColorSpace::ITU_709 },
    { CM_LINEAR_P3, ColorSpace::DISPLAY_P3 },
    { CM_LINEAR_BT2020, ColorSpace::ITU_2020 },
    { CM_DISPLAY_SRGB, ColorSpace::SRGB },
    { CM_DISPLAY_P3_SRGB, ColorSpace::DISPLAY_P3 },
    { CM_DISPLAY_P3_HLG, ColorSpace::DISPLAY_P3 },
    { CM_DISPLAY_P3_PQ, ColorSpace::DISPLAY_P3 },
    { CM_DISPLAY_BT2020_SRGB, ColorSpace::ITU_2020 },
    { CM_DISPLAY_BT2020_HLG, ColorSpace::ITU_2020 },
    { CM_DISPLAY_BT2020_PQ, ColorSpace::ITU_2020 },
};

static const std::map<CM_ColorSpaceType, ColorManager::ColorSpaceName> CM_COLORSPACE_NAME_MAP = {
    {CM_COLORSPACE_NONE, ColorManager::NONE},
    {CM_BT601_EBU_FULL, ColorManager::BT601_EBU},
    {CM_BT601_SMPTE_C_FULL, ColorManager::BT601_SMPTE_C},
    {CM_BT709_FULL, ColorManager::BT709},
    {CM_BT2020_HLG_FULL, ColorManager::BT2020_HLG},
    {CM_BT2020_PQ_FULL, ColorManager::BT2020_PQ},
    {CM_BT601_EBU_LIMIT, ColorManager::BT601_EBU_LIMIT},
    {CM_BT601_SMPTE_C_LIMIT, ColorManager::BT601_SMPTE_C_LIMIT},
    {CM_BT709_LIMIT, ColorManager::BT709_LIMIT},
    {CM_BT2020_HLG_LIMIT, ColorManager::BT2020_HLG_LIMIT},
    {CM_BT2020_PQ_LIMIT, ColorManager::BT2020_PQ_LIMIT},
    {CM_SRGB_FULL, ColorManager::SRGB},
    {CM_P3_FULL, ColorManager::DISPLAY_P3},
    {CM_P3_HLG_FULL, ColorManager::P3_HLG},
    {CM_P3_PQ_FULL, ColorManager::P3_PQ},
    {CM_ADOBERGB_FULL, ColorManager::ADOBE_RGB},
    {CM_SRGB_LIMIT, ColorManager::SRGB_LIMIT},
    {CM_P3_LIMIT, ColorManager::DISPLAY_P3_LIMIT},
    {CM_P3_HLG_LIMIT, ColorManager::P3_HLG_LIMIT},
    {CM_P3_PQ_LIMIT, ColorManager::P3_PQ_LIMIT},
    {CM_ADOBERGB_LIMIT, ColorManager::ADOBE_RGB_LIMIT},
    {CM_LINEAR_SRGB, ColorManager::LINEAR_SRGB},
    {CM_LINEAR_BT709, ColorManager::LINEAR_BT709},
    {CM_LINEAR_P3, ColorManager::LINEAR_P3},
    {CM_LINEAR_BT2020, ColorManager::LINEAR_BT2020},
    {CM_DISPLAY_SRGB, ColorManager::DISPLAY_SRGB},
    {CM_DISPLAY_P3_SRGB, ColorManager::DISPLAY_P3_SRGB},
    {CM_DISPLAY_P3_HLG, ColorManager::DISPLAY_P3_HLG},
    {CM_DISPLAY_P3_PQ, ColorManager::DISPLAY_P3_PQ},
    {CM_DISPLAY_BT2020_SRGB, ColorManager::DISPLAY_BT2020_SRGB},
    {CM_DISPLAY_BT2020_HLG, ColorManager::DISPLAY_BT2020_HLG},
    {CM_DISPLAY_BT2020_PQ, ColorManager::DISPLAY_BT2020_PQ},
};
#endif


bool ImageUtils::GetFileSize(const string &pathName, size_t &size)
{
    if (pathName.empty()) {
        IMAGE_LOGE("[ImageUtil]input parameter exception.");
        return false;
    }
    struct stat statbuf;
    int ret = stat(pathName.c_str(), &statbuf);
    if (ret != 0) {
        IMAGE_LOGE("[ImageUtil]get the file size failed, ret:%{public}d, errno:%{public}d.", ret, errno);
        return false;
    }
    size = statbuf.st_size;
    return true;
}

bool ImageUtils::GetFileSize(const int fd, size_t &size)
{
    struct stat statbuf;

    if (fd < 0) {
        return false;
    }

    int ret = fstat(fd, &statbuf);
    if (ret != 0) {
        IMAGE_LOGE("[ImageUtil]get the file size failed, ret:%{public}d, errno:%{public}d.", ret, errno);
        return false;
    }
    size = statbuf.st_size;
    return true;
}

bool ImageUtils::GetInputStreamSize(istream &inputStream, size_t &size)
{
    if (inputStream.rdbuf() == nullptr) {
        IMAGE_LOGE("[ImageUtil]input parameter exception.");
        return false;
    }
    size_t original = inputStream.tellg();
    inputStream.seekg(0, ios_base::end);
    size = inputStream.tellg();
    inputStream.seekg(original);
    return true;
}

int32_t ImageUtils::GetPixelBytes(const PixelFormat &pixelFormat)
{
    int pixelBytes = 0;
    switch (pixelFormat) {
        case PixelFormat::ARGB_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGBA_8888:
        case PixelFormat::RGBA_1010102:
        case PixelFormat::CMYK:
            pixelBytes = ARGB8888_BYTES;
            break;
        case PixelFormat::ALPHA_8:
            pixelBytes = ALPHA8_BYTES;
            break;
        case PixelFormat::RGB_888:
            pixelBytes = RGB888_BYTES;
            break;
        case PixelFormat::RGB_565:
            pixelBytes = RGB565_BYTES;
            break;
        case PixelFormat::RGBA_F16:
        case PixelFormat::RGBA_U16:
            pixelBytes = RGBA_F16_BYTES;
            break;
        case PixelFormat::NV21:
        case PixelFormat::NV12:
            pixelBytes = NV21_BYTES;  // perl pixel 1.5 Bytes but return int so return 2
            break;
        case PixelFormat::ASTC_4x4:
        case PixelFormat::ASTC_6x6:
        case PixelFormat::ASTC_8x8:
            pixelBytes = ASTC_4X4_BYTES;
            break;
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010:
            pixelBytes = NV21P010_BYTES;
            break;
        default:
            IMAGE_LOGE("[ImageUtil]get pixel bytes failed, pixelFormat:%{public}d.",
                static_cast<int32_t>(pixelFormat));
            break;
    }
    return pixelBytes;
}

static AVPixelFormat PixelFormatToAVPixelFormat(const PixelFormat &pixelFormat)
{
    auto formatSearch = FFMPEG_PIXEL_FORMAT_MAP.find(pixelFormat);
    return (formatSearch != FFMPEG_PIXEL_FORMAT_MAP.end()) ?
        formatSearch->second : AVPixelFormat::AV_PIX_FMT_NONE;
}

int32_t ImageUtils::GetYUVByteCount(const ImageInfo& info)
{
    if (!IsYuvFormat(info.pixelFormat)) {
        IMAGE_LOGE("[ImageUtil]unsupported pixel format");
        return -1;
    }
    if (info.size.width <= 0 || info.size.height <= 0) {
        IMAGE_LOGE("[ImageUtil]image size error");
        return -1;
    }
    AVPixelFormat avPixelFormat = PixelFormatToAVPixelFormat(info.pixelFormat);
    if (avPixelFormat == AVPixelFormat::AV_PIX_FMT_NONE) {
        IMAGE_LOGE("[ImageUtil]pixel format to ffmpeg pixel format failed");
        return -1;
    }
    return av_image_get_buffer_size(avPixelFormat, info.size.width, info.size.height, 1);
}

int32_t ImageUtils::GetByteCount(ImageInfo imageInfo)
{
    if (ImageUtils::IsAstc(imageInfo.pixelFormat)) {
        return static_cast<int32_t>(ImageUtils::GetAstcBytesCount(imageInfo));
    }
    if (IsYuvFormat(imageInfo.pixelFormat)) {
        return GetYUVByteCount(imageInfo);
    }
    int64_t rowDataSize =
        ImageUtils::GetRowDataSizeByPixelFormat(imageInfo.size.width, imageInfo.pixelFormat);
    int64_t height = imageInfo.size.height;
    int64_t byteCount = rowDataSize * height;
    if (rowDataSize <= 0 || byteCount > INT32_MAX) {
        IMAGE_LOGE("[PixelMap] GetByteCount failed: invalid rowDataSize or byteCount overflowed");
        return 0;
    }
    return static_cast<int32_t>(byteCount);
}

int32_t ImageUtils::GetRowDataSizeByPixelFormat(const int32_t &width, const PixelFormat &format)
{
    uint64_t uWidth = static_cast<uint64_t>(width);
    uint64_t pixelBytes = static_cast<uint64_t>(GetPixelBytes(format));
    uint64_t rowDataSize = 0;
    switch (format) {
        case PixelFormat::ALPHA_8:
            rowDataSize = pixelBytes * ((uWidth + FILL_NUMBER) / ALIGN_NUMBER * ALIGN_NUMBER);
            break;
        case PixelFormat::ASTC_4x4:
            rowDataSize = pixelBytes * (((uWidth + NUM_3) >> NUM_2) << NUM_2);
            break;
        case PixelFormat::ASTC_6x6:
            rowDataSize = pixelBytes * (((uWidth + NUM_5) / NUM_6) * NUM_6);
            break;
        case PixelFormat::ASTC_8x8:
            rowDataSize = pixelBytes * (((uWidth + NUM_7) >> NUM_3) << NUM_3);
            break;
        default:
            rowDataSize = pixelBytes * uWidth;
    }
    if (rowDataSize > INT32_MAX) {
        IMAGE_LOGE("GetRowDataSizeByPixelFormat failed: rowDataSize overflowed");
        return -1;
    }
    return static_cast<int32_t>(rowDataSize);
}

uint32_t ImageUtils::RegisterPluginServer()
{
#ifdef _WIN32
    vector<string> pluginPaths = { "" };
#elif defined(_APPLE)
    vector<string> pluginPaths = { "./" };
#elif defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
    vector<string> pluginPaths = {};
#else
    vector<string> pluginPaths = { "/system/etc/multimediaplugin/image" };
#endif
    PluginServer &pluginServer = DelayedRefSingleton<PluginServer>::GetInstance();
    uint32_t result = pluginServer.Register(std::move(pluginPaths));
    if (result != SUCCESS) {
        IMAGE_LOGE("[ImageUtil]failed to register plugin server, ERRNO: %{public}u.", result);
    } else {
        g_pluginRegistered = true;
        IMAGE_LOGD("[ImageUtil]success to register plugin server");
    }
    return result;
}

PluginServer& ImageUtils::GetPluginServer()
{
    if (!g_pluginRegistered) {
        uint32_t result = RegisterPluginServer();
        if (result != SUCCESS) {
            IMAGE_LOGI("[ImageUtil]failed to register plugin server, ERRNO: %{public}u.", result);
        }
    }
    return DelayedRefSingleton<PluginServer>::GetInstance();
}

bool ImageUtils::PathToRealPath(const string &path, string &realPath)
{
    if (path.empty()) {
        IMAGE_LOGE("path is empty!");
        return false;
    }

    if ((path.length() >= PATH_MAX)) {
        IMAGE_LOGE("path len is error, the len is: [%{public}lu]", static_cast<unsigned long>(path.length()));
        return false;
    }

    char tmpPath[PATH_MAX] = { 0 };

#ifdef _WIN32
    if (_fullpath(tmpPath, path.c_str(), PATH_MAX) == nullptr) {
        IMAGE_LOGW("path to _fullpath error");
    }
#else
    if (realpath(path.c_str(), tmpPath) == nullptr) {
        IMAGE_LOGE("path to realpath is nullptr");
        return false;
    }
#endif

    realPath = tmpPath;
    return true;
}

bool ImageUtils::FloatCompareZero(float src)
{
    return fabs(src - 0) < EPSILON;
}

AlphaType ImageUtils::GetValidAlphaTypeByFormat(const AlphaType &dstType, const PixelFormat &format)
{
    switch (format) {
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGBA_1010102:
        case PixelFormat::RGBA_F16: {
            break;
        }
        case PixelFormat::ALPHA_8: {
            if (dstType != AlphaType::IMAGE_ALPHA_TYPE_PREMUL) {
                return AlphaType::IMAGE_ALPHA_TYPE_PREMUL;
            }
            break;
        }
        case PixelFormat::RGB_888:
        case PixelFormat::RGB_565: {
            if (dstType != AlphaType::IMAGE_ALPHA_TYPE_OPAQUE) {
                return AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
            }
            break;
        }
        case PixelFormat::NV21:
        case PixelFormat::NV12:
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010: {
            if (dstType != AlphaType::IMAGE_ALPHA_TYPE_OPAQUE) {
                return AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
            }
            break;
        }
        case PixelFormat::CMYK:
        default: {
            IMAGE_LOGE("GetValidAlphaTypeByFormat unsupport the format(%{public}d).", format);
            return AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
        }
    }
    return dstType;
}

AllocatorType ImageUtils::GetPixelMapAllocatorType(const Size &size, const PixelFormat &format, bool preferDma)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    return IsSizeSupportDma(size) && (preferDma || (IsWidthAligned(size.width) && IsFormatSupportDma(format))) &&
        (format == PixelFormat::RGBA_8888 || Is10Bit(format)) ?
        AllocatorType::DMA_ALLOC : AllocatorType::SHARE_MEM_ALLOC;
#else
    return AllocatorType::HEAP_ALLOC;
#endif
}

bool ImageUtils::IsValidImageInfo(const ImageInfo &info)
{
    if (info.size.width <= 0 || info.size.height <= 0 || info.size.width > MAX_DIMENSION ||
        info.size.height > MAX_DIMENSION) {
        IMAGE_LOGE("width(%{public}d) or height(%{public}d) is invalid.", info.size.width, info.size.height);
        return false;
    }
    if (info.pixelFormat == PixelFormat::UNKNOWN || info.alphaType == AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN) {
        IMAGE_LOGE("check pixelformat and alphatype is invalid.");
        return false;
    }
    return true;
}

bool ImageUtils::IsValidAuxiliaryInfo(const std::shared_ptr<PixelMap> &pixelMap, const AuxiliaryPictureInfo &info)
{
    int32_t rowSize = ImageUtils::GetRowDataSizeByPixelFormat(info.size.width, info.pixelFormat);
    bool cond = rowSize <= 0 || info.size.height <= 0 ||
                rowSize > std::numeric_limits<int32_t>::max() / info.size.height;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s rowSize: %{public}d, height: %{public}d may overflowed",
                               __func__, rowSize, info.size.height);
    uint32_t infoSize = static_cast<uint32_t>(rowSize * info.size.height);
    uint32_t pixelsSize = pixelMap->GetCapacity();
    cond = infoSize > pixelsSize;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s invalid infoSize: %{public}u, pixelsSize: %{public}u",
                               __func__, infoSize, pixelsSize);
    return true;
}

bool ImageUtils::IsAstc(PixelFormat format)
{
    return format == PixelFormat::ASTC_4x4 || format == PixelFormat::ASTC_6x6 || format == PixelFormat::ASTC_8x8;
}

bool IsYUV8Bit(PixelFormat &format)
{
    return format == PixelFormat::NV12 || format == PixelFormat::NV21;
}

bool IsYUV10Bit(PixelFormat &format)
{
    return format == PixelFormat::YCBCR_P010 || format == PixelFormat::YCRCB_P010;
}

bool ImageUtils::IsYuvFormat(PixelFormat format)
{
    return IsYUV8Bit(format) || IsYUV10Bit(format);
}

bool ImageUtils::IsRGBX(PixelFormat format)
{
    return format == PixelFormat::ARGB_8888 || format == PixelFormat::RGB_565 ||
        format == PixelFormat::RGBA_8888 || format == PixelFormat::BGRA_8888 ||
        format == PixelFormat::RGB_888 || format == PixelFormat::ALPHA_8 ||
        format == PixelFormat::RGBA_F16 || format == PixelFormat::RGBA_1010102 ||
        format == PixelFormat::RGBA_U16 || format == PixelFormat::UNKNOWN;
}

bool ImageUtils::PixelMapCreateCheckFormat(PixelFormat format)
{
    if (IsRGBX(format)) {
        return true;
    }
    if (IsYuvFormat(format)) {
        return true;
    }
    return false;
}

bool ImageUtils::CheckTlvSupportedFormat(PixelFormat format)
{
    if (format == PixelFormat::UNKNOWN || format == PixelFormat::RGBA_U16 ||
        IsYUV8Bit(format)) {
        return false;
    }
    if (IsRGBX(format)) {
        return true;
    }
    if (IsYUV10Bit(format)) {
        return true;
    }
    return false;
}

bool ImageUtils::IsWidthAligned(const int32_t &width)
{
    return ((static_cast<uint32_t>(width) * NUM_4) & INT_255) == 0;
}

bool ImageUtils::IsSizeSupportDma(const Size &size)
{
    // Check for overflow risk
    if (size.width > 0 && size.height > INT_MAX / size.width) {
        return false;
    }
    return size.width * size.height >= DMA_SIZE;
}

bool ImageUtils::IsFormatSupportDma(const PixelFormat &format)
{
    return format == PixelFormat::UNKNOWN || format == PixelFormat::RGBA_8888;
}

bool ImageUtils::Is10Bit(const PixelFormat &format)
{
    return format == PixelFormat::RGBA_1010102 ||
        format == PixelFormat::YCRCB_P010 || format == PixelFormat::YCBCR_P010;
}

bool ImageUtils::CheckMulOverflow(int32_t width, int32_t bytesPerPixel)
{
    if (width == 0 || bytesPerPixel == 0) {
        IMAGE_LOGE("param is 0");
        return true;
    }
    int32_t rowSize = width * bytesPerPixel;
    if ((rowSize / width) != bytesPerPixel) {
        IMAGE_LOGE("width * bytesPerPixel overflow!");
        return true;
    }
    return false;
}

bool ImageUtils::CheckMulOverflow(int32_t width, int32_t height, int32_t bytesPerPixel)
{
    if (width == 0 || height == 0 || bytesPerPixel == 0) {
        IMAGE_LOGE("param is 0");
        return true;
    }
    int32_t rectSize = width * height;
    if ((rectSize / width) != height) {
        IMAGE_LOGE("width * height overflow!");
        return true;
    }
    int32_t bufferSize = rectSize * bytesPerPixel;
    if ((bufferSize / bytesPerPixel) != rectSize) {
        IMAGE_LOGE("bytesPerPixel overflow!");
        return true;
    }
    return false;
}

bool ImageUtils::CheckFloatMulOverflow(float num1, float num2)
{
    if (fabs(num1) <= FLOAT_1 || fabs(num2) <= FLOAT_1) {
        return false;
    }
    CHECK_ERROR_RETURN_RET_LOG(fabs(num1) > std::numeric_limits<float>::max() / fabs(num2), true,
        "num1 * num2 overflow! num1:%{public}f, num2:%{public}f", num1, num2);
    return false;
}

static void ReversePixels(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    if (byteCount % NUM_4 != NUM_0) {
        IMAGE_LOGE("Pixel count must multiple of 4.");
        return;
    }
    uint8_t *src = srcPixels;
    uint8_t *dst = dstPixels;
    for (uint32_t i = NUM_0 ; i < byteCount; i += NUM_4) {
        // 0-B 1-G 2-R 3-A
        dst[NUM_0] = src[NUM_3];
        dst[NUM_1] = src[NUM_2];
        dst[NUM_2] = src[NUM_1];
        dst[NUM_3] = src[NUM_0];
        src += NUM_4;
        dst += NUM_4;
    }
}

void ImageUtils::BGRAToARGB(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    ImageTrace imageTrace("BGRAToARGB");
    ReversePixels(srcPixels, dstPixels, byteCount);
}

void ImageUtils::ARGBToBGRA(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount)
{
    ReversePixels(srcPixels, dstPixels, byteCount);
}

int32_t ImageUtils::SurfaceBuffer_Reference(void* buffer)
{
    if (buffer == nullptr) {
        IMAGE_LOGE("input parameter error");
        return ERR_SURFACEBUFFER_REFERENCE_FAILED;
    }
    OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(buffer);
    ref->IncStrongRef(ref);
    return SUCCESS;
}

int32_t ImageUtils::SurfaceBuffer_Unreference(void* buffer)
{
    if (buffer == nullptr) {
        IMAGE_LOGE("input parameter error");
        return ERR_SURFACEBUFFER_UNREFERENCE_FAILED;
    }
    OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(buffer);
    ref->DecStrongRef(ref);
    return SUCCESS;
}

#if !defined(CROSS_PLATFORM)
bool ImageUtils::GetYuvInfoFromSurfaceBuffer(YUVDataInfo &yuvInfo,
    sptr<SurfaceBuffer> surfaceBuffer)
{
    OH_NativeBuffer_Planes* planes = nullptr;
    GSError retVal = surfaceBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    if (retVal == OHOS::GSERROR_OK && planes != nullptr && planes->planeCount >= NUM_2) {
        yuvInfo.yStride = planes->planes[PLANE_Y].columnStride;
        yuvInfo.uvStride = planes->planes[PLANE_U].columnStride;
        yuvInfo.yOffset = planes->planes[PLANE_Y].offset;
        if (surfaceBuffer->GetFormat() == GRAPHIC_PIXEL_FMT_YCRCB_420_SP) {
            yuvInfo.uvOffset = planes->planes[PLANE_V].offset;
        } else {
            yuvInfo.uvOffset = planes->planes[PLANE_U].offset;
        }
        return true;
    } else {
        IMAGE_LOGE("%{public}s, get planesInfo failed, retVal:%{public}d", __func__, retVal);
        return false;
    }
}

bool ImageUtils::CopyYuvPixelMapToSurfaceBuffer(PixelMap* pixelmap,
    sptr<SurfaceBuffer> surfaceBuffer)
{
    uint8_t* src = const_cast<uint8_t*>(pixelmap->GetPixels());
    uint8_t* dst = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
    uint32_t dstSize = surfaceBuffer->GetSize();

    YUVDataInfo yuvDstInfo;
    YUVDataInfo yuvSrcInfo;
    pixelmap->GetImageYUVInfo(yuvSrcInfo);

    bool cond = !ImageUtils::GetYuvInfoFromSurfaceBuffer(yuvDstInfo, surfaceBuffer);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Get YUVInfo from SurfaceBuffer failed");

    for (uint32_t i = 0; i < yuvSrcInfo.yHeight; ++i) {
        if (memcpy_s(dst, dstSize, src, yuvSrcInfo.yWidth) != EOK) {
            return false;
        }
        dst += yuvDstInfo.yStride;
        dstSize -= yuvDstInfo.yStride;
        src += yuvSrcInfo.yWidth;
    }

    uint64_t uvWidth = yuvSrcInfo.uvWidth * NUM_2;
    dst = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr()) + yuvDstInfo.uvOffset;

    for (uint32_t i = 0; i < yuvSrcInfo.uvHeight; ++i) {
        if (memcpy_s(dst, dstSize, src, uvWidth) != EOK) {
            return false;
        }
        dst += yuvDstInfo.uvStride;
        dstSize -= yuvDstInfo.uvStride;
        src += uvWidth;
    }

    return true;
}
#endif

void ImageUtils::DumpPixelMap(PixelMap* pixelMap, std::string customFileName, uint64_t imageId)
{
    IMAGE_LOGI("ImageUtils::DumpPixelMap start");
    std::string fileName = FILE_DIR_IN_THE_SANDBOX + GetLocalTime() + customFileName + std::to_string(imageId) +
        GetPixelMapName(pixelMap) + ".dat";
    int32_t totalSize = pixelMap->GetRowStride() * pixelMap->GetHeight();
    PixelFormat pixelFormat = pixelMap->GetPixelFormat();
    if (pixelFormat == PixelFormat::NV12 || pixelFormat == PixelFormat::NV21 ||
        pixelFormat == PixelFormat::YCBCR_P010 || pixelFormat == PixelFormat::YCRCB_P010) {
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
        if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
            auto sbBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
            if (!sbBuffer) {
                return;
            }
            totalSize = static_cast<int32_t>(sbBuffer->GetSize());
        } else {
            totalSize = static_cast<int32_t>(pixelMap->GetCapacity());
        }
#else
        totalSize = static_cast<int32_t>(pixelMap->GetCapacity());
#endif
        IMAGE_LOGI("ImageUtils::DumpPixelMapIfDumpEnabled YUV420 totalSize is %{public}d", totalSize);
    }
    if (SUCCESS != SaveDataToFile(fileName, reinterpret_cast<const char*>(pixelMap->GetPixels()), totalSize)) {
        IMAGE_LOGI("ImageUtils::DumpPixelMap failed");
        return;
    }
    IMAGE_LOGI("ImageUtils::DumpPixelMap success, path = %{public}s", fileName.c_str());
}

void ImageUtils::DumpPixelMapIfDumpEnabled(std::unique_ptr<PixelMap>& pixelMap, uint64_t imageId)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }
    if (pixelMap == nullptr) {
        IMAGE_LOGI("ImageUtils::DumpPixelMapIfDumpEnabled pixelMap is null");
        return;
    }
    DumpPixelMap(pixelMap.get(), "_imageId", imageId);
}

void ImageUtils::DumpPixelMapIfDumpEnabled(PixelMap& pixelMap, std::string func)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }
    DumpPixelMap(&pixelMap, "_imageId_" + func + "_");
}

void ImageUtils::DumpPixelMapBeforeEncode(PixelMap& pixelMap)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }
    DumpPixelMap(&pixelMap, "_beforeEncode");
}

void ImageUtils::DumpData(const char* data, const size_t& totalSize,
    const std::string& fileSuffix, uint64_t imageId)
{
    std::string fileName = FILE_DIR_IN_THE_SANDBOX + GetLocalTime() + "_imageId" + std::to_string(imageId) +
        "_data_total" + std::to_string(totalSize) + "." + fileSuffix;
    if (SUCCESS != SaveDataToFile(fileName, data, totalSize)) {
        IMAGE_LOGI("ImageUtils::DumpDataIfDumpEnabled failed");
        return;
    }
    IMAGE_LOGI("ImageUtils::DumpDataIfDumpEnabled success, path = %{public}s", fileName.c_str());
}

void ImageUtils::DumpDataIfDumpEnabled(const char* data, const size_t& totalSize,
    const std::string& fileSuffix, uint64_t imageId)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }
    DumpData(data, totalSize, fileSuffix, imageId);
}

#if !defined(CROSS_PLATFORM)
void ImageUtils::DumpHdrBufferEnabled(sptr<SurfaceBuffer>& buffer, const std::string& fileName)
{
    bool cond = !ImageSystemProperties::GetDumpHdrEnabled() || buffer == nullptr;
    CHECK_ERROR_RETURN(cond);
    uint32_t bufferSize = buffer->GetSize();
    std::string fileSuffix = fileName + "-format-" + std::to_string(buffer->GetFormat()) + "-Width-"
        + std::to_string(buffer->GetWidth()) + "-Height-" + std::to_string(buffer->GetHeight()) + "-Stride-"
        + std::to_string(buffer->GetStride()) + ".dat";
    std::vector<uint8_t> staticMetadata;
    std::vector<uint8_t> dynamicMetadata;
    buffer->GetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_STATIC_METADATA, staticMetadata);
    buffer->GetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata);
    uint64_t bufferId = buffer->GetBufferId();
    DumpData(reinterpret_cast<const char*>(buffer->GetVirAddr()), bufferSize, fileSuffix, bufferId);
    DumpData(reinterpret_cast<const char*>(staticMetadata.data()), staticMetadata.size(), fileSuffix, bufferId);
    DumpData(reinterpret_cast<const char*>(dynamicMetadata.data()), dynamicMetadata.size(), fileSuffix, bufferId);
}

template <typename T>
static void AppendStringifyPropToStream(int intend, std::stringstream& ss, std::string varName, T arr,
    size_t length)
{
    ss << std::string(intend, ' ') << varName << "[" << length << "]:";
    for (size_t i = 0; i < length; ++i) {
        ss << " " << static_cast<double>(arr[i]);
    }
    ss << "\n";
}

template <typename T>
static void AppendStringifyPropToStream(int intend, std::stringstream& ss, std::string varName, T value)
{
    ss << std::string(intend, ' ') << varName << ": " << static_cast<double>(value) << "\n";
}

static void AppendISOMetadataToStream(int intend, std::stringstream& ss, const ISOMetadata& iso)
{
    ss << std::string(intend, ' ') << "ISOMetadata" << " {\n";
    int nextIntend = intend + 1;
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.writeVersion), iso.writeVersion);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.miniVersion), iso.miniVersion);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.gainmapChannelNum), iso.gainmapChannelNum);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.useBaseColorFlag), iso.useBaseColorFlag);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.baseHeadroom), iso.baseHeadroom);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.alternateHeadroom), iso.alternateHeadroom);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.enhanceClippedThreholdMaxGainmap),
        iso.enhanceClippedThreholdMaxGainmap, std::size(iso.enhanceClippedThreholdMaxGainmap));
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.enhanceClippedThreholdMinGainmap),
        iso.enhanceClippedThreholdMinGainmap, std::size(iso.enhanceClippedThreholdMaxGainmap));
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.enhanceMappingGamma),
        iso.enhanceMappingGamma, std::size(iso.enhanceClippedThreholdMaxGainmap));
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.enhanceMappingBaselineOffset),
        iso.enhanceMappingBaselineOffset, std::size(iso.enhanceClippedThreholdMaxGainmap));
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(iso.enhanceMappingAlternateOffset),
        iso.enhanceMappingAlternateOffset, std::size(iso.enhanceClippedThreholdMaxGainmap));
    ss << std::string(intend, ' ') << "}\n";
}

static void AppendGainmapColorMetadataToStream(int intend, std::stringstream& ss, const GainmapColorMetadata& gcm)
{
    ss << std::string(intend, ' ') << "GainmapColorMetadata" << " {\n";
    int nextIntend = intend + 1;
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.enhanceDataColorPrimary), gcm.enhanceDataColorPrimary);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.enhanceDataTransFunction),
        gcm.enhanceDataTransFunction);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.enhanceDataColorModel), gcm.enhanceDataColorModel);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineColorPrimary), gcm.combineColorPrimary);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineTransFunction), gcm.combineTransFunction);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineColorModel), gcm.combineColorModel);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.alternateColorPrimary), gcm.alternateColorPrimary);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.alternateTransFunction), gcm.alternateTransFunction);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.alternateColorModel), gcm.alternateColorModel);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.enhanceICCSize), gcm.enhanceICCSize);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.enhanceICC), gcm.enhanceICC, gcm.enhanceICC.size());
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineMappingFlag), gcm.combineMappingFlag);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineMappingSize), gcm.combineMappingSize);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineMappingMatrix), gcm.combineMappingMatrix,
        std::size(gcm.combineMappingMatrix));
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(gcm.combineMapping), gcm.combineMapping,
        gcm.combineMapping.size());
    ss << std::string(intend, ' ') << "}\n";
}

static void AppendBaseColorMetadataToStream(int intend, std::stringstream& ss, const BaseColorMetadata& bcm)
{
    ss << std::string(intend, ' ') << "BaseColorMetadata" << " {\n";
    int nextIntend = intend + 1;
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseColorPrimary), bcm.baseColorPrimary);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseTransFunction), bcm.baseTransFunction);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseColorModel), bcm.baseColorModel);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseIccSize), bcm.baseIccSize);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseICC), bcm.baseICC, bcm.baseICC.size());
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseMappingFlag), bcm.baseMappingFlag);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseMappingSize), bcm.baseMappingSize);
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseMappingMatrix), bcm.baseMappingMatrix,
        std::size(bcm.baseMappingMatrix));
    AppendStringifyPropToStream(nextIntend, ss, GET_VAR_NAME(bcm.baseMapping), bcm.baseMapping, bcm.baseMapping.size());
    ss << std::string(intend, ' ') << "}\n";
}

static std::string StringifyHDRVividExtendMetadata(const HDRVividExtendMetadata& meta)
{
    std::stringstream ss;
    int intend = 0;

    ss << "HDRVividExtendMetadata {\n";
    AppendISOMetadataToStream(intend + 1, ss, meta.metaISO);
    AppendGainmapColorMetadataToStream(intend + 1, ss, meta.gainmapColorMeta);
    AppendBaseColorMetadataToStream(intend + 1, ss, meta.baseColorMeta);
    ss << "}\n";

    std::string hdrExtendMetadataStr = ss.str();
    return hdrExtendMetadataStr;
}

void ImageUtils::DumpHdrExtendMetadataEnabled(sptr<SurfaceBuffer>& buffer, const std::string& fileName)
{
    bool cond = !ImageSystemProperties::GetDumpHdrEnabled() || buffer == nullptr;
    CHECK_ERROR_RETURN(cond);
    std::string fileSuffix = fileName + "-format-" + std::to_string(buffer->GetFormat()) + "-Width-"
        + std::to_string(buffer->GetWidth()) + "-Height-" + std::to_string(buffer->GetHeight()) + "-Stride-"
        + std::to_string(buffer->GetStride()) + ".dat";

    std::vector<uint8_t> dynamicMetadata;
    buffer->GetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata);
    HDRVividExtendMetadata extendMetadata = {};

    size_t copySize = std::min(sizeof(HDRVividExtendMetadata), dynamicMetadata.size());
    int32_t memCpyRes = memcpy_s(&extendMetadata, sizeof(HDRVividExtendMetadata),
        dynamicMetadata.data(), copySize);
    if (memCpyRes != EOK) {
        IMAGE_LOGE("%{public}s memcpy_s extendMetadata fail, error: %{public}d", __func__, memCpyRes);
        return;
    }

    std::string hdrExtendMetadataStr = StringifyHDRVividExtendMetadata(extendMetadata);
    DumpData(reinterpret_cast<const char*>(hdrExtendMetadataStr.data()), hdrExtendMetadataStr.size(), fileSuffix,
        buffer->GetBufferId());
}

void ImageUtils::DumpSurfaceBufferAllKeysEnabled(sptr<SurfaceBuffer>& buffer, const std::string& fileName)
{
    bool cond = !ImageSystemProperties::GetDumpHdrEnabled() || buffer == nullptr;
    CHECK_ERROR_RETURN(cond);
    std::string filePrefix = fileName + "-format-" + std::to_string(buffer->GetFormat()) + "-Width-"
        + std::to_string(buffer->GetWidth()) + "-Height-" + std::to_string(buffer->GetHeight()) + "-Stride-"
        + std::to_string(buffer->GetStride());

    uint64_t bufferId = buffer->GetBufferId();
    std::vector<uint8_t> attrInfo{};
    std::vector<uint32_t> keys{};
    if (buffer->ListMetadataKeys(keys) == GSERROR_OK && !keys.empty()) {
        for (size_t i = 0; i < keys.size(); i++) {
            if (buffer->GetMetadata(keys[i], attrInfo) == GSERROR_OK && !attrInfo.empty()) {
                IMAGE_LOGD("%{public}s dump SurfaceBufferInfo metadata key:%{public}d", __func__, keys[i]);
                std::string fileSuffix = filePrefix + "-key-" + std::to_string(keys[i]) + ".dat";
                DumpData(reinterpret_cast<const char*>(attrInfo.data()), attrInfo.size(), fileSuffix, bufferId);
            }
            attrInfo.clear();
        }
    }
}

ColorManager::ColorSpaceName ImageUtils::SbCMColorSpaceType2ColorSpaceName(
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_NAME_MAP.find(type);
    CHECK_ERROR_RETURN_RET(iter == CM_COLORSPACE_NAME_MAP.end(), ColorManager::NONE);
    return iter->second;
}

static bool IsAlphaFormat(PixelFormat format)
{
    return format == PixelFormat::RGBA_8888 || format == PixelFormat::BGRA_8888 ||
        format == PixelFormat::RGBA_1010102 || format == PixelFormat::RGBA_F16;
}

PixelFormat ImageUtils::SbFormat2PixelFormat(int32_t sbFormat)
{
    auto iter = PIXEL_FORMAT_MAP.find(sbFormat);
    if (iter == PIXEL_FORMAT_MAP.end()) {
        return PixelFormat::UNKNOWN;
    }
    return iter->second;
}

static CM_ColorSpaceType GetCMColorSpaceType(sptr<SurfaceBuffer>& buffer)
{
    CHECK_ERROR_RETURN_RET(buffer == nullptr, CM_ColorSpaceType::CM_COLORSPACE_NONE);
    CM_ColorSpaceType type;
    MetadataHelper::GetColorSpaceType(buffer, type);
    return type;
}

static ColorSpace CMColorSpaceType2ColorSpace(CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_MAP.find(type);
    CHECK_ERROR_RETURN_RET(iter == CM_COLORSPACE_MAP.end(), ColorSpace::UNKNOWN);
    return iter->second;
}

#ifdef IMAGE_COLORSPACE_FLAG
static ColorManager::ColorSpaceName CMColorSpaceType2ColorSpaceName(CM_ColorSpaceType type)
{
    auto iter = CM_COLORSPACE_NAME_MAP.find(type);
    CHECK_ERROR_RETURN_RET(iter == CM_COLORSPACE_NAME_MAP.end(), ColorManager::NONE);
    return iter->second;
}
#endif

static ImageInfo MakeImageInfo(int width, int height, PixelFormat pf, AlphaType at, ColorSpace cs)
{
    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = pf;
    info.alphaType = at;
    info.colorSpace = cs;
    return info;
}

void ImageUtils::SetYuvDataInfo(std::unique_ptr<PixelMap> &pixelMap, sptr<OHOS::SurfaceBuffer> &sBuffer)
{
    bool cond = pixelMap == nullptr || sBuffer == nullptr;
    CHECK_ERROR_RETURN(cond);
    int32_t width = sBuffer->GetWidth();
    int32_t height = sBuffer->GetHeight();
    OH_NativeBuffer_Planes *planes = nullptr;
    GSError retVal = sBuffer->GetPlanesInfo(reinterpret_cast<void**>(&planes));
    YUVDataInfo info;
    info.imageSize = { width, height };
    cond = retVal != OHOS::GSERROR_OK || planes == nullptr || planes->planeCount <= NUM_1;
    CHECK_ERROR_RETURN_LOG(cond, "Get planesInfo failed, retVal:%{public}d", retVal);
    info.yWidth = static_cast<uint32_t>(width);
    info.uvWidth = static_cast<uint32_t>(width / NUM_2);
    info.yHeight = static_cast<uint32_t>(height);
    info.uvHeight = static_cast<uint32_t>(height / NUM_2);
    if (planes->planeCount >= NUM_2) {
        int32_t pixelFmt = sBuffer->GetFormat();
        bool isYuvP010 = (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_P010 || pixelFmt == GRAPHIC_PIXEL_FMT_YCRCB_P010);
        int uvPlaneOffset = (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_420_SP ||
            pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_P010) ? NUM_1 : NUM_2;
        info.yStride = isYuvP010 ? (planes->planes[NUM_0].columnStride / NUM_2) : (planes->planes[NUM_0].columnStride);
        info.uvStride = isYuvP010 ? (planes->planes[uvPlaneOffset].columnStride / NUM_2) :
            (planes->planes[uvPlaneOffset].columnStride);
        info.yOffset = isYuvP010 ? (planes->planes[NUM_0].offset / NUM_2) : (planes->planes[NUM_0].offset);
        info.uvOffset =
            isYuvP010 ? (planes->planes[uvPlaneOffset].offset / NUM_2) : (planes->planes[uvPlaneOffset].offset);
    }
    pixelMap->SetImageYUVInfo(info);
}

bool ImageUtils::SurfaceBuffer2PixelMap(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, std::unique_ptr<PixelMap> &Pixelmap)
{
    if (surfaceBuffer == nullptr || Pixelmap == nullptr) {
        return false;
    }
    PixelFormat pixelFormat = ImageUtils::SbFormat2PixelFormat(surfaceBuffer->GetFormat());
    ColorSpace colorSpace = CMColorSpaceType2ColorSpace(GetCMColorSpaceType(surfaceBuffer));
    AlphaType alphaType = IsAlphaFormat(pixelFormat) ?
        AlphaType::IMAGE_ALPHA_TYPE_PREMUL : AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    int32_t err = ImageUtils::SurfaceBuffer_Reference(nativeBuffer);
    CHECK_ERROR_RETURN_RET_LOG(err != OHOS::GSERROR_OK, false, "NativeBufferReference failed");

    ImageInfo imageInfo = MakeImageInfo(surfaceBuffer->GetWidth(),
                                        surfaceBuffer->GetHeight(), pixelFormat, alphaType, colorSpace);
    Pixelmap->SetImageInfo(imageInfo, true);
    Pixelmap->SetPixelsAddr(surfaceBuffer->GetVirAddr(),
                            nativeBuffer, Pixelmap->GetRowBytes() * Pixelmap->GetHeight(),
                            AllocatorType::DMA_ALLOC, nullptr);
#ifdef IMAGE_COLORSPACE_FLAG
    ColorManager::ColorSpaceName colorSpaceName =
        CMColorSpaceType2ColorSpaceName(GetCMColorSpaceType(surfaceBuffer));
    Pixelmap->InnerSetColorSpace(ColorManager::ColorSpace(colorSpaceName));
#endif
    if (ImageUtils::IsYuvFormat(pixelFormat)) {
        SetYuvDataInfo(Pixelmap, surfaceBuffer);
    }
    return true;
}

#endif

uint64_t ImageUtils::GetNowTimeMilliSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

uint64_t ImageUtils::GetNowTimeMicroSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

std::string ImageUtils::GetCurrentProcessName()
{
    std::string processName;
    std::ifstream cmdlineFile("/proc/self/cmdline");
    if (cmdlineFile.is_open()) {
        std::ostringstream oss;
        oss << cmdlineFile.rdbuf();
        cmdlineFile.close();

        //Extrace process name from the command line
        std::string cmdline = oss.str();
        size_t pos = cmdline.find_first_of('\0');
        if (pos != std::string::npos) {
            processName = cmdline.substr(0, pos);
        }
    }
    return processName;
}

bool ImageUtils::SetInitializationOptionAutoMem(InitializationOptions &option)
{
    if (option.pixelFormat == PixelFormat::RGBA_1010102||
        option.pixelFormat == PixelFormat::YCBCR_P010||
        option.pixelFormat == PixelFormat::YCRCB_P010) {
        option.allocatorType = AllocatorType::DMA_ALLOC;
        option.useDMA = true;
        return true;
    }
    if (option.size.width * option.size.height >= DMA_SIZE) {
        if (SetInitializationOptionDmaMem(option)) {
            return true;
        }
    }
    option.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    option.useDMA = false;
    return true;
}

bool ImageUtils::SetInitializationOptionDmaMem(InitializationOptions &option)
{
    switch (option.pixelFormat) {
        case PixelFormat::RGB_565:
        case PixelFormat::RGBA_8888:
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGBA_F16:
        case PixelFormat::RGBA_1010102:
        case PixelFormat::YCBCR_P010:
        case PixelFormat::YCRCB_P010:
            option.allocatorType = AllocatorType::DMA_ALLOC;
            option.useDMA = true;
            return true;
        default:
            IMAGE_LOGE("pixelformat:%{public}d is not surport DMA.", option.pixelFormat);
            return false;
    }
    return false;
}

bool ImageUtils::SetInitializationOptionAllocatorType(InitializationOptions &option, int32_t allocatorType)
{
    if (allocatorType > NUM_2 || allocatorType < 0) {
        IMAGE_LOGE("allocatorType is invalided.");
        return false;
    }
    switch (allocatorType) {
        case MEM_DMA:
            return SetInitializationOptionDmaMem(option);
        case MEM_SHARE:
            if (option.pixelFormat == PixelFormat::RGBA_1010102 ||
                option.pixelFormat == PixelFormat::YCBCR_P010 ||
                option.pixelFormat == PixelFormat::YCRCB_P010) {
                IMAGE_LOGE("pixelFormat is unsupport:%{public}d.", option.pixelFormat);
                return false;
            }
            option.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
            option.useDMA = false;
            return true;
        default:
            return SetInitializationOptionAutoMem(option);
    }
    return true;
}

uint32_t ImageUtils::SaveDataToFile(const std::string& fileName, const char* data, const size_t& totalSize)
{
    std::ofstream outFile(fileName, std::ofstream::out);
    if (!outFile.is_open()) {
        IMAGE_LOGI("ImageUtils::SaveDataToFile write error, path=%{public}s", fileName.c_str());
        return IMAGE_RESULT_SAVE_DATA_TO_FILE_FAILED;
    }
    if (data == nullptr) {
        IMAGE_LOGE("ImageUtils::SaveDataToFile data is nullptr");
        return IMAGE_RESULT_SAVE_DATA_TO_FILE_FAILED;
    }
    outFile.write(data, totalSize);
    return SUCCESS;
}

std::string ImageUtils::GetLocalTime()
{
    // time string : "year-month-day hour_minute_second.millisecond", ':' is not supported in windows file name
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&t);
    if (tm == nullptr) {
        IMAGE_LOGE("ImageUtils::GetLocalTime error, returned nullptr");
        return "";
    }

    std::stringstream ss;
    int millSecondWidth = 3;
    ss << std::put_time(tm, "%Y-%m-%d %H_%M_%S.") << std::setfill('0') << std::setw(millSecondWidth) << ms.count();
    return ss.str();
}

std::string ImageUtils::GetPixelMapName(PixelMap* pixelMap)
{
    if (!pixelMap) {
        IMAGE_LOGE("ImageUtils::GetPixelMapName error, pixelMap is null");
        return "";
    }
#ifdef IOS_PLATFORM
    std::string pixelMapStr = "_pixelMap_w" + std::to_string(pixelMap->GetWidth()) +
        "_h" + std::to_string(pixelMap->GetHeight()) +
        "_rowStride" + std::to_string(pixelMap->GetRowStride()) +
        "_pixelFormat" + std::to_string((int32_t)pixelMap->GetPixelFormat()) +
        "_total" + std::to_string(pixelMap->GetRowStride() * pixelMap->GetHeight()) +
        "_pid" + std::to_string(getpid()) +
        "_tid" + std::to_string(syscall(SYS_thread_selfid)) +
        "_uniqueId" + std::to_string(pixelMap->GetUniqueId());
#else
    std::string yuvInfoStr = "";
    if (pixelMap->GetPixelFormat() == PixelFormat::NV12 || pixelMap->GetPixelFormat() == PixelFormat::NV21) {
        YUVDataInfo yuvInfo;
        pixelMap->GetImageYUVInfo(yuvInfo);
        yuvInfoStr += "_yWidth" + std::to_string(yuvInfo.yWidth) +
            "_yHeight" + std::to_string(yuvInfo.yHeight) +
            "_yStride" + std::to_string(yuvInfo.yStride) +
            "_yOffset" + std::to_string(yuvInfo.yOffset) +
            "_uvWidth" + std::to_string(yuvInfo.uvWidth) +
            "_uvHeight" + std::to_string(yuvInfo.uvHeight) +
            "_uvStride" + std::to_string(yuvInfo.uvStride) +
            "_uvOffset" + std::to_string(yuvInfo.uvOffset);
    }
    std::string pixelMapStr = "_pixelMap_w" + std::to_string(pixelMap->GetWidth()) +
        "_h" + std::to_string(pixelMap->GetHeight()) +
        "_rowStride" + std::to_string(pixelMap->GetRowStride()) +
        "_pixelFormat" + std::to_string((int32_t)pixelMap->GetPixelFormat()) +
        "_total" + std::to_string(pixelMap->GetRowStride() * pixelMap->GetHeight()) +
        "_pid" + std::to_string(getpid()) +
        "_tid" + std::to_string(gettid()) +
        "_uniqueId" + std::to_string(pixelMap->GetUniqueId());
#endif
    return pixelMapStr;
}

 // BytesToUint16 function will modify the offset value.
uint16_t ImageUtils::BytesToUint16(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian)
{
    uint16_t data = 0;
    if (bytes == nullptr || offset + NUM_2 > size) {
        return data;
    }
    if (isBigEndian) {
        data = (bytes[offset] << MOVE_BITS_8) | bytes[offset + NUM_1];
    } else {
        data = (bytes[offset + NUM_1] << MOVE_BITS_8) | bytes[offset];
    }
    offset += NUM_2;
    return data;
}

// BytesToUint32 function will modify the offset value.
uint32_t ImageUtils::BytesToUint32(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian)
{
    uint32_t data = 0;
    if (bytes == nullptr || offset + NUM_4 > size) {
        return data;
    }
    if (isBigEndian) {
        data = (bytes[offset] << MOVE_BITS_24) | (bytes[offset + NUM_1] << MOVE_BITS_16) |
                (bytes[offset + NUM_2] << MOVE_BITS_8) | (bytes[offset + NUM_3]);
    } else {
        data = (bytes[offset + NUM_3] << MOVE_BITS_24) | (bytes[offset + NUM_2] << MOVE_BITS_16) |
                (bytes[offset + NUM_1] << MOVE_BITS_8) | bytes[offset];
    }
    offset += NUM_4;
    return data;
}

// BytesToInt32 function will modify the offset value.
int32_t ImageUtils::BytesToInt32(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian)
{
    int32_t data = 0;
    if (bytes == nullptr || offset + NUM_4 > size) {
        return data;
    }
    if (isBigEndian) {
        data = (bytes[offset] << MOVE_BITS_24) | (bytes[offset + NUM_1] << MOVE_BITS_16) |
                (bytes[offset + NUM_2] << MOVE_BITS_8) | (bytes[offset + NUM_3]);
    } else {
        data = (bytes[offset + NUM_3] << MOVE_BITS_24) | (bytes[offset + NUM_2] << MOVE_BITS_16) |
                (bytes[offset + NUM_1] << MOVE_BITS_8) | bytes[offset];
    }
    offset += NUM_4;
    return data;
}

// BytesToFloat function will modify the offset value.
float ImageUtils::BytesToFloat(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian)
{
    uint32_t data = BytesToUint32(bytes, offset, size, isBigEndian);
    union {
        uint32_t i;
        float f;
    } u;
    u.i = data;
    return u.f;
}

void ImageUtils::Uint16ToBytes(uint16_t data, vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian)
{
    uint8_t BYTE_ONE = (data >> MOVE_BITS_8) & 0xFF;
    uint8_t BYTE_TWO = data & 0xFF;
    if (isBigEndian) {
        bytes[offset++] = BYTE_ONE;
        bytes[offset++] = BYTE_TWO;
    } else {
        bytes[offset++] = BYTE_TWO;
        bytes[offset++] = BYTE_ONE;
    }
}

void ImageUtils::Uint32ToBytes(uint32_t data, vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian)
{
    uint8_t BYTE_ONE = (data >> MOVE_BITS_24) & 0xFF;
    uint8_t BYTE_TWO = (data >> MOVE_BITS_16) & 0xFF;
    uint8_t BYTE_THREE = (data >> MOVE_BITS_8) & 0xFF;
    uint8_t BYTE_FOUR = data & 0xFF;
    if (isBigEndian) {
        bytes[offset++] = BYTE_ONE;
        bytes[offset++] = BYTE_TWO;
        bytes[offset++] = BYTE_THREE;
        bytes[offset++] = BYTE_FOUR;
    } else {
        bytes[offset++] = BYTE_FOUR;
        bytes[offset++] = BYTE_THREE;
        bytes[offset++] = BYTE_TWO;
        bytes[offset++] = BYTE_ONE;
    }
}

void ImageUtils::FloatToBytes(float data, vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian)
{
    union {
        uint32_t i;
        float f;
    } u;
    u.f = data;
    Uint32ToBytes(u.i, bytes, offset, isBigEndian);
}

void ImageUtils::Int32ToBytes(int32_t data, vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian)
{
    union {
        uint32_t uit;
        int32_t it;
    } u;
    u.it = data;
    Uint32ToBytes(u.uit, bytes, offset, isBigEndian);
}

void ImageUtils::ArrayToBytes(const uint8_t* data, uint32_t length, vector<uint8_t>& bytes, uint32_t& offset)
{
    for (uint32_t i = 0; i < length; i++) {
        bytes[offset++] = data[i] & 0xFF;
    }
}

#if !defined(CROSS_PLATFORM)
void ImageUtils::FlushSurfaceBuffer(sptr<SurfaceBuffer>& surfaceBuffer)
{
    if (surfaceBuffer && (surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = surfaceBuffer->FlushCache();
        bool cond = err != GSERROR_OK;
        CHECK_ERROR_PRINT_LOG(cond, "ImageUtils FlushCache failed, GSError=%{public}d", err);
    }
}
#endif

void ImageUtils::FlushSurfaceBuffer(PixelMap* pixelMap)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (!pixelMap || pixelMap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return;
    }
    SurfaceBuffer* surfaceBuffer = static_cast<SurfaceBuffer*>(pixelMap->GetFd());
    if (surfaceBuffer && (surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = surfaceBuffer->Map();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("ImageUtils Map failed, GSError=%{public}d", err);
            return;
        }
        err = surfaceBuffer->FlushCache();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("ImageUtils FlushCache failed, GSError=%{public}d", err);
        }
    }
#else
    return;
#endif
}

void ImageUtils::FlushContextSurfaceBuffer(ImagePlugin::DecodeContext& context)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (context.pixelsBuffer.context == nullptr || context.allocatorType != AllocatorType::DMA_ALLOC) {
        return;
    }
    SurfaceBuffer* surfaceBuffer = static_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    if (surfaceBuffer && (surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = surfaceBuffer->Map();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("ImageUtils Map failed, GSError=%{public}d", err);
            return;
        }
        err = surfaceBuffer->FlushCache();
        if (err != GSERROR_OK) {
            IMAGE_LOGE("ImageUtils FlushCache failed, GSError=%{public}d", err);
        }
    }
#else
    return;
#endif
}

void ImageUtils::InvalidateContextSurfaceBuffer(ImagePlugin::DecodeContext& context)
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    bool cond = context.pixelsBuffer.context == nullptr || context.allocatorType != AllocatorType::DMA_ALLOC;
    CHECK_ERROR_RETURN(cond);
    SurfaceBuffer* surfaceBuffer = static_cast<SurfaceBuffer*>(context.pixelsBuffer.context);
    if (surfaceBuffer && (surfaceBuffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE)) {
        GSError err = surfaceBuffer->InvalidateCache();
        cond = err != GSERROR_OK;
        CHECK_ERROR_PRINT_LOG(cond, "ImageUtils FlushCache failed, GSError=%{public}d", err);
    }
#else
    return;
#endif
}

bool ImageUtils::IsAuxiliaryPictureTypeSupported(AuxiliaryPictureType type)
{
    auto auxTypes = GetAllAuxiliaryPictureType();
    return (auxTypes.find(type) != auxTypes.end());
}

bool ImageUtils::IsAuxiliaryPictureEncoded(AuxiliaryPictureType type)
{
    return AuxiliaryPictureType::GAINMAP == type || AuxiliaryPictureType::UNREFOCUS_MAP == type ||
        AuxiliaryPictureType::FRAGMENT_MAP == type;
}

bool ImageUtils::IsMetadataTypeSupported(MetadataType metadataType)
{
    if (metadataType == MetadataType::EXIF || metadataType == MetadataType::FRAGMENT ||
        metadataType == MetadataType::XTSTYLE || metadataType == MetadataType::RFDATAB) {
        return true;
    } else {
        return false;
    }
}

const std::set<AuxiliaryPictureType> &ImageUtils::GetAllAuxiliaryPictureType()
{
    static const std::set<AuxiliaryPictureType> auxTypes = {
        AuxiliaryPictureType::GAINMAP,
        AuxiliaryPictureType::DEPTH_MAP,
        AuxiliaryPictureType::UNREFOCUS_MAP,
        AuxiliaryPictureType::LINEAR_MAP,
        AuxiliaryPictureType::FRAGMENT_MAP,
        AuxiliaryPictureType::THUMBNAIL,
    };
    return auxTypes;
}

const std::set<MetadataType> &ImageUtils::GetAllMetadataType()
{
    static const std::set<MetadataType> metadataTypes = {
        MetadataType::EXIF,
        MetadataType::FRAGMENT,
        MetadataType::XTSTYLE,
        MetadataType::RFDATAB,
        MetadataType::STDATA,
        MetadataType::HEIFS,
    };
    return metadataTypes;
}

size_t ImageUtils::GetAstcBytesCount(const ImageInfo& imageInfo)
{
    size_t astcBytesCount = 0;
    uint32_t blockWidth = 0;
    uint32_t blockHeight = 0;

    switch (imageInfo.pixelFormat) {
        case PixelFormat::ASTC_4x4:
            blockWidth = ASTC_4X4_BLOCK;
            blockHeight = ASTC_4X4_BLOCK;
            break;
        case PixelFormat::ASTC_6x6:
            blockWidth = ASTC_6X6_BLOCK;
            blockHeight = ASTC_6X6_BLOCK;
            break;
        case PixelFormat::ASTC_8x8:
            blockWidth = ASTC_8X8_BLOCK;
            blockHeight = ASTC_8X8_BLOCK;
            break;
        default:
            IMAGE_LOGE("ImageUtils GetAstcBytesCount failed, format is not supported %{public}d",
                imageInfo.pixelFormat);
            return 0;
    }
    if ((blockWidth >= ASTC_4X4_BLOCK) && (blockHeight >= ASTC_4X4_BLOCK)) {
        astcBytesCount = ((imageInfo.size.width + blockWidth - 1) / blockWidth) *
            ((imageInfo.size.height + blockHeight - 1) / blockHeight) * ASTC_BLOCK_SIZE + ASTC_HEADER_SIZE;
    }
    return astcBytesCount;
}

bool ImageUtils::StrToUint32(const std::string& str, uint32_t& value)
{
    if (str.empty() || !isdigit(str.front())) {
        return false;
    }

    char* end = nullptr;
    errno = 0;
    auto addr = str.c_str();
    auto result = strtoul(addr, &end, 10); /* 10 means decimal */
    if ((end == addr) || (end[0] != '\0') || (errno == ERANGE) ||
        (result > UINT32_MAX)) {
        return false;
    }
    value = static_cast<uint32_t>(result);
    return true;
}

bool ImageUtils::IsInRange(uint32_t value, uint32_t minValue, uint32_t maxValue)
{
    return (value >= minValue) && (value <= maxValue);
}

bool ImageUtils::IsInRange(int32_t value, int32_t minValue, int32_t maxValue)
{
    return (value >= minValue) && (value <= maxValue);
}

bool ImageUtils::IsEven(int32_t value)
{
    return value % BASE_EVEN_DIVISOR == 0;
}

bool ImageUtils::HasOverflowed(uint32_t num1, uint32_t num2)
{
    return num1 > std::numeric_limits<uint32_t>::max() - num2;
}

std::string ImageUtils::GetEncodedHeifFormat()
{
    if (GetAPIVersion() > APIVERSION_13) {
        return "image/heic";
    } else {
        return "image/heif";
    }
}

std::string ImageUtils::GetEncodedHeifsFormat()
{
    return "image/heif-sequence";
}

int32_t ImageUtils::GetAPIVersion()
{
#if !defined(CROSS_PLATFORM)
    static std::atomic<int32_t> apiVersion = GetAPIVersionInner();
    if (apiVersion.load() <= 0) {
        apiVersion.store(GetAPIVersionInner());
    }
    return apiVersion.load();
#else
    return FAULT_API_VERSION;
#endif
}

int32_t ImageUtils::GetAPIVersionInner()
{
#if !defined(CROSS_PLATFORM)
    uint32_t targetVersion = 0;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        IMAGE_LOGE("Get ability manager failed");
        return FAULT_API_VERSION;
    }
    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        IMAGE_LOGE("Object is NULL");
        return FAULT_API_VERSION;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        IMAGE_LOGE("Bundle manager service is NULL.");
        return FAULT_API_VERSION;
    }
    AppExecFwk::BundleInfo bundleInfo;
    if (bms->GetBundleInfoForSelf(0, bundleInfo) != ERR_OK) {
        IMAGE_LOGE("Get bundle info for self failed");
        return FAULT_API_VERSION;
    }
    targetVersion = bundleInfo.targetVersion;
    int32_t apiVersionResult = static_cast<int32_t>(targetVersion % 100);
    return apiVersionResult;
#else
    return FAULT_API_VERSION;
#endif
}

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static void GetYUVStrideInfo(int32_t pixelFmt, OH_NativeBuffer_Planes *planes, YUVStrideInfo &dstStrides)
{
    if (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_420_SP) {
        auto yStride = planes->planes[PLANE_Y].columnStride;
        auto uvStride = planes->planes[PLANE_U].columnStride;
        auto yOffset = planes->planes[PLANE_Y].offset;
        auto uvOffset = planes->planes[PLANE_U].offset;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    } else if (pixelFmt == GRAPHIC_PIXEL_FMT_YCRCB_420_SP) {
        auto yStride = planes->planes[PLANE_Y].columnStride;
        auto uvStride = planes->planes[PLANE_V].columnStride;
        auto yOffset = planes->planes[PLANE_Y].offset;
        auto uvOffset = planes->planes[PLANE_V].offset;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    } else if (pixelFmt == GRAPHIC_PIXEL_FMT_YCBCR_P010) {
        auto yStride = planes->planes[PLANE_Y].columnStride / 2;
        auto uvStride = planes->planes[PLANE_U].columnStride / 2;
        auto yOffset = planes->planes[PLANE_Y].offset / 2;
        auto uvOffset = planes->planes[PLANE_U].offset / 2;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    } else if (pixelFmt == GRAPHIC_PIXEL_FMT_YCRCB_P010) {
        auto yStride = planes->planes[PLANE_Y].columnStride / 2;
        auto uvStride = planes->planes[PLANE_V].columnStride / 2;
        auto yOffset = planes->planes[PLANE_Y].offset / 2;
        auto uvOffset = planes->planes[PLANE_V].offset / 2;
        dstStrides = {yStride, uvStride, yOffset, uvOffset};
    }
}
#endif

void ImageUtils::UpdateSdrYuvStrides(const ImageInfo &imageInfo, YUVStrideInfo &dstStrides,
    void *context, AllocatorType dstType)
{
    int32_t dstWidth = imageInfo.size.width;
    int32_t dstHeight = imageInfo.size.height;
    int32_t dstYStride = dstWidth;
    int32_t dstUvStride = (dstWidth + 1) / NUM_2 * NUM_2;
    int32_t dstYOffset = 0;
    int32_t dstUvOffset = dstYStride * dstHeight;
    dstStrides = {dstYStride, dstUvStride, dstYOffset, dstUvOffset};

#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (context == nullptr) {
        return;
    }
    if (dstType == AllocatorType::DMA_ALLOC) {
        auto sb = static_cast<SurfaceBuffer*>(context);
        if (sb == nullptr) {
            IMAGE_LOGE("get SurfaceBuffer failed");
            return;
        }
        OH_NativeBuffer_Planes *planes = nullptr;
        GSError retVal = sb->GetPlanesInfo(reinterpret_cast<void**>(&planes));
        if (retVal != OHOS::GSERROR_OK || planes == nullptr) {
            IMAGE_LOGE("UpdateSdrYuvStrides Get planesInfo failed, retVal:%{public}d", retVal);
        } else if (planes->planeCount >= NUM_2) {
            int32_t pixelFmt = sb->GetFormat();
            GetYUVStrideInfo(pixelFmt, planes, dstStrides);
        }
    }
#endif
}

uint16_t ImageUtils::GetReusePixelRefCount(const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if !defined(CROSS_PLATFORM)
    if (reusePixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return 0;
    }
    void* sbBuffer = reusePixelmap->GetFd();
    if (sbBuffer != nullptr) {
        OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(sbBuffer);
        uint16_t reusePixelRefCount = static_cast<uint16_t>(ref->GetSptrRefCount());
        return reusePixelRefCount;
    }
    return 0;
#else
    return 0;
#endif
}

bool ImageUtils::CanReusePixelMap(ImagePlugin::DecodeContext& context, int width,
    int height, const std::shared_ptr<PixelMap> &reusePixelmap)
{
    if (reusePixelmap == nullptr) {
        IMAGE_LOGD("reusePixelmap is nullptr");
        return false;
    }
    bool cond = GetReusePixelRefCount(reusePixelmap) != 1;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "reusePixelmap reference count is not equal to 1");
    cond = ((width != reusePixelmap->GetWidth()) || (height != reusePixelmap->GetHeight()));
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "The height or width of image is not equal to reusePixelmap");
    cond = ((reusePixelmap->GetAllocatorType() != AllocatorType::DMA_ALLOC) ||
        (context.allocatorType != AllocatorType::DMA_ALLOC));
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Image allocatortype is not DMA");
    return true;
}

bool ImageUtils::CanReusePixelMapHdr(ImagePlugin::DecodeContext& context, int width,
    int height, const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if !defined(CROSS_PLATFORM)
    if (!CanReusePixelMap(context, width, height, reusePixelmap)) {
        return false;
    }
    auto hdrPixelFormat = GRAPHIC_PIXEL_FMT_RGBA_1010102;
    if (context.photoDesiredPixelFormat == PixelFormat::YCBCR_P010) {
        hdrPixelFormat = GRAPHIC_PIXEL_FMT_YCBCR_P010;
    }
    SetContextHdr(context, hdrPixelFormat);
    bool cond = (reusePixelmap->GetPixelFormat() != context.info.pixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "PixelFormat of Hdrimage is not equal to reusePixelmap");
    return true;
#else
    return false;
#endif
}

bool ImageUtils::CanReusePixelMapSdr(ImagePlugin::DecodeContext& context, int width,
    int height, const std::shared_ptr<PixelMap> &reusePixelmap)
{
    if (!CanReusePixelMap(context, width, height, reusePixelmap)) {
        return false;
    }
    bool cond = ((reusePixelmap->GetPixelFormat() == PixelFormat::RGBA_1010102) ||
        (context.info.pixelFormat == PixelFormat::RGBA_1010102));
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "Sdr image is not RGBA 10bit");
    cond = (reusePixelmap->GetPixelFormat() != context.info.pixelFormat);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "PixelFormat of Sdrimage is not equal to reusePixelmap");
    return true;
}

bool CanApplyMemForReusePixel(ImagePlugin::DecodeContext& context,
    const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if !defined(CROSS_PLATFORM)
    uint8_t *reusePixelBuffer = const_cast<uint8_t *>(reusePixelmap->GetPixels());
    int32_t err = ImageUtils::SurfaceBuffer_Reference(reusePixelmap->GetFd());
    bool cond = err != OHOS::GSERROR_OK;
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "reusePixelmapBuffer Reference failed");
    ImageUtils::SetReuseContextBuffer(context, AllocatorType::DMA_ALLOC, reusePixelBuffer,
        reusePixelmap->GetCapacity(), reusePixelmap->GetFd());
    return true;
#else
    return false;
#endif
}

bool ImageUtils::IsSdrPixelMapReuseSuccess(ImagePlugin::DecodeContext& context, int width,
    int height, const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if !defined(CROSS_PLATFORM)
    if (!CanReusePixelMapSdr(context, width, height, reusePixelmap)) {
        return false;
    }
    return CanApplyMemForReusePixel(context, reusePixelmap);
#else
    return false;
#endif
}

bool ImageUtils::IsHdrPixelMapReuseSuccess(ImagePlugin::DecodeContext& context, int width,
    int height, const std::shared_ptr<PixelMap> &reusePixelmap)
{
#if !defined(CROSS_PLATFORM)
    if (!CanReusePixelMapHdr(context, width, height, reusePixelmap)) {
        return false;
    }
    return CanApplyMemForReusePixel(context, reusePixelmap);
#else
    return false;
#endif
}

void ImageUtils::SetContextHdr(ImagePlugin::DecodeContext& context, uint32_t format)
{
#if !defined(CROSS_PLATFORM)
    context.info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    if (format == GRAPHIC_PIXEL_FMT_RGBA_1010102) {
        context.pixelFormat = PixelFormat::RGBA_1010102;
        context.info.pixelFormat = PixelFormat::RGBA_1010102;
        context.grColorSpaceName = ColorManager::BT2020_HLG;
    } else if (format == GRAPHIC_PIXEL_FMT_YCBCR_P010) {
        context.pixelFormat = PixelFormat::YCBCR_P010;
        context.info.pixelFormat = PixelFormat::YCBCR_P010;
        context.grColorSpaceName = ColorManager::BT2020_HLG;
    }
#endif
}

void ImageUtils::SetReuseContextBuffer(ImagePlugin::DecodeContext& context,
    AllocatorType type, uint8_t* ptr, uint64_t count, void* fd)
{
    context.allocatorType = type;
    context.freeFunc = nullptr;
    context.pixelsBuffer.buffer = ptr;
    context.pixelsBuffer.bufferSize = count;
    context.pixelsBuffer.context = fd;
}

bool ImageUtils::CheckRowDataSizeIsVaild(int32_t &rowDataSize, ImageInfo &imgInfo)
{
    int32_t bytesPerPixel = ImageUtils::GetPixelBytes(imgInfo.pixelFormat);
    if (bytesPerPixel == 0 || rowDataSize <=0 ||
        rowDataSize != ImageUtils::GetRowDataSizeByPixelFormat(imgInfo.size.width, imgInfo.pixelFormat)) {
        IMAGE_LOGE("[ImageUtils] RowDataSizeIsVaild: bytesPerPixel or rowDataSize:%{public}d", rowDataSize);
        return false;
    }
    return true;
}

bool ImageUtils::CheckBufferSizeIsVaild(int32_t &bufferSize, uint64_t &expectedBufferSize, AllocatorType &allocatorType)
{
    if (bufferSize <= 0 ||
        expectedBufferSize > (allocatorType == AllocatorType::HEAP_ALLOC ? PIXEL_MAP_MAX_RAM_SIZE : INT_MAX) ||
        expectedBufferSize != static_cast<uint64_t>(bufferSize)) {
        IMAGE_LOGE("[ImageUtils] BufferSizeIsVaild: bufferSize invalid, expect:%{public}llu, actual:%{public}d",
            static_cast<unsigned long long>(expectedBufferSize), bufferSize);
        return false;
    }
    return true;
}

bool ImageUtils::CheckYuvDataInfoValid(const YUVDataInfo& yDataInfo)
{
    //size
    if (yDataInfo.yWidth == 0 || yDataInfo.yHeight == 0) {
        IMAGE_LOGE("Invalid Y plane size: yWidth or yHeight is 0");
        return false;
    }
    const uint32_t uvExpectedWidth = (yDataInfo.yWidth + NUM_1) / NUM_2;
    const uint32_t uvExpectedHeight = (yDataInfo.yHeight + NUM_1) / NUM_2;
    if (yDataInfo.uvWidth == 0 || yDataInfo.uvHeight == 0) {
        IMAGE_LOGE("Invalid UV plane size: uvWidth or uvHeight is 0");
        return false;
    }
    if (yDataInfo.uvWidth != uvExpectedWidth || yDataInfo.uvHeight != uvExpectedHeight) {
        IMAGE_LOGE("Invalid UV plane size: UV(%{public}u, %{public}u) mismatch expected(%{public}u, %{public}u)",
            yDataInfo.uvWidth, yDataInfo.uvHeight, uvExpectedWidth, uvExpectedHeight);
        return false;
    }

    //stride
    if (yDataInfo.yStride < yDataInfo.yWidth) {
        IMAGE_LOGE("Invalid Y stride: %{public}u < width=%{public}u", yDataInfo.yStride, yDataInfo.yWidth);
        return false;
    }
    if (yDataInfo.uvStride < yDataInfo.uvWidth) {
        IMAGE_LOGE("Invalid UV stride: %{public}u < width=%{public}u", yDataInfo.uvStride, yDataInfo.uvWidth);
        return false;
    }
    if (yDataInfo.yStride >= yDataInfo.yWidth * NUM_2 || yDataInfo.uvStride >= yDataInfo.yWidth * NUM_2) {
        IMAGE_LOGW("Possible invalid stride as byte value: Stride=(%{public}u, %{public}u), Width=%{public}u",
            yDataInfo.yStride, yDataInfo.uvStride, yDataInfo.yWidth);
    }
    if (yDataInfo.uStride != 0 && yDataInfo.uStride < yDataInfo.uvWidth) {
        IMAGE_LOGW("Invalid U stride: %{public}u < uvWidth=%{public}u", yDataInfo.uStride, yDataInfo.uvWidth);
    }
    if (yDataInfo.vStride != 0 && yDataInfo.vStride < yDataInfo.uvWidth) {
        IMAGE_LOGW("Invalid V stride: %{public}u < uvWidth=%{public}u", yDataInfo.vStride, yDataInfo.uvWidth);
    }

    //offset
    if (yDataInfo.yOffset != 0) {
        IMAGE_LOGW("Invalid Y offset: %{public}u (expected 0)", yDataInfo.yOffset);
    }

    uint64_t yPlaneSize = static_cast<uint64_t>(yDataInfo.yStride) * yDataInfo.yHeight;
    if (yDataInfo.uvOffset < yPlaneSize) {
        IMAGE_LOGE("Invalid UV offset: %{public}u less than Y plane size", yDataInfo.uvOffset);
        return false;
    }
    uint64_t bufferSize = yPlaneSize + static_cast<uint64_t>(yDataInfo.uvStride) * yDataInfo.uvHeight;
    if (bufferSize > UINT32_MAX) {
        IMAGE_LOGE("Invalid YUV buffer size: overflow (exceeds UINT32_MAX)");
        return false;
    }

    return true;
}

bool ImageUtils::GetAlignedNumber(int32_t& number, int32_t align)
{
    if (number < 0 || align <= 0) {
        return false;
    }
    int64_t res = number;
    res = (res + align - 1) / align * align;
    if (res > INT32_MAX) {
        return false;
    }
    number = static_cast<int32_t>(res);
    return true;
}

uint16_t ImageUtils::GetRGBA1010102ColorR(uint32_t color)
{
    return (color >> RGBA1010102_R_SHIFT) & RGBA1010102_RGB_MASK;
}

uint16_t ImageUtils::GetRGBA1010102ColorG(uint32_t color)
{
    return (color >> RGBA1010102_G_SHIFT) & RGBA1010102_RGB_MASK;
}

uint16_t ImageUtils::GetRGBA1010102ColorB(uint32_t color)
{
    return (color >> RGBA1010102_B_SHIFT) & RGBA1010102_RGB_MASK;
}

uint16_t ImageUtils::GetRGBA1010102ColorA(uint32_t color)
{
    return (color >> RGBA1010102_A_SHIFT) & RGBA1010102_ALPHA_MASK;
}

bool ImageUtils::CheckPixelsInput(PixelMap* pixelMap, const RWPixelsOptions &opts)
{
    const Rect& rect = opts.region;
    if (opts.bufferSize == 0 || opts.pixels == nullptr) {
        IMAGE_LOGE("checkPixelsInput bufferSize or dst address invalid, bufferSize: %{public}" PRIu64, opts.bufferSize);
        return false;
    }
    if (rect.left < 0 || rect.top < 0 || opts.stride > numeric_limits<int32_t>::max() ||
        static_cast<uint64_t>(opts.offset) > opts.bufferSize) {
        IMAGE_LOGE(
            "checkPixelsInput left(%{public}d) or top(%{public}d) or stride(%{public}u) or offset(%{public}u) < 0.",
            rect.left, rect.top, opts.stride, opts.offset);
        return false;
    }
    if (rect.width <= 0 || rect.height <= 0 || rect.width > MAX_DIMENSION || rect.height > MAX_DIMENSION) {
        IMAGE_LOGE("checkPixelsInput width(%{public}d) or height(%{public}d) is < 0.", rect.width, rect.height);
        return false;
    }
    if (rect.left > pixelMap->GetWidth() - rect.width) {
        IMAGE_LOGE("checkPixelsInput left(%{public}d) + width(%{public}d) is > pixelmap width(%{public}d).",
            rect.left, rect.width, pixelMap->GetWidth());
        return false;
    }
    if (rect.top > pixelMap->GetHeight() - rect.height) {
        IMAGE_LOGE("checkPixelsInput top(%{public}d) + height(%{public}d) is > pixelmap height(%{public}d).",
            rect.top, rect.height, pixelMap->GetHeight());
        return false;
    }
    uint32_t regionStride = static_cast<uint32_t>(rect.width) * NUM_4;  // bytes count, need multiply by 4
    if (opts.pixelFormat == PixelFormat::RGB_888) {
        regionStride = static_cast<uint32_t>(rect.width) * NUM_3;  // bytes count, need multiply by 3
    }
    if (opts.stride < regionStride) {
        IMAGE_LOGE("checkPixelsInput stride(%{public}d) < width*4 (%{public}d).", opts.stride, regionStride);
        return false;
    }
    if (opts.bufferSize < regionStride) {
        IMAGE_LOGE("checkPixelsInput input buffer size is < width * 4.");
        return false;
    }
    // "1" is except the last line.
    uint64_t lastLinePos = opts.offset + static_cast<uint64_t>(rect.height - NUM_1) * opts.stride;
    if (static_cast<uint64_t>(opts.offset) > (opts.bufferSize - regionStride) ||
        lastLinePos > (opts.bufferSize - regionStride)) {
            IMAGE_LOGE(
                "checkPixelsInput fail, height(%{public}d), width(%{public}d), lastLine(%{public}" PRIu64 "), "
                "offset(%{public}u), bufferSize:%{public}" PRIu64 ".", rect.height, rect.width,
                static_cast<uint64_t>(lastLinePos), opts.offset, static_cast<uint64_t>(opts.bufferSize));
            return false;
    }
    return true;
}

bool ImageUtils::FloatEqual(float a, float b)
{
    return std::fabs(a - b) < EPSILON;
}

void ImageUtils::WriteUint8(std::vector<uint8_t> &buff, uint8_t value)
{
    buff.push_back(value);
}

void ImageUtils::WriteVarint(std::vector<uint8_t> &buff, int32_t value)
{
    uint32_t uValue = uint32_t(value);
    while (uValue > TLV_VARINT_MASK) {
        buff.push_back(TLV_VARINT_MORE | uint8_t(uValue & TLV_VARINT_MASK));
        uValue >>= TLV_VARINT_BITS;
    }
    buff.push_back(uint8_t(uValue));
}

uint8_t ImageUtils::GetVarintLen(int32_t value)
{
    uint32_t uValue = static_cast<uint32_t>(value);
    uint8_t len = 1;
    while (uValue > TLV_VARINT_MASK) {
        len++;
        uValue >>= TLV_VARINT_BITS;
    }
    return len;
}

void ImageUtils::TlvWriteSurfaceInfo(const PixelMap* pixelMap, vector<uint8_t>& buff)
{
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    sptr<SurfaceBuffer> surfaceBuffer(reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd()));
    CM_ColorSpaceType colorSpaceType;
    if (VpeUtils::GetSbColorSpaceType(surfaceBuffer, colorSpaceType)) {
        WriteUint8(buff, TLV_IMAGE_COLORTYPE);
        WriteVarint(buff, GetVarintLen(static_cast<int32_t>(colorSpaceType)));
        WriteVarint(buff, static_cast<int32_t>(colorSpaceType));
    }
    CM_HDR_Metadata_Type metadataType;
    if (VpeUtils::GetSbMetadataType(surfaceBuffer, metadataType)) {
        WriteUint8(buff, TLV_IMAGE_METADATATYPE);
        WriteVarint(buff, GetVarintLen(static_cast<int32_t>(metadataType)));
        WriteVarint(buff, static_cast<int32_t>(metadataType));
    }
    vector<uint8_t> staticMetadata;
    if (VpeUtils::GetSbStaticMetadata(surfaceBuffer, staticMetadata)) {
        WriteUint8(buff, TLV_IMAGE_STATICMETADATA);
        WriteVarint(buff, static_cast<int32_t>(staticMetadata.size()));
        buff.insert(buff.end(), staticMetadata.begin(), staticMetadata.end());
    }
    vector<uint8_t> dynamicMetadata;
    if (VpeUtils::GetSbDynamicMetadata(surfaceBuffer, dynamicMetadata)) {
        WriteUint8(buff, TLV_IMAGE_DYNAMICMETADATA);
        WriteVarint(buff, static_cast<int32_t>(dynamicMetadata.size()));
        buff.insert(buff.end(), dynamicMetadata.begin(), dynamicMetadata.end());
    }
#endif
    return;
}

int32_t ImageUtils::ReadVarint(std::vector<uint8_t> &buff, int32_t &cursor)
{
    uint32_t value = 0;
    uint8_t shift = 0;
    uint32_t item = 0;
    do {
        if (static_cast<size_t>(cursor + 1) > buff.size()) {
            IMAGE_LOGE("ReadVarint out of range");
            return static_cast<int32_t>(TLV_END);
        }
        item = uint32_t(buff[cursor++]);
        value |= (item & TLV_VARINT_MASK) << shift;
        shift += TLV_VARINT_BITS;
    } while ((item & TLV_VARINT_MORE) != 0);
    return int32_t(value);
}

int32_t ImageUtils::AllocPixelMapMemory(std::unique_ptr<AbsMemory> &dstMemory, int32_t &dstRowStride,
    const ImageInfo &dstImageInfo, const InitializationOptions &opts)
{
    int64_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(dstImageInfo.size.width, dstImageInfo.pixelFormat);
    if (rowDataSize <= 0) {
        IMAGE_LOGE("[PixelMap] AllocPixelMapMemory: Get row data size failed");
        return -1;
    }
    int64_t bufferSize = rowDataSize * dstImageInfo.size.height;
    if (bufferSize > UINT32_MAX) {
        IMAGE_LOGE("[PixelMap]Create: pixelmap size too large: width = %{public}d, height = %{public}d",
            dstImageInfo.size.width, dstImageInfo.size.height);
        return -1;
    }
    if (IsYuvFormat(dstImageInfo.pixelFormat)) {
        bufferSize = GetYUVByteCount(dstImageInfo);
    }
    MemoryData memoryData = {nullptr, static_cast<size_t>(bufferSize), "Create PixelMap", dstImageInfo.size,
        dstImageInfo.pixelFormat};
    AllocatorType allocType = opts.allocatorType == AllocatorType::DEFAULT ?
        ImageUtils::GetPixelMapAllocatorType(dstImageInfo.size, dstImageInfo.pixelFormat, opts.useDMA) :
        opts.allocatorType;
    dstMemory = MemoryManager::CreateMemory(allocType, memoryData);
    if (dstMemory == nullptr) {
        IMAGE_LOGE("[PixelMap]Create: allocate memory failed");
        return -1;
    }

    dstRowStride = dstImageInfo.size.width * ImageUtils::GetPixelBytes(dstImageInfo.pixelFormat);
#if !defined(_WIN32) && !defined(_APPLE) && !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    if (dstMemory->GetType() == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = static_cast<SurfaceBuffer*>(dstMemory->extend.data);
        if (sbBuffer == nullptr) {
            IMAGE_LOGE("get SurfaceBuffer failed");
            return -1;
        }
        dstRowStride = sbBuffer->GetStride();
    }
#endif
    return SUCCESS;
}

std::unique_ptr<AbsMemory> ImageUtils::ReadData(std::vector<uint8_t> &buff, int32_t size, int32_t &cursor,
    AllocatorType allocType, ImageInfo imageInfo)
{
    if (size <= 0 || static_cast<size_t>(size) > MAX_TLV_HEAP_SIZE) {
        IMAGE_LOGE("[PixelMap] tlv read data fail: invalid size[%{public}d]", size);
        return nullptr;
    }
    if (static_cast<size_t>(cursor + size) > buff.size()) {
        IMAGE_LOGE("[PixelMap] ReadData out of range");
        return nullptr;
    }
    std::unique_ptr<AbsMemory> dstMemory = nullptr;
    int32_t dstRowStride = 0;
    InitializationOptions opts;
    opts.allocatorType = allocType;
    int32_t errorCode = AllocPixelMapMemory(dstMemory, dstRowStride, imageInfo, opts);
    if (dstMemory == nullptr || dstMemory->data.data == nullptr || errorCode != SUCCESS) {
        IMAGE_LOGE("[PixelMap] tlv read data fail: alloc memory failed");
        return nullptr;
    }
    uint8_t* addr = static_cast<uint8_t*>(dstMemory->data.data);
    int32_t rowDataSize = ImageUtils::GetRowDataSizeByPixelFormat(imageInfo.size.width, imageInfo.pixelFormat);
    uint8_t* srcAddr = buff.data() + cursor;

    if (size != rowDataSize * imageInfo.size.height) {
        IMAGE_LOGE("[PixelMap] tlv read data fail: alloc memory failed");
        return nullptr;
    }
#if !defined(CROSS_PLATFORM)
    if (allocType == AllocatorType::DMA_ALLOC) {
        if (dstRowStride == 0 || dstRowStride < rowDataSize ||
            static_cast<uint32_t>(size) > static_cast<SurfaceBuffer*>(dstMemory->extend.data)->GetSize()) {
                IMAGE_LOGE("[PixelMap] tlv check dma size failed");
                return nullptr;
        }
        for (int i = 0; i < imageInfo.size.height; i++) {
            if (memcpy_s(addr + i * dstRowStride, rowDataSize, srcAddr + i * rowDataSize, rowDataSize) != 0) {
                IMAGE_LOGE("[PixelMap] tlv copy dma data failed");
                return nullptr;
            }
        }
    } else {
#endif
        if (rowDataSize != dstRowStride) {
            IMAGE_LOGE("[PixelMap] tlv check heap size failed");
            return nullptr;
        }
        if (memcpy_s(addr, size, srcAddr, size) != 0) {
            IMAGE_LOGE("[PixelMap] tlv copy heap data failed");
            return nullptr;
        }
#if !defined(CROSS_PLATFORM)
    }
#endif
    return dstMemory;
}

PixelFormat ImageUtils::ConvertTo10BitPixelFormat(PixelFormat pixelFormat)
{
    PixelFormat hdrAllocFormat = PixelFormat::UNKNOWN;
    switch (pixelFormat) {
        case PixelFormat::RGBA_8888:
            hdrAllocFormat = PixelFormat::RGBA_1010102;
            break;
        case PixelFormat::NV21:
            hdrAllocFormat = PixelFormat::YCRCB_P010;
            break;
        case PixelFormat::NV12:
            hdrAllocFormat = PixelFormat::YCBCR_P010;
            break;
        case PixelFormat::RGBA_1010102:
            hdrAllocFormat = PixelFormat::RGBA_1010102;
            break;
        case PixelFormat::YCRCB_P010:
            hdrAllocFormat = PixelFormat::YCRCB_P010;
            break;
        case PixelFormat::YCBCR_P010:
            hdrAllocFormat = PixelFormat::YCBCR_P010;
            break;
        default:
            IMAGE_LOGE("ConvertTo10BitPixleFormat failed, format: %{public}d", pixelFormat);
            break;
    }
    return hdrAllocFormat;
}
} // namespace Media
} // namespace OHOS
