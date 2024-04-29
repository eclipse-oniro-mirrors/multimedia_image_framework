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

#include "__config"
#include "image_log.h"
#include "ios"
#include "istream"
#include "media_errors.h"
#include "new"
#include "plugin_server.h"
#include "singleton.h"
#include "string"
#include "type_traits"
#include "vector"
#include "image_trace.h"
#include "hitrace_meter.h"
#include "image_system_properties.h"
#include "pixel_map.h"
#ifdef IOS_PLATFORM
#include <sys/syscall.h>
#endif
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "surface_buffer.h"
#else
#include "refbase.h"
#endif

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "imageUtils"

namespace OHOS {
namespace Media {
using namespace std;
using namespace MultimediaPlugin;

constexpr int32_t ALPHA8_BYTES = 1;
constexpr int32_t RGB565_BYTES = 2;
constexpr int32_t RGB888_BYTES = 3;
constexpr int32_t ARGB8888_BYTES = 4;
constexpr int32_t RGBA_F16_BYTES = 8;
constexpr int32_t NV21_BYTES = 2;  // Each pixel is sorted on 3/2 bytes.
constexpr uint8_t MOVE_BITS_8 = 8;
constexpr uint8_t MOVE_BITS_16 = 16;
constexpr uint8_t MOVE_BITS_24 = 24;
constexpr int32_t ASTC_4X4_BYTES = 1;
constexpr float EPSILON = 1e-6;
constexpr int MAX_DIMENSION = INT32_MAX >> 2;
static bool g_pluginRegistered = false;
static const uint8_t NUM_0 = 0;
static const uint8_t NUM_1 = 1;
static const uint8_t NUM_2 = 2;
static const uint8_t NUM_3 = 3;
static const uint8_t NUM_4 = 4;
static const string FILE_DIR_IN_THE_SANDBOX = "/data/storage/el2/base/files/";

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
        default:
            IMAGE_LOGE("[ImageUtil]get pixel bytes failed, pixelFormat:%{public}d.",
                static_cast<int32_t>(pixelFormat));
            break;
    }
    return pixelBytes;
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
    if (_fullpath(tmpPath, path.c_str(), path.length()) == nullptr) {
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
        case PixelFormat::CMYK:
        default: {
            IMAGE_LOGE("GetValidAlphaTypeByFormat unsupport the format(%{public}d).", format);
            return AlphaType::IMAGE_ALPHA_TYPE_UNKNOWN;
        }
    }
    return dstType;
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

bool ImageUtils::CheckMulOverflow(int32_t width, int32_t bytesPerPixel)
{
    if (width == 0 || bytesPerPixel == 0) {
        IMAGE_LOGE("param is 0");
        return true;
    }
    int64_t rowSize = static_cast<int64_t>(width) * bytesPerPixel;
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
    int64_t rectSize = static_cast<int64_t>(width) * height;
    if ((rectSize / width) != height) {
        IMAGE_LOGE("width * height overflow!");
        return true;
    }
    int64_t bufferSize = rectSize * bytesPerPixel;
    if ((bufferSize / bytesPerPixel) != rectSize) {
        IMAGE_LOGE("bytesPerPixel overflow!");
        return true;
    }
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
        IMAGE_LOGE("parameter error, please check input parameter");
        return ERR_SURFACEBUFFER_REFERENCE_FAILED;
    }
    OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(buffer);
    ref->IncStrongRef(ref);
    return SUCCESS;
}

int32_t ImageUtils::SurfaceBuffer_Unreference(void* buffer)
{
    if (buffer == nullptr) {
        IMAGE_LOGE("parameter error, please check input parameter");
        return ERR_SURFACEBUFFER_UNREFERENCE_FAILED;
    }
    OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(buffer);
    ref->DecStrongRef(ref);
    return SUCCESS;
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

    IMAGE_LOGI("ImageUtils::DumpPixelMapIfDumpEnabled start");
    std::string fileName = FILE_DIR_IN_THE_SANDBOX + GetLocalTime() + "_imageId" + std::to_string(imageId) +
        GetPixelMapName(pixelMap.get()) + ".dat";
    int32_t totalSize = pixelMap->GetRowStride() * pixelMap->GetHeight();
    if (pixelMap->GetPixelFormat() == PixelFormat::NV12 || pixelMap->GetPixelFormat() == PixelFormat::NV21) {
        if (pixelMap->GetAllocatorType() == AllocatorType::DMA_ALLOC) {
            auto sbBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap->GetFd());
            totalSize = static_cast<int32_t>(sbBuffer->GetSize());
        } else {
            totalSize = static_cast<int32_t>(pixelMap->GetCapacity());
        }
        IMAGE_LOGI("ImageUtils::DumpPixelMapIfDumpEnabled YUV420 totalSize is %{public}d", totalSize);
    }
    if (SUCCESS != SaveDataToFile(fileName, reinterpret_cast<const char*>(pixelMap->GetPixels()), totalSize)) {
        IMAGE_LOGI("ImageUtils::DumpPixelMapIfDumpEnabled failed");
        return;
    }
    IMAGE_LOGI("ImageUtils::DumpPixelMapIfDumpEnabled success, path = %{public}s", fileName.c_str());
}

void ImageUtils::DumpPixelMapBeforeEncode(PixelMap& pixelMap)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }
    IMAGE_LOGI("ImageUtils::DumpPixelMapBeforeEncode start");
    std::string fileName = FILE_DIR_IN_THE_SANDBOX + GetLocalTime() + "_beforeEncode" + GetPixelMapName(&pixelMap) +
        ".dat";
    int32_t totalSize = pixelMap.GetRowStride() * pixelMap.GetHeight();
    if (SUCCESS != SaveDataToFile(fileName, reinterpret_cast<const char*>(pixelMap.GetPixels()), totalSize)) {
        IMAGE_LOGI("ImageUtils::DumpPixelMapBeforeEncode failed");
        return;
    }
    IMAGE_LOGI("ImageUtils::DumpPixelMapBeforeEncode success, path = %{public}s", fileName.c_str());
}

void ImageUtils::DumpDataIfDumpEnabled(const char* data, const size_t& totalSize,
    const std::string& fileSuffix, uint64_t imageId)
{
    if (!ImageSystemProperties::GetDumpImageEnabled()) {
        return;
    }
    std::string fileName = FILE_DIR_IN_THE_SANDBOX + GetLocalTime() + "_imageId" + std::to_string(imageId) +
        "_data_total" + std::to_string(totalSize) + "." + fileSuffix;
    if (SUCCESS != SaveDataToFile(fileName, data, totalSize)) {
        IMAGE_LOGI("ImageUtils::DumpDataIfDumpEnabled failed");
        return;
    }
    IMAGE_LOGI("ImageUtils::DumpDataIfDumpEnabled success, path = %{public}s", fileName.c_str());
}

uint64_t ImageUtils::GetNowTimeMilliSeconds()
{
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
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

uint32_t ImageUtils::SaveDataToFile(const std::string& fileName, const char* data, const size_t& totalSize)
{
    std::ofstream outFile(fileName, std::ofstream::out);
    if (!outFile.is_open()) {
        IMAGE_LOGI("ImageUtils::SaveDataToFile write error, path=%{public}s", fileName.c_str());
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
    std::tm tm = *std::localtime(&t);

    std::stringstream ss;
    int millSecondWidth = 3;
    ss << std::put_time(&tm, "%Y-%m-%d %H_%M_%S.") << std::setfill('0') << std::setw(millSecondWidth) << ms.count();
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
uint16_t ImageUtils::BytesToUint16(uint8_t* bytes, uint32_t& offset, bool isBigEndian)
{
    uint16_t data = 0;
    if (bytes == nullptr) {
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
uint32_t ImageUtils::BytesToUint32(uint8_t* bytes, uint32_t& offset, bool isBigEndian)
{
    uint32_t data = 0;
    if (bytes == nullptr) {
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
int32_t ImageUtils::BytesToInt32(uint8_t* bytes, uint32_t& offset, bool isBigEndian)
{
    int32_t data = 0;
    if (bytes == nullptr) {
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
float ImageUtils::BytesToFloat(uint8_t* bytes, uint32_t& offset, bool isBigEndian)
{
    uint32_t data = BytesToUint32(bytes, offset, isBigEndian);
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
} // namespace Media
} // namespace OHOS
