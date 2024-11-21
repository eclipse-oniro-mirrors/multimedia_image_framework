/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_pixelmap_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>
#include "image_log.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "securec.h"


constexpr uint32_t STRING_LENGTH = 10;
constexpr uint32_t MIN_LENGTH_MODULO = 100;
constexpr uint32_t PIXELFORMAT_MODULO = 10;
constexpr uint32_t COLOR_FORMAT_COUNT = 10;

namespace OHOS {
namespace Media {
namespace {
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace

/*
 * describe: get data from outside untrusted data(g_data) which size is according to sizeof(T)
 * tips: only support basic type
 */
template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || objectSize > g_size - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

/*
 * get string from g_data
 */
std::string GetStringFromData()
{
    std::unique_ptr<char[]> strings = std::make_unique<char[]>(STRING_LENGTH);
    if (strings == nullptr) {
        return "";
    }
    for (size_t i = 0; i < STRING_LENGTH; i++) {
        strings[i] = GetData<char>();
    }
    std::string str(strings.get(), STRING_LENGTH);
    return str;
}

/*
 * get a pixelmap from opts
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromOptsSmall(Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    int32_t width = GetData<int32_t>() % MIN_LENGTH_MODULO;
    int32_t height = GetData<int32_t>() % MIN_LENGTH_MODULO;
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.srcPixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.pixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    auto pixelmap = Media::PixelMap::Create(opts);
    return pixelmap;
}

/*
 * Test PixelMap GetColorARGB
 */
bool PixelMapGetColorARGBTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    if (pixelMap == nullptr) {
        return false;
    }
    int32_t positionX = GetData<int32_t>() % MIN_LENGTH_MODULO;
    int32_t positionY = GetData<int32_t>() % MIN_LENGTH_MODULO;
    uint32_t color;
    if (!(pixelMap->GetARGB32Color(positionX, positionY, color))) {
        return false;
    }
    uint8_t colorA = pixelMap->GetARGB32ColorA(color);
    uint8_t colorR = pixelMap->GetARGB32ColorR(color);
    uint8_t colorG = pixelMap->GetARGB32ColorG(color);
    uint8_t colorB = pixelMap->GetARGB32ColorB(color);
    uint32_t combinedColor = (static_cast<uint32_t>(colorA) << 24) |
                            (static_cast<uint32_t>(colorR) << 16) |
                            (static_cast<uint32_t>(colorG) << 8) |
                            static_cast<uint32_t>(colorB);
    if (combinedColor != color) {
        return false;
    }
    return true;
}

/*
 * test pixelmap get functions
 */
bool PixelMapGetFunctionsTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    if (pixelMap == nullptr) {
        return false;
    }
    pixelMap->GetPixelBytes();
    pixelMap->GetRowBytes();
    pixelMap->GetWidth();
    pixelMap->GetHeight();
    pixelMap->GetBaseDensity();
    Media::ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    pixelMap->GetPixelFormat();
    pixelMap->GetColorSpace();
    pixelMap->GetAlphaType();
    pixelMap->GetAllocatorType();
    pixelMap->GetToSdrColorSpaceIsSRGB();
    return true;
}

bool PixelMapMainFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    for (uint32_t i = 0; i < COLOR_FORMAT_COUNT; i++) {
        std::unique_ptr<Media::PixelMap> pixelMap = GetPixelMapFromOptsSmall(PixelFormat(i));
        PixelMapGetColorARGBTest(pixelMap);
        PixelMapGetFunctionsTest(pixelMap);
    }
    return true;
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::PixelMapMainFuzzTest(data, size);
    return 0;
}