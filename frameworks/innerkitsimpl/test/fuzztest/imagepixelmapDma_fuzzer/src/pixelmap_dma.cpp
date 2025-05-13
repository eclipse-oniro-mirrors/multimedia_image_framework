/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <thread>
#include <chrono>
#include "pixel_map.h"
#include "image_utils.h"
#include "image_log.h"

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t PIXELFORMAT_COUNT = 110;
constexpr uint32_t NUM_1 = 1;
constexpr uint32_t NUM_2 = 2;
constexpr uint32_t NUM_3 = 3;
constexpr uint32_t NUM_4 = 4;
constexpr uint32_t NUM_6 = 6;

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

bool CreateFromOption(int32_t width, int32_t height, AllocatorType allocatorType,
    Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.srcPixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.pixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>() % SCALEMODE_MODULO);
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    opts.useDMA = GetData<bool>();
    opts.allocatorType = allocatorType;
    auto pixelmap = Media::PixelMap::Create(opts);
    if (pixelmap == nullptr) {
        return false;
    }
    return true;
}

std::unique_ptr<Media::PixelMap> CreateFromColor(int32_t width, int32_t height, AllocatorType allocatorType,
    Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.srcPixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.pixelFormat = pixelFormat == PixelFormat::UNKNOWN ?
        static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO) : pixelFormat;
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>() % SCALEMODE_MODULO);
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    opts.useDMA = GetData<bool>();
    opts.allocatorType = allocatorType;
    size_t datalength = width * height * ImageUtils::GetPixelBytes(opts.pixelFormat);
    uint32_t* colorData = new uint32_t[datalength];
    for (size_t i = 0; i < width * height; i++) {
        colorData[i] = GetData<uint32_t>();
    }
    auto pixelmap = Media::PixelMap::Create(colorData, datalength, opts);
    if (colorData != nullptr) {
        delete[] colorData;
        colorData = nullptr;
    }
    return pixelmap;
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

    CreateFromOption(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(0));
    CreateFromOption(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(NUM_1));
    CreateFromOption(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(NUM_2));
    CreateFromOption(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(NUM_4));
    for (uint32_t i = 0; i < PIXELFORMAT_COUNT; i++) {
        CreateFromOption(NUM_4, NUM_6, AllocatorType(i % NUM_3), PixelFormat(i));
    }

    CreateFromColor(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(0));
    CreateFromColor(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(NUM_1));
    CreateFromColor(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(NUM_2));
    CreateFromColor(GetData<int32_t>() % MAX_LENGTH_MODULO,
        GetData<int32_t>() % MAX_LENGTH_MODULO, AllocatorType(NUM_4));
    for (uint32_t i = 0; i < PIXELFORMAT_COUNT; i++) {
        CreateFromColor(NUM_4, NUM_6, AllocatorType(i % NUM_3), PixelFormat(i));
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