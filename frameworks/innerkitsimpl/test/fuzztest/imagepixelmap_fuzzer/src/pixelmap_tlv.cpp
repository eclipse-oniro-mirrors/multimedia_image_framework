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

#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "pixel_map.h"

#include <chrono>
#include <thread>
#include "image_log.h"

constexpr uint32_t STRING_LENGTH = 10;
constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t PIXELFORMAT_COUNT = 110;
constexpr uint32_t NUM_4 = 4;
constexpr uint32_t NUM_6 = 6;
constexpr uint32_t NUM_8 = 8;
constexpr uint32_t NUM_9 = 9;

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

void VariationBuff()
{
    size_t size = GetData<int32_t>() % MAX_LENGTH_MODULO;
    if (size > g_size) {
        size = g_size;
    }
    std::vector<uint8_t> buff(size);
    for (size_t i = 0; i < size; i++) {
        buff.push_back(*(g_data + i));
    }
    PixelMap *pixelmapTlv = PixelMap::DecodeTlv(buff);
    if (pixelmapTlv != nullptr) {
        delete pixelmapTlv;
        pixelmapTlv = nullptr;
    }
    buff.clear();

    const uint32_t dataLength = NUM_4 * NUM_6;
    uint32_t *data = new uint32_t[dataLength];
    for (uint32_t i = 0; i < dataLength; i++) {
        data[i] = i;
    }
    InitializationOptions opts;
    opts.pixelFormat = OHOS::Media::PixelFormat::ARGB_8888;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts.size.width = NUM_4;
    opts.size.height = NUM_6;
    std::unique_ptr<PixelMap> pixelmap = PixelMap::Create(data, dataLength, opts);
    pixelmap->EncodeTlv(buff);
    pixelmapTlv = PixelMap::DecodeTlv(buff);
    if (pixelmapTlv != nullptr) {
        delete pixelmapTlv;
        pixelmapTlv = nullptr;
    }
    buff.clear();
    return;
}

void EmptyDataTest(int32_t width, int32_t height, PixelFormat format)
{
    std::unique_ptr<PixelMap> pixelMap = std::make_unique<PixelMap>();
    std::vector<uint8_t> buff;

    if (pixelMap->EncodeTlv(buff)) {
        PixelMap *pixelmapTlv = PixelMap::DecodeTlv(buff);
        if (pixelmapTlv != nullptr) {
            delete pixelmapTlv;
            pixelmapTlv = nullptr;
        }
    }
    buff.clear();

    ImageInfo info;
    info.size.width = width;
    info.size.height = height;
    info.pixelFormat = format;
    info.colorSpace = ColorSpace::SRGB;
    pixelMap->SetImageInfo(info);

    if (pixelMap->EncodeTlv(buff)) {
        PixelMap *pixelmapTlv = PixelMap::DecodeTlv(buff);
        if (pixelmapTlv != nullptr) {
            delete pixelmapTlv;
            pixelmapTlv = nullptr;
        }
    }
    buff.clear();

    uint32_t bufferSize = pixelMap->GetByteCount();
    if (bufferSize > 0) {
        void *buffer = malloc(bufferSize);
        if (buffer == nullptr) {
            return;
        }
        char *ch = static_cast<char *>(buffer);
        for (unsigned int i = 0; i < bufferSize; i++) {
            *(ch++) = (char)i;
        }
        pixelMap->SetPixelsAddr(buffer, nullptr, bufferSize,
            AllocatorType::HEAP_ALLOC, nullptr);
    }
    if (pixelMap->EncodeTlv(buff)) {
        PixelMap *pixelmapTlv = PixelMap::DecodeTlv(buff);
        if (pixelmapTlv != nullptr) {
            delete pixelmapTlv;
            pixelmapTlv = nullptr;
        }
    }
    buff.clear();
}

void TlvTest(int32_t width, int32_t height,
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
    auto pixelmap = Media::PixelMap::Create(opts);
    if (pixelmap == nullptr) {
        return;
    }
    std::vector<uint8_t> buff;
    if (pixelmap->EncodeTlv(buff)) {
        PixelMap *pixelmapTlv = PixelMap::DecodeTlv(buff);
        if (pixelmapTlv != nullptr) {
            delete pixelmapTlv;
            pixelmapTlv = nullptr;
        }
    }
    return;
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

    TlvTest(GetData<int32_t>() % MAX_LENGTH_MODULO, GetData<int32_t>() % MAX_LENGTH_MODULO);
    TlvTest(NUM_4, NUM_6, PixelFormat(GetData<int32_t>() % MAX_LENGTH_MODULO));
    TlvTest(NUM_4, NUM_6, PixelFormat::RGBA_8888);
    for (uint32_t i = 0; i< PIXELFORMAT_COUNT; i++) {
        TlvTest(NUM_4, NUM_6, PixelFormat(i));
    }

    EmptyDataTest(NUM_4, NUM_6, PixelFormat::BGRA_8888);
    EmptyDataTest(NUM_8, NUM_9, PixelFormat::RGBA_8888);
    EmptyDataTest(NUM_4, NUM_6, PixelFormat::ARGB_8888);
    EmptyDataTest(GetData<int32_t>() % MAX_LENGTH_MODULO, GetData<int32_t>() % MAX_LENGTH_MODULO,
        PixelFormat::RGBA_8888);
    EmptyDataTest(GetData<int32_t>() % MAX_LENGTH_MODULO, GetData<int32_t>() % MAX_LENGTH_MODULO,
        PixelFormat(GetData<int32_t>()));
    VariationBuff();
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