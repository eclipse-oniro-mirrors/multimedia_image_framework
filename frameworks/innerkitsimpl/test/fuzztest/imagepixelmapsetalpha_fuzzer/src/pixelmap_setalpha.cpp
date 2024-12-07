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
#include "message_parcel.h"
#include "pixel_map.h"
#include "securec.h"

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t BOOLEANMODULO = 2;
constexpr uint32_t SETALPHAMINWIDTH = 50;
constexpr uint32_t SETALPHAMINHEIGHT = 50;
constexpr uint32_t NUM_15 = 15;
constexpr uint32_t NUM_10 = 10;

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

Media::InitializationOptions GetInitialRandomOpts()
{
    int32_t width = GetData<int32_t>() % MAX_LENGTH_MODULO;
    int32_t height = GetData<int32_t>() % MAX_LENGTH_MODULO;
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO);
    opts.pixelFormat  = static_cast<Media::PixelFormat>(GetData<int32_t>() % PIXELFORMAT_MODULO);
    opts.alphaType = static_cast<Media::AlphaType>(GetData<int32_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(GetData<int32_t>() % SCALEMODE_MODULO);
    opts.editable = GetData<bool>();
    opts.useSourceIfMatch = GetData<bool>();
    return opts;
}

/*
 * get a pixelmap from opts
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromOpts(const Media::InitializationOptions &opts)
{
    auto pixelmap = Media::PixelMap::Create(opts);
    if (pixelmap == nullptr) {
        return nullptr;
    }
    return pixelmap;
}

/*
 * get a pixelmap from opts and data
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromOptsAndRandomData(const Media::InitializationOptions &opts)
{
    uint32_t size = opts.size.width * opts.size.height;
    std::unique_ptr<uint32_t[]> buffer = std::make_unique<uint32_t[]>(size);
    for (int i = 0; i < size; i++) {
        buffer[i] = GetData<uint32_t>();
    }
    auto pixelmap = Media::PixelMap::Create(buffer.get(), size, opts);
    return pixelmap;
}

void FuzzTestPureRandomSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.size.width = GetData<uint32_t>() % SETALPHAMINWIDTH;
    opts.size.height = GetData<uint32_t>() % SETALPHAMINHEIGHT;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    if (GetData<uint32_t>() % BOOLEANMODULO) {
        pixelmap->UnMap();
    } else {
        pixelmap->ReMap();
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        return;
    }
}

void FuzzTestRGBA_1010102PixelMapSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.pixelFormat = PixelFormat::RGBA_1010102;
    opts.size.width = GetData<uint32_t>() % SETALPHAMINWIDTH;
    opts.size.height = GetData<uint32_t>() % SETALPHAMINHEIGHT;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        return;
    }
}

void FuzzTestGetNamedPixelFormat()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    static int32_t formatName = 1;
    opts.pixelFormat = static_cast<Media::PixelFormat>(formatName++ % NUM_15);
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    float percent = static_cast<float>((GetData<uint32_t>()) % 10) / 10.0;
    pixelmap->UnMap();
    pixelmap->SetAlpha(percent);
}

void FuzzTestPremulPixelMapSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.pixelFormat = PixelFormat::RGBA_8888;
    opts.size.width = NUM_10;
    opts.size.height = NUM_10;
    opts.alphaType = AlphaType::IMAGE_ALPHA_TYPE_PREMUL;

    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOptsAndRandomData(opts);
    if (!pixelmap) {
        return;
    }
    IMAGE_LOGE("GetPixelMapFromOptsAndRandomData SUCCESS");
    if (GetData<uint32_t>() % BOOLEANMODULO) {
        pixelmap->UnMap();
    } else {
        pixelmap->ReMap();
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    pixelmap->SetAlpha(percent);
}

void PixelMapSetAlphaFuzzTest()
{
    FuzzTestPureRandomSetAlpha();
    FuzzTestRGBA_1010102PixelMapSetAlpha();
    FuzzTestGetNamedPixelFormat();
    FuzzTestPremulPixelMapSetAlpha();
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
    PixelMapSetAlphaFuzzTest();
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