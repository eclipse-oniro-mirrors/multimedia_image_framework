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
#include <chrono>
#include <thread>

#include "pixel_map.h"
#include "image_log.h"
#include "post_proc.h"
#include "pixel_map_gl_post_proc_program.h"

namespace OHOS {
namespace Media {
namespace SlrGpu {
constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t NUM_360 = 360;

namespace {
constexpr uint32_t DIVISOR = 2;
constexpr uint32_t NUM_1 = 1;
const uint8_t* g_data = nullptr;
size_t g_size = 0;
size_t g_pos;
} // namespace
using namespace GlCommon;
void PixelMapResize(std::unique_ptr<Media::PixelMap> &pixelMapFromOpts);

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

std::unique_ptr<Media::PixelMap> GetPixelMapFromOpts(Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    int32_t width = GetData<int32_t>() % MAX_LENGTH_MODULO;
    int32_t height = GetData<int32_t>() % MAX_LENGTH_MODULO;
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
        return nullptr;
    }
    return pixelmap;
}

void PixelMapScale(std::unique_ptr<Media::PixelMap> &pixelMapFromOpts)
{
    if (!pixelMapFromOpts) {
        return;
    }
    float xy = GetData<float>();
    PostProc::ScalePixelMapWithGPU(*(pixelMapFromOpts.get()),
        {pixelMapFromOpts->GetWidth() * xy, pixelMapFromOpts->GetHeight() * xy}, AntiAliasingOption::HIGH);
}

void PixelMapResize(std::unique_ptr<Media::PixelMap> &pixelMapFromOpts)
{
    if (!pixelMapFromOpts) {
        return;
    }
    PostProc::RotateInRectangularSteps(*(pixelMapFromOpts.get()), GetData<int32_t>() % NUM_360);
}

std::unique_ptr<Media::PixelMap> GetPixelMapFromPixelmap(std::unique_ptr<Media::PixelMap> &pixelMap,
                                                         Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN,
                                                         bool crop = false)
{
    int32_t width = pixelMap->GetWidth() / DIVISOR + NUM_1;
    int32_t height = pixelMap->GetHeight() / DIVISOR + NUM_1;
    Rect rect;
    if (crop) {
        rect.width = width / 2; // num 2
        rect.height = height / 2; // num 2
    }
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    auto outPixelmap = Media::PixelMap::Create(*pixelMap, rect, opts);
    if (outPixelmap == nullptr) {
        return nullptr;
    }
    return outPixelmap;
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

    // create PixelMap from opts
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts = GetPixelMapFromOpts();
    if (!pixelMapFromOpts || pixelMapFromOpts->GetPixelFormat() == Media::PixelFormat::RGB_888) {
        return false;
    }
    PixelMapResize(pixelMapFromOpts);

    // PixelMap Transform Test
    std::unique_ptr<Media::PixelMap> pixelMapTransform = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapTransform) {
        return false;
    }
    PixelMapResize(pixelMapFromOpts);

    // create from opts with PixelFormat::RGBA_8888
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts_rgba8888 = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOpts_rgba8888) {
        return false;
    }
    PixelMapResize(pixelMapFromOpts);

    // create PixelMap from other PixelMap
    std::unique_ptr<Media::PixelMap> pixelMapFromOtherPixelMap = GetPixelMapFromPixelmap(pixelMapFromOpts_rgba8888,
        Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOtherPixelMap) {
        return false;
    }
    PixelMapResize(pixelMapFromOpts);

    // create cropped PixelMap from other PixelMap
    std::unique_ptr<Media::PixelMap> pixelMapCropFromOtherPixelMap = GetPixelMapFromPixelmap(pixelMapFromOpts_rgba8888,
        Media::PixelFormat::RGBA_8888, true);
    PixelMapResize(pixelMapFromOpts);
    return true;
}

} // namespace SlrGpu
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::SlrGpu::PixelMapMainFuzzTest(data, size);
    return 0;
}