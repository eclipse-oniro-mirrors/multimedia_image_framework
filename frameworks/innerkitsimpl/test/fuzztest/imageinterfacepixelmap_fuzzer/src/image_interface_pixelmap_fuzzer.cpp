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

#include "image_interface_pixelmap_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>

#include "image_log.h"
#include "media_errors.h"
#include "message_parcel.h"
#include "pixel_map.h"
#include "securec.h"

constexpr uint32_t STRING_LENGTH = 10;
constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t DMA_WIDTH = 512;
constexpr uint32_t DMA_HEIGHT = 512;

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
 * show PixelMap
 */
static void ShowPixelMapDetail(PixelMap &pixelmap)
{
    ImageInfo imageInfo;
    pixelmap.GetImageInfo(imageInfo);
    IMAGE_LOGE("size is %{public}d, %{public}d ", imageInfo.size.width, imageInfo.size.height);
    IMAGE_LOGE("format is %{public}d ", static_cast<int32_t>(imageInfo.pixelFormat));
    IMAGE_LOGE("colorSpace is %{public}d ", static_cast<int32_t>(imageInfo.colorSpace));
    IMAGE_LOGE("alphaType is %{public}d ", static_cast<int32_t>(imageInfo.alphaType));
    IMAGE_LOGE("baseDensity is %{public}d ", static_cast<int32_t>(imageInfo.baseDensity));
    IMAGE_LOGE("encodedFormat is %{public}s ", imageInfo.encodedFormat.c_str());
    IMAGE_LOGE("pixelmap memory type is %{public}d ", static_cast<int32_t>(pixelmap.GetAllocatorType()));
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

void FuzzTestSetMemoryName()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.size.width = 1024; // 1024:width
    opts.size.height = 512; // 512:height
    opts.useDMA = true;

    // create PixelMap from random opts
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts = GetPixelMapFromOpts(opts);
    if (!pixelMapFromOpts) {
        return;
    }

    if (SUCCESS != pixelMapFromOpts->SetMemoryName(GetStringFromData())) {
        IMAGE_LOGI("fail set name");
    }
}

void FuzzTesGetPixels()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    int32_t pos_x = GetData<uint32_t>() % (opts.size.width + (opts.size.width >> 2)); // 2:adjusting range
    int32_t pos_y = GetData<uint32_t>() % (opts.size.height + (opts.size.height >> 2)); // 2:adjusting range
    if (!pixelmap->GetPixel16(pos_x, pos_y)) {
        IMAGE_LOGI("FuzzTesGetPixels get pixels16_1 failed");
    }
    if (!pixelmap->GetPixel32(pos_x, pos_y)) {
        IMAGE_LOGI("FuzzTesGetPixels get pixels32_1 failed");
    }
    pos_x = GetData<int32_t>() % (opts.size.width + (opts.size.width >> 2)); // 2:adjusting range
    pos_y = GetData<int32_t>() % (opts.size.height + (opts.size.height >> 2)); // 2:adjusting range
    if (!pixelmap->GetPixel16(pos_x, pos_y)) {
        IMAGE_LOGI("FuzzTesGetPixels get pixels16_2 failed");
    }
    if (!pixelmap->GetPixel32(pos_x, pos_y)) {
        IMAGE_LOGI("FuzzTesGetPixels get pixels32_2 failed");
    }
}

void FuzzTestGetAllocatedByteCount()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    ImageInfo imageInfo;
    pixelmap->GetImageInfo(imageInfo);
    if (PixelMap::GetAllocatedByteCount(imageInfo) < 0) {
        return ;
    }
    // create NV12 to test GetAllocatedByteCount
    ImageInfo yuvImageInfo;
    opts.pixelFormat = PixelFormat::NV12;
    pixelmap = nullptr;
    pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    pixelmap->GetImageInfo(yuvImageInfo);
    if (PixelMap::GetAllocatedByteCount(yuvImageInfo) < 0) {
        return ;
    }
}

void FuzzTestGetImageProperty()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    std::string key = GetStringFromData();
    std::string val;
    if (SUCCESS != pixelmap->GetImagePropertyString(key, val)) {
        IMAGE_LOGI("%{public}s GetImagePropertyString failed", __func__);
    }

    key = GetStringFromData();
    int32_t value;
    if (SUCCESS != pixelmap->GetImagePropertyInt(key, value)) {
        IMAGE_LOGI("%{public}s GetImagePropertyInt failed", __func__);
    }
}

void FuzzTestScale()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI(" %{public}s create pixelmap failed", __func__);
        return;
    }
    float x = 0.0;
    float y = 0.0;
    x += static_cast<float>((GetData<int32_t>() % 100) / 100); // 100: adjusting scale x
    y += static_cast<float>((GetData<int32_t>() % 100) / 100); // 100: adjusting scale y
    pixelmap->scale(x, y);
}

void DmaAndYuvPixelMapCreate()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.size.height = DMA_HEIGHT;
    opts.size.width = DMA_WIDTH;
    opts.useDMA = true;
    int32_t tmp_format = GetData<int32_t>() % 2; // 2:yuv format range
    opts.pixelFormat = static_cast<Media::PixelFormat>(8 + tmp_format); // 8:adjusting yuv format range
    std::unique_ptr<Media::PixelMap> pixelmap_dma_yuv = GetPixelMapFromOpts(opts);
    if (!pixelmap_dma_yuv) {
        IMAGE_LOGI("%{public}s create pixelmap_dma_yuv failed", __func__);
        ShowPixelMapDetail(*(pixelmap_dma_yuv.get()));
    }
}

void CreatePixelMapFuzzTest()
{
    DmaAndYuvPixelMapCreate();
}

void PixelMapInterfaceFuzzTest()
{
    FuzzTestSetMemoryName();
    FuzzTesGetPixels();
    FuzzTestGetAllocatedByteCount();
    FuzzTestGetImageProperty();
    FuzzTestScale();
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
    PixelMapInterfaceFuzzTest();
    CreatePixelMapFuzzTest();
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