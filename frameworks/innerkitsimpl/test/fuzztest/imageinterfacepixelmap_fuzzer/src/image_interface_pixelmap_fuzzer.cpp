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
constexpr uint32_t DMA_WIDTH = 1024;
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
    IMAGE_LOGI("size is %{public}d, %{public}d ", imageInfo.size.width, imageInfo.size.height);
    IMAGE_LOGI("format is %{public}d ", static_cast<int32_t>(imageInfo.pixelFormat));
    IMAGE_LOGI("colorSpace is %{public}d ", static_cast<int32_t>(imageInfo.colorSpace));
    IMAGE_LOGI("alphaType is %{public}d ", static_cast<int32_t>(imageInfo.alphaType));
    IMAGE_LOGI("baseDensity is %{public}d ", static_cast<int32_t>(imageInfo.baseDensity));
    IMAGE_LOGI("encodedFormat is %{public}s ", imageInfo.encodedFormat.c_str());
    IMAGE_LOGI("pixelmap memory type is %{public}d ", static_cast<int32_t>(pixelmap.GetAllocatorType()));
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
    pixelmap->GetImagePropertyString(key, val);

    key = GetStringFromData();
    int32_t value;
    pixelmap->GetImagePropertyInt(key, value);
    key = GetStringFromData();
    val = GetStringFromData();
    pixelmap->ModifyImageProperty(key, val);
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

void FuzzTestIsSameImage()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s craete pixelmap failed", __func__);
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap_same = GetPixelMapFromOpts(opts);
    pixelmap->IsSameImage(*(pixelmap_same.get()));

    opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap_dif = GetPixelMapFromOpts(opts);
    if (!pixelmap_dif) {
        IMAGE_LOGI("%{public}s craete pixelmap_dif failed", __func__);
        return;
    }
    pixelmap->IsSameImage(*(pixelmap_dif.get()));
}

void FuzzTestReadPixelsAndWritePixels()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    int32_t size = pixelmap->GetByteCount();
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
    if (SUCCESS != pixelmap->ReadPixels(size, buffer.get())) {
        IMAGE_LOGI("%{public}s read pixels failed", __func__);
        return;
    }
    if (SUCCESS != pixelmap->WritePixels(buffer.get(), size)) {
        IMAGE_LOGI("%{public}s write pixels failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s write pixels success", __func__);
}

static bool NeedToExclude(PixelFormat pixelFormat)
{
    return pixelFormat == PixelFormat::RGB_565 || pixelFormat == PixelFormat::RGBA_8888 ||
        pixelFormat == PixelFormat::BGRA_8888 || pixelFormat == PixelFormat::RGB_888 ||
        pixelFormat == PixelFormat::NV21 || pixelFormat == PixelFormat::NV12 ||
        pixelFormat == PixelFormat::ALPHA_8;
}

void FuzzTestReadARGBPixels()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (NeedToExclude(opts.pixelFormat)) {
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    int32_t size = pixelmap->GetByteCount();
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
    if (SUCCESS != pixelmap->ReadARGBPixels(size, buffer.get())) {
        IMAGE_LOGI("%{public}s pixelmap read failed", __func__);
    }
}

void FuzzTestAboutMap()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (opts.pixelFormat == PixelFormat::ALPHA_8 || !pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    pixelmap->UnMap();
    pixelmap->ReMap();
}

static Rect GetRandomRect(int32_t width = 0, int32_t height = 0)
{
    Rect rect;
    rect.left = width == 0 ? GetData<uint32_t>() : (1 + (GetData<uint32_t>() % (width >> 2))); // 2: adjusting size
    rect.top = height == 0 ? GetData<uint32_t>() : (1 + (GetData<uint32_t>() % (height >> 2))); // 2: adjusting size
    rect.width = width == 0 ? GetData<uint32_t>() : GetData<uint32_t>() % width;
    rect.height = height == 0 ? GetData<uint32_t>() : GetData<uint32_t>() % height;
    return rect;
}

void FuzzTestReadAndWritePixelsWith5Args(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    Rect region = GetRandomRect(opts.size.width, opts.size.height);
    int32_t srcSize = pixelmap->GetByteCount();
    uint32_t offset = GetData<uint32_t>() % (srcSize >> 2);
    uint32_t regionStride = pixelmap->GetPixelBytes() * region.width;
    uint64_t dstSize = regionStride * region.height;
    std::unique_ptr<uint8_t[]> regionBuffer = std::make_unique<uint8_t[]>(dstSize);
    if (SUCCESS != pixelmap->ReadPixels(dstSize, offset, regionStride, region, regionBuffer.get())) {
        IMAGE_LOGI("%{public}s read pixels failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s read pixels success", __func__);

    region = GetRandomRect(opts.size.width, opts.size.height);
    srcSize = pixelmap->GetByteCount();
    offset = GetData<uint32_t>() % (srcSize >> 2);
    regionStride = pixelmap->GetPixelBytes() * region.width;
    dstSize = regionStride * region.height;
    std::unique_ptr<uint8_t[]> regionBuffer_with_write = std::make_unique<uint8_t[]>(dstSize);
    if (SUCCESS != pixelmap->WritePixels(regionBuffer_with_write.get(), dstSize, offset, regionStride, region)) {
        IMAGE_LOGI("%{public}s write pixels failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s write pixels success", __func__);
}

void FuzzTestReadSinglePixel()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    int32_t x = (GetData<int32_t>() % (opts.size.width >> 2));
    int32_t y = (GetData<int32_t>() % (opts.size.height >> 2));
    Position pos = {x, y};
    uint32_t dst;
    if (SUCCESS != pixelmap->ReadPixel(pos, dst)) {
        IMAGE_LOGI("%{public}s ReadSinglePixel failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s ReadSinglePixel SUCCESS", __func__);
}

void FuzzTestPureRandomSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    IMAGE_LOGI("%{public}s create percent is %{public}lf", __func__, percent);
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        IMAGE_LOGI("%{public}s set alpha failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s set alpha success", __func__);
}

void FuzzTestRGBA_F16PixelMapSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.pixelFormat = PixelFormat::RGBA_F16;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    IMAGE_LOGI("%{public}s create percent is %{public}lf", __func__, percent);
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        IMAGE_LOGI("%{public}s RGBA_F16 set alpha failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s RGBA_F16 set alpha success", __func__);
}

void FuzzTestRGBA_1010102PixelMapSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.pixelFormat = PixelFormat::RGBA_1010102;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    IMAGE_LOGI("%{public}s create percent is %{public}lf", __func__, percent);
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        IMAGE_LOGI("%{public}s RGBA_1010102 set alpha failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s RGBA_1010102 set alpha success", __func__);
}

void CropCreate()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (opts.pixelFormat == PixelFormat::ALPHA_8 || !pixelmap) {
        return;
    }
    ImageInfo imageInfo;
    pixelmap->GetImageInfo(imageInfo);
    Rect rect = GetRandomRect(imageInfo.size.width, imageInfo.size.height);
    opts.size.width = rect.width;
    opts.size.height = rect.height;
    std::unique_ptr<Media::PixelMap> pixelmap_crop = PixelMap::Create(*(pixelmap.get()), rect, opts);
    if (!pixelmap_crop) {
        IMAGE_LOGI("%{public}s create pixelmap failed", __func__);
        return;
    }
    IMAGE_LOGI("%{public}s create pixelmap_crop success", __func__);
}

void DmaAndYuvPixelMapCreate()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.size.height = DMA_HEIGHT;
    opts.size.width = DMA_WIDTH;
    opts.useDMA = true;
    opts.pixelFormat = PixelFormat::YCBCR_P010; 
    std::unique_ptr<Media::PixelMap> pixelmap_dma_yuv = GetPixelMapFromOpts(opts);

    if (!pixelmap_dma_yuv) {
        IMAGE_LOGI("%{public}s create pixelmap_dma_yuv failed", __func__);
        ShowPixelMapDetail(*(pixelmap_dma_yuv.get()));
        return;
    }
    IMAGE_LOGI("%{public}s create pixelmap_dma_yuv success", __func__);
}

void CreatePixelMapFuzzTest()
{
    CropCreate();
    DmaAndYuvPixelMapCreate();
}

void PixelMapInterfaceFuzzTest()
{
    FuzzTestSetMemoryName();
    FuzzTesGetPixels();
    FuzzTestGetAllocatedByteCount();
    FuzzTestGetImageProperty();
    FuzzTestScale();
    FuzzTestIsSameImage();
    FuzzTestReadPixelsAndWritePixels();
    FuzzTestReadARGBPixels();
    FuzzTestReadSinglePixel();
    FuzzTestAboutMap();
    FuzzTestReadAndWritePixelsWith5Args(GetData<uint32_t>() % 2); // 2: random true of false
    FuzzTestPureRandomSetAlpha();
    FuzzTestRGBA_F16PixelMapSetAlpha();
    FuzzTestRGBA_1010102PixelMapSetAlpha();
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