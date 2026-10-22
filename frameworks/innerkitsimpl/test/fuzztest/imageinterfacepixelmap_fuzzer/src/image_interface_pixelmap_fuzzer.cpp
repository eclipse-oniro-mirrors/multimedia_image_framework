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
constexpr uint32_t BOOLMODULE = 2;
constexpr uint32_t RGB_565_BYTES = 2;
constexpr uint32_t RGB_888_BYTES = 3;
constexpr uint32_t RGBA_8888_BYTES = 4;
constexpr uint32_t RGBA_F16_BYTES = 8;
constexpr uint32_t STRIDE_PADDING_MODULO = 4;
constexpr uint32_t MAX_BUFFER_SIZE_MULTIPLIER = 2;

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

bool IsYuv(Media::PixelFormat format)
{
    return format == Media::PixelFormat::NV12 || format == Media::PixelFormat::NV21 ||
        format == Media::PixelFormat::YCBCR_P010 || format == Media::PixelFormat::YCRCB_P010;
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
    pixelMapFromOpts->SetMemoryName(GetStringFromData());
    pixelMapFromOpts->SetMemoryName("");
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
    pixelmap->GetPixel16(pos_x, pos_y);
    pixelmap->GetPixel32(pos_x, pos_y);
    pos_x = GetData<int32_t>() % (opts.size.width + (opts.size.width >> 2)); // 2:adjusting range
    pos_y = GetData<int32_t>() % (opts.size.height + (opts.size.height >> 2)); // 2:adjusting range
    pixelmap->GetPixel16(pos_x, pos_y);
    pixelmap->GetPixel32(pos_x, pos_y);
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
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap_same = GetPixelMapFromOpts(opts);
    pixelmap->IsSameImage(*(pixelmap_same.get()));

    opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap_dif = GetPixelMapFromOpts(opts);
    if (!pixelmap_dif) {
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
        return;
    }
    int32_t size = pixelmap->GetByteCount();
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
    if (SUCCESS != pixelmap->ReadPixels(size, buffer.get())) {
        return;
    }
    if (SUCCESS != pixelmap->WritePixels(buffer.get(), size)) {
        return;
    }
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
        IMAGE_LOGD("%{public}s pixelmap read failed", __func__);
    }
}

void FuzzTestAboutMap()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (opts.pixelFormat == PixelFormat::ALPHA_8 || !pixelmap) {
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

void FuzzTestReadWith5Args(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    Rect region = GetRandomRect(opts.size.width, opts.size.height);
    int32_t srcSize = pixelmap->GetByteCount();
    uint32_t offset = GetData<uint32_t>() % (srcSize >> 2);
    uint32_t regionStride = pixelmap->GetPixelBytes() * region.width;
    uint64_t dstSize = regionStride * region.height;
    std::unique_ptr<uint8_t[]> regionBuffer = std::make_unique<uint8_t[]>(dstSize);
    pixelmap->ReadPixels(dstSize, offset, regionStride, region, regionBuffer.get());
}

void FuzzTestReadSinglePixel()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    int32_t x = (GetData<int32_t>() % (opts.size.width >> 2));
    int32_t y = (GetData<int32_t>() % (opts.size.height >> 2));
    Position pos = {x, y};
    uint32_t dst;
    if (SUCCESS != pixelmap->ReadPixel(pos, dst)) {
        return;
    }
}

void FuzzTestPureRandomSetAlpha()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        return;
    }
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
        return;
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
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    float percent = static_cast<float>((GetData<int32_t>()) % 10) / 10.0;
    if (SUCCESS != pixelmap->SetAlpha(percent)) {
        return;
    }
}

void FuzzTestWritePixelsWith5Args(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    Rect region = GetRandomRect(opts.size.width, opts.size.height);
    int32_t srcSize = pixelmap->GetByteCount();
    uint32_t offset = GetData<uint32_t>() % (srcSize >> 2);
    uint32_t regionStride = pixelmap->GetPixelBytes() * region.width;
    uint64_t dstSize = regionStride * region.height;
    std::unique_ptr<uint8_t[]> regionBuffer_with_write = std::make_unique<uint8_t[]>(dstSize);
    pixelmap->WritePixels(regionBuffer_with_write.get(), dstSize, offset, regionStride, region);
}

void FuzzTestWritePixelsWithPixelFormat(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    // Skip ALPHA_8 target: 1Bpp format, source conversion not supported by WritePixelsConvert
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    // Random source format - may or may not be supported
    PixelFormat srcFormat = static_cast<PixelFormat>(GetData<uint32_t>() % PIXELFORMAT_MODULO);
    // Random buffer size - may be too small or larger than needed
    int32_t targetSize = pixelmap->GetByteCount();
    if (targetSize <= 0) {
        return;
    }
    uint64_t bufferSize = GetData<uint32_t>() % (static_cast<uint32_t>(targetSize) * MAX_BUFFER_SIZE_MULTIPLIER + 1);
    if (bufferSize == 0) {
        bufferSize = 1;
    }
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(bufferSize);
    pixelmap->WritePixels(buffer.get(), bufferSize, srcFormat);
}

void FuzzTestWritePixelsToARGBTarget(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    // Random source format - test non-4bpp sources that previously caused heap overflow
    PixelFormat srcFormat = static_cast<PixelFormat>(GetData<uint32_t>() % PIXELFORMAT_MODULO);
    uint32_t srcBpp = 0;
    switch (srcFormat) {
        case PixelFormat::BGRA_8888:
        case PixelFormat::RGBA_8888:
        case PixelFormat::ARGB_8888:
        case PixelFormat::RGBA_1010102:
            srcBpp = RGBA_8888_BYTES;
            break;
        case PixelFormat::RGB_888:
            srcBpp = RGB_888_BYTES;
            break;
        case PixelFormat::RGB_565:
            srcBpp = RGB_565_BYTES;
            break;
        case PixelFormat::RGBA_F16:
            srcBpp = RGBA_F16_BYTES;
            break;
        default:
            return;
    }
    if (srcBpp == 0) {
        return;
    }
    int32_t width = pixelmap->GetWidth();
    int32_t height = pixelmap->GetHeight();
    uint64_t srcSize = static_cast<uint64_t>(srcBpp) * width * height;
    if (srcSize == 0 || srcSize > static_cast<uint64_t>(INT32_MAX)) {
        return;
    }
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(srcSize);
    pixelmap->WritePixels(buffer.get(), srcSize, srcFormat);
}

void FuzzTestWritePixelsWithStride(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8) {
        return;
    }
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    // Test RGB_888 source with random stride (may include padding)
    int32_t width = pixelmap->GetWidth();
    int32_t height = pixelmap->GetHeight();
    uint32_t rowBytes = static_cast<uint32_t>(width) * RGB_888_BYTES;
    uint32_t stride = rowBytes + GetData<uint32_t>() % STRIDE_PADDING_MODULO; // stride with random padding
    uint64_t bufferSize = static_cast<uint64_t>(stride) * height;
    if (bufferSize == 0 || bufferSize > static_cast<uint64_t>(INT32_MAX)) {
        return;
    }
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(bufferSize);
    Media::Rect region = {0, 0, width, height};
    Media::RWPixelsOptions optsRW{buffer.get(), bufferSize, 0, stride, region, PixelFormat::RGB_888};
    pixelmap->WritePixels(optsRW);
}

void FuzzTestWritePixelsAreaToARGB(bool isEditable)
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.pixelFormat = PixelFormat::ARGB_8888;
    opts.editable = isEditable;
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    // Test non-4bpp source with offset/stride to ARGB target (ARGB two-step conversion path)
    static const PixelFormat SRC_FORMATS[] = {
        PixelFormat::RGB_565,
        PixelFormat::RGB_888,
        PixelFormat::RGBA_F16,
    };
    PixelFormat srcFormat = SRC_FORMATS[GetData<uint32_t>() % (sizeof(SRC_FORMATS) / sizeof(SRC_FORMATS[0]))];
    uint32_t srcBpp = (srcFormat == PixelFormat::RGB_565) ? RGB_565_BYTES :
                      (srcFormat == PixelFormat::RGB_888) ? RGB_888_BYTES : RGBA_F16_BYTES;
    if (srcBpp == 0) {
        return;
    }
    int32_t width = pixelmap->GetWidth();
    int32_t height = pixelmap->GetHeight();
    if (width <= 0 || height <= 0) {
        return;
    }
    uint32_t rowBytes = static_cast<uint32_t>(width) * static_cast<uint32_t>(srcBpp);
    uint32_t stride = rowBytes + GetData<uint32_t>() % STRIDE_PADDING_MODULO;
    uint32_t offset = GetData<uint32_t>() % STRIDE_PADDING_MODULO;
    uint64_t bufferSize = offset + static_cast<uint64_t>(stride) * (height - 1) + rowBytes;
    if (bufferSize == 0 || bufferSize > static_cast<uint64_t>(INT32_MAX)) {
        return;
    }
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(bufferSize);
    Media::Rect region = {0, 0, width, height};
    Media::RWPixelsOptions optsRW{buffer.get(), bufferSize, offset, stride, region, srcFormat};
    pixelmap->WritePixels(optsRW);
}

void FuzzTestCrop()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (opts.pixelFormat == PixelFormat::ALPHA_8 || opts.pixelFormat == PixelFormat::RGB_888) {
        return;
    }
    opts.useDMA = GetData<uint32_t>() % BOOLMODULE;
    if (opts.useDMA) {
        opts.size.height += DMA_HEIGHT;
        opts.size.width += DMA_HEIGHT;
    }
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    Rect rect = GetRandomRect(opts.size.width, opts.size.height);
    pixelmap->crop(rect);
}

void FuzzTestSetFunc()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    if (!pixelmap) {
        return;
    }
    pixelmap->SetFreePixelMapProc([](void *addr, void *context, uint32_t size) {
        return;
    });
}

void FuzzTestClone()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    if (IsYuv(opts.pixelFormat)) {
        return;
    }
    std::unique_ptr<Media::PixelMap> pixelMap = GetPixelMapFromOpts(opts);
    if (pixelMap != nullptr && pixelMap->IsAstc()) {
        return;
    }
    int32_t errorCode = 0;
    pixelMap->Clone(errorCode);
}

void CropCreate()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    std::unique_ptr<Media::PixelMap> pixelmap = GetPixelMapFromOpts(opts);
    opts.useSourceIfMatch = false;
    if (opts.pixelFormat == PixelFormat::ALPHA_8 || !pixelmap) {
        return;
    }
    ImageInfo imageInfo;
    pixelmap->GetImageInfo(imageInfo);
    Rect rect = GetRandomRect(imageInfo.size.width, imageInfo.size.height);
    opts.size.width = rect.width;
    opts.size.height = rect.height;
    PixelMap::Create(*(pixelmap.get()), rect, opts);
}

void DmaAndYuvPixelMapCreate()
{
    Media::InitializationOptions opts = GetInitialRandomOpts();
    opts.size.height = DMA_HEIGHT;
    opts.size.width = DMA_WIDTH;
    opts.useDMA = true;
    opts.pixelFormat = PixelFormat::YCBCR_P010; 
    std::unique_ptr<Media::PixelMap> pixelmap_dma_yuv = GetPixelMapFromOpts(opts);
    opts.pixelFormat = PixelFormat::NV12;
    std::unique_ptr<Media::PixelMap> pixelmap_dma_yuv_nv12 = GetPixelMapFromOpts(opts);
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
    FuzzTestReadWith5Args(GetData<uint32_t>() % 2); // 2: true or false
    FuzzTestPureRandomSetAlpha();
    FuzzTestRGBA_F16PixelMapSetAlpha();
    FuzzTestRGBA_1010102PixelMapSetAlpha();
    FuzzTestWritePixelsWith5Args(GetData<uint32_t>() % 2); // 2: true or false
    FuzzTestWritePixelsWithPixelFormat(GetData<uint32_t>() % 2); // 2: true or false
    FuzzTestWritePixelsToARGBTarget(GetData<uint32_t>() % 2); // 2: true or false
    FuzzTestWritePixelsWithStride(GetData<uint32_t>() % 2); // 2: true or false
    FuzzTestWritePixelsAreaToARGB(GetData<uint32_t>() % 2); // 2: true or false
    FuzzTestCrop();
    FuzzTestSetFunc();
    FuzzTestClone();
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