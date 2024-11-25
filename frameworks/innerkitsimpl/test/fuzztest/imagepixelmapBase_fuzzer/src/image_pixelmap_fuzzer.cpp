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

constexpr uint32_t WIDTH_FACTOR = 4;
constexpr uint32_t STRING_LENGTH = 10;
constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;

constexpr uint32_t DIVISOR = 2;
constexpr uint32_t NUM_1 = 1;

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
 * get parcel from g_data
 */
bool ChangeParcel(Parcel &parcel)
{
    if (!parcel.WriteBuffer(g_data, g_size)) {
        return false;
    }
    return true;
}

/*
 * get a pixelmap from opts
 */
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

/*
 * get a pixelmap from g_data
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromData(Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
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
    size_t datalength = width * height * WIDTH_FACTOR;
    uint32_t* colorData = new uint32_t[datalength];
    for (size_t i = 0; i < width * height; i++) {
        colorData[i] = GetData<uint32_t>();
    }
    auto pixelmap = Media::PixelMap::Create(colorData, datalength, opts);
    if (colorData!=nullptr) {
        delete[] colorData;
        colorData = nullptr;
    }
    return pixelmap;
}

/*
 * get a pixelmap from other Pixelmap
 */
std::unique_ptr<Media::PixelMap> GetPixelMapFromPixelmap(std::unique_ptr<Media::PixelMap> &pixelMap,
                                                         Media::PixelFormat pixelFormat = PixelFormat::UNKNOWN)
{
    int32_t width = pixelMap->GetWidth() / DIVISOR + NUM_1;
    int32_t height = pixelMap->GetHeight() / DIVISOR + NUM_1;
    Media::InitializationOptions opts;
    opts.size.width = width;
    opts.size.height = height;
    auto outPixelmap = Media::PixelMap::Create(*pixelMap, opts);
    if (outPixelmap == nullptr) {
        return nullptr;
    }
    return outPixelmap;
}

/*
 * get yuv info
 */
Media::YUVDataInfo GetYUVDataInfo()
{
    Media::YUVDataInfo yuvInfo;
    Media::Size imageSize;
    imageSize.width = GetData<int32_t>();
    imageSize.height = GetData<int32_t>();
    yuvInfo.imageSize = imageSize;
    yuvInfo.yWidth = GetData<uint32_t>();
    yuvInfo.yHeight = GetData<uint32_t>();
    yuvInfo.uvWidth = GetData<uint32_t>();
    yuvInfo.uvHeight = GetData<uint32_t>();
    yuvInfo.yStride = GetData<uint32_t>();
    yuvInfo.uStride = GetData<uint32_t>();
    yuvInfo.vStride = GetData<uint32_t>();
    yuvInfo.uvStride = GetData<uint32_t>();
    yuvInfo.yOffset = GetData<uint32_t>();
    yuvInfo.uOffset = GetData<uint32_t>();
    yuvInfo.vOffset = GetData<uint32_t>();
    yuvInfo.uvOffset = GetData<uint32_t>();
    return yuvInfo;
}

/*
 * get yuv stride info
 */
Media::YUVStrideInfo GetYUVStrideInfo()
{
    Media::YUVStrideInfo yuvStrideInfo;
    yuvStrideInfo.yStride = GetData<uint32_t>();
    yuvStrideInfo.uvStride = GetData<uint32_t>();
    yuvStrideInfo.yOffset = GetData<uint32_t>();
    yuvStrideInfo.uvOffset = GetData<uint32_t>();
    return yuvStrideInfo;
}

/*
 * test pixelmap setImageInfo
 */
bool g_pixelMapSetImageInfoTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    Media::YUVDataInfo yuvInfo = GetYUVDataInfo();
    pixelMap->SetImageYUVInfo(yuvInfo);
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    Media::PixelFormat pixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    pixelMap->AssignYuvDataOnType(pixelFormat, width, height);
    Media::YUVStrideInfo strides = GetYUVStrideInfo();
    pixelMap->UpdateYUVDataInfo(pixelFormat, width, height, strides);
    return true;
}

/*
 * test pixelmap GetPixels
 */
bool PixelMapGetPixelsTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    if (pixelMap == nullptr) {
        return false;
    }
    int32_t width = GetData<int32_t>();
    int32_t height = GetData<int32_t>();
    const uint8_t* pixel = pixelMap->GetPixel(width, height);
    if (pixel == nullptr) {
        return false;
    }
    const uint8_t* pixel8 = pixelMap->GetPixel8(width, height);
    if (pixel8 == nullptr) {
        return false;
    }
    const uint16_t* pixel16 = pixelMap->GetPixel16(width, height);
    if (pixel16 == nullptr) {
        return false;
    }
    const uint32_t* pixel32 = pixelMap->GetPixel32(width, height);
    if (pixel32 == nullptr) {
        return false;
    }
    void* writablePixels = pixelMap->GetWritablePixels();
    if (writablePixels == nullptr) {
        return false;
    }
    const uint8_t* pixels = pixelMap->GetPixels();
    if (pixels == nullptr) {
        return false;
    }
    uint32_t color;
    if (!(pixelMap->GetARGB32Color(width, height, color))) {
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
 * test pixelmap ReadPixels
 */
bool PixelMapReadPixelsTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    uint64_t bufferSize = GetData<uint64_t>();
    uint32_t offset = GetData<uint32_t>();
    uint32_t stride = GetData<uint32_t>();
    Media::Rect rect;
    rect.left = GetData<int32_t>();
    rect.top = GetData<int32_t>();
    rect.width = GetData<int32_t>();
    rect.height = GetData<int32_t>();
    std::unique_ptr<uint8_t[]> dst = std::make_unique<uint8_t[]>(pixelMap->GetByteCount());
    if (dst == nullptr) {
        return false;
    }
    pixelMap->ReadPixels(bufferSize, offset, stride, rect, dst.get());
    pixelMap->ReadPixels(bufferSize, dst.get());
    pixelMap->ReadARGBPixels(bufferSize, dst.get());
    Media::Position position;
    position.x = GetData<int32_t>();
    position.y = GetData<int32_t>();
    uint32_t color;
    pixelMap->ReadPixel(position, color);
    return true;
}

/*
 * test pixelmap WritePixels
 */
bool PixelMapWritePixelsTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    Media::Position position;
    position.x = GetData<int32_t>();
    position.y = GetData<int32_t>();
    uint32_t color = GetData<uint32_t>();
    pixelMap->WritePixel(position, color);
    pixelMap->WritePixels(color);
    std::unique_ptr<uint8_t[]> src = std::make_unique<uint8_t[]>(pixelMap->GetByteCount());
    if (src == nullptr) {
        return false;
    }
    uint64_t bufferSize = GetData<uint64_t>();
    uint32_t offset = GetData<uint32_t>();
    uint32_t stride = GetData<uint32_t>();
    Media::Rect rect;
    rect.left = GetData<int32_t>();
    rect.top = GetData<int32_t>();
    rect.width = GetData<int32_t>();
    rect.height = GetData<int32_t>();
    pixelMap->WritePixels(src.get(), bufferSize, offset, stride, rect);
    pixelMap->WritePixels(src.get(), bufferSize);
    return true;
}

static Rect GetRandomRect(int32_t width = 0, int32_t height = 0)
{
    Rect rect;
    rect.left = width == 0 ? GetData<uint32_t>() : (1 + (GetData<uint32_t>() % (width >> 2))); // 2: adjusting size
    rect.top = height == 0? GetData<uint32_t>() : (1 + (GetData<uint32_t>() % (height >> 2))); // 2: adjusting size
    rect.width = width == 0 ? GetData<uint32_t>() : GetData<uint32_t>() % width;
    rect.height = height == 0? GetData<uint32_t>() : GetData<uint32_t>() % height;
    return rect;
}

/*
 * test pixelmap transform
 */
bool PixelMapTransformTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    float scaleX = std::fmod(GetData<float>(), 1.0f);
    float scaleY = std::fmod(GetData<float>(), 1.0f);
    Media::AntiAliasingOption antiAliasingOption = static_cast<Media::AntiAliasingOption>(GetData<uint32_t>());
    pixelMap->scale(scaleX, scaleY, antiAliasingOption);
    float rotateDegrees = GetData<float>();
    pixelMap->rotate(rotateDegrees);
    float translateX = std::fmod(GetData<float>(), 10.0f);
    float translateY = std::fmod(GetData<float>(), 10.0f);
    pixelMap->translate(translateX, translateY);
    bool flipX = GetData<bool>();
    bool flipY = GetData<bool>();
    pixelMap->flip(flipX, flipY);
    Media::ImageInfo imageInfo;
    pixelmap->GetImageInfo(imageInfo);
    Media::Rect rect = GetRandomRect(imageInfo.size.width, imageInfo.size.height);
    pixelMap->crop(rect);
    pixelMap->ToSdr();
    Media::PixelFormat pixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    bool toSRGB = GetData<bool>();
    pixelMap->ToSdr(pixelFormat, toSRGB);
    // test scale and resize
    float resizeX = std::fmod(GetData<float>(), 1.0f);
    float resizeY = std::fmod(GetData<float>(), 1.0f);
    pixelMap->scale(scaleX, scaleY);
    pixelMap->resize(resizeX, resizeY);
    bool toSdrColorSpaceIsSRGB = GetData<bool>();
    pixelMap->SetToSdrColorSpaceIsSRGB(toSdrColorSpaceIsSRGB);
    return true;
}

/*
 * test pixelmap set image properties
 */
bool PixelMapSetImagePropertiesTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test set ImageInfo
    g_pixelMapSetImageInfoTest(pixelMap);
    // reset config
    Media::Size size;
    size.width = GetData<int32_t>();
    size.height = GetData<int32_t>();
    Media::PixelFormat pixelFormat = static_cast<Media::PixelFormat>(GetData<int32_t>());
    pixelMap->ResetConfig(size, pixelFormat);
    // Set Alpha Type
    Media::AlphaType alphaType = static_cast<Media::AlphaType>(GetData<int32_t>());
    pixelMap->SetAlphaType(alphaType);
    // Set Memory Name
    std::string memoryName = GetStringFromData();
    pixelMap->SetMemoryName(memoryName);
    // Set PixelMap Error
    uint32_t errorCode = GetData<uint32_t>();
    std::string errorInfo = GetStringFromData();
    pixelMap->SetPixelMapError(errorCode, errorInfo);
    // Set Astc
    Media::Size astcSize;
    astcSize.width = GetData<int32_t>();
    astcSize.height = GetData<int32_t>();
    pixelMap->SetAstcRealSize(astcSize);
    pixelMap->SetAstc(GetData<bool>());
    // Set Transform Data
    Media::TransformData transformData;
    transformData.scaleX = std::fmod(GetData<float>(), 1.0f);
    transformData.scaleY = std::fmod(GetData<float>(), 1.0f);
    transformData.rotateD = std::fmod(GetData<float>(), 1.0f);
    transformData.cropLeft = std::fmod(GetData<float>(), 1.0f);
    transformData.cropTop = std::fmod(GetData<float>(), 1.0f);
    transformData.cropWidth = std::fmod(GetData<float>(), 1.0f);
    transformData.cropHeight = std::fmod(GetData<float>(), 1.0f);
    transformData.translateX = std::fmod(GetData<float>(), 10.0f);
    transformData.translateY = std::fmod(GetData<float>(), 10.0f);
    transformData.flipX = GetData<bool>();
    transformData.flipY = GetData<bool>();
    pixelMap->SetTransformData(transformData);
    pixelMap->SetTransformered(GetData<bool>());
    // Set RowStride
    int32_t rowStride = GetData<int32_t>();
    pixelMap->SetRowStride(rowStride);
    // Set Hdr Type
    Media::ImageHdrType imageHdrType = static_cast<Media::ImageHdrType>(GetData<int32_t>());
    pixelMap->SetHdrType(imageHdrType);
    return true;
}

/*
 * test pixelmap is same image
 */
bool PixelMapIsSameImageTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    std::unique_ptr<Media::PixelMap> otherPixelMap = GetPixelMapFromOpts();
    if (!otherPixelMap) {
        return false;
    }
    pixelMap->IsSameImage(*(otherPixelMap.get()));
    return true;
}

/*
 * test pixelmap get functions
 */
bool PixelMapGetFunctionsTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    if (pixelMap->IsHdr()) {
        pixelMap->GetHdrType();
        pixelMap->GetHdrMetadata();
    }
    // test Get Image Property
    std::string imagePropertyKey = GetStringFromData();
    int32_t intValue;
    std::string strValue;
    pixelMap->GetImagePropertyInt(imagePropertyKey, intValue);
    pixelMap->GetImagePropertyString(imagePropertyKey, strValue);
    // test Modify Image Property
    std::string modifyImagePropertyKey = GetStringFromData();
    std::string modifyImagePropertyVal = GetStringFromData();
    pixelMap->ModifyImageProperty(modifyImagePropertyKey, modifyImagePropertyVal);
    // test basic get functions
    pixelMap->GetAlphaType();
    pixelMap->GetExifMetadata();
    pixelMap->GetColorSpace();
    pixelMap->GetToSdrColorSpaceIsSRGB();
    // test basic boolean functions
    pixelMap->IsStrideAlignment();
    pixelMap->IsEditable();
    pixelMap->IsSourceAsResponse();
    pixelMap->IsTransformered();
    return true;
}

/*
 * test pixelmap get image properties
 */
bool PixelMapGetImagePropertiesTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test GetPixels
    if (!PixelMapGetPixelsTest(pixelMap)) {
        return false;
    }
    Media::ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    if (pixelMap->GetPixelBytes() <= 0 ||
        pixelMap->GetRowBytes() <= 0 ||
        pixelMap->GetByteCount() <= 0 ||
        pixelMap->GetWidth() <= 0 ||
        pixelMap->GetHeight() <= 0 ||
        pixelMap->GetCapacity() <= 0 ||
        pixelMap->GetRowStride() <= 0 ||
        pixelMap->GetUniqueId() < 0) {
        return false;
    }
    if (imageInfo.pixelFormat == Media::PixelFormat::ASTC_4x4 ||
        imageInfo.pixelFormat == Media::PixelFormat::ASTC_6x6 ||
        imageInfo.pixelFormat == Media::PixelFormat::ASTC_8x8) {
        if (!pixelMap->IsAstc()) {
            return false;
        }
        Media::Size astcSize;
        pixelMap->GetAstcRealSize(astcSize);
        if (astcSize.width == 0 || astcSize.height == 0) {
            return false;
        }
        Media::TransformData transformData;
        pixelMap->GetTransformData(transformData);
    }
    if (pixelMap->GetBaseDensity() < 0) {
        return false;
    }
    // test ReadPixels
    PixelMapReadPixelsTest(pixelMap);
    if (pixelMap->GetAllocatorType() == Media::AllocatorType::SHARE_MEM_ALLOC ||
        pixelMap->GetAllocatorType() == Media::AllocatorType::DMA_ALLOC) {
        pixelMap->GetAllocatedByteCount(imageInfo);
        if (!(pixelMap->GetFd())) {
            return false;
        }
    }
    Media::YUVDataInfo yuvDataInfo;
    pixelMap->GetImageYUVInfo(yuvDataInfo);
    pixelMap->GetYUVByteCount(imageInfo);
    pixelMap->GetRGBxRowDataSize(imageInfo);
    pixelMap->GetRGBxByteCount(imageInfo);
    // test pixelmap get functions
    PixelMapGetFunctionsTest(pixelMap);
    return true;
}

/*
 * test all pixelmap interfaces
 */
bool PixelMapInterfaceTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test get Image Properties
    PixelMapGetImagePropertiesTest(pixelMap);
    // test get pixels
    PixelMapGetPixelsTest(pixelMap);
    // test set Image Properties
    PixelMapSetImagePropertiesTest(pixelMap);
    // test get Image Properties again
    PixelMapGetImagePropertiesTest(pixelMap);
    return true;
}

/*
 * test pixelmap CS interface
 */
bool PixelMapCSTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
#ifdef IMAGE_COLORSPACE_FLAG
    constexpr uint32_t COLORSPACENAME_MODULO = 10;
    OHOS::ColorManager::ColorSpaceName colorSpaceName =
        static_cast<OHOS::ColorManager::ColorSpaceName>(GetData<int32_t>() % COLORSPACENAME_MODULO);
    OHOS::ColorManager::ColorSpace grColorSpace = OHOS::ColorManager::ColorSpace(colorSpaceName);
    pixelMap->InnerSetColorSpace(grColorSpace);
    pixelMap->InnerSetColorSpace(grColorSpace, true);
    pixelMap->InnerGetGrColorSpace();
    pixelMap->ApplyColorSpace(grColorSpace);
#endif
    return true;
}

/*
 * test pixelmap IPC interface
 */
bool PixelMapIPCTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test parcel pixelmap
    Parcel parcel;
    pixelMap->SetMemoryName("MarshallingPixelMap");
    if (!pixelMap->Marshalling(parcel)) {
        IMAGE_LOGI("PixelMapIPCTest Marshalling failed id: %{public}d, isUnmap: %{public}d",
            pixelMap->GetUniqueId(), pixelMap->IsUnMap());
        return false;
    }
    Media::PixelMap* unmarshallingPixelMap = Media::PixelMap::Unmarshalling(parcel);
    if (!unmarshallingPixelMap) {
        return false;
    }
    unmarshallingPixelMap->SetMemoryName("unmarshallingPixelMap");
    IMAGE_LOGI("PixelMapIPCTest unmarshallingPixelMap failed id: %{public}d, isUnmap: %{public}d",
        unmarshallingPixelMap->GetUniqueId(), unmarshallingPixelMap->IsUnMap());
    unmarshallingPixelMap->FreePixelMap();
    delete unmarshallingPixelMap;
    unmarshallingPixelMap = nullptr;
    return true;
}

/*
 * test pixelmap TLV interface
 */
bool PixelMapTLVTest(std::unique_ptr<Media::PixelMap> &pixelMap)
{
    // test tlv pixelmap
    std::vector<uint8_t> buff;
    if (!pixelMap->EncodeTlv(buff)) {
        return false;
    }
    Media::PixelMap* decodePixelMap = Media::PixelMap::DecodeTlv(buff);
    if (!decodePixelMap) {
        return false;
    }
    decodePixelMap->FreePixelMap();
    delete decodePixelMap;
    decodePixelMap = nullptr;
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

    // create PixelMap from opts
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts = GetPixelMapFromOpts();
    if (!pixelMapFromOpts) {
        return false;
    }
    PixelMapInterfaceTest(pixelMapFromOpts);

    // PixelMap Transform Test
    std::unique_ptr<Media::PixelMap> pixelMapTransform = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapTransform) {
        return false;
    }
    PixelMapTransformTest(pixelMapTransform);

    // create from opts with PixelFormat::RGBA_8888
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts_rgba8888 = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOpts_rgba8888) {
        return false;
    }
    PixelMapWritePixelsTest(pixelMapFromOpts_rgba8888);
    PixelMapTLVTest(pixelMapFromOpts_rgba8888);
    pixelMapFromOpts_rgba8888->SetMemoryName("pixelMapFromOpts_rgba8888");

    // create PixelMap from other PixelMap
    std::unique_ptr<Media::PixelMap> pixelMapFromOtherPixelMap = GetPixelMapFromPixelmap(pixelMapFromOpts_rgba8888,
        Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOtherPixelMap) {
        return false;
    }

    return true;
}

bool PixelMapFromOptsMainFuzzTest()
{
    if (g_data == nullptr) {
        return false;
    }
    // create from opts
    std::unique_ptr<Media::PixelMap> pixelMapFromOpts = GetPixelMapFromOpts(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromOpts) {
        return false;
    }
    PixelMapIPCTest(pixelMapFromOpts);
    PixelMapCSTest(pixelMapFromOpts);
    return true;
}

bool PixelMapFromDataMainFuzzTest()
{
    // create from data
    std::unique_ptr<Media::PixelMap> pixelMapFromData = GetPixelMapFromData(Media::PixelFormat::RGBA_8888);
    if (!pixelMapFromData) {
        return false;
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
    OHOS::Media::PixelMapFromOptsMainFuzzTest();
    OHOS::Media::PixelMapFromDataMainFuzzTest();
    return 0;
}