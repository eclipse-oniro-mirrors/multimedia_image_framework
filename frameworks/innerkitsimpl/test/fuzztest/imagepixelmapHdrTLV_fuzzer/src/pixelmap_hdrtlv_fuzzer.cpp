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
#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include "image_log.h"
#include "image_source.h"
#include "image_utils.h"
#include "pixel_map.h"

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t HDR_PIXELFORMAT_COUNT = 3;
constexpr uint32_t MIN_DMA_SIZE = 512;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t SCALEMODE_MODULO = 2;

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

std::unique_ptr<Media::PixelMap> CreateDmaHdrPixelMap(const std::string& pathName)
{
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return nullptr;
    }
    const PixelFormat hdrFormats[] = {PixelFormat::RGBA_1010102, PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = GetData<int32_t>() % MAX_LENGTH_MODULO + MIN_DMA_SIZE;
    decodeOpts.desiredSize.height = GetData<int32_t>() % MAX_LENGTH_MODULO + MIN_DMA_SIZE;
    decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
    decodeOpts.preferDma = true;
    decodeOpts.desiredPixelFormat = hdrFormats[GetData<int32_t>() % HDR_PIXELFORMAT_COUNT];
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    return pixelMap;
}

void PixelMapHdrTlvFuzzTest(const std::string& pathName)
{
    auto hdrPixelMap = CreateDmaHdrPixelMap(pathName);
    if (!hdrPixelMap) {
        return;
    }
    std::vector<uint8_t> buff;
    hdrPixelMap->EncodeTlv(buff);
    Media::PixelMap::DecodeTlv(buff);
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
void PixelMapTlvFuzzTest()
{
    auto pixelMap = Media::PixelMap::Create(GetInitialRandomOpts());
    if (!pixelMap) {
        return;
    }
    std::vector<uint8_t> buff;
    pixelMap->EncodeTlv(buff);
    Media::PixelMap::DecodeTlv(buff);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::g_data = data;
    OHOS::Media::g_size = size;
    OHOS::Media::g_pos = 0;
    static const std::string pathName = "/data/local/tmp/image/hdr.jpg";
    OHOS::Media::PixelMapHdrTlvFuzzTest(pathName);
    OHOS::Media::PixelMapTlvFuzzTest();
    return 0;
}