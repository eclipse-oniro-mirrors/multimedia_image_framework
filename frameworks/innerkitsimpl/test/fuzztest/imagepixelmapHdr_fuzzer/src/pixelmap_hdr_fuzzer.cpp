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
#include "image_log.h"
#include "image_source.h"
#include "image_utils.h"
#include "pixel_map.h"

constexpr uint32_t MAX_LENGTH_MODULO = 1024;
constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t HDR_PIXELFORMAT_COUNT = 3;
constexpr uint32_t MIN_DMA_SIZE = 512;
constexpr uint32_t SUCCESS = 0;

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
    IMAGE_LOGI("%{public}s IN", __func__);
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
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
    return pixelMap;
}

bool PixelMapHdrToSdrFuzzTest(const uint8_t* data, size_t size, const std::string& pathName)
{
    if (data == nullptr) {
        return false;
    }
    // Initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    auto hdrPixelMap = CreateDmaHdrPixelMap(pathName);
    if (!hdrPixelMap) {
        return false;
    }
    uint32_t ret = hdrPixelMap->ToSdr();
    if (ret != SUCCESS) {
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
    static const std::string pathName = "/data/local/tmp/image/hdr.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }
    close(fd);
    OHOS::Media::PixelMapHdrToSdrFuzzTest(data, size, pathName);
    return 0;
}