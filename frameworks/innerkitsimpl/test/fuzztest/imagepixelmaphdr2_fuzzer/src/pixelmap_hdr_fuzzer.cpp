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
#include <fuzzer/FuzzedDataProvider.h>
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
constexpr uint32_t HDR_PIXELFORMAT_COUNT = 3;
constexpr uint32_t MIN_DMA_SIZE = 512;
constexpr uint32_t SUCCESS = 0;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
 
std::unique_ptr<Media::PixelMap> CreateDmaHdrPixelMap()
{
    const PixelFormat hdrFormats[] = {PixelFormat::RGBA_1010102, PixelFormat::YCBCR_P010, PixelFormat::YCRCB_P010};
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO + MIN_DMA_SIZE;
    decodeOpts.desiredSize.height = FDP->ConsumeIntegral<uint16_t>() % MAX_LENGTH_MODULO + MIN_DMA_SIZE;
    decodeOpts.allocatorType = AllocatorType::DMA_ALLOC;
    decodeOpts.preferDma = true;
    decodeOpts.desiredPixelFormat = hdrFormats[FDP->ConsumeIntegral<uint8_t>() % HDR_PIXELFORMAT_COUNT];
    decodeOpts.desiredDynamicRange = DecodeDynamicRange::HDR;
	
	static const std::string pathName = "/data/local/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    size_t size = FDP->remaining_bytes();
	uint8_t* data = (uint8_t*)malloc(size);
	FDP->ConsumeData(data, FDP->remaining_bytes());
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return 0;
    }
    close(fd);
	free(data);
 
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return nullptr;
    }

    auto pixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    remove(pathName.c_str());
    return pixelMap;
}
 
bool PixelMapHdrToSdrFuzzTest()
{
    auto hdrPixelMap = CreateDmaHdrPixelMap();
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

    FuzzedDataProvider fdp(data, size);
    OHOS::Media::FDP = &fdp;
    OHOS::Media::PixelMapHdrToSdrFuzzTest();
    return 0;
}
