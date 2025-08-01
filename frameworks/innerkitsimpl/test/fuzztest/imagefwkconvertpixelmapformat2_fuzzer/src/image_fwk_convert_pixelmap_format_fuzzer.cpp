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
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "image_fwk_convert_pixelmap_format_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fstream>
#include <vector>
#include <fcntl.h>

#include <filesystem>
#include <iostream>
#include <unistd.h>

#include "buffer_packer_stream.h"
#include "image_format_convert.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"

constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t COLORSPACE_MODULO = 17;
constexpr uint32_t SCALEMODE_MODULO = 2;
constexpr uint32_t DYNAMICRANGE_MODULO = 3;
constexpr uint32_t RESOLUTION_MODULO = 4;
constexpr uint32_t MIMTTYPE_MODULO = 16;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t OPT_SIZE = 80;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
static const std::string IMAGE_INPUT_JPG_PATH1 = "/data/local/tmp/test.jpg";

void PixelMapFormattotalFuzzTest001()
{
    std::string mimeType[] = {"image/png" , "image/raw" , "image/vnd.wap.wbmp" , "image/bmp" , "image/gif" , "image/jpeg" , "image/mpo" , "image/jpeg" , "image/jpeg" , "image/heif" , "image/heif" , "image/x-adobe-dng" , "image/webp" , "image/tiff" , "image/x-icon" , "image/x-sony-arw"};
	
    uint32_t errorCode = 0;
    SourceOptions srcopts;
    srcopts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % MIMTTYPE_MODULO];
    std::string jpgPath = IMAGE_INPUT_JPG_PATH1;
    std::shared_ptr<ImageSource> rImageSource = ImageSource::CreateImageSource(jpgPath, srcopts, errorCode);
    if (errorCode != SUCCESS || rImageSource.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: CreateImageSource fail");
        return;
    }

    DecodeOptions decodeOpts;
	decodeOpts.fitDensity = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.CropRect.left = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.CropRect.top = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.CropRect.width = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.CropRect.height = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.desiredSize.width = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    decodeOpts.desiredSize.height = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
	decodeOpts.desiredRegion.left = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.desiredRegion.top = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.desiredRegion.width = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.desiredRegion.height = FDP->ConsumeIntegral<int32_t>();
    decodeOpts.rotateDegrees = FDP->ConsumeFloatingPoint<float>();
	decodeOpts.rotateNewDegrees = FDP->ConsumeIntegral<uint32_t>();
    decodeOpts.sampleSize = FDP->ConsumeIntegral<uint32_t>();
    decodeOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
	decodeOpts.photoDesiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    decodeOpts.desiredColorSpace = static_cast<Media::ColorSpace>(FDP->ConsumeIntegral<uint8_t>() % COLORSPACE_MODULO);
    decodeOpts.allowPartialImage = FDP->ConsumeBool();
    decodeOpts.editable = FDP->ConsumeBool();
	decodeOpts.preference = static_cast<Media::MemoryUsagePreference>(FDP->ConsumeBool());
	decodeOpts.fastAstc = FDP->ConsumeBool();
	decodeOpts.invokeType = FDP->ConsumeIntegral<uint16_t>();
	decodeOpts.desiredDynamicRange = static_cast<Media::DecodeDynamicRange>(FDP->ConsumeIntegral<uint8_t>() % DYNAMICRANGE_MODULO);
    decodeOpts.resolutionQuality = static_cast<Media::ResolutionQuality>(FDP->ConsumeIntegral<uint8_t>() % RESOLUTION_MODULO);
	decodeOpts.isAisr = FDP->ConsumeBool();
    decodeOpts.isAppUseAllocator = FDP->ConsumeBool();
	
    std::shared_ptr<PixelMap> srcPixelMap = rImageSource->CreatePixelMap(decodeOpts, errorCode);
    if (errorCode != SUCCESS || srcPixelMap.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: CreatePixelMap fail");
        return;
    }

    uint32_t *data = (uint32_t *)srcPixelMap->GetPixels();
    const uint32_t dataLength = srcPixelMap->GetByteCount();
    InitializationOptions opts;
    opts.srcPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    opts.alphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    opts.scaleMode = static_cast<Media::ScaleMode>(FDP->ConsumeIntegral<uint8_t>() % SCALEMODE_MODULO);
    opts.editable = FDP->ConsumeBool();
    opts.useSourceIfMatch = FDP->ConsumeBool();

    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(data, dataLength, opts);
    if (pixelMap.get() == nullptr) {
        IMAGE_LOGE("PixelMapFormatConvert: PixelMap::Create fail");
        return;
    }
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if(size < OPT_SIZE) return -1;
    FuzzedDataProvider fdp(data + size - OPT_SIZE, OPT_SIZE);
    OHOS::Media::FDP = &fdp;
	
    static const std::string pathName = "/data/local/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size - OPT_SIZE) != (ssize_t)size - OPT_SIZE) {
        close(fd);
        IMAGE_LOGE("Fuzzer copy data fail");
        return 0;
    }
    close(fd);
    OHOS::Media::PixelMapFormattotalFuzzTest001();
    return 0;
}
