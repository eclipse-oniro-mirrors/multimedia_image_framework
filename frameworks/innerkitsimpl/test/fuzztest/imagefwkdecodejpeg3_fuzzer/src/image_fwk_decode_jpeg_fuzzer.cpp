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
#include "image_fwk_decode_jpeg_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "ext_decoder.h"
#include "svg_decoder.h"
#include "jpeg_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_JPEG_FUZZ"

constexpr uint32_t PIXELFORMAT_MODULO = 105;
constexpr uint32_t COLORSPACE_MODULO = 17;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t OPT_SIZE = 40;

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
const std::string ORIENTATION = "Orientation";

using namespace OHOS::ImagePlugin;
void JpegTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    srcOpts.formatHint = "image/jpeg";
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    int32_t value = 0;
    imageSource->GetImagePropertyInt(0, "Orientation", value);
	auto jpegDecoder = static_cast<JpegDecoder*>(imageSource->CreateDecoder(errorCode));
    if (jpegDecoder == nullptr) {
        return;
    }
	PixelDecodeOptions plOpts;
	plOpts.CropRect.left = FDP->ConsumeIntegral<int32_t>();
    plOpts.CropRect.top = FDP->ConsumeIntegral<int32_t>();
    plOpts.CropRect.width = FDP->ConsumeIntegral<int32_t>();
    plOpts.CropRect.height = FDP->ConsumeIntegral<int32_t>();
    plOpts.desiredSize.width = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    plOpts.desiredSize.height = FDP->ConsumeIntegralInRange<uint16_t>(0, 0xfff);
    plOpts.rotateDegrees = FDP->ConsumeFloatingPoint<float>();
    plOpts.sampleSize = FDP->ConsumeIntegral<uint32_t>();
    plOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    plOpts.desiredColorSpace = static_cast<Media::ColorSpace>(FDP->ConsumeIntegral<uint8_t>() % COLORSPACE_MODULO);
    plOpts.desireAlphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    plOpts.allowPartialImage = FDP->ConsumeBool();
    plOpts.editable = FDP->ConsumeBool();
	
    PlImageInfo plInfo;
    jpegDecoder->SetDecodeOptions(0, plOpts, plInfo);
	jpegDecoder->GetImagePropertyInt(0, ORIENTATION, value);
    DecodeContext context;
    if (jpegDecoder->Decode(0, context) != SUCCESS) {
        jpegDecoder->Reset();
        delete jpegDecoder;
        jpegDecoder = nullptr;
        return;
    }

    Size size;
    jpegDecoder->GetImageSize(0, size);
	
	ProgDecodeContext progContext;
	jpegDecoder->PromoteIncrementalDecode(0, progContext);

    jpegDecoder->Reset();
    delete jpegDecoder;
    jpegDecoder = nullptr;
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
    static const std::string pathName = "/data/local/tmp/test_decode_jpg.jpg";
    WriteDataToFile(data, size, pathName);
    OHOS::Media::JpegTest001(pathName);
    return 0;
}
