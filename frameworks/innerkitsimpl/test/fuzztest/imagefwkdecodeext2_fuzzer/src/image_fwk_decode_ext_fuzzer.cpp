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
#include "image_fwk_decode_ext_fuzzer.h"

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
#include "bmp_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"
#include "file_source_stream.h"

constexpr uint32_t PIXELFORMAT_MODULO = 8;
constexpr uint32_t COLORSPACE_MODULO = 17;
constexpr uint32_t ALPHATYPE_MODULO = 4;
constexpr uint32_t OPT_SIZE = 40;

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_EXT_FUZZ"

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
using namespace OHOS::ImagePlugin;
void ExtDecoderFuncTest001(const std::string& pathName)
{
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s imageSource nullptr", __func__);
        return;
    }
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    SourceStream* sourceStreamPtr = (imageSource->sourceStreamPtr_).get();
    extDecoder->SetSource(*sourceStreamPtr);
    if (!extDecoder->DecodeHeader()) {
        IMAGE_LOGE("%{public}s init failed", __func__);
        return;
    }
	
    DecodeContext context;
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
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
	
    uint32_t ret = extDecoder->SetDecodeOptions(0, plOpts, plInfo);
    if (ret != SUCCESS) return;
	extDecoder->Decode(0, context);
	
	context.info.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    extDecoder->DecodeToYuv420(0, context);
    extDecoder->CheckContext(context);
	
    extDecoder->DoHeifToYuvDecode(context);
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
    WriteDataToFile(data, size - OPT_SIZE, pathName);
    OHOS::Media::ExtDecoderFuncTest001(pathName);
    return 0;
}
