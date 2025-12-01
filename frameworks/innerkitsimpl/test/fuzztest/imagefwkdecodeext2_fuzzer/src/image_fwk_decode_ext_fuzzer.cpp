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
constexpr uint32_t ALLOCATORTYPE_MODULO = 5;
constexpr uint32_t OPT_SIZE = 40;
constexpr uint32_t MAX_SAMPLE_SIZE = 16u;
constexpr float MAX_ROTATE = 360.0f;

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_EXT_FUZZ"

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;
using namespace OHOS::ImagePlugin;

const static std::string CODEC_INITED_KEY = "CodecInited";
const static std::string ENCODED_FORMAT_KEY = "EncodedFormat";
const static std::string SUPPORT_SCALE_KEY = "SupportScale";
const static std::string SUPPORT_CROP_KEY = "SupportCrop";
const static std::string EXT_SHAREMEM_NAME = "EXT RawData";
const static std::string IMAGE_DELAY_TIME = "DelayTime";
const static std::string IMAGE_DISPOSAL_TYPE = "DisposalType";
const static std::string IMAGE_LOOP_COUNT = "GIFLoopCount";
const std::string ACTUAL_IMAGE_ENCODED_FORMAT = "actual_encoded_format";
void ExtDecoderFuncTest002(std::shared_ptr<ExtDecoder> extDecoder)
{
    std::vector<std::string> keys = {
        CODEC_INITED_KEY, ENCODED_FORMAT_KEY, SUPPORT_SCALE_KEY, SUPPORT_CROP_KEY,
        EXT_SHAREMEM_NAME, IMAGE_DELAY_TIME, IMAGE_DISPOSAL_TYPE, IMAGE_LOOP_COUNT, ACTUAL_IMAGE_ENCODED_FORMAT};
    std::string key = keys[FDP->ConsumeIntegral<uint8_t>() % keys.size()];

    int32_t value = 0;
    extDecoder->GetImagePropertyInt(0, key, value);
    std::string valueStr;
    extDecoder->GetImagePropertyString(0, key, valueStr);
    extDecoder->ModifyImageProperty(0, key, valueStr, "");
    extDecoder->ModifyImageProperty(0, key, valueStr, 0);
    extDecoder->ModifyImageProperty(0, key, valueStr, nullptr, 0);
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    extDecoder->GetFilterArea(0, ranges);
    ColorManager::ColorSpaceName gainmap;
    ColorManager::ColorSpaceName hdr;
    extDecoder->GetHeifHdrColorSpace(gainmap, hdr);
}

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
    plOpts.rotateDegrees = FDP->ConsumeFloatingPointInRange<float>(0.0f, MAX_ROTATE);
    plOpts.sampleSize = FDP->ConsumeIntegralInRange<uint32_t>(1u, MAX_SAMPLE_SIZE);
    plOpts.desiredPixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    plOpts.desiredColorSpace = static_cast<Media::ColorSpace>(FDP->ConsumeIntegral<uint8_t>() % COLORSPACE_MODULO);
    plOpts.desireAlphaType = static_cast<Media::AlphaType>(FDP->ConsumeIntegral<uint8_t>() % ALPHATYPE_MODULO);
    plOpts.allowPartialImage = FDP->ConsumeBool();
    plOpts.editable = FDP->ConsumeBool();
	
    uint32_t ret = extDecoder->SetDecodeOptions(0, plOpts, plInfo);
    if (ret != SUCCESS) return;
    extDecoder->Decode(0, context);

    context.info.pixelFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
    context.allocatorType = static_cast<Media::AllocatorType>(FDP->ConsumeIntegral<uint8_t>() % ALLOCATORTYPE_MODULO);
    switch (FDP->ConsumeIntegralInRange<uint8_t>(0, 2)) {
        case 0: extDecoder->DecodeToYuv420(0, context); break;
        case 1: extDecoder->DoHeifToYuvDecode(context); break;
        default: extDecoder->DoHeifDecode(context); break;
    }
    extDecoder->CheckContext(context);
    ExtDecoderFuncTest002(extDecoder);
    extDecoder->Reset();
    context.pixelsBuffer.buffer = nullptr;
    context.freeFunc = nullptr;
    context.pixelsBuffer.bufferSize = 0;
    context.pixelsBuffer.context = nullptr;
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