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

#include "image_fwk_decode_png_fuzzer.h"

#define private public
#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "png_decoder.h"
#include "nine_patch_listener.h"
#include "image_log.h"
#include "file_source_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_PNG_FUZZER"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

const std::string NINE_PATCH = "ninepatch";
constexpr uint32_t OPT_SIZE = 40;
constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;

void PngDecoderFuncTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    Media::SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullptr.", __func__);
        return;
    }
    DecodeOptions dstOpts;
    SetFdpDecodeOptions(FDP, dstOpts);
    imageSource->CreatePixelMap(0, dstOpts, errorCode);
    std::shared_ptr<PngDecoder> pngDecoder = std::make_shared<PngDecoder>();
    SourceStream* sourceStreamPtr = (imageSource->sourceStreamPtr_).get();
    pngDecoder->SetSource(*sourceStreamPtr);
    pngDecoder->HasProperty(NINE_PATCH);
    PixelDecodeOptions plOpts;
    SetFdpPixelDecodeOptions(FDP, plOpts);
    PlImageInfo plInfo;
    pngDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    if (pngDecoder->Decode(0, context) != SUCCESS) {
        pngDecoder->Reset();
        return;
    }
    Size size;
    pngDecoder->GetImageSize(0, size);
    ProgDecodeContext progContext;
    pngDecoder->PromoteIncrementalDecode(0, progContext);
    pngDecoder->SetSource(*(pngDecoder->inputStreamPtr_));
    pngDecoder->Reset();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void CreateImageSourceByNinePatchFuzz001(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    NinePatchListener ninepath;
    const std::string tag = "npTc";
    ninepath.ReadChunk(tag, reinterpret_cast<void *>(const_cast<uint8_t *>(data)), size);

    float scaleX = FDP->ConsumeFloatingPoint<float>();
    float scaleY = FDP->ConsumeFloatingPoint<float>();
    int32_t scaledWidth = FDP->ConsumeIntegral<int32_t>();
    int32_t scaledHeight = FDP->ConsumeIntegral<int32_t>();
    ninepath.Scale(scaleX, scaleY, scaledWidth, scaledHeight);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (size < OHOS::Media::OPT_SIZE) {
        return -1;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    static const std::string pathName = "/data/local/tmp/test_decoder_png.png";
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, pathName);
    OHOS::Media::PngDecoderFuncTest001(pathName);
    OHOS::Media::CreateImageSourceByNinePatchFuzz001(data, size);
    return 0;
}