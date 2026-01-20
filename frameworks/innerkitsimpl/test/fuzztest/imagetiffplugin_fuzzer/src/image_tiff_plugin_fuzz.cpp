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

#include "image_tiff_plugin_fuzz.h"

#include <cstdint>
#include <string>
#include <unistd.h>
#include <fcntl.h>

#include "buffer_source_stream.h"
#include "common_fuzztest_function.h"
#include "image_log.h"
#include "image_source.h"
#include "tiff_decoder.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "TIFF_PLUGIN_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
FuzzedDataProvider* FDP;

static constexpr uint32_t OPT_SIZE = 40;

bool SetDecodeOptionsFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder)
{
    if (!tiffDecoder) {
        return false;
    }
    PlImageInfo plInfo;
    PixelDecodeOptions plOpts;
    SetFdpPixelDecodeOptions(FDP, plOpts);
    if (tiffDecoder->SetDecodeOptions(0, plOpts, plInfo) != SUCCESS) {
        return false;
    }
    return true;
}

void DecodeFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder)
{
    if (!tiffDecoder) {
        return;
    }
    DecodeContext context;
    tiffDecoder->Decode(0, context);
    if (context.pixelsBuffer.buffer != nullptr) {
        if (context.freeFunc != nullptr) {
            context.freeFunc(context.pixelsBuffer.buffer, context.pixelsBuffer.context,
                context.pixelsBuffer.bufferSize);
        } else {
            PixelMap::ReleaseMemory(context.allocatorType, context.pixelsBuffer.buffer,
                context.pixelsBuffer.context, context.pixelsBuffer.bufferSize);
        }
    }
}

void GetImageSizeFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder)
{
    if (!tiffDecoder) {
        return;
    }
    Size size;
    tiffDecoder->GetImageSize(0, size);
}

void SetSourceStreamFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder, BufferSourceStream& bufferSourceStream)
{
    if (!tiffDecoder) {
        return;
    }
    tiffDecoder->SetSource(bufferSourceStream);
}

void HasPropertyFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder)
{
    if (!tiffDecoder) {
        return;
    }
    std::string mockStr = "MOCK";
    tiffDecoder->HasProperty(mockStr);
}

void ResetFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder)
{
    if (!tiffDecoder) {
        return;
    }
    tiffDecoder->Reset();
}

void ParseICCProfileFuzzTest(std::shared_ptr<TiffDecoder> tiffDecoder)
{
    if (!tiffDecoder) {
        return;
    }
#ifdef IMAGE_COLORSPACE_FLAG
    tiffDecoder->ParseICCProfile();
#endif
}


void NormalDecodeFuzzTest(const uint8_t *data, size_t size)
{
    std::shared_ptr<TiffDecoder> tiffDecoder = std::make_shared<TiffDecoder>();
    if (!tiffDecoder || !data) {
        return;
    }
    std::unique_ptr<BufferSourceStream> sourceStream = BufferSourceStream::CreateSourceStream(data, size);
    if (sourceStream != nullptr) {
        SetSourceStreamFuzzTest(tiffDecoder, *(sourceStream.get()));
    }
    if (!SetDecodeOptionsFuzzTest(tiffDecoder)) {
        return;
    }
    DecodeFuzzTest(tiffDecoder);
    GetImageSizeFuzzTest(tiffDecoder);
    HasPropertyFuzzTest(tiffDecoder);
    ParseICCProfileFuzzTest(tiffDecoder);
    ProgDecodeContext progContext;
    tiffDecoder->PromoteIncrementalDecode(0, progContext);
    uint32_t num = 0;
    tiffDecoder->GetTopLevelImageNum(num);
    bool callReset = FDP->ConsumeBool();
    if (callReset) {
        ResetFuzzTest(tiffDecoder);
    }
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data) {
        return 0;
    }
    /* Run your code on data */
    if (size <  OHOS::Media::OPT_SIZE) {
        return 0;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    OHOS::Media::FDP = &fdp;
    if (!OHOS::Media::FDP) {
        return 0;
    }
    OHOS::Media::NormalDecodeFuzzTest(data, size - OHOS::Media::OPT_SIZE);
    return 0;
}