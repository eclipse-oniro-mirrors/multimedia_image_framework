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

#include "image_fwk_decode_svg_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "svg_decoder.h"
#include "image_log.h"
#include "pixel_yuv.h"
#include "file_source_stream.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_SVG_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
void SvgDecoderFuncTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN path: %{public}s", __func__, pathName.c_str());
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s CreateImageSource failed", __func__);
        return;
    }
    imageSource->GetiTxtLength();
    std::shared_ptr<SvgDecoder> svgDecoder = std::make_shared<SvgDecoder>();
    SourceStream* sourceStreamPtr = (imageSource->sourceStreamPtr_).get();
    svgDecoder->SetSource(*sourceStreamPtr);
    if (!svgDecoder->DoDecodeHeader()) {
        IMAGE_LOGE("%{public}s not svg", __func__);
        return;
    }
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    svgDecoder->SetDecodeOptions(0, plOpts, plInfo);
    DecodeContext context;
    svgDecoder->Decode(0, context);
    uint32_t num;
    svgDecoder->GetTopLevelImageNum(num);
    context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::DMA_ALLOC;
    svgDecoder->AllocBuffer(context);
    context.allocatorType = AllocatorType::HEAP_ALLOC;
    svgDecoder->AllocBuffer(context);
    svgDecoder->DoSetDecodeOptions(0, plOpts, plInfo);
    Size plSize;
    svgDecoder->DoGetImageSize(0, plSize);
    svgDecoder->DoDecode(0, context);

    DecodeOptions dstOpts;
    imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    imageSource->CreatePixelMap(0, dstOpts, errorCode);
    imageSource->Reset();
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    static const std::string pathName = "/data/local/tmp/test_decode_svg.svg";
    WriteDataToFile(data, size, pathName);
    OHOS::Media::SvgDecoderFuncTest001(pathName);
    return 0;
}