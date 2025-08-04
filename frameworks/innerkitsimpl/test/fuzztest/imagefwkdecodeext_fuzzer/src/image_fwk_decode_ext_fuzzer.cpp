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

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_EXT_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
void ExtDecoderFuncTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN path: %{public}s", __func__, pathName.c_str());
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return;
    }
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(fd, srcOpts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s imageSource nullptr", __func__);
        close(fd);
        return;
    }
    std::shared_ptr<ExtDecoder> extDecoder = std::make_shared<ExtDecoder>();
    SourceStream* sourceStreamPtr = (imageSource->sourceStreamPtr_).get();
    extDecoder->SetSource(*sourceStreamPtr);
    if (!extDecoder->DecodeHeader()) {
        IMAGE_LOGE("%{public}s init failed", __func__);
        close(fd);
        return;
    }
    Media::DecodeOptions dopts;
    DecodeContext context;
    SkImageInfo heifInfo;
    extDecoder->HeifYUVMemAlloc(context, heifInfo);
    int dWidth;
    int dHeight;
    float scale;
    extDecoder->GetScaledSize(dWidth, dHeight, scale);
    extDecoder->GetHardwareScaledSize(dWidth, dHeight, scale);
    extDecoder->IsSupportScaleOnDecode();
    PixelDecodeOptions plOpts;
    PlImageInfo plInfo;
    extDecoder->SetDecodeOptions(0, plOpts, plInfo);
    PixelFormat dstFormat = PixelFormat::UNKNOWN;
    extDecoder->PreDecodeCheckYuv(0, dstFormat);
    extDecoder->DoHardWareDecode(context);
    extDecoder->GetJpegYuvOutFmt(dstFormat);
    extDecoder->DecodeToYuv420(0, context);
    extDecoder->CheckContext(context);
    extDecoder->HardWareDecode(context);
    SkAlphaType alphaType;
    AlphaType outputType;
    extDecoder->ConvertInfoToAlphaType(alphaType, outputType);
    SkColorType format;
    PixelFormat outputFormat;
    extDecoder->ConvertInfoToColorType(format, outputFormat);
    std::string key = "ImageWidth";
    std::string value = "500";
    int32_t valInt = 0;
    extDecoder->GetImagePropertyInt(0, key, valInt);
    extDecoder->GetImagePropertyString(0, key, value);
    extDecoder->GetMakerImagePropertyString(key, value);
    extDecoder->DoHeifToYuvDecode(context);
    close(fd);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    static const std::string pathName = "/data/local/tmp/test.jpg";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        return 0;
    }
    close(fd);
    OHOS::Media::ExtDecoderFuncTest001(pathName);
    return 0;
}