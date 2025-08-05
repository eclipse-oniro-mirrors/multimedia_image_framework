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

#include "image_fwk_decode_hdr_fuzzer.h"

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

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_DECODE_HDR_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
void HdrTest001(const std::string& pathName)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return;
    }
    ImageInfo imageInfo;
    imageSource->GetImageInfo(0, imageInfo);
    if (!imageSource->IsHdrImage()) {
        IMAGE_LOGE("%{public}s %{public}s is not hdr", __func__, pathName.c_str());
        return;
    }
    DecodeContext gainMapCtx;
    if (imageSource->mainDecoder_->DecodeHeifGainMap(gainMapCtx)) {
        IMAGE_LOGI("%{public}s DecodeHeifGainMap SUCCESS, %{public}s", __func__, pathName.c_str());
        imageSource->mainDecoder_->GetHdrMetadata(imageSource->mainDecoder_->CheckHdrType());
    } else {
        IMAGE_LOGE("%{public}s DecodeHeifGainMap failed, %{public}s", __func__, pathName.c_str());
    }
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
    OHOS::Media::HdrTest001(pathName);
    return 0;
}