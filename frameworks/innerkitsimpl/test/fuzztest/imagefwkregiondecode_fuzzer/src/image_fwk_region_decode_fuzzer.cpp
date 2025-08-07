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

#include "image_fwk_region_decode_fuzzer.h"

#define private public
#define protected public
#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

#include "common_fuzztest_function.h"
#include "image_source.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "IMAGE_FWK_REGION_DECODE_FUZZ"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;
void RegionDecodeTest001(const std::string& pathName, CropAndScaleStrategy strategy = CropAndScaleStrategy::DEFAULT)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = {100, 100};
    decodeOpts.CropRect = {0, 0, 50, 50};
    decodeOpts.cropAndScaleStrategy = strategy;
    imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void FormatTest001(const std::string& pathName, PixelFormat dstPixelFormat)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    SourceOptions srcOpts;
    uint32_t errorCode;
    auto imageSource = ImageSource::CreateImageSource(pathName, srcOpts, errorCode);
    if (imageSource == nullptr) {
        return ;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredPixelFormat = dstPixelFormat;
    imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string jpegPath1 = "/data/local/tmp/test.jpg";
    OHOS::Media::RegionDecodeTest001(jpegPath1);
    OHOS::Media::RegionDecodeTest001(jpegPath1, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(jpegPath1, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    OHOS::Media::FormatTest001(jpegPath1, OHOS::Media::PixelFormat::NV21);
    std::string jpegPath2 = "/data/local/tmp/test_entrys.jpg";
    OHOS::Media::RegionDecodeTest001(jpegPath2);
    OHOS::Media::RegionDecodeTest001(jpegPath2, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(jpegPath2, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    OHOS::Media::FormatTest001(jpegPath2, OHOS::Media::PixelFormat::NV12);
    std::string jpegPath3 = "/data/local/tmp/test_exif.jpg";
    OHOS::Media::RegionDecodeTest001(jpegPath3);
    OHOS::Media::RegionDecodeTest001(jpegPath3, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(jpegPath3, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    OHOS::Media::FormatTest001(jpegPath3, OHOS::Media::PixelFormat::NV21);
    std::string heicPath1 = "/data/local/tmp/test_heic_128_128.heic";
    OHOS::Media::RegionDecodeTest001(heicPath1);
    OHOS::Media::RegionDecodeTest001(heicPath1, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(heicPath1, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    std::string heicPath2 = "/data/local/tmp/test_heif.heic";
    OHOS::Media::RegionDecodeTest001(heicPath2);
    OHOS::Media::RegionDecodeTest001(heicPath2, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(heicPath2, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    OHOS::Media::FormatTest001(heicPath2, OHOS::Media::PixelFormat::NV12);
    std::string heicPath3 = "/data/local/tmp/test_heif_hdr.heic";
    OHOS::Media::RegionDecodeTest001(heicPath3);
    OHOS::Media::RegionDecodeTest001(heicPath3, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(heicPath3, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    OHOS::Media::FormatTest001(heicPath3, OHOS::Media::PixelFormat::NV21);
    std::string pngPath1 = "/data/local/tmp/test_picture_png.png";
    OHOS::Media::RegionDecodeTest001(pngPath1);
    OHOS::Media::RegionDecodeTest001(pngPath1, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
    OHOS::Media::RegionDecodeTest001(pngPath1, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
    /* Run your code on data */
    static const std::string pathName = "/data/local/tmp/test_region_decode_jpg.jpg";
    WriteDataToFile(data, size, pathName);
    OHOS::Media::RegionDecodeTest001(pathName);
    return 0;
}