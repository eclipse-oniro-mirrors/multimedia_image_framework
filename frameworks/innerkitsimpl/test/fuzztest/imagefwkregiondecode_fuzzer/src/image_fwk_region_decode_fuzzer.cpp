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
static constexpr uint32_t OPT_SIZE = 80;
static const std::string OHOS::Media::JPEG_PATH_1 = "/data/local/tmp/test.jpg";
static const std::string JPEG_PATH_2 = "/data/local/tmp/test_entrys.jpg";
static const std::string JPEG_PATH_3 = "/data/local/tmp/test_exif.jpg";
static const std::string HEIC_PATH_1 = "/data/local/tmp/test_heic_128_128.heic";
static const std::string HEIC_PATH_2 = "/data/local/tmp/test_heif.heic";
static const std::string HEIC_PATH_3 = "/data/local/tmp/test_heif_hdr.heic";
static const std::string PNG_PATH_1 = "/data/local/tmp/test_picture_png.png";
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
    if (size < OHOS::Media::OPT_SIZE) {
        return 0;
    }
    FuzzedDataProvider fdp(data + size - OHOS::Media::OPT_SIZE, OHOS::Media::OPT_SIZE);
    std::vector<std::string> paths = {OHOS::Media::JPEG_PATH_1, OHOS::Media::JPEG_PATH_2, OHOS::Media::JPEG_PATH_3,
        HEIC_PATH_2, HEIC_PATH_3, HEIC_PATH_1, PNG_PATH_1}
    uint8_t index = fdp.ConsumeIntegral<uint8_t>() % paths.size();
    std::string path = paths[index];
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, path);
    uint8_t action = fdp.ConsumeIntegral<uint8_t>() % 5;
    switch (action) {
        case 0:
            OHOS::Media::RegionDecodeTest001(path);
            break;
        case 1:
            OHOS::Media::RegionDecodeTest001(path, OHOS::Media::CropAndScaleStrategy::SCALE_FIRST);
            break;
        case 2:
            OHOS::Media::RegionDecodeTest001(path, OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
            break;
        case 3:
            OHOS::Media::FormatTest001(path, OHOS::Media::PixelFormat::NV21);
            break;
        case 4: {
            static const std::string newPath = "/data/local/tmp/test_region_decode_jpg.jpg";
            WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, newPath);
            OHOS::Media::RegionDecodeTest001(newPath);
            unlink(newPath.c_str());
            break;
        }
        default:
            break;
    }
    return 0;
}