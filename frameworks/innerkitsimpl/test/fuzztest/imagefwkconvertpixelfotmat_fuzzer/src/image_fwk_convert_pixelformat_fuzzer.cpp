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
#include <fuzzer/FuzzedDataProvider.h>
#include "image_fwk_convert_p010yuv2rgb_ext_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>
#include <fstream>
#include <vector>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <unistd.h>

#include "common_fuzztest_function.h"
#include "buffer_packer_stream.h"
#include "image_format_convert.h"
#include "image_format_convert_utils.h"
#include "image_log.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "message_parcel.h"

namespace OHOS {
namespace Media {
FuzzedDataProvider* FDP;

constexpr uint32_t OPT_SIZE = 40;
constexpr uint32_t SOURCEOPTIONS_MIMETYPE_MODULO = 3;
constexpr uint32_t PIXELFORMAT_MODULO = 105;

void ConvertPixelFormatFuzzTest001(std::string pathName)
{
    PixelFormat destFormat = static_cast<Media::PixelFormat>(FDP->ConsumeIntegral<uint8_t>() % PIXELFORMAT_MODULO);
	
    Media::SourceOptions opts;
    std::string mimeType[] = {"image/jpeg", "image/heic", "image/heif"};
    opts.formatHint = mimeType[FDP->ConsumeIntegral<uint8_t>() % SOURCEOPTIONS_MIMETYPE_MODULO];
    uint32_t errorCode;
    std::shared_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s failed, imageSource is nullptr.", __func__);
        return;
    }
    DecodeOptions decodeOpts;
    SetFdpDecodeOptions(FDP, decodeOpts);
    std::shared_ptr<PixelMap> srcPixelMap = imageSource->CreatePixelMapEx(0, decodeOpts, errorCode);
    if (srcPixelMap == nullptr) {
        IMAGE_LOGE("%{public}s failed, srcPixelMap is nullptr.", __func__);
        return;
    }
    
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(srcPixelMap, destFormat);
    if (ret != SUCCESS) {
        srcPixelMap->FreePixelMap();
        IMAGE_LOGE("ConvertPixelFormatFuzzTest001: CreatePixelMap fail");
        return;
    }
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
    static const std::string pathName = "/data/local/tmp/P010.yuv";
    WriteDataToFile(data, size - OHOS::Media::OPT_SIZE, pathName);
    OHOS::Media::ConvertPixelFormatFuzzTest001(pathName);
    return 0;
}
