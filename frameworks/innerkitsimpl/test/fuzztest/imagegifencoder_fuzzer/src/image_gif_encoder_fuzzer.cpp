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

#include "image_gif_encoder_fuzzer.h"

#include <fcntl.h>

#include "image_packer.h"
#include "abs_image_encoder.h"
#include "gif_encoder.h"
#include "image_source.h"
#include "buffer_packer_stream.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {

static constexpr uint32_t SIZE_TEN = 10;
static constexpr uint32_t ARRAY_LENGTH = 1000;

void GifEncoderPackingEmptyImageFuzz()
{
    auto gifEncoder = std::make_shared<ImagePlugin::GifEncoder>();
    ImagePlugin::PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ARRAY_LENGTH);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), SIZE_TEN);
    gifEncoder->StartEncode(*stream.get(), plOpts);

    std::unique_ptr<uint8_t[]> rgb = std::make_unique<uint8_t[]>(SIZE_TEN);
    gifEncoder->Write(rgb.get(), SIZE_TEN);

    Media::InitializationOptions opts;
    opts.size.width = SIZE_TEN;
    opts.size.height = SIZE_TEN;
    opts.editable = true;
    auto pixelMap = Media::PixelMap::Create(opts);
    gifEncoder->AddImage(*pixelMap.get());
    gifEncoder->FinalizeEncode();
}

void GifEncoderPackingEmptyPixelMapFuzz()
{
    auto gifEncoder = std::make_shared<ImagePlugin::GifEncoder>();
    gifEncoder->FinalizeEncode();
}

void GifEncoderPacking(std::unique_ptr<ImageSource>& imageSource)
{
    auto gifEncoder = std::make_shared<ImagePlugin::GifEncoder>();
    DecodeOptions opts;
    uint32_t errorCode = SUCCESS;
    auto pixelMapList = imageSource->CreatePixelMapList(opts, errorCode);
    if (errorCode != SUCCESS) {
        return;
    }
    ImagePlugin::PlEncodeOptions plOpts;
    auto outputData = std::make_unique<uint8_t[]>(ARRAY_LENGTH);
    auto stream = std::make_shared<BufferPackerStream>(outputData.get(), SIZE_TEN);
    gifEncoder->StartEncode(*stream.get(), plOpts);
    for (auto& pixelMapPtr : *pixelMapList) {
        gifEncoder->AddImage(*pixelMapPtr);
    }
    gifEncoder->FinalizeEncode();
}

void GifEncoderPackingByPathNameFuzz(const uint8_t* data, size_t size)
{
    std::string pathName = "/data/local/tmp/moving_test.gif";
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        return;
    }
    Media::SourceOptions opts;
    uint32_t errorCode;
    auto imageSource = Media::ImageSource::CreateImageSource(pathName, opts, errorCode);
    if (errorCode != SUCCESS) {
        close(fd);
        return;
    }
    close(fd);
    GifEncoderPacking(imageSource);
}
} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::GifEncoderPackingEmptyImageFuzz();
    OHOS::Media::GifEncoderPackingEmptyPixelMapFuzz();
    OHOS::Media::GifEncoderPackingByPathNameFuzz(data, size);
    return 0;
}
