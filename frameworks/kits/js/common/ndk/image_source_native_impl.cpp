/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "image_source_native_impl.h"

using namespace OHOS;
using namespace Media;
#ifdef __cplusplus
extern "C" {
#endif

OH_ImageSourceNative::~OH_ImageSourceNative()
{
    if (innerImageSource_) {
        innerImageSource_ = nullptr;
    }
}

std::shared_ptr<ImageSource> OH_ImageSourceNative::GetInnerImageSource()
{
    return innerImageSource_;
}

OH_ImageSourceNative::OH_ImageSourceNative(std::shared_ptr<ImageSource> imageSource)
{
    innerImageSource_ = imageSource;
}

OH_ImageSourceNative::OH_ImageSourceNative(char *uri, size_t size, SourceOptions opts)
{
    std::string strUri = std::string(uri, size);
    std::string path = UrlToPath(strUri);
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(path, opts, errorCode);
    if (nativeImageSource == nullptr) {
        innerImageSource_ = nullptr;
        return;
    }
    innerImageSource_ = std::move(nativeImageSource);
}

OH_ImageSourceNative::OH_ImageSourceNative(int32_t fd, SourceOptions opts)
{
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    if (nativeImageSource == nullptr) {
        innerImageSource_ = nullptr;
        return;
    }
    innerImageSource_ = std::move(nativeImageSource);
}

OH_ImageSourceNative::OH_ImageSourceNative(uint8_t *data, size_t dataSize, SourceOptions opts, bool isUserBuffer)
{
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(
        data, dataSize, opts, errorCode, isUserBuffer);
    if (errorCode != IMAGE_SUCCESS || nativeImageSource == nullptr) {
        innerImageSource_ = nullptr;
        return;
    }
    innerImageSource_ = std::move(nativeImageSource);
}

OH_ImageSourceNative::OH_ImageSourceNative(RawFileDescriptor rawFile, SourceOptions opts)
{
    uint32_t errorCode = IMAGE_BAD_PARAMETER;
    int32_t rawFileLength = rawFile.start + rawFile.length;
    std::unique_ptr<ImageSource> nativeImageSource = ImageSource::CreateImageSource(
        rawFile.fd, rawFile.start, rawFileLength, opts, errorCode);
    if (nativeImageSource == nullptr) {
        innerImageSource_ = nullptr;
        return;
    }
    innerImageSource_ = std::move(nativeImageSource);
}

OH_DecodingOptionsForPicture::OH_DecodingOptionsForPicture(
    std::shared_ptr<OHOS::Media::DecodingOptionsForPicture> decodingOptionsForPicture)
{
    decodingOptionsForPicture_ = decodingOptionsForPicture;
}

OH_DecodingOptionsForPicture::~OH_DecodingOptionsForPicture() {}

std::shared_ptr<OHOS::Media::DecodingOptionsForPicture> OH_DecodingOptionsForPicture::GetInnerDecodingOptForPicture()
{
    return decodingOptionsForPicture_;
}

OH_ImageRawData::OH_ImageRawData(std::vector<uint8_t>& imageData, uint32_t bitsPerPixel)
    : imageData_(std::move(imageData)), bitsPerPixel_(bitsPerPixel)
{
}

OH_ImageRawData::~OH_ImageRawData() {}

size_t OH_ImageRawData::GetSize() const
{
    return static_cast<size_t>(imageData_.size());
}

uint8_t* OH_ImageRawData::GetData()
{
    return static_cast<uint8_t*>(imageData_.data());
}

uint8_t OH_ImageRawData::GetBitsPerPixel() const
{
    return static_cast<uint8_t>(bitsPerPixel_);
}

#ifdef __cplusplus
};
#endif