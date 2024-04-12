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
#include "image_packer_native_impl.h"
#include "image_source_native_impl.h"
#include "pixelmap_native_impl.h"

using namespace OHOS;
using namespace Media;
#ifdef __cplusplus
extern "C" {
#endif


OH_ImagePackerNative::OH_ImagePackerNative()
{
    imagePacker_ = std::make_shared<OHOS::Media::ImagePacker>();
}

OH_ImagePackerNative::OH_ImagePackerNative(std::shared_ptr<OHOS::Media::ImagePacker> imagePacker)
{
    imagePacker_ = imagePacker;
}

OH_ImagePackerNative::~OH_ImagePackerNative()
{
    if (imagePacker_) {
        imagePacker_ = nullptr;
    }
}

int32_t OH_ImagePackerNative::PackingFromImageSource(OHOS::Media::PackOption *option, OH_ImageSourceNative *imageSource,
    uint8_t *outData, int64_t *size)
{
    if (option == nullptr || imageSource == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::ImagePacker *imagePacker = imagePacker_.get();
    OHOS::Media::ImageSource *imageSourcePtr = imageSource->GetInnerImageSource().get();
    int64_t packedSize = 0;
    uint32_t ret = IMAGE_SUCCESS;
    const int64_t DEFAULT_BUFFER_SIZE = 25 * 1024 * 1024;
    int64_t bufferSize = (*size <= 0) ? DEFAULT_BUFFER_SIZE : (*size);
    ret = imagePacker->StartPacking(outData, bufferSize, *option);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    ret = imagePacker->AddImage(*imageSourcePtr);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    ret = imagePacker->FinalizePacking(packedSize);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    if (packedSize > 0 && (packedSize < bufferSize)) {
        *size = packedSize;
        return IMAGE_SUCCESS;
    }
    return IMAGE_ENCODE_FAILED;
}

int32_t OH_ImagePackerNative::PackingFromPixelmap(OHOS::Media::PackOption *option, OH_PixelmapNative *pixelmap,
    uint8_t *outData, int64_t *size)
{
    if (option == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::ImagePacker *imagePacker = imagePacker_.get();
    OHOS::Media::PixelMap *pixelmapPtr = pixelmap->GetInnerPixelmap().get();
    int64_t packedSize = 0;
    uint32_t ret = IMAGE_SUCCESS;
    const int64_t DEFAULT_BUFFER_SIZE = 25 * 1024 * 1024;
    int64_t bufferSize = (*size <= 0) ? DEFAULT_BUFFER_SIZE : (*size);
    ret = imagePacker->StartPacking(outData, bufferSize, *option);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    ret = imagePacker->AddImage(*pixelmapPtr);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    ret = imagePacker->FinalizePacking(packedSize);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    if (packedSize > 0 && (packedSize < bufferSize)) {
        *size = packedSize;
        return IMAGE_SUCCESS;
    }
    return IMAGE_ENCODE_FAILED;
}

int32_t OH_ImagePackerNative::PackToFileFromImageSource(OHOS::Media::PackOption *option,
    OH_ImageSourceNative *imageSource, const int fd)
{
    if (option == nullptr || imageSource == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::ImagePacker *imagePacker = imagePacker_.get();
    OHOS::Media::ImageSource *imageSourcePtr = imageSource->GetInnerImageSource().get();
    int64_t packedSize = 0;
    uint32_t ret = IMAGE_SUCCESS;
    ret = imagePacker->StartPacking(fd, *option);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    ret = imagePacker->AddImage(*imageSourcePtr);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    return imagePacker->FinalizePacking(packedSize);
}

int32_t OH_ImagePackerNative::PackToFileFromPixelmap(OHOS::Media::PackOption *option, OH_PixelmapNative *pixelmap,
    int32_t fd)
{
    if (option == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::ImagePacker *imagePacker = imagePacker_.get();
    OHOS::Media::PixelMap *pixelmapPtr = pixelmap->GetInnerPixelmap().get();
    int64_t packedSize = 0;
    uint32_t ret = IMAGE_SUCCESS;
    ret = imagePacker->StartPacking(fd, *option);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    ret = imagePacker->AddImage(*pixelmapPtr);
    if (ret != IMAGE_SUCCESS) {
        return ret;
    }
    return imagePacker->FinalizePacking(packedSize);
}

std::shared_ptr<OHOS::Media::ImagePacker> OH_ImagePackerNative::GetInnerImagePacker()
{
    return imagePacker_;
}

#ifdef __cplusplus
};
#endif