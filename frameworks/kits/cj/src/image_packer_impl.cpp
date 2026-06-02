/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "image_packer_impl.h"

#include "image_common.h"

namespace {
constexpr int32_t INVALID_FD = -1;
constexpr int32_t SIZE_256 = 256;
constexpr int32_t SIZE_512 = 512;
constexpr int32_t SIZE_1024 = 1024;
constexpr int32_t SIZE_1440 = 1440;
constexpr int32_t SIZE_1920 = 1920;
constexpr uint64_t FILE_SIZE_300K = 300 * 1024;
constexpr uint64_t FILE_SIZE_1M = 1 * 1024 * 1024;
constexpr uint64_t FILE_SIZE_4M = 4 * 1024 * 1024;
constexpr uint64_t FILE_SIZE_10M = 10 * 1024 * 1024;
} // namespace

namespace OHOS {
namespace Media {
const int32_t TYPE_IMAGE_SOURCE = 1;
const int32_t TYPE_PIXEL_MAP = 2;
const int32_t TYPE_PICTURE = 3;
const uint64_t DEFAULT_BUFFER_SIZE = 25 * 1024 * 1024; // 25M is the maximum default packedSize

ImagePackerImpl::ImagePackerImpl()
{
    real_ = std::make_unique<ImagePacker>();
}

std::shared_ptr<ImagePacker> ImagePackerImpl::GetImagePacker()
{
    if (real_ == nullptr) {
        return nullptr;
    }
    std::shared_ptr<ImagePacker> res = real_;
    return res;
}

struct ImagePackerContext {
    std::shared_ptr<ImageSource> rImageSource;
    std::shared_ptr<ImagePacker> rImagePacker;
    std::shared_ptr<PixelMap> rPixelMap;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    std::shared_ptr<Picture> rPicture;
#endif
    int32_t packType = TYPE_IMAGE_SOURCE;
};

static std::shared_ptr<ImagePackerContext> CreateImagePackerContext(
    std::shared_ptr<ImagePacker> packer, int32_t packType)
{
    auto context = std::make_shared<ImagePackerContext>();
    if (context) {
        context->rImagePacker = packer;
        context->packType = packType;
    }
    return context;
}

static uint64_t getDefaultBufferSize(int32_t width, int32_t height)
{
    if (width <= SIZE_256 && height <= SIZE_256) {
        return FILE_SIZE_300K;
    }
    if (width <= SIZE_512 && height <= SIZE_512) {
        return FILE_SIZE_1M;
    }
    if (width <= SIZE_1024 && height <= SIZE_1024) {
        return FILE_SIZE_4M;
    }
    if (width <= SIZE_1440 && height <= SIZE_1920) {
        return FILE_SIZE_10M;
    }
    return DEFAULT_BUFFER_SIZE;
}

static uint64_t getDefaultBufferSize(std::shared_ptr<ImagePackerContext> context)
{
    if (context == nullptr) {
        return DEFAULT_BUFFER_SIZE;
    }
    ImageInfo imageInfo {};
    if (context->packType == TYPE_IMAGE_SOURCE) {
        if (context->rImageSource == nullptr) {
            return DEFAULT_BUFFER_SIZE;
        }
        context->rImageSource->GetImageInfo(imageInfo);
    } else if (context->packType == TYPE_PIXEL_MAP) {
        if (context->rPixelMap == nullptr) {
            return DEFAULT_BUFFER_SIZE;
        }
        context->rPixelMap->GetImageInfo(imageInfo);
    }
    if (imageInfo.size.width <= 0 || imageInfo.size.height <= 0) {
        return DEFAULT_BUFFER_SIZE;
    }
    return getDefaultBufferSize(imageInfo.size.width, imageInfo.size.height);
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
bool SetPicture(std::shared_ptr<ImagePackerContext> context, uint32_t& addImageRet)
{
    if (context->rPicture == nullptr) {
        return false;
    }
    addImageRet = context->rImagePacker->AddPicture(*(context->rPicture));
    return true;
}
#endif

static uint32_t CommonPackToDataExec(std::shared_ptr<ImagePackerContext> context)
{
    if (context->packType == TYPE_IMAGE_SOURCE) {
        if (context->rImageSource == nullptr) {
            IMAGE_LOGE("ImageSource is nullptr");
            return COMMON_ERR_INVALID_PARAMETER;
        }
        return context->rImagePacker->AddImage(*(context->rImageSource));
    } else if (context->packType == TYPE_PIXEL_MAP) {
        if (context->rPixelMap == nullptr) {
            IMAGE_LOGE("PixelMap is nullptr");
            return COMMON_ERR_INVALID_PARAMETER;
        }
        return context->rImagePacker->AddImage(*(context->rPixelMap));
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        uint32_t addImageRet = SUCCESS;
        if (!SetPicture(context, addImageRet)) {
            IMAGE_LOGE("pic null");
            return IMAGE_BAD_PARAMETER;
        }
        return addImageRet;
#endif
    }
    return COMMON_ERR_INVALID_PARAMETER;
}

static std::tuple<int32_t, uint8_t*, int64_t> CommonPackToData(
    std::shared_ptr<ImagePackerContext> context, const PackOption& option, uint64_t bufferSize)
{
    uint32_t innerEncodeErrorCode =
        static_cast<uint32_t>(context->packType == TYPE_PICTURE ? IMAGE_ENCODE_FAILED : ERR_IMAGE_ENCODE_FAILED);
    if (context->rImagePacker == nullptr) {
        IMAGE_LOGE("Pack: real null");
        return std::make_tuple(innerEncodeErrorCode, nullptr, 0);
    }

    bufferSize = bufferSize <= 0 ? getDefaultBufferSize(context) : bufferSize;
    if (bufferSize > INT32_MAX) {
        IMAGE_LOGE("Pack: buf > INT32_MAX");
        return std::make_tuple(innerEncodeErrorCode, nullptr, 0);
    }

    uint8_t* resultBuffer = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * bufferSize));
    if (resultBuffer == nullptr) {
        IMAGE_LOGE("buf alloc err");
        return std::make_tuple(innerEncodeErrorCode, nullptr, 0);
    }

    uint32_t packingRet = context->rImagePacker->StartPacking(resultBuffer, bufferSize, option);
    if (packingRet != SUCCESS) {
        IMAGE_LOGE("Pack: start fail");
        free(resultBuffer);
        packingRet = packingRet == ERR_IMAGE_INVALID_PARAMETER ? COMMON_ERR_INVALID_PARAMETER : innerEncodeErrorCode;
        return std::make_tuple(packingRet, nullptr, 0);
    }

    uint32_t addImageRet = CommonPackToDataExec(context);
    if (addImageRet != SUCCESS) {
        IMAGE_LOGE("Pack: add fail %{public}u", addImageRet);
        free(resultBuffer);
        return std::make_tuple(addImageRet, nullptr, 0);
    }

    int64_t packedSize = 0;
    uint32_t finalPackRet = context->rImagePacker->FinalizePacking(packedSize);
    if (finalPackRet == SUCCESS) {
        return std::make_tuple(SUCCESS_CODE, resultBuffer, packedSize);
    } else if (packedSize == static_cast<int64_t>(bufferSize)) {
        IMAGE_LOGE("buf not enough");
        free(resultBuffer);
        return context->packType == TYPE_PICTURE ? std::make_tuple(IMAGE_ENCODE_FAILED, nullptr, 0)
                                                 : std::make_tuple(ERR_IMAGE_TOO_LARGE, nullptr, 0);
    } else {
        IMAGE_LOGE("Pack: size err");
        free(resultBuffer);
        finalPackRet =
            finalPackRet == ERR_IMAGE_INVALID_PARAMETER ? ERR_IMAGE_INVALID_PARAMETER : innerEncodeErrorCode;
        return std::make_tuple(finalPackRet, nullptr, 0);
    }
}

static uint32_t FinalizePacking(std::shared_ptr<ImagePackerContext> context)
{
    int64_t packedSize = 0;
    uint32_t finalPackRet = context->rImagePacker->FinalizePacking(packedSize);
    if (finalPackRet == SUCCESS && packedSize > 0) {
        return SUCCESS;
    } else {
        IMAGE_LOGE("Pack: size err");
        if (context->packType != TYPE_PICTURE) {
            return finalPackRet;
        }
        return finalPackRet == ERR_IMAGE_INVALID_PARAMETER ? ERR_IMAGE_INVALID_PARAMETER : IMAGE_ENCODE_FAILED;
    }
}

static uint32_t CommonPackToFile(std::shared_ptr<ImagePackerContext> context, int fd, const PackOption& option)
{
    if (fd <= INVALID_FD) {
        IMAGE_LOGE("Pack: invalid fd");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (context->rImagePacker == nullptr) {
        IMAGE_LOGE("Pack: real null");
        return context->packType == TYPE_PICTURE ? ERR_IMAGE_INVALID_PARAMETER : ERR_IMAGE_INIT_ABNORMAL;
    }

    uint32_t packingRet = context->rImagePacker->StartPacking(fd, option);
    if (packingRet != SUCCESS) {
        IMAGE_LOGE("Pack: start fail %{public}u", packingRet);
        return packingRet;
    }

    uint32_t addImageRet = SUCCESS;
    if (context->packType == TYPE_IMAGE_SOURCE) {
        if (context->rImageSource == nullptr) {
            IMAGE_LOGE("ImageSource is nullptr");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
        addImageRet = context->rImagePacker->AddImage(*(context->rImageSource));
    } else if (context->packType == TYPE_PIXEL_MAP) {
        if (context->rPixelMap == nullptr) {
            IMAGE_LOGE("PixelMap is nullptr");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
        addImageRet = context->rImagePacker->AddImage(*(context->rPixelMap));
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    } else if (context->packType == TYPE_PICTURE) {
        if (!SetPicture(context, addImageRet)) {
            IMAGE_LOGE("pic null");
            return ERR_IMAGE_INVALID_PARAMETER;
        }
#endif
    }
    if (addImageRet != SUCCESS) {
        IMAGE_LOGE("Pack: add fail %{public}u", addImageRet);
        return addImageRet;
    }
    return FinalizePacking(context);
}

namespace {
template<typename T>
std::tuple<int32_t, uint8_t*, int64_t> CommonPacking(
    std::shared_ptr<ImagePacker> real, T& source, const PackOption& option, uint64_t bufferSize)
{
    if (real == nullptr) {
        IMAGE_LOGE("Pack: real null");
        return std::make_tuple(ERR_IMAGE_INIT_ABNORMAL, nullptr, 0);
    }

    if (bufferSize <= 0 || bufferSize > INT32_MAX) {
        IMAGE_LOGE("Pack: buf range err");
        return std::make_tuple(ERR_IMAGE_INIT_ABNORMAL, nullptr, 0);
    }

    uint8_t* resultBuffer = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * bufferSize));
    if (resultBuffer == nullptr) {
        IMAGE_LOGE("Pack: malloc fail");
        return std::make_tuple(ERR_IMAGE_INIT_ABNORMAL, nullptr, 0);
    }

    uint32_t packingRet = real->StartPacking(resultBuffer, bufferSize, option);
    if (packingRet != SUCCESS) {
        IMAGE_LOGE("Pack: start fail %{public}u", packingRet);
        free(resultBuffer);
        return std::make_tuple(packingRet, nullptr, 0);
    }

    uint32_t addImageRet = real->AddImage(source);
    if (addImageRet != SUCCESS) {
        IMAGE_LOGE("Pack: add fail %{public}u", addImageRet);
        free(resultBuffer);
        return std::make_tuple(addImageRet, nullptr, 0);
    }

    int64_t packedSize = 0;
    uint32_t finalPackRet = real->FinalizePacking(packedSize);
    if (finalPackRet != SUCCESS) {
        IMAGE_LOGE("Pack: finalize fail %{public}u", finalPackRet);
        free(resultBuffer);
        return std::make_tuple(finalPackRet, nullptr, 0);
    }

    return std::make_tuple(SUCCESS_CODE, resultBuffer, packedSize);
}
} // namespace

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::Packing(
    PixelMap& source, const PackOption& option, uint64_t bufferSize)
{
    return CommonPacking<PixelMap>(real_, source, option, bufferSize);
}

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::Packing(
    ImageSource& source, const PackOption& option, uint64_t bufferSize)
{
    return CommonPacking<ImageSource>(real_, source, option, bufferSize);
}

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::PackToData(
    std::shared_ptr<PixelMap> source, const PackOption& option, uint64_t bufferSize)
{
    auto context = CreateImagePackerContext(real_, TYPE_PIXEL_MAP);
    if (context == nullptr || source == nullptr) {
        return std::make_tuple(ERR_IMAGE_ENCODE_FAILED, nullptr, 0);
    }
    context->rPixelMap = source;
    return CommonPackToData(context, option, bufferSize);
}

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::PackToData(
    std::shared_ptr<ImageSource> source, const PackOption& option, uint64_t bufferSize)
{
    auto context = CreateImagePackerContext(real_, TYPE_IMAGE_SOURCE);
    if (context == nullptr || source == nullptr) {
        return std::make_tuple(ERR_IMAGE_ENCODE_FAILED, nullptr, 0);
    }
    context->rImageSource = source;
    return CommonPackToData(context, option, bufferSize);
}

std::tuple<int32_t, uint8_t*, int64_t> ImagePackerImpl::PackToData(
    std::shared_ptr<Picture> source, const PackOption& option, uint64_t bufferSize)
{
    auto context = CreateImagePackerContext(real_, TYPE_PICTURE);
    if (context == nullptr || source == nullptr) {
        return std::make_tuple(IMAGE_ENCODE_FAILED, nullptr, 0);
    }
    context->rPicture = source;
    return CommonPackToData(context, option, bufferSize);
}

uint32_t ImagePackerImpl::PackToFile(std::shared_ptr<PixelMap> source, int fd, const PackOption& option)
{
    auto context = CreateImagePackerContext(real_, TYPE_PIXEL_MAP);
    if (context == nullptr || source == nullptr) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    context->rPixelMap = source;
    return CommonPackToFile(context, fd, option);
}

uint32_t ImagePackerImpl::PackToFile(std::shared_ptr<ImageSource> source, int fd, const PackOption& option)
{
    auto context = CreateImagePackerContext(real_, TYPE_IMAGE_SOURCE);
    if (context == nullptr || source == nullptr) {
        return ERR_IMAGE_ENCODE_FAILED;
    }
    context->rImageSource = source;
    return CommonPackToFile(context, fd, option);
}

uint32_t ImagePackerImpl::PackToFile(std::shared_ptr<Picture> source, int fd, const PackOption& option)
{
    auto context = CreateImagePackerContext(real_, TYPE_PICTURE);
    if (context == nullptr || source == nullptr) {
        return IMAGE_ENCODE_FAILED;
    }
    context->rPicture = source;
    return CommonPackToFile(context, fd, option);
}
} // namespace Media
} // namespace OHOS
