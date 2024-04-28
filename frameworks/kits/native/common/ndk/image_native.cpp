/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <inttypes.h>

#include "common_utils.h"
#include "image_log.h"
#include "image_native.h"
#include "image_kits.h"

#ifdef __cplusplus
extern "C" {
#endif

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetImageSize(OH_ImageNative* image, Image_Size* size)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == size) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p, size=0x%{public}p", image, size);
        return IMAGE_BAD_PARAMETER;
    }
    int32_t width = 0;
    int32_t height = 0;
    Image_ErrorCode err = (Image_ErrorCode)image->imgNative->GetSize(width, height);
    size->width = static_cast<uint32_t>(width);
    size->height = static_cast<uint32_t>(height);
    return err;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetComponentTypes(OH_ImageNative* image, uint32_t** types, size_t* typeSize)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == typeSize) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p, typeSize=0x%{public}p", image, typeSize);
        return IMAGE_BAD_PARAMETER;
    }

    image->imgNative->GetComponent(int32_t(OHOS::Media::ComponentType::JPEG));

    auto& components = image->imgNative->GetComponents();
    *typeSize = components.size();
    if (nullptr == types) {
        return IMAGE_SUCCESS;
    }

    uint32_t* p = *types;
    for (auto itor = components.begin(); itor != components.end(); ++itor) {
        *p = itor->first;
        p++;
    }

    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetByteBuffer(OH_ImageNative* image,
                                             uint32_t componentType, OH_NativeBuffer** nativeBuffer)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == nativeBuffer) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p, nativeBuffer=0x%{public}p", image, nativeBuffer);
        return IMAGE_BAD_PARAMETER;
    }

    auto component = image->imgNative->GetComponent(componentType);
    if (nullptr == component) {
        return IMAGE_BAD_PARAMETER;
    }

    auto buffer = image->imgNative->GetBuffer();
    if (buffer != nullptr) {
        *nativeBuffer = buffer->SurfaceBufferToNativeBuffer();
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetBufferSize(OH_ImageNative* image, uint32_t componentType, size_t* size)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == size) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p, size=0x%{public}p", image, size);
        return IMAGE_BAD_PARAMETER;
    }

    auto component = image->imgNative->GetComponent(componentType);
    if (nullptr == component) {
        return IMAGE_BAD_PARAMETER;
    }

    *size = component->size;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetRowStride(OH_ImageNative* image, uint32_t componentType, int32_t* rowStride)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == rowStride) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p, rowStride=0x%{public}p", image, rowStride);
        return IMAGE_BAD_PARAMETER;
    }

    auto component = image->imgNative->GetComponent(componentType);
    if (nullptr == component) {
        return IMAGE_BAD_PARAMETER;
    }

    *rowStride = component->rowStride;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetPixelStride(OH_ImageNative* image, uint32_t componentType, int32_t* pixelStride)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == pixelStride) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p, pixelStride=0x%{public}p", image, pixelStride);
        return IMAGE_BAD_PARAMETER;
    }

    auto component = image->imgNative->GetComponent(componentType);
    if (nullptr == component) {
        return IMAGE_BAD_PARAMETER;
    }

    *pixelStride = component->pixelStride;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_Release(OH_ImageNative* image)
{
    if (nullptr == image) {
        IMAGE_LOGE("Invalid parameter: image=0x%{public}p", image);
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr != image->imgNative) {
        image->imgNative->release();
        delete image->imgNative;
    }
    IMAGE_LOGI("OH_ImageNative 0x%{public}p has been deleted.", image);
    delete image;
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif
