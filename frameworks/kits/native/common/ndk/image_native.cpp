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
#include "media_errors.h"
#include "native_color_space_manager.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
#include "v1_0/cm_color_space.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
#ifdef IMAGE_COLORSPACE_FLAG
static std::unordered_map<CM_ColorSpaceType, ColorSpaceName> HDI_TO_COLORSPACENAME_MAP = {
    {CM_COLORSPACE_NONE, NONE},
    {CM_BT601_EBU_FULL, BT601_EBU},
    {CM_BT601_SMPTE_C_FULL, BT601_SMPTE_C},
    {CM_BT709_FULL, BT709},
    {CM_BT2020_HLG_FULL, BT2020_HLG},
    {CM_BT2020_PQ_FULL, BT2020_PQ},
    {CM_BT601_EBU_LIMIT, BT601_EBU_LIMIT},
    {CM_BT601_SMPTE_C_LIMIT, BT601_SMPTE_C_LIMIT},
    {CM_BT709_LIMIT, BT709_LIMIT},
    {CM_BT2020_HLG_LIMIT, BT2020_HLG_LIMIT},
    {CM_BT2020_PQ_LIMIT, BT2020_PQ_LIMIT},
    {CM_SRGB_FULL, SRGB},
    {CM_P3_FULL, DISPLAY_P3},
    {CM_P3_HLG_FULL, P3_HLG},
    {CM_P3_PQ_FULL, P3_PQ},
    {CM_ADOBERGB_FULL, ADOBE_RGB},
    {CM_SRGB_LIMIT, SRGB_LIMIT},
    {CM_P3_LIMIT, DISPLAY_P3_LIMIT},
    {CM_P3_HLG_LIMIT, P3_HLG_LIMIT},
    {CM_P3_PQ_LIMIT, P3_PQ_LIMIT},
    {CM_ADOBERGB_LIMIT, ADOBE_RGB_LIMIT},
    {CM_LINEAR_SRGB, LINEAR_SRGB},
    {CM_LINEAR_BT709, LINEAR_BT709},
    {CM_LINEAR_P3, LINEAR_P3},
    {CM_LINEAR_BT2020, LINEAR_BT2020},
    {CM_DISPLAY_SRGB, DISPLAY_SRGB},
    {CM_DISPLAY_P3_SRGB, DISPLAY_P3_SRGB},
    {CM_DISPLAY_P3_HLG, DISPLAY_P3_HLG},
    {CM_DISPLAY_P3_PQ, DISPLAY_P3_PQ},
    {CM_DISPLAY_BT2020_SRGB, DISPLAY_BT2020_SRGB},
    {CM_DISPLAY_BT2020_HLG, BT2020_HLG},
    {CM_DISPLAY_BT2020_PQ, BT2020_PQ},
};
#endif
#endif

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetImageSize(OH_ImageNative* image, Image_Size* size)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == size) {
        IMAGE_LOGE("OH_ImageNative_GetImageSize: Invalid parameter");
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
        IMAGE_LOGE("OH_ImageNative_GetComponentTypes: Invalid parameter");
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
        IMAGE_LOGE("OH_ImageNative_GetByteBuffer: Invalid parameter");
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
        IMAGE_LOGE("OH_ImageNative_GetBufferSize: Invalid parameter");
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
        IMAGE_LOGE("OH_ImageNative_GetRowStride: Invalid parameter");
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
        IMAGE_LOGE("OH_ImageNative_GetPixelStride: Invalid parameter");
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
Image_ErrorCode OH_ImageNative_GetTimestamp(OH_ImageNative *image, int64_t *timestamp)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == timestamp) {
        IMAGE_LOGE("%{public}s Invalid parameter: Null Pointer Error", __func__);
        return IMAGE_BAD_PARAMETER;
    }
    if (OHOS::Media::SUCCESS == image->imgNative->GetTimestamp(*timestamp)) {
        return IMAGE_SUCCESS;
    } else {
        IMAGE_LOGE("image buffer is unusable");
        return IMAGE_BAD_PARAMETER;
    }
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_Release(OH_ImageNative* image)
{
    if (nullptr == image) {
        IMAGE_LOGE("OH_ImageNative_Release: Invalid parameter");
        return IMAGE_BAD_PARAMETER;
    }
    if (nullptr != image->imgNative) {
        image->imgNative->release();
        delete image->imgNative;
    }
    IMAGE_LOGD("OH_ImageNative Release");
    delete image;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetColorSpace(OH_ImageNative *image, int32_t *colorSpaceName)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == colorSpaceName) {
        IMAGE_LOGE("%{public}s Invalid parameter: Null Pointer Error", __func__);
        return IMAGE_BAD_PARAMETER;
    }
    int32_t colorSpaceValue = 0;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM) && defined(IMAGE_COLORSPACE_FLAG)

    if (OHOS::Media::SUCCESS != image->imgNative->GetColorSpace(colorSpaceValue)) {
        IMAGE_LOGE("image buffer is unusable");
        return IMAGE_BAD_PARAMETER;
    }
    auto it = HDI_TO_COLORSPACENAME_MAP.find(static_cast<CM_ColorSpaceType>(colorSpaceValue));
    if (it == HDI_TO_COLORSPACENAME_MAP.end()) {
        IMAGE_LOGE("Unsupported color space type: %{public}d", colorSpaceValue);
        return IMAGE_BAD_PARAMETER;
    }
    *colorSpaceName = it->second;
#else
    *colorSpaceName = colorSpaceValue;
#endif
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetFormat(OH_ImageNative *image, OH_NativeBuffer_Format *format)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == format) {
        IMAGE_LOGE("%{public}s Invalid parameter: Null Pointer Error", __func__);
        return IMAGE_BAD_PARAMETER;
    }
    int32_t imageFormat;
    if (OHOS::Media::SUCCESS != image->imgNative->GetFormat(imageFormat)) {
        IMAGE_LOGE("native image get format failed");
        return IMAGE_BAD_PARAMETER;
    }
    if (imageFormat > static_cast<int32_t>(NATIVEBUFFER_PIXEL_FMT_Y16) &&
        imageFormat < static_cast<int32_t>(NATIVEBUFFER_PIXEL_FMT_VENDER_MASK)) {
        IMAGE_LOGE("image format %{public}d is invalid", imageFormat);
        return IMAGE_BAD_PARAMETER;
    } else {
        *format = static_cast<OH_NativeBuffer_Format>(imageFormat);
        return IMAGE_SUCCESS;
    }
}

MIDK_EXPORT
Image_ErrorCode OH_ImageNative_GetBufferData(OH_ImageNative *image, OH_ImageBufferData *imageBufferData)
{
    if (nullptr == image || nullptr == image->imgNative || nullptr == imageBufferData) {
        IMAGE_LOGE("%{public}s Invalid parameter: Null Pointer Error", __func__);
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::NativeBufferData* bufferData = image->imgNative->GetBufferData();
    if (bufferData == nullptr) {
        IMAGE_LOGE("get native buffer data failed");
        return IMAGE_BAD_PARAMETER;
    }
    imageBufferData->rowStride = bufferData->rowStride.data();
    imageBufferData->pixelStride = bufferData->pixelStride.data();
    imageBufferData->numStride = bufferData->rowStride.size();
    imageBufferData->bufferSize = bufferData->size;
    sptr<SurfaceBuffer> buffer = image->imgNative->GetBuffer();
    if (buffer == nullptr) {
        IMAGE_LOGE("get surface buffer failed, buffer is nullptr");
        return IMAGE_BAD_PARAMETER;
    }
    imageBufferData->nativeBuffer = buffer->SurfaceBufferToNativeBuffer();
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif
