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

#include "pixelmap_native.h"

#include "common_utils.h"
#include "image_type.h"
#include "pixelmap_native_impl.h"

using namespace OHOS::Media;
#ifdef __cplusplus
extern "C" {
#endif

constexpr int32_t IMAGE_BASE = 62980096;
static constexpr int32_t IMAGE_BASE_19 = 19;
static constexpr int32_t IMAGE_BASE_16 = 16;
static constexpr int32_t IMAGE_BASE_17 = 17;
static constexpr int32_t IMAGE_BASE_26 = 26;
static constexpr int32_t IMAGE_BASE_31 = 31;
static constexpr int32_t IMAGE_BASE_152 = 152;
static constexpr int32_t IMAGE_BASE_27 = 27;
static constexpr int32_t IMAGE_BASE_12 = 12;
static constexpr int32_t IMAGE_BASE_13 = 13;
static constexpr int32_t IMAGE_BASE_6 = 6;
static constexpr int32_t IMAGE_BASE_14 = 14;
static constexpr int32_t IMAGE_BASE_4 = 4;
static constexpr int32_t IMAGE_BASE_9 = 9;
static constexpr int32_t IMAGE_BASE_20 = 20;
static constexpr int32_t IMAGE_BASE_22 = 22;
static constexpr int32_t IMAGE_BASE_23 = 23;

struct OH_Pixelmap_InitializationOptions {
    uint32_t width;
    uint32_t height;
    PIXEL_FORMAT srcPixelFormat = PIXEL_FORMAT::PIXEL_FORMAT_BGRA_8888;
    PIXEL_FORMAT pixelFormat = PIXEL_FORMAT::PIXEL_FORMAT_UNKNOWN;
    uint32_t editable = false;
    PIXELMAP_ALPHA_TYPE alphaType = PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
};

struct OH_Pixelmap_ImageInfo {
    uint32_t width;
    uint32_t height;
    uint32_t rowStride;
    int32_t pixelFormat = PIXEL_FORMAT::PIXEL_FORMAT_UNKNOWN;
    PIXELMAP_ALPHA_TYPE alphaType = PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
    bool isHdr = false;
};

static PIXEL_FORMAT ParsePixelForamt(int32_t val)
{
    if (val <= static_cast<int32_t>(PIXEL_FORMAT::PIXEL_FORMAT_NV12)) {
        return PIXEL_FORMAT(val);
    }

    return PIXEL_FORMAT::PIXEL_FORMAT_UNKNOWN;
}

static PIXELMAP_ALPHA_TYPE ParseAlphaType(int32_t val)
{
    if (val <= static_cast<int32_t>(PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNPREMULTIPLIED)) {
        return PIXELMAP_ALPHA_TYPE(val);
    }

    return PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
}

static Image_ErrorCode ToNewErrorCode(int code)
{
    switch (code) {
        case 0:
            return IMAGE_SUCCESS;
        case IMAGE_BASE + IMAGE_BASE_19:
            return IMAGE_BAD_PARAMETER;
        case IMAGE_BASE + IMAGE_BASE_16:
        case IMAGE_BASE + IMAGE_BASE_17:
        case IMAGE_BASE + IMAGE_BASE_26:
            return IMAGE_UNKNOWN_MIME_TYPE;
        case IMAGE_BASE + IMAGE_BASE_31:
            return IMAGE_TOO_LARGE;
        case IMAGE_BASE + IMAGE_BASE_152:
            return IMAGE_UNSUPPORTED_OPERATION;
        case IMAGE_BASE + IMAGE_BASE_27:
            return IMAGE_UNSUPPORTED_METADATA;
        case IMAGE_BASE + IMAGE_BASE_12:
            return IMAGE_UNSUPPORTED_CONVERSION;
        case IMAGE_BASE + IMAGE_BASE_13:
            return IMAGE_INVALID_REGION;
        case IMAGE_BASE + IMAGE_BASE_6:
            return IMAGE_ALLOC_FAILED;
        case IMAGE_BASE + IMAGE_BASE_14:
            return IMAGE_BAD_SOURCE;
        case IMAGE_BASE + IMAGE_BASE_4:
        case IMAGE_BASE + IMAGE_BASE_9:
        case IMAGE_BASE + IMAGE_BASE_20:
        case IMAGE_BASE + IMAGE_BASE_22:
            return IMAGE_DECODE_FAILED;
        case IMAGE_BASE + IMAGE_BASE_23:
            return IMAGE_ENCODE_FAILED;
        default:
            return IMAGE_UNKNOWN_ERROR;
    }
};

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_Create(OH_Pixelmap_InitializationOptions **ops)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *ops = new OH_Pixelmap_InitializationOptions();
    if (*ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_GetWidth(OH_Pixelmap_InitializationOptions *ops,
    uint32_t *width)
{
    if (ops == nullptr || width == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *width = ops->width;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetWidth(OH_Pixelmap_InitializationOptions *ops,
    uint32_t width)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ops->width = width;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_GetHeight(OH_Pixelmap_InitializationOptions *ops,
    uint32_t *height)
{
    if (ops == nullptr || height == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *height = ops->height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetHeight(OH_Pixelmap_InitializationOptions *ops,
    uint32_t height)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ops->height = height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_GetPixelFormat(OH_Pixelmap_InitializationOptions *ops,
    int32_t *pixelFormat)
{
    if (ops == nullptr || pixelFormat == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *pixelFormat = static_cast<int32_t>(ops->pixelFormat);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetPixelFormat(OH_Pixelmap_InitializationOptions *ops,
    int32_t pixelFormat)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ops->pixelFormat = ParsePixelForamt(pixelFormat);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_GetSrcPixelFormat(OH_Pixelmap_InitializationOptions *ops,
    int32_t *srcpixelFormat)
{
    if (ops == nullptr || srcpixelFormat == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *srcpixelFormat = static_cast<int32_t>(ops->srcPixelFormat);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetSrcPixelFormat(OH_Pixelmap_InitializationOptions *ops,
    int32_t srcpixelFormat)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ops->srcPixelFormat = ParsePixelForamt(srcpixelFormat);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_GetAlphaType(OH_Pixelmap_InitializationOptions *ops,
    int32_t *alphaType)
{
    if (ops == nullptr || alphaType == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *alphaType = static_cast<int32_t>(ops->alphaType);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetAlphaType(OH_Pixelmap_InitializationOptions *ops,
    int32_t alphaType)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ops->alphaType = ParseAlphaType(alphaType);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_Release(OH_Pixelmap_InitializationOptions *ops)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete ops;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_Create(OH_Pixelmap_ImageInfo **info)
{
    if (info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *info = new OH_Pixelmap_ImageInfo();
    if (*info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_GetWidth(OH_Pixelmap_ImageInfo *info, uint32_t *width)
{
    if (info == nullptr || width == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *width =  info->width;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_GetHeight(OH_Pixelmap_ImageInfo *info, uint32_t *height)
{
    if (info == nullptr || height == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *height =  info->height;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_GetRowStride(OH_Pixelmap_ImageInfo *info, uint32_t *rowStride)
{
    if (info == nullptr || rowStride == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *rowStride =  info->rowStride;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_GetPixelFormat(OH_Pixelmap_ImageInfo *info, int32_t *pixelFormat)
{
    if (info == nullptr || pixelFormat == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *pixelFormat =  info->pixelFormat;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_GetAlphaType(OH_Pixelmap_ImageInfo *info, int32_t *alphaType)
{
    if (info == nullptr || alphaType == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *alphaType = static_cast<int32_t>(info->alphaType);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_GetDynamicRange(OH_Pixelmap_ImageInfo *info, bool *isHdr)
{
    if (info == nullptr || isHdr == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *isHdr = info->isHdr;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapImageInfo_Release(OH_Pixelmap_ImageInfo *info)
{
    if (info == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete  info;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreatePixelmap(uint8_t *data, size_t dataLength,
    OH_Pixelmap_InitializationOptions *options, OH_PixelmapNative **pixelmap)
{
    if (data == nullptr || options == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    InitializationOptions info;
    info.editable = true;
    info.alphaType = static_cast<AlphaType>(options->alphaType);
    info.srcPixelFormat = static_cast<PixelFormat>(options->srcPixelFormat);
    info.pixelFormat = static_cast<PixelFormat>(options->pixelFormat);
    info.size.height = static_cast<int32_t>(options->height);
    info.size.width = static_cast<int32_t>(options->width);

    auto pixelmap2 = new OH_PixelmapNative(reinterpret_cast<uint32_t*>(data), static_cast<uint32_t>(dataLength), info);
    if (pixelmap2 == nullptr || pixelmap2->GetInnerPixelmap() == nullptr) {
        if (pixelmap2) {
            delete pixelmap2;
        }
        return IMAGE_BAD_PARAMETER;
    }
    *pixelmap = pixelmap2;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreateEmptyPixelmap(
    OH_Pixelmap_InitializationOptions *options, OH_PixelmapNative **pixelmap)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    InitializationOptions info;
    info.editable = true;
    info.alphaType = static_cast<AlphaType>(options->alphaType);
    info.srcPixelFormat = static_cast<PixelFormat>(options->srcPixelFormat);
    info.pixelFormat = static_cast<PixelFormat>(options->pixelFormat);
    info.size.height = options->height;
    info.size.width = options->width;

    auto pixelmap2 = new OH_PixelmapNative(info);
    if (pixelmap2 == nullptr || pixelmap2->GetInnerPixelmap() == nullptr) {
        if (pixelmap2) {
            delete pixelmap2;
        }
        return IMAGE_BAD_PARAMETER;
    }
    *pixelmap = pixelmap2;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ReadPixels(OH_PixelmapNative *pixelmap, uint8_t *destination, size_t *bufferSize)
{
    if (pixelmap == nullptr || destination == nullptr || bufferSize == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->ReadPixels(*bufferSize, destination));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_WritePixels(OH_PixelmapNative *pixelmap, uint8_t *source, size_t bufferSize)
{
    if (pixelmap == nullptr || source == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->WritePixels(source, bufferSize));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetImageInfo(OH_PixelmapNative *pixelmap, OH_Pixelmap_ImageInfo *imageInfo)
{
    if (pixelmap == nullptr || imageInfo == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    ImageInfo srcInfo;
    pixelmap->GetInnerPixelmap()->GetImageInfo(srcInfo);
    imageInfo->width = static_cast<uint32_t>(srcInfo.size.width);
    imageInfo->height = static_cast<uint32_t>(srcInfo.size.height);
    imageInfo->rowStride = static_cast<uint32_t>(pixelmap->GetInnerPixelmap()->GetRowStride());
    imageInfo->pixelFormat = static_cast<int32_t>(srcInfo.pixelFormat);
    imageInfo->isHdr = pixelmap->GetInnerPixelmap()->IsHdr();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Opacity(OH_PixelmapNative *pixelmap, float rate)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->SetAlpha(rate);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Scale(OH_PixelmapNative *pixelmap, float scaleX, float scaleY)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->scale(scaleX, scaleY);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Translate(OH_PixelmapNative *pixelmap, float x, float y)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->translate(x, y);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Rotate(OH_PixelmapNative *pixelmap, float angle)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->rotate(angle);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Flip(OH_PixelmapNative *pixelmap, bool shouldFilpHorizontally,
    bool shouldFilpVertically)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->flip(shouldFilpHorizontally, shouldFilpVertically);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Crop(OH_PixelmapNative *pixelmap, Image_Region *region)
{
    if (pixelmap == nullptr || region == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    Rect rect;
    rect.left = static_cast<int32_t>(region->x);
    rect.top = static_cast<int32_t>(region->y);
    rect.width = static_cast<int32_t>(region->width);
    rect.height = static_cast<int32_t>(region->height);
    pixelmap->GetInnerPixelmap()->crop(rect);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Release(OH_PixelmapNative *pixelmap)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->~OH_PixelmapNative();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ConvertAlphaFormat(OH_PixelmapNative* srcpixelmap,
    OH_PixelmapNative* dstpixelmap, const bool isPremul)
{
    if (srcpixelmap == nullptr || dstpixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    srcpixelmap->GetInnerPixelmap()->ConvertAlphaFormat(*(dstpixelmap->GetInnerPixelmap()), isPremul);
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif