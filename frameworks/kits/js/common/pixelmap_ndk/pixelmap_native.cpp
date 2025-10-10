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

#include <charconv>
#include "common_utils.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_pixel_map_napi_kits.h"
#include "pixel_map_from_surface.h"
#include "pixel_map_napi.h"
#include "pixelmap_native_impl.h"
#include "image_format_convert.h"
#include "surface_buffer.h"
#include "sync_fence.h"
#include "transaction/rs_interfaces.h"

#include "vpe_utils.h"
#include "refbase.h"
#include "securec.h"
#include "color_utils.h"
#include "media_errors.h"
#include "memory.h"
#include "image_log.h"

#include "native_color_space_manager.h"
#include "ndk_color_space.h"

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
    bool editable = true;
    PIXELMAP_ALPHA_TYPE alphaType = PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
    int32_t srcRowStride = 0;
};

struct OH_Pixelmap_ImageInfo {
    uint32_t width;
    uint32_t height;
    uint32_t rowStride;
    int32_t pixelFormat = PIXEL_FORMAT::PIXEL_FORMAT_UNKNOWN;
    PIXELMAP_ALPHA_TYPE alphaMode = PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
    PIXELMAP_ALPHA_TYPE alphaType = PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
    bool isHdr = false;
    Image_MimeType mimeType;
};

static PIXEL_FORMAT ParsePixelForamt(int32_t val)
{
    if (val <= static_cast<int32_t>(PIXEL_FORMAT::PIXEL_FORMAT_YCRCB_P010)) {
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
        case IMAGE_RESULT_MALLOC_ABNORMAL:
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
        case IMAGE_RESULT_INIT_ABNORMAL:
            return IMAGE_INIT_FAILED;
        case IMAGE_RESULT_DATA_UNSUPPORT:
            return IMAGE_UNSUPPORTED_DATA_FORMAT;
        case IMAGE_RESULT_TOO_LARGE:
            return IMAGE_TOO_LARGE;
        default:
            return IMAGE_UNKNOWN_ERROR;
    }
};

static bool IsMatchType(IMAGE_FORMAT type, PixelFormat format)
{
    if (type == IMAGE_FORMAT::IMAGE_FORMAT_YUV_TYPE) {
        switch (format) {
            case PixelFormat::NV12:
            case PixelFormat::NV21:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else if (type == IMAGE_FORMAT::IMAGE_FORMAT_RGB_TYPE) {
        switch (format) {
            case PixelFormat::RGB_565:
            case PixelFormat::RGBA_8888:
            case PixelFormat::BGRA_8888:
            case PixelFormat::RGB_888:
            case PixelFormat::RGBA_F16:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else {
        return false;
    }
}

static void releaseMimeType(Image_MimeType *mimeType)
{
    if (mimeType->data != nullptr) {
        free(mimeType->data);
        mimeType->data = nullptr;
    }
    mimeType->size = 0;
}

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
Image_ErrorCode OH_PixelmapInitializationOptions_GetEditable(OH_Pixelmap_InitializationOptions *options,
    bool *editable)
{
    if (options == nullptr || editable == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *editable = options->editable;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetEditable(OH_Pixelmap_InitializationOptions *options,
    bool editable)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->editable = editable;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_GetRowStride(OH_Pixelmap_InitializationOptions *options,
    int32_t *rowStride)
{
    if (options == nullptr || rowStride == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *rowStride = options->srcRowStride;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_SetRowStride(OH_Pixelmap_InitializationOptions *options,
    int32_t rowStride)
{
    if (options == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    options->srcRowStride = rowStride;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapInitializationOptions_Release(OH_Pixelmap_InitializationOptions *ops)
{
    if (ops == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete ops;
    ops = nullptr;
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
Image_ErrorCode OH_PixelmapImageInfo_GetAlphaMode(OH_Pixelmap_ImageInfo *info, int32_t *alphaMode)
{
    if (info == nullptr || alphaMode == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *alphaMode = static_cast<int32_t>(info->alphaMode);
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
    releaseMimeType(&info->mimeType);
    delete  info;
    info = nullptr;
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
    info.editable = options->editable;
    info.alphaType = static_cast<AlphaType>(options->alphaType);
    info.srcPixelFormat = static_cast<PixelFormat>(options->srcPixelFormat);
    info.pixelFormat = static_cast<PixelFormat>(options->pixelFormat);
    info.srcRowStride = options->srcRowStride;
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

static bool UsingAllocatorPixelFormatCheck(PixelFormat srcPixelFormat,
    PixelFormat dstPixelFormat, bool isSupportYUV10Bit = false)
{
    if (dstPixelFormat >= PixelFormat::EXTERNAL_MAX ||
        dstPixelFormat <= PixelFormat::UNKNOWN ||
        srcPixelFormat >= PixelFormat::EXTERNAL_MAX ||
        srcPixelFormat <= PixelFormat::UNKNOWN) {
        IMAGE_LOGE("%{public}s PixelFormat type is unspport %{public}d,%{public}d.", __func__,
            dstPixelFormat, srcPixelFormat);
        return false;
    }
    if (!isSupportYUV10Bit &&
        (srcPixelFormat == PixelFormat::YCBCR_P010 ||
        srcPixelFormat == PixelFormat::YCRCB_P010 ||
        dstPixelFormat == PixelFormat::YCBCR_P010 ||
        dstPixelFormat == PixelFormat::YCRCB_P010)) {
        IMAGE_LOGE("%{public}s PixelFormat type is unspport %{public}d,%{public}d.", __func__,
            dstPixelFormat, srcPixelFormat);
        return false;
    }
    return true;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreatePixelmapUsingAllocator(uint8_t *data, size_t dataLength,
    OH_Pixelmap_InitializationOptions *options, IMAGE_ALLOCATOR_MODE allocator, OH_PixelmapNative **pixelmap)
{
    if (data == nullptr || options == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    InitializationOptions info;
    info.editable = options->editable;
    info.alphaType = static_cast<AlphaType>(options->alphaType);
    info.srcPixelFormat = static_cast<PixelFormat>(options->srcPixelFormat);
    info.pixelFormat = static_cast<PixelFormat>(options->pixelFormat);
    info.srcRowStride = options->srcRowStride;
    info.size.height = static_cast<int32_t>(options->height);
    info.size.width = static_cast<int32_t>(options->width);
    if (!UsingAllocatorPixelFormatCheck(info.srcPixelFormat, info.pixelFormat)) {
        return IMAGE_UNSUPPORTED_OPERATION;
    }
    if (allocator < IMAGE_ALLOCATOR_MODE_AUTO ||
        allocator > IMAGE_ALLOCATOR_MODE_SHARED_MEMORY) {
        IMAGE_LOGE("%{public}s allocator type is unspport:%{public}d.", __func__, allocator);
        return IMAGE_ALLOCATOR_MODE_UNSUPPROTED;
    }
    if (!ImageUtils::SetInitializationOptionAllocatorType(info, static_cast<int32_t>(allocator))) {
        IMAGE_LOGE("%{public}s allocator type failed %{public}d,%{public}d.", __func__,
            allocator, info.allocatorType);
        return IMAGE_UNSUPPORTED_OPERATION;
    }
    IMAGE_LOGD("%{public}s allocator type is %{public}d,%{public}d.", __func__,
        allocator, info.allocatorType);
    auto pixelmap2 =
        new OH_PixelmapNative(reinterpret_cast<uint32_t*>(data), static_cast<uint32_t>(dataLength), info, allocator);
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
    info.editable = options->editable;
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
Image_ErrorCode OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator(
    OH_Pixelmap_InitializationOptions *options, IMAGE_ALLOCATOR_MODE allocator, OH_PixelmapNative **pixelmap)
{
    if (options == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    InitializationOptions info;
    info.editable = options->editable;
    info.alphaType = static_cast<AlphaType>(options->alphaType);
    info.srcPixelFormat = static_cast<PixelFormat>(options->srcPixelFormat);
    info.pixelFormat = static_cast<PixelFormat>(options->pixelFormat);
    info.size.height = options->height;
    info.size.width = options->width;
    if (!UsingAllocatorPixelFormatCheck(info.srcPixelFormat, info.pixelFormat, true)) {
        return IMAGE_UNSUPPORTED_OPERATION;
    }
    if (allocator < IMAGE_ALLOCATOR_MODE_AUTO ||
        allocator > IMAGE_ALLOCATOR_MODE_SHARED_MEMORY) {
        IMAGE_LOGE("%{public}s allocator type is unspport:%{public}d.", __func__, allocator);
        return IMAGE_ALLOCATOR_MODE_UNSUPPROTED;
    }
    if (!ImageUtils::SetInitializationOptionAllocatorType(info, static_cast<int32_t>(allocator))) {
        IMAGE_LOGE("%{public}s allocator type failed %{public}d,%{public}d.", __func__,
            allocator, info.allocatorType);
        return IMAGE_UNSUPPORTED_OPERATION;
    }
    IMAGE_LOGD("%{public}s allocator type is %{public}d,%{public}d.", __func__,
        allocator, info.allocatorType);
    auto pixelmap2 = new OH_PixelmapNative(info, allocator);
    if (pixelmap2 == nullptr || pixelmap2->GetInnerPixelmap() == nullptr) {
        if (pixelmap2) {
            delete pixelmap2;
        }
        return IMAGE_BAD_PARAMETER;
    }
    *pixelmap = pixelmap2;
    return IMAGE_SUCCESS;
}

static bool GetSurfaceSize(uint64_t surfaceId, OHOS::Media::Rect &region)
{
    if (region.width <= 0 || region.height <= 0) {
        sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
        if (surface == nullptr) {
            IMAGE_LOGE("GetSurfaceSize: GetSurface failed");
            return false;
        }
        sptr<SyncFence> fence = SyncFence::InvalidFence();
        // 4 * 4 idetity matrix
        float matrix[16] = {
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };
        sptr<SurfaceBuffer> surfaceBuffer = nullptr;
        GSError ret = surface->GetLastFlushedBuffer(surfaceBuffer, fence, matrix);
        if (ret != GSERROR_OK || surfaceBuffer == nullptr) {
            IMAGE_LOGE("GetSurfaceSize: GetLastFlushedBuffer failed, ret = %{public}d", ret);
            return false;
        }
        region.width = surfaceBuffer->GetWidth();
        region.height = surfaceBuffer->GetHeight();
    }
    return true;
}

static Image_ErrorCode CreatePixelMapFromSurface(const std::string &surfaceId, OHOS::Media::Rect &region,
    OH_PixelmapNative **pixelmap)
{
    uint64_t surfaceIdInt = 0;
    auto res = std::from_chars(surfaceId.data(), surfaceId.data() + surfaceId.size(), surfaceIdInt);
    if (res.ec != std::errc()) {
        return IMAGE_BAD_PARAMETER;
    }
    if (!GetSurfaceSize(surfaceIdInt, region)) {
        return IMAGE_BAD_PARAMETER;
    }

    auto &rsClient = Rosen::RSInterfaces::GetInstance();
    OHOS::Rect r = {
        .x = region.left,
        .y = region.top,
        .w = region.width,
        .h = region.height,
    };
    std::shared_ptr<PixelMap> pixelMapFromSurface = rsClient.CreatePixelMapFromSurfaceId(surfaceIdInt, r);
#ifndef EXT_PIXEL
    if (pixelMapFromSurface == nullptr) {
        pixelMapFromSurface = CreatePixelMapFromSurfaceId(surfaceIdInt, region);
    }
#endif
    if (pixelMapFromSurface == nullptr) {
        return IMAGE_CREATE_PIXELMAP_FAILED;
    }
    *pixelmap = new(std::nothrow) OH_PixelmapNative(std::move(pixelMapFromSurface));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreatePixelmapFromSurface(const char *surfaceId, size_t length,
    OH_PixelmapNative **pixelmap)
{
    if (pixelmap == nullptr || surfaceId == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::Rect region;
    return CreatePixelMapFromSurface(std::string(surfaceId, length), region, pixelmap);
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreatePixelmapFromNativeBuffer(OH_NativeBuffer *nativeBuffer,
    OH_PixelmapNative **pixelmap)
{
    if (nativeBuffer == nullptr || pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    OHOS::SurfaceBuffer* surfaceBuffer = OHOS::SurfaceBuffer::NativeBufferToSurfaceBuffer(nativeBuffer);
    sptr<OHOS::SurfaceBuffer> source(surfaceBuffer);
    std::unique_ptr<PixelMap> pixelMapFromSurface = Picture::SurfaceBuffer2PixelMap(source);
    if (pixelMapFromSurface == nullptr) {
        return IMAGE_CREATE_PIXELMAP_FAILED;
    }
    *pixelmap = new(std::nothrow) OH_PixelmapNative(std::move(pixelMapFromSurface));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ConvertPixelmapNativeToNapi(napi_env env, OH_PixelmapNative *pixelmapNative,
    napi_value *pixelmapNapi)
{
    if (pixelmapNative == nullptr || pixelmapNative->GetInnerPixelmap() == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = pixelmapNative->GetInnerPixelmap();
    *pixelmapNapi = PixelMapNapi::CreatePixelMap(env, pixelMap);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, *pixelmapNapi, &valueType);
    return (valueType == napi_undefined) ? IMAGE_BAD_PARAMETER : IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ConvertPixelmapNativeFromNapi(napi_env env, napi_value pixelmapNapi,
    OH_PixelmapNative **pixelmapNative)
{
    PixelMapNapi* napi = PixelMapNapi_Unwrap(env, pixelmapNapi);
    if (napi == nullptr || napi->GetPixelNapiInner() == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    auto pixelmap = new OH_PixelmapNative(napi->GetPixelNapiInner());
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr) {
        if (pixelmap) {
            delete pixelmap;
        }
        return IMAGE_ALLOC_FAILED;
    }
    *pixelmapNative = pixelmap;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ReadPixels(OH_PixelmapNative *pixelmap, uint8_t *destination, size_t *bufferSize)
{
    if (pixelmap == nullptr || destination == nullptr || bufferSize == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->ReadPixels(*bufferSize, destination));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_WritePixels(OH_PixelmapNative *pixelmap, uint8_t *source, size_t bufferSize)
{
    if (pixelmap == nullptr || source == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->WritePixels(source, bufferSize));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ReadPixelsFromArea(OH_PixelmapNative *pixelmap, Image_PositionArea *area)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap() || area == nullptr || area->pixels == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    OHOS::Media::Rect region = {
        .left = static_cast<int32_t>(area->region.x),
        .top = static_cast<int32_t>(area->region.y),
        .width = static_cast<int32_t>(area->region.width),
        .height = static_cast<int32_t>(area->region.height)
    };
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->ReadPixels(
        area->pixelsSize, area->offset, area->stride, region, area->pixels));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_WritePixelsToArea(OH_PixelmapNative *pixelmap, Image_PositionArea *area)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap() || area == nullptr || area->pixels == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    OHOS::Media::Rect region = {
        .left = static_cast<int32_t>(area->region.x),
        .top = static_cast<int32_t>(area->region.y),
        .width = static_cast<int32_t>(area->region.width),
        .height = static_cast<int32_t>(area->region.height)
    };
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->WritePixels(
        area->pixels, area->pixelsSize, area->offset, area->stride, region));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetArgbPixels(OH_PixelmapNative *pixelmap, uint8_t *destination, size_t *bufferSize)
{
    if (pixelmap == nullptr || destination == nullptr || bufferSize == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    return ToNewErrorCode(pixelmap->GetInnerPixelmap()->ReadARGBPixels(*bufferSize, destination));
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ToSdr(OH_PixelmapNative *pixelmap)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    if (pixelmap->GetInnerPixelmap()->ToSdr() != IMAGE_SUCCESS) {
        return IMAGE_UNSUPPORTED_OPERATION;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetImageInfo(OH_PixelmapNative *pixelmap, OH_Pixelmap_ImageInfo *imageInfo)
{
    if (pixelmap == nullptr || imageInfo == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    ImageInfo srcInfo;
    pixelmap->GetInnerPixelmap()->GetImageInfo(srcInfo);
    imageInfo->alphaMode = (PIXELMAP_ALPHA_TYPE)(pixelmap->GetInnerPixelmap()->GetAlphaType());
    imageInfo->width = static_cast<uint32_t>(srcInfo.size.width);
    imageInfo->height = static_cast<uint32_t>(srcInfo.size.height);
    imageInfo->rowStride = static_cast<uint32_t>(pixelmap->GetInnerPixelmap()->GetRowStride());
    imageInfo->pixelFormat = static_cast<int32_t>(srcInfo.pixelFormat);
    imageInfo->isHdr = pixelmap->GetInnerPixelmap()->IsHdr();

    if (!srcInfo.encodedFormat.empty() && imageInfo->mimeType.data == nullptr) {
        imageInfo->mimeType.size = srcInfo.encodedFormat.size();
        imageInfo->mimeType.data = static_cast<char *>(malloc(imageInfo->mimeType.size));
        if (memcpy_s(imageInfo->mimeType.data, imageInfo->mimeType.size, srcInfo.encodedFormat.c_str(),
            srcInfo.encodedFormat.size()) != 0) {
            releaseMimeType(&imageInfo->mimeType);
        }
    }

    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetPixelMapImageInfo(OH_PixelmapNative *pixelmap, OH_Pixelmap_ImageInfo *imageInfo)
{
    if (pixelmap == nullptr || imageInfo == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    ImageInfo srcInfo;
    pixelmap->GetInnerPixelmap()->GetImageInfo(srcInfo);
    imageInfo->width = static_cast<uint32_t>(srcInfo.size.width);
    imageInfo->height = static_cast<uint32_t>(srcInfo.size.height);
    imageInfo->rowStride = static_cast<uint32_t>(pixelmap->GetInnerPixelmap()->GetRowStride());
    imageInfo->pixelFormat = static_cast<int32_t>(srcInfo.pixelFormat);
    imageInfo->isHdr = pixelmap->GetInnerPixelmap()->IsHdr();
    imageInfo->alphaType = static_cast<PIXELMAP_ALPHA_TYPE>(srcInfo.alphaType);

    if (!srcInfo.encodedFormat.empty() && imageInfo->mimeType.data == nullptr) {
        imageInfo->mimeType.size = srcInfo.encodedFormat.size();
        imageInfo->mimeType.data = static_cast<char *>(malloc(imageInfo->mimeType.size));
        if (memcpy_s(imageInfo->mimeType.data, imageInfo->mimeType.size, srcInfo.encodedFormat.c_str(),
            srcInfo.encodedFormat.size()) != 0) {
            releaseMimeType(&imageInfo->mimeType);
        }
    }

    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Opacity(OH_PixelmapNative *pixelmap, float rate)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->SetAlpha(rate);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Scale(OH_PixelmapNative *pixelmap, float scaleX, float scaleY)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->scale(scaleX, scaleY);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ScaleWithAntiAliasing(OH_PixelmapNative *pixelmap, float scaleX, float scaleY,
    OH_PixelmapNative_AntiAliasingLevel level)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->scale(scaleX, scaleY, static_cast<AntiAliasingOption>(level));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreateAlphaPixelmap(OH_PixelmapNative *srcPixelmap, OH_PixelmapNative **dstPixelmap)
{
    if (srcPixelmap == nullptr || !srcPixelmap->GetInnerPixelmap() || dstPixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    InitializationOptions opts;
    opts.pixelFormat = PixelFormat::ALPHA_8;
    std::unique_ptr<PixelMap> alphaPixelmap = PixelMap::Create(*(srcPixelmap->GetInnerPixelmap()), opts);
    if (alphaPixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *dstPixelmap = new(std::nothrow) OH_PixelmapNative(std::move(alphaPixelmap));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Clone(OH_PixelmapNative *srcPixelmap, OH_PixelmapNative **dstPixelmap)
{
    if (srcPixelmap == nullptr || !srcPixelmap->GetInnerPixelmap() || dstPixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    int32_t errorCode = 0;
    std::unique_ptr<PixelMap> clonedPixelmap = srcPixelmap->GetInnerPixelmap()->Clone(errorCode);
    if (clonedPixelmap == nullptr) {
        return ToNewErrorCode(errorCode);
    }
    *dstPixelmap = new(std::nothrow) OH_PixelmapNative(std::move(clonedPixelmap));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreateCroppedAndScaledPixelMap(OH_PixelmapNative *srcPixelmap, Image_Region *region,
    Image_Scale *scale, OH_PixelmapNative_AntiAliasingLevel level, OH_PixelmapNative **dstPixelmap)
{
    if (srcPixelmap == nullptr || !srcPixelmap->GetInnerPixelmap() || region == nullptr || scale == nullptr ||
        dstPixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    int32_t errorCode = 0;
    std::unique_ptr<PixelMap> clonedPixelmap = srcPixelmap->GetInnerPixelmap()->Clone(errorCode);
    if (clonedPixelmap == nullptr) {
        return ToNewErrorCode(errorCode);
    }

    OHOS::Media::Rect rect = {
        .left = static_cast<int32_t>(region->x),
        .top = static_cast<int32_t>(region->y),
        .width = static_cast<int32_t>(region->width),
        .height = static_cast<int32_t>(region->height)
    };
    clonedPixelmap->crop(rect);
    clonedPixelmap->scale(scale->x, scale->y, static_cast<AntiAliasingOption>(level));
    *dstPixelmap = new(std::nothrow) OH_PixelmapNative(std::move(clonedPixelmap));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreateScaledPixelMap(OH_PixelmapNative *srcPixelmap, OH_PixelmapNative **dstPixelmap,
    float scaleX, float scaleY)
{
    if (srcPixelmap == nullptr || !srcPixelmap->GetInnerPixelmap() || dstPixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    InitializationOptions opts;
    std::unique_ptr<PixelMap> clonePixelmap = PixelMap::Create(*(srcPixelmap->GetInnerPixelmap()), opts);
    if (clonePixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    clonePixelmap->scale(scaleX, scaleY);
    *dstPixelmap = new(std::nothrow) OH_PixelmapNative(std::move(clonePixelmap));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing(OH_PixelmapNative *srcPixelmap,
    OH_PixelmapNative **dstPixelmap, float scaleX, float scaleY, OH_PixelmapNative_AntiAliasingLevel level)
{
    if (srcPixelmap == nullptr || !srcPixelmap->GetInnerPixelmap() || dstPixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    InitializationOptions opts;
    std::unique_ptr<PixelMap> clonePixelmap = PixelMap::Create(*(srcPixelmap->GetInnerPixelmap()), opts);
    if (clonePixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    clonePixelmap->scale(scaleX, scaleY, static_cast<AntiAliasingOption>(level));
    *dstPixelmap = new(std::nothrow) OH_PixelmapNative(std::move(clonePixelmap));
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Translate(OH_PixelmapNative *pixelmap, float x, float y)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->translate(x, y);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Rotate(OH_PixelmapNative *pixelmap, float angle)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->rotate(angle);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Flip(OH_PixelmapNative *pixelmap, bool shouldFilpHorizontally,
    bool shouldFilpVertically)
{
    if (pixelmap == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->flip(shouldFilpHorizontally, shouldFilpVertically);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Crop(OH_PixelmapNative *pixelmap, Image_Region *region)
{
    if (pixelmap == nullptr || region == nullptr || !pixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    OHOS::Media::Rect rect;
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
    if (pixelmap == nullptr || (pixelmap->GetInnerPixelmap() != nullptr &&
        !pixelmap->GetInnerPixelmap()->IsModifiable())) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->~OH_PixelmapNative();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_Destroy(OH_PixelmapNative **pixelmap)
{
    if (pixelmap == nullptr || *pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    delete *pixelmap;
    *pixelmap = nullptr;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_ConvertAlphaFormat(OH_PixelmapNative* srcpixelmap,
    OH_PixelmapNative* dstpixelmap, const bool isPremul)
{
    if (srcpixelmap == nullptr || dstpixelmap == nullptr ||
        !srcpixelmap->GetInnerPixelmap() || !dstpixelmap->GetInnerPixelmap()) {
        return IMAGE_BAD_PARAMETER;
    }
    srcpixelmap->GetInnerPixelmap()->ConvertAlphaFormat(*(dstpixelmap->GetInnerPixelmap()), isPremul);
    return IMAGE_SUCCESS;
}

static uint32_t ImageConvert_YuvToRgb(OH_PixelmapNative *srcPixelMap, OH_PixelmapNative **destPixelMap,
                                      int32_t destPixelFormat)
{
    if (srcPixelMap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    PixelFormat srcPixelFormat = srcPixelMap->GetInnerPixelmap()->GetPixelFormat();
    PixelFormat destFormat = static_cast<PixelFormat>(destPixelFormat);
    if (!IsMatchType(IMAGE_FORMAT::IMAGE_FORMAT_YUV_TYPE, srcPixelFormat) ||
        !IsMatchType(IMAGE_FORMAT::IMAGE_FORMAT_RGB_TYPE, destFormat)) {
        return IMAGE_BAD_PARAMETER;
    }

    std::shared_ptr<OHOS::Media::PixelMap> innerPixelMap = srcPixelMap->GetInnerPixelmap();
    std::shared_ptr<PixelMap> pixelMap = std::static_pointer_cast<PixelMap>(innerPixelMap);
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(pixelMap, destFormat);
    *destPixelMap = new OH_PixelmapNative(pixelMap);

    return ret;
}

static uint32_t ImageConvert_RgbToYuv(OH_PixelmapNative *srcPixelMap, OH_PixelmapNative **destPixelMap,
                                      int32_t destPixelFormat)
{
    if (srcPixelMap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PixelFormat srcPixelFormat = srcPixelMap->GetInnerPixelmap()->GetPixelFormat();
    PixelFormat destFormat = static_cast<PixelFormat>(destPixelFormat);
    if (!IsMatchType(IMAGE_FORMAT::IMAGE_FORMAT_RGB_TYPE, srcPixelFormat) ||
        !IsMatchType(IMAGE_FORMAT::IMAGE_FORMAT_YUV_TYPE, destFormat)) {
        return IMAGE_BAD_PARAMETER;
    }

    std::shared_ptr<OHOS::Media::PixelMap> innerPixelMap = srcPixelMap->GetInnerPixelmap();
    std::shared_ptr<PixelMap> pixelMap = std::static_pointer_cast<PixelMap>(innerPixelMap);
    uint32_t ret = ImageFormatConvert::ConvertImageFormat(pixelMap, destFormat);
    *destPixelMap = new OH_PixelmapNative(pixelMap);
    return ret;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelMapNative_ConvertPixelFormat(OH_PixelmapNative *srcPixelMap, OH_PixelmapNative **destPixelMap,
                                                     int32_t destPixelFormat)
{
    if (srcPixelMap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    PixelFormat srcPixelFormat = srcPixelMap->GetInnerPixelmap()->GetPixelFormat();
    const uint32_t SUCCESS = 0;
    if (IsMatchType(IMAGE_FORMAT::IMAGE_FORMAT_YUV_TYPE, srcPixelFormat)) {
        if (ImageConvert_YuvToRgb(srcPixelMap, destPixelMap, destPixelFormat) != SUCCESS) {
            return IMAGE_BAD_PARAMETER;
        }
    } else if (IsMatchType(IMAGE_FORMAT::IMAGE_FORMAT_RGB_TYPE, srcPixelFormat)) {
        if (ImageConvert_RgbToYuv(srcPixelMap, destPixelMap, destPixelFormat) != SUCCESS) {
            return IMAGE_BAD_PARAMETER;
        }
    } else {
        return IMAGE_BAD_PARAMETER;
    }
    return IMAGE_SUCCESS;
}
constexpr uint8_t INDEX_ZERO = 0;
constexpr uint8_t INDEX_ONE = 1;
constexpr uint8_t INDEX_TWO = 2;
static std::map<OH_Pixelmap_HdrMetadataType, const CM_HDR_Metadata_Type> NdkMetadataTypeMap = {
    {HDR_METADATA_TYPE_NONE, CM_METADATA_NONE},
    {HDR_METADATA_TYPE_BASE, CM_IMAGE_HDR_VIVID_DUAL},
    {HDR_METADATA_TYPE_GAINMAP, CM_METADATA_NONE},
    {HDR_METADATA_TYPE_ALTERNATE, CM_IMAGE_HDR_VIVID_SINGLE},
};

static std::map<CM_HDR_Metadata_Type, OH_Pixelmap_HdrMetadataType> MetadataNdkTypeMap = {
    {CM_METADATA_NONE, HDR_METADATA_TYPE_NONE},
    {CM_IMAGE_HDR_VIVID_DUAL, HDR_METADATA_TYPE_BASE},
    {CM_METADATA_NONE, HDR_METADATA_TYPE_GAINMAP},
    {CM_IMAGE_HDR_VIVID_SINGLE, HDR_METADATA_TYPE_ALTERNATE},
};

static bool ConvertStaticMetadata(const OH_Pixelmap_HdrStaticMetadata &metadata,
    std::vector<uint8_t> &staticMetadataVec)
{
#if defined(_WIN32) || defined(_APPLE) || defined(IOS_PLATFORM) || defined(ANDROID_PLATFORM)
    return {};
#else
    HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata staticMetadata{};
    staticMetadata.smpte2086.displayPrimaryRed.x = metadata.displayPrimariesX[INDEX_ZERO];
    staticMetadata.smpte2086.displayPrimaryRed.y = metadata.displayPrimariesY[INDEX_ZERO];
    staticMetadata.smpte2086.displayPrimaryGreen.x = metadata.displayPrimariesX[INDEX_ONE];
    staticMetadata.smpte2086.displayPrimaryGreen.y = metadata.displayPrimariesY[INDEX_ONE];
    staticMetadata.smpte2086.displayPrimaryBlue.x = metadata.displayPrimariesX[INDEX_TWO];
    staticMetadata.smpte2086.displayPrimaryBlue.y = metadata.displayPrimariesY[INDEX_TWO];
    staticMetadata.smpte2086.whitePoint.x = metadata.whitePointX;
    staticMetadata.smpte2086.whitePoint.y = metadata.whitePointY;
    staticMetadata.smpte2086.maxLuminance = metadata.maxLuminance;
    staticMetadata.smpte2086.minLuminance = metadata.minLuminance;
    staticMetadata.cta861.maxContentLightLevel = metadata.maxContentLightLevel;
    staticMetadata.cta861.maxFrameAverageLightLevel = metadata.maxFrameAverageLightLevel;
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    if (memcpy_s(staticMetadataVec.data(), vecSize, &staticMetadata, vecSize) != EOK) {
        return false;
    }
    return true;
#endif
}

static void ConvertGainmapMetadata(OH_Pixelmap_HdrGainmapMetadata &metadata, HDRVividExtendMetadata &extendMetadata)
{
    extendMetadata.metaISO.writeVersion = metadata.writerVersion;
    extendMetadata.metaISO.miniVersion = metadata.minVersion;
    extendMetadata.metaISO.gainmapChannelNum = metadata.gainmapChannelNum;
    extendMetadata.metaISO.useBaseColorFlag = metadata.useBaseColorFlag;
    extendMetadata.metaISO.baseHeadroom = metadata.baseHdrHeadroom;
    extendMetadata.metaISO.alternateHeadroom = metadata.alternateHdrHeadroom;

    extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO] = metadata.gainmapMax[INDEX_ZERO];
    extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ONE] = metadata.gainmapMax[INDEX_ONE];
    extendMetadata.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_TWO] = metadata.gainmapMax[INDEX_TWO];

    extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO] = metadata.gainmapMin[INDEX_ZERO];
    extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ONE] = metadata.gainmapMin[INDEX_ONE];
    extendMetadata.metaISO.enhanceClippedThreholdMinGainmap[INDEX_TWO] = metadata.gainmapMin[INDEX_TWO];

    extendMetadata.metaISO.enhanceMappingGamma[INDEX_ZERO] = metadata.gamma[INDEX_ZERO];
    extendMetadata.metaISO.enhanceMappingGamma[INDEX_ONE] = metadata.gamma[INDEX_ONE];
    extendMetadata.metaISO.enhanceMappingGamma[INDEX_TWO] = metadata.gamma[INDEX_TWO];

    extendMetadata.metaISO.enhanceMappingBaselineOffset[INDEX_ZERO] = metadata.baselineOffset[INDEX_ZERO];
    extendMetadata.metaISO.enhanceMappingBaselineOffset[INDEX_ONE] = metadata.baselineOffset[INDEX_ONE];
    extendMetadata.metaISO.enhanceMappingBaselineOffset[INDEX_TWO] = metadata.baselineOffset[INDEX_TWO];

    extendMetadata.metaISO.enhanceMappingAlternateOffset[INDEX_ZERO] = metadata.alternateOffset[INDEX_ZERO];
    extendMetadata.metaISO.enhanceMappingAlternateOffset[INDEX_ONE] = metadata.alternateOffset[INDEX_ONE];
    extendMetadata.metaISO.enhanceMappingAlternateOffset[INDEX_TWO] = metadata.alternateOffset[INDEX_TWO];
}

static bool BuildGainmapMetadata(OHOS::Media::PixelMap &pixelmap, OH_Pixelmap_HdrGainmapMetadata &metadata,
    std::vector<uint8_t> &extendMetadataVec)
{
    HDRVividExtendMetadata extendMetadata;
    #ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace colorSpace = pixelmap.InnerGetGrColorSpace();
    uint16_t SS = ColorUtils::GetPrimaries(colorSpace.GetColorSpaceName());
    #else
    uint16_t SS = 0;
    #endif
    extendMetadata.baseColorMeta.baseColorPrimary = SS;
    extendMetadata.gainmapColorMeta.combineColorPrimary = metadata.useBaseColorFlag ? SS: (uint8_t)CM_BT2020_HLG_FULL;
    extendMetadata.gainmapColorMeta.enhanceDataColorModel = metadata.useBaseColorFlag ? SS: (uint8_t)CM_BT2020_HLG_FULL;
    extendMetadata.gainmapColorMeta.alternateColorPrimary = (uint8_t)CM_BT2020_HLG_FULL;
    ConvertGainmapMetadata(metadata, extendMetadata);
    uint32_t vecSize = sizeof(HDRVividExtendMetadata);
    if (memcpy_s(extendMetadataVec.data(), vecSize, &extendMetadata, vecSize) != EOK) {
        return false;
    }
    return true;
}

static bool SetHdrMetadata(OHOS::Media::PixelMap &pixelmap, OHOS::sptr<OHOS::SurfaceBuffer> &buffer,
    OH_Pixelmap_HdrMetadataKey key, OH_Pixelmap_HdrMetadataValue &value)
{
    switch (key) {
        case OH_Pixelmap_HdrMetadataKey::HDR_METADATA_TYPE:
            if (NdkMetadataTypeMap.find(value.type) != NdkMetadataTypeMap.end()) {
                VpeUtils::SetSbMetadataType(buffer, NdkMetadataTypeMap[value.type]);
            }
            break;
        case OH_Pixelmap_HdrMetadataKey::HDR_STATIC_METADATA:
            {
                OH_Pixelmap_HdrStaticMetadata &staticMetadata = value.staticMetadata;
                uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
                std::vector<uint8_t> metadataVec(vecSize);
                if (!ConvertStaticMetadata(staticMetadata, metadataVec)) {
                    return false;
                }
                if (!VpeUtils::SetSbStaticMetadata(buffer, metadataVec)) {
                    return false;
                }
            }
            break;
        case OH_Pixelmap_HdrMetadataKey::HDR_DYNAMIC_METADATA:
            {
                std::vector<uint8_t> metadataVec(value.dynamicMetadata.length);
                if (memcpy_s(metadataVec.data(), value.dynamicMetadata.length, value.dynamicMetadata.data,
                    value.dynamicMetadata.length) != EOK) {
                    return false;
                }
                if (!VpeUtils::SetSbDynamicMetadata(buffer, metadataVec)) {
                    return false;
                }
            }
            break;
        case OH_Pixelmap_HdrMetadataKey::HDR_GAINMAP_METADATA:
            {
                std::vector<uint8_t> extendMetadataVec(sizeof(HDRVividExtendMetadata));
                if (!BuildGainmapMetadata(pixelmap, value.gainmapMetadata, extendMetadataVec)) {
                    return false;
                }
                if (!VpeUtils::SetSbDynamicMetadata(buffer, extendMetadataVec)) {
                    return false;
                }
            }
            break;
        default:
            break;
    }

    return true;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_SetMetadata(OH_PixelmapNative *pixelmap, OH_Pixelmap_HdrMetadataKey key,
    OH_Pixelmap_HdrMetadataValue *value)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || value == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    if (pixelmap->GetInnerPixelmap()->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return IMAGE_DMA_NOT_EXIST;
    }

    OHOS::sptr<OHOS::SurfaceBuffer> surfaceBuffer(
        reinterpret_cast<OHOS::SurfaceBuffer*>(pixelmap->GetInnerPixelmap()->GetFd()));
    if (!SetHdrMetadata(*(pixelmap->GetInnerPixelmap().get()), surfaceBuffer, key, *value)) {
        return IMAGE_COPY_FAILED;
    }

    return IMAGE_SUCCESS;
}

static void ConvertToOHGainmapMetadata(HDRVividExtendMetadata &src, OH_Pixelmap_HdrGainmapMetadata &dst)
{
    dst.writerVersion = src.metaISO.writeVersion;
    dst.minVersion = src.metaISO.miniVersion;
    dst.gainmapChannelNum = src.metaISO.gainmapChannelNum;
    dst.useBaseColorFlag = src.metaISO.useBaseColorFlag;
    dst.baseHdrHeadroom = src.metaISO.baseHeadroom;
    dst.alternateHdrHeadroom = src.metaISO.alternateHeadroom;

    dst.gainmapMax[INDEX_ZERO] = src.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ZERO];
    dst.gainmapMax[INDEX_ONE] = src.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_ONE];
    dst.gainmapMax[INDEX_TWO] = src.metaISO.enhanceClippedThreholdMaxGainmap[INDEX_TWO];

    dst.gainmapMin[INDEX_ZERO] = src.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ZERO];
    dst.gainmapMin[INDEX_ONE] = src.metaISO.enhanceClippedThreholdMinGainmap[INDEX_ONE];
    dst.gainmapMin[INDEX_TWO] = src.metaISO.enhanceClippedThreholdMinGainmap[INDEX_TWO];

    dst.gamma[INDEX_ZERO] = src.metaISO.enhanceMappingGamma[INDEX_ZERO];
    dst.gamma[INDEX_ONE] = src.metaISO.enhanceMappingGamma[INDEX_ONE];
    dst.gamma[INDEX_TWO] = src.metaISO.enhanceMappingGamma[INDEX_TWO];

    dst.baselineOffset[INDEX_ZERO] = src.metaISO.enhanceMappingBaselineOffset[INDEX_ZERO];
    dst.baselineOffset[INDEX_ONE] = src.metaISO.enhanceMappingBaselineOffset[INDEX_ONE];
    dst.baselineOffset[INDEX_TWO] = src.metaISO.enhanceMappingBaselineOffset[INDEX_TWO];

    dst.alternateOffset[INDEX_ZERO] = src.metaISO.enhanceMappingAlternateOffset[INDEX_ZERO];
    dst.alternateOffset[INDEX_ONE] = src.metaISO.enhanceMappingAlternateOffset[INDEX_ONE];
    dst.alternateOffset[INDEX_TWO] = src.metaISO.enhanceMappingAlternateOffset[INDEX_TWO];
}

static bool ConvertTONdkStaticMetadata(HdrStaticMetadata &src,
    OH_Pixelmap_HdrStaticMetadata &dst)
{
    dst.displayPrimariesX[INDEX_ZERO] = src.smpte2086.displayPrimaryRed.x;
    dst.displayPrimariesY[INDEX_ZERO] = src.smpte2086.displayPrimaryRed.y;
    dst.displayPrimariesX[INDEX_ONE] = src.smpte2086.displayPrimaryGreen.x;
    dst.displayPrimariesY[INDEX_ONE] = src.smpte2086.displayPrimaryGreen.y;
    dst.displayPrimariesX[INDEX_TWO] = src.smpte2086.displayPrimaryBlue.x;
    dst.displayPrimariesY[INDEX_TWO] = src.smpte2086.displayPrimaryBlue.y;
    dst.whitePointX = src.smpte2086.whitePoint.x;
    dst.whitePointY = src.smpte2086.whitePoint.y;
    dst.maxLuminance = src.smpte2086.maxLuminance;
    dst.minLuminance = src.smpte2086.minLuminance;
    dst.maxContentLightLevel = src.cta861.maxContentLightLevel;
    dst.maxFrameAverageLightLevel = src.cta861.maxFrameAverageLightLevel;
    return true;
}

static bool GetStaticMetadata(const OHOS::sptr<OHOS::SurfaceBuffer> &buffer,
    OH_Pixelmap_HdrMetadataValue *metadataValue)
{
    std::vector<uint8_t> staticData;
    uint32_t vecSize = sizeof(HDI::Display::Graphic::Common::V1_0::HdrStaticMetadata);
    if (VpeUtils::GetSbStaticMetadata(buffer, staticData) &&
        (staticData.size() == vecSize)) {
        OH_Pixelmap_HdrStaticMetadata &dst = metadataValue->staticMetadata;
        HdrStaticMetadata &src = *(reinterpret_cast<HdrStaticMetadata*>(staticData.data()));
        return ConvertTONdkStaticMetadata(src, dst);
    }
    return false;
}

static bool GetHdrMetadata(const OHOS::sptr<OHOS::SurfaceBuffer> &buffer,
    OH_Pixelmap_HdrMetadataKey key, OH_Pixelmap_HdrMetadataValue *metadataValue)
{
    if (buffer == nullptr || metadataValue == nullptr) {
        IMAGE_LOGE("GetHdrMetadata buffer is nullptr");
        return false;
    }
    switch (key) {
        case OH_Pixelmap_HdrMetadataKey::HDR_METADATA_TYPE:
            {
                CM_HDR_Metadata_Type type;
                VpeUtils::GetSbMetadataType(buffer, type);
                if (MetadataNdkTypeMap.find(type) != MetadataNdkTypeMap.end()) {
                    metadataValue->type = MetadataNdkTypeMap[type];
                    return true;
                }
            }
            break;
        case OH_Pixelmap_HdrMetadataKey::HDR_STATIC_METADATA:
            return GetStaticMetadata(buffer, metadataValue);
            break;
        case OH_Pixelmap_HdrMetadataKey::HDR_DYNAMIC_METADATA:
            {
                std::vector<uint8_t> dynamicData;
                if (VpeUtils::GetSbDynamicMetadata(buffer, dynamicData) && (dynamicData.size() > 0)) {
                    metadataValue->dynamicMetadata.data = (uint8_t*)malloc(dynamicData.size());
                    if (metadataValue->dynamicMetadata.data == nullptr || memcpy_s(metadataValue->dynamicMetadata.data,
                        dynamicData.size(), dynamicData.data(), dynamicData.size()) != EOK) {
                        return false;
                    }
                    metadataValue->dynamicMetadata.length = dynamicData.size();
                    return true;
                }
            }
            break;
        case OH_Pixelmap_HdrMetadataKey::HDR_GAINMAP_METADATA:
            {
                std::vector<uint8_t> gainmapData;
                if (VpeUtils::GetSbDynamicMetadata(buffer, gainmapData) &&
                    (gainmapData.size() == sizeof(HDRVividExtendMetadata))) {
                    OH_Pixelmap_HdrGainmapMetadata &dst = metadataValue->gainmapMetadata;
                    HDRVividExtendMetadata &src = *(reinterpret_cast<HDRVividExtendMetadata*>(gainmapData.data()));
                    ConvertToOHGainmapMetadata(src, dst);
                    return true;
                }
            }
            break;
        default:
            break;
    }

    return false;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetMetadata(OH_PixelmapNative *pixelmap, OH_Pixelmap_HdrMetadataKey key,
    OH_Pixelmap_HdrMetadataValue **value)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || value == nullptr || *value == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    if (pixelmap->GetInnerPixelmap()->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return IMAGE_DMA_NOT_EXIST;
    }

    OHOS::sptr<OHOS::SurfaceBuffer> sourceSurfaceBuffer(
        reinterpret_cast<OHOS::SurfaceBuffer*>(pixelmap->GetInnerPixelmap()->GetFd()));
    if (!GetHdrMetadata(sourceSurfaceBuffer, key, *value)) {
        return IMAGE_COPY_FAILED;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetNativeBuffer(OH_PixelmapNative *pixelmap, OH_NativeBuffer **nativeBuffer)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || nativeBuffer == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    if (pixelmap->GetInnerPixelmap()->GetAllocatorType() != AllocatorType::DMA_ALLOC) {
        return IMAGE_DMA_NOT_EXIST;
    }

    OHOS::SurfaceBuffer *buffer = reinterpret_cast<OHOS::SurfaceBuffer*>(pixelmap->GetInnerPixelmap()->GetFd());
    if (buffer == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *nativeBuffer = buffer->SurfaceBufferToNativeBuffer();
    int32_t err = OH_NativeBuffer_Reference(*nativeBuffer);
    if (err != OHOS::SURFACE_ERROR_OK) {
        return IMAGE_DMA_OPERATION_FAILED;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetColorSpaceNative(OH_PixelmapNative *pixelmap,
    OH_NativeColorSpaceManager **colorSpaceNative)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || colorSpaceNative == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    if (pixelmap->GetInnerPixelmap()->InnerGetGrColorSpacePtr() == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    std::shared_ptr<OHOS::ColorManager::ColorSpace> colorSpace =
        pixelmap->GetInnerPixelmap()->InnerGetGrColorSpacePtr();
    NativeColorSpaceManager* nativeColorspace = new NativeColorSpaceManager(*(colorSpace.get()));

    *colorSpaceNative = reinterpret_cast<OH_NativeColorSpaceManager*>(nativeColorspace);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_SetColorSpaceNative(OH_PixelmapNative *pixelmap,
    OH_NativeColorSpaceManager *colorSpaceNative)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || colorSpaceNative == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }

    ColorManager::ColorSpace nativeColorspace =
        reinterpret_cast<NativeColorSpaceManager*>(colorSpaceNative)->GetInnerColorSpace();

    pixelmap->GetInnerPixelmap()->InnerSetColorSpace(nativeColorspace, true);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_SetMemoryName(OH_PixelmapNative *pixelmap, char *name, size_t *size)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || name == nullptr || size == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t ret = pixelmap->GetInnerPixelmap()->SetMemoryName(std::string(name, *size));
    if (ret == SUCCESS) {
        return IMAGE_SUCCESS;
    } else if (ret == COMMON_ERR_INVALID_PARAMETER) {
        return IMAGE_BAD_PARAMETER;
    } else if (ret == ERR_MEMORY_NOT_SUPPORT) {
        return IMAGE_UNSUPPORTED_MEMORY_FORMAT;
    }
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetByteCount(OH_PixelmapNative *pixelmap, uint32_t *byteCount)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || byteCount == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    int32_t rawByteCount = pixelmap->GetInnerPixelmap()->GetByteCount();
    if (rawByteCount <= 0) {
        return IMAGE_BAD_PARAMETER;
    }
    *byteCount = static_cast<uint32_t>(rawByteCount);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetAllocationByteCount(OH_PixelmapNative *pixelmap, uint32_t *allocationByteCount)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || allocationByteCount == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    uint32_t rawByteCount = pixelmap->GetInnerPixelmap()->GetAllocationByteCount();
    if (rawByteCount == 0) {
        return IMAGE_BAD_PARAMETER;
    }
    *allocationByteCount = rawByteCount;
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_AccessPixels(OH_PixelmapNative *pixelmap, void **addr)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr || addr == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->SetModifiable(false);
    *addr = pixelmap->GetInnerPixelmap()->GetWritablePixels();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_UnaccessPixels(OH_PixelmapNative *pixelmap)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    pixelmap->GetInnerPixelmap()->SetModifiable(true);
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_GetUniqueId(OH_PixelmapNative *pixelmap, uint32_t *uniqueId)
{
    if (pixelmap == nullptr || pixelmap->GetInnerPixelmap() == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *uniqueId = pixelmap->GetInnerPixelmap()->GetUniqueId();
    return IMAGE_SUCCESS;
}

MIDK_EXPORT
Image_ErrorCode OH_PixelmapNative_IsReleased(OH_PixelmapNative *pixelmap, bool *released)
{
    if (pixelmap == nullptr) {
        return IMAGE_BAD_PARAMETER;
    }
    *released = pixelmap->GetInnerPixelmap() == nullptr;
    return IMAGE_SUCCESS;
}

#ifdef __cplusplus
};
#endif