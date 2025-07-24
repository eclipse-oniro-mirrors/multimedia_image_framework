/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "pixelmap_native.h"
#include "pixelmap_native_impl.h"
#include "common_utils.h"
#include "image_source_native.h"
#include "securec.h"
#include "image_utils.h"
#include "native_color_space_manager.h"
#include "image_mime_type.h"

using namespace testing::ext;
using namespace OHOS::Media;

struct OH_Pixelmap_ImageInfo {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t rowStride = 0;
    int32_t pixelFormat = PIXEL_FORMAT::PIXEL_FORMAT_UNKNOWN;
    PIXELMAP_ALPHA_TYPE alphaType = PIXELMAP_ALPHA_TYPE::PIXELMAP_ALPHA_TYPE_UNKNOWN;
    bool isHdr = false;
    Image_MimeType mimeType;
};

namespace OHOS {
namespace Media {

constexpr int8_t ARGB_8888_BYTES = 4;

class PixelMapNdk2Test : public testing::Test {
public:
    PixelMapNdk2Test() {}
    ~PixelMapNdk2Test() {}
};

constexpr int32_t bufferSize = 256;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob001.jpg";
static const std::string IMAGE_JPEG_PATH_TEST = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_JPEG_PATH_TEST_PICTURE = "/data/local/tmp/image/test_picture.jpg";

/**
 * @tc.name: OH_PixelmapInitializationOptions_Create
 * @tc.desc: OH_PixelmapInitializationOptions_Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_Create, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_Create start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    Image_ErrorCode res = OH_PixelmapInitializationOptions_Create(&ops);
    ASSERT_EQ(res, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_Create end";
}

/**
 * @tc.name: OH_PixelmapInitializationOptions_SetGetWidth
 * @tc.desc: OH_PixelmapInitializationOptions_SetGetWidth
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetGetWidth, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_GetWidth start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    uint32_t width = 0;
    OH_PixelmapInitializationOptions_SetWidth(ops, 1);
    OH_PixelmapInitializationOptions_GetWidth(ops, &width);
    ASSERT_EQ(width, 1);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_GetWidth end";
}

/**
 * @tc.name: OH_PixelmapInitializationOptions_SetGetHeight
 * @tc.desc: OH_PixelmapInitializationOptions_SetGetHeight
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetGetHeight, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetGetHeight start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    uint32_t height = 0;
    OH_PixelmapInitializationOptions_SetHeight(ops, 1);
    OH_PixelmapInitializationOptions_GetHeight(ops, &height);
    ASSERT_EQ(height, 1);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetGetHeight end";
}

/**
 * @tc.name: OH_PixelmapInitializationOptions_SetGetPixelFormat
 * @tc.desc: OH_PixelmapInitializationOptions_SetGetPixelFormat
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetGetPixelFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_InitializationSetOptionsGetPixelFormat start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    int32_t pixelFormat = 0;
    OH_PixelmapInitializationOptions_SetPixelFormat(ops, 1);
    OH_PixelmapInitializationOptions_GetPixelFormat(ops, &pixelFormat);
    ASSERT_EQ(pixelFormat, 1);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_InitializationSetOptionsGetPixelFormat end";
}

HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetGetAlphaType, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetGetAlphaType start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    int32_t alphaType = 0;
    OH_PixelmapInitializationOptions_SetAlphaType(ops, 1);
    OH_PixelmapInitializationOptions_GetAlphaType(ops, &alphaType);
    ASSERT_EQ(alphaType, 1);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetGetAlphaType end";
}

/**
 * @tc.name: OH_PixelmapInitializationOptions_SetEditable
 * @tc.desc: OH_PixelmapInitializationOptions_SetEditable
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetEditable, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetEditable start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    bool editable = false;
    OH_PixelmapInitializationOptions_GetEditable(ops, &editable);
    ASSERT_EQ(editable, true);
    OH_PixelmapInitializationOptions_SetEditable(ops, false);
    OH_PixelmapInitializationOptions_GetEditable(ops, &editable);
    ASSERT_EQ(editable, false);
    ASSERT_EQ(OH_PixelmapInitializationOptions_SetEditable(nullptr, true), 401);
    ASSERT_EQ(OH_PixelmapInitializationOptions_SetEditable(nullptr, false), 401);
    ASSERT_EQ(OH_PixelmapInitializationOptions_GetEditable(nullptr, &editable), 401);
    ASSERT_EQ(OH_PixelmapInitializationOptions_GetEditable(nullptr, &editable), 401);
    OH_PixelmapInitializationOptions_Release(ops);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetEditable end";
}

/**
 * @tc.name: OH_PixelmapNative_Destroy
 * @tc.desc: Test OH_PixelmapNative_Destroy with valid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Destroy, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Destroy start";

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF};
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1);
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1);
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    OH_PixelmapNative *pixelMap = nullptr;
    Image_ErrorCode errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);

    OH_PixelmapNative_Destroy(&pixelMap);
    ASSERT_EQ(pixelMap, nullptr);
    ASSERT_EQ(OH_PixelmapNative_Destroy(nullptr), 401);
    OH_PixelmapInitializationOptions_Release(createOpts);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Destroy end";
}


/**
 * @tc.name: OH_PixelmapInitializationOptions_Release
 * @tc.desc: OH_PixelmapInitializationOptions_Release
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_Release start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    Image_ErrorCode ret = OH_PixelmapInitializationOptions_Release(ops);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_Release end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_Create
 * @tc.desc: OH_PixelmapImageInfo_Create
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_Create, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_Create start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    Image_ErrorCode ret = OH_PixelmapImageInfo_Create(&ImageInfo);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_Create end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_GetWidth
 * @tc.desc: OH_PixelmapImageInfo_GetWidth
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_GetWidth, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetWidth start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    uint32_t width = 0;
    Image_ErrorCode ret = OH_PixelmapImageInfo_GetWidth(ImageInfo, &width);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetWidth end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_GetHeight
 * @tc.desc: OH_PixelmapImageInfo_GetHeight
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_GetHeight, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetHeight start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    uint32_t height = 0;
    Image_ErrorCode ret = OH_PixelmapImageInfo_GetHeight(ImageInfo, &height);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetHeight end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_GetRowStride
 * @tc.desc: OH_PixelmapImageInfo_GetRowStride
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_GetRowStride, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetRowStride start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    uint32_t rowSize = 0;
    Image_ErrorCode ret = OH_PixelmapImageInfo_GetRowStride(ImageInfo, &rowSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetRowStride end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_GetPixelFormat
 * @tc.desc: OH_PixelmapImageInfo_GetPixelFormat
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_GetPixelFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetPixelFormat start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    int32_t pixelFormat = 0;
    Image_ErrorCode ret = OH_PixelmapImageInfo_GetPixelFormat(ImageInfo, &pixelFormat);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetPixelFormat end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_GetAlphaType
 * @tc.desc: OH_PixelmapImageInfo_GetAlphaType
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_GetAlphaType, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetAlphaType start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    int32_t density = 0;
    Image_ErrorCode ret = OH_PixelmapImageInfo_GetAlphaType(ImageInfo, &density);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_GetAlphaType end";
}

/**
 * @tc.name: OH_PixelmapImageInfo_Release
 * @tc.desc: OH_PixelmapImageInfo_Release
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapImageInfo_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_Release start";
    OH_Pixelmap_ImageInfo *ImageInfo = nullptr;
    Image_ErrorCode ret = OH_PixelmapImageInfo_Release(ImageInfo);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapImageInfo_Release end";
}

/**
 * @tc.name: OH_PixelmapNative_CreatePixelMap
 * @tc.desc: OH_PixelmapNative_CreatePixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreatePixelMap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelMap start";
    uint8_t *colors = nullptr;
    size_t colorLength = 0;
    OH_Pixelmap_InitializationOptions *opts = nullptr;
    OH_PixelmapNative *pixelMap = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_CreatePixelmap(colors, colorLength, opts, &pixelMap);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelMap end";
}

/**
 * @tc.name: OH_PixelmapNative_ConvertPixelmapNativeToNapi
 * @tc.desc: test OH_PixelmapNative_ConvertPixelmapNativeToNapi
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_ConvertPixelmapNativeToNapi, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ConvertPixelmapNativeToNapi start";
    napi_env env = nullptr;
    OH_PixelmapNative *pixelMap = nullptr;
    napi_value res = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_ConvertPixelmapNativeToNapi(env, pixelMap, &res);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ConvertPixelmapNativeToNapi end";
}

/**
 * @tc.name: OH_PixelmapNative_ConvertPixelmapNativeFromNapi
 * @tc.desc: test OH_PixelmapNative_ConvertPixelmapNativeFromNapi
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_ConvertPixelmapNativeFromNapi, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ConvertPixelmapNativeFromNapi start";
    napi_env env = nullptr;
    napi_value source = nullptr;
    OH_PixelmapNative *pixelMap = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_ConvertPixelmapNativeFromNapi(env, source, &pixelMap);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ConvertPixelmapNativeFromNapi end";
}

/**
 * @tc.name: OH_PixelmapNative_ReadPixels
 * @tc.desc: OH_PixelmapNative_ReadPixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_ReadPixels, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ReadPixels start";
    OH_PixelmapNative *pixelMap = nullptr;
    uint8_t *buffer = nullptr;
    size_t *bufferSize = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_ReadPixels(pixelMap, buffer, bufferSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ReadPixels end";
}

/**
 * @tc.name: OH_PixelmapNative_WritePixels
 * @tc.desc: OH_PixelmapNative_WritePixels
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_WritePixels, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_WritePixels start";
    OH_PixelmapNative *pixelMap = nullptr;
    uint8_t *source = nullptr;
    size_t bufferSize = 0;
    Image_ErrorCode ret = OH_PixelmapNative_WritePixels(pixelMap, source, bufferSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_WritePixels end";
}


static int32_t GetPixelBytes(PIXEL_FORMAT &pixelFormat)
{
    int pixelBytes = 0;
    switch (pixelFormat) {
        case PIXEL_FORMAT_BGRA_8888:
        case PIXEL_FORMAT_RGBA_8888:
        case PIXEL_FORMAT_RGBA_1010102:
            pixelBytes = 4;
            break;
        case PIXEL_FORMAT_ALPHA_8:
            pixelBytes = 1;
            break;
        case PIXEL_FORMAT_RGB_888:
            pixelBytes = 3;
            break;
        case PIXEL_FORMAT_RGB_565:
            pixelBytes = 2;
            break;
        case PIXEL_FORMAT_RGBA_F16:
            pixelBytes = 8;
            break;
        case PIXEL_FORMAT_NV21:
        case PIXEL_FORMAT_NV12:
            pixelBytes = 2;  // perl pixel 1.5 Bytes but return int so return 2
            break;
        case PIXEL_FORMAT_YCBCR_P010:
        case PIXEL_FORMAT_YCRCB_P010:
            pixelBytes = 3;
            break;
        default:
            return 4;
            break;
    }
    return pixelBytes;
}

static bool OH_PixelmapNative_CreatePixelmapUsingAllocator_others(uint32_t size,
    PIXEL_FORMAT pixelFormat, IMAGE_ALLOCATOR_MODE type)
{
    size_t bufferSize = size * size * GetPixelBytes(pixelFormat);
    uint8_t *destination = static_cast<uint8_t *>(malloc(bufferSize));
    OH_Pixelmap_InitializationOptions *initOpts = nullptr;
    OH_PixelmapInitializationOptions_Create(&initOpts);
    OH_PixelmapInitializationOptions_SetSrcPixelFormat(initOpts, pixelFormat);
    OH_PixelmapInitializationOptions_SetPixelFormat(initOpts, pixelFormat);
    OH_PixelmapInitializationOptions_SetHeight(initOpts, size);
    OH_PixelmapInitializationOptions_SetWidth(initOpts, size);
    OH_PixelmapInitializationOptions_SetAlphaType(initOpts, PIXELMAP_ALPHA_TYPE_UNPREMULTIPLIED);
    OH_PixelmapNative *resultPixelmap = nullptr;
    Image_ErrorCode errCode = OH_PixelmapNative_CreatePixelmapUsingAllocator(destination,
        bufferSize, initOpts, type, &resultPixelmap);
    if (IMAGE_SUCCESS != errCode) {
        return false;
    }
    OH_Pixelmap_ImageInfo *imageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&imageInfo);
    OH_PixelmapNative_GetImageInfo(resultPixelmap, imageInfo);
    uint32_t dstWidth = 0;
    OH_PixelmapImageInfo_GetWidth(imageInfo, &dstWidth);
    uint32_t dstHeight = 0;
    OH_PixelmapImageInfo_GetHeight(imageInfo, &dstHeight);
    uint32_t dstRowStride = 0;
    OH_PixelmapImageInfo_GetRowStride(imageInfo, &dstRowStride);
    int32_t dstFormat;
    OH_PixelmapImageInfo_GetPixelFormat(imageInfo, &dstFormat);
    int32_t alphaMode;
    OH_PixelmapImageInfo_GetAlphaMode(imageInfo, &alphaMode);
    free(destination);
    OH_PixelmapInitializationOptions_Release(initOpts);
    OH_PixelmapImageInfo_Release(imageInfo);
    OH_PixelmapNative_Destroy(&resultPixelmap);
    return true;
}

static OH_ImageSourceNative *CreateImageSourceNative(std::string IMAGE_PATH)
{
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_PATH.c_str(), realPath) || realPath.empty()) {
        return nullptr;
    }
    char filePath[bufferSize];
    if (strcpy_s(filePath, sizeof(filePath), realPath.c_str()) != EOK) {
        return nullptr;
    }
    size_t length = realPath.size();
    OH_ImageSourceNative *source = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    if (ret != Image_ErrorCode::IMAGE_SUCCESS || source == nullptr) {
        return nullptr;
    }
    return source;
}

static bool OH_PixelmapNative_CreatePixelmapUsingAllocator_Test(uint32_t size,
    PIXEL_FORMAT pixelFormat, IMAGE_ALLOCATOR_MODE type, OH_ImageSourceNative *imageSource)
{
    OH_DecodingOptions *decodeOpts = nullptr;
    Image_ErrorCode errCode = OH_DecodingOptions_Create(&decodeOpts);
    if (IMAGE_SUCCESS != errCode || imageSource == nullptr) {
        return false;
    }
    OH_DecodingOptions_SetPixelFormat(decodeOpts, pixelFormat);
    Image_Size desiredSize = {size, size};
    OH_DecodingOptions_SetDesiredSize(decodeOpts, &desiredSize);
    OH_PixelmapNative *resPixMap = nullptr;
    if (IMAGE_SUCCESS != OH_ImageSourceNative_CreatePixelmap(imageSource, decodeOpts, &resPixMap)) {
        return false;
    }
    OH_Pixelmap_ImageInfo *imageInfo1 = nullptr;
    OH_PixelmapImageInfo_Create(&imageInfo1);
    OH_PixelmapNative_GetImageInfo(resPixMap, imageInfo1);
    uint32_t srcHeight = 0;
    OH_PixelmapImageInfo_GetHeight(imageInfo1, &srcHeight);
    uint32_t srcRowStride = 0;
    OH_PixelmapImageInfo_GetRowStride(imageInfo1, &srcRowStride);
    size_t bufferSize = srcRowStride * srcHeight;
    uint8_t *destination = static_cast<uint8_t *>(malloc(bufferSize));
    OH_PixelmapNative_ReadPixels(resPixMap, destination, &bufferSize);
    OH_Pixelmap_InitializationOptions *initOpts = nullptr;
    OH_PixelmapInitializationOptions_Create(&initOpts);
    OH_PixelmapInitializationOptions_SetSrcPixelFormat(initOpts, pixelFormat);
    OH_PixelmapInitializationOptions_SetPixelFormat(initOpts, pixelFormat);
    OH_PixelmapInitializationOptions_SetHeight(initOpts, size);
    OH_PixelmapInitializationOptions_SetWidth(initOpts, size);
    OH_PixelmapInitializationOptions_SetAlphaType(initOpts, PIXELMAP_ALPHA_TYPE_UNPREMULTIPLIED);
    OH_PixelmapNative *resultPixelmap = nullptr;
    errCode = OH_PixelmapNative_CreatePixelmapUsingAllocator(destination, bufferSize, initOpts, type, &resultPixelmap);
    if (IMAGE_SUCCESS != errCode) {
        return false;
    }
    OH_Pixelmap_ImageInfo *imageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&imageInfo);
    OH_PixelmapNative_GetImageInfo(resultPixelmap, imageInfo);
    int32_t alphaMode;
    OH_PixelmapImageInfo_GetAlphaMode(imageInfo, &alphaMode);
    free(destination);
    OH_PixelmapInitializationOptions_Release(initOpts);
    OH_PixelmapImageInfo_Release(imageInfo1);
    OH_PixelmapImageInfo_Release(imageInfo);
    OH_PixelmapNative_Destroy(&resPixMap);
    OH_PixelmapNative_Destroy(&resultPixelmap);
    return true;
}

static bool CreateUsingAlloc(uint32_t size,
    PIXEL_FORMAT pixelFormat, IMAGE_ALLOCATOR_MODE type, OH_ImageSourceNative *imageSource)
{
    if (pixelFormat == PIXEL_FORMAT_RGBA_1010102 ||
        pixelFormat == PIXEL_FORMAT_YCBCR_P010 ||
        pixelFormat == PIXEL_FORMAT_YCRCB_P010 ||
        pixelFormat == PIXEL_FORMAT_RGB_888 ||
        pixelFormat == PIXEL_FORMAT_ALPHA_8) {
        return OH_PixelmapNative_CreatePixelmapUsingAllocator_others(size, pixelFormat, type);
    }
    return OH_PixelmapNative_CreatePixelmapUsingAllocator_Test(size, pixelFormat, type, imageSource);
}
/**
 * @tc.name: OH_PixelmapNative_CreatePixelmapUsingAllocator
 * @tc.desc: Test OH_PixelmapNative_CreatePixelmapUsingAllocator with valid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreatePixelmapUsingAllocator, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelmapUsingAllocator start";
    const int32_t size = 300;
    const int32_t dmaSize = 512;
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH_TEST_PICTURE);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_RGB_888, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_ALPHA_8, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_NV21, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_NV12, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(dmaSize, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_AUTO, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_DMA, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_DMA, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_DMA, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGB_888, IMAGE_ALLOCATOR_MODE_DMA, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_ALPHA_8, IMAGE_ALLOCATOR_MODE_DMA, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_NV21, IMAGE_ALLOCATOR_MODE_DMA, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_NV12, IMAGE_ALLOCATOR_MODE_DMA, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_DMA, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_DMA, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_DMA, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGB_888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_ALPHA_8, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGBA_F16, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_NV21, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_NV12, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), true);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_RGBA_1010102,
        IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), false);
    ASSERT_EQ(CreateUsingAlloc(size, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY, imageSource), false);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelmapUsingAllocator end";
}

bool CreateEmptypixelmap(uint32_t size, int32_t pixelFormat, IMAGE_ALLOCATOR_MODE type)
{
    OH_Pixelmap_InitializationOptions *initOpts = nullptr;
    OH_PixelmapInitializationOptions_Create(&initOpts);
    OH_PixelmapInitializationOptions_SetSrcPixelFormat(initOpts, pixelFormat);
    OH_PixelmapInitializationOptions_SetPixelFormat(initOpts, pixelFormat);
    OH_PixelmapInitializationOptions_SetHeight(initOpts, size);
    OH_PixelmapInitializationOptions_SetWidth(initOpts, size);
    OH_PixelmapNative *resultPixelmap = nullptr;
    Image_ErrorCode errCode = OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator(initOpts, type, &resultPixelmap);
    if (IMAGE_SUCCESS != errCode) {
        return false;
    }
    OH_Pixelmap_ImageInfo *imageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&imageInfo);
    OH_PixelmapNative_GetImageInfo(resultPixelmap, imageInfo);
    uint32_t dstWidth = 0;
    OH_PixelmapImageInfo_GetWidth(imageInfo, &dstWidth);
    uint32_t dstHeight = 0;
    OH_PixelmapImageInfo_GetHeight(imageInfo, &dstHeight);
    uint32_t dstRowStride = 0;
    OH_PixelmapImageInfo_GetRowStride(imageInfo, &dstRowStride);
    int32_t dstFormat;
    OH_PixelmapImageInfo_GetPixelFormat(imageInfo, &dstFormat);
    int32_t alphaMode;
    OH_PixelmapImageInfo_GetAlphaMode(imageInfo, &alphaMode);
    OH_PixelmapInitializationOptions_Release(initOpts);
    OH_PixelmapImageInfo_Release(imageInfo);
    OH_PixelmapNative_Destroy(&resultPixelmap);
    return true;
}

/**
 * @tc.name: OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator
 * @tc.desc: OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator For PIXEL_FORMAT_YCRCB_P010
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator start";
    const int32_t size = 300;
    const int32_t dmaSize = 512;
    bool ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGB_888, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_ALPHA_8, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_F16, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_NV21, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_NV12, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_AUTO);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGBA_F16, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_DMA);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGB_888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_ALPHA_8, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_F16, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_NV21, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_NV12, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, true);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, false);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, false);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator end";
}
}
}
