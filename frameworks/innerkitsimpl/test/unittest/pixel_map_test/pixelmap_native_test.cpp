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

const int32_t ZERO = 0;
const int32_t ONE = 1;
const int32_t TWO = 2;
const int32_t THREE = 3;
const int32_t FOUR = 4;
const int32_t EIGHT = 8;
const float PRIMARIES = 0.1;
const int32_t VERSION_VALUE = 50;
constexpr int32_t bufferSize = 256;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_jpeg_writeexifblob001.jpg";
static const std::string IMAGE_JPEG_PATH_TEST = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_JPEG_PATH_TEST_PICTURE = "/data/local/tmp/image/test_picture.jpg";

/* Compare two OH_Pixelmap_ImageInfo structures for equality */
static bool CompareImageInfo(OH_Pixelmap_ImageInfo* srcImageInfo, OH_Pixelmap_ImageInfo* dstImageInfo)
{
    if (srcImageInfo == nullptr && dstImageInfo == nullptr) {
        return true;
    }

    if ((srcImageInfo == nullptr) ^ (dstImageInfo == nullptr)) {
        return false;
    }

    // Declare variables to store source image properties
    uint32_t srcWidth = 0;
    uint32_t srcHeight = 0;
    uint32_t srcRowStride = 0;  // Bytes per row including padding
    int32_t srcPixelFormat = 0; // Pixel format enum value
    int32_t srcAlphaType = 0;   // Alpha handling method
    bool srcIsHdr = false;      // High Dynamic Range flag

    OH_PixelmapImageInfo_GetWidth(srcImageInfo, &srcWidth);
    OH_PixelmapImageInfo_GetHeight(srcImageInfo, &srcHeight);
    OH_PixelmapImageInfo_GetRowStride(srcImageInfo, &srcRowStride);
    OH_PixelmapImageInfo_GetPixelFormat(srcImageInfo, &srcPixelFormat);
    OH_PixelmapImageInfo_GetAlphaType(srcImageInfo, &srcAlphaType);
    OH_PixelmapImageInfo_GetDynamicRange(srcImageInfo, &srcIsHdr);

    uint32_t dstWidth = 0;
    uint32_t dstHeight = 0;
    uint32_t dstRowStride = 0;
    int32_t dstPixelFormat = 0;
    int32_t dstAlphaType = 0;
    bool dstIsHdr = false;
    OH_PixelmapImageInfo_GetWidth(dstImageInfo, &dstWidth);
    OH_PixelmapImageInfo_GetHeight(dstImageInfo, &dstHeight);
    OH_PixelmapImageInfo_GetRowStride(dstImageInfo, &dstRowStride);
    OH_PixelmapImageInfo_GetPixelFormat(dstImageInfo, &dstPixelFormat);
    OH_PixelmapImageInfo_GetAlphaType(dstImageInfo, &dstAlphaType);
    OH_PixelmapImageInfo_GetDynamicRange(dstImageInfo, &dstIsHdr);

    return srcWidth == dstWidth && srcHeight == dstHeight && srcRowStride == dstRowStride
        && srcPixelFormat == dstPixelFormat && srcAlphaType == dstAlphaType && srcIsHdr == dstIsHdr;
}

static void CreatePixelmapNative(OH_PixelmapNative** pixelmapNative,
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE_AUTO)
{
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_JPEG_PATH_TEST_PICTURE.c_str(), realPath)) {
        return;
    }

    char filePath[bufferSize];
    if (strcpy_s(filePath, sizeof(filePath), realPath.c_str()) != EOK) {
        return;
    }

    size_t length = realPath.size();
    OH_ImageSourceNative *source = nullptr;
    OH_ImageSourceNative_CreateFromUri(filePath, length, &source);

    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);

    OH_PixelmapNative *pixelmap = nullptr;
    if (allocator == IMAGE_ALLOCATOR_TYPE_AUTO) {
        OH_ImageSourceNative_CreatePixelmap(source, opts, &pixelmap);
    } else {
        OH_ImageSourceNative_CreatePixelmapUsingAllocator(source, opts, allocator, &pixelmap);
    }
    *pixelmapNative = pixelmap;
}

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
    uint32_t width = 0; // Initialize width to 0
    OH_PixelmapInitializationOptions_SetWidth(ops, 1); // Set width to 1
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
    uint32_t height = 0; // Initialize height to 0
    OH_PixelmapInitializationOptions_SetHeight(ops, 1); // Set height to 1
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
    int32_t pixelFormat = 0; // Initialize pixelFormat to 0
    OH_PixelmapInitializationOptions_SetPixelFormat(ops, 1); // Set pixelFormat to 1
    OH_PixelmapInitializationOptions_GetPixelFormat(ops, &pixelFormat);
    ASSERT_EQ(pixelFormat, 1);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_InitializationSetOptionsGetPixelFormat end";
}

HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetGetAlphaType, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapInitializationOptions_SetGetAlphaType start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    int32_t alphaType = 0; // Initialize alphaType to 0
    OH_PixelmapInitializationOptions_SetAlphaType(ops, 1); // Set alphaType to 1
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
    ASSERT_EQ(OH_PixelmapInitializationOptions_SetEditable(nullptr, true), 401); // Check for null pointer
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
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF}; // Example ARGB data
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
    uint32_t width = 0; // Initialize width to 0
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
    uint32_t height = 0; // Initialize height to 0
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
    uint32_t rowSize = 0; // Initialize rowSize to 0
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
    int32_t pixelFormat = 0; // Initialize pixelFormat to 0
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
    int32_t density = 0; // Initialize density to 0
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
    size_t colorLength = 0; // Initialize colorLength to 0
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

/**
 * @tc.name: OH_PixelmapNative_GetArgbPixels_Test001
 * @tc.desc: Test OH_PixelmapNative_GetArgbPixels with valid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetArgbPixels_Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetArgbPixels_Test001 start";

    size_t dataSize = ARGB_8888_BYTES;
    uint8_t data[] = {0x01, 0x02, 0x03, 0xFF}; // Example ARGB data
    OH_Pixelmap_InitializationOptions *createOpts;
    OH_PixelmapInitializationOptions_Create(&createOpts);
    OH_PixelmapInitializationOptions_SetWidth(createOpts, 1); // Set width to 1
    OH_PixelmapInitializationOptions_SetHeight(createOpts, 1); // Set height to 1
    OH_PixelmapInitializationOptions_SetPixelFormat(createOpts, PIXEL_FORMAT_BGRA_8888);
    OH_PixelmapNative *pixelMap = nullptr;
    Image_ErrorCode errCode = OH_PixelmapNative_CreatePixelmap(data, dataSize, createOpts, &pixelMap);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);

    uint8_t result[ARGB_8888_BYTES];
    errCode = OH_PixelmapNative_GetArgbPixels(pixelMap, result, &dataSize);
    ASSERT_EQ(errCode, IMAGE_SUCCESS);
    ASSERT_EQ(result[0], data[3]);
    ASSERT_EQ(result[1], data[2]);
    ASSERT_EQ(result[2], data[1]);
    ASSERT_EQ(result[3], data[0]);

    OH_PixelmapNative_Release(pixelMap);
    OH_PixelmapInitializationOptions_Release(createOpts);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetArgbPixels_Test001 end";
}

/**
 * @tc.name: OH_PixelmapNative_GetArgbPixels_Test002
 * @tc.desc: Test OH_PixelmapNative_GetArgbPixels with invalid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetArgbPixels_Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetArgbPixels_Test002 start";
    OH_PixelmapNative *pixelMap = nullptr;
    uint8_t *buffer = nullptr;
    size_t *bufferSize = nullptr;
    Image_ErrorCode errCode = OH_PixelmapNative_GetArgbPixels(pixelMap, buffer, bufferSize);
    ASSERT_EQ(errCode, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetArgbPixels_Test002 end";
}

/**
 * @tc.name: OH_PixelmapNative_GetImageInfo
 * @tc.desc: OH_PixelmapNative_GetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetImageInfo, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetImageInfo start";
    OH_PixelmapNative *pixelMap = nullptr;
    OH_Pixelmap_ImageInfo *imageInfo = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_GetImageInfo(pixelMap, imageInfo);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetImageInfo end";
}

/**
 * @tc.name: OH_PixelmapNative_Opacity
 * @tc.desc: OH_PixelmapNative_Opacity
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Opacity, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Opacity start";
    OH_PixelmapNative *pixelMap = nullptr;
    float rate = 0;
    Image_ErrorCode ret = OH_PixelmapNative_Opacity(pixelMap, rate);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Opacity end";
}

/**
 * @tc.name: OH_PixelmapNative_Scale
 * @tc.desc: OH_PixelmapNative_Scale
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Scale, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Scale start";
    OH_PixelmapNative *pixelMap = nullptr;
    float x = 0;
    float y = 0;
    Image_ErrorCode ret = OH_PixelmapNative_Scale(pixelMap, x, y);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Scale end";
}

/**
 * @tc.name: OH_PixelmapNative_ScaleWithAntiAliasing
 * @tc.desc: OH_PixelmapNative_ScaleWithAntiAliasing
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_ScaleWithAntiAliasing, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ScaleWithAntiAliasing start";
    OH_PixelmapNative *pixelMap = nullptr;
    float x = 0;
    float y = 0;
    Image_ErrorCode ret = OH_PixelmapNative_ScaleWithAntiAliasing(pixelMap, x, y,
        OH_PixelmapNative_AntiAliasingLevel::OH_PixelmapNative_AntiAliasing_NONE);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ScaleWithAntiAliasing end";
}

/**
 * @tc.name: OH_PixelmapNative_Translate
 * @tc.desc: OH_PixelmapNative_Translate
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Translate, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Translate start";
    OH_PixelmapNative *pixelMap = nullptr;
    float x = 0;
    float y = 0;
    Image_ErrorCode ret = OH_PixelmapNative_Translate(pixelMap, x, y);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Translate end";
}

/**
 * @tc.name: OH_PixelmapNative_Rotate
 * @tc.desc: OH_PixelmapNative_Rotate
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Rotate, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Rotate start";
    OH_PixelmapNative *pixelMap = nullptr;
    float angle = 0;
    Image_ErrorCode ret = OH_PixelmapNative_Rotate(pixelMap, angle);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Rotate end";
}

/**
 * @tc.name: OH_PixelmapNative_Flip
 * @tc.desc: OH_PixelmapNative_Flip
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Flip, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Flip start";
    OH_PixelmapNative *pixelMap = nullptr;
    bool horizontal = 0;
    bool vertical = 0;
    Image_ErrorCode ret = OH_PixelmapNative_Flip(pixelMap, horizontal, vertical);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Flip end";
}

/**
 * @tc.name: OH_PixelmapNative_Crop
 * @tc.desc: OH_PixelmapNative_Crop
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Crop, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Crop start";
    OH_PixelmapNative *pixelMap = nullptr;
    Image_Region *region = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_Crop(pixelMap, region);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Crop end";
}

/**
 * @tc.name: OH_PixelmapNative_Release
 * @tc.desc: OH_PixelmapNative_Release
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Release start";
    OH_PixelmapNative *pixelMap = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_Release(pixelMap);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Release end";
}

/**
 * @tc.name: OH_PixelmapInitializationOptions_SetGetSrcPixelFormat
 * @tc.desc: OH_PixelmapInitializationOptions_SetGetSrcPixelFormat
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapInitializationOptions_SetGetSrcPixelFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_InitializationSetOptionsGetSrcPixelFormat start";
    OH_Pixelmap_InitializationOptions *ops = nullptr;
    OH_PixelmapInitializationOptions_Create(&ops);
    int32_t srcpixelFormat = 0; // Initialize srcpixelFormat to 0
    OH_PixelmapInitializationOptions_SetSrcPixelFormat(ops, 1); // Set srcpixelFormat to 1
    OH_PixelmapInitializationOptions_GetSrcPixelFormat(ops, &srcpixelFormat);
    ASSERT_EQ(srcpixelFormat, 1);
    Image_ErrorCode ret = OH_PixelmapInitializationOptions_Release(ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_InitializationSetOptionsGetSrcPixelFormat end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateEmptyPixelmap
 * @tc.desc: OH_PixelmapNative_CreateEmptyPixelmap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateEmptyPixelmap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmap start";
    OH_Pixelmap_InitializationOptions *options = nullptr;
    OH_PixelmapNative **pixelmap = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_CreateEmptyPixelmap(options, pixelmap);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmap end";
}

/**
 * @tc.name: OH_PixelmapNative_ConvertAlphaFormat
 * @tc.desc: OH_PixelmapNative_ConvertAlphaFormat
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_ConvertAlphaFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ConvertAlphaFormat start";
    OH_PixelmapNative* srcpixelmap = nullptr;
    OH_PixelmapNative* dstpixelmap = nullptr;
    const bool isPremul = false;
    Image_ErrorCode ret = OH_PixelmapNative_ConvertAlphaFormat(srcpixelmap, dstpixelmap, isPremul);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ConvertAlphaFormat end";
}

static void CreateMetadataValue(OH_Pixelmap_HdrMetadataValue &value)
{
    OH_Pixelmap_HdrMetadataType &type = value.type;
    type = OH_Pixelmap_HdrMetadataType(THREE);
    float base = PRIMARIES;
    uint32_t version = VERSION_VALUE;

    OH_Pixelmap_HdrStaticMetadata &staticMetadata = value.staticMetadata;
    staticMetadata.displayPrimariesX[ZERO] = base++;
    staticMetadata.displayPrimariesX[ONE] = base++;
    staticMetadata.displayPrimariesX[TWO] = base++;
    staticMetadata.displayPrimariesY[ZERO] = base++;
    staticMetadata.displayPrimariesY[ONE] = base++;
    staticMetadata.displayPrimariesY[TWO] = base++;
    staticMetadata.whitePointX = base++;
    staticMetadata.whitePointY = base++;
    staticMetadata.maxLuminance = base++;
    staticMetadata.minLuminance = base++;
    staticMetadata.maxContentLightLevel = base++;
    staticMetadata.maxFrameAverageLightLevel = base++;

    OH_Pixelmap_HdrGainmapMetadata &gainmapMetadata = value.gainmapMetadata;
    gainmapMetadata.writerVersion = version++;
    gainmapMetadata.minVersion = version++;
    gainmapMetadata.gainmapChannelNum = version++;
    gainmapMetadata.useBaseColorFlag = true;
    gainmapMetadata.baseHdrHeadroom = base++;
    gainmapMetadata.alternateHdrHeadroom = base++;
    gainmapMetadata.gainmapMax[ZERO] = base++;
    gainmapMetadata.gainmapMax[ONE] = base++;
    gainmapMetadata.gainmapMax[TWO] = base++;
    gainmapMetadata.gainmapMax[ZERO] = base++;
    gainmapMetadata.gainmapMax[ONE] = base++;
    gainmapMetadata.gainmapMax[TWO] = base++;
    gainmapMetadata.gamma[ZERO] = base++;
    gainmapMetadata.gamma[ONE] = base++;
    gainmapMetadata.gamma[TWO] = base++;
    gainmapMetadata.baselineOffset[ZERO] = base++;
    gainmapMetadata.baselineOffset[ONE] = base++;
    gainmapMetadata.baselineOffset[TWO] = base++;
    gainmapMetadata.alternateOffset[ZERO] = base++;
    gainmapMetadata.alternateOffset[ONE] = base++;
    gainmapMetadata.alternateOffset[TWO] = base++;
}

static void DumpMetadata(OH_Pixelmap_HdrMetadataValue value)
{
    GTEST_LOG_(INFO) << "DumpMetadata Dump IN";
    OH_Pixelmap_HdrMetadataType &type = value.type;
    GTEST_LOG_(INFO) << "DumpMetadata : " << type;
    OH_Pixelmap_HdrStaticMetadata &staticMetadata = value.staticMetadata;
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.displayPrimariesX[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.displayPrimariesX[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.displayPrimariesX[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.displayPrimariesY[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.displayPrimariesY[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.displayPrimariesY[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.whitePointX;
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.whitePointY;
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.maxLuminance;
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.minLuminance;
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.maxContentLightLevel;
    GTEST_LOG_(INFO) << "DumpMetadata : " << staticMetadata.maxFrameAverageLightLevel;
    OH_Pixelmap_HdrGainmapMetadata &gainmapMetadata = value.gainmapMetadata;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.writerVersion;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.minVersion;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapChannelNum;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.useBaseColorFlag;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.baseHdrHeadroom;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.alternateHdrHeadroom;
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapMax[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapMax[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapMax[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapMax[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapMax[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gainmapMax[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gamma[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gamma[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.gamma[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.baselineOffset[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.baselineOffset[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.baselineOffset[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.alternateOffset[ZERO];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.alternateOffset[ONE];
    GTEST_LOG_(INFO) << "DumpMetadata : " << gainmapMetadata.alternateOffset[TWO];
    GTEST_LOG_(INFO) << "DumpMetadata Dump OUT";
}

Image_ErrorCode SetMetadata(OH_Pixelmap_HdrMetadataValue &value, OH_PixelmapNative *pixelmapNative)
{
    GTEST_LOG_(INFO) << "SetMetadata IN";
    Image_ErrorCode errorCode = IMAGE_SUCCESS;
    errorCode = OH_PixelmapNative_SetMetadata(pixelmapNative, OH_Pixelmap_HdrMetadataKey(ZERO), &value);
    errorCode = OH_PixelmapNative_SetMetadata(pixelmapNative, OH_Pixelmap_HdrMetadataKey(ONE), &value);
    errorCode = OH_PixelmapNative_SetMetadata(pixelmapNative, OH_Pixelmap_HdrMetadataKey(THREE), &value);
    GTEST_LOG_(INFO) << "SetMetadata OUT";
    return errorCode;
}

Image_ErrorCode GetMetadata(OH_Pixelmap_HdrMetadataValue &value,
    OH_PixelmapNative *pixelmapNative)
{
    GTEST_LOG_(INFO) << "SetMetadata IN";
    Image_ErrorCode errorCode = IMAGE_SUCCESS;
    OH_Pixelmap_HdrMetadataValue* vv = &value;
    errorCode = OH_PixelmapNative_GetMetadata(pixelmapNative,
        OH_Pixelmap_HdrMetadataKey(ZERO), &vv);
    errorCode = OH_PixelmapNative_GetMetadata(pixelmapNative,
        OH_Pixelmap_HdrMetadataKey(ONE), &vv);
    errorCode = OH_PixelmapNative_GetMetadata(pixelmapNative,
        OH_Pixelmap_HdrMetadataKey(THREE), &vv);
    GTEST_LOG_(INFO) << "SetMetadata OUT";
    return errorCode;
}

/**
 * @tc.name: OH_PixelmapNative_SetMetadata
 * @tc.desc: OH_PixelmapNative_SetMetadata
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_SetMetadata, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_SetMetadata start";
    Image_ErrorCode errorCode = IMAGE_SUCCESS;
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_JPEG_PATH.c_str(), realPath)) {
        if (!ImageUtils::PathToRealPath(IMAGE_JPEG_PATH_TEST.c_str(), realPath)) {
            return;
        }
    }
    char filePath[bufferSize];
    if (strcpy_s(filePath, sizeof(filePath), realPath.c_str()) != EOK) {
        return;
    }
    size_t length = realPath.size();
    OH_ImageSourceNative *source = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_DecodingOptions *opts = nullptr;
    OH_PixelmapNative *pixelmap = nullptr;
    OH_DecodingOptions_Create(&opts);

    ret = OH_ImageSourceNative_CreatePixelmap(source, opts, &pixelmap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_Pixelmap_HdrMetadataValue setValue;
    CreateMetadataValue(setValue);
    DumpMetadata(setValue);
    errorCode = SetMetadata(setValue, pixelmap);
    if (errorCode == IMAGE_DMA_NOT_EXIST) {
        GTEST_LOG_(INFO) << "PixelMapNdk2Test pixelmap is not DMA";
        return;
    }
    OH_Pixelmap_HdrMetadataValue getValue;
    GetMetadata(getValue, pixelmap);
    DumpMetadata(getValue);
    EXPECT_EQ(errorCode, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_SetMetadata end";
}

/**
 * @tc.name: OH_PixelmapNative_SetGetColorSpace
 * @tc.desc: OH_PixelmapNative_SetGetColorSpace
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_SetGetColorSpace, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_SetGetColorSpace start";
    OH_PixelmapNative *pixelmap = nullptr;
    CreatePixelmapNative(&pixelmap);
    EXPECT_NE(pixelmap, nullptr);

    OH_NativeColorSpaceManager *setColorSpaceNative = nullptr;
    ColorSpaceName setColorSpaceName = SRGB_LIMIT;
    setColorSpaceNative = OH_NativeColorSpaceManager_CreateFromName(setColorSpaceName);
    Image_ErrorCode ret = OH_PixelmapNative_SetColorSpaceNative(pixelmap, setColorSpaceNative);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_NativeColorSpaceManager *getColorSpaceNative = nullptr;
    ret = OH_PixelmapNative_GetColorSpaceNative(pixelmap, &getColorSpaceNative);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    int getColorSpaceName = OH_NativeColorSpaceManager_GetColorSpaceName(getColorSpaceNative);
    EXPECT_EQ(setColorSpaceName, getColorSpaceName);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_SetGetColorSpace end";
}

/**
 * @tc.name: OH_PixelmapNative_GetByteCount
 * @tc.desc: Test OH_PixelmapNative_GetByteCount and OH_PixelmapNative_GetAllocationByteCount
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetByteCount, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetByteCount start";

    OH_Pixelmap_InitializationOptions* options = nullptr;
    OH_PixelmapInitializationOptions_Create(&options);
    OH_PixelmapInitializationOptions_SetWidth(options, 1);
    OH_PixelmapInitializationOptions_SetHeight(options, 1);
    OH_PixelmapNative* pixelmap = nullptr;
    Image_ErrorCode ret = OH_PixelmapNative_CreateEmptyPixelmap(options, &pixelmap);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t byteCount = 0; // Initialize byteCount to 0
    ret = OH_PixelmapNative_GetByteCount(pixelmap, &byteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t allocByteCount = 0; // Initialize allocByteCount to 0
    ret = OH_PixelmapNative_GetAllocationByteCount(pixelmap, &allocByteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_TRUE(byteCount == ARGB_8888_BYTES && allocByteCount >= byteCount);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetByteCount end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing
 * @tc.desc: OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing start";
    OH_PixelmapNative *srcPixelmap = nullptr;
    CreatePixelmapNative(&srcPixelmap);
    EXPECT_NE(srcPixelmap, nullptr);

    OH_Pixelmap_ImageInfo *srcImageInfoBefore = nullptr;
    OH_PixelmapImageInfo_Create(&srcImageInfoBefore);
    OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfoBefore);

    OH_PixelmapNative *dstPixelmap = nullptr;
    float scaleX = 0.5; // Scale down by 50%
    float scaleY = 0.5; // Scale down by 50%
    Image_ErrorCode ret = OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing(srcPixelmap, &dstPixelmap,
        scaleX, scaleY, OH_PixelmapNative_AntiAliasingLevel::OH_PixelmapNative_AntiAliasing_HIGH);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    EXPECT_NE(dstPixelmap, nullptr);
    OH_Pixelmap_ImageInfo *dstImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&dstImageInfo);
    OH_PixelmapNative_GetImageInfo(dstPixelmap, dstImageInfo);

    OH_Pixelmap_ImageInfo *srcImageInfoAfter = nullptr;
    OH_PixelmapImageInfo_Create(&srcImageInfoAfter);
    OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfoAfter);
    EXPECT_EQ(CompareImageInfo(srcImageInfoAfter, srcImageInfoBefore), true);

    OH_PixelmapNative *sameSrcPixelmap = nullptr;
    CreatePixelmapNative(&sameSrcPixelmap);
    EXPECT_NE(sameSrcPixelmap, nullptr);
    ret = OH_PixelmapNative_ScaleWithAntiAliasing(sameSrcPixelmap, scaleX, scaleY,
        OH_PixelmapNative_AntiAliasingLevel::OH_PixelmapNative_AntiAliasing_HIGH);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_Pixelmap_ImageInfo *sameSrcImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&sameSrcImageInfo);
    OH_PixelmapNative_GetImageInfo(sameSrcPixelmap, sameSrcImageInfo);
    EXPECT_EQ(CompareImageInfo(sameSrcImageInfo, dstImageInfo), true);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateScaledPixelMapWithAntiAliasing end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateScaledPixelMap
 * @tc.desc: OH_PixelmapNative_CreateScaledPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateScaledPixelMap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateScaledPixelMap start";
    OH_PixelmapNative *srcPixelmap = nullptr;
    CreatePixelmapNative(&srcPixelmap);
    EXPECT_NE(srcPixelmap, nullptr);

    OH_Pixelmap_ImageInfo *srcImageInfoBefore = nullptr;
    OH_PixelmapImageInfo_Create(&srcImageInfoBefore);
    OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfoBefore);

    OH_PixelmapNative *dstPixelmap = nullptr;
    float scaleX = 1.5; // Scale up by 150%
    float scaleY = 1.5; // Scale up by 150%
    Image_ErrorCode ret = OH_PixelmapNative_CreateScaledPixelMap(srcPixelmap, &dstPixelmap, scaleX, scaleY);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    EXPECT_NE(dstPixelmap, nullptr);
    OH_Pixelmap_ImageInfo *dstImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&dstImageInfo);
    OH_PixelmapNative_GetImageInfo(dstPixelmap, dstImageInfo);

    OH_Pixelmap_ImageInfo *srcImageInfoAfter = nullptr;
    OH_PixelmapImageInfo_Create(&srcImageInfoAfter);
    OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfoAfter);
    EXPECT_EQ(CompareImageInfo(srcImageInfoAfter, srcImageInfoBefore), true);

    OH_PixelmapNative *sameSrcPixelmap = nullptr;
    CreatePixelmapNative(&sameSrcPixelmap);
    EXPECT_NE(sameSrcPixelmap, nullptr);
    ret = OH_PixelmapNative_Scale(sameSrcPixelmap, scaleX, scaleY);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_Pixelmap_ImageInfo *sameSrcImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&sameSrcImageInfo);
    OH_PixelmapNative_GetImageInfo(sameSrcPixelmap, sameSrcImageInfo);
    EXPECT_EQ(CompareImageInfo(sameSrcImageInfo, dstImageInfo), true);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateScaledPixelMap end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateEmptyPixelmap
 * @tc.desc: OH_PixelmapNative_CreateEmptyPixelmap For PIXEL_FORMAT_RGBA_1010102
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateEmptyPixelmapForRGBA_1010102, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapForRGBA_1010102 start";
    OH_Pixelmap_InitializationOptions *options = nullptr;
    OH_PixelmapInitializationOptions_Create(&options);
    OH_PixelmapInitializationOptions_SetWidth(options, 512);
    OH_PixelmapInitializationOptions_SetHeight(options, 512);
    OH_PixelmapInitializationOptions_SetPixelFormat(options, PIXEL_FORMAT_RGBA_1010102);
    OH_PixelmapNative *pixelmap = nullptr;

    Image_ErrorCode ret = OH_PixelmapNative_CreateEmptyPixelmap(options, &pixelmap);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Scale(pixelmap, 2, 2); // 2: scale size
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Rotate(pixelmap, 64.0); // 64.0: rotate angle
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t byteCount = 0;
    ret = OH_PixelmapNative_GetByteCount(pixelmap, &byteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t allocByteCount = 0;
    ret = OH_PixelmapNative_GetAllocationByteCount(pixelmap, &allocByteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Flip(pixelmap, 0, 1); // 1: need to flip; 0: no need flip
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapForRGBA_1010102 end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateEmptyPixelmap
 * @tc.desc: OH_PixelmapNative_CreateEmptyPixelmap For PIXEL_FORMAT_YCBCR_P010
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateEmptyPixelmapForPIXEL_FORMAT_YCBCR_P010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapForPIXEL_FORMAT_YCBCR_P010 start";
    OH_Pixelmap_InitializationOptions *options = nullptr;
    OH_PixelmapInitializationOptions_Create(&options);
    OH_PixelmapInitializationOptions_SetWidth(options, 512);
    OH_PixelmapInitializationOptions_SetHeight(options, 512);
    OH_PixelmapInitializationOptions_SetPixelFormat(options, PIXEL_FORMAT_YCBCR_P010);
    OH_PixelmapNative *pixelmap = nullptr;

    Image_ErrorCode ret = OH_PixelmapNative_CreateEmptyPixelmap(options, &pixelmap);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Scale(pixelmap, 2, 2); // 2: scale size
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Rotate(pixelmap, 64.0); // 64.0: rotate angle
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t byteCount = 0;
    ret = OH_PixelmapNative_GetByteCount(pixelmap, &byteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t allocByteCount = 0;
    ret = OH_PixelmapNative_GetAllocationByteCount(pixelmap, &allocByteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Flip(pixelmap, 0, 1); // 1: need to flip; 0: no need flip
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapForPIXEL_FORMAT_YCBCR_P010 end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateEmptyPixelmap
 * @tc.desc: OH_PixelmapNative_CreateEmptyPixelmap For PIXEL_FORMAT_YCRCB_P010
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateEmptyPixelmapForPIXEL_FORMAT_YCRCB_P010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapForPIXEL_FORMAT_YCRCB_P010 start";
    OH_Pixelmap_InitializationOptions *options = nullptr;
    OH_PixelmapInitializationOptions_Create(&options);
    OH_PixelmapInitializationOptions_SetWidth(options, 512);
    OH_PixelmapInitializationOptions_SetHeight(options, 512);
    OH_PixelmapInitializationOptions_SetPixelFormat(options, PIXEL_FORMAT_YCRCB_P010);
    OH_PixelmapNative *pixelmap = nullptr;

    Image_ErrorCode ret = OH_PixelmapNative_CreateEmptyPixelmap(options, &pixelmap);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Scale(pixelmap, 2, 2); // 2: scale size
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Rotate(pixelmap, 64.0); // 64.0: rotate angle
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t byteCount = 0;
    ret = OH_PixelmapNative_GetByteCount(pixelmap, &byteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    uint32_t allocByteCount = 0;
    ret = OH_PixelmapNative_GetAllocationByteCount(pixelmap, &allocByteCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_PixelmapNative_Flip(pixelmap, 0, 1); // 1: need to flip; 0: no need flip
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapForPIXEL_FORMAT_YCRCB_P010 end";
}

static int32_t GetPixelBytes(PIXEL_FORMAT &pixelFormat)
{
    int pixelBytes = ZERO;
    switch (pixelFormat) {
        case PIXEL_FORMAT_BGRA_8888:
        case PIXEL_FORMAT_RGBA_8888:
        case PIXEL_FORMAT_RGBA_1010102:
            pixelBytes = FOUR;
            break;
        case PIXEL_FORMAT_ALPHA_8:
            pixelBytes = ONE;
            break;
        case PIXEL_FORMAT_RGB_888:
            pixelBytes = THREE;
            break;
        case PIXEL_FORMAT_RGB_565:
            pixelBytes = TWO;
            break;
        case PIXEL_FORMAT_RGBA_F16:
            pixelBytes = EIGHT;
            break;
        case PIXEL_FORMAT_NV21:
        case PIXEL_FORMAT_NV12:
            pixelBytes = TWO;  // perl pixel 1.5 Bytes but return int so return 2
            break;
        case PIXEL_FORMAT_YCBCR_P010:
        case PIXEL_FORMAT_YCRCB_P010:
            pixelBytes = THREE;
            break;
        default:
            return FOUR;
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

static bool CheckCreateEmptypixelmap()
{
    const int32_t size = 300;
    const int32_t dmaSize = 512;
    bool ret = true;
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_DMA);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_RGB_888, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_ALPHA_8, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_F16, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_NV21, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_NV12, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_AUTO);
    ret = ret && CreateEmptypixelmap(size, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_AUTO);
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGB_565, IMAGE_ALLOCATOR_MODE_DMA);
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGBA_8888, IMAGE_ALLOCATOR_MODE_DMA);
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_BGRA_8888, IMAGE_ALLOCATOR_MODE_DMA);
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGBA_F16, IMAGE_ALLOCATOR_MODE_DMA);
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_DMA);
    ret = ret && CreateEmptypixelmap(dmaSize, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_DMA);
    return ret;
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
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_RGBA_1010102, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, false);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_YCBCR_P010, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, false);
    ret = CreateEmptypixelmap(size, PIXEL_FORMAT_YCRCB_P010, IMAGE_ALLOCATOR_MODE_SHARED_MEMORY);
    ASSERT_EQ(ret, false);
    ASSERT_EQ(CheckCreateEmptypixelmap(), true);
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateEmptyPixelmapUsingAllocator end";
}

/**
 * @tc.name: OH_PixelmapNative_GetNativeBuffer
 * @tc.desc: OH_PixelmapNative_GetNativeBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetNativeBuffer, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetNativeBuffer start";

    Image_ErrorCode ret = OH_PixelmapNative_GetNativeBuffer(nullptr, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* pixelmap = nullptr;
    CreatePixelmapNative(&pixelmap, IMAGE_ALLOCATOR_TYPE_DMA);
    EXPECT_NE(pixelmap, nullptr);

    OH_NativeBuffer* nativeBuffer = nullptr;
    ret = OH_PixelmapNative_GetNativeBuffer(pixelmap, &nativeBuffer);
    if (ret != IMAGE_DMA_NOT_EXIST) {
        EXPECT_EQ(ret, IMAGE_SUCCESS);
        EXPECT_NE(nativeBuffer, nullptr);
    }

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetNativeBuffer end";
}

/**
 * @tc.name: OH_PixelmapNative_CreatePixelmapFromSurface
 * @tc.desc: OH_PixelmapNative_CreatePixelmapFromSurface
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreatePixelmapFromSurface, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelmapFromSurface start";

    Image_ErrorCode ret = OH_PixelmapNative_CreatePixelmapFromSurface("", 0, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* dstPixelmap = nullptr;
    ret = OH_PixelmapNative_CreatePixelmapFromSurface("1", 1, &dstPixelmap);
    EXPECT_NE(ret, IMAGE_SUCCESS);
    EXPECT_EQ(dstPixelmap, nullptr);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelmapFromSurface end";
}

/**
 * @tc.name: OH_PixelmapNative_CreatePixelmapFromNativeBuffer
 * @tc.desc: OH_PixelmapNative_CreatePixelmapFromNativeBuffer
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreatePixelmapFromNativeBuffer, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelmapFromNativeBuffer start";

    Image_ErrorCode ret = OH_PixelmapNative_CreatePixelmapFromNativeBuffer(nullptr, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* srcPixelmap = nullptr;
    CreatePixelmapNative(&srcPixelmap, IMAGE_ALLOCATOR_TYPE_DMA);
    EXPECT_NE(srcPixelmap, nullptr);

    OH_NativeBuffer* nativeBuffer = nullptr;
    ret = OH_PixelmapNative_GetNativeBuffer(srcPixelmap, &nativeBuffer);
    if (ret == IMAGE_SUCCESS && nativeBuffer != nullptr) {
        OH_PixelmapNative* dstPixelmap = nullptr;
        ret = OH_PixelmapNative_CreatePixelmapFromNativeBuffer(nativeBuffer, &dstPixelmap);
        EXPECT_EQ(ret, IMAGE_SUCCESS);
        EXPECT_NE(dstPixelmap, nullptr);

        OH_Pixelmap_ImageInfo* srcImageInfo = nullptr;
        OH_Pixelmap_ImageInfo* dstImageInfo = nullptr;
        OH_PixelmapImageInfo_Create(&srcImageInfo);
        OH_PixelmapImageInfo_Create(&dstImageInfo);
        OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfo);
        OH_PixelmapNative_GetImageInfo(dstPixelmap, dstImageInfo);
        EXPECT_EQ(CompareImageInfo(srcImageInfo, dstImageInfo), true);
    }

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreatePixelmapFromNativeBuffer end";
}

/**
 * @tc.name: OH_PixelmapNative_ReadPixelsFromArea
 * @tc.desc: OH_PixelmapNative_ReadPixelsFromArea
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_ReadPixelsFromArea, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ReadPixelsFromArea start";

    Image_ErrorCode ret = OH_PixelmapNative_ReadPixelsFromArea(nullptr, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* pixelmap = nullptr;
    CreatePixelmapNative(&pixelmap);
    EXPECT_NE(pixelmap, nullptr);

    size_t pixelsSize = 4;
    std::unique_ptr<uint8_t[]> pixels = std::make_unique<uint8_t[]>(pixelsSize);
    Image_PositionArea positionArea = {
        .pixels = pixels.get(),
        .pixelsSize = pixelsSize,
        .offset = 0,
        .stride = pixelsSize,
        .region = {0, 0, 1, 1}
    };
    ret = OH_PixelmapNative_ReadPixelsFromArea(pixelmap, &positionArea);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_ReadPixelsFromArea end";
}

/**
 * @tc.name: OH_PixelmapNative_WritePixelsToArea
 * @tc.desc: OH_PixelmapNative_WritePixelsToArea
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_WritePixelsToArea, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_WritePixelsToArea start";

    Image_ErrorCode ret = OH_PixelmapNative_WritePixelsToArea(nullptr, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* pixelmap = nullptr;
    CreatePixelmapNative(&pixelmap);
    EXPECT_NE(pixelmap, nullptr);

    size_t pixelsSize = 4;
    std::unique_ptr<uint8_t[]> pixels = std::make_unique<uint8_t[]>(pixelsSize);
    Image_PositionArea positionArea = {
        .pixels = pixels.get(),
        .pixelsSize = pixelsSize,
        .offset = 0,
        .stride = pixelsSize,
        .region = {0, 0, 1, 1}
    };
    ret = OH_PixelmapNative_WritePixelsToArea(pixelmap, &positionArea);
    EXPECT_NE(ret, IMAGE_SUCCESS); // Pixelmap is not editable

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_WritePixelsToArea end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateAlphaPixelmap
 * @tc.desc: OH_PixelmapNative_CreateAlphaPixelmap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateAlphaPixelmap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateAlphaPixelmap start";

    Image_ErrorCode ret = OH_PixelmapNative_CreateAlphaPixelmap(nullptr, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* srcPixelmap = nullptr;
    CreatePixelmapNative(&srcPixelmap);
    EXPECT_NE(srcPixelmap, nullptr);

    OH_PixelmapNative* dstPixelmap = nullptr;
    ret = OH_PixelmapNative_CreateAlphaPixelmap(srcPixelmap, &dstPixelmap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(dstPixelmap, nullptr);

    OH_Pixelmap_ImageInfo* dstImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&dstImageInfo);
    OH_PixelmapNative_GetImageInfo(dstPixelmap, dstImageInfo);
    int32_t dstPixelFormat = 0;
    OH_PixelmapImageInfo_GetPixelFormat(dstImageInfo, &dstPixelFormat);
    EXPECT_EQ(dstPixelFormat, PIXEL_FORMAT_ALPHA_8);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateAlphaPixelmap end";
}

/**
 * @tc.name: OH_PixelmapNative_Clone
 * @tc.desc: OH_PixelmapNative_Clone
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_Clone, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Clone start";

    Image_ErrorCode ret = OH_PixelmapNative_Clone(nullptr, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* srcPixelmap = nullptr;
    CreatePixelmapNative(&srcPixelmap);
    EXPECT_NE(srcPixelmap, nullptr);

    OH_PixelmapNative* dstPixelmap = nullptr;
    ret = OH_PixelmapNative_Clone(srcPixelmap, &dstPixelmap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(dstPixelmap, nullptr);

    OH_Pixelmap_ImageInfo* srcImageInfo = nullptr;
    OH_Pixelmap_ImageInfo* dstImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&srcImageInfo);
    OH_PixelmapImageInfo_Create(&dstImageInfo);
    OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfo);
    OH_PixelmapNative_GetImageInfo(dstPixelmap, dstImageInfo);
    EXPECT_EQ(CompareImageInfo(srcImageInfo, dstImageInfo), true);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_Clone end";
}

/**
 * @tc.name: OH_PixelmapNative_CreateCroppedAndScaledPixelMap
 * @tc.desc: OH_PixelmapNative_CreateCroppedAndScaledPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_CreateCroppedAndScaledPixelMap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateCroppedAndScaledPixelMap start";

    Image_ErrorCode ret = OH_PixelmapNative_CreateCroppedAndScaledPixelMap(
        nullptr, nullptr, nullptr, OH_PixelmapNative_AntiAliasing_NONE, nullptr);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* srcPixelmap = nullptr;
    CreatePixelmapNative(&srcPixelmap);
    EXPECT_NE(srcPixelmap, nullptr);

    Image_Region region = {0, 0, 1, 1};
    Image_Scale scale = {2, 2};

    OH_PixelmapNative* dstPixelmap = nullptr;
    ret = OH_PixelmapNative_CreateCroppedAndScaledPixelMap(
        srcPixelmap, &region, &scale, OH_PixelmapNative_AntiAliasing_HIGH, &dstPixelmap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(dstPixelmap, nullptr);

    OH_Pixelmap_ImageInfo* srcImageInfo = nullptr;
    OH_Pixelmap_ImageInfo* dstImageInfo = nullptr;
    OH_PixelmapImageInfo_Create(&srcImageInfo);
    OH_PixelmapImageInfo_Create(&dstImageInfo);
    OH_PixelmapNative_GetImageInfo(srcPixelmap, srcImageInfo);
    OH_PixelmapNative_GetImageInfo(dstPixelmap, dstImageInfo);
    EXPECT_EQ(CompareImageInfo(srcImageInfo, dstImageInfo), false);
    uint32_t dstWidth, dstHeight = 0;
    OH_PixelmapImageInfo_GetWidth(dstImageInfo, &dstWidth);
    OH_PixelmapImageInfo_GetHeight(dstImageInfo, &dstHeight);
    EXPECT_EQ(dstWidth, 2);
    EXPECT_EQ(dstHeight, 2);
    
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_CreateCroppedAndScaledPixelMap end";
}

/**
 * @tc.name: OH_PixelmapNative_GetUniqueId
 * @tc.desc: OH_PixelmapNative_GetUniqueId
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetUniqueId, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetUniqueId start";

    uint32_t uniqueId = 0;
    Image_ErrorCode ret = OH_PixelmapNative_GetUniqueId(nullptr, &uniqueId);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* pixelmap = nullptr;
    CreatePixelmapNative(&pixelmap);
    EXPECT_NE(pixelmap, nullptr);

    ret = OH_PixelmapNative_GetUniqueId(pixelmap, &uniqueId);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(uniqueId, 0);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetUniqueId end";
}

/**
 * @tc.name: OH_PixelmapNative_IsReleased
 * @tc.desc: OH_PixelmapNative_IsReleased
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_IsReleased, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_IsReleased start";

    bool released = false;
    Image_ErrorCode ret = OH_PixelmapNative_IsReleased(nullptr, &released);
    EXPECT_NE(ret, IMAGE_SUCCESS);

    OH_PixelmapNative* pixelmap = nullptr;
    CreatePixelmapNative(&pixelmap);
    EXPECT_NE(pixelmap, nullptr);

    ret = OH_PixelmapNative_IsReleased(pixelmap, &released);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(released, false);

    OH_PixelmapNative_Release(pixelmap);
    ret = OH_PixelmapNative_IsReleased(pixelmap, &released);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(released, true);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_IsReleased end";
}
}
}
