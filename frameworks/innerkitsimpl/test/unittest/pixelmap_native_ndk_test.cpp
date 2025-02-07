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

using namespace testing::ext;
using namespace OHOS::Media;
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

/**
 * @tc.name: OH_PixelmapNative_GetArgbPixels_Test001
 * @tc.desc: Test OH_PixelmapNative_GetArgbPixels with valid inputs
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_GetArgbPixels_Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_GetArgbPixels_Test001 start";

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
    int32_t srcpixelFormat = 0;
    OH_PixelmapInitializationOptions_SetSrcPixelFormat(ops, 1);
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

/**
 * @tc.name: OH_PixelmapNative_SetGetColorSpace
 * @tc.desc: OH_PixelmapNative_SetGetColorSpace
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapNdk2Test, OH_PixelmapNative_SetGetColorSpace, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_SetGetColorSpace start";
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

    OH_NativeColorSpaceManager *setColorSpaceNative = nullptr;
    ColorSpaceName setColorSpaceName = SRGB_LIMIT;
    setColorSpaceNative = OH_NativeColorSpaceManager_CreateFromName(setColorSpaceName);
    ret = OH_PixelmapNative_SetColorSpaceNative(pixelmap, setColorSpaceNative);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    OH_NativeColorSpaceManager *getColorSpaceNative = nullptr;
    ret = OH_PixelmapNative_GetColorSpaceNative(pixelmap, &getColorSpaceNative);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    int getColorSpaceName = OH_NativeColorSpaceManager_GetColorSpaceName(getColorSpaceNative);
    EXPECT_EQ(setColorSpaceName, getColorSpaceName);

    GTEST_LOG_(INFO) << "PixelMapNdk2Test: OH_PixelmapNative_SetGetColorSpace end";
}
}
}
