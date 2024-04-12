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

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
class PixelMapNdk2Test : public testing::Test {
public:
    PixelMapNdk2Test() {}
    ~PixelMapNdk2Test() {}
};

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

}
}
