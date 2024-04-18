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
#include "common_utils.h"

#include "image_source_native.h"
#include "image_source_native_impl.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
class ImagSourceNdk2Test : public testing::Test {
public:
    ImagSourceNdk2Test() {}
    ~ImagSourceNdk2Test() {}
};

/**
 * @tc.name: OH_ImageSourceInfo_Create
 * @tc.desc: test OH_ImageSourceInfo_Create
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceInfo_Create, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_Create start";
    OH_ImageSource_Info *ops = nullptr;
    Image_ErrorCode ret = OH_ImageSourceInfo_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_Create end";
}

/**
 * @tc.name: OH_ImageSourceInfo_GetWidth
 * @tc.desc: test OH_ImageSourceInfo_GetWidth
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceInfo_GetWidth, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetWidth start";
    OH_ImageSource_Info *ops = nullptr;
    uint32_t *width = nullptr;
    Image_ErrorCode ret = OH_ImageSourceInfo_GetWidth(ops, width);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetWidth end";
}

/**
 * @tc.name: OH_ImageSourceInfo_GetHeight
 * @tc.desc: test OH_ImageSourceInfo_GetHeight
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceInfo_GetHeight, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetHeight start";
    OH_ImageSource_Info *ops = nullptr;
    uint32_t *width = nullptr;
    Image_ErrorCode ret = OH_ImageSourceInfo_GetHeight(ops, width);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetHeight end";
}

/**
 * @tc.name: OH_ImageSourceInfo_Release
 * @tc.desc: test OH_ImageSourceInfo_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceInfo_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_Release start";
    OH_ImageSource_Info *ops = nullptr;
    Image_ErrorCode ret = OH_ImageSourceInfo_Release(ops);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_Release end";
}

/**
 * @tc.name: OH_DecodingOptions_Create
 * @tc.desc: test OH_DecodingOptions_Create
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_DecodingOptions_Create, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_DecodingOptions_Create start";
    OH_DecodingOptions *ops = nullptr;
    Image_ErrorCode ret = OH_DecodingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_DecodingOptions_Create end";
}

/**
 * @tc.name: OH_ImageSource_DecodingOptionsSetGetPixelFormat
 * @tc.desc: test OH_ImageSource_DecodingOptionsSetGetPixelFormat
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSource_DecodingOptionsSetGetPixelFormat, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetPixelFormat start";
    OH_DecodingOptions *ops = nullptr;
    Image_ErrorCode ret = IMAGE_UNKNOWN_ERROR;
    int32_t pixelFormat = 0;
    ret = OH_DecodingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_SetPixelFormat(ops, 1);
    OH_DecodingOptions_GetPixelFormat(ops, &pixelFormat);
    ASSERT_EQ(pixelFormat, 1);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetPixelFormat end";
}

/**
 * @tc.name: OH_ImageSource_DecodingOptionsSetGetIndex
 * @tc.desc: test OH_ImageSource_DecodingOptionsSetGetIndex
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSource_DecodingOptionsSetGetIndex, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetIndex start";
    OH_DecodingOptions *ops = nullptr;
    Image_ErrorCode ret = IMAGE_UNKNOWN_ERROR;
    uint32_t index = 0;
    ret = OH_DecodingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_SetIndex(ops, 1);
    OH_DecodingOptions_GetIndex(ops, &index);
    ASSERT_EQ(index, 1);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetIndex end";
}

/**
 * @tc.name: OH_ImageSource_DecodingOptionsSetGetRotate
 * @tc.desc: test OH_ImageSource_DecodingOptionsSetGetRotate
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSource_DecodingOptionsSetGetRotate, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetRotate start";
    OH_DecodingOptions *ops = nullptr;
    Image_ErrorCode ret = IMAGE_UNKNOWN_ERROR;
    float rotate = 0;
    ret = OH_DecodingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_SetRotate(ops, 1);
    OH_DecodingOptions_GetRotate(ops, &rotate);
    ASSERT_EQ(rotate, 1);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetRotate end";
}

/**
 * @tc.name: OH_ImageSource_DecodingOptionsSetGetDesiredSize
 * @tc.desc: test OH_ImageSource_DecodingOptionsSetGetDesiredSize
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSource_DecodingOptionsSetGetDesiredSize, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetDesiredSize start";
    OH_DecodingOptions *ops = nullptr;
    Image_ErrorCode ret = IMAGE_UNKNOWN_ERROR;
    Image_Size desiredSize = {0, 0};
    Image_Size desiredSize2 = {1, 2};
    ret = OH_DecodingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_SetDesiredSize(ops, &desiredSize2);
    OH_DecodingOptions_GetDesiredSize(ops, &desiredSize);
    ASSERT_EQ(desiredSize.width, desiredSize2.width);
    ASSERT_EQ(desiredSize.height, desiredSize2.height);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetDesiredSize end";
}

/**
 * @tc.name: OH_ImageSource_DecodingOptionsSetGetDesiredRegion
 * @tc.desc: test OH_ImageSource_DecodingOptionsSetGetDesiredRegion
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSource_DecodingOptionsSetGetDesiredRegion, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetDesiredRegion start";
    OH_DecodingOptions *ops = nullptr;
    Image_ErrorCode ret = IMAGE_UNKNOWN_ERROR;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {1, 2, 3, 4};
    ret = OH_DecodingOptions_Create(&ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 1);
    ASSERT_EQ(desiredRegion.y, 2);
    ASSERT_EQ(desiredRegion.width, 3);
    ASSERT_EQ(desiredRegion.height, 4);
    ret = OH_DecodingOptions_Release(ops);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSource_DecodingOptionsSetGetDesiredRegion end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreateFromUri
 * @tc.desc: test OH_ImageSourceNative_CreateFromUri
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreateFromUri, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromUri start";
    OH_ImageSourceNative *imageSource = nullptr;
    char *uri = nullptr;
    size_t uriSize = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(uri, uriSize, &imageSource);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromUri end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreateFromFd
 * @tc.desc: test OH_ImageSourceNative_CreateFromFd
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreateFromFd, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromFd start";
    OH_ImageSourceNative *imageSource = nullptr;
    int32_t fd = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromFd(fd, &imageSource);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromFd end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreateFromData
 * @tc.desc: test OH_ImageSourceNative_CreateFromData
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreateFromData, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromData start";
    OH_ImageSourceNative *imageSource = nullptr;
    uint8_t* data = nullptr;
    size_t dataSize = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromData(data, dataSize, &imageSource);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromData end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreateFromRawFile002
 * @tc.desc: test OH_ImageSourceNative_CreateFromRawFile
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreateFromRawFile002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromRawFile002 start";
    OH_ImageSourceNative *imageSource = nullptr;
    RawFileDescriptor *rawFile = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromRawFile(rawFile, &imageSource);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromRawFile002 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmap
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmap
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmap, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmap start";
    OH_ImageSourceNative *imageSource = nullptr;
    OH_DecodingOptions* ops = nullptr;
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmap end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapList
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapList
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapList, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapList start";
    OH_DecodingOptions *ops = nullptr;
    OH_ImageSourceNative *imageSource = nullptr;
    OH_PixelmapNative** resVecPixMap = nullptr;
    size_t outSize = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapList(imageSource, ops, resVecPixMap, outSize);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapList end";
}

/**
 * @tc.name: OH_ImageSourceNative_GetDelayTimeList
 * @tc.desc: test OH_ImageSourceNative_GetDelayTimeList
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetDelayTimeList, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetDelayTimeList start";
    OH_ImageSourceNative *imageSource = nullptr;
    int32_t* delayTimeList = nullptr;
    size_t size = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_GetDelayTimeList(imageSource, delayTimeList, size);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetDelayTimeList end";
}

/**
 * @tc.name: OH_ImageSourceNative_GetImageInfo
 * @tc.desc: test OH_ImageSourceNative_GetImageInfo
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetImageInfo, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImageInfo start";
    OH_ImageSourceNative *imageSource = nullptr;
    int32_t index = 0;
    OH_ImageSource_Info* info = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_GetImageInfo(imageSource, index, info);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImageInfo end";
}

/**
 * @tc.name: OH_ImageSourceNative_GetImageProperty
 * @tc.desc: test OH_ImageSourceNative_GetImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetImageProperty, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImageProperty start";
    OH_ImageSourceNative *imageSource = nullptr;
    Image_String* key = nullptr;
    Image_String* value = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_GetImageProperty(imageSource, key, value);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImageProperty end";
}

/**
 * @tc.name: OH_ImageSourceNative_ModifyImageProperty
 * @tc.desc: test OH_ImageSourceNative_ModifyImageProperty
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_ModifyImageProperty, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_ModifyImageProperty start";
    OH_ImageSourceNative *imageSource = nullptr;
    Image_String* key = nullptr;
    Image_String* value = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_ModifyImageProperty(imageSource, key, value);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_ModifyImageProperty end";
}

/**
 * @tc.name: OH_ImageSourceNative_GetFrameCount
 * @tc.desc: test OH_ImageSourceNative_GetFrameCount
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetFrameCount, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetFrameCount start";
    OH_ImageSourceNative *imageSource = nullptr;
    uint32_t* res = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_GetFrameCount(imageSource, res);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetFrameCount end";
}

/**
 * @tc.name: OH_ImageSourceNative_Release
 * @tc.desc: test OH_ImageSourceNative_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_Release, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_Release start";
    OH_ImageSourceNative *imageSource = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_Release(imageSource);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_Release end";
}

}
}
