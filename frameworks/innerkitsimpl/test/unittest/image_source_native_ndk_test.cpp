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
#include "image_utils.h"
#include "pixelmap_native.h"
#include "securec.h"
#include "image_mime_type.h"

using namespace testing::ext;

struct OH_ImageSource_Info {
    int32_t width = 0;
    int32_t height = 0;
    bool isHdr = false;
    Image_MimeType mimeType;
};

namespace OHOS {
namespace Media {
class ImagSourceNdk2Test : public testing::Test {
public:
    ImagSourceNdk2Test() {}
    ~ImagSourceNdk2Test() {}
};

static constexpr int32_t TestLength = 2;
static const std::string IMAGE_JPEG_PATH_TEST = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_picture.jpg";
static const std::string IMAGE_JPEG_HDR_PATH = "/data/local/tmp/image/test_jpeg_hdr.jpg";
static const std::string IMAGE_HEIF_PATH = "/data/local/tmp/image/test_allocator_heif.heic";
static const std::string IMAGE_HEIF_HDR_PATH = "/data/local/tmp/image/test_heif_hdr.heic";
static const std::string IMAGE_PNG_PATH = "/data/local/tmp/image/test_picture_png.png";
static const std::string IMAGE_GIF_MOVING_PATH = "/data/local/tmp/image/moving_test.gif";
static const std::string IMAGE_GIF_LARGE_PATH = "/data/local/tmp/image/fake_large_size_test.gif";  // 50000x50000
static const std::string IMAGE_GIF_INCOMPLETE_PATH = "/data/local/tmp/image/incomplete_test.gif";
static const size_t IMAGE_GIF_MOVING_FRAME_COUNT = 3;
static const size_t IMAGE_GIF_INCOMPLETE_FRAME_INDEX = 16;
static const int32_t MAX_BUFFER_SIZE = 256;
static const int32_t INVALID_INDEX = 1000;

static OH_ImageSourceNative *CreateImageSourceNative(std::string IMAGE_PATH)
{
    std::string realPath;
    if (!ImageUtils::PathToRealPath(IMAGE_PATH.c_str(), realPath) || realPath.empty()) {
        return nullptr;
    }
    char filePath[MAX_BUFFER_SIZE];
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
 * @tc.name: OH_ImageSourceNative_CreateFromDataWithUserBuffer001
 * @tc.desc: test OH_ImageSourceNative_CreateFromDataWithUserBuffer001
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreateFromDataWithUserBuffer001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromDataWithUserBuffer001 start";
    OH_ImageSourceNative *imageSource = nullptr;
    uint8_t* data = nullptr;
    size_t dataSize = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromDataWithUserBuffer(data, dataSize, &imageSource);
    ASSERT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromDataWithUserBuffer001 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreateFromDataWithUserBuffer002
 * @tc.desc: test OH_ImageSourceNative_CreateFromDataWithUserBuffer002
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreateFromDataWithUserBuffer002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromDataWithUserBuffer002 start";
    void *data = malloc(100);
    size_t dataSize = 100;
    memset_s(data, dataSize, 0, dataSize);
    OH_ImageSourceNative *imageSource = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromDataWithUserBuffer((uint8_t*)data, dataSize, &imageSource);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(imageSource, nullptr);
    if (imageSource != nullptr) {
        ret = OH_ImageSourceNative_Release(imageSource);
    }
    free(data);
    data = nullptr;
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreateFromDataWithUserBuffer002 end";
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
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest001
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest001
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest001 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {1920, 1080, 1920, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 1920);
    ASSERT_EQ(desiredRegion.y, 1080);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest001 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest002
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest002
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest002 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {0, 0, 1920, 2160};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 0);
    ASSERT_EQ(desiredRegion.y, 0);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 2160);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest002 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest003
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest003
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest003 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {0, 0, 3840, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 0);
    ASSERT_EQ(desiredRegion.y, 0);
    ASSERT_EQ(desiredRegion.width, 3840);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest003 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest004
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest004
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest004 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {1920, 1080, 3840, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 1920);
    ASSERT_EQ(desiredRegion.y, 1080);
    ASSERT_EQ(desiredRegion.width, 3840);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest004 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest005
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest005
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest005 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {3840, 2160, 1920, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 3840);
    ASSERT_EQ(desiredRegion.y, 2160);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest005 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest006
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest006
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest006 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {1920, 1080, 1920, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 1920);
    ASSERT_EQ(desiredRegion.y, 1080);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest006 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest007
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest007
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest007 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {0, 0, 1920, 2160};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 0);
    ASSERT_EQ(desiredRegion.y, 0);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 2160);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest007 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest008
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest008
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest008 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {0, 0, 3840, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 0);
    ASSERT_EQ(desiredRegion.y, 0);
    ASSERT_EQ(desiredRegion.width, 3840);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest008 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest009
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest009
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest009 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {1920, 1080, 3840, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 1920);
    ASSERT_EQ(desiredRegion.y, 1080);
    ASSERT_EQ(desiredRegion.width, 3840);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest009 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest010
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest010
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest010 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {3840, 2160, 1920, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 3840);
    ASSERT_EQ(desiredRegion.y, 2160);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest010 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest011
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest011
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest011 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {960, 540, 1920, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 960);
    ASSERT_EQ(desiredRegion.y, 540);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest011 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest012
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest012
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest012 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {960, 540, 1920, 1080};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 960);
    ASSERT_EQ(desiredRegion.y, 540);
    ASSERT_EQ(desiredRegion.width, 1920);
    ASSERT_EQ(desiredRegion.height, 1080);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest012 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest013
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest013
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest013 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {0, 0, 3840, 2160};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 0);
    ASSERT_EQ(desiredRegion.y, 0);
    ASSERT_EQ(desiredRegion.width, 3840);
    ASSERT_EQ(desiredRegion.height, 2160);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest013 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapTest014
 * @tc.desc: test OH_ImageSourceNative_CreatePixelmapTest014
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest014 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_PNG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* ops = nullptr;
    Image_Region desiredRegion = {0, 0, 0, 0};
    Image_Region desiredRegion2 = {0, 0, 3840, 2160};
    OH_DecodingOptions_Create(&ops);
    OH_DecodingOptions_SetDesiredRegion(ops, &desiredRegion2);
    OH_DecodingOptions_GetDesiredRegion(ops, &desiredRegion);
    ASSERT_EQ(desiredRegion.x, 0);
    ASSERT_EQ(desiredRegion.y, 0);
    ASSERT_EQ(desiredRegion.width, 3840);
    ASSERT_EQ(desiredRegion.height, 2160);
    OH_DecodingOptions_SetCropAndScaleStrategy(ops, 2);
    OH_PixelmapNative* resPixMap = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmap(imageSource, ops, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(ops);
    OH_PixelmapNative_Release(resPixMap);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePixelmapTest014 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest001
 * @tc.desc: Test create Pixelmap use DMA.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest001, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest002
 * @tc.desc: Test create Pixelmap use SHARE_MEMORY.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest002, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest003
 * @tc.desc: Test create Pixelmap if source is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest003, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = nullptr;
    OH_DecodingOptions* opts = nullptr;
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest004
 * @tc.desc: Test create Pixelmap if index is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest004, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    uint32_t tempIndex = INVALID_INDEX;
    Image_ErrorCode ret = OH_DecodingOptions_SetIndex(opts, tempIndex);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_DECODE_FAILED);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest005
 * @tc.desc: Test the creation of a pixelmap using AUTO allocator for JPEG image format, expecting success.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest005, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_AUTO;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest006
 * @tc.desc: Test the creation of a pixelmap using DMA allocator with invalid decoding options (nullptr) for JPEG image
 *           format, expecting IMAGE_BAD_PARAMETER error.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest006, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions* opts = nullptr;
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest007
 * @tc.desc: Test the creation of a pixelmap using DMA allocator, with NV21 pixel format for HEIF image format,
 *           expecting success.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest007, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest008
 * @tc.desc: Test the creation of a pixelmap using DMA allocator, with RGBA_8888 pixel format for HEIF image format,
 *           expecting success.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest008, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest009
 * @tc.desc: Test the creation of a pixelmap using shared memory allocator, with NV21 pixel format for HEIF image
 *           format, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest009, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest010
 * @tc.desc: Test the creation of a pixelmap using shared memory allocator, with RGBA_8888 pixel format for HEIF image
 *           format, expecting success.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest010, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest011
 * @tc.desc: Test the creation of a pixelmap using shared memory allocator, with RGBA_8888 pixel format and HDR dynamic
 *           range, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest011, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest012
 * @tc.desc: Test the creation of a pixelmap using shared memory allocator, with RGBA_8888 pixel format and auto
 *           dynamic range, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest012, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest013
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with RGBA_8888 pixel format and HDR dynamic range,
 *           expecting successful operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest013, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest014
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with RGBA_8888 pixel format and auto dynamic range,
 *           expecting successful operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest014, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest015
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with NV21 pixel format and HDR dynamic range,
 *           expecting successful operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest015, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest016
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with NV21 pixel format and auto dynamic range,
 *           expecting successful operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest016, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest017
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with NV21 pixel format and HDR dynamic
 *           range, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest017, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest018
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with NV21 pixel format and auto
 *           dynamic range, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest018, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest019
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with RGBA_8888 pixel format and HDR
 *           dynamic range, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest019, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest020
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with RGBA_8888 pixel format and auto
 *           dynamic range, expecting unsupported operation.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest020, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest021
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with RGBA_8888 pixel format and HDR dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest021, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest022
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with RGBA_8888 pixel format and auto dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest022, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_RGBA_8888);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest023
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with NV21 pixel format and HDR dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest023, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest024
 * @tc.desc: Test the creation of a pixelmap using a DMA allocator, with NV21 pixel format and auto dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest024, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest025
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with HDR dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest025, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    auto ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest026
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with NV21 pixel format and auto
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest026, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_HEIF_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    Image_ErrorCode ret = OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_NV21);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_AUTO);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
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

/**
 * @tc.name: OH_ImageSourceInfo_GetMimeType001
 * @tc.desc: Verify that OH_ImageSourceInfo_GetMimeType correctly handles null input parameters by returning
 *           IMAGE_SOURCE_INVALID_PARAMETER when either info or mimeType output pointer is null.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceInfo_GetMimeType001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetMimeType001 start";
    OH_ImageSource_Info *info1 = nullptr;
    Image_ErrorCode ret = OH_ImageSourceInfo_Create(&info1);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(info1, nullptr);
    OH_ImageSource_Info *info2 = nullptr;

    Image_MimeType mimeType1;
    Image_MimeType *mimeType2 = nullptr;
    ret = OH_ImageSourceInfo_GetMimeType(info2, &mimeType1);
    EXPECT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);
    ret = OH_ImageSourceInfo_GetMimeType(info1, mimeType2);
    EXPECT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);
    ret = OH_ImageSourceInfo_GetMimeType(info2, mimeType2);
    EXPECT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);

    ret = OH_ImageSourceInfo_Release(info1);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetMimeType001 end";
}

/**
 * @tc.name: OH_ImageSourceInfo_GetMimeType002
 * @tc.desc: Verify that OH_ImageSourceInfo_GetMimeType can correctly get the MIME type (JPEG in this case)
 *           from an image source.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceInfo_GetMimeType002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetMimeType002 start";
    size_t length = IMAGE_JPEG_PATH_TEST.size();
    char filePath[length + 1];
    strcpy_s(filePath, sizeof(filePath), IMAGE_JPEG_PATH_TEST.c_str());

    OH_ImageSourceNative *source = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(source, nullptr);

    OH_ImageSource_Info *info = nullptr;
    ret = OH_ImageSourceInfo_Create(&info);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    int32_t index = 0;
    ret = OH_ImageSourceNative_GetImageInfo(source, index, info);
    ASSERT_EQ(ret, IMAGE_SUCCESS);

    Image_MimeType mimeType;
    ret = OH_ImageSourceInfo_GetMimeType(info, &mimeType);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(mimeType.data, nullptr);
    EXPECT_EQ(strcmp(mimeType.data, IMAGE_JPEG_FORMAT.c_str()), 0);
    ret = OH_ImageSourceNative_Release(source);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_ImageSourceInfo_Release(info);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceInfo_GetMimeType002 end";
}

/**
 * @tc.name: OH_DecodingOptionsForPicture_CreateTest001
 * @tc.desc: Tests the creation of decoding options for a picture.
 *           The test checks if the decoding options are created successfully.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_DecodingOptionsForPicture_CreateTest001, TestSize.Level1)
{
    OH_DecodingOptionsForPicture *options = nullptr;
    Image_ErrorCode ret;
    ret = OH_DecodingOptionsForPicture_Create(&options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptionsForPicture_Release(options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_DecodingOptionsForPicture_ReleaseTest001
 * @tc.desc: test OH_DecodingOptionsForPicture_Release with a null pointer.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_DecodingOptionsForPicture_ReleaseTest001, TestSize.Level3)
{
    Image_ErrorCode ret = OH_DecodingOptionsForPicture_Release(nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPicturesTest001
 * @tc.desc: Tests getting the desired auxiliary pictures from decoding options.
 *           The test checks if the set and get functions work correctly.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPicturesTest001, TestSize.Level1)
{
    OH_DecodingOptionsForPicture *options = nullptr;
    Image_ErrorCode ret = OH_DecodingOptionsForPicture_Create(&options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    size_t srcLength = TestLength;
    Image_AuxiliaryPictureType srcAuxTypeList[srcLength];
    srcAuxTypeList[0] = AUXILIARY_PICTURE_TYPE_GAINMAP;
    srcAuxTypeList[1] = AUXILIARY_PICTURE_TYPE_DEPTH_MAP;
    OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPictures(options, srcAuxTypeList, srcLength);
    Image_AuxiliaryPictureType *dstAuxTypeList = nullptr;
    size_t dstLength = 0;
    ret = OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPictures(options, &dstAuxTypeList, &dstLength);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(dstAuxTypeList, nullptr);
    EXPECT_EQ(srcLength, dstLength);
    for (size_t index = 0; index < srcLength; index++) {
        EXPECT_EQ(srcAuxTypeList[index], dstAuxTypeList[index]);
    }
    delete[] dstAuxTypeList;
    ret = OH_DecodingOptionsForPicture_Release(options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPicturesTest002
 * @tc.desc: test OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPictures with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPicturesTest002, TestSize.Level3)
{
    Image_ErrorCode ret = OH_DecodingOptionsForPicture_GetDesiredAuxiliaryPictures(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPicturesTest001
 * @tc.desc: test OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPictures with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPicturesTest001, TestSize.Level3)
{
    Image_ErrorCode ret = OH_DecodingOptionsForPicture_SetDesiredAuxiliaryPictures(nullptr, nullptr, 0);
    EXPECT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureTest001
 * @tc.desc: test OH_ImageSourceNative_CreatePicture with null pointers.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureTest001, TestSize.Level3)
{
    OH_ImageSourceNative *source = nullptr;
    OH_DecodingOptionsForPicture *options = nullptr;
    OH_PictureNative **picture = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePicture(source, options, picture);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureTest002
 * @tc.desc: Tests creating an image from a raw buffer and then extracting a picture from it.
 *           The test checks if the creation and release of resources are successful
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureTest002, TestSize.Level1)
{
    size_t length = IMAGE_JPEG_PATH.size();
    char filePath[length + 1];
    strcpy_s(filePath, sizeof(filePath), IMAGE_JPEG_PATH.c_str());

    OH_ImageSourceNative *source = nullptr;
    OH_DecodingOptionsForPicture *options = nullptr;
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreateFromUri(filePath, length, &source);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(source, nullptr);

    ret = OH_DecodingOptionsForPicture_Create(&options);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);

    ret = OH_ImageSourceNative_CreatePicture(source, options, &picture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_NE(picture, nullptr);

    ret = OH_ImageSourceNative_Release(source);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ret = OH_DecodingOptionsForPicture_Release(options);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_PictureNative_Release(picture);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
}

/**
 * @tc.name: ImageRegionDecode001
 * @tc.desc: Test Region decode, CropAndScaleStrategy is DEFAULT, Showing the original image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode001, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 1920, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode002
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing the original image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode002, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 1000, 1000};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode003
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing the left half image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode003, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 500, 1000};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode004
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing the top half image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode004, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 1000, 500};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode005
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing the right bottom image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode005, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {500, 500, 500, 500};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode006
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing NULL.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode006, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {500, 500, 1000, 500};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_NE(ret, IMAGE_SUCCESS);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode007
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing NULL.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode007, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {1000, 1000, 500, 500};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_NE(ret, IMAGE_SUCCESS);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode008
 * @tc.desc: Test Region decode, CropAndScaleStrategy is SCALE_FIRST, Showing the middle quarter image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode008, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {250, 250, 500, 500};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 1;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode009
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing the original image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode009, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 3840, 2160};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode010
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing the left half image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode010, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 1920, 2160};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode011
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing the top half image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode011, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 3840, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode012
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing the right bottom image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode012, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {1920, 1080, 1920, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode013
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing NULL.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode013, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {1920, 1080, 3840, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_NE(ret, IMAGE_SUCCESS);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode014
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing NULL.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode014, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {3840, 2160, 1920, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_NE(ret, IMAGE_SUCCESS);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode015
 * @tc.desc: Test Region decode, CropAndScaleStrategy is CROP_FIRST, Showing the middle quarter image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode015, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {960, 540, 1920, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 2;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1000, 1000};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: ImageRegionDecode016
 * @tc.desc: Test Region decode, CropAndScaleStrategy is OTHER, Showing the original image.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, ImageRegionDecode016, TestSize.Level3)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_Region desiredRegion = {0, 0, 1920, 1080};
    OH_DecodingOptions_SetDesiredRegion(opts, &desiredRegion);
    int32_t cropAndScaleStrategy = 3;
    OH_DecodingOptions_SetCropAndScaleStrategy(opts, cropAndScaleStrategy);
    Image_Size desiredSize = {1920, 1080};
    OH_DecodingOptions_SetDesiredSize(opts, &desiredSize);
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_GetSupportedFormatTest001
 * @tc.desc: Verify ImageSource can retrieve supported formats with valid data structure.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetSupportedFormatTest001, TestSize.Level3)
{
    Image_MimeType* supportedFormat = nullptr;
    size_t length = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_GetSupportedFormats(&supportedFormat, &length);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    for (size_t i = 0; i < length; i++) {
        EXPECT_NE(supportedFormat[i].data, nullptr);
        EXPECT_NE(supportedFormat[i].size, 0);
    }
    EXPECT_NE(length, 0);
}

/**
 * @tc.name: OH_ImageSourceNative_GetSupportedFormatTest002
 * @tc.desc: Verify null parameter validation for GetSupportedFormat API.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetSupportedFormatTest002, TestSize.Level3)
{
    Image_MimeType* supportedFormat = nullptr;
    size_t length = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_GetSupportedFormats(nullptr, &length);
    EXPECT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);
    ret = OH_ImageSourceNative_GetSupportedFormats(&supportedFormat, nullptr);
    EXPECT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);
    ret = OH_ImageSourceNative_GetSupportedFormats(nullptr, nullptr);
    EXPECT_EQ(ret, IMAGE_SOURCE_INVALID_PARAMETER);
}

/**
 * @tc.name: OH_ImageSourceNative_GetImagePropertyWithNullTest001
 * @tc.desc: test OH_ImageSourceNative_GetImagePropertyWithNull with null pointer
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetImagePropertyWithNullTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImagePropertyWithNullTest001 start";
    OH_ImageSourceNative *imageSource = nullptr;
    Image_String* key = nullptr;
    Image_String* value = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_GetImagePropertyWithNull(imageSource, key, value);
    ASSERT_NE(ret, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImagePropertyWithNullTest001 end";
}

/**
 * @tc.name: OH_ImageSourceNative_GetImagePropertyWithNullTest002
 * @tc.desc: test OH_ImageSourceNative_GetImagePropertyWithNull with right value
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_GetImagePropertyWithNullTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImagePropertyWithNullTest002 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);
    Image_String key;
    Image_String value;
    key.data = const_cast<char*>(OHOS_IMAGE_PROPERTY_EXIF_VERSION);
    key.size = strlen(OHOS_IMAGE_PROPERTY_EXIF_VERSION);
    value.data = nullptr;
    value.size = 100;
    Image_ErrorCode ret = OH_ImageSourceNative_GetImagePropertyWithNull(imageSource, &key, &value);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    if (ret == IMAGE_SUCCESS) {
        free(value.data);
    }
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_GetImagePropertyWithNullTest002 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex001
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex001
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex001 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_GIF_MOVING_PATH);
    ASSERT_NE(imageSource, nullptr);
    uint32_t frameCount = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_GetFrameCount(imageSource, &frameCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_EQ(frameCount, IMAGE_GIF_MOVING_FRAME_COUNT);
    OH_PictureNative *picture = nullptr;

    ret = OH_ImageSourceNative_CreatePictureAtIndex(imageSource, 0, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_PictureMetadata *gifMetadata = nullptr;
    ret = OH_PictureNative_GetMetadata(picture, GIF_METADATA, &gifMetadata);
    EXPECT_EQ(ret, IMAGE_SUCCESS);

    Image_String keyDelayTime;
    keyDelayTime.data = strdup(IMAGE_PROPERTY_GIF_DELAY_TIME);
    keyDelayTime.size = strlen(keyDelayTime.data);
    Image_String valueDelayTime;
    ret = OH_PictureMetadata_GetProperty(gifMetadata, &keyDelayTime, &valueDelayTime);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(strncmp(valueDelayTime.data, "70", valueDelayTime.size), 0);

    Image_String keyDisposalType;
    keyDisposalType.data = strdup(IMAGE_PROPERTY_GIF_DISPOSAL_TYPE);
    keyDisposalType.size = strlen(keyDisposalType.data);
    Image_String valueDisposalType;
    ret = OH_PictureMetadata_GetProperty(gifMetadata, &keyDisposalType, &valueDisposalType);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_EQ(strncmp(valueDisposalType.data, "1", valueDisposalType.size), 0);

    OH_ImageSourceNative_Release(imageSource);
    OH_PictureNative_Release(picture);
    OH_PictureMetadata_Release(gifMetadata);
    free(keyDelayTime.data);
    free(keyDisposalType.data);
    delete[] valueDelayTime.data;
    delete[] valueDisposalType.data;
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex001 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex002
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex002
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex002 start";
    OH_ImageSourceNative *imageSource = nullptr;
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePictureAtIndex(imageSource, 0, &picture);
    EXPECT_EQ(ret, IMAGE_BAD_SOURCE);
    OH_ImageSourceNative_Release(imageSource);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex002 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex003
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex003
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex003 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_GIF_MOVING_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_PictureNative **picture = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePictureAtIndex(imageSource, 0, picture);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_OPTIONS);
    OH_ImageSourceNative_Release(imageSource);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex003 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex004
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex004
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex004 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_PATH_TEST);
    ASSERT_NE(imageSource, nullptr);
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePictureAtIndex(imageSource, 0, &picture);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_MIMETYPE);
    OH_ImageSourceNative_Release(imageSource);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex004 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex005
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex005
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex005 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_GIF_MOVING_PATH);
    ASSERT_NE(imageSource, nullptr);
    uint32_t frameCount = 0;
    Image_ErrorCode ret = OH_ImageSourceNative_GetFrameCount(imageSource, &frameCount);
    ASSERT_EQ(ret, IMAGE_SUCCESS);
    ASSERT_EQ(frameCount, IMAGE_GIF_MOVING_FRAME_COUNT);
    OH_PictureNative *picture = nullptr;
    ret = OH_ImageSourceNative_CreatePictureAtIndex(imageSource, frameCount, &picture);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_OPTIONS);
    OH_ImageSourceNative_Release(imageSource);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex005 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex006
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex006
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex006 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_GIF_LARGE_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePictureAtIndex(imageSource, 0, &picture);
    EXPECT_EQ(ret, IMAGE_SOURCE_TOO_LARGE);
    OH_ImageSourceNative_Release(imageSource);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex006 end";
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePictureAtIndex007
 * @tc.desc: test OH_ImageSourceNative_CreatePictureAtIndex007
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePictureAtIndex007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex007 start";
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_GIF_INCOMPLETE_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_PictureNative *picture = nullptr;
    Image_ErrorCode ret =
        OH_ImageSourceNative_CreatePictureAtIndex(imageSource, IMAGE_GIF_INCOMPLETE_FRAME_INDEX, &picture);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    OH_ImageSourceNative_Release(imageSource);
    GTEST_LOG_(INFO) << "ImagSourceNdk2Test: OH_ImageSourceNative_CreatePictureAtIndex007 end";
}
}
}
