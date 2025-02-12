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
#include "pixelmap_native.h"
#include "pixelmap_native_impl.h"
#include "image_utils.h"
#include "pixelmap_native.h"
#include "securec.h"

using namespace testing::ext;
namespace OHOS {
namespace Media {
class ImagSourceNdk2Test : public testing::Test {
public:
    ImagSourceNdk2Test() {}
    ~ImagSourceNdk2Test() {}
};

static constexpr int32_t TestLength = 2;
static const std::string IMAGE_JPEG_PATH = "/data/local/tmp/image/test_picture.jpg";
static const std::string IMAGE_JPEG_HDR_PATH = "/data/local/tmp/image/test_jpeg_hdr.jpg";
static const std::string IMAGE_HEIF_PATH = "/data/local/tmp/image/test_allocator_heif.heic";
static const std::string IMAGE_HEIF_HDR_PATH = "/data/local/tmp/image/test_heif_hdr.heic";
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
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest027
 * @tc.desc: Test the creation of a pixelmap using a shared memory allocator, with ARGB pixel format and SDR
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest027, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_ARGB_8888);
    OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_SDR);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    EXPECT_EQ(resPixMap->GetInnerPixelmap()->GetPixelFormat(), PixelFormat::ARGB_8888);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest028
 * @tc.desc: Test the creation of a pixelmap using a dma memory allocator, with ARGB pixel format and SDR
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest028, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_ARGB_8888);
    OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_SDR);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest029
 * @tc.desc: Test the creation of a pixelmap using a auto memory allocator, with ARGB pixel format and SDR
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest029, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_ARGB_8888);
    OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_SDR);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_AUTO;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    EXPECT_EQ(resPixMap->GetInnerPixelmap()->GetPixelFormat(), PixelFormat::ARGB_8888);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest030
 * @tc.desc: Test the creation of a pixelmap using a share memory allocator, with ARGB pixel format and HDR
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest030, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_ARGB_8888);
    OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_SHARE_MEMORY;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE);
    EXPECT_EQ(resPixMap, nullptr);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest031
 * @tc.desc: Test the creation of a pixelmap using a dma memory allocator, with ARGB pixel format and HDR
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest031, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_ARGB_8888);
    OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_DMA;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    EXPECT_EQ(resPixMap->GetInnerPixelmap()->GetPixelFormat(), PixelFormat::RGBA_1010102);
    OH_ImageSourceNative_Release(imageSource);
    OH_DecodingOptions_Release(opts);
    OH_PixelmapNative_Release(resPixMap);
}

/**
 * @tc.name: OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest032
 * @tc.desc: Test the creation of a pixelmap using a auto memory allocator, with ARGB pixel format and HDR
 *           dynamic range.
 * @tc.type: FUNC
 */
HWTEST_F(ImagSourceNdk2Test, OH_ImageSourceNative_CreatePixelmapUsingAllocatorTest032, TestSize.Level1)
{
    OH_ImageSourceNative *imageSource = CreateImageSourceNative(IMAGE_JPEG_HDR_PATH);
    ASSERT_NE(imageSource, nullptr);
    OH_DecodingOptions *opts = nullptr;
    OH_DecodingOptions_Create(&opts);
    ASSERT_NE(opts, nullptr);
    OH_DecodingOptions_SetPixelFormat(opts, PIXEL_FORMAT_ARGB_8888);
    OH_DecodingOptions_SetDesiredDynamicRange(opts, IMAGE_DYNAMIC_RANGE::IMAGE_DYNAMIC_RANGE_HDR);
    OH_PixelmapNative* resPixMap = nullptr;
    IMAGE_ALLOCATOR_TYPE allocator = IMAGE_ALLOCATOR_TYPE::IMAGE_ALLOCATOR_TYPE_AUTO;
    Image_ErrorCode ret = OH_ImageSourceNative_CreatePixelmapUsingAllocator(imageSource, opts, allocator, &resPixMap);
    EXPECT_EQ(ret, IMAGE_SUCCESS);
    EXPECT_NE(resPixMap, nullptr);
    EXPECT_EQ(resPixMap->GetInnerPixelmap()->GetPixelFormat(), PixelFormat::RGBA_1010102);
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
}
}
