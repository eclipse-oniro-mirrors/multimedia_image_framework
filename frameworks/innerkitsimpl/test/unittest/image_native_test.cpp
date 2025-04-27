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

#include <gtest/gtest.h>
#define private public
#include "common_utils.h"
#include "image_native.h"
#include "image_receiver_native.h"
#include "image_kits.h"
#include "image_receiver.h"

struct OH_NativeBuffer {};

using namespace testing::ext;
namespace OHOS {
namespace Media {

class ImageNativeTest : public testing::Test {
public:
    ImageNativeTest() {}
    ~ImageNativeTest() {}
};

/**
 * @tc.name: OH_ImageNative_ReleaseTest
 * @tc.desc: OH_ImageNative_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_ReleaseTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_ReleaseTest start";
    OH_ImageNative* pImg = nullptr;
    Image_ErrorCode nRst = OH_ImageNative_Release(pImg);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_ReleaseTest end";
}

/**
 * @tc.name: OH_ImageNative_GetByteBufferTest
 * @tc.desc: OH_ImageNative_GetByteBuffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetByteBufferTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest start";
    OH_ImageNative* pImg = nullptr;
    OH_NativeBuffer* pBuffer = nullptr;
    Image_ErrorCode nRst = OH_ImageNative_GetByteBuffer(pImg, 0, &pBuffer);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest end";
}

/**
 * @tc.name: OH_ImageNative_GetBufferSizeTest
 * @tc.desc: OH_ImageNative_GetBufferSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetBufferSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetBufferSizeTest start";
    OH_ImageNative* pImg = nullptr;
    size_t nSize = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetBufferSize(pImg, 0, &nSize);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetBufferSizeTest end";
}

/**
 * @tc.name: OH_ImageNative_GetComponentTypesTest
 * @tc.desc: OH_ImageNative_GetComponentTypes
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetComponentTypesTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest start";
    OH_ImageNative* pImg = nullptr;
    uint32_t* pTypes = nullptr;
    size_t nTypeSize = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetComponentTypes(pImg, &pTypes, &nTypeSize);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest end";
}

/**
 * @tc.name: OH_ImageNative_GetRowStrideTest
 * @tc.desc: OH_ImageNative_GetRowStride
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetRowStrideTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetRowStrideTest start";
    OH_ImageNative* pImg = nullptr;
    int32_t nRowStride = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetRowStride(pImg, 0, &nRowStride);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetRowStrideTest end";
}

/**
 * @tc.name: OH_ImageNative_GetRowStrideTest002
 * @tc.desc: OH_ImageNative_GetRowStride
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetRowStrideTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetRowStrideTest002 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    uint32_t componentType = 0;
    int32_t nRowStride = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetRowStride(pImg, componentType, &nRowStride);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetRowStrideTest002 end";
}

/**
 * @tc.name: OH_ImageNative_GetPixelStrideTest
 * @tc.desc: OH_ImageNative_GetPixelStride
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetPixelStrideTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetPixelStrideTest start";
    OH_ImageNative* pImg = nullptr;
    int32_t nPixelStride = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetPixelStride(pImg, 0, &nPixelStride);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetPixelStrideTest end";
}

/**
 * @tc.name: OH_ImageNative_GetImageSizeTest
 * @tc.desc: OH_ImageNative_GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetImageSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest start";
    OH_ImageNative* pImg = nullptr;
    Image_Size szImg = { 0 };
    Image_ErrorCode nRst = OH_ImageNative_GetImageSize(pImg, &szImg);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest end";
}

/**
@tc.name: OH_ImageNative_GetComponentTypesTest002
@tc.desc: OH_ImageNative_GetComponentTypes
@tc.type: FUNC
*/
HWTEST_F(ImageNativeTest, OH_ImageNative_GetComponentTypesTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest002 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser = nullptr;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    uint32_t data = 0;
    uint32_t* pTypes = &data;
    size_t nTypeSize = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetComponentTypes(pImg, &pTypes, &nTypeSize);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    uint32_t componentType = 128;
    size_t* size = (size_t *)&data;
    nRst = OH_ImageNative_GetBufferSize(pImg, componentType, size);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    int32_t* rowStride = (int32_t *)&data;
    nRst = OH_ImageNative_GetRowStride(pImg, componentType, rowStride);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    int32_t* pixelStride = (int32_t *)&data;
    nRst = OH_ImageNative_GetPixelStride(pImg, componentType, pixelStride);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest002 end";
}

/**
 * @tc.name: OH_ImageNative_GetComponentTypesTest003
 * @tc.desc: OH_ImageNative_GetComponentTypes
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetComponentTypesTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest003 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    uint32_t* pTypes = nullptr;
    size_t nTypeSize = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetComponentTypes(pImg, &pTypes, &nTypeSize);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest003 end";
}

/**
 * @tc.name: OH_ImageNative_GetByteBufferTest002
 * @tc.desc: OH_ImageNative_GetByteBuffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetByteBufferTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest002 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    OH_NativeBuffer* pBuffer;
    uint32_t type = 128;
    Image_ErrorCode nRst = OH_ImageNative_GetByteBuffer(pImg, type, &pBuffer);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest002 end";
}

/**
 * @tc.name: OH_ImageNative_GetByteBufferTest003
 * @tc.desc: OH_ImageNative_GetByteBuffer
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetByteBufferTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest003 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    OH_NativeBuffer* pBuffer;
    uint32_t type = 1;
    uint8_t vir = 0;
    pImg->imgNative->CreateComponent(1, 1, 1, 1, &vir);
    Image_ErrorCode nRst = OH_ImageNative_GetByteBuffer(pImg, type, &pBuffer);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest003 end";
}

/**
 * @tc.name: OH_ImageNative_GetImageSizeTest002
 * @tc.desc: OH_ImageNative_GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetImageSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest002 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    Image_Size szImg = {0, 0};
    Image_ErrorCode nRst = OH_ImageNative_GetImageSize(pImg, &szImg);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest002 end";
}

/**
 * @tc.name: OH_ImageNative_GetImageSizeTest003
 * @tc.desc: OH_ImageNative_GetImageSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetImageSizeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest003 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    pImg->imgNative->buffer_ = nullptr;
    Image_Size szImg = {0, 0};
    Image_ErrorCode nRst = OH_ImageNative_GetImageSize(pImg, &szImg);
    ASSERT_EQ(nRst, ERR_MEDIA_DEAD_OBJECT);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest003 end";
}

/**
 * @tc.name: OH_ImageNative_GetTimestampTest001
 * @tc.desc: OH_ImageNative_GetTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetTimestampTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest001 start";
    OH_ImageNative* pImg = nullptr;
    int64_t timestamp = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetTimestamp(pImg, &timestamp);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetTimestampTest002
 * @tc.desc: OH_ImageNative_GetTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetTimestampTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest002 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    int64_t timestamp = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetTimestamp(pImg, &timestamp);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest002 end";
}

/**
 * @tc.name: OH_ImageNative_GetTimestampTest003
 * @tc.desc: OH_ImageNative_GetTimestamp
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetTimestampTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest003 start";
    struct OH_ImageNative imageNative;
    OH_ImageNative* pImg = &imageNative;
    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    pImg->imgNative = &imgNative;
    int64_t timestamp = 0;
    Image_ErrorCode nRst = OH_ImageNative_GetTimestamp(pImg, &timestamp);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest003 end";
}

/**
 * @tc.name: OH_ImageNative_GetImageSizeTest001
 * @tc.desc: test the OH_ImageNative_GetImageSize when image, imgNative and size is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetImageSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    Image_Size* size = new Image_Size;
    ASSERT_NE(size, nullptr);
    image->imgNative = nullptr;

    Image_ErrorCode errCode = OH_ImageNative_GetImageSize(nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageNative_GetImageSize(image, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetImageSize(image, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(image->imgNative, nullptr);
    imgNative.buffer_ = nullptr;
    errCode = OH_ImageNative_GetImageSize(image, size);
    EXPECT_EQ(errCode, ERR_MEDIA_DEAD_OBJECT);

    delete image;
    delete size;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetImageSizeTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetComponentTypesTest001
 * @tc.desc: test the OH_ImageNative_GetComponentTypes when image, imgNative, typeSize and types are nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetComponentTypesTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    uint32_t typesArr = 0;
    uint32_t* typesPtr = &typesArr;
    uint32_t** types = &typesPtr;
    size_t typeSize = 5;
    image->imgNative = nullptr;

    Image_ErrorCode errCode = OH_ImageNative_GetComponentTypes(nullptr, nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageNative_GetComponentTypes(image, nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetComponentTypes(image, nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(image->imgNative, nullptr);
    errCode = OH_ImageNative_GetComponentTypes(image, nullptr, &typeSize);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    ASSERT_NE(image->imgNative, nullptr);
    errCode = OH_ImageNative_GetComponentTypes(image, types, &typeSize);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete image;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetComponentTypesTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetByteBufferTest001
 * @tc.desc: test the OH_ImageNative_GetByteBuffer when image, imgNative, nativeBuffer and buffer are nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetByteBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    uint32_t componentType = 0;
    int32_t type = 0;
    OH_NativeBuffer nativeBuffer;
    OH_NativeBuffer* nativeBufferPtr = &nativeBuffer;

    Image_ErrorCode errCode = OH_ImageNative_GetByteBuffer(nullptr, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    image->imgNative = nullptr;
    errCode = OH_ImageNative_GetByteBuffer(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser;
    std::unique_ptr<NativeComponent> component = std::make_unique<NativeComponent>();
    ASSERT_NE(component, nullptr);
    NativeImage imgNative(buffer, releaser);
    imgNative.components_.emplace(type, std::move(component));
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetByteBuffer(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(image->imgNative, nullptr);
    errCode = OH_ImageNative_GetByteBuffer(image, componentType, static_cast<OH_NativeBuffer**>(&nativeBufferPtr));
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete image;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetByteBufferTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetBufferSizeTest001
 * @tc.desc: test the OH_ImageNative_GetBufferSize when image, imgNative, size and component are nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetBufferSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetBufferSizeTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    uint32_t componentType = 0;
    int32_t type = 0;
    size_t size = 0;

    Image_ErrorCode errCode = OH_ImageNative_GetBufferSize(nullptr, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    image->imgNative = nullptr;
    errCode = OH_ImageNative_GetBufferSize(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser;
    std::unique_ptr<NativeComponent> component = std::make_unique<NativeComponent>();
    NativeImage imgNative(buffer, releaser);
    imgNative.components_.emplace(type, std::move(component));
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetBufferSize(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(image->imgNative, nullptr);
    errCode = OH_ImageNative_GetBufferSize(image, componentType, static_cast<size_t*>(&size));
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete image;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetBufferSizeTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetRowStrideTest001
 * @tc.desc: test the OH_ImageNative_GetRowStride when image, imgNative, rowStride and component are nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetRowStrideTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetRowStrideTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    uint32_t componentType = 0;
    int32_t type = 0;
    int32_t rowStride = 0;

    Image_ErrorCode errCode = OH_ImageNative_GetRowStride(nullptr, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    image->imgNative = nullptr;
    errCode = OH_ImageNative_GetRowStride(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser;
    std::unique_ptr<NativeComponent> component = std::make_unique<NativeComponent>();
    NativeImage imgNative(buffer, releaser);
    imgNative.components_.emplace(type, std::move(component));
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetRowStride(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageNative_GetRowStride(image, componentType, &rowStride);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete image;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetRowStrideTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetPixelStrideTest001
 * @tc.desc: test the OH_ImageNative_GetPixelStride when image, imgNative, pixelStride and component are nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetPixelStrideTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetPixelStrideTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    uint32_t componentType = 0;
    int32_t type = 0;
    int32_t pixelStride = 0;

    Image_ErrorCode errCode = OH_ImageNative_GetRowStride(nullptr, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    image->imgNative = nullptr;
    errCode = OH_ImageNative_GetRowStride(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    ASSERT_NE(buffer, nullptr);
    std::shared_ptr<IBufferProcessor> releaser;
    std::unique_ptr<NativeComponent> component = std::make_unique<NativeComponent>();
    NativeImage imgNative(buffer, releaser);
    imgNative.components_.emplace(type, std::move(component));
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetRowStride(image, componentType, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageNative_GetRowStride(image, componentType, &pixelStride);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete image;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetPixelStrideTest001 end";
}

/**
 * @tc.name: OH_ImageNative_GetTimestampTest011
 * @tc.desc: test the OH_ImageNative_GetTimestamp when image, imgNative and timestamp are nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_GetTimestampTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest011 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);
    int64_t timestamp = 0;

    Image_ErrorCode errCode = OH_ImageNative_GetTimestamp(nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    image->imgNative = nullptr;
    errCode = OH_ImageNative_GetTimestamp(image, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    sptr<SurfaceBuffer> buffer = nullptr;
    std::shared_ptr<IBufferProcessor> releaser;
    NativeImage imgNative(buffer, releaser);
    image->imgNative = &imgNative;
    errCode = OH_ImageNative_GetTimestamp(image, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageNative_GetTimestamp(image, &timestamp);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    delete image;
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_GetTimestampTest011 end";
}

/**
 * @tc.name: OH_ImageNative_ReleaseTest001
 * @tc.desc: test the OH_ImageNative_Release when image and imgNative is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageNativeTest, OH_ImageNative_ReleaseTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_ReleaseTest001 start";
    OH_ImageNative* image = new OH_ImageNative;
    ASSERT_NE(image, nullptr);

    Image_ErrorCode errCode = OH_ImageNative_Release(nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    image->imgNative = nullptr;
    errCode = OH_ImageNative_Release(image);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageNativeTest: OH_ImageNative_ReleaseTest001 end";
}
} // namespace Media
} // namespace OHOS
