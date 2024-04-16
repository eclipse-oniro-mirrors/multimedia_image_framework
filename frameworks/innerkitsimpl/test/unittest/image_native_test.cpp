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
#include "common_utils.h"
#include "image_native.h"
#include "image_receiver_native.h"
#include "image_kits.h"
#include "image_receiver.h"

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

} // namespace Media
} // namespace OHOS
