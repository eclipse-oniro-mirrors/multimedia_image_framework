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

static constexpr int32_t IMAGE_TEST_WIDTH = 8192;
static constexpr int32_t IMAGE_TEST_HEIGHT = 8;
static constexpr int32_t IMAGE_TEST_CAPACITY = 8;

class ImageReceiverNativeTest : public testing::Test {
public:
    ImageReceiverNativeTest() {}
    ~ImageReceiverNativeTest() {}
    static OH_ImageReceiverNative* CreateReceiver();
};

OH_ImageReceiverNative* ImageReceiverNativeTest::CreateReceiver()
{
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    if (nRst != IMAGE_SUCCESS || options == nullptr) {
        return nullptr;
    }
    std::shared_ptr<OH_ImageReceiverOptions> ptrOptions(options, OH_ImageReceiverOptions_Release);

    Image_Size size;
    size.width = IMAGE_TEST_WIDTH;
    size.height = IMAGE_TEST_HEIGHT;
    nRst = OH_ImageReceiverOptions_SetSize(options, size);
    if (nRst != IMAGE_SUCCESS) {
        return nullptr;
    }

    nRst = OH_ImageReceiverOptions_SetCapacity(options, IMAGE_TEST_CAPACITY);
    if (nRst != IMAGE_SUCCESS) {
        return nullptr;
    }

    OH_ImageReceiverNative* pReceiver = nullptr;
    nRst = OH_ImageReceiverNative_Create(options, &pReceiver);
    if (nRst != IMAGE_SUCCESS || pReceiver == nullptr) {
        return nullptr;
    }
    return pReceiver;
}

/**
 * @tc.name: OH_ImageReceiverOptions_CreateTest
 * @tc.desc: OH_ImageReceiverOptions_Create
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_CreateTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_CreateTest start";
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    std::shared_ptr<OH_ImageReceiverOptions> ptrOptions(options, OH_ImageReceiverOptions_Release);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_CreateTest end";
}

/**
 * @tc.name: OH_ImageReceiverOptions_ReleaseTest
 * @tc.desc: OH_ImageReceiverOptions_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_ReleaseTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_ReleaseTest start";
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    nRst = OH_ImageReceiverOptions_Release(options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_ReleaseTest end";
}

/**
 * @tc.name: OH_ImageReceiverOptions_SetSizeTest
 * @tc.desc: OH_ImageReceiverOptions_SetSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_SetSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_SetSizeTest start";
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    std::shared_ptr<OH_ImageReceiverOptions> ptrOptions(options, OH_ImageReceiverOptions_Release);

    Image_Size size;
    size.width = IMAGE_TEST_WIDTH;
    size.height = IMAGE_TEST_HEIGHT;
    nRst = OH_ImageReceiverOptions_SetSize(options, size);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_SetSizeTest end";
}

/**
 * @tc.name: OH_ImageReceiverOptions_GetSizeTest
 * @tc.desc: OH_ImageReceiverOptions_GetSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_GetSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_GetSizeTest start";
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    std::shared_ptr<OH_ImageReceiverOptions> ptrOptions(options, OH_ImageReceiverOptions_Release);

    Image_Size size;
    size.width = IMAGE_TEST_WIDTH;
    size.height = IMAGE_TEST_HEIGHT;
    nRst = OH_ImageReceiverOptions_SetSize(options, size);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);

    Image_Size size_get;
    nRst = OH_ImageReceiverOptions_GetSize(options, &size_get);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_EQ(size_get.width, IMAGE_TEST_WIDTH);
    ASSERT_EQ(size_get.height, IMAGE_TEST_HEIGHT);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_GetSizeTest end";
}

/**
 * @tc.name: OH_ImageReceiverOptions_SetCapacityTest
 * @tc.desc: OH_ImageReceiverOptions_SetCapacity
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_SetCapacityTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_SetCapacityTest start";
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    std::shared_ptr<OH_ImageReceiverOptions> ptrOptions(options, OH_ImageReceiverOptions_Release);

    nRst = OH_ImageReceiverOptions_SetCapacity(options, IMAGE_TEST_CAPACITY);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_SetCapacityTest end";
}

/**
 * @tc.name: OH_ImageReceiverOptions_GetCapacityTest
 * @tc.desc: OH_ImageReceiverOptions_GetCapacity
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_GetCapacityTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_GetCapacityTest start";
    OH_ImageReceiverOptions* options = nullptr;
    Image_ErrorCode nRst = IMAGE_SUCCESS;
    nRst = OH_ImageReceiverOptions_Create(&options);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_NE(options, nullptr);
    std::shared_ptr<OH_ImageReceiverOptions> ptrOptions(options, OH_ImageReceiverOptions_Release);

    nRst = OH_ImageReceiverOptions_SetCapacity(options, IMAGE_TEST_CAPACITY);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);

    int32_t nCapacity = 0;
    nRst = OH_ImageReceiverOptions_GetCapacity(options, &nCapacity);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    ASSERT_EQ(nCapacity, IMAGE_TEST_CAPACITY);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_GetCapacityTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_CreateTest
 * @tc.desc: OH_ImageReceiverNative_Create
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_CreateTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_CreateTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_CreateTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_ReleaseTest
 * @tc.desc: OH_ImageReceiverNative_Release
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_ReleaseTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReleaseTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    Image_ErrorCode nRst = OH_ImageReceiverNative_Release(pReceiver);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReleaseTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetReceivingSurfaceIdTest
 * @tc.desc: OH_ImageReceiverNative_GetReceivingSurfaceId
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetReceivingSurfaceIdTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    uint64_t nSurfaceId = 0;
    Image_ErrorCode nRst = OH_ImageReceiverNative_GetReceivingSurfaceId(pReceiver, &nSurfaceId);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_ReadLatestImageTest
 * @tc.desc: OH_ImageReceiverNative_ReadLatestImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_ReadLatestImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadLatestImageTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    OH_ImageNative* pImg = nullptr;
    Image_ErrorCode nRst = OH_ImageReceiverNative_ReadLatestImage(pReceiver, &pImg);
    ASSERT_EQ(nRst, IMAGE_UNKNOWN_ERROR);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadLatestImageTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_ReadNextImageTest
 * @tc.desc: OH_ImageReceiverNative_ReadNextImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_ReadNextImageTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadNextImageTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    OH_ImageNative* pImg = nullptr;
    Image_ErrorCode nRst = OH_ImageReceiverNative_ReadNextImage(pReceiver, &pImg);
    ASSERT_EQ(nRst, IMAGE_UNKNOWN_ERROR);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadNextImageTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_OnTest
 * @tc.desc: OH_ImageReceiverNative_On
 * @tc.type: FUNC
 */
static void OH_ImageReceiver_OnCallback(OH_ImageReceiverNative* receiver) {}

HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OnTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    Image_ErrorCode nRst = OH_ImageReceiverNative_On(pReceiver, OH_ImageReceiver_OnCallback);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_OffTest
 * @tc.desc: OH_ImageReceiverNative_Off
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OffTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    Image_ErrorCode nRst = OH_ImageReceiverNative_Off(pReceiver);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetSizeTest
 * @tc.desc: OH_ImageReceiverNative_GetSize
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetSizeTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetSizeTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    Image_Size size;
    Image_ErrorCode nRst = OH_ImageReceiverNative_GetSize(pReceiver, &size);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetSizeTest end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetCapacityTest
 * @tc.desc: OH_ImageReceiverNative_GetCapacity
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetCapacityTest, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetCapacityTest start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);

    int32_t nCapacity = 0;
    Image_ErrorCode nRst = OH_ImageReceiverNative_GetCapacity(pReceiver, &nCapacity);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetCapacityTest end";
}

} // namespace Media
} // namespace OHOS