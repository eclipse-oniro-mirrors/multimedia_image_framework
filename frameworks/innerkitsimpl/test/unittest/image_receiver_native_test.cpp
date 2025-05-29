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
#define protected public
#include "common_utils.h"
#include "image_native.h"
#include "image_receiver_native.h"
#include "image_kits.h"
#include "image_receiver.h"

struct OH_ImageReceiverNative {
    std::shared_ptr<OHOS::Media::ImageReceiver> ptrImgRcv;
};

struct OH_ImageReceiverOptions {
    int32_t width = 0;
    int32_t height = 0;
    int32_t format = 0;
    int32_t capacity = 0;
};

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

static void OH_ImageReceiver_ImageArriveCallback_Test(OH_ImageReceiverNative *receiver, void *userData) 
{
    if (userData != nullptr) {
        int32_t *number = static_cast<int32_t *>(userData);
        *number = 1;
    }
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

/**
@tc.name: OH_ImageReceiverOptions_CreateTest002
@tc.desc: OH_ImageReceiverOptions_Create
@tc.type: FUNC
*/
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_CreateTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_CreateTest002 start";
    OH_ImageReceiverOptions** options = nullptr;
    Image_ErrorCode nRst = OH_ImageReceiverOptions_Create(options);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    OH_ImageReceiverOptions* opt = nullptr;
    Image_Size size;
    nRst = OH_ImageReceiverOptions_GetSize(opt, &size);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    nRst = OH_ImageReceiverOptions_SetSize(opt, size);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    int32_t capacity = 0;
    nRst = OH_ImageReceiverOptions_GetCapacity(opt, &capacity);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    nRst = OH_ImageReceiverOptions_SetCapacity(opt, capacity);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_CreateTest002 end";
}

/**
@tc.name: OH_ImageReceiverNative_CreateTest002
@tc.desc: OH_ImageReceiverNative_Create
@tc.type: FUNC
*/
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_CreateTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_CreateTest002 start";
    OH_ImageReceiverOptions* options = nullptr;
    OH_ImageReceiverNative* receiver = nullptr;
    Image_ErrorCode nRst = OH_ImageReceiverNative_Create(options, &receiver);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    OH_ImageReceiverOptions_Create(&options);
    ASSERT_NE(options, nullptr);
    receiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(receiver, nullptr);
    ASSERT_NE(&receiver, nullptr);
    nRst = OH_ImageReceiverNative_Create(options, &receiver);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_CreateTest002 end";
}

/**
@tc.name: OH_ImageReceiverNative_GetReceivingSurfaceIdTest002
@tc.desc: OH_ImageReceiverNative_GetReceivingSurfaceId
@tc.type: FUNC
*/
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetReceivingSurfaceIdTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest002 start";
    OH_ImageReceiverNative* receiver = nullptr;
    uint64_t* surfaceId = nullptr;
    Image_ErrorCode nRst = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, surfaceId);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    OH_ImageNative** image = nullptr;
    nRst = OH_ImageReceiverNative_ReadLatestImage(receiver, image);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    nRst = OH_ImageReceiverNative_ReadNextImage(receiver, image);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    nRst = OH_ImageReceiverNative_On(receiver, OH_ImageReceiver_OnCallback);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    nRst = OH_ImageReceiverNative_Off(receiver);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    Image_Size* size = nullptr;
    nRst = OH_ImageReceiverNative_GetSize(receiver, size);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    int32_t* capacity = nullptr;
    nRst = OH_ImageReceiverNative_GetCapacity(receiver, capacity);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    nRst = OH_ImageReceiverNative_Release(receiver);
    ASSERT_EQ(nRst, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetReceivingSurfaceIdTest003
 * @tc.desc: test the OH_ImageReceiverNative_GetReceivingSurfaceId
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetReceivingSurfaceIdTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest003 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    uint64_t surfaceId = 0;
    Image_ErrorCode ret = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, &surfaceId);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest003 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetReceivingSurfaceIdTest004
 * @tc.desc: test the OH_ImageReceiverNative_GetReceivingSurfaceId
             when receiverKey is empty,return IMAGE_UNKNOWN_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetReceivingSurfaceIdTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest004 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    std::string receiverKey = "";
    receiver->ptrImgRcv->iraContext_->SetReceiverKey(receiverKey);
    uint64_t surfaceId = 0;
    Image_ErrorCode ret = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, &surfaceId);
    ASSERT_EQ(ret, IMAGE_UNKNOWN_ERROR);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest004 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetReceivingSurfaceIdTest005
 * @tc.desc: test the OH_ImageReceiverNative_GetReceivingSurfaceId
             when receiverKey convert string to uint64_t failed,return IMAGE_UNKNOWN_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetReceivingSurfaceIdTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest005 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    std::string receiverKey = "abc";
    receiver->ptrImgRcv->iraContext_->SetReceiverKey(receiverKey);
    uint64_t surfaceId = 0;
    Image_ErrorCode ret = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, &surfaceId);
    ASSERT_EQ(ret, IMAGE_UNKNOWN_ERROR);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest005 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_ReadLatestImageTest002
 * @tc.desc: test the OH_ImageReceiverNative_ReadLatestImage
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_ReadLatestImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadLatestImageTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    OH_ImageNative* image = nullptr;
    Image_ErrorCode ret = OH_ImageReceiverNative_ReadLatestImage(receiver, &image);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadLatestImageTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_ReadNextImageTest002
 * @tc.desc: test the OH_ImageReceiverNative_ReadNextImage
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_ReadNextImageTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadNextImageTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    OH_ImageNative* image = nullptr;
    Image_ErrorCode ret = OH_ImageReceiverNative_ReadNextImage(receiver, &image);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_ReadNextImageTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_OnTest002
 * @tc.desc: test the OH_ImageReceiverNative_On
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OnTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    Image_ErrorCode ret = OH_ImageReceiverNative_On(receiver, OH_ImageReceiver_OnCallback);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_OffTest002
 * @tc.desc: test the OH_ImageReceiverNative_Off
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OffTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    Image_ErrorCode ret = OH_ImageReceiverNative_Off(receiver);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetSizeTest002
 * @tc.desc: test the OH_ImageReceiverNative_GetSize
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetSizeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetSizeTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    Image_Size size = {1, 1};
    Image_ErrorCode ret = OH_ImageReceiverNative_GetSize(receiver, &size);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetSizeTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetCapacityTest002
 * @tc.desc: test the OH_ImageReceiverNative_GetCapacity
             when receiver->ptrImgRcv is nullptr,return IMAGE_BAD_PARAMETER
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetCapacityTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetCapacityTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    int32_t capacity = 0;
    Image_ErrorCode ret = OH_ImageReceiverNative_GetCapacity(receiver, &capacity);
    ASSERT_EQ(ret, IMAGE_BAD_PARAMETER);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetCapacityTest002 end";
}

/**
 * @tc.name: OH_ImageReceiverOptions_ReleaseTest001
 * @tc.desc: test the OH_ImageReceiverOptions_Release when options is not nullptr or nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverOptions_ReleaseTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_ReleaseTest001 start";
    OH_ImageReceiverOptions* options = new OH_ImageReceiverOptions;
    ASSERT_NE(options, nullptr);
    Image_ErrorCode errCode = OH_ImageReceiverOptions_Release(options);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    errCode = OH_ImageReceiverOptions_Release(nullptr);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverOptions_ReleaseTest001 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_CreateTest001
 * @tc.desc: test the OH_ImageReceiverNative_Create when options and receiver is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_CreateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_CreateTest001 start";
    Image_ErrorCode errCode = OH_ImageReceiverNative_Create(nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    OH_ImageReceiverOptions* options = new OH_ImageReceiverOptions;
    ASSERT_NE(options, nullptr);
    errCode = OH_ImageReceiverNative_Create(options, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    OH_ImageReceiverNative* receiver = new OH_ImageReceiverNative;
    ASSERT_NE(receiver, nullptr);
    errCode = OH_ImageReceiverNative_Create(options, &receiver);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete options;
    delete receiver;
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_CreateTest001 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetReceivingSurfaceIdTest001
 * @tc.desc: test the OH_ImageReceiverNative_GetReceivingSurfaceId when ptrImgRcv or iraContexe is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetReceivingSurfaceIdTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest001 start";
    OH_ImageReceiverNative* receiver = new OH_ImageReceiverNative;
    ASSERT_NE(receiver, nullptr);
    uint64_t mockSurfaceId = 1;
    receiver->ptrImgRcv = nullptr;

    Image_ErrorCode errCode = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, &mockSurfaceId);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    receiver->ptrImgRcv = std::make_shared<OHOS::Media::ImageReceiver>();
    ASSERT_NE(receiver->ptrImgRcv, nullptr);
    receiver->ptrImgRcv->iraContext_ = nullptr;
    errCode = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, &mockSurfaceId);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(receiver->ptrImgRcv, nullptr);
    receiver->ptrImgRcv->iraContext_ = std::make_shared<OHOS::Media::ImageReceiverContext>();
    ASSERT_NE(receiver->ptrImgRcv->iraContext_, nullptr);
    receiver->ptrImgRcv->iraContext_->receiverKey_ = "";
    errCode = OH_ImageReceiverNative_GetReceivingSurfaceId(receiver, &mockSurfaceId);
    EXPECT_EQ(errCode, IMAGE_UNKNOWN_ERROR);

    delete receiver;
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetReceivingSurfaceIdTest001 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_OnTest001
 * @tc.desc: test the OH_ImageReceiverNative_On when receiver and callback is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OnTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest001 start";
    OH_ImageReceiverNative* receiver = new OH_ImageReceiverNative;
    ASSERT_NE(receiver, nullptr);
    receiver->ptrImgRcv = nullptr;

    Image_ErrorCode errCode = OH_ImageReceiverNative_On(nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageReceiverNative_On(receiver, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageReceiverNative_On(receiver, OH_ImageReceiver_OnCallback);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    delete receiver;
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest001 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetSizeTest001
 * @tc.desc: test the OH_ImageReceiverNative_GetSize when size and iraContext is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetSizeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetSizeTest001 start";
    OH_ImageReceiverNative* receiver = new OH_ImageReceiverNative;
    ASSERT_NE(receiver, nullptr);
    Image_Size* size = new Image_Size;
    ASSERT_NE(size, nullptr);

    Image_ErrorCode errCode = OH_ImageReceiverNative_GetSize(nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageReceiverNative_GetSize(receiver, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    receiver->ptrImgRcv = nullptr;
    errCode = OH_ImageReceiverNative_GetSize(receiver, size);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    receiver->ptrImgRcv = std::make_shared<OHOS::Media::ImageReceiver>();
    ASSERT_NE(receiver->ptrImgRcv, nullptr);
    receiver->ptrImgRcv->iraContext_ = nullptr;
    errCode = OH_ImageReceiverNative_GetSize(receiver, size);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(receiver->ptrImgRcv, nullptr);
    receiver->ptrImgRcv->iraContext_ = std::make_shared<OHOS::Media::ImageReceiverContext>();
    ASSERT_NE(receiver->ptrImgRcv->iraContext_, nullptr);
    errCode = OH_ImageReceiverNative_GetSize(receiver, size);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete receiver;
    delete size;
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetSizeTest001 end";
}

/**
 * @tc.name: OH_ImageReceiverNative_GetCapacityTest001
 * @tc.desc: test the OH_ImageReceiverNative_GetCapacity when capacity and iraContext is nullptr or not
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_GetCapacityTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetCapacityTest001 start";
    OH_ImageReceiverNative* receiver = new OH_ImageReceiverNative;
    ASSERT_NE(receiver, nullptr);
    int32_t mockCapacity = 32;

    Image_ErrorCode errCode = OH_ImageReceiverNative_GetCapacity(nullptr, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    errCode = OH_ImageReceiverNative_GetCapacity(receiver, nullptr);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    receiver->ptrImgRcv = nullptr;
    errCode = OH_ImageReceiverNative_GetCapacity(receiver, &mockCapacity);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    receiver->ptrImgRcv = std::make_shared<OHOS::Media::ImageReceiver>();
    ASSERT_NE(receiver->ptrImgRcv, nullptr);
    receiver->ptrImgRcv->iraContext_ = nullptr;
    mockCapacity = 32;
    errCode = OH_ImageReceiverNative_GetCapacity(receiver, &mockCapacity);
    EXPECT_EQ(errCode, IMAGE_BAD_PARAMETER);

    ASSERT_NE(receiver->ptrImgRcv, nullptr);
    receiver->ptrImgRcv->iraContext_ = std::make_shared<OHOS::Media::ImageReceiverContext>();
    ASSERT_NE(receiver->ptrImgRcv->iraContext_, nullptr);
    mockCapacity = 32;
    errCode = OH_ImageReceiverNative_GetCapacity(receiver, &mockCapacity);
    EXPECT_EQ(errCode, IMAGE_SUCCESS);

    delete receiver;
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_GetCapacityTest001 end";
}

/*
* @tc.name: OH_ImageReceiverNative_OnImageArriveTest001
* @tc.desc: erify that OH_ImageReceiverNative_OnImageArrive correctly registers the callback, handles duplicate
*           registrations, and triggers the callback when a surface buffer becomes available, updating the user data.
* @tc.type: FUNC
*/

HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OnImageArriveTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnImageArriveTest001 start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    int32_t number = 0;
    void* userData = &number;
    Image_ErrorCode nRst = OH_ImageReceiverNative_OnImageArrive(pReceiver,
        OH_ImageReceiver_ImageArriveCallback_Test, userData);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    nRst = OH_ImageReceiverNative_OnImageArrive(pReceiver, OH_ImageReceiver_ImageArriveCallback_Test, userData);
    ASSERT_EQ(nRst, IMAGE_RECEIVER_INVALID_PARAMETER);

    ASSERT_NE(pReceiver->ptrImgRcv, nullptr);
    std::shared_ptr<ImageReceiverArriveListener> receiverArriveListener =
        std::make_shared<ImageReceiverArriveListener>(pReceiver);
    receiverArriveListener->RegisterCallback(OH_ImageReceiver_ImageArriveCallback_Test, userData);
    pReceiver->ptrImgRcv->surfaceBufferAvaliableListener_ = receiverArriveListener;
    ASSERT_NE(pReceiver->ptrImgRcv->surfaceBufferAvaliableListener_, nullptr);

    pReceiver->ptrImgRcv->surfaceBufferAvaliableListener_->OnSurfaceBufferAvaliable();
    EXPECT_EQ(number, 1);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnImageArriveTest001 end";
}

/**
* @tc.name: OH_ImageReceiverNative_OnImageArriveTest002
* @tc.desc: Verify that OH_ImageReceiverNative_OnImageArrive returns IMAGE_RECEIVER_INVALID_PARAMETER when the receiver
*           is null, the callback is null, or the receiver's internal pointer is null.
* @tc.type: FUNC
*/
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OnImageArriveTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnImageArriveTest002 start";
    OH_ImageReceiverNative* receiver = ImageReceiverNativeTest::CreateReceiver();
    receiver->ptrImgRcv = nullptr;
    Image_ErrorCode ret;
    ret = OH_ImageReceiverNative_OnImageArrive(nullptr, OH_ImageReceiver_ImageArriveCallback_Test, nullptr);
    ASSERT_EQ(ret, IMAGE_RECEIVER_INVALID_PARAMETER);
    ret = OH_ImageReceiverNative_OnImageArrive(receiver, OH_ImageReceiver_ImageArriveCallback_Test, nullptr);
    ASSERT_EQ(ret, IMAGE_RECEIVER_INVALID_PARAMETER);
    ret = OH_ImageReceiverNative_OnImageArrive(receiver, nullptr, nullptr);
    ASSERT_EQ(ret, IMAGE_RECEIVER_INVALID_PARAMETER);
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(receiver, OH_ImageReceiverNative_Release);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OnTest002 end";
}

/**
* @tc.name: OH_ImageReceiverNative_OffImageArriveTest001
* @tc.desc: Verify that OH_ImageReceiverNative_OffImageArrive correctly handles invalid parameters, including null
*           receiver, null callback, and receiver with a null internal pointer, and returns appropriate error codes.
* @tc.type: FUNC
*/
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OffImageArriveTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffImageArriveTest001 start";
    Image_ErrorCode nRst = OH_ImageReceiverNative_OffImageArrive(nullptr, OH_ImageReceiver_ImageArriveCallback_Test);
    ASSERT_EQ(nRst, IMAGE_RECEIVER_INVALID_PARAMETER); 
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    nRst = OH_ImageReceiverNative_OffImageArrive(pReceiver, nullptr);
    ASSERT_EQ(nRst, IMAGE_SUCCESS); 
    pReceiver->ptrImgRcv = nullptr;
    nRst = OH_ImageReceiverNative_OffImageArrive(pReceiver, OH_ImageReceiver_ImageArriveCallback_Test);
    ASSERT_EQ(nRst, IMAGE_RECEIVER_INVALID_PARAMETER); 
    std::shared_ptr<OH_ImageReceiverNative> ptrReceiver(pReceiver, OH_ImageReceiverNative_Release);
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffImageArriveTest001 end";
}

/**
* @tc.name: OH_ImageReceiverNative_OffImageArriveTest002
* @tc.desc: Verify that OH_ImageReceiverNative_OffImageArrive correctly handles registering
*           and unregistering the callback.
* @tc.type: FUNC
*/
HWTEST_F(ImageReceiverNativeTest, OH_ImageReceiverNative_OffImageArriveTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverNativeTest: OH_ImageReceiverNative_OffImageArriveTest002 start";
    OH_ImageReceiverNative* pReceiver = ImageReceiverNativeTest::CreateReceiver();
    ASSERT_NE(pReceiver, nullptr);
    int32_t number = 0;
    void* userData = &number;
    Image_ErrorCode nRst;
    nRst = OH_ImageReceiverNative_OffImageArrive(pReceiver, OH_ImageReceiver_ImageArriveCallback_Test);
    ASSERT_EQ(nRst, IMAGE_RECEIVER_INVALID_PARAMETER);
    
    nRst = OH_ImageReceiverNative_OnImageArrive(pReceiver, OH_ImageReceiver_ImageArriveCallback_Test, userData);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);

    nRst = OH_ImageReceiverNative_OffImageArrive(pReceiver, OH_ImageReceiver_ImageArriveCallback_Test);
    ASSERT_EQ(nRst, IMAGE_SUCCESS);
    
    nRst = OH_ImageReceiverNative_OffImageArrive(pReceiver, OH_ImageReceiver_ImageArriveCallback_Test);
    ASSERT_EQ(nRst, IMAGE_RECEIVER_INVALID_PARAMETER);
}

} // namespace Media
} // namespace OHOS