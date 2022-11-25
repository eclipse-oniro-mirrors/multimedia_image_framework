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
#include <fstream>
#include <surface.h>
#include "image_receiver.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"
#include "hilog/log.h"
#include "image_receiver_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace std;
namespace OHOS {
namespace Multimedia {
static constexpr int32_t RECEIVER_TEST_WIDTH = 8192;
static constexpr int32_t RECEIVER_TEST_HEIGHT = 8;
static constexpr int32_t RECEIVER_TEST_CAPACITY = 8;
static constexpr int32_t RECEIVER_TEST_FORMAT = 4;
class ImageReceiverManagerTest : public testing::Test {
public:
    ImageReceiverManagerTest() {}
    ~ImageReceiverManagerTest() {}
};

/**
 * @tc.name: ImageReceiverManager001
 * @tc.desc: test SaveImageReceiver
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverManagerTest, ImageReceiverManager001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager001 start";
    std::shared_ptr<ImageReceiver> iva = std::make_shared<ImageReceiver>();
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::string receiverKey = imageReceiverManager.SaveImageReceiver(iva);
    ASSERT_EQ(receiverKey, "1");
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager001 end";
}

/**
 * @tc.name: ImageReceiverManager002
 * @tc.desc: test getImageReceiverByKeyId
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverManagerTest, ImageReceiverManager002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager002 start";
    std::string id = "1";
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::shared_ptr<ImageReceiver> imaReceive = imageReceiverManager.getImageReceiverByKeyId(id);
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager002 end";
}

/**
 * @tc.name: ImageReceiverManager003
 * @tc.desc: test getSurfaceByKeyId
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverManagerTest, ImageReceiverManager003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager003 start";
    auto iva = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::string receiverKey = imageReceiverManager.SaveImageReceiver(iva);
    ASSERT_EQ(receiverKey, "1");
    auto surface = imageReceiverManager.getSurfaceByKeyId("");
    bool result = (surface == nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager003 end";
}

/**
 * @tc.name: ImageReceiverManager004
 * @tc.desc: test getSurfaceByKeyId
 * @tc.type: FUNC
 */
HWTEST_F(ImageReceiverManagerTest, ImageReceiverManager004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager004 start";
    auto iva = ImageReceiver::CreateImageReceiver(RECEIVER_TEST_WIDTH,
        RECEIVER_TEST_HEIGHT, RECEIVER_TEST_FORMAT, RECEIVER_TEST_CAPACITY);
    ImageReceiverManager& imageReceiverManager = ImageReceiverManager::getInstance();
    std::string receiverKey = imageReceiverManager.SaveImageReceiver(iva);
    auto surface = imageReceiverManager.getSurfaceByKeyId(receiverKey);
    bool result = (surface != nullptr);
    ASSERT_EQ(result, true);
    GTEST_LOG_(INFO) << "ImageReceiverManagerTest: ImageReceiverManager004 end";
}
}
}