/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "image_creator_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class ImageCreatorManagerTest : public testing::Test {
public:
    ImageCreatorManagerTest() {}
    ~ImageCreatorManagerTest() {}
};

/**
 * @tc.name: SaveImageCreator001
 * @tc.desc: test SaveImageCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorManagerTest, SaveImageCreator001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: SaveImageCreator001 start";
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    shared_ptr<ImageCreator> imageCreator;
    string id = "1";
    shared_ptr<ImageCreator> bki = imageCreatorManager.GetImageCreatorByKeyId(id);
    ASSERT_EQ(bki, nullptr);
    string saveimagecreate = imageCreatorManager.SaveImageCreator(imageCreator);
    ASSERT_EQ(saveimagecreate, "1");
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: SaveImageCreator001 end";
}

/**
 * @tc.name: SaveImageCreator002
 * @tc.desc: test SaveImageCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorManagerTest, SaveImageCreator002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: SaveImageCreator002 start";
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    shared_ptr<ImageCreator> imageCreator;
    string id = "1";
    shared_ptr<ImageCreator> bki = imageCreatorManager.GetImageCreatorByKeyId(id);
    ASSERT_EQ(bki, nullptr);
    string saveimagecreate = imageCreatorManager.SaveImageCreator(imageCreator);
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: SaveImageCreator002 end";
}

/**
 * @tc.name: GetSurfaceByKeyId001
 * @tc.desc: test GetSurfaceByKeyId
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorManagerTest, GetSurfaceByKeyId001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: GetSurfaceByKeyId001 start";
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    string keyId = "";
    shared_ptr<ImageCreator> imageCreator;
    sptr<Surface> getsurf = imageCreatorManager.GetSurfaceByKeyId(keyId);
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: GetSurfaceByKeyId001 end";
}

/**
 * @tc.name: GetSurfaceByKeyId002
 * @tc.desc: test GetSurfaceByKeyId
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorManagerTest, GetSurfaceByKeyId002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: GetSurfaceByKeyId002 start";
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    string keyId = "";
    shared_ptr<ImageCreator> imageCreator = nullptr;
    sptr<Surface> getsurf = imageCreatorManager.GetSurfaceByKeyId(keyId);
    ASSERT_EQ(getsurf, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: GetSurfaceByKeyId002 end";
}

/**
 * @tc.name: GetImageCreatorByKeyId001
 * @tc.desc: test GetImageCreatorByKeyId
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorManagerTest, GetImageCreatorByKeyId001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: GetImageCreatorByKeyId001 start";
    ImageCreatorManager& imageCreatorManager = ImageCreatorManager::getInstance();
    string keyId = "";
    shared_ptr<ImageCreator> getimagec = imageCreatorManager.GetImageCreatorByKeyId(keyId);
    ASSERT_EQ(getimagec, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorManagerTest: GetImageCreatorByKeyId001 end";
}
} // namespace Multimedia
} // namespace OHOS