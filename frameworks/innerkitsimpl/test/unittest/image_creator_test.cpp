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
#include "hilog/log.h"
#include "image_creator.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_utils.h"
#include "directory_ex.h"
#include "image_creator_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class ImageCreatorTest : public testing::Test {
public:
    ImageCreatorTest() {}
    ~ImageCreatorTest() {}
};

/**
 * @tc.name: CreateImageCreator001
 * @tc.desc: test CreateImageCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, CreateImageCreator001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator001 start";
    ImageCreator creat;
    int32_t width = 1;
    int32_t height = 2;
    int32_t format = 3;
    int32_t capicity = 4;
    std::shared_ptr<ImageCreator> createimagec = creat.CreateImageCreator(width, height, format, capicity);
    ASSERT_NE(createimagec, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: CreateImageCreator001 end";
}

/**
 * @tc.name: SaveSTP001
 * @tc.desc: test SaveSTP
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSTP001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP001 start";
    ImageCreator creat;
    uint32_t *buffer = nullptr;
    uint8_t *tempBuffer = nullptr;
    uint32_t bufferSize= 1;
    InitializationOptions initializationOpts;
    int32_t savesp = creat.SaveSTP(buffer, tempBuffer, bufferSize, initializationOpts);
    ASSERT_EQ(savesp, -1);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP001 end";
}

/**
 * @tc.name: SaveSTP002
 * @tc.desc: test SaveSTP
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSTP002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP002 start";
    ImageCreator creat;
    uint32_t *buffer = nullptr;
    uint8_t *tempBuffer = nullptr;
    uint32_t bufferSize= 0;
    InitializationOptions initializationOpts;
    std::unique_ptr<PixelMap> pixelMap = PixelMap::Create(buffer, bufferSize, initializationOpts);
    ASSERT_EQ(pixelMap, nullptr);
    int32_t savesp = creat.SaveSTP(buffer, tempBuffer, bufferSize, initializationOpts);
    ASSERT_EQ(savesp, ERR_MEDIA_INVALID_VALUE);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSTP002 end";
}

/**
 * @tc.name: SaveSenderBufferAsImage001
 * @tc.desc: test SaveSenderBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSenderBufferAsImage001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage001 start";
    ImageCreator creat;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    InitializationOptions initializationOpts;
    int32_t savesend = creat.SaveSenderBufferAsImage(buffer, initializationOpts);
    ASSERT_EQ(savesend, 0);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage001 end";
}

/**
 * @tc.name: SaveSenderBufferAsImage002
 * @tc.desc: test SaveSenderBufferAsImage
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, SaveSenderBufferAsImage002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage002start";
    ImageCreator creat;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer;
    InitializationOptions initializationOpts;
    int32_t savesend = creat.SaveSenderBufferAsImage(buffer, initializationOpts);
    ASSERT_EQ(savesend, 0);
    GTEST_LOG_(INFO) << "ImageCreatorTest: SaveSenderBufferAsImage002 end";
}

/**
 * @tc.name: getSurfaceById001
 * @tc.desc: test getSurfaceById
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, getSurfaceById001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: getSurfaceById001 start";
    ImageCreator creat;
    std::string id = "";
    sptr<Surface> getsrfid = creat.getSurfaceById(id);
    ASSERT_EQ(getsrfid, nullptr);
    GTEST_LOG_(INFO) << "ImageCreatorTest: getSurfaceById001 end";
}

/**
 * @tc.name: ReleaseCreator001
 * @tc.desc: test ReleaseCreator
 * @tc.type: FUNC
 */
HWTEST_F(ImageCreatorTest, ReleaseCreator001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageCreatorTest: ReleaseCreator001 start";
    ImageCreator creat;
    creat.ReleaseCreator();
    GTEST_LOG_(INFO) << "ImageCreatorTest: ReleaseCreator001 end";
}
} // namespace Multimedia
} // namespace OHOS