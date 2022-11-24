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

// /**
//  * @tc.name: OnBufferRelease001
//  * @tc.desc: test OnBufferRelease
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, OnBufferRelease001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease001 start";
//     ImageCreator creat;
//     sptr<SurfaceBuffer> buffer;
//     GSError onbuffer = creat.OnBufferRelease(buffer);
//     ASSERT_EQ(onbuffer, GSERROR_NO_ENTRY);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferRelease001 end";
// }

// /**
//  * @tc.name: OnBufferAvailable001
//  * @tc.desc: test OnBufferAvailable
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, OnBufferAvailable001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable001 start";
//     OnBufferAvailable();
//     GTEST_LOG_(INFO) << "ImageCreatorTest: OnBufferAvailable001 end";
// }

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

// /**
//  * @tc.name: ReleaseBuffer001
//  * @tc.desc: test ReleaseBuffer
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, ReleaseBuffer001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: ReleaseBuffer001 start";
//     AllocatorType allocatorType;
//     uint8_t **buffer = nullptr;
//     ReleaseBuffer(allocatorType, buffer);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: ReleaseBuffer001 end";
// }

// /**
//  * @tc.name: AllocHeapBuffer001
//  * @tc.desc: test AllocHeapBuffer
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, AllocHeapBuffer001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: AllocHeapBuffer001 start";
//     uint64_t bufferSize = 0;
//     uint8_t **buffer = 'a';
//     bool alloc = AllocHeapBuffer(bufferSize, buffer);
//     ASSERT_EQ(alloc, false);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: AllocHeapBuffer001 end";
// }

// /**
//  * @tc.name: AllocHeapBuffer002
//  * @tc.desc: test AllocHeapBuffer
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, AllocHeapBuffer002, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: AllocHeapBuffer002 start";
//     uint64_t bufferSize = 1;
//     uint8_t **buffer = nullptr;
//     bool alloc = AllocHeapBuffer(bufferSize, buffer);
//     ASSERT_EQ(alloc, false);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: AllocHeapBuffer002 end";
// }

// /**
//  * @tc.name: AllocHeapBuffer003
//  * @tc.desc: test AllocHeapBuffer
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, AllocHeapBuffer003, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: AllocHeapBuffer003 start";
//     uint64_t bufferSize = 1;
//     uint8_t **buffer = "a";
//     bool alloc = AllocHeapBuffer(bufferSize, buffer);
//     ASSERT_EQ(alloc, true);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: AllocHeapBuffer003 end";
// }

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

// /**
//  * @tc.name: DequeueImage001
//  * @tc.desc: test DequeueImage
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, DequeueImage001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueImage001 start";
//     ImageCreator creat;
//     OHOS::sptr<OHOS::SurfaceBuffer> dequeimage = creat.DequeueImage();
//     ASSERT_NE(dequeimage, nullptr);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: DequeueImage001 end";
// }

// /**
//  * @tc.name: QueueImage001
//  * @tc.desc: test QueueImage
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, QueueImage001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: QueueImage001 start";
//     ImageCreator creat;
//     OHOS::sptr<OHOS::SurfaceBuffer> buffer;
//     creat.QueueImage(buffer);
//     GTEST_LOG_(INFO) << "ImageCreatorTest: QueueImage001 end";
// }

// /**
//  * @tc.name: GetCreatorSurface001
//  * @tc.desc: test GetCreatorSurface
//  * @tc.type: FUNC
//  */
// HWTEST_F(ImageCreatorTest, GetCreatorSurface001, TestSize.Level3)
// {
//     GTEST_LOG_(INFO) << "ImageCreatorTest: GetCreatorSurface001 start";
//     ImageCreator creat;
//     sptr<Surface> ImageCreator = creat.GetCreatorSurface();
//     GTEST_LOG_(INFO) << "ImageCreatorTest: GetCreatorSurface001 end";
// }

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