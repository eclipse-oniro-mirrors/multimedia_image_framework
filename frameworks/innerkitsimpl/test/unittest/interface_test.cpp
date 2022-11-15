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
#include <fcntl.h>
#include "directory_ex.h"
#include "image_packer.h"
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "incremental_pixel_map.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_map_manager.h"
#include "image_receiver.h"
#include "image_source_util.h"
#include "graphic_common.h"
#include "image_receiver_manager.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string OPTION_FORMAT_TEST = "image/jpeg";
static const std::int32_t OPTION_QUALITY_TEST = 100;
static const std::int32_t OPTION_NUMBERHINT_TEST = 1;

class InterfaceTest : public testing::Test {
public:
    InterfaceTest() {}
    ~InterfaceTest() {}
};

/**
 * @tc.name: InterfaceTest001
 * @tc.desc: PromoteDecoding
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest001 start";
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    uint8_t decodeProgress = 0;
    incPixelMap->PromoteDecoding(decodeProgress);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest001 end";
}

/**
 * @tc.name: InterfaceTest002
 * @tc.desc: DetachFromDecoding
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest002 start";
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    incPixelMap->DetachFromDecoding();
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest002 end";
}

/**
 * @tc.name: InterfaceTest003
 * @tc.desc: GetDecodingStatus
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest003 start";
    uint32_t errorCode = 0;
    IncrementalSourceOptions incOpts;
    incOpts.incrementalMode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    DecodeOptions decodeOpts;
    std::unique_ptr<IncrementalPixelMap> incPixelMap = imageSource->CreateIncrementalPixelMap(0, decodeOpts,
        errorCode);
    incPixelMap->DetachFromDecoding();
    IncrementalDecodingStatus status = incPixelMap->GetDecodingStatus();
    ASSERT_EQ(status.decodingProgress, 0);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest003 end";
}

/**
 * @tc.name: InterfaceTest004
 * @tc.desc: FreePixels
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest004 start";
    PixelMap *pixelMap = nullptr;
    PixelMapManager pixelMapManager(pixelMap);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest111 start";
    pixelMapManager.FreePixels();
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest004 end";
}

/**
 * @tc.name: InterfaceTest005
 * @tc.desc: Invalid
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest005 start";
    PixelMap *pixelMap = nullptr;
    PixelMapManager pixelMapManager(pixelMap);
    bool flag = pixelMapManager.Invalid();
    ASSERT_EQ(flag, true);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest005 end";
}

/**
 * @tc.name: InterfaceTest006
 * @tc.desc: GetPixelMap
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest006 start";
    PixelMap *pixelMap = nullptr;
    PixelMapManager pixelMapManager(pixelMap);
    pixelMapManager.GetPixelMap();
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest006 end";
}

/**
 * @tc.name: InterfaceTest007
 * @tc.desc: GetByteCount
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest007 start";
    PixelMap *pixelMap = nullptr;
    PixelMapManager pixelMapManager(pixelMap);
    int32_t count = pixelMapManager.GetByteCount();
    ASSERT_EQ(count, 0);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest007 end";
}

/**
 * @tc.name: InterfaceTest008
 * @tc.desc: Ref
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest008 start";
    PixelMap *pixelMap = nullptr;
    PixelMapManager pixelMapManager(pixelMap);
    pixelMapManager.Ref();
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest008 end";
}

/**
 * @tc.name: InterfaceTest009
 * @tc.desc: UnRef
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest009 start";
    PixelMap *pixelMap = nullptr;
    PixelMapManager pixelMapManager(pixelMap);
    pixelMapManager.UnRef();
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest009 end";
}

/**
 * @tc.name: InterfaceTest0010
 * @tc.desc: ImagePacker StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest0010 start";
    ImagePacker imagePacker;
    PackOption option;
    option.format = OPTION_FORMAT_TEST;
    option.quality = OPTION_QUALITY_TEST;
    option.numberHint = OPTION_NUMBERHINT_TEST;
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    uint32_t tmp = imagePacker.StartPacking(buffer, bufferSize, option);
    ASSERT_EQ(tmp, SUCCESS);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest0010 end";
}

/**
 * @tc.name: InterfaceTest0011
 * @tc.desc: ImagePacker StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest0011 start";
    ImagePacker imagePacker;
    PackOption option;
    option.format = OPTION_FORMAT_TEST;
    option.quality = OPTION_QUALITY_TEST;
    option.numberHint = OPTION_NUMBERHINT_TEST;
    size_t bufferSize = 0;
    bool ret = ImageUtils::GetFileSize(IMAGE_INPUT_JPEG_PATH, bufferSize);
    ASSERT_EQ(ret, true);
    uint8_t *buffer = nullptr;
    uint32_t tmp = imagePacker.StartPacking(buffer, bufferSize, option);
    ASSERT_NE(tmp, SUCCESS);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest0011 end";
}

/**
 * @tc.name: InterfaceTest0012
 * @tc.desc: ImagePacker StartPacking
 * @tc.type: FUNC
 */
HWTEST_F(InterfaceTest, InterfaceTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest0012 start";
    ImagePacker imagePacker;
    PackOption option;
    option.format = OPTION_FORMAT_TEST;
    option.quality = OPTION_QUALITY_TEST;
    option.numberHint = OPTION_NUMBERHINT_TEST;
    size_t bufferSize = 0;
    uint8_t *buffer = reinterpret_cast<uint8_t *>(malloc(bufferSize));
    ASSERT_NE(buffer, nullptr);
    uint32_t tmp = imagePacker.StartPacking(buffer, bufferSize, option);
    ASSERT_EQ(tmp, SUCCESS);
    GTEST_LOG_(INFO) << "InterfaceTest: InterfaceTest0012 end";
}
}
}