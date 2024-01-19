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
#include "buffer_packer_stream.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/test.jpg";
static constexpr uint32_t MAXSIZE = 10000;
class BufferPackerStreamTest : public testing::Test {
public:
    BufferPackerStreamTest() {}
    ~BufferPackerStreamTest() {}
};

/**
 * @tc.name: BufferPackerStreamTest002
 * @tc.desc: Write buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BufferPackerStreamTest, BufferPackerStreamTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest002 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest002 end";
}

/**
 * @tc.name: BufferPackerStreamTest003
 * @tc.desc: Write size is 0
 * @tc.type: FUNC
 */
HWTEST_F(BufferPackerStreamTest, BufferPackerStreamTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest003 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = 0;
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest003 end";
}

/**
 * @tc.name: BufferPackerStreamTest001
 * @tc.desc: Write
 * @tc.type: FUNC
 */
HWTEST_F(BufferPackerStreamTest, BufferPackerStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest001 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest001 end";
}

/**
 * @tc.name: BufferPackerStreamTest004
 * @tc.desc: Write outputData is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BufferPackerStreamTest, BufferPackerStreamTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest004 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    uint8_t *data = nullptr;
    const uint8_t *buffer = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    bool ret = bufferPackerStream.Write(buffer, size);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest004 end";
}

/**
 * @tc.name: BufferPackerStreamTest005
 * @tc.desc: Write
 * @tc.type: FUNC
 */
HWTEST_F(BufferPackerStreamTest, BufferPackerStreamTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest005 start";
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(IMAGE_INPUT_JPG_PATH, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource.get(), nullptr);

    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(pixelMap.get(), nullptr);
    uint8_t *data = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t maxSize = MAXSIZE;
    BufferPackerStream bufferPackerStream(data, maxSize);
    int64_t ret = bufferPackerStream.BytesWritten();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "BufferPackerStreamTest: BufferPackerStreamTest005 end";
}
}
}