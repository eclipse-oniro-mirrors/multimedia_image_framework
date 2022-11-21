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
#include "incremental_source_stream.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_source.h"
#include "image_source_util.h"
#include "media_errors.h"
#include "pixel_map.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::ImageSourceUtil;
using namespace OHOS::ImagePlugin;

namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPG_PATH = "/data/local/tmp/image/test.jpg";
static constexpr uint32_t MAXSIZE = 10000;
static constexpr size_t SIZE_T = 0;
class IncrementalSourceStreamTest : public testing::Test {
public:
    IncrementalSourceStreamTest() {}
    ~IncrementalSourceStreamTest() {}
};

/**
 * @tc.name: IncrementalSourceStreamTest001
 * @tc.desc: CreateSourceStream by pathName
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest001 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest001 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest002
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest002 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = MAXSIZE;
    bool ret = ins->Peek(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest002 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest003
 * @tc.desc: Peek desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest003 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 0;
    bool ret = ins->Peek(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest003 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest004
 * @tc.desc: Read
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest004 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = MAXSIZE;
    bool ret = ins->Read(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest004 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest005
 * @tc.desc: Read desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest005 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 0;
    bool ret = ins->Read(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest005 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest006
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest006 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = size;
    uint32_t readSize;
    bool ret = ins->Peek(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest006 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest007
 * @tc.desc: Peek desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest007 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = 0;
    uint32_t readSize;
    bool ret = ins->Peek(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest007 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest008
 * @tc.desc: Read
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest008 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = size;
    uint32_t readSize;
    bool ret = ins->Read(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest008 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest009
 * @tc.desc: Read desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest009 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = 0;
    uint32_t readSize;
    bool ret = ins->Read(desiredSize, data, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest009 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0010
 * @tc.desc: Tell
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0010 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    uint32_t ret = ins->Tell();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0010 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0011
 * @tc.desc: Seek
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0011 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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

    uint32_t position = pixelMap->GetCapacity();
    bool ret = ins->Seek(position);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0011 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0012
 * @tc.desc: Seek position is -1
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0012 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);

    uint32_t position = -1;
    bool ret = ins->Seek(position);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0012 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0013
 * @tc.desc: Seek IncrementalMode is INCREMENTAL_DATA
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0013 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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

    const uint8_t *data = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    bool isCompleted = true;
    uint32_t ret = ins->UpdateData(data, size, isCompleted);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0013 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0014
 * @tc.desc: Seek IncrementalMode is FULL_DATA
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0014 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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

    const uint8_t *data = pixelMap->GetPixels();
    uint32_t size = pixelMap->GetCapacity();
    bool isCompleted = true;
    uint32_t ret = ins->UpdateData(data, size, isCompleted);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0014 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0015
 * @tc.desc: UpdateData data is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0015 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
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

    const uint8_t *data = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    bool isCompleted = true;
    uint32_t ret = ins->UpdateData(data, size, isCompleted);
    ASSERT_EQ(ret, ERR_IMAGE_DATA_ABNORMAL);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0015 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0016
 * @tc.desc: Seek position is -1
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0016 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    bool ret = ins->IsStreamCompleted();
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0016 end";
}

/**
 * @tc.name: IncrementalSourceStreamTest0017
 * @tc.desc: GetStreamSize
 * @tc.type: FUNC
 */
HWTEST_F(IncrementalSourceStreamTest, IncrementalSourceStreamTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0017 start";
    IncrementalMode mode = IncrementalMode::INCREMENTAL_DATA;
    std::unique_ptr<IncrementalSourceStream> ins = IncrementalSourceStream::CreateSourceStream(mode);
    ASSERT_NE(ins, nullptr);
    size_t ret = ins->GetStreamSize();
    ASSERT_EQ(ret, SIZE_T);
    GTEST_LOG_(INFO) << "IncrementalSourceStreamTest: IncrementalSourceStreamTest0017 end";
}
}
}