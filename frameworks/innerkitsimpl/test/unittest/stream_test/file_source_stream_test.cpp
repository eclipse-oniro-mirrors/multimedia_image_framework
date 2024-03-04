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
#define private public
#include <fstream>
#include <fcntl.h>
#include "file_source_stream.h"
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
static constexpr size_t FILE_SIZE = 10;
static constexpr size_t SIZE_T = 0;
class FileSourceStreamTest : public testing::Test {
public:
    FileSourceStreamTest() {}
    ~FileSourceStreamTest() {}
};

/**
 * @tc.name: FileSourceStreamTest001
 * @tc.desc: CreateSourceStream by pathName
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest001 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest001 end";
}

/**
 * @tc.name: FileSourceStreamTest002
 * @tc.desc: CreateSourceStream by wrong pathName
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest002 start";
    const string pathName = "";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(pathName);
    ASSERT_EQ(fileSourceStream, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest002 end";
}

/**
 * @tc.name: FileSourceStreamTest003
 * @tc.desc: CreateSourceStream fd is -1
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest003 start";
    const int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(fd);
    ASSERT_NE(fileSourceStream, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest003 end";
}

/**
 * @tc.name: FileSourceStreamTest004
 * @tc.desc: CreateSourceStream fd is -1
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest004 start";
    const int fd = -1;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(fd);
    ASSERT_EQ(fileSourceStream, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest004 end";
}

/**
 * @tc.name: FileSourceStreamTest005
 * @tc.desc: Read
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest005 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = MAXSIZE;
    bool ret = fileSourceStream->Read(desiredSize, outData);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest005 end";
}

/**
 * @tc.name: FileSourceStreamTest006
 * @tc.desc: Read desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest006 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 0;
    bool ret = fileSourceStream->Read(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest006 end";
}

/**
 * @tc.name: FileSourceStreamTest007
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest007 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = MAXSIZE;
    bool ret = fileSourceStream->Peek(desiredSize, outData);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest007 end";
}

/**
 * @tc.name: FileSourceStreamTest008
 * @tc.desc: Peek desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest008 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 0;
    bool ret = fileSourceStream->Peek(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest008 end";
}

/**
 * @tc.name: FileSourceStreamTest009
 * @tc.desc: Read
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest009 start";
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

    uint8_t *outBuffer = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = size;
    uint32_t readSize;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest009 end";
}

/**
 * @tc.name: FileSourceStreamTest0010
 * @tc.desc: Read desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0010 start";
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

    uint8_t *outBuffer = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = 0;
    uint32_t readSize;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0010 end";
}

/**
 * @tc.name: FileSourceStreamTest0011
 * @tc.desc: Read outBuffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0011 start";
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

    uint8_t *outBuffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = size;
    uint32_t readSize;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0011 end";
}

/**
 * @tc.name: FileSourceStreamTest0012
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0012 start";
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

    uint8_t *outBuffer = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = size;
    uint32_t readSize;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0012 end";
}

/**
 * @tc.name: FileSourceStreamTest0013
 * @tc.desc: Peek desiredSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0013 start";
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

    uint8_t *outBuffer = const_cast<uint8_t *>(pixelMap->GetPixels());
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = 0;
    uint32_t readSize;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0013 end";
}

/**
 * @tc.name: FileSourceStreamTest0014
 * @tc.desc: Peek outBuffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0014 start";
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

    uint8_t *outBuffer = nullptr;
    uint32_t size = pixelMap->GetCapacity();
    uint32_t desiredSize = size;
    uint32_t readSize;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0014 end";
}

/**
 * @tc.name: FileSourceStreamTest0015
 * @tc.desc: Tell
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0015 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint32_t ret = fileSourceStream->Tell();
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0015 end";
}

/**
 * @tc.name: FileSourceStreamTest0016
 * @tc.desc: Seek position is 0
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0016 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint32_t position = 0;
    bool ret = fileSourceStream->Seek(position);
    ASSERT_NE(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0016 end";
}

/**
 * @tc.name: FileSourceStreamTest0017
 * @tc.desc: Seek position is 10000
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0017 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint32_t position = MAXSIZE;
    bool ret = fileSourceStream->Seek(position);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0017 end";
}

/**
 * @tc.name: FileSourceStreamTest0018
 * @tc.desc: GetStreamSize
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0018 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    size_t ret = fileSourceStream->GetStreamSize();
    ASSERT_NE(ret, SIZE_T);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0018 end";
}

/**
 * @tc.name: FileSourceStreamTest0019
 * @tc.desc: GetDataPtr
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0019 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint8_t *ret = fileSourceStream->GetDataPtr();
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0019 end";
}

/**
 * @tc.name: FileSourceStreamTest0020
 * @tc.desc: GetStreamType
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0020 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint32_t ret = fileSourceStream->GetStreamType();
    ASSERT_EQ(ret, ImagePlugin::FILE_STREAM_TYPE);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0020 end";
}

/**
 * @tc.name: FileSourceStreamTest0021
 * @tc.desc: CreateSourceStream fd
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0021 start";
    const int fd = open("/data/local/tmp/image/test.jpg", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(fd, SIZE_T, FILE_SIZE);
    ASSERT_NE(fileSourceStream, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0021 end";
}

/**
 * @tc.name: FileSourceStreamTest0022
 * @tc.desc: CreateSourceStream fd is -1
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0022 start";
    const int fd = -1;
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(fd, -1, SIZE_T);
    ASSERT_EQ(fileSourceStream, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0022 end";
}

/**
 * @tc.name: FileSourceStreamTest0023
 * @tc.desc: Read desiredSize is 1
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0023 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 1;
    fileSourceStream->filePtr_ = fopen("/data/local/tmp/image/test.jpg", "w+");
    fileSourceStream->fileSize_ = 0;
    fileSourceStream->fileOffset_ = 0;
    bool ret = fileSourceStream->Read(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0023 end";
}

/**
 * @tc.name: FileSourceStreamTest0024
 * @tc.desc: Peek desiredSize is 1
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0024 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    DataStreamBuffer outData;
    uint32_t desiredSize = 1;
    fileSourceStream->filePtr_ = fopen("/data/local/tmp/image/test.jpg", "w+");
    fileSourceStream->fileSize_ = 0;
    fileSourceStream->fileOffset_ = 0;
    bool ret = fileSourceStream->Peek(desiredSize, outData);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0024 end";
}

/**
 * @tc.name: FileSourceStreamTest0025
 * @tc.desc: Read desiredSize is 1
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0025 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint32_t desiredSize = 0;
    uint8_t *outBuffer = nullptr;
    uint32_t bufferSize = 0;
    uint32_t readSize = 0;
    bool ret = fileSourceStream->Read(desiredSize, outBuffer, bufferSize, readSize);
    ASSERT_EQ(ret, false);

    desiredSize = 2;
    outBuffer = new uint8_t;
    fileSourceStream->fileSize_ = 1;
    fileSourceStream->fileOffset_ = 1;
    ret = fileSourceStream->Read(desiredSize, outBuffer, bufferSize, readSize);
    ASSERT_EQ(ret, false);
    delete outBuffer;
    outBuffer = nullptr;
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0025 end";
}

/**
 * @tc.name: FileSourceStreamTest0026
 * @tc.desc: Peek
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0026 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    uint8_t *outBuffer = new uint8_t;
    uint32_t size = 2;
    uint32_t desiredSize = 1;
    uint32_t readSize = 2;
    fileSourceStream->fileSize_ = 2;
    fileSourceStream->fileOffset_ = 2;
    bool ret = fileSourceStream->Peek(desiredSize, outBuffer, size, readSize);
    ASSERT_EQ(ret, false);
    delete outBuffer;
    outBuffer = nullptr;
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0026 end";
}

/**
 * @tc.name: FileSourceStreamTest0027
 * @tc.desc: GetDataPtr
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourcFileSourceStreamTest0027eStreamTest0019 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    fileSourceStream->fileData_ = new uint8_t;
    uint8_t *ret = fileSourceStream->GetDataPtr();
    ASSERT_NE(ret, nullptr);
    delete fileSourceStream->fileData_;
    fileSourceStream->fileData_ = nullptr;
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0027 end";
}

/**
 * @tc.name: FileSourceStreamTest0028
 * @tc.desc: ToOutputDataStream
 * @tc.type: FUNC
 */
HWTEST_F(FileSourceStreamTest, FileSourceStreamTest0028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0028 start";
    std::unique_ptr<FileSourceStream> fileSourceStream = FileSourceStream::CreateSourceStream(IMAGE_INPUT_JPG_PATH);
    ASSERT_NE(fileSourceStream, nullptr);
    fileSourceStream->filePtr_ = fopen("/data/local/tmp/image/test.jpg", "w+");
    auto ret = fileSourceStream->ToOutputDataStream();
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "FileSourceStreamTest: FileSourceStreamTest0028 end";
}
}
}
