/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "image_mime_type.h"
#include "image_source.h"
#include "media_errors.h"
#include "source_stream.h"
#include "xmp_metadata.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {

namespace {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";
static const std::string IMAGE_DNG_XMP_PATH = "/data/local/tmp/image/dng_xmp.dng";
static const std::string IMAGE_GIF_XMP_PATH = "/data/local/tmp/image/gif_xmp.gif";
static const std::string IMAGE_JPEG_XMP_PATH = "/data/local/tmp/image/jpeg_xmp.jpg";
static const std::string IMAGE_PNG_XMP_PATH = "/data/local/tmp/image/png_xmp.png";
static const std::string IMAGE_TIFF_XMP_PATH = "/data/local/tmp/image/tiff_xmp.tiff";

static const uint32_t MAX_SOURCE_SIZE = 300 * 1024 * 1024;
constexpr int32_t INVALID_FILE_DESCRIPTOR = -1;
}

class ImageSourceXMPTest : public testing::Test {
public:
    ImageSourceXMPTest() {}
    ~ImageSourceXMPTest() {}
};

class MockSourceStream : public SourceStream {
public:
    MockSourceStream(uint8_t* bufPtr, uint32_t size) : bufferPtr_(bufPtr), size_(size) {};
    ~MockSourceStream() = default;

    bool Read(uint32_t desiredSize, ImagePlugin::DataStreamBuffer &outData)
    {
        return false;
    }

    bool Read(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize)
    {
        return false;
    }

    bool Peek(uint32_t desiredSize, ImagePlugin::DataStreamBuffer &outData)
    {
        return false;
    }

    bool Peek(uint32_t desiredSize, uint8_t *outBuffer, uint32_t bufferSize, uint32_t &readSize)
    {
        return false;
    }

    uint32_t Tell()
    {
        return 0;
    }

    bool Seek(uint32_t position)
    {
        return false;
    }

    uint8_t* GetDataPtr()
    {
        return bufferPtr_;
    }

    size_t GetStreamSize()
    {
        return size_;
    }

private:
    uint8_t* bufferPtr_ = nullptr;
    uint32_t size_ = 0;
};

static bool CompareXMPTag(const XMPTag &tag1, const XMPTag &tag2)
{
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.value: " << tag1.value << ", tag2.value: " << tag2.value;
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.type: " << static_cast<int>(tag1.type) << ", tag2.type: "
        << static_cast<int>(tag2.type);
    return tag1.value == tag2.value && tag1.type == tag2.type;
}

static std::unique_ptr<ImageSource> CreateImageSourceByPath(const std::string &path)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(path, opts, errorCode);
    return imageSource;
}

static std::unique_ptr<ImageSource> CreateImageSourceByFd(const int fd)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/jpeg";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(fd, opts, errorCode);
    return imageSource;
}

/**
 * @tc.name: ReadXMPMetadataTest001
 * @tc.desc: Verify that ReadXMPMetadata works correctly using jpeg image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest001 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    imageSource->xmpMetadata_ = nullptr;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest001 end";
}

/**
 * @tc.name: ReadXMPMetadataTest002
 * @tc.desc: Verify that ReadXMPMetadata works correctly using png image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest002 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_PNG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest002 end";
}

/**
 * @tc.name: ReadXMPMetadataTest003
 * @tc.desc: Verify that ReadXMPMetadata works correctly using gif image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest003 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_GIF_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest003 end";
}

/**
 * @tc.name: ReadXMPMetadataTest004
 * @tc.desc: Verify that ReadXMPMetadata works correctly using tiff image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest004 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_TIFF_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest004 end";
}

/**
 * @tc.name: ReadXMPMetadataTest005
 * @tc.desc: Verify that ReadXMPMetadata works correctly using dng image.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest005 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_DNG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = imageSource->CreateXMPMetadataByImageSource(IMAGE_DNG_FORMAT);
    ASSERT_EQ(errorCode, SUCCESS);
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest005 end";
}

/**
 * @tc.name: ReadXMPMetadataTest006
 * @tc.desc: Verify that ReadXMPMetadata works correctly when called multiple times.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest006 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata1 = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata1, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    std::shared_ptr<XMPMetadata> xmpMetadata2 = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata2, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_EQ(xmpMetadata1.get(), xmpMetadata2.get());

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest006 end";
}

/**
 * @tc.name: ReadXMPMetadataTest007
 * @tc.desc: Verify that ReadXMPMetadata returns nullptr when there is no xmp metadata.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, ReadXMPMetadataTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest007 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_INPUT_JPEG_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_EQ(xmpMetadata, nullptr);
    ASSERT_NE(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: ReadXMPMetadataTest007 end";
}

/**
 * @tc.name: WriteXMPMetadataTest001
 * @tc.desc: Verify that WriteXMPMetadata works correctly with jpeg source.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest001 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag;
    tag.type = XMPTagType::SIMPLE;
    tag.value = "WriteXMPMetadataTest001";
    errorCode = xmpMetadata->SetValue("xmp:CreatorTool", tag.type, tag.value);
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_EQ(errorCode, SUCCESS);

    // Verify that the XMP metadata is written correctly
    std::unique_ptr<ImageSource> imageSource2 = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource2, nullptr);

    std::shared_ptr<XMPMetadata> xmpMetadata2 = imageSource2->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata2, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag2;
    xmpMetadata2->GetTag("xmp:CreatorTool", tag2);
    EXPECT_TRUE(CompareXMPTag(tag, tag2));
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest001 end";
}

/**
 * @tc.name: WriteXMPMetadataTest002
 * @tc.desc: Verify that WriteXMPMetadata works correctly when using file descriptor.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest002 start";
    int32_t fd = open(IMAGE_JPEG_XMP_PATH.c_str(), O_RDWR);
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByFd(fd);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    imageSource->srcFilePath_ = "";

    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_EQ(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest002 end";
}

/**
 * @tc.name: WriteXMPMetadataTest003
 * @tc.desc: Verify that WriteXMPMetadata works correctly when both file path and file descriptor are invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest003 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    imageSource->srcFilePath_ = "";
    imageSource->srcFd_ = INVALID_FILE_DESCRIPTOR;

    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_NE(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest003 end";
}

/**
 * @tc.name: WriteXMPMetadataTest004
 * @tc.desc: Verify that WriteXMPMetadata works correctly when xmpMetadata is null.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest004 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = nullptr;
    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_NE(errorCode, SUCCESS);

    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest004 end";
}

/**
 * @tc.name: WriteXMPMetadataTest005
 * @tc.desc: Verify that WriteXMPMetadata works correctly with gif source.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest005 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_GIF_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag;
    tag.type = XMPTagType::SIMPLE;
    tag.value = "WriteXMPMetadataTest005";
    errorCode = xmpMetadata->SetValue("xmp:CreatorTool", tag.type, tag.value);
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_EQ(errorCode, SUCCESS);

    // Verify that the XMP metadata is written correctly
    std::unique_ptr<ImageSource> imageSource2 = CreateImageSourceByPath(IMAGE_GIF_XMP_PATH);
    ASSERT_NE(imageSource2, nullptr);

    std::shared_ptr<XMPMetadata> xmpMetadata2 = imageSource2->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata2, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag2;
    xmpMetadata2->GetTag("xmp:CreatorTool", tag2);
    EXPECT_TRUE(CompareXMPTag(tag, tag2));
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest005 end";
}

/**
 * @tc.name: WriteXMPMetadataTest006
 * @tc.desc: Verify that WriteXMPMetadata works correctly with png source.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest006 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_PNG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag;
    tag.type = XMPTagType::SIMPLE;
    tag.value = "WriteXMPMetadataTest007";
    errorCode = xmpMetadata->SetValue("xmp:CreatorTool", tag.type, tag.value);
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_EQ(errorCode, SUCCESS);

    // Verify that the XMP metadata is written correctly
    std::unique_ptr<ImageSource> imageSource2 = CreateImageSourceByPath(IMAGE_PNG_XMP_PATH);
    ASSERT_NE(imageSource2, nullptr);

    std::shared_ptr<XMPMetadata> xmpMetadata2 = imageSource2->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata2, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag2;
    xmpMetadata2->GetTag("xmp:CreatorTool", tag2);
    EXPECT_TRUE(CompareXMPTag(tag, tag2));
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest006 end";
}

/**
 * @tc.name: WriteXMPMetadataTest007
 * @tc.desc: Verify that WriteXMPMetadata works correctly with tiff source.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, WriteXMPMetadataTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest007 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_TIFF_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    uint32_t errorCode = 0;
    std::shared_ptr<XMPMetadata> xmpMetadata = imageSource->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag;
    tag.type = XMPTagType::SIMPLE;
    tag.value = "WriteXMPMetadataTest008";
    errorCode = xmpMetadata->SetValue("xmp:CreatorTool", tag.type, tag.value);
    ASSERT_EQ(errorCode, SUCCESS);
    errorCode = imageSource->WriteXMPMetadata(xmpMetadata);
    ASSERT_EQ(errorCode, SUCCESS);

    // Verify that the XMP metadata is written correctly
    std::unique_ptr<ImageSource> imageSource2 = CreateImageSourceByPath(IMAGE_TIFF_XMP_PATH);
    ASSERT_NE(imageSource2, nullptr);

    std::shared_ptr<XMPMetadata> xmpMetadata2 = imageSource2->ReadXMPMetadata(errorCode);
    ASSERT_NE(xmpMetadata2, nullptr);
    ASSERT_EQ(errorCode, SUCCESS);

    XMPTag tag2;
    xmpMetadata2->GetTag("xmp:CreatorTool", tag2);
    EXPECT_TRUE(CompareXMPTag(tag, tag2));
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: WriteXMPMetadataTest007 end";
}

/**
 * @tc.name: CreateXMPMetadataByImageSourceTest001
 * @tc.desc: Verify that CreateXMPMetadataByImageSource when xmpMetadata is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, CreateXMPMetadataByImageSourceTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest001 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    imageSource->xmpMetadata_ = std::make_shared<XMPMetadata>();
    uint32_t errorCode = imageSource->CreateXMPMetadataByImageSource(IMAGE_JPEG_FORMAT);
    ASSERT_EQ(errorCode, SUCCESS);
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest001 end";
}

/**
 * @tc.name: CreateXMPMetadataByImageSourceTest002
 * @tc.desc: Verify that CreateXMPMetadataByImageSource when sourceStreamPtr is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, CreateXMPMetadataByImageSourceTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest002 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);
    ASSERT_EQ(imageSource->xmpMetadata_, nullptr);

    imageSource->sourceStreamPtr_ = nullptr;
    uint32_t errorCode = imageSource->CreateXMPMetadataByImageSource(IMAGE_JPEG_FORMAT);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest002 end";
}

/**
 * @tc.name: CreateXMPMetadataByImageSourceTest003
 * @tc.desc: Verify that CreateXMPMetadataByImageSource when data size is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, CreateXMPMetadataByImageSourceTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest003 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    imageSource->sourceStreamPtr_ = std::make_unique<MockSourceStream>(nullptr, 0);
    uint32_t errorCode = imageSource->CreateXMPMetadataByImageSource(IMAGE_JPEG_FORMAT);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);

    imageSource->sourceStreamPtr_ = std::make_unique<MockSourceStream>(nullptr, MAX_SOURCE_SIZE + 1);
    errorCode = imageSource->CreateXMPMetadataByImageSource(IMAGE_JPEG_FORMAT);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest003 end";
}

/**
 * @tc.name: CreateXMPMetadataByImageSourceTest004
 * @tc.desc: Verify that CreateXMPMetadataByImageSource when data buffer is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceXMPTest, CreateXMPMetadataByImageSourceTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest004 start";
    std::unique_ptr<ImageSource> imageSource = CreateImageSourceByPath(IMAGE_JPEG_XMP_PATH);
    ASSERT_NE(imageSource, nullptr);

    imageSource->sourceStreamPtr_ = std::make_unique<MockSourceStream>(nullptr, MAX_SOURCE_SIZE);
    uint32_t errorCode = imageSource->CreateXMPMetadataByImageSource(IMAGE_JPEG_FORMAT);
    ASSERT_EQ(errorCode, ERR_IMAGE_SOURCE_DATA);
    GTEST_LOG_(INFO) << "ImageSourceXMPTest: CreateXMPMetadataByImageSourceTest004 end";
}
} // namespace Multimedia
} // namespace OHOS