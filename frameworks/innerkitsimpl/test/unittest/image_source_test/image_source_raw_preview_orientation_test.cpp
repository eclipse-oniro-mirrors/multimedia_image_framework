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
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <memory>
#include <unistd.h>
#include <vector>

#include "image_source.h"
#include "image_type.h"
#include "media_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;

namespace OHOS {
namespace Multimedia {
namespace {
const std::string IMAGE_ROOT_PATH = "/data/local/tmp/image/";
const std::string RAW_PREVIEW_ORIENTATION_KEY = "PreviewOrientation";
const std::string ORIENTATION_KEY = "Orientation";
constexpr size_t BYTE_INDEX_2 = 2;
constexpr size_t BYTE_INDEX_3 = 3;
constexpr size_t BYTE_INDEX_4 = 4;
constexpr uint32_t BYTE_SHIFT_8 = 8;
constexpr uint32_t BYTE_SHIFT_16 = 16;
constexpr uint32_t BYTE_SHIFT_24 = 24;
constexpr size_t TIFF_HEADER_SIZE = 8;
constexpr uint16_t TIFF_MAGIC = 42;
constexpr size_t TIFF_ENTRY_COUNT_SIZE = 2;
constexpr size_t TIFF_IFD_ENTRY_SIZE = 12;
constexpr size_t TIFF_VALUE_FIELD_OFFSET = 8;
constexpr uint16_t EXIF_TYPE_SHORT = 3;
constexpr uint16_t EXIF_TYPE_LONG = 4;
constexpr uint16_t EXIF_NEW_SUBFILE_TYPE_TAG = 0x00FE;

std::unique_ptr<ImageSource> CreateRawSource(const std::string &fileName, uint32_t &errorCode)
{
    SourceOptions opts;
    return ImageSource::CreateImageSource(IMAGE_ROOT_PATH + fileName, opts, errorCode);
}

bool ReadFileToVector(const std::string &fileName, std::vector<uint8_t> &data)
{
    std::ifstream input(IMAGE_ROOT_PATH + fileName, std::ios::binary);
    if (!input.is_open()) {
        return false;
    }
    data = std::vector<uint8_t>(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    return !data.empty();
}

uint16_t ReadUint16(const std::vector<uint8_t> &data, size_t offset, bool littleEndian)
{
    if (offset + BYTE_INDEX_2 > data.size()) {
        return 0;
    }
    return littleEndian ? static_cast<uint16_t>(data[offset] | (data[offset + 1] << BYTE_SHIFT_8)) :
        static_cast<uint16_t>((data[offset] << BYTE_SHIFT_8) | data[offset + 1]);
}

uint32_t ReadUint32(const std::vector<uint8_t> &data, size_t offset, bool littleEndian)
{
    if (offset + BYTE_INDEX_4 > data.size()) {
        return 0;
    }
    if (littleEndian) {
        return static_cast<uint32_t>(data[offset]) |
            (static_cast<uint32_t>(data[offset + 1]) << BYTE_SHIFT_8) |
            (static_cast<uint32_t>(data[offset + BYTE_INDEX_2]) << BYTE_SHIFT_16) |
            (static_cast<uint32_t>(data[offset + BYTE_INDEX_3]) << BYTE_SHIFT_24);
    }
    return (static_cast<uint32_t>(data[offset]) << BYTE_SHIFT_24) |
        (static_cast<uint32_t>(data[offset + 1]) << BYTE_SHIFT_16) |
        (static_cast<uint32_t>(data[offset + BYTE_INDEX_2]) << BYTE_SHIFT_8) |
        data[offset + BYTE_INDEX_3];
}

// Turns the DNG preview IFD into a main IFD in memory, leaving its Orientation only on
// the original image. The preview-only request must not return that value.
bool MakeDngIfd0MainImage(std::vector<uint8_t> &data)
{
    if (data.size() < TIFF_HEADER_SIZE) {
        return false;
    }
    bool littleEndian = false;
    if (data[0] == 'I' && data[1] == 'I') {
        littleEndian = true;
    } else if (data[0] == 'M' && data[1] == 'M') {
        littleEndian = false;
    } else {
        return false;
    }
    if (ReadUint16(data, BYTE_INDEX_2, littleEndian) != TIFF_MAGIC) {
        return false;
    }
    uint32_t ifd0Offset = ReadUint32(data, BYTE_INDEX_4, littleEndian);
    if (ifd0Offset + TIFF_ENTRY_COUNT_SIZE > data.size()) {
        return false;
    }
    uint16_t entryCount = ReadUint16(data, ifd0Offset, littleEndian);
    if (entryCount > (data.size() - ifd0Offset - TIFF_ENTRY_COUNT_SIZE) / TIFF_IFD_ENTRY_SIZE) {
        return false;
    }
    for (uint16_t i = 0; i < entryCount; ++i) {
        size_t entryOffset = ifd0Offset + TIFF_ENTRY_COUNT_SIZE + static_cast<size_t>(i) * TIFF_IFD_ENTRY_SIZE;
        if (ReadUint16(data, entryOffset, littleEndian) != EXIF_NEW_SUBFILE_TYPE_TAG) {
            continue;
        }
        uint16_t type = ReadUint16(data, entryOffset + TIFF_ENTRY_COUNT_SIZE, littleEndian);
        if (type == EXIF_TYPE_SHORT) {
            data[entryOffset + TIFF_VALUE_FIELD_OFFSET] = 0;
            data[entryOffset + TIFF_VALUE_FIELD_OFFSET + 1] = 0;
            return true;
        }
        if (type == EXIF_TYPE_LONG) {
            for (size_t j = 0; j < BYTE_INDEX_4; ++j) {
                data[entryOffset + TIFF_VALUE_FIELD_OFFSET + j] = 0;
            }
            return true;
        }
        return false;
    }
    return false;
}
} // namespace

class ImageSourceRawPreviewOrientationTest : public testing::Test {
public:
    ImageSourceRawPreviewOrientationTest() {}
    ~ImageSourceRawPreviewOrientationTest() {}
};

/**
 * @tc.name: DngPreviewOrientation001
 * @tc.desc: DNG returns the preview Orientation through the reserved key.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, DngPreviewOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.dng", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Top-left");
}

/**
 * @tc.name: DngPreviewOrientationKeepsExif001
 * @tc.desc: Reading the DNG preview Orientation keeps the existing DNG EXIF result unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, DngPreviewOrientationKeepsExif001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.dng", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string dngOrientationBefore;
    uint32_t dngRetBefore = imageSource->GetImagePropertyString(0, ORIENTATION_KEY, dngOrientationBefore);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);

    std::string dngOrientationAfter;
    uint32_t dngRetAfter = imageSource->GetImagePropertyString(0, ORIENTATION_KEY, dngOrientationAfter);
    EXPECT_EQ(dngRetBefore, dngRetAfter);
    EXPECT_EQ(dngOrientationBefore, dngOrientationAfter);
}

/**
 * @tc.name: ReservedPreviewOrientationKeyRejected001
 * @tc.desc: The reserved preview Orientation key is not a generic property key for any
 *           property query API.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, ReservedPreviewOrientationKeyRejected001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.raf", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string reservedValue;
    EXPECT_EQ(imageSource->GetImagePropertyString(0, RAW_PREVIEW_ORIENTATION_KEY, reservedValue),
        static_cast<uint32_t>(ERR_IMAGE_SOURCE_DATA));
    EXPECT_TRUE(reservedValue.empty());

    EXPECT_EQ(imageSource->GetImagePropertyStringBySync(0, RAW_PREVIEW_ORIENTATION_KEY, reservedValue),
        static_cast<uint32_t>(ERR_IMAGE_SOURCE_DATA));
    EXPECT_TRUE(reservedValue.empty());

    MetadataValue typedValue;
    EXPECT_EQ(imageSource->GetImagePropertyByType(0, RAW_PREVIEW_ORIENTATION_KEY, typedValue),
        static_cast<uint32_t>(ERR_IMAGE_SOURCE_DATA));
    EXPECT_TRUE(typedValue.stringValue.empty());
}

/**
 * @tc.name: DngPreviewOrientationRotated001
 * @tc.desc: DNG preview IFD Orientation with a non-default rotation is returned.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, DngPreviewOrientationRotated001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test_dng_readmetadata001.dng", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Right-top");
}

/**
 * @tc.name: DngMainImageOrientationIgnored001
 * @tc.desc: A DNG whose Orientation exists only in the main IFD must not return the original
 *           image rotation through the preview-only request.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, DngMainImageOrientationIgnored001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    ASSERT_TRUE(ReadFileToVector("test_dng_readmetadata001.dng", data));
    ASSERT_TRUE(MakeDngIfd0MainImage(data));

    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data.data(), static_cast<uint32_t>(data.size()), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    uint32_t ret = imageSource->GetRawPreviewOrientation(previewOrientation);
    EXPECT_NE(ret, SUCCESS);
    EXPECT_TRUE(previewOrientation.empty());
}

/**
 * @tc.name: RafPreviewOrientation001
 * @tc.desc: RAF preview EXIF Orientation is returned.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, RafPreviewOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.raf", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Top-left");
}

/**
 * @tc.name: Rw2PreviewOrientation001
 * @tc.desc: RW2 preview EXIF Orientation is returned.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, Rw2PreviewOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.rw2", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Left-bottom");
}

/**
 * @tc.name: PreviewWithoutExifOrientation001
 * @tc.desc: A RAW preview JPEG without its own EXIF Orientation reports unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewWithoutExifOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.arw", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation),
        static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
    EXPECT_TRUE(previewOrientation.empty());
}

/**
 * @tc.name: PreviewWithoutExifOrientationKeepsContainer001
 * @tc.desc: A failed preview Orientation request keeps the container Orientation readable.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewWithoutExifOrientationKeepsContainer001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.arw", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string containerOrientationBefore;
    uint32_t retBefore = imageSource->GetImagePropertyString(0, ORIENTATION_KEY, containerOrientationBefore);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation),
        static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));

    std::string containerOrientationAfter;
    uint32_t retAfter = imageSource->GetImagePropertyString(0, ORIENTATION_KEY, containerOrientationAfter);
    EXPECT_EQ(retBefore, retAfter);
    EXPECT_EQ(containerOrientationBefore, containerOrientationAfter);
}

/**
 * @tc.name: NonRawImageUnsupported001
 * @tc.desc: Non-RAW images are rejected by the preview Orientation request.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, NonRawImageUnsupported001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(IMAGE_ROOT_PATH + "test.jpg", opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation),
        static_cast<uint32_t>(ERR_IMAGE_UNKNOWN_FORMAT));
    EXPECT_TRUE(previewOrientation.empty());
}

/**
 * @tc.name: BufferSourcePreviewOrientation001
 * @tc.desc: The preview Orientation request works on a buffer source.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, BufferSourcePreviewOrientation001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    ASSERT_TRUE(ReadFileToVector("test.raf", data));
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data.data(), static_cast<uint32_t>(data.size()), opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Top-left");
}

/**
 * @tc.name: FdSourcePreviewOrientation001
 * @tc.desc: The preview Orientation request works on a file descriptor source.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, FdSourcePreviewOrientation001, TestSize.Level1)
{
    int fd = open((IMAGE_ROOT_PATH + "test.rw2").c_str(), O_RDONLY);
    ASSERT_NE(fd, -1);
    uint32_t errorCode = 0;
    SourceOptions opts;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(fd, opts, errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Left-bottom");
    close(fd);
}
} // namespace Multimedia
} // namespace OHOS
