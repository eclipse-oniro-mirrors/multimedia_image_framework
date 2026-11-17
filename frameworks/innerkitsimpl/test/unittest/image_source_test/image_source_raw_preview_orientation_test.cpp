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

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <memory>
#include <string>
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
// 只保留 CR3 的 ftyp 品牌头，用于验证截断的 box 结构被拒绝。
constexpr size_t TRUNCATED_CR3_SIZE = 32;

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
 * @tc.name: Cr3PreviewWithoutExifOrientation001
 * @tc.desc: A CR3 preview located through its PRVW box without EXIF Orientation reports unsupported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, Cr3PreviewWithoutExifOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("test.cr3", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation),
        static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
    EXPECT_TRUE(previewOrientation.empty());
}

/**
 * @tc.name: ArwSamplePreviewOrientation001
 * @tc.desc: A Sony ARW preview JPEG carrying its own EXIF Orientation is decoded.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, ArwSamplePreviewOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("sample_arw_sony_ilce7s.arw", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Right-top");
}

/**
 * @tc.name: Cr2SamplePreviewOrientation001
 * @tc.desc: A Canon CR2 preview JPEG carrying its own EXIF Orientation is decoded.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, Cr2SamplePreviewOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("sample_cr2_canon_eos20d.cr2", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Left-bottom");
}

/**
 * @tc.name: Cr3SamplePreviewOrientation001
 * @tc.desc: A Canon CR3 preview located through its PRVW box returns its EXIF Orientation.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, Cr3SamplePreviewOrientation001, TestSize.Level1)
{
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = CreateRawSource("sample_cr3_canon_eos_r6.cr3", errorCode);
    ASSERT_EQ(errorCode, SUCCESS);
    ASSERT_NE(imageSource, nullptr);

    std::string previewOrientation;
    EXPECT_EQ(imageSource->GetRawPreviewOrientation(previewOrientation), SUCCESS);
    EXPECT_EQ(previewOrientation, "Right-top");
}

/**
 * @tc.name: TruncatedSourceRejected001
 * @tc.desc: A source truncated inside the CR3 box structure is rejected.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, TruncatedSourceRejected001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    ASSERT_TRUE(ReadFileToVector("sample_cr3_canon_eos_r6.cr3", data));
    // 保留 ftypcrx 品牌但截断 box 结构，CR3 预览定位必须失败。
    data.resize(TRUNCATED_CR3_SIZE);
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(data.data(), static_cast<uint32_t>(data.size()), opts, errorCode);
    if (imageSource == nullptr) {
        EXPECT_NE(errorCode, SUCCESS);
        return;
    }

    std::string orientation;
    EXPECT_NE(imageSource->GetRawPreviewOrientation(orientation), SUCCESS);
    EXPECT_TRUE(orientation.empty());
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

namespace {
constexpr uint8_t JPEG_MARKER_PREFIX = 0xFF;
constexpr uint8_t JPEG_MARKER_SOI = 0xD8;
constexpr uint8_t JPEG_MARKER_EOI = 0xD9;
constexpr uint8_t JPEG_MARKER_SOS = 0xDA;
constexpr uint8_t JPEG_MARKER_APP0 = 0xE0;
constexpr uint8_t JPEG_MARKER_APP1 = 0xE1;
constexpr uint16_t EXIF_ORIENTATION_TAG = 0x0112;
constexpr uint16_t EXIF_SUB_IFD_TAG = 0x8769;
constexpr uint16_t EXIF_TYPE_RATIONAL = 5;
constexpr uint16_t EXIF_TIFF_BAD_MAGIC = 43;
constexpr uint16_t ORIENTATION_MIN = 1;
constexpr uint16_t ORIENTATION_MAX = 8;
constexpr uint16_t ORIENTATION_OUT_OF_RANGE = 9;
constexpr size_t JPEG_SEGMENT_LENGTH_OFFSET = 2;
constexpr size_t EXIF_HEADER_SIZE = 6;
// APP1 段内 "Exif\0\0" 起始偏移：段标记 2 字节 + 长度 2 字节。
constexpr size_t APP1_EXIF_HEADER_OFFSET = 4;
// APP1 段内 TIFF 起始偏移：位于 "Exif\0\0" 之后。
constexpr size_t APP1_TIFF_OFFSET = APP1_EXIF_HEADER_OFFSET + EXIF_HEADER_SIZE;
// 构造的预览 JPEG 必须远小于真实预览长度，避免覆盖 RAW 容器元数据。
constexpr size_t MAX_SYNTHETIC_PREVIEW_SIZE = 512;

struct TiffEntrySpec {
    uint16_t tag;
    uint16_t type;
    uint32_t count;
    uint32_t value;
};

void PutUint16(std::vector<uint8_t> &data, size_t offset, uint16_t value, bool bigEndian)
{
    if (bigEndian) {
        data[offset] = static_cast<uint8_t>(value >> BYTE_SHIFT_8);
        data[offset + 1] = static_cast<uint8_t>(value & 0xFF);
        return;
    }
    data[offset] = static_cast<uint8_t>(value & 0xFF);
    data[offset + 1] = static_cast<uint8_t>(value >> BYTE_SHIFT_8);
}

void PutUint32(std::vector<uint8_t> &data, size_t offset, uint32_t value, bool bigEndian)
{
    if (bigEndian) {
        data[offset] = static_cast<uint8_t>(value >> BYTE_SHIFT_24);
        data[offset + 1] = static_cast<uint8_t>((value >> BYTE_SHIFT_16) & 0xFF);
        data[offset + BYTE_INDEX_2] = static_cast<uint8_t>((value >> BYTE_SHIFT_8) & 0xFF);
        data[offset + BYTE_INDEX_3] = static_cast<uint8_t>(value & 0xFF);
        return;
    }
    data[offset] = static_cast<uint8_t>(value & 0xFF);
    data[offset + 1] = static_cast<uint8_t>((value >> BYTE_SHIFT_8) & 0xFF);
    data[offset + BYTE_INDEX_2] = static_cast<uint8_t>((value >> BYTE_SHIFT_16) & 0xFF);
    data[offset + BYTE_INDEX_3] = static_cast<uint8_t>(value >> BYTE_SHIFT_24);
}

uint32_t SubIfdPointer(size_t ifd0EntryCount)
{
    return static_cast<uint32_t>(TIFF_HEADER_SIZE + TIFF_ENTRY_COUNT_SIZE +
        ifd0EntryCount * TIFF_IFD_ENTRY_SIZE + BYTE_INDEX_4);
}

void WriteIfd(std::vector<uint8_t> &data, size_t offset, const std::vector<TiffEntrySpec> &entries, bool bigEndian)
{
    PutUint16(data, offset, static_cast<uint16_t>(entries.size()), bigEndian);
    for (size_t i = 0; i < entries.size(); ++i) {
        const size_t entryOffset = offset + TIFF_ENTRY_COUNT_SIZE + i * TIFF_IFD_ENTRY_SIZE;
        PutUint16(data, entryOffset, entries[i].tag, bigEndian);
        PutUint16(data, entryOffset + BYTE_INDEX_2, entries[i].type, bigEndian);
        PutUint32(data, entryOffset + BYTE_INDEX_4, entries[i].count, bigEndian);
        // SHORT 值只落在值域前两个字节，其余保持 0，符合 EXIF 对齐约定。
        if (entries[i].type == EXIF_TYPE_SHORT) {
            PutUint16(data, entryOffset + TIFF_VALUE_FIELD_OFFSET,
                static_cast<uint16_t>(entries[i].value), bigEndian);
        } else {
            PutUint32(data, entryOffset + TIFF_VALUE_FIELD_OFFSET, entries[i].value, bigEndian);
        }
    }
}

std::vector<uint8_t> BuildTiff(bool bigEndian, uint16_t magic, const std::vector<TiffEntrySpec> &ifd0,
    const std::vector<TiffEntrySpec> &subIfd = {})
{
    const size_t ifd0Size = TIFF_ENTRY_COUNT_SIZE + ifd0.size() * TIFF_IFD_ENTRY_SIZE + BYTE_INDEX_4;
    const size_t subIfdSize = subIfd.empty() ? 0 :
        TIFF_ENTRY_COUNT_SIZE + subIfd.size() * TIFF_IFD_ENTRY_SIZE + BYTE_INDEX_4;
    std::vector<uint8_t> data(TIFF_HEADER_SIZE + ifd0Size + subIfdSize, 0);
    data[0] = bigEndian ? 'M' : 'I';
    data[1] = data[0];
    PutUint16(data, BYTE_INDEX_2, magic, bigEndian);
    PutUint32(data, BYTE_INDEX_4, static_cast<uint32_t>(TIFF_HEADER_SIZE), bigEndian);
    WriteIfd(data, TIFF_HEADER_SIZE, ifd0, bigEndian);
    if (!subIfd.empty()) {
        WriteIfd(data, TIFF_HEADER_SIZE + ifd0Size, subIfd, bigEndian);
    }
    return data;
}

std::vector<uint8_t> BuildSegment(uint8_t marker, const std::vector<uint8_t> &payload)
{
    const size_t length = payload.size() + JPEG_SEGMENT_LENGTH_OFFSET;
    std::vector<uint8_t> segment { JPEG_MARKER_PREFIX, marker,
        static_cast<uint8_t>(length >> BYTE_SHIFT_8), static_cast<uint8_t>(length & 0xFF) };
    segment.insert(segment.end(), payload.begin(), payload.end());
    return segment;
}

std::vector<uint8_t> BuildExifPayload(const std::vector<uint8_t> &tiff)
{
    std::vector<uint8_t> payload { 'E', 'x', 'i', 'f', 0, 0 };
    payload.insert(payload.end(), tiff.begin(), tiff.end());
    return payload;
}

std::vector<uint8_t> BuildExifSegment(const std::vector<uint8_t> &tiff)
{
    return BuildSegment(JPEG_MARKER_APP1, BuildExifPayload(tiff));
}

std::vector<uint8_t> BuildPreviewJpeg(const std::vector<std::vector<uint8_t>> &segments, uint8_t tailMarker)
{
    std::vector<uint8_t> jpeg { JPEG_MARKER_PREFIX, JPEG_MARKER_SOI };
    for (const auto &segment : segments) {
        jpeg.insert(jpeg.end(), segment.begin(), segment.end());
    }
    jpeg.push_back(JPEG_MARKER_PREFIX);
    jpeg.push_back(tailMarker);
    return jpeg;
}

size_t FindFirstJpegSoi(const std::vector<uint8_t> &data)
{
    for (size_t i = 0; i + BYTE_INDEX_3 <= data.size(); ++i) {
        if (data[i] == JPEG_MARKER_PREFIX && data[i + 1] == JPEG_MARKER_SOI &&
            data[i + BYTE_INDEX_2] == JPEG_MARKER_PREFIX) {
            return i;
        }
    }
    return std::string::npos;
}

bool ReplacePreviewJpeg(std::vector<uint8_t> &data, const std::vector<uint8_t> &jpeg)
{
    const size_t soi = FindFirstJpegSoi(data);
    if (soi == std::string::npos || jpeg.size() > MAX_SYNTHETIC_PREVIEW_SIZE ||
        soi + jpeg.size() > data.size()) {
        return false;
    }
    std::copy(jpeg.begin(), jpeg.end(), data.begin() + soi);
    return true;
}

uint32_t ReadBufferPreviewOrientation(std::vector<uint8_t> &data, std::string &orientation)
{
    SourceOptions opts;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(data.data(),
        static_cast<uint32_t>(data.size()), opts, errorCode);
    if (imageSource == nullptr) {
        return errorCode;
    }
    return imageSource->GetRawPreviewOrientation(orientation);
}

// 在真实 RAW 资源上覆写首个 JPEG SOI 起的字节，得到可控的预览 JPEG。
uint32_t ReadPatchedPreviewOrientation(std::vector<uint8_t> &data, const std::vector<uint8_t> &jpeg,
    std::string &orientation, bool &patched)
{
    patched = ReplacePreviewJpeg(data, jpeg);
    if (!patched) {
        return ERR_IMAGE_SOURCE_DATA;
    }
    return ReadBufferPreviewOrientation(data, orientation);
}

// 定位首个 JPEG 之后的 EXIF APP1 段，用于原位改写 TIFF，避免依赖预览偏移推断。
size_t FindPreviewExifSegment(const std::vector<uint8_t> &data)
{
    const size_t soi = FindFirstJpegSoi(data);
    if (soi == std::string::npos) {
        return std::string::npos;
    }
    for (size_t i = soi + BYTE_INDEX_2; i + APP1_TIFF_OFFSET <= data.size(); ++i) {
        if (data[i] == JPEG_MARKER_PREFIX && data[i + 1] == JPEG_MARKER_APP1 &&
            std::memcmp(&data[i + APP1_EXIF_HEADER_OFFSET], "Exif\0\0", EXIF_HEADER_SIZE) == 0) {
            return i;
        }
    }
    return std::string::npos;
}

bool RewritePreviewExifTiff(std::vector<uint8_t> &data, const std::vector<uint8_t> &tiff)
{
    const size_t app1 = FindPreviewExifSegment(data);
    if (app1 == std::string::npos) {
        return false;
    }
    const size_t segmentLength = (static_cast<size_t>(data[app1 + JPEG_SEGMENT_LENGTH_OFFSET]) << BYTE_SHIFT_8) |
        data[app1 + JPEG_SEGMENT_LENGTH_OFFSET + 1];
    if (segmentLength < JPEG_SEGMENT_LENGTH_OFFSET + EXIF_HEADER_SIZE) {
        return false;
    }
    const size_t tiffSize = segmentLength - JPEG_SEGMENT_LENGTH_OFFSET - EXIF_HEADER_SIZE;
    if (tiff.size() > tiffSize) {
        return false;
    }
    std::copy(tiff.begin(), tiff.end(), data.begin() + app1 + APP1_TIFF_OFFSET);
    return true;
}

uint32_t ReadRewrittenPreviewOrientation(std::vector<uint8_t> &data, const std::vector<uint8_t> &tiff,
    std::string &orientation, bool &patched)
{
    patched = RewritePreviewExifTiff(data, tiff);
    if (!patched) {
        return ERR_IMAGE_SOURCE_DATA;
    }
    return ReadBufferPreviewOrientation(data, orientation);
}
} // namespace

/**
 * @tc.name: PreviewOrientationBigEndian001
 * @tc.desc: A big-endian EXIF TIFF block of the preview JPEG is decoded.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationBigEndian001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    ASSERT_TRUE(ReadFileToVector("test.raf", data));
    const std::vector<uint8_t> tiff = BuildTiff(true, TIFF_MAGIC,
        {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 6}});
    std::string orientation;
    bool patched = false;
    ASSERT_EQ(ReadRewrittenPreviewOrientation(data, tiff, orientation, patched), SUCCESS);
    EXPECT_TRUE(patched);
    EXPECT_EQ(orientation, "Right-top");
}

/**
 * @tc.name: PreviewOrientationLongType001
 * @tc.desc: An Orientation entry stored as EXIF LONG is decoded.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationLongType001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    ASSERT_TRUE(ReadFileToVector("test.raf", data));
    const std::vector<uint8_t> tiff = BuildTiff(false, TIFF_MAGIC,
        {{EXIF_ORIENTATION_TAG, EXIF_TYPE_LONG, 1, ORIENTATION_MAX}});
    std::string orientation;
    bool patched = false;
    ASSERT_EQ(ReadRewrittenPreviewOrientation(data, tiff, orientation, patched), SUCCESS);
    EXPECT_TRUE(patched);
    EXPECT_EQ(orientation, "Left-bottom");
}

/**
 * @tc.name: PreviewOrientationSubIfd001
 * @tc.desc: An Orientation stored only in the Exif SubIFD is used as the fallback.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationSubIfd001, TestSize.Level1)
{
    std::vector<uint8_t> data;
    ASSERT_TRUE(ReadFileToVector("test.raf", data));
    const std::vector<uint8_t> tiff = BuildTiff(false, TIFF_MAGIC,
        {{EXIF_SUB_IFD_TAG, EXIF_TYPE_LONG, 1, SubIfdPointer(1)}},
        {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 3}});
    std::string orientation;
    bool patched = false;
    ASSERT_EQ(ReadRewrittenPreviewOrientation(data, tiff, orientation, patched), SUCCESS);
    EXPECT_TRUE(patched);
    EXPECT_EQ(orientation, "Bottom-right");
}

/**
 * @tc.name: PreviewOrientationInvalidValue001
 * @tc.desc: Orientation values outside 1..8 are rejected instead of being reported.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationInvalidValue001, TestSize.Level1)
{
    std::vector<uint8_t> source;
    ASSERT_TRUE(ReadFileToVector("test.raf", source));
    for (const uint16_t invalidValue : {static_cast<uint16_t>(0), ORIENTATION_OUT_OF_RANGE}) {
        std::vector<uint8_t> data = source;
        const std::vector<uint8_t> tiff = BuildTiff(false, TIFF_MAGIC,
            {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, invalidValue}});
        std::string orientation;
        bool patched = false;
        EXPECT_EQ(ReadRewrittenPreviewOrientation(data, tiff, orientation, patched),
            static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
        EXPECT_TRUE(patched);
        EXPECT_TRUE(orientation.empty());
    }
}

/**
 * @tc.name: PreviewOrientationUnsupportedEntry001
 * @tc.desc: An Orientation entry with an unsupported type or count is ignored.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationUnsupportedEntry001, TestSize.Level1)
{
    std::vector<uint8_t> source;
    ASSERT_TRUE(ReadFileToVector("test.raf", source));
    const std::vector<std::vector<TiffEntrySpec>> cases = {
        {{EXIF_ORIENTATION_TAG, EXIF_TYPE_RATIONAL, 1, ORIENTATION_MIN}},
        {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 2, ORIENTATION_MIN}},
    };
    for (const auto &entries : cases) {
        std::vector<uint8_t> data = source;
        const std::vector<uint8_t> tiff = BuildTiff(false, TIFF_MAGIC, entries);
        std::string orientation;
        bool patched = false;
        EXPECT_EQ(ReadRewrittenPreviewOrientation(data, tiff, orientation, patched),
            static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
        EXPECT_TRUE(patched);
    }
}

/**
 * @tc.name: PreviewOrientationMalformedTiff001
 * @tc.desc: Broken TIFF header, IFD offset and entry count are rejected without crashing.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationMalformedTiff001, TestSize.Level1)
{
    std::vector<uint8_t> source;
    ASSERT_TRUE(ReadFileToVector("test.raf", source));

    std::vector<std::vector<uint8_t>> tiffs;
    // 空 IFD：没有 Orientation 也没有 SubIFD 指针。
    tiffs.push_back(BuildTiff(false, TIFF_MAGIC, {}));
    // TIFF 魔数错误。
    tiffs.push_back(BuildTiff(false, EXIF_TIFF_BAD_MAGIC, {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 1}}));
    // IFD 偏移落在 TIFF 头内部。
    std::vector<uint8_t> lowIfd = BuildTiff(false, TIFF_MAGIC, {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 1}});
    PutUint32(lowIfd, BYTE_INDEX_4, static_cast<uint32_t>(BYTE_INDEX_4), false);
    tiffs.push_back(lowIfd);
    // IFD 偏移越过数据尾部。
    std::vector<uint8_t> farIfd = BuildTiff(false, TIFF_MAGIC, {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 1}});
    PutUint32(farIfd, BYTE_INDEX_4, 0xFFFF, false);
    tiffs.push_back(farIfd);
    // 条目数远超数据可容纳的条目。
    std::vector<uint8_t> hugeCount = BuildTiff(false, TIFF_MAGIC, {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 1}});
    PutUint16(hugeCount, TIFF_HEADER_SIZE, 0xFFFF, false);
    tiffs.push_back(hugeCount);
    // 非法字节序标记。
    std::vector<uint8_t> badOrder = BuildTiff(false, TIFF_MAGIC, {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 1}});
    badOrder[0] = 'X';
    badOrder[1] = 'X';
    tiffs.push_back(badOrder);

    for (const auto &tiff : tiffs) {
        std::vector<uint8_t> data = source;
        std::string orientation;
        bool patched = false;
        EXPECT_EQ(ReadRewrittenPreviewOrientation(data, tiff, orientation, patched),
            static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
        EXPECT_TRUE(patched);
        EXPECT_TRUE(orientation.empty());
    }
}

/**
 * @tc.name: PreviewOrientationInvalidSegments001
 * @tc.desc: Invalid segment length, stop markers and truncated segments end the scan.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationInvalidSegments001, TestSize.Level1)
{
    std::vector<uint8_t> source;
    ASSERT_TRUE(ReadFileToVector("test.raf", source));
    const std::vector<uint8_t> exifSegment = BuildExifSegment(BuildTiff(false, TIFF_MAGIC,
        {{EXIF_ORIENTATION_TAG, EXIF_TYPE_SHORT, 1, 1}}));

    // 段长度小于长度字段自身。
    std::vector<uint8_t> zeroLength = exifSegment;
    zeroLength[JPEG_SEGMENT_LENGTH_OFFSET] = 0x00;
    zeroLength[JPEG_SEGMENT_LENGTH_OFFSET + 1] = 0x01;
    // Exif 头不足 6 字节。
    std::vector<uint8_t> shortExif = BuildSegment(JPEG_MARKER_APP1, { 'E', 'x', 'i', 'f' });
    // Exif 头之后的 TIFF 数据不足 8 字节。
    std::vector<uint8_t> shortTiff = BuildSegment(JPEG_MARKER_APP1, BuildExifPayload({ 0x49, 0x49, 0x2A, 0x00 }));

    const std::vector<std::vector<std::vector<uint8_t>>> segmentCases = {
        {zeroLength},
        {shortExif},
        {shortTiff},
    };
    for (const auto &segments : segmentCases) {
        std::vector<uint8_t> data = source;
        const std::vector<uint8_t> jpeg = BuildPreviewJpeg(segments, JPEG_MARKER_EOI);
        std::string orientation;
        bool patched = false;
        EXPECT_EQ(ReadPatchedPreviewOrientation(data, jpeg, orientation, patched),
            static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
        EXPECT_TRUE(patched);
        EXPECT_TRUE(orientation.empty());
    }

    for (const uint8_t tail : { JPEG_MARKER_EOI, JPEG_MARKER_SOS }) {
        std::vector<uint8_t> data = source;
        const std::vector<uint8_t> jpeg = BuildPreviewJpeg({}, tail);
        std::string orientation;
        bool patched = false;
        EXPECT_EQ(ReadPatchedPreviewOrientation(data, jpeg, orientation, patched),
            static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
        EXPECT_TRUE(patched);
    }
}

/**
 * @tc.name: PreviewOrientationInvalidJpegSignature001
 * @tc.desc: A preview range that is not a JPEG is rejected on the first bytes.
 * @tc.type: FUNC
 */
HWTEST_F(ImageSourceRawPreviewOrientationTest, PreviewOrientationInvalidJpegSignature001, TestSize.Level1)
{
    std::vector<uint8_t> source;
    ASSERT_TRUE(ReadFileToVector("test.raf", source));
    const std::vector<std::vector<uint8_t>> jpegs = {
        { 0x00, 0x00, 0x00, 0x00 },
        { JPEG_MARKER_PREFIX, 0x00, JPEG_MARKER_PREFIX, 0x00 },
        { JPEG_MARKER_PREFIX, JPEG_MARKER_SOI, 0x00, 0x00 },
        // 段结束后游标落在非 marker 前缀字节上，扫描终止。
        { JPEG_MARKER_PREFIX, JPEG_MARKER_SOI, JPEG_MARKER_PREFIX, JPEG_MARKER_APP0, 0x00, 0x04, 0x00, 0x00, 0x00 },
    };
    for (const auto &jpeg : jpegs) {
        std::vector<uint8_t> data = source;
        std::string orientation;
        bool patched = false;
        EXPECT_EQ(ReadPatchedPreviewOrientation(data, jpeg, orientation, patched),
            static_cast<uint32_t>(ERR_IMAGE_DECODE_EXIF_UNSUPPORT));
        EXPECT_TRUE(patched);
        EXPECT_TRUE(orientation.empty());
    }
}

} // namespace Multimedia
} // namespace OHOS
