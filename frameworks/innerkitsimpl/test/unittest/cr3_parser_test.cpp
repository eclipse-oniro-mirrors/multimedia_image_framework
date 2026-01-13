/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "cr3_parser.h"
#include "heif_utils.h"
#include "image_log.h"
#include "securec.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
static constexpr uint8_t DATA_SIZE = 16;
static constexpr size_t SIZE = 16;
static constexpr size_t LENGTH_SIZE = 16;
static constexpr size_t FOURCC_LENGTH = 4;
static constexpr uint32_t JPEG_SIZE = 128;
static constexpr uint32_t PAYLOAD_SIZE = 8;
static constexpr uint32_t HEADER_SIZE = 8;
static constexpr uint8_t PAYLOAD_DATA = 0xAB;
static constexpr uint8_t UINT32_BYTE0_SHIFT = 24;
static constexpr uint8_t UINT32_BYTE1_SHIFT = 16;
static constexpr uint8_t UINT32_BYTE2_SHIFT = 8;
static const std::vector<uint8_t> STREAM_MINIMAL_FTYP_MOOV = { 0x00, 0x00, 0x00, 0x14, 'f', 't', 'y', 'p',
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 24) & 0xFF), static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 16) & 0xFF),
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 8) & 0xFF), static_cast<uint8_t>(CR3_FILE_TYPE_CRX & 0xFF),
    0x00, 0x00, 0x00, 0x00, static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 24) & 0xFF),
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 16) & 0xFF), static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 8) & 0xFF),
    static_cast<uint8_t>(CR3_FILE_TYPE_CRX & 0xFF), 0x00, 0x00, 0x00, 0x20, 'm', 'o', 'o', 'v',
    0x00, 0x00, 0x00, 0x18, 'u', 'u', 'i', 'd', 0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0,
    0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48 };
static const std::vector<uint8_t> STREAM_FTYP_NON_CRX = { 0x00, 0x00, 0x00, 0x14, 'f', 't', 'y', 'p',
    'n', 'o', 't', 'e', 0x00, 0x00, 0x00, 0x00, 'n', 'o', 't', 'h', 0x00, 0x00, 0x00, 0x20, 'm', 'o', 'o', 'v',
    0x00, 0x00, 0x00, 0x18, 'u', 'u', 'i', 'd', 0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0,
    0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48 };
static const std::vector<uint8_t> STREAM_FTYP_MOOV = { 0x00, 0x00, 0x00, 0x14, 'f', 't', 'y', 'p',
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 24) & 0xFF), static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 16) & 0xFF),
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 8) & 0xFF), static_cast<uint8_t>(CR3_FILE_TYPE_CRX & 0xFF),
    0x00, 0x00, 0x00, 0x00, 'c', 'r', 'x', ' ', 0x00, 0x00, 0x00, 0x20, 'm', 'o', 'o', 'v',
    0x00, 0x00, 0x00, 0x18, 'u', 'u', 'i', 'd', 0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0,
    0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48, 0x00, 0x00, 0x00, 0x08, 'f', 'r', 'e', 'e' };
static const std::vector<uint8_t> STREAM_FTYP_MOOV_UUID = { 0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p',
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 24) & 0xFF), static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 16) & 0xFF),
    static_cast<uint8_t>((CR3_FILE_TYPE_CRX >> 8) & 0xFF), static_cast<uint8_t>(CR3_FILE_TYPE_CRX & 0xFF),
    0x00, 0x00, 0x00, 0x00, 'c', 'r', 'x', ' ', 'c', 'r', 'x', ' ', 0x00, 0x00, 0x00, 0x20, 'm', 'o', 'o', 'v',
    0x00, 0x00, 0x00, 0x18, 'u', 'u', 'i', 'd', 0x85, 0xC0, 0xB6, 0x87, 0x82, 0x0F, 0x11, 0xE0,
    0x81, 0x11, 0xF4, 0xCE, 0x46, 0x2B, 0x6A, 0x48, 0x00, 0x00, 0x00, 0x38, 'u', 'u', 'i', 'd',
    0xEA, 0xF4, 0x2B, 0x5E, 0x1C, 0x98, 0x4B, 0x88, 0xB9, 0xFB, 0xB7, 0xDC, 0x40, 0x6E, 0x4D, 0x16,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 'p', 'r', 'v', 'w',
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00 };

static void AppendUint32(std::vector<uint8_t> &buf, uint32_t value)
{
    buf.push_back(static_cast<uint8_t>((value >> UINT32_BYTE0_SHIFT) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> UINT32_BYTE1_SHIFT) & 0xFF));
    buf.push_back(static_cast<uint8_t>((value >> UINT32_BYTE2_SHIFT) & 0xFF));
    buf.push_back(static_cast<uint8_t>(value & 0xFF));
}

static void AppendFourcc(std::vector<uint8_t> &buf, const char *fourcc)
{
    buf.insert(buf.end(), fourcc, fourcc + FOURCC_LENGTH);
}

class Cr3ParserTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    std::shared_ptr<Cr3Parser> InitCr3ParserResources()
    {
        size = SIZE;
        needCopy = false;
        heifInputStream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
        start = 0;
        length = 0;
        heifStreamReader = std::make_shared<HeifStreamReader>(heifInputStream, start, length);
        cr3Parser = std::make_shared<Cr3Parser>();
        return cr3Parser;
    }
    uint8_t data[DATA_SIZE] = {0};
    size_t size;
    bool needCopy;
    std::shared_ptr<HeifInputStream> heifInputStream;
    int64_t start;
    size_t length;
    std::shared_ptr<HeifStreamReader> heifStreamReader;
    std::shared_ptr<Cr3Parser> cr3Parser;
};

/**
 * @tc.name: ParseCr3BoxesTest004
 * @tc.desc: Test ParseCr3Boxes, return heif_error_ok when the parser process a minimal FTYP + MOOV payload.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest004, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest004 start";
    auto stream = std::make_shared<HeifBufferInputStream>(STREAM_MINIMAL_FTYP_MOOV.data(),
        STREAM_MINIMAL_FTYP_MOOV.size(), false);
    auto reader = std::make_shared<HeifStreamReader>(stream, 0, STREAM_MINIMAL_FTYP_MOOV.size());
    auto cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->uuidCanonBox_ = std::make_shared<Cr3UuidBox>();

    auto ret = cr3Parser->ParseCr3Boxes(*reader);
    EXPECT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest004 end";
}

/**
 * @tc.name: ParseCr3BoxesTest005
 * @tc.desc: Test ParseCr3Boxes, return heif_error_no_ftyp when the parser process a FTYP with non-CRX brand.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest005, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest005 start";
    auto stream = std::make_shared<HeifBufferInputStream>(STREAM_FTYP_NON_CRX.data(),
        STREAM_FTYP_NON_CRX.size(), false);
    auto reader = std::make_shared<HeifStreamReader>(stream, 0, STREAM_FTYP_NON_CRX.size());
    auto cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->ftypBox_ = std::make_shared<Cr3FtypBox>();

    auto ret = cr3Parser->ParseCr3Boxes(*reader);
    EXPECT_EQ(ret, heif_error_no_ftyp);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest005 end";
}

/**
 * @tc.name: ParseCr3BoxesTest006
 * @tc.desc: Test ParseCr3Boxes, return heif_error_ok when feed a full FTYP + MOOV + dummy free box sequence,
 *           to confirm successful parsing with canonical data.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest006, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest006 start";
    auto stream = std::make_shared<HeifBufferInputStream>(STREAM_FTYP_MOOV.data(), STREAM_FTYP_MOOV.size(), false);
    auto reader = std::make_shared<HeifStreamReader>(stream, 0, STREAM_FTYP_MOOV.size());
    auto cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->ftypBox_ = std::make_shared<Cr3FtypBox>();
    cr3Parser->ftypBox_->majorBrand_ = CR3_FILE_TYPE_CRX;

    auto ret = cr3Parser->ParseCr3Boxes(*reader);
    EXPECT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest006 end";
}

/**
 * @tc.name: ParseCr3BoxesTest007
 * @tc.desc: Test ParseCr3Boxes, return heif_error_ok when the parser process a FTYP + MOOV + PREVIEW-UUID sequence
 *           and populate the preview box.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest007, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest007 start";
    auto stream = std::make_shared<HeifBufferInputStream>(STREAM_FTYP_MOOV_UUID.data(),
        STREAM_FTYP_MOOV_UUID.size(), false);
    auto reader = std::make_shared<HeifStreamReader>(stream, 0, STREAM_FTYP_MOOV_UUID.size());
    auto cr3Parser = std::make_shared<Cr3Parser>();

    auto ret = cr3Parser->ParseCr3Boxes(*reader);
    EXPECT_EQ(ret, heif_error_ok);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest007 end";
}

/**
 * @tc.name: GetPreviewImageInfoTest001
 * @tc.desc: Test GetPreviewImageInfo, preview info size is same as prvwBox_->jpegSize_ when prvwBox_ is not nullptr,
 *           otherwise, is 0.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, GetPreviewImageInfoTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetPreviewImageInfoTest001 start";
    auto cr3Parser = std::make_shared<Cr3Parser>();

    auto ret = cr3Parser->GetPreviewImageInfo();
    EXPECT_EQ(ret.size, 0);
    EXPECT_EQ(cr3Parser->prvwBox_, nullptr);

    cr3Parser->prvwBox_ = std::make_shared<Cr3PrvwBox>();
    cr3Parser->prvwBox_->jpegSize_ = JPEG_SIZE;
    ret = cr3Parser->GetPreviewImageInfo();
    EXPECT_EQ(ret.size, JPEG_SIZE);
    EXPECT_NE(cr3Parser->prvwBox_, nullptr);
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetPreviewImageInfoTest001 end";
}

/**
 * @tc.name: GetCr3BoxDataTest002
 * @tc.desc: Test GetCr3BoxData, return the correct payload data when input a valid box and stream.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, GetCr3BoxDataTest002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetCr3BoxDataTest002 start";
    std::vector<uint8_t> payload(PAYLOAD_SIZE, PAYLOAD_DATA);
    std::vector<uint8_t> boxStream;
    AppendUint32(boxStream, static_cast<uint32_t>(payload.size() + HEADER_SIZE));
    AppendFourcc(boxStream, "udta");
    boxStream.insert(boxStream.end(), payload.begin(), payload.end());

    auto parseStream = std::make_shared<HeifBufferInputStream>(boxStream.data(), boxStream.size(), false);
    HeifStreamReader reader(parseStream, 0, boxStream.size());
    std::shared_ptr<Cr3Box> box;
    uint32_t recursionCount = 0;
    ASSERT_EQ(Cr3Box::MakeCr3FromReader(reader, box, recursionCount), heif_error_ok);
    ASSERT_NE(box, nullptr);

    auto cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->inputStream_ = std::make_shared<HeifBufferInputStream>(boxStream.data(), boxStream.size(), false);

    auto ret = cr3Parser->GetCr3BoxData(box);
    EXPECT_EQ(ret, payload);
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetCr3BoxDataTest002 end";
}

/**
 * @tc.name: GetCr3BoxDataTest003
 * @tc.desc: Test GetCr3BoxData, return empty vector when input box is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, GetCr3BoxDataTest003, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetCr3BoxDataTest003 start";
    std::shared_ptr<Cr3Box> box;
    ASSERT_EQ(box, nullptr);
    auto cr3Parser = std::make_shared<Cr3Parser>();

    auto ret = cr3Parser->GetCr3BoxData(box);
    EXPECT_EQ(ret, std::vector<uint8_t>());
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetCr3BoxDataTest003 end";
}

/**
 * @tc.name: ParseCr3BoxesTest001
 * @tc.desc: Test Cr3Parser::ParseCr3Boxes - when ftypBox is not initialized (neither exists nor sets majorBrand),
 *           expect return error code heif_error_no_ftyp.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest001 start";
    auto cr3Parser = InitCr3ParserResources();
    auto ret = cr3Parser->ParseCr3Boxes(*heifStreamReader);
    EXPECT_EQ(ret, heif_error_no_ftyp);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest001 end";
}

/**
 * @tc.name: ParseCr3BoxesTest002
 * @tc.desc: Test Cr3Parser::ParseCr3Boxes - ftypBox valid, moovBox lacks uuidCanonBox,
 *           expect heif_error_primary_item_not_found.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest002, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest002 start";
    auto cr3Parser = InitCr3ParserResources();
    cr3Parser->ftypBox_ = std::make_shared<Cr3FtypBox>();
    cr3Parser->ftypBox_->majorBrand_ = CR3_FILE_TYPE_CRX;
    cr3Parser->moovBox_ = std::make_shared<Cr3MoovBox>();
    auto ret = cr3Parser->ParseCr3Boxes(*heifStreamReader);
    EXPECT_EQ(ret, heif_error_primary_item_not_found);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest002 end";
}

/**
 * @tc.name: ParseCr3BoxesTest003
 * @tc.desc: Test Cr3Parser::ParseCr3Boxes - ftypBox with boxSize < headerSize (invalid),
 *           expect heif_error_invalid_box_size.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, ParseCr3BoxesTest003, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest003 start";
    uint8_t data[DATA_SIZE] = {0x00, 0x00, 0x00, 0x07, 0x66, 0x74, 0x79, 0x70};
    size_t size = sizeof(data);
    bool needCopy = false;
    std::shared_ptr<HeifInputStream> stream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    int64_t start = 0;
    size_t length = LENGTH_SIZE;
    std::shared_ptr<HeifStreamReader> reader
        = std::make_shared<HeifStreamReader>(stream, start, length);
    std::shared_ptr<Cr3Parser> cr3Parser = std::make_shared<Cr3Parser>();
    auto ret = cr3Parser->ParseCr3Boxes(*reader);
    EXPECT_EQ(ret, heif_error_invalid_box_size);
    GTEST_LOG_(INFO) << "Cr3ParserTest: ParseCr3BoxesTest003 start";
}

/**
 * @tc.name: GetCr3BoxDataTest001
 * @tc.desc: Test Cr3Parser::GetCr3BoxData - when Cr3Parser's inputStream_ is set to nullptr (invalid stream),
 *           call method to read data from valid Cr3Box, expect return empty std::vector<uint8_t>.
 * @tc.type: FUNC
 */
HWTEST_F(Cr3ParserTest, GetCr3BoxDataTest001, TestSize.Level3) {
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetCr3BoxDataTest001 start";
    const std::shared_ptr<Cr3Box> cr3Box = std::make_shared<Cr3Box>();
    std::shared_ptr<Cr3Parser> cr3Parser = std::make_shared<Cr3Parser>();
    cr3Parser->inputStream_ = nullptr;
    auto ret = cr3Parser->GetCr3BoxData(cr3Box);
    EXPECT_EQ(ret, std::vector<uint8_t>());
    GTEST_LOG_(INFO) << "Cr3ParserTest: GetCr3BoxDataTest001 end";
}
} // namespace ImagePlugin
} // namespace OHOS