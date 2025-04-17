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

#define private public
#include <gtest/gtest.h>

#include "media_errors.h"
#include "png_image_chunk_utils.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {
constexpr size_t BUF_SIZE_ZERO = 0;
constexpr size_t BUF_SIZE_ONE = 1;
constexpr size_t BUF_SIZE_TWO = 2;
constexpr size_t BUF_SIZE_FOUR = 4;
constexpr size_t IMAGE_SEG_MAX_SIZE = 65536;
constexpr size_t ERR_IMAGE_SEG_MAX_SIZE = 65540;
constexpr auto PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE = 21;
constexpr size_t KEY_SIZE_ZERO = 0;
constexpr size_t KEY_SIZE_ONE = 1;
constexpr size_t OFFSET_ZERO = 0;
constexpr size_t OFFSET_ONE = 1;
constexpr size_t OFFSET_TWO = 2;
constexpr uint8_t BYTE_ZERO = 0;
constexpr uint8_t BYTE_ONE = 1;
constexpr int BUF_CMP_SUCCESS = 0;

class PngImageChunkUtilsTest : public testing::Test {
public:
    PngImageChunkUtilsTest() {}
    ~PngImageChunkUtilsTest() {}
};

/**
 *@tc.name: ParseTextChunk001
 *@tc.desc: test the ParseTextChunk method when value is 0 or 1
 *@tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, ParseTextChuink001, TestSize.Level3)
{
    DataBuf chunkData(BUF_SIZE_ONE);
    DataBuf tiffData(BUF_SIZE_ONE);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ONE);
    bool isCompressed = true;
    int res = PngImageChunkUtils::ParseTextChunk(
        chunkData, PngImageChunkUtils::TextChunkType::tEXtChunk, tiffData, isCompressed);
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);

    chunkData.Reset();
    tiffData.Reset();
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ZERO);
    res = PngImageChunkUtils::ParseTextChunk(
        chunkData, PngImageChunkUtils::TextChunkType::tEXtChunk, tiffData, isCompressed);
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
}

/**
 * @tc.name: GetRawTextFromZtxtChunk001
 * @tc.desc: test the GetRawTextFromZtxtChunk method
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, GetRawTextFromZtxtChunk001, TestSize.Level3)
{
    DataBuf emptyBuf = {};
    DataBuf chunkData(BUF_SIZE_ZERO);
    DataBuf rawText;
    bool isCompressed = true;
    auto res = PngImageChunkUtils::GetRawTextFromZtxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    int cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);

    chunkData.Reset();
    chunkData.Resize(BUF_SIZE_ONE);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ZERO);
    rawText.Reset();
    res = PngImageChunkUtils::GetRawTextFromZtxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);

    chunkData.Reset();
    chunkData.Resize(BUF_SIZE_TWO);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ZERO);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ONE);
    rawText.Reset();
    res = PngImageChunkUtils::GetRawTextFromZtxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);
}

/**
 * @tc.name: GetRawTextFromZtxtChunk002
 * @tc.desc: test the GetRawTextFromZtxtChunk method when key size is zero or the size of chunkData is error
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, GetRawTextFromZtxtChunk002, TestSize.Level3)
{
    DataBuf emptyBuf = {};
    DataBuf chunkData(BUF_SIZE_TWO);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ZERO);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ZERO);
    DataBuf rawText;
    bool isCompressed = true;
    auto res = PngImageChunkUtils::GetRawTextFromZtxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    int cmpRes = res.CmpBytes(OFFSET_ZERO, &rawText, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);

    chunkData.Reset();
    rawText.Reset();
    chunkData.Resize(ERR_IMAGE_SEG_MAX_SIZE);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ZERO);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ZERO);
    res = PngImageChunkUtils::GetRawTextFromZtxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);
}

/**
 * @tc.name: GetRawTextFromTextChunk001
 * @tc.desc: test the GetRawTextFromTextChunk method when rawTextsize is 0
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, GetRawTextFromTextChunk001, TestSize.Level3)
{
    DataBuf chunkData(BUF_SIZE_TWO);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ZERO);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ZERO);
    DataBuf rawText;
    auto res = PngImageChunkUtils::GetRawTextFromTextChunk(chunkData, KEY_SIZE_ONE, rawText);
    int cmpRes = res.CmpBytes(OFFSET_ZERO, &rawText, rawText.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);
}

/**
 * @tc.name: GetRawTextFromItxtChunk001
 * @tc.desc: test the GetRawTextFromItxtChunk method when buffer size is 2 or 4 or IMAGE_SEG_MAX_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, GetRawTextFromItxtChunk001, TestSize.Level3)
{
    DataBuf emptyBuf = {};
    DataBuf chunkData(BUF_SIZE_TWO);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ONE);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ONE);
    DataBuf rawText;
    bool isCompressed = true;
    auto res = PngImageChunkUtils::GetRawTextFromItxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    int cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);

    chunkData.Reset();
    rawText.Reset();
    chunkData.Resize(BUF_SIZE_FOUR);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ONE);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ONE);
    chunkData.WriteUInt8(OFFSET_TWO, BYTE_ONE);
    res = PngImageChunkUtils::GetRawTextFromItxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);

    chunkData.Reset ();
    rawText.Reset ();
    chunkData.Resize(IMAGE_SEG_MAX_SIZE);
    chunkData.WriteUInt8(OFFSET_ZERO, BYTE_ONE);
    chunkData.WriteUInt8(OFFSET_ONE, BYTE_ONE);
    chunkData.WriteUInt8(OFFSET_TWO, BYTE_ONE);
    res = PngImageChunkUtils::GetRawTextFromItxtChunk(chunkData, KEY_SIZE_ZERO, rawText, isCompressed);
    cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);
}

/**
 * @tc.name: GetRawTextFromChunk001
 * @tc.desc: test the GetRawTextFromChunk method when chunkType is error type
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, GetRawTextFromChunk001, TestSize.Level3)
{
    PngImageChunkUtils::TextChunkType errChunkType = static_cast<PngImageChunkUtils::TextChunkType>(10);
    DataBuf emptyBuf = {};
    DataBuf chunkData(BUF_SIZE_ONE);
    bool isCompressed = true;
    auto res = PngImageChunkUtils::GetRawTextFromChunk(chunkData, KEY_SIZE_ZERO, errChunkType, isCompressed);
    int cmpRes = res.CmpBytes(OFFSET_ZERO, &emptyBuf, emptyBuf.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);
}

/**
 * @tc.name: FindExifKeyword001
 * @tc.desc: test the FindExifKeyword method when keyword is nullptr and size is 0 or IMAGE_SEG_MAX_SIZE and key word is
 *           normal or error
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, FindExifKeyword001, TestSize.Level3)
{
    std::string str1 = "Raw profile type exif";
    std::string str2 = "Raw profile type APP1";
    std::string str3 = "Error profile type";
    const byte* PNG_PROFILE_EXIF = reinterpret_cast<const byte*>(str1.data());
    const byte* PNG_PROFILE_APP1 = reinterpret_cast<const byte*>(str2.data());
    const byte* ERR_PNG_PROFILE = reinterpret_cast<const byte*>(str3.data());

    bool res = PngImageChunkUtils::FindExifKeyword(nullptr, BUF_SIZE_ZERO);
    EXPECT_FALSE(res);

    res = PngImageChunkUtils::FindExifKeyword(nullptr, IMAGE_SEG_MAX_SIZE);
    EXPECT_FALSE(res);

    res = PngImageChunkUtils::FindExifKeyword(
        ERR_PNG_PROFILE, PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE);
    EXPECT_FALSE(res);

    res = PngImageChunkUtils::FindExifKeyword(
        ERR_PNG_PROFILE, PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE);
    EXPECT_FALSE(res);

    res = PngImageChunkUtils::FindExifKeyword(
        PNG_PROFILE_EXIF, PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE);
    EXPECT_TRUE(res);

    res = PngImageChunkUtils::FindExifKeyword(
        PNG_PROFILE_APP1, PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: FindExifFromTxt001
 * @tc.desc: test the FindExifFromTxt method when chunkData size is over PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, FindExifFromTxt001, TestSize.Level3)
{
    DataBuf chunkData(PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE + 1);
    std::string str1 = "Raw profile type exif";
    byte* PNG_PROFILE_EXIF = reinterpret_cast<byte*>(str1.data());
    byte* index = PNG_PROFILE_EXIF;
    for (size_t offset = 0; offset < PNG_CHUNK_KEYBOARD_EXIF_APP1_SIZE; offset++) {
        chunkData.WriteUInt8(offset, *index);
        index++;
    }
    bool res = PngImageChunkUtils::FindExifFromTxt(chunkData);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: GetTiffDataFromRawText001
 * @tc.desc: test the GetTiffDataFromRawText method when exifInfo is empty
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, GetTiffDataFromRawText001, TestSize.Level3)
{
    DataBuf rawText(BUF_SIZE_ZERO);
    DataBuf tiffData;
    int res = PngImageChunkUtils::GetTiffDataFromRawText(rawText, tiffData);
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
}

/**
 * @tc.name: StepOverNewLine001
 * @tc.desc: test the StepOverNewLine method when the newline in different places
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, StepOverNewLine001, TestSize.Level3)
{
    std::string str1 = "sourcePtr";
    byte* data = reinterpret_cast<byte*>(str1.data());
    byte* pData = data;
    DataBuf rawText(str1.size());
    for (size_t offset = 0; offset < str1.size(); offset++) {
        rawText.WriteUInt8(offset, *pData);
        pData++;
    }
    const char *sourcePtr1 = reinterpret_cast<const char *>(rawText.CData());
    const char *endPtr1 = reinterpret_cast<const char *>(rawText.CData(rawText.Size() - 1));
    ASSERT_FALSE(sourcePtr1 >= endPtr1);
    const char* res1 = PngImageChunkUtils::StepOverNewLine(sourcePtr1, endPtr1);
    EXPECT_EQ(res1, NULL);

    rawText.Reset();
    std::string str2 = "sourcePt\nr";
    data = reinterpret_cast<byte*>(str2.data());
    pData = data;
    rawText.Resize(str2.size());
    for (size_t offset = 0; offset < str2.size(); offset++) {
        rawText.WriteUInt8(offset, *pData);
        pData++;
    }
    const char* sourcePtr2 = reinterpret_cast<const char *>(rawText.CData());
    const char* endPtr2 = reinterpret_cast<const char*>(rawText.CData(rawText.Size()- 1));
    ASSERT_FALSE(sourcePtr2 >= endPtr2);
    const char* res2 = PngImageChunkUtils::StepOverNewLine(sourcePtr2, endPtr2);
    EXPECT_EQ(res2, NULL);

    rawText.Reset();
    std::string str3 = "source\nPtr";
    data = reinterpret_cast<byte*>(str3.data());
    pData = data;
    rawText.Resize(str2.size());
    for (size_t offset = 0; offset < str3.size(); offset++) {
        rawText.WriteUInt8(offset, *pData);
        pData++;
    }
    const char* sourcePtr3 = reinterpret_cast<const char *>(rawText.CData());
    const char* endPtr3 = reinterpret_cast<const char *>(rawText.CData(rawText.Size() - 1));
    ASSERT_FALSE(sourcePtr3 >= endPtr3);
    const char* res3 = PngImageChunkUtils::StepOverNewLine(sourcePtr3, endPtr3);
    EXPECT_NE(res3, NULL);
}

/**
 * @tc.name: ConvertAsciiToInt001
 * @tc.desc: test the ConvertAsciiToInt method when the sorcePtr and destPtr is normal or nullptr
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, ConvertAsciiToInt001, TestSize.Level3)
{
    const char *sourcePtr = "sourcePtr";
    std::string ptr = "destPtr";
    unsigned char *destPtr = reinterpret_cast<unsigned char *>(ptr.data());
    size_t exifInfolength = 10;

    int res = PngImageChunkUtils::ConvertAsciiToInt(nullptr, exifInfolength, nullptr);
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);

    res = PngImageChunkUtils::ConvertAsciiToInt(sourcePtr, exifInfolength, nullptr);
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);

    res = PngImageChunkUtils::ConvertAsciiToInt(nullptr, exifInfolength, destPtr);
    EXPECT_EQ(res, ERR_IMAGE_SOURCE_DATA_INCOMPLETE);
}

/**
 * @tc.name: ConvertRawTextToExifInfo001
 * @tc.desc: test the ConvertRawTextToExifInfo method when rawText size is 1
 * @tc.type: FUNC
 */
HWTEST_F(PngImageChunkUtilsTest, ConvertRawTextToExifInfo001, TestSize.Level3)
{
    DataBuf empty = {};
    DataBuf rawText(BUF_SIZE_ONE);
    auto res = PngImageChunkUtils::ConvertRawTextToExifInfo(rawText);
    int cmpRes = res.CmpBytes(OFFSET_ZERO, &empty, empty.Size());
    EXPECT_EQ(cmpRes, BUF_CMP_SUCCESS);
}
} // namespace Multimedia
} // namespace OHOS