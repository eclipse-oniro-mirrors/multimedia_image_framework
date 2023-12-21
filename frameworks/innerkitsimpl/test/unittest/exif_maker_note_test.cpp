/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <memory>
#include <fcntl.h>
#include "exif_maker_note.h"
#include "securec.h"
#include "string_ex.h"
#include "hilog/log.h"
#include "log_tags.h"
#include "media_errors.h"
#include "exif_info.h"
#include "jpeg_decoder.h"
#include "jpeg_encoder.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace ImagePlugin {
constexpr unsigned char EXIF_HEADER[] = {'E', 'x', 'i', 'f', '\0', '\0'};
constexpr unsigned char EXIF_TAIL[] = {'e', 'x', 'p', 'o', 'r', 't', 's', 'c', 't', 'e', 's', 't', '\0'};
constexpr unsigned char EXIF_TCL[] = {'f', 'd', 'e', 'b'};
constexpr unsigned char EXIF_TCB[] = {'f', 'd'};
class ExifMakerNoteTest : public testing::Test {
public:
    ExifMakerNoteTest() {}
    ~ExifMakerNoteTest() {}
};

/**
 * @tc.name: CopyItemTest0001
 * @tc.desc: Test of CopyItem
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, CopyItemTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: CopyItemTest001 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    ExifMakerNote::ExifItem item;
    item.ifd = 1;
    ExifMakerNote->CopyItem(item);
    ASSERT_EQ(item.ifd, 1);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: CopyItemTest0001 end";
}

/**
 * @tc.name: GetValueTest001
 * @tc.desc: Test of GetValue
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetValueTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest001 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string value = "111";
    ExifByteOrder order = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
    bool mock = true;
    bool ret = ExifMakerNote->GetValue(value, order, mock);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest001 end";
}

/**
 * @tc.name: GetValueTest002
 * @tc.desc: Test of GetValue
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetValueTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest002 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string value = "111";
    ExifData *exifData = nullptr;
    bool mock = true;
    bool ret = ExifMakerNote->GetValue(value, exifData, mock);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest002 end";
}

/**
 * @tc.name: DumpTest001
 * @tc.desc: Test of Dump
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, DumpTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: DumpTest001 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string info = "nihao";
    ExifByteOrder order = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
    ExifMakerNote::ExifItem item;
    item.tag =2;
    ExifMakerNote->Dump(info, order);
    ASSERT_EQ(item.tag, 2);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: DumpTest001 end";
}

/**
 * @tc.name: GetValueTest003
 * @tc.desc: Test of GetValue
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetValueTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest003 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string value = "111";
    ExifByteOrder order = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
    ExifMakerNote::ExifItem item;
    bool mock = true;
    bool ret = ExifMakerNote->GetValue(value, order, item, mock);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest003 end";
}

/**
 * @tc.name: GetValueTest004
 * @tc.desc: Test of GetValue
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetValueTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest004 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string value = "111";
    ExifData *exifData = nullptr;
    ExifMakerNote::ExifItem item;
    bool mock = true;
    bool ret = ExifMakerNote->GetValue(value, exifData, item, mock);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest004 end";
}

/**
 * @tc.name: GetValueTest005
 * @tc.desc: Test of GetValue
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetValueTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest005 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string value = "111";
    ExifContent *exifContent = nullptr;
    ExifMakerNote::ExifItem item;
    bool mock = true;
    bool ret = ExifMakerNote->GetValue(value, exifContent, item, mock);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetValueTest005 end";
}

/**
 * @tc.name: DumpTest002
 * @tc.desc: Test of Dump
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, DumpTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: DumpTest002 start";
    auto ExifMakerNote = std::make_shared<ExifMakerNote::ExifItem>();
    std::string info = "infomation";
    ExifMakerNote::ExifItem item;
    item.ifd = 1;
    ExifByteOrder order = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
    ExifMakerNote->Dump(info, item, order);
    ASSERT_EQ(item.ifd, 1);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: DumpTest002 end";
}

/**
 * @tc.name: ParserTest001
 * @tc.desc: Test of Parser
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, ParserTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserTest001 start";
    ExifMakerNote exifMakerNote;
    ExifData *exif = nullptr;
    unsigned char* data = nullptr;
    uint32_t size = 11;
    uint32_t ret = exifMakerNote.Parser(exif, data, size);
    ASSERT_EQ(ret, Media::SUCCESS);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserTest001 end";
}

/**
 * @tc.name: FindExifLocationTest001
 * @tc.desc: Test of FindExifLocation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, FindExifLocationTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindExifLocationTest001 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = nullptr;
    uint32_t size = 3;
    const unsigned char *&newData = data;
    uint32_t newSize = 7;
    bool result = exifMakerNote.FindExifLocation(data, size, newData, newSize);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindExifLocationTest001 end";
}

/**
 * @tc.name: FindExifLocationTest002
 * @tc.desc: Test of FindExifLocation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, FindExifLocationTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindExifLocationTest002 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = EXIF_HEADER;
    uint32_t size = 6;
    const unsigned char *&newData = data;
    uint32_t newSize = 7;
    bool result = exifMakerNote.FindExifLocation(data, size, newData, newSize);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindExifLocationTest002 end";
}

/**
 * @tc.name: FindExifLocationTest003
 * @tc.desc: Test of FindExifLocation
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, FindExifLocationTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindExifLocationTest003 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = EXIF_TAIL;
    uint32_t size = 13;
    const unsigned char *&newData = data;
    uint32_t newSize = 7;
    bool result = exifMakerNote.FindExifLocation(data, size, newData, newSize);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindExifLocationTest003 end";
}

/**
 * @tc.name: FindJpegAPP1Test001
 * @tc.desc: Test of FindJpegAPP1
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, FindJpegAPP1Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindJpegAPP1Test001 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = EXIF_TCL;
    uint32_t size = 4;
    const unsigned char *&newData = data;
    uint32_t newSize = 7;
    bool result = exifMakerNote.FindJpegAPP1(data, size, newData, newSize);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindJpegAPP1Test001 end";
}

/**
 * @tc.name: FindJpegAPP1Test002
 * @tc.desc: Test of FindJpegAPP1
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, FindJpegAPP1Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindJpegAPP1Test002 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = EXIF_TCB;
    uint32_t size = 2;
    const unsigned char *&newData = data;
    uint32_t newSize = 7;
    bool result = exifMakerNote.FindJpegAPP1(data, size, newData, newSize);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: FindJpegAPP1Test002 end";
}

/**
 * @tc.name: IsParsedTest001
 * @tc.desc: Test of IsParsed
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, IsParsedTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsParsedTest001 start";
    ExifMakerNote exifMakerNote;
    bool result = exifMakerNote.IsParsed();
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsParsedTest001 end";
}

/**
 * @tc.name: ParserMakerNoteTest001
 * @tc.desc: Test of ParserMakerNote
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, ParserMakerNoteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserMakerNoteTest001 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = nullptr;
    uint32_t size = 0;
    uint32_t result = exifMakerNote.ParserMakerNote(data, size);
    ASSERT_EQ(result, Media::ERROR);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserMakerNoteTest001 end";
}

/**
 * @tc.name: IsHwMakerNoteTest001
 * @tc.desc: Test of IsHwMakerNote
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, IsHwMakerNoteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest001 start";
    ExifMakerNote exifMakerNote;
    const unsigned char *data = nullptr;
    uint32_t size = 0;
    bool result = exifMakerNote.IsHwMakerNote(data, size);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest001 end";
}

/**
 * @tc.name: IsHwMakerNoteTest002
 * @tc.desc: Test of IsHwMakerNote
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, IsHwMakerNoteTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest002 start";
    ExifMakerNote exifMakerNote;
    const unsigned char data[] = { 'e', 'x', 'p', 'o', 'r', 't', 's', 'c', 'I', 'I' };
    uint32_t size = 20;
    bool result = exifMakerNote.IsHwMakerNote(data, size);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest002 end";
}

/**
 * @tc.name: IsHwMakerNoteTest003
 * @tc.desc: Test of IsHwMakerNote
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, IsHwMakerNoteTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest003 start";
    ExifMakerNote exifMakerNote;
    const unsigned char data[] = { 'e', 'x', 'p', 'o', 'r', 't', 's', 'c', 'M', 'M' };
    uint32_t size = 20;
    bool result = exifMakerNote.IsHwMakerNote(data, size);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest003 end";
}

/**
 * @tc.name: IsHwMakerNoteTest004
 * @tc.desc: Test of IsHwMakerNote
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, IsHwMakerNoteTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest004 start";
    ExifMakerNote exifMakerNote;
    const unsigned char data[] = { 'e', 'x' };
    uint32_t size = 20;
    bool result = exifMakerNote.IsHwMakerNote(data, size);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: IsHwMakerNoteTest004 end";
}

/**
 * @tc.name: GetUInt16Test001
 * @tc.desc: Test of GetUInt16
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetUInt16Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt16Test001 start";
    ExifMakerNote exifMakerNote;
    const std::vector<unsigned char> buffer;
    ExifByteOrder order = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
    size_t offset = 0;
    uint16_t value;
    bool result = exifMakerNote.GetUInt16(buffer, order, offset, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt16Test001 end";
}

/**
 * @tc.name: GetUInt16Test002
 * @tc.desc: Test of GetUInt16
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetUInt16Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt16Test002 start";
    ExifMakerNote exifMakerNote;
    size_t offset = 0;
    uint16_t value;
    bool result = exifMakerNote.GetUInt16(offset, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt16Test002 end";
}

/**
 * @tc.name: GetUInt16AndMoveTest001
 * @tc.desc: Test of GetUInt16AndMove
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetUInt16AndMoveTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt16AndMoveTest001 start";
    ExifMakerNote exifMakerNote;
    uint32_t offset = 0;
    uint16_t value;
    bool result = exifMakerNote.GetUInt16AndMove(offset, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt16AndMoveTest001 end";
}

/**
 * @tc.name: ParserIFDTest001
 * @tc.desc: Test of ParserIFD
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, ParserIFDTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserIFDTest001 start";
    ExifMakerNote exifMakerNote;
    uint32_t offset = 0;
    uint32_t ifd = 0;
    uint32_t deep = 0;
    bool result = exifMakerNote.ParserIFD(offset, ifd, deep);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserIFDTest001 end";
}

/**
 * @tc.name: ParserHwMakerNoteTest001
 * @tc.desc: Test of ParserHwMakerNote
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, ParserHwMakerNoteTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserHwMakerNoteTest001 start";
    ExifMakerNote exifMakerNote;
    bool result = exifMakerNote.ParserHwMakerNote();
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserHwMakerNoteTest001 end";
}

/**
 * @tc.name: ParserItemTest001
 * @tc.desc: Test of ParserItem
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, ParserItemTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserItemTest001 start";
    ExifMakerNote exifMakerNote;
    uint32_t offset = 0;
    uint32_t ifd = 0;
    uint32_t deep = 0;
    bool result = exifMakerNote.ParserItem(offset, ifd, deep);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: ParserItemTest001 end";
}

/**
 * @tc.name: GetUInt32Test001
 * @tc.desc: Test of GetUInt32
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetUInt32Test001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt32Test001 start";
    ExifMakerNote exifMakerNote;
    const std::vector<unsigned char> buffer;
    ExifByteOrder order = ExifByteOrder::EXIF_BYTE_ORDER_INTEL;
    size_t offset = 0;
    uint32_t value;
    bool result = exifMakerNote.GetUInt32(buffer, order, offset, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt32Test001 end";
}

/**
 * @tc.name: GetUInt32Test002
 * @tc.desc: Test of GetUInt32
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetUInt32Test002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt32Test002 start";
    ExifMakerNote exifMakerNote;
    uint32_t offset = 0;
    uint32_t value;
    bool result = exifMakerNote.GetUInt32(offset, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt32Test002 end";
}

/**
 * @tc.name: GetUInt32AndMoveTest001
 * @tc.desc: Test of GetUInt32AndMove
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetUInt32AndMoveTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt32AndMoveTest001 start";
    ExifMakerNote exifMakerNote;
    uint32_t offset = 0;
    uint32_t value;
    bool result = exifMakerNote.GetUInt32AndMove(offset, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetUInt32AndMoveTest001 end";
}

/**
 * @tc.name: GetDataTest001
 * @tc.desc: Test of GetData
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetDataTest001 start";
    ExifMakerNote exifMakerNote;
    const std::vector<unsigned char> buffer(3);
    size_t offset = 2;
    size_t count = 2;
    std::vector<unsigned char> value;
    bool result = exifMakerNote.GetData(buffer, offset, count, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetDataTest001 end";
}

/**
 * @tc.name: GetDataTest002
 * @tc.desc: Test of GetData
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetDataTest002 start";
    ExifMakerNote exifMakerNote;
    const std::vector<unsigned char> buffer(3);
    size_t offset = 2;
    size_t count = 2;
    std::vector<unsigned char> value;
    bool result = exifMakerNote.GetData(offset, count, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetDataTest002 end";
}

/**
 * @tc.name: GetDataTest003
 * @tc.desc: Test of GetData
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, GetDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetDataTest003 start";
    ExifMakerNote exifMakerNote;
    const std::vector<unsigned char> buffer(5);
    size_t offset = 2;
    size_t count = 2;
    std::vector<unsigned char> value;
    bool result = exifMakerNote.GetData(buffer, offset, count, value);
    ASSERT_EQ(result, false);
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: GetDataTest003 end";
}

/**
 * @tc.name: DumpTest003
 * @tc.desc: Test of Dump
 * @tc.type: FUNC
 */
HWTEST_F(ExifMakerNoteTest, DumpTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: DumpTest003 start";
    ExifMakerNote exifMakerNote;
    const std::vector<unsigned char> data(2);
    uint32_t offset = 1;
    uint32_t sum = 1;
    std::string result = exifMakerNote.Dump(data, offset, sum);
    ASSERT_EQ(result, "00");
    GTEST_LOG_(INFO) << "ExifMakerNoteTest: DumpTest003 end";
}
}
}