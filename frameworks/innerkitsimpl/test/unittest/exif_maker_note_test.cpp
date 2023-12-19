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
}
}