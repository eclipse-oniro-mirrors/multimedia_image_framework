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