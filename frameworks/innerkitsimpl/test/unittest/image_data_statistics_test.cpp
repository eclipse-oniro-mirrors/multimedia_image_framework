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

#include <gtest/gtest.h>
#include <string>
#include "image_data_statistics.h"

using namespace OHOS::Media;
using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
static const uint32_t BUFFER = 1024 * 1024;
static const std::string INPUT_STRING = "hello10,title";
class ImageDataStatisticsTest : public testing::Test {
    public:
        ImageDataStatisticsTest() {}
        ~ImageDataStatisticsTest() {}
};

/**
 * @tc.name: DataStatistics001
 * @tc.desc: SetRequestMemory
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: StartPacking001 start";
    ImageDataStatistics imageDataStatistics(INPUT_STRING);
    imageDataStatistics.SetRequestMemory(BUFFER);
    GTEST_LOG_(INFO) << "ImagePackerTest: DataStatistics001 end";
}

/**
 * @tc.name: DataStatistics002
 * @tc.desc: AddTitle
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: StartPacking002 start";
    ImageDataStatistics imageDataStatistics("%s%d,%s", "hello", 10, "title");
    imageDataStatistics.AddTitle("datastatisticsTest");
    GTEST_LOG_(INFO) << "ImagePackerTest: StartPacking002 end";
}

/**
 * @tc.name: DataStatistics003
 * @tc.desc: Test ImageDataStatistics constructor format error
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics003 start";
    ImageDataStatistics imageDataStatistics("%s %d %d", "only_one_string");
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics003 end";
}

/**
 * @tc.name: DataStatistics004
 * @tc.desc: Test AddTitle format error
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics004 start";
    ImageDataStatistics imageDataStatistics("test");
    imageDataStatistics.AddTitle("%d %d", 1);
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics004 end";
}

/**
 * @tc.name: DataStatistics005
 * @tc.desc: Test AddTitle nullptr param
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics005 start";
    ImageDataStatistics imageDataStatistics("test");
    imageDataStatistics.AddTitle(nullptr);
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics005 end";
}

/**
 * @tc.name: DataStatistics006
 * @tc.desc: Test ImageDataStatistics constructor with nullptr
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics006 start";
    
    EXPECT_NO_FATAL_FAILURE({
        ImageDataStatistics imageDataStatistics(nullptr);
    });
    
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics006 end";
}

/**
 * @tc.name: DataStatistics007
 * @tc.desc: Test ImageDataStatistics constructor format error
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics007 start";
    
    EXPECT_NO_FATAL_FAILURE({
        ImageDataStatistics stats("%n");
    });
    
    EXPECT_NO_FATAL_FAILURE({
        ImageDataStatistics stats("%d", "string_not_int");
    });
    
    EXPECT_NO_FATAL_FAILURE({
        ImageDataStatistics stats("%s %d", "only_string");
    });
    
    EXPECT_NO_FATAL_FAILURE({
        std::string longFmt(1000, 'A');
        longFmt += "%s";
        ImageDataStatistics stats(longFmt.c_str(), "additional_string");
    });
    
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics007 end";
}

/**
 * @tc.name: DataStatistics008
 * @tc.desc: Test ImageDataStatistics destructor memory threshold branch
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, DataStatistics008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics008 start";
    
    EXPECT_NO_FATAL_FAILURE({
        ImageDataStatistics stats("Memory threshold test");
        stats.SetRequestMemory(314572801);
    });
    
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: DataStatistics008 end";
}

/**
 * @tc.name: AddTitleStringTest001
 * @tc.desc: Test AddTitle with string
 * @tc.type: FUNC
 */
HWTEST_F(ImageDataStatisticsTest, AddTitleStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: AddTitleStringTest001 start";
    
    EXPECT_NO_FATAL_FAILURE({
        ImageDataStatistics stats("initial title");
        stats.AddTitle(" additional text");
    }) << "Basic AddTitle should not crash";
    
    GTEST_LOG_(INFO) << "ImageDataStatisticsTest: AddTitleStringTest001 end";
}
} // namespace Multimedia
} // namespace OHOS