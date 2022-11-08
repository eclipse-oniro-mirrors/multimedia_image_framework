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
#include <fstream>
#include "attr_data.h"
#include "image_type.h"
#include "plugin_errors.h"

using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::MultimediaPlugin;
namespace OHOS {
namespace Multimedia {
static const std::string IMAGE_INPUT_JPEG_PATH = "/data/local/tmp/image/test.jpg";

class AttrDataTest : public testing::Test {
public:
    AttrDataTest() {}
    ~AttrDataTest() {}
};

/**
 * @tc.name: AttrDataTest001
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest001 start";
    bool value = false;
    MultimediaPlugin::AttrData aData(value);
    bool value1 = false;
    aData.SetData(value1);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest001 end";
}

/**
 * @tc.name: AttrDataTest02
 * @tc.desc: test SetData and ClearData data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest002 start";
    bool value = true;
    MultimediaPlugin::AttrData aData(value);
    bool value1 = true;
    aData.SetData(value1);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest002 end";
}

/**
 * @tc.name: AttrDataTest003
 * @tc.desc: test SetData and ClearData data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest003 start";
    uint32_t value = 0;
    MultimediaPlugin::AttrData aData(value);
    uint32_t value1 = 2;
    aData.SetData(value1);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest003 end";
}

/**
 * @tc.name: AttrDataTest004
 * @tc.desc: test SetData and ClearData data type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest004 start";
    std::string value = "0";
    MultimediaPlugin::AttrData aData(value);
    std::string value1 = "1";
    uint32_t ret = aData.SetData(value1);
    ASSERT_EQ(ret, SUCCESS);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest004 end";
}

/**
 * @tc.name: AttrDataTest005
 * @tc.desc: test SetData and ClearData data type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest005 start";
    std::string &&value = "11";
    MultimediaPlugin::AttrData aData(value);
    std::string &&value1 = "1";
    uint32_t ret = aData.SetData(value1);
    ASSERT_EQ(ret, SUCCESS);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest005 end";
}

/**
 * @tc.name: AttrDataTest006
 * @tc.desc: test SetData and ClearData data type is uint32_t and uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest006 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest006 end";
}

/**
 * @tc.name: AttrDataTest007
 * @tc.desc: test SetData data and ClearData type is uint32_t and uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest007 start";
    uint32_t value1 = 100;
    uint32_t value2 = 1;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest007 end";
}

/**
 * @tc.name: AttrDataTest008
 * @tc.desc: test SetData and ClearData data type is uint32_t and uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest008 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 1000;
    uint32_t value4 = 0;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_NE(ret, SUCCESS);
    aData.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest008 end";
}

/**
 * @tc.name: AttrDataTest0010
 * @tc.desc: test InsertSet type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0010 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 0;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0010 end";
}

/**
 * @tc.name: AttrDataTest0011
 * @tc.desc: test InsertSet type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0011 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0011 end";
}

/**
 * @tc.name: AttrDataTest0012
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0012 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData(value);
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, ERR_UNSUPPORTED);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0012 end";
}

/**
 * @tc.name: AttrDataTest0013
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0013 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0013 end";
}

/**
 * @tc.name: AttrDataTest0014
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0014 start";
    std::string value = "";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0014 end";
}

/**
 * @tc.name: AttrDataTest0015
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0015 start";
    std::string &&value = "11";
    MultimediaPlugin::AttrData aData(value);
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, ERR_UNSUPPORTED);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0015 end";
}

/**
 * @tc.name: AttrDataTest0016
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0016 start";
    std::string &&value = "11";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0016 end";
}

/**
 * @tc.name: AttrDataTest0017
 * @tc.desc: test InRange type is bool
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0017 start";
    MultimediaPlugin::AttrData aData(true);
    bool value = true;
    bool ret = aData.InRange(value);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0017 end";
}

/**
 * @tc.name: AttrDataTest0018
 * @tc.desc: test InRange type is bool
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0018 start";
    MultimediaPlugin::AttrData aData;
    bool value = false;
    bool ret = aData.InRange(value);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0018 end";
}

/**
 * @tc.name: AttrDataTest0019
 * @tc.desc: test InRange type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0019 start";
    uint32_t value = 11;
    MultimediaPlugin::AttrData aData(value);
    uint32_t value1 = 1;
    bool ret = aData.InRange(value1);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0019 end";
}

/**
 * @tc.name: AttrDataTest0020
 * @tc.desc: test InRange type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0020 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    bool ret = aData.InRange(value);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0020 end";
}

/**
 * @tc.name: AttrDataTest0021
 * @tc.desc: test InRange type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0021 start";
    std::string value = "1";
    MultimediaPlugin::AttrData aData(value);
    std::string value1 = "11";
    bool ret = aData.InRange(value1);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0021 end";
}

/**
 * @tc.name: AttrDataTest0022
 * @tc.desc: test InRange type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0022 start";
    MultimediaPlugin::AttrData aData;
    std::string value1 = "11";
    bool ret = aData.InRange(value1);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0022 end";
}

/**
 * @tc.name: AttrDataTest0023
 * @tc.desc: test InRange type is MultimediaPlugin::AttrData
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0023 start";
    MultimediaPlugin::AttrData aData;
    MultimediaPlugin::AttrData data;
    MultimediaPlugin::AttrData aData1(data);
    bool ret = aData.InRange(aData1);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0023 end";
}

/**
 * @tc.name: AttrDataTest0024
 * @tc.desc: test InRange type is MultimediaPlugin::AttrData
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0024 start";
    MultimediaPlugin::AttrData aData;
    MultimediaPlugin::AttrData aData1;
    bool ret = aData.InRange(aData1);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0024 end";
}

/**
 * @tc.name: AttrDataTest0025
 * @tc.desc: test GetType
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0025 start";
    MultimediaPlugin::AttrData aData;
    AttrDataType type = aData.GetType();
    ASSERT_EQ(type, AttrDataType::ATTR_DATA_NULL);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0025 end";
}

/**
 * @tc.name: AttrDataTest0026
 * @tc.desc: test GetMinValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0026 start";
    uint32_t value = 1;
    MultimediaPlugin::AttrData aData(value);
    uint32_t v;
    uint32_t ret = aData.GetMinValue(v);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0026 end";
}

/**
 * @tc.name: AttrDataTest0027
 * @tc.desc: test GetMinValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0027 start";
    MultimediaPlugin::AttrData aData;
    uint32_t v;
    uint32_t ret = aData.GetMinValue(v);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0027 end";
}

/**
 * @tc.name: AttrDataTest0028
 * @tc.desc: test GetMaxValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0028, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0028 start";
    uint32_t value = 1;
    MultimediaPlugin::AttrData aData(value);
    uint32_t v;
    uint32_t ret = aData.GetMaxValue(v);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0028 end";
}

/**
 * @tc.name: AttrDataTest0029
 * @tc.desc: test GetMaxValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0029, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0029 start";
    MultimediaPlugin::AttrData aData;
    uint32_t v;
    uint32_t ret = aData.GetMaxValue(v);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0029 end";
}

/**
 * @tc.name: AttrDataTest0033
 * @tc.desc: test GetValue and data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0033, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0033 start";
    bool value = true;
    MultimediaPlugin::AttrData aData(value);
    bool v;
    uint32_t ret = aData.GetValue(v);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0033 end";
}

/**
 * @tc.name: AttrDataTest0034
 * @tc.desc: test GetValue and data type is bool
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0034, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0034 start";
    MultimediaPlugin::AttrData aData;
    bool v;
    uint32_t ret = aData.GetValue(v);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0034 end";
}

/**
 * @tc.name: AttrDataTest0035
 * @tc.desc: test GetValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0035, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0035 start";
    uint32_t value = 1;
    MultimediaPlugin::AttrData aData(value);
    uint32_t v;
    uint32_t ret = aData.GetValue(v);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0035 end";
}

/**
 * @tc.name: AttrDataTest0036
 * @tc.desc: test GetValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0036, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0036 start";
    MultimediaPlugin::AttrData aData;
    uint32_t v;
    uint32_t ret = aData.GetValue(v);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0036 end";
}

/**
 * @tc.name: AttrDataTest0037
 * @tc.desc: test GetValue and data type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0037, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0037 start";
    std::string value = "1";
    MultimediaPlugin::AttrData aData(value);
    std::string v;
    uint32_t ret = aData.GetValue(v);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0037 end";
}

/**
 * @tc.name: AttrDataTest0038
 * @tc.desc: test GetValue and data type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0038, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0038 start";
    MultimediaPlugin::AttrData aData;
    std::string v;
    uint32_t ret = aData.GetValue(v);
    ASSERT_EQ(ret, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0038 end";
}
}
}