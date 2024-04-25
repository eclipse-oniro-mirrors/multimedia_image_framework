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

#define private public
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
static constexpr uint8_t LOWER_BOUND_INDEX = 0;
static constexpr uint8_t UPPER_BOUND_INDEX = 1;
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
    ASSERT_EQ(aData.GetValue(value), SUCCESS);
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
    ASSERT_EQ(aData.GetValue(value), SUCCESS);
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
    ASSERT_EQ(aData.GetValue(value), SUCCESS);
    aData.ClearData();
    ASSERT_EQ(value, value1);
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
 * @tc.name: AttrDataTest009
 * @tc.desc: test InsertSet type is std::string &&
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest009 start";
    std::string &&value = "111";
    MultimediaPlugin::AttrData aData(value);
    std::string &&value1 = "1111";
    uint32_t ret = aData.SetData(value1);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest009 end";
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
 * @tc.name: AttrDataTest0030
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0030, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0030 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t value0 = 1;
    bool res = aData.InRange(value0);
    ASSERT_EQ(res, true);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0030 end";
}

/**
 * @tc.name: AttrDataTest0031
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0031, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0031 start";
    MultimediaPlugin::AttrData aData;
    std::string value = "1";
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    std::string value1 = "11";
    bool res = aData.InRange(value1);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0031 end";
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

/**
 * @tc.name: AttrDataTest0039
 * @tc.desc: test GetValue and data type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0039, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0039 start";
    MultimediaPlugin::AttrData aData;
    bool value = true;
    bool value1 = false;
    aData.SetData(value1);
    MultimediaPlugin::AttrData aData1(aData);
    ASSERT_EQ(aData1.GetValue(value), SUCCESS);
    ASSERT_EQ(value, value1);
    aData1.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0039 end";
}

/**
 * @tc.name: AttrDataTest0040
 * @tc.desc: test GetValue and data type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0040, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0040 start";
    uint32_t value = 0;
    uint32_t value1 = 1;
    MultimediaPlugin::AttrData aData(value);
    MultimediaPlugin::AttrData aData1(aData);
    ASSERT_EQ(aData1.GetValue(value1), SUCCESS);
    ASSERT_EQ(value, value1);
    aData1.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0040 end";
}

/**
 * @tc.name: AttrDataTest0041
 * @tc.desc: test InsertSet type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0041, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0041 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 0;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    MultimediaPlugin::AttrData aData1(aData);
    aData1.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0041 end";
}

/**
 * @tc.name: AttrDataTest0042
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0042, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0042 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    MultimediaPlugin::AttrData aData1(aData);
    aData1.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0042 end";
}

/**
 * @tc.name: AttrDataTest0043
 * @tc.desc: test SetData and ClearData data type is uint32_t and uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0043, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0043 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    MultimediaPlugin::AttrData aData1(aData);
    aData1.ClearData();
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0043 end";
}

/**
 * @tc.name: AttrDataTest0044
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0044, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0044 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 0;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    const std::string value1 = "111";
    aData.SetData(value1);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0044 end";
}

/**
 * @tc.name: AttrDataTest0045
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0045, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0045 start";
    std::string value1 = "111";
    MultimediaPlugin::AttrData aData(value1);
    uint32_t value = 0;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, ERR_UNSUPPORTED);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0045 end";
}

/**
 * @tc.name: AttrDataTest0046
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0046, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0046 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 0;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t value1 = 1;
    bool res = aData.InRange(value1);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0046 end";
}

/**
 * @tc.name: AttrDataTest0047
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0047, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0047 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t res = aData.InsertSet(value);
    ASSERT_EQ(res, ERR_INTERNAL);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0047 end";
}

/**
 * @tc.name: AttrDataTest0048
 * @tc.desc: test InsertSet type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0048, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0048 start";
    uint32_t value = 1;
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t res = aData.InsertSet(value);
    ASSERT_EQ(res, ERR_GENERAL);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0048 end";
}

/**
 * @tc.name: AttrDataTest0049
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0049, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0049 start";
    std::string value = "111";
    std::string value1 = "1111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t res = aData.InsertSet(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0049 end";
}

/**
 * @tc.name: AttrDataTest0050
 * @tc.desc: test InsertSet type is uint32_t
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0050, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0050 start";
    uint32_t value = 1;
    uint32_t value1 = 11;
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t res = aData.InsertSet(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0050 end";
}

/**
 * @tc.name: AttrDataTest0051
 * @tc.desc: test InsertSet type is std::string &&
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0051, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0051 start";
    std::string &&value = "111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0051 end";
}

/**
 * @tc.name: AttrDataTest0052
 * @tc.desc: test InsertSet type is std::string &&
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0052, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0052 start";
    std::string &&value = "111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t res = aData.InsertSet(value);
    ASSERT_EQ(res, ERR_INTERNAL);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0052 end";
}

/**
 * @tc.name: AttrDataTest0053
 * @tc.desc: test InsertSet type is std::string &&
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0053, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0053 start";
    std::string &&value = "111";
    std::string &&value1 = "1111";
    MultimediaPlugin::AttrData aData;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t res = aData.InsertSet(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0053 end";
}

/**
 * @tc.name: AttrDataTest0054
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0054, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0054 start";
    uint32_t value = 0;
    MultimediaPlugin::AttrData aData(value);
    std::string &&value1 = "111";
    uint32_t ret = aData.InsertSet(value1);
    ASSERT_EQ(ret, ERR_UNSUPPORTED);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0054 end";
}

/**
 * @tc.name: AttrDataTest0055
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0055, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0055 start";
    MultimediaPlugin::AttrData aData;
    std::string value = "1";
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    MultimediaPlugin::AttrData aData1;
    bool res = aData1.InRange(aData);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0055 end";
}

/**
 * @tc.name: AttrDataTest0055
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0056, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0055 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    MultimediaPlugin::AttrData aData1;
    bool res = aData1.InRange(aData);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0056 end";
}

/**
 * @tc.name: AttrDataTest0057
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0057, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0057 start";
    std::string value = "1";
    MultimediaPlugin::AttrData aData(value);
    MultimediaPlugin::AttrData aData1;
    bool res = aData1.InRange(aData);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0057 end";
}

/**
 * @tc.name: AttrDataTest0058
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0058, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0058 start";
    uint32_t value = 1;
    MultimediaPlugin::AttrData aData(value);
    MultimediaPlugin::AttrData aData1;
    bool res = aData1.InRange(aData);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0058 end";
}

/**
 * @tc.name: AttrDataTest0059
 * @tc.desc: test InsertSet type is std::string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0059, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0059 start";
    bool value = true;
    MultimediaPlugin::AttrData aData(value);
    MultimediaPlugin::AttrData aData1;
    bool res = aData1.InRange(aData);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0059 end";
}

/**
 * @tc.name: AttrDataTest0060
 * @tc.desc: test InsertSet type is range
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0060, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0060 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    MultimediaPlugin::AttrData aData1;
    bool res = aData1.InRange(aData);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0060 end";
}

/**
 * @tc.name: AttrDataTest0061
 * @tc.desc: test GetMinValue and data type is uint32_t range
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0061, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0061 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t v;
    uint32_t res = aData.GetMinValue(v);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0061 end";
}

/**
 * @tc.name: AttrDataTest0062
 * @tc.desc: test GetMinValue and data type is uint32_t set
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0062, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0062 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t v;
    uint32_t res = aData.GetMinValue(v);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0062 end";
}

/**
 * @tc.name: AttrDataTest0063
 * @tc.desc: test GetMaxValue and data type is uint32_t range
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0063, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0063 start";
    uint32_t value1 = 0;
    uint32_t value2 = 1000;
    MultimediaPlugin::AttrData aData(value1, value2);
    uint32_t value3 = 0;
    uint32_t value4 = 1000;
    uint32_t ret = aData.SetData(value3, value4);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t v;
    uint32_t res = aData.GetMaxValue(v);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0063 end";
}

/**
 * @tc.name: AttrDataTest0064
 * @tc.desc: test GetMaxValue and data type is uint32_t set
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0064, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0064 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    uint32_t v;
    uint32_t res = aData.GetMaxValue(v);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0064 end";
}

/**
 * @tc.name: AttrDataTest0065
 * @tc.desc: test GetMinValue and data type is uint32_t set
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0065, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0065 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    const string *value1 = nullptr;
    uint32_t res = aData.GetMinValue(value1);
    ASSERT_EQ(res, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0065 end";
}

/**
 * @tc.name: AttrDataTest0066
 * @tc.desc: test GetMinValue and data type is string set
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0066, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0066 start";
    MultimediaPlugin::AttrData aData;
    std::string value = "111";
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    const string *value1 = nullptr;
    uint32_t res = aData.GetMinValue(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0066 end";
}

/**
 * @tc.name: AttrDataTest0067
 * @tc.desc: test GetMinValue and data type is string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0067, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0067 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData(value);
    const string *value1 = nullptr;
    uint32_t res = aData.GetMinValue(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0067 end";
}

/**
 * @tc.name: AttrDataTest0068
 * @tc.desc: test GetMaxValue and data type is uint32_t set
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0068, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0068 start";
    MultimediaPlugin::AttrData aData;
    uint32_t value = 1;
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    const string *value1 = nullptr;
    uint32_t res = aData.GetMaxValue(value1);
    ASSERT_EQ(res, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0068 end";
}

/**
 * @tc.name: AttrDataTest0069
 * @tc.desc: test GetMaxValue and data type is string set
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0069, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0069 start";
    MultimediaPlugin::AttrData aData;
    std::string value = "111";
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    const string *value1 = nullptr;
    uint32_t res = aData.GetMaxValue(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0069 end";
}

/**
 * @tc.name: AttrDataTest0070
 * @tc.desc: test GetMaxValue and data type is string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0070, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0070 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData(value);
    const string *value1 = nullptr;
    uint32_t res = aData.GetMaxValue(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0070 end";
}

/**
 * @tc.name: AttrDataTest0071
 * @tc.desc: test GetMaxValue and data type is string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0071, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0071 start";
    MultimediaPlugin::AttrData aData;
    std::string value = "111";
    uint32_t ret = aData.InsertSet(value);
    ASSERT_EQ(ret, SUCCESS);
    const string *value1 = nullptr;
    uint32_t res = aData.GetValue(value1);
    ASSERT_EQ(res, ERR_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0071 end";
}

/**
 * @tc.name: AttrDataTest0072
 * @tc.desc: test GetMaxValue and data type is string
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0072, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0072 start";
    std::string value = "111";
    MultimediaPlugin::AttrData aData(value);
    const string *value1 = nullptr;
    uint32_t res = aData.GetValue(value1);
    ASSERT_EQ(res, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0072 end";
}

/**
 * @tc.name: AttrDataTest0073
 * @tc.desc: test AttrData::AttrData
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest0073, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0073 start";
    uint32_t value = 1;
    MultimediaPlugin::AttrData aData(value);
    aData.SetData(value);
    value = 2;
    aData.SetData(value);
    value = 3;
    aData.SetData(value);
    value = 4;
    aData.SetData(value);
    value = 5;
    aData.SetData(value);
    value = 6;
    aData.SetData(value);
    value = 7;
    aData.SetData(value);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest0073 end";
}

/**
 * @tc.name: AttrDataTest0074
 * @tc.desc: test InRange
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, InRangeTest0074, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest0074 start";
    uint32_t value = 2;
    MultimediaPlugin::AttrData aData(value);
    bool res = aData.InRange(value);
    ASSERT_EQ(res, true);
    value = 6;
    res = aData.InRange(value);
    ASSERT_EQ(res, false);
    value = 8;
    res = aData.InRange(value);
    ASSERT_EQ(res, false);
    GTEST_LOG_(INFO) << "AttrDataTest: InRange1Test0074 end";
}

/**
 * @tc.name: SetDataTest001
 * @tc.desc: test SetData
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, SetDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: SetDataTest001 start";
    string &&value = "AttrData";
    AttrData attrData(std::move(value));
    ASSERT_EQ(attrData.type_, AttrDataType::ATTR_DATA_STRING);
    ASSERT_EQ(*(attrData.value_.stringValue), "AttrData");
    ASSERT_EQ(value, "");

    attrData.type_ = AttrDataType::ATTR_DATA_STRING;
    string &&value1 = "SetData";
    uint32_t ret = attrData.SetData(std::move(value1));
    ASSERT_EQ(*(attrData.value_.stringValue), "SetData");
    ASSERT_EQ(value1, "");
    ASSERT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "AttrDataTest: SetDataTest001 end";
}

/**
 * @tc.name: InsertSetTest001
 * @tc.desc: test InsertSet
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, InsertSetTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: InsertSetTest001 start";
    string &&value = "AttrData";
    AttrData attrData(std::move(value));
    attrData.type_ = AttrDataType::ATTR_DATA_NULL;
    string &&value1 = "SetData";
    uint32_t ret = attrData.InsertSet(std::move(value1));
    ASSERT_EQ(attrData.type_, AttrDataType::ATTR_DATA_STRING_SET);
    ASSERT_EQ(ret, SUCCESS);

    attrData.type_ = AttrDataType::ATTR_DATA_BOOL;
    ret = attrData.InsertSet(std::move(value1));
    ASSERT_EQ(ret, ERR_UNSUPPORTED);

    attrData.type_ = AttrDataType::ATTR_DATA_STRING_SET;
    ret = attrData.InsertSet(std::move(value1));
    ASSERT_EQ(ret, SUCCESS);

    attrData.value_.stringSet->insert(std::move(value1));
    ret = attrData.InsertSet(std::move(value1));
    ASSERT_EQ(ret, ERR_INTERNAL);
    GTEST_LOG_(INFO) << "AttrDataTest: InsertSetTest001 end";
}

/**
 * @tc.name: InRangeTest001
 * @tc.desc: test InRange
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, InRangeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest001 start";
    AttrData attr;
    AttrData attrData(attr);
    attr.type_ = AttrDataType::ATTR_DATA_TYPE_INVALID;
    bool ret = attrData.InRange(attr);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest001 end";
}

/**
 * @tc.name: AttrDataTest075
 * @tc.desc: test GetMinValue and GetMaxValue
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest075, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest075 start";
    uint32_t value = 0;
    AttrData attrData(value);
    uint32_t value1 = 0;
    attrData.type_ = AttrDataType::ATTR_DATA_UINT32_SET;
    attrData.value_.uint32Set = new (std::nothrow) std::set<uint32_t>();
    ASSERT_NE(attrData.value_.uint32Set, nullptr);

    attrData.value_.uint32Set->begin() = attrData.value_.uint32Set->end();
    uint32_t ret = attrData.GetMinValue(value1);
    ASSERT_EQ(ret, ERR_GENERAL);

    attrData.value_.uint32Set->rbegin() = attrData.value_.uint32Set->rend();
    ret = attrData.GetMaxValue(value1);
    ASSERT_EQ(ret, ERR_GENERAL);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest075 end";
}

/**
 * @tc.name: AttrDataTest076
 * @tc.desc: test GetMinValue and GetMaxValue
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, AttrDataTest076, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest076 start";
    string value = "AttrData";
    AttrData attrData(value);
    const string *value1 = nullptr;
    attrData.type_ = AttrDataType::ATTR_DATA_STRING_SET;
    attrData.value_.uint32Set = new (std::nothrow) std::set<uint32_t>();
    ASSERT_NE(attrData.value_.uint32Set, nullptr);

    attrData.value_.uint32Set->begin() = attrData.value_.uint32Set->end();
    uint32_t ret = attrData.GetMinValue(value1);
    ASSERT_EQ(ret, ERR_GENERAL);

    attrData.value_.uint32Set->rbegin() = attrData.value_.uint32Set->rend();
    ret = attrData.GetMaxValue(value1);
    ASSERT_EQ(ret, ERR_GENERAL);
    GTEST_LOG_(INFO) << "AttrDataTest: AttrDataTest076 end";
}

/**
 * @tc.name: InRangeTest002
 * @tc.desc: test InRange
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, InRangeTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest002 start";
    AttrData attrData;
    std::set<uint32_t> uint32Set;
    ASSERT_EQ(uint32Set.empty(), true);
    bool ret = attrData.InRange(uint32Set);
    ASSERT_EQ(ret, false);

    attrData.type_ = AttrDataType::ATTR_DATA_UINT32;
    uint32Set.insert(attrData.value_.uint32Value);
    ASSERT_EQ(uint32Set.empty(), false);
    ret = attrData.InRange(uint32Set);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest002 end";
}

/**
 * @tc.name: InRangeTest003
 * @tc.desc: test InRange
 * @tc.type: FUNC
 */
HWTEST_F(AttrDataTest, InRangeTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest003 start";
    AttrData attrData(1, 0);
    bool ret = attrData.InRange(attrData.value_.uint32Rang);
    ASSERT_EQ(attrData.value_.uint32Rang[LOWER_BOUND_INDEX], 1);
    ASSERT_EQ(attrData.value_.uint32Rang[UPPER_BOUND_INDEX], 0);
    ASSERT_EQ(ret, false);

    AttrData attr(0, 1);
    attr.type_ = AttrDataType::ATTR_DATA_UINT32;
    ret = attrData.InRange(attr.value_.uint32Rang);
    ASSERT_EQ(ret, false);

    attr.type_ = AttrDataType::ATTR_DATA_UINT32_RANGE;
    ret = attr.InRange(attr.value_.uint32Rang);
    ASSERT_EQ(ret, true);

    attr.type_ = AttrDataType::ATTR_DATA_TYPE_INVALID;
    ret = attr.InRange(attr.value_.uint32Rang);
    ASSERT_EQ(ret, false);
    GTEST_LOG_(INFO) << "AttrDataTest: InRangeTest003 end";
}
}
}