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

#include <gtest/gtest.h>
#include "media_errors.h"
#include "XMP_Const.h"
#include "xmp_helper.h"

using namespace testing::ext;

namespace OHOS {
namespace Media {

class XmpHelperTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: TrimTest001
 * @tc.desc: Trim function returns empty string when all characters of the input string are in the trimChars set
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, TrimTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: TrimTest001 start";
    std::string_view str = "###";
    std::string_view trimChars = "#";
    auto ret = XMPHelper::Trim(str, trimChars);
    ASSERT_EQ(ret, "");
    GTEST_LOG_(INFO) << "XmpHelperTest: TrimTest001 end";
}

/**
 * @tc.name: TrimTest002
 * @tc.desc: Test that Trim function correctly trims the leading and trailing trimChars and returns valid string when
 *           input string contains characters not in trimChars
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, TrimTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: TrimTest002 start";
    std::string_view str = "  abc  ";
    std::string_view trimChars = " ";
    auto ret = XMPHelper::Trim(str, trimChars);
    ASSERT_EQ(ret, "abc");
    GTEST_LOG_(INFO) << "XmpHelperTest: TrimTest002 end";
}

/**
 * @tc.name: MapXMPErrorToMediaErrorTest001
 * @tc.desc: Test MapXMPErrorToMediaError covers all error code branches
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, MapXMPErrorToMediaErrorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: MapXMPErrorToMediaErrorTest001 start";

    XMP_Error errorBadParam(kXMPErr_BadParam, "Bad parameter error");
    uint32_t retBadParam = XMPHelper::MapXMPErrorToMediaError(errorBadParam);
    ASSERT_EQ(retBadParam, ERR_IMAGE_INVALID_PARAMETER);

    XMP_Error errorBadValue(kXMPErr_BadValue, "Bad value error");
    uint32_t retBadValue = XMPHelper::MapXMPErrorToMediaError(errorBadValue);
    ASSERT_EQ(retBadValue, ERR_IMAGE_INVALID_PARAMETER);

    XMP_Error errorUnimplemented(kXMPErr_Unimplemented, "Unimplemented operation error");
    uint32_t retUnimplemented = XMPHelper::MapXMPErrorToMediaError(errorUnimplemented);
    ASSERT_EQ(retUnimplemented, ERR_MEDIA_UNSUPPORT_OPERATION);

    XMP_Error errorDefault(kXMPErr_Unknown, "Unknown XMP error");
    uint32_t retDefault = XMPHelper::MapXMPErrorToMediaError(errorDefault);
    ASSERT_EQ(retDefault, ERR_XMP_DECODE_FAILED);

    GTEST_LOG_(INFO) << "XmpHelperTest: MapXMPErrorToMediaErrorTest001 end";
}

/**
 * @tc.name: LogXMPErrorTest001
 * @tc.desc: Test LogXMPError can handle null error message correctly without crash
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, LogXMPErrorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: LogXMPErrorTest001 start";
    const char* funcName = "LogXMPErrorTest001";
    XMP_Error error(kXMPErr_Unknown, nullptr);
    ASSERT_NO_FATAL_FAILURE(XMPHelper::LogXMPError(funcName, error));
    GTEST_LOG_(INFO) << "XmpHelperTest: LogXMPErrorTest001 end";
}

/**
 * @tc.name: LogXMPErrorTest002
 * @tc.desc: Test LogXMPError can handle non-null error message correctly without crash
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, LogXMPErrorTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: LogXMPErrorTest002 start";
    const char* funcName = "LogXMPErrorTest002";
    const char* testErrMsg = "Test XMP error: Bad parameter";
    XMP_Error error(kXMPErr_BadParam, testErrMsg);
    ASSERT_NO_FATAL_FAILURE(XMPHelper::LogXMPError(funcName, error));
    GTEST_LOG_(INFO) << "XmpHelperTest: LogXMPErrorTest002 end";
}

/**
 * @tc.name: ExtractPropertyTest001
 * @tc.desc: Test ExtractProperty returns empty when pathExpression is empty
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest001 start";
    std::string_view pathExpression = "";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest001 end";
}

/**
 * @tc.name: ExtractPropertyTest002
 * @tc.desc: Test ExtractProperty not return empty when pathExpression is non-empty
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest002 start";
    std::string_view pathExpression = "dc:creator";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "dc:creator");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest002 end";
}

/**
 * @tc.name: ExtractPropertyTest003
 * @tc.desc: Test ExtractProperty returns empty when pathExpression is all whitespace
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest003 start";
    std::string_view pathExpression = "  \t\r\n  ";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest003 end";
}

/**
 * @tc.name: ExtractPropertyTest004
 * @tc.desc: Test ExtractProperty not return empty when pathExpression is trimmed to non-empty
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest004 start";
    std::string_view pathExpression = "  dc:creator  ";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "dc:creator");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest004 end";
}

/**
 * @tc.name: ExtractPropertyTest005
 * @tc.desc: Test ExtractProperty returns original path when no '[' and '/' exists
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest005 start";
    std::string_view pathExpression = "dc:creator";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "dc:creator");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest005 end";
}

/**
 * @tc.name: ExtractPropertyTest006
 * @tc.desc: Test ExtractProperty not return original path when '[' or '/' exists
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest006 start";
    std::string_view pathExpression = "dc:subject[2]";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "dc:subject[2]");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest006 end";
}

/**
 * @tc.name: ExtractPropertyTest007
 * @tc.desc: Test ExtractProperty returns 'xml:lang' when path contains '/@xml:lang' or '/?xml:lang'
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest007 start";
    std::string_view pathExpression = "dc:title[1]/@xml:lang";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "xml:lang");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest007 end";
}

/**
 * @tc.name: ExtractPropertyTest008
 * @tc.desc: Test ExtractProperty not return 'xml:lang' when path not contains lang related path
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest008 start";
    std::string_view pathExpression = "dc:title[1]/?book:lastUpdated";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "book:lastUpdated");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest008 end";
}

/**
 * @tc.name: ExtractPropertyTest009
 * @tc.desc: Test ExtractProperty returns qualifier when path contains '/?'
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest009 start";
    std::string_view pathExpression = "dc:title[1]/?book:lastUpdated";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "book:lastUpdated");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest009 end";
}

/**
 * @tc.name: ExtractPropertyTest010
 * @tc.desc: Test ExtractProperty not return qualifier
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest010 start";
    std::string_view pathExpression = "exif:Flash/"; 
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest010 end";
}

/**
 * @tc.name: ExtractPropertyTest011
 * @tc.desc: Test ExtractProperty returns last component
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest011 start";
    std::string_view pathExpression = "exif:Flash/exif:Fired";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "exif:Fired");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest011 end";
}

/**
 * @tc.name: ExtractPropertyTest012
 * @tc.desc: Test ExtractProperty not return last component when '/' is at end or no '/'
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest012 start";
    std::string_view pathExpression = "dc:subject[2]";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "dc:subject[2]");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest012 end";
}

/**
 * @tc.name: ExtractPropertyTest013
 * @tc.desc: Test ExtractProperty returns original path when path contains '['
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest013 start";
    std::string_view pathExpression = "dc:subject[last()]";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "dc:subject[last()]");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest013 end";
}

/**
 * @tc.name: ExtractPropertyTest014
 * @tc.desc: Test ExtractProperty returns empty when path has no '[' and no matched branch
 * @tc.type: FUNC
 */
HWTEST_F(XmpHelperTest, ExtractPropertyTest014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest014 start";
    std::string_view pathExpression = "unknown:path/";
    std::string result = XMPHelper::ExtractProperty(pathExpression);
    ASSERT_STREQ(result.c_str(), "");
    GTEST_LOG_(INFO) << "XmpHelperTest: ExtractPropertyTest014 end";
}

} // namespace Media
} // namespace OHOS