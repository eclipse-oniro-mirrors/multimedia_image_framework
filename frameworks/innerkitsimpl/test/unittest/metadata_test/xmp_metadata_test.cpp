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
#include <memory>

#include "image_log.h"
#include "media_errors.h"
#include "xmp_metadata.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {

class XmpMetadataTest : public testing::Test {
public:
    XmpMetadataTest() = default;
    ~XmpMetadataTest() = default;
};

static bool CompareXMPTag(const XMPTag &tag1, const XMPTag &tag2)
{
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.xmlns: " << tag1.xmlns << ", tag2.xmlns: " << tag2.xmlns;
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.prefix: " << tag1.prefix << ", tag2.prefix: " << tag2.prefix;
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.name: " << tag1.name << ", tag2.name: " << tag2.name;
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.value: " << tag1.value << ", tag2.value: " << tag2.value;
    GTEST_LOG_(INFO) << "CompareXMPTag: tag1.type: " << static_cast<int>(tag1.type) << ", tag2.type: " << static_cast<int>(tag2.type);
    return tag1.xmlns == tag2.xmlns && tag1.prefix == tag2.prefix && tag1.name == tag2.name &&
        tag1.value == tag2.value && tag1.type == tag2.type;
}

/**
 * @tc.name: InitializeTest001
 * @tc.desc: test the Initialize method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, InitializeTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: InitializeTest001 start";
    bool ret = XMPMetadata::Initialize();
    EXPECT_TRUE(ret);
    XMPMetadata::Terminate();
    GTEST_LOG_(INFO) << "XmpMetadataTest: InitializeTest001 end";
}

/**
 * @tc.name: InitializeTest002
 * @tc.desc: test the Initialize method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, InitializeTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: InitializeTest002 start";
    bool ret = XMPMetadata::Initialize();
    EXPECT_TRUE(ret);
    ret = XMPMetadata::Initialize();
    EXPECT_TRUE(ret);
    XMPMetadata::Terminate();
    GTEST_LOG_(INFO) << "XmpMetadataTest: InitializeTest002 end";
}


/**
 * @tc.name: TerminateTest001
 * @tc.desc: test the Terminate method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, TerminateTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: TerminateTest001 start";
    XMPMetadata::Terminate();
    GTEST_LOG_(INFO) << "XmpMetadataTest: TerminateTest001 end";
}


/**
 * @tc.name: RegisterNamespacePrefixTest001
 * @tc.desc: test the RegisterNamespacePrefix method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest001 start";
    XMPMetadata xmpMetadata;
    std::string namespaceURI = "http://example.com/custom/1.0/";
    std::string preferredPrefix = "custom";
    bool ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest001 end";
}

/**
 * @tc.name: RegisterNamespacePrefixTest002
 * @tc.desc: test the RegisterNamespacePrefix when try to register a namespace that is already registered.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest002 start";
    XMPMetadata xmpMetadata;
    std::string namespaceURI = "http://ns.adobe.com/xap/1.0/";
    std::string preferredPrefix = "xmp";
    bool ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest002 end";
}

/**
 * @tc.name: RegisterNamespacePrefixTest003
 * @tc.desc: test the RegisterNamespacePrefix when try to register a prefix that is already registered.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest003 start";
    XMPMetadata xmpMetadata;
    std::string namespaceURI = "http://example.com/custom/1.0/";
    std::string preferredPrefix = "xmp";
    bool ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest003 end";
}

/**
 * @tc.name: SetTagTest001
 * @tc.desc: test the SetTag method when the type of tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest001 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest001";
    tag.type = XMPTagType::SIMPLE;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest001 end";
}

/**
 * @tc.name: SetTagTest002
 * @tc.desc: test the SetTag method when the type of tag is unordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest002 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest002";
    tag.type = XMPTagType::UNORDERED_ARRAY;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest002 end";
}

/**
 * @tc.name: SetTagTest003
 * @tc.desc: test the SetTag method when the type of tag is ordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest003 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest003";
    tag.type = XMPTagType::ORDERED_ARRAY;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest003 end";
}

/**
 * @tc.name: SetTagTest004
 * @tc.desc: test the SetTag method when the type of tag is alternate array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest004 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest004";
    tag.type = XMPTagType::ALTERNATE_ARRAY;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest004 end";
}

/**
 * @tc.name: SetTagTest005
 * @tc.desc: test the SetTag method when the type of tag is alternate text.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest005 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest005";
    tag.type = XMPTagType::ALTERNATE_TEXT;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest005 end";
}

/**
 * @tc.name: SetTagTest006
 * @tc.desc: test the SetTag method when the type of tag is alternate text.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest006 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest006";
    tag.type = XMPTagType::ALTERNATE_TEXT;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest006 end";
}

/**
 * @tc.name: SetTagTest007
 * @tc.desc: test the SetTag method when the type of tag is structure.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest007 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest007";
    tag.type = XMPTagType::STRUCTURE;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest007 end";
}

/**
 * @tc.name: SetTagTest008
 * @tc.desc: test the SetTag method when the type of tag is qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest008 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = NS_DC;
    baseTag.prefix = PF_DC;
    baseTag.name = "title";
    baseTag.value = "XmpMetadataTest.SetTagTest008_title";
    baseTag.type = XMPTagType::SIMPLE;
    bool ret = xmpMetadata.SetTag("dc:title", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag;
    childTag.xmlns = NS_DC;
    childTag.prefix = PF_DC;
    childTag.name = "language";
    childTag.value = "English";
    childTag.type = XMPTagType::QUALIFIER;
    ret = xmpMetadata.SetTag("dc:title/?dc:language", childTag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest008 end";
}

/**
 * @tc.name: GetTagTest001
 * @tc.desc: test the GetTag method when the type of parent tag is unordered array and the child type is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest001 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = NS_DC;
    baseTag.prefix = PF_DC;
    baseTag.name = "subject";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag tag;
    tag.xmlns = NS_DC;
    tag.prefix = PF_DC;
    tag.name = "subject";
    tag.type = XMPTagType::SIMPLE;
    tag.value = "XmpMetadataTest.GetTagTest001_value1";
    ret = xmpMetadata.SetTag("dc:subject[1]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    tag.value = "XmpMetadataTest.GetTagTest001_value2";
    ret = xmpMetadata.SetTag("dc:subject[2]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[2]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest001 end";
}

/**
 * @tc.name: GetTagTest002
 * @tc.desc: test the GetTag method when the type of parent tag is ordered array and the child type is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest002 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = NS_DC;
    baseTag.prefix = PF_DC;
    baseTag.name = "subject";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag tag;
    tag.xmlns = NS_DC;
    tag.prefix = PF_DC;
    tag.name = "subject";
    tag.type = XMPTagType::SIMPLE;
    tag.value = "XmpMetadataTest.GetTagTest002_value1";
    ret = xmpMetadata.SetTag("dc:subject[1]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    tag.value = "XmpMetadataTest.GetTagTest002_value2";
    ret = xmpMetadata.SetTag("dc:subject[2]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[2]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest002 end";
}

/**
 * @tc.name: GetTagTest003
 * @tc.desc: test the GetTag method when the type of parent tag is alternate array and the child type is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest003 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = NS_DC;
    baseTag.prefix = PF_DC;
    baseTag.name = "subject";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag tag;
    tag.xmlns = NS_DC;
    tag.prefix = PF_DC;
    tag.name = "subject";
    tag.type = XMPTagType::SIMPLE;
    tag.value = "XmpMetadataTest.GetTagTest003_value1";
    ret = xmpMetadata.SetTag("dc:subject[1]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    tag.value = "XmpMetadataTest.GetTagTest003_value2";
    ret = xmpMetadata.SetTag("dc:subject[2]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[2]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest003 end";
}

/**
 * @tc.name: GetTagTest004
 * @tc.desc: test the GetTag method when the type of parent tag is alternate text and the child type is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest004 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = NS_DC;
    baseTag.prefix = PF_DC;
    baseTag.name = "subject";
    baseTag.type = XMPTagType::ALTERNATE_TEXT;
    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag tag;
    tag.xmlns = NS_DC;
    tag.prefix = PF_DC;
    tag.name = "subject";
    tag.type = XMPTagType::SIMPLE;
    tag.value = "XmpMetadataTest.GetTagTest004_value1";
    ret = xmpMetadata.SetTag("dc:subject[1]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    tag.value = "XmpMetadataTest.GetTagTest004_value2";
    ret = xmpMetadata.SetTag("dc:subject[2]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[2]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest004 end";
}

/**
 * @tc.name: GetTagTest005
 * @tc.desc: test the GetTag method when the type of parent tag is alternate text and the child type is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest005 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = NS_DC;
    baseTag.prefix = PF_DC;
    baseTag.name = "title";
    baseTag.value = "XmpMetadataTest.GetTagTest005_title";
    baseTag.type = XMPTagType::SIMPLE;
    bool ret = xmpMetadata.SetTag("dc:title", baseTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:title", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag tag;
    tag.xmlns = NS_DC;
    tag.prefix = PF_DC;
    tag.name = "language";
    tag.type = XMPTagType::QUALIFIER;
    tag.value = "XmpMetadataTest.English";
    ret = xmpMetadata.SetTag("dc:title/?dc:language", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:title/?dc:language", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest005 end";
}
} // namespace Multimedia
} // namespace OHOS
