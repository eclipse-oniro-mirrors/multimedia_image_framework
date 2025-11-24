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
 *@tc.name: InitializeTest001
 *@tc.desc: test the Initialize method.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, InitializeTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: InitializeTest001 start";
    bool ret = XMPMetadata::Initialize();
    EXPECT_TRUE(ret);
    XMPMetadata::Terminate();
    GTEST_LOG_(INFO) << "XmpMetadataTest: InitializeTest001 end";
}

/**
 *@tc.name: InitializeTest002
 *@tc.desc: test the Initialize method.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, InitializeTest002, TestSize.Level3)
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
 *@tc.name: TerminateTest001
 *@tc.desc: test the Terminate method.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, TerminateTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: TerminateTest001 start";
    XMPMetadata::Terminate();
    GTEST_LOG_(INFO) << "XmpMetadataTest: TerminateTest001 end";
}


/**
 *@tc.name: RegisterNamespacePrefixTest001
 *@tc.desc: test the RegisterNamespacePrefix method.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest001, TestSize.Level3)
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
 *@tc.name: RegisterNamespacePrefixTest002
 *@tc.desc: test the RegisterNamespacePrefix when try to register a namespace that is already registered.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest002, TestSize.Level3)
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
 *@tc.name: RegisterNamespacePrefixTest003
 *@tc.desc: test the RegisterNamespacePrefix when try to register a prefix that is already registered.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest003, TestSize.Level3)
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
 *@tc.name: SetTagTest001
 *@tc.desc: test the SetTag method.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest001, TestSize.Level3)
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
 *@tc.name: SetTagTest002
 *@tc.desc: test the SetTag method.
 *@tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest002 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    baseTag.xmlns = "http://purl.org/dc/elements/1.1/";
    baseTag.prefix = "dc";
    baseTag.name = "subject";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag tag;
    tag.xmlns = "http://purl.org/dc/elements/1.1/";
    tag.prefix = "dc";
    tag.name = "subject";
    tag.type = XMPTagType::SIMPLE;
    tag.value = "XmpMetadataTest.SetTagTest002_value1";
    ret = xmpMetadata.SetTag("dc:subject[1]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    tag.value = "XmpMetadataTest.SetTagTest002_value2";
    ret = xmpMetadata.SetTag("dc:subject[2]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[2]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    tag.value = "XmpMetadataTest.SetTagTest002_value3";
    ret = xmpMetadata.SetTag("dc:subject[3]", tag);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.GetTag("dc:subject[3]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(tag, getTag));

    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest002 end";
}

} // namespace Multimedia
} // namespace OHOS
