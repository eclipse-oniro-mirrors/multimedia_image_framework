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

#define private public
#include <gtest/gtest.h>
#include <memory>
#include <thread>

#include "image_log.h"
#include "media_errors.h"
#include "xmp_metadata.h"
#include "xmp_helper.h"

using namespace OHOS::Media;
using namespace testing::ext;

namespace OHOS {
namespace Multimedia {

namespace {
constexpr const uint8_t XMP_BLOB_DATA[] = R"XMP(<?xpacket begin="?" id="W5M0MpCehiHzreSzNTczkc9d"?>
 <x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 5.4-c002 1.000000, 0000/00/00-00:00:00        ">
   <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description rdf:about=""
            xmlns:xmp="http://ns.adobe.com/xap/1.0/">
         <xmp:CreatorTool>Picasa</xmp:CreatorTool>
      </rdf:Description>
      <rdf:Description rdf:about=""
            xmlns:mwg-rs="http://www.metadataworkinggroup.com/schemas/regions/"
            xmlns:stDim="http://ns.adobe.com/xap/1.0/sType/Dimensions#"
            xmlns:stArea="http://ns.adobe.com/xmp/sType/Area#">
         <mwg-rs:Regions rdf:parseType="Resource">
            <mwg-rs:AppliedToDimensions rdf:parseType="Resource">
               <stDim:w>912</stDim:w>
               <stDim:h>687</stDim:h>
               <stDim:unit>pixel</stDim:unit>
            </mwg-rs:AppliedToDimensions>
            <mwg-rs:RegionList>
               <rdf:Bag>
                  <rdf:li rdf:parseType="Resource">
                     <mwg-rs:Area rdf:parseType="Resource">
                        <stArea:x>0.680921052631579</stArea:x>
                        <stArea:y>0.3537117903930131</stArea:y>
                        <stArea:h>0.4264919941775837</stArea:h>
                        <stArea:w>0.32127192982456143</stArea:w>
                     </mwg-rs:Area>
                  </rdf:li>
               </rdf:Bag>
            </mwg-rs:RegionList>
         </mwg-rs:Regions>
      </rdf:Description>
   </rdf:RDF>
 </x:xmpmeta>
<?xpacket end="w"?>)XMP";

constexpr std::string_view EMPTY_STRING = "";
constexpr std::string_view TEST_PATH = "test:path";
constexpr std::string_view COLON = ":";

const std::pair<std::string, std::string> RESULT_PAIR = {"test", "path"};
const std::pair<std::string, std::string> ERROR_RESULT_PAIR = {};
}

class XmpMetadataTest : public testing::Test {
public:
    XmpMetadataTest() = default;
    ~XmpMetadataTest() = default;
};

static bool SetValueForTest(XMPMetadata &xmpMetadata, const std::string &path, XMPTagType type,
    const std::string &value)
{
    uint32_t ret = xmpMetadata.SetValue(path, type, value);
    if (ret != SUCCESS) {
        GTEST_LOG_(INFO) << "SetValueForTest: SetValue failed for path: " << path;
    }
    return ret == SUCCESS;
}

static bool GetTagForTest(XMPMetadata &xmpMetadata, const std::string &path, XMPTag &outTag)
{
    uint32_t ret = xmpMetadata.GetTag(path, outTag);
    if (ret != SUCCESS) {
        GTEST_LOG_(INFO) << "GetTagForTest: GetTag failed for path: " << path;
    }
    return ret == SUCCESS;
}

static bool SetValueAndGetTagForTest(XMPMetadata &xmpMetadata, const std::string &path, XMPTagType type,
    const std::string &value, XMPTag &outTag)
{
    if (!SetValueForTest(xmpMetadata, path, type, value)) {
        return false;
    }
    return GetTagForTest(xmpMetadata, path, outTag);
}

struct ExpectedTagTypeValue {
    XMPTagType type;
    std::string value;
};

static void GetLastTag(XMPMetadata &xmpMetadata, std::string &path, ExpectedTagTypeValue &lastTag,
    std::vector<ExpectedTagTypeValue> &xmpTagVec)
{
    XMPTag parentTag;
    std::string lastTagPath;
    (void)xmpMetadata.GetTag(path, parentTag);

    switch (parentTag.type) {
        case XMPTagType::UNORDERED_ARRAY:
        case XMPTagType::ORDERED_ARRAY:
        case XMPTagType::ALTERNATE_ARRAY:
            lastTagPath = path + "[last()]";
            {
                XMPTag lastXmpTag;
                (void)xmpMetadata.GetTag(lastTagPath, lastXmpTag);
                lastTag = { lastXmpTag.type, lastXmpTag.value };
            }
            break;
        case XMPTagType::SIMPLE:
        case XMPTagType::STRUCTURE:
            if (!xmpTagVec.empty()) {
                lastTag = xmpTagVec.back();
            }
            break;
        default:
            GTEST_LOG_(INFO) << "GetLastTag: Invalid XMPTagType";
            break;
    }
}

static Media::XMPMetadata::EnumerateCallback InitTestCallback(std::vector<ExpectedTagTypeValue> &xmpTagVec,
    XMPMetadata &xmpMetadata, std::string &parentPath)
{
    Media::XMPMetadata::EnumerateCallback callback =
        [&xmpTagVec, &xmpMetadata, &parentPath](const std::string &path, const XMPTag &tag) -> bool {
            GTEST_LOG_(INFO) <<
                "name: " << tag.name << ", type: " << static_cast<int>(tag.type) << ", value: " << tag.value << " in.";
            bool isTagFound = false;
            for (const ExpectedTagTypeValue &it : xmpTagVec) {
                if (it.type == tag.type && it.value == tag.value) {
                    isTagFound = true;
                    break;
                }
            }
            if (!isTagFound) {
                GTEST_LOG_(INFO) <<
                    "name: " << tag.name <<
                    ", type: " << static_cast<int>(tag.type) << ", value: " << tag.value << " not found!";
            }
            EXPECT_TRUE(isTagFound);
            isTagFound = false;

            ExpectedTagTypeValue lastTag { XMPTagType::UNKNOWN, "" };
            GetLastTag(xmpMetadata, parentPath, lastTag, xmpTagVec);

            if (tag.type == lastTag.type && tag.value == lastTag.value) {
                return false;
            }
            return true;
        };
    return callback;
}

static void InitTestChildTagsPart1(XMPMetadata &xmpMetadata, std::vector<ExpectedTagTypeValue> &xmpTagVec)
{
    bool ret = SetValueForTest(xmpMetadata, "dc:unorderedArray[1]", XMPTagType::SIMPLE, "first");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "first" });

    ret = SetValueForTest(xmpMetadata, "dc:unorderedArray[2]", XMPTagType::UNORDERED_ARRAY, "");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::UNORDERED_ARRAY, "" });

    ret = SetValueForTest(xmpMetadata, "dc:unorderedArray[2][1]", XMPTagType::SIMPLE, "firstChild");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "firstChild" });

    ret = SetValueForTest(xmpMetadata, "dc:unorderedArray[2][2]", XMPTagType::SIMPLE, "secondChild");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "secondChild" });

    ret = SetValueForTest(xmpMetadata, "dc:orderedArray[1]", XMPTagType::SIMPLE, "first");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "first" });

    ret = SetValueForTest(xmpMetadata, "dc:orderedArray[2]", XMPTagType::SIMPLE, "second");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "second" });

    ret = SetValueForTest(xmpMetadata, "dc:alternateArray[1]", XMPTagType::SIMPLE, "first");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "first" });

    ret = SetValueForTest(xmpMetadata, "dc:alternateArray[2]", XMPTagType::SIMPLE, "second");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "second" });
}

static void InitTestChildTagsPart2(XMPMetadata &xmpMetadata, std::vector<ExpectedTagTypeValue> &xmpTagVec)
{
    bool ret = SetValueForTest(xmpMetadata, "dc:title[1]", XMPTagType::SIMPLE, "Default Title");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "Default Title" });

    ret = SetValueForTest(xmpMetadata, "dc:title[2]", XMPTagType::SIMPLE, "中文标题");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "中文标题" });

    ret = SetValueForTest(xmpMetadata, "dc:title[1]/@xml:lang", XMPTagType::QUALIFIER, "x-default");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::QUALIFIER, "x-default" });

    ret = SetValueForTest(xmpMetadata, "dc:title[2]/@xml:lang", XMPTagType::QUALIFIER, "zh-CN");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::QUALIFIER, "zh-CN" });

    ret = SetValueForTest(xmpMetadata, "dc:structure/dc:first", XMPTagType::SIMPLE, "first");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "first" });

    ret = SetValueForTest(xmpMetadata, "dc:structure/dc:second", XMPTagType::SIMPLE, "second");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "second" });

    ret = SetValueForTest(xmpMetadata, "dc:simple/?xml:first", XMPTagType::QUALIFIER, "first");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::QUALIFIER, "first" });

    ret = SetValueForTest(xmpMetadata, "dc:simple/?xml:second", XMPTagType::QUALIFIER, "second");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::QUALIFIER, "second" });
}

static void InitTestXMPMetadataForEnumerate(XMPMetadata &xmpMetadata, std::vector<ExpectedTagTypeValue> &xmpTagVec)
{
    bool ret = SetValueForTest(xmpMetadata, "dc:unorderedArray", XMPTagType::UNORDERED_ARRAY, "");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:orderedArray", XMPTagType::ORDERED_ARRAY, "");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::ORDERED_ARRAY, "" });

    ret = SetValueForTest(xmpMetadata, "dc:alternateArray", XMPTagType::ALTERNATE_ARRAY, "");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::ALTERNATE_ARRAY, "" });

    ret = SetValueForTest(xmpMetadata, "dc:title", XMPTagType::ALTERNATE_TEXT, "");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::ALTERNATE_TEXT, "" });

    ret = SetValueForTest(xmpMetadata, "dc:structure", XMPTagType::STRUCTURE, "");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::STRUCTURE, "" });

    ret = SetValueForTest(xmpMetadata, "dc:simple", XMPTagType::SIMPLE, "simple");
    EXPECT_TRUE(ret);
    xmpTagVec.push_back({ XMPTagType::SIMPLE, "simple" });

    InitTestChildTagsPart1(xmpMetadata, xmpTagVec);
    InitTestChildTagsPart2(xmpMetadata, xmpTagVec);
}

/**
 * @tc.name: XMPMetadataRefCountTest001
 * @tc.desc: test the constructor method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, XMPMetadataRefCountTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: XMPMetadataRefCountTest001 start";
    std::unique_ptr<XMPMetadata> xmpMetadata1;
    std::unique_ptr<XMPMetadata> xmpMetadata2;
    std::thread t1([&xmpMetadata1]() {
        xmpMetadata1 = std::make_unique<XMPMetadata>();
    });
    std::thread t2([&xmpMetadata2]() {
        xmpMetadata2 = std::make_unique<XMPMetadata>();
    });

    t1.join();
    t2.join();
    GTEST_LOG_(INFO) << "XmpMetadataTest: XMPMetadataRefCountTest001 refCount: " << XMPMetadata::refCount_;
    EXPECT_TRUE(XMPMetadata::refCount_ == 2);
    xmpMetadata1.reset();
    GTEST_LOG_(INFO) << "XmpMetadataTest: XMPMetadataRefCountTest001 refCount: " << XMPMetadata::refCount_;
    EXPECT_TRUE(XMPMetadata::refCount_ == 1);
    xmpMetadata2.reset();
    GTEST_LOG_(INFO) << "XmpMetadataTest: XMPMetadataRefCountTest001 refCount: " << XMPMetadata::refCount_;
    EXPECT_TRUE(XMPMetadata::refCount_ == 0);
    GTEST_LOG_(INFO) << "XmpMetadataTest: XMPMetadataRefCountTest001 end";
}

/**
 * @tc.name: RegisterNamespacePrefixTest001
 * @tc.desc: test the RegisterNamespacePrefix method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest001 start";
    XMPMetadata xmpMetadata;
    std::string namespaceURI = "http://example.com/custom/1.0/";
    std::string preferredPrefix = "custom";
    uint32_t ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix);
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest001 end";
}

/**
 * @tc.name: RegisterNamespacePrefixTest002
 * @tc.desc: test the RegisterNamespacePrefix when try to register a namespace that is already registered.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest002 start";
    XMPMetadata xmpMetadata;
    std::string namespaceURI = "http://ns.adobe.com/xap/1.0/";
    std::string preferredPrefix = "xmp";
    uint32_t ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix);
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest002 end";
}

/**
 * @tc.name: RegisterNamespacePrefixTest003
 * @tc.desc: test the RegisterNamespacePrefix when try to register a prefix that is already registered.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RegisterNamespacePrefixTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest003 start";
    XMPMetadata xmpMetadata;
    std::string namespaceURI = "http://example.com/custom/1.0/";
    std::string preferredPrefix = "xmp";
    uint32_t ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix);
    EXPECT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest003 end";
}

/**
 * @tc.name: SetTagTest001
 * @tc.desc: test the SetTag method when the type of tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest001 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest001";
    tag.type = XMPTagType::SIMPLE;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, tag.value);
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest001 end";
}

/**
 * @tc.name: SetTagTest002
 * @tc.desc: test the SetTag method when the type of tag is unordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest002 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::UNORDERED_ARRAY;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, "");
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest002 end";
}

/**
 * @tc.name: SetTagTest003
 * @tc.desc: test the SetTag method when the type of tag is ordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest003 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::ORDERED_ARRAY;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, "");
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest003 end";
}

/**
 * @tc.name: SetTagTest004
 * @tc.desc: test the SetTag method when the type of tag is alternate array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest004 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::ALTERNATE_ARRAY;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, "");
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest004 end";
}

/**
 * @tc.name: SetTagTest005
 * @tc.desc: test the SetTag method when the type of tag is alternate text.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest005 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::ALTERNATE_TEXT;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, "");
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest005 end";
}

/**
 * @tc.name: SetTagTest006
 * @tc.desc: test the SetTag method when the type of tag is structure.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest006 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::STRUCTURE;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, "");
    EXPECT_EQ(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest006 end";
}

/**
 * @tc.name: SetTagTest007
 * @tc.desc: test the SetTag method when the type of tag is unordered array with value.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest007 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest007";
    tag.type = XMPTagType::UNORDERED_ARRAY;
    uint32_t ret = xmpMetadata.SetValue("xmp:CreatorTool", tag.type, tag.value);
    EXPECT_NE(ret, SUCCESS);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest007 end";
}

/**
 * @tc.name: GetTagTest001
 * @tc.desc: test the GetTag method when the type of the first parent tag, the second parent tag and the third parent
 *           tag are all unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest001 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest001_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest001 end";
}

/**
 * @tc.name: GetTagTest002
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both unordered
 *           array, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest002 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest002_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest002 end";
}

/**
 * @tc.name: GetTagTest003
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both unordered
 *           array, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest003 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest003_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest003 end";
}

/**
 * @tc.name: GetTagTest004
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both unordered
 *           array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest004 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest004_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest004 end";
}

/**
 * @tc.name: GetTagTest005
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both unordered
 *           array, the second parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest005 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest005_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest005 end";
}

/**
 * @tc.name: GetTagTest006
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag and
 *           the third parent tag are both ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest006 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest006_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest006 end";
}

/**
 * @tc.name: GetTagTest007
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag is
 *           ordered array, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest007 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest007_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest007 end";
}

/**
 * @tc.name: GetTagTest008
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag is
 *           ordered array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest008 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest008_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest008 end";
}

/**
 * @tc.name: GetTagTest009
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both unordered
 *           array, the second parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest009 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest009_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest009 end";
}

/**
 * @tc.name: GetTagTest010
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both unordered
 *           array, the second parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest010 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest010_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest010 end";
}

/**
 * @tc.name: GetTagTest011
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag and
 *           the third parent tag are both alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest011 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest011_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest011 end";
}

/**
 * @tc.name: GetTagTest012
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag is
 *           alternate array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest012 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest012_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest012 end";
}

/**
 * @tc.name: GetTagTest013
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag is
 *           structure, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest013 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest013_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest013 end";
}

/**
 * @tc.name: GetTagTest014
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag is
 *           structure, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest014 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest014_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest014 end";
}

/**
 * @tc.name: GetTagTest015
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag is
 *           structure, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest015 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest015_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest015 end";
}

/**
 * @tc.name: GetTagTest016
 * @tc.desc: test the GetTag method when the type of the first parent tag is unordered array, the second parent tag and
 *           the third parent tag are both structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest016 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest016_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest016 end";
}

/**
 * @tc.name: GetTagTest017
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag and
 *           the third parent tag are both unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest017 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest017_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest017 end";
}

/**
 * @tc.name: GetTagTest018
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both ordered
 *           array, the second parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest018 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest018_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest018 end";
}

/**
 * @tc.name: GetTagTest019
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag is
 *           unordered array, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest019 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest019_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest019 end";
}

/**
 * @tc.name: GetTagTest020
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag is
 *           unordered array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest020 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest020_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest020 end";
}

/**
 * @tc.name: GetTagTest021
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both ordered
 *           array, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest021 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest021_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest021 end";
}

/**
 * @tc.name: GetTagTest022
 * @tc.desc: test the GetTag method when the type of the first parent tag, the second parent tag and the third parent
 *           tag are all ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest022 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest022_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest022 end";
}

/**
 * @tc.name: GetTagTest023
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both ordered
 *           array, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest023 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest023_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest023 end";
}

/**
 * @tc.name: GetTagTest024
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both ordered
 *           array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest024 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest024_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest024 end";
}

/**
 * @tc.name: GetTagTest025
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag is
 *           alternate array, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest025 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest025_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest025 end";
}

/**
 * @tc.name: GetTagTest026
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both ordered
 *           array, the second parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest026 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest026_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest026 end";
}

/**
 * @tc.name: GetTagTest027
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag and
 *           the third parent tag are both alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest027 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest027_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest027 end";
}

/**
 * @tc.name: GetTagTest028
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag is
 *           alternate array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest028 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest028_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest028 end";
}

/**
 * @tc.name: GetTagTest029
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag is
 *           structure, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest029 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest029_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest029 end";
}

/**
 * @tc.name: GetTagTest030
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both ordered
 *           array, the second parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest030 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest030_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest030 end";
}

/**
 * @tc.name: GetTagTest031
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag is
 *           structure, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest031 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest031_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest031 end";
}

/**
 * @tc.name: GetTagTest032
 * @tc.desc: test the GetTag method when the type of the first parent tag is ordered array, the second parent tag and
 *           the third parent tag are both alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest032 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest032_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest032 end";
}

/**
 * @tc.name: GetTagTest033
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag and
 *           the third parent tag are both unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest033 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest033_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest033 end";
}

/**
 * @tc.name: GetTagTest034
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag is
 *           unordered array, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest034 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest034_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest034 end";
}

/**
 * @tc.name: GetTagTest035
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both alternate
 *           array, the second parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest035 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest035_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest035 end";
}

/**
 * @tc.name: GetTagTest036
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag is
 *           unordered array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest036 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest036_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest036 end";
}

/**
 * @tc.name: GetTagTest037
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag is
 *           ordered array, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest037 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest037_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest037 end";
}

/**
 * @tc.name: GetTagTest038
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag and
 *           the third parent tag are both ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest038 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest038_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest038 end";
}

/**
 * @tc.name: GetTagTest039
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both alternate
 *           array, the second parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest039 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest039_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest039 end";
}

/**
 * @tc.name: GetTagTest040
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag is
 *           ordered array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest040, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest040 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest040_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest040 end";
}

/**
 * @tc.name: GetTagTest041
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both alternate
 *           array, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest041, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest041 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest041_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest041 end";
}

/**
 * @tc.name: GetTagTest042
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both alternate
 *           array, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest042, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest042 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest042_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest042 end";
}

/**
 * @tc.name: GetTagTest043
 * @tc.desc: test the GetTag method when the type of the first parent tag, the second parent tag and the third parent
 *           tag are all alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest043, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest043 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest043_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest043 end";
}

/**
 * @tc.name: GetTagTest044
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both alternate
 *           array, the third parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest044, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest044 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest044_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest044 end";
}

/**
 * @tc.name: GetTagTest045
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag is
 *           structure, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest045, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest045 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest045_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest045 end";
}

/**
 * @tc.name: GetTagTest046
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag is
 *           structure, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest046, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest046 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest046_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest046 end";
}

/**
 * @tc.name: GetTagTest047
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both alternate
 *           array, the second parent tag is structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest047, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest047 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest047_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest047 end";
}

/**
 * @tc.name: GetTagTest048
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate array, the second parent tag and
 *           the third parent tag are both structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest048, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest048 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest048_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first[1]/dc:second/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest048 end";
}

/**
 * @tc.name: GetTagTest049
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag and
 *           the third parent tag are both unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest049, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest049 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest049_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest049 end";
}

/**
 * @tc.name: GetTagTest050
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag is
 *           unordered array, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest050, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest050 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest050_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest050 end";
}

/**
 * @tc.name: GetTagTest051
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag is
 *           unordered array, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest051, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest051 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest051_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest051 end";
}

/**
 * @tc.name: GetTagTest052
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure and the second parent tag are
 *           both structure, the second parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest052, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest052 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::UNORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest052_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest052 end";
}

/**
 * @tc.name: GetTagTest053
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag is
 *           ordered array, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest053, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest053 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest053_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest053 end";
}

/**
 * @tc.name: GetTagTest054
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag and the
 *           third parent tag are both ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest054, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest054 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest054_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest054 end";
}

/**
 * @tc.name: GetTagTest055
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag is
 *           ordered array, the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest055, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest055 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest055_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest055 end";
}

/**
 * @tc.name: GetTagTest056
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both structure,
 *           the second parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest056, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest056 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest056_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest056 end";
}

/**
 * @tc.name: GetTagTest057
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag is
 *           alternate array, the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest057, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest057 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest057_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest057 end";
}

/**
 * @tc.name: GetTagTest058
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag is
 *           alternate array, the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest058, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest058 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::ORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest058_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest058 end";
}

/**
 * @tc.name: GetTagTest059
 * @tc.desc: test the GetTag method when the type of the first parent tag is structure, the second parent tag and the
 *           third parent tag are both alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest059, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest059 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest059_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest059 end";
}

/**
 * @tc.name: GetTagTest060
 * @tc.desc: test the GetTag method when the type of the first parent tag and the third parent tag are both structure,
 *           the second parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest060, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest060 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::ALTERNATE_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest060_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second[1]/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest060 end";
}

/**
 * @tc.name: GetTagTest061
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both structure,
 *           the third parent tag is unordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest061, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest061 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third", XMPTagType::UNORDERED_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::UNORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest061_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest061 end";
}

/**
 * @tc.name: GetTagTest062
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both structure,
 *           the third parent tag is ordered array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest062, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest062 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third", XMPTagType::ORDERED_ARRAY, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ORDERED_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest062_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest062 end";
}

/**
 * @tc.name: GetTagTest063
 * @tc.desc: test the GetTag method when the type of the first parent tag and the second parent tag are both structure,
 *           the third parent tag is alternate array, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest063, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest063 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third", XMPTagType::ALTERNATE_ARRAY, "",
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_ARRAY);

    const std::string childValue = "XmpMetadataTest.GetTagTest063_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third[1]", XMPTagType::SIMPLE, childValue,
        getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest063 end";
}

/**
 * @tc.name: GetTagTest064
 * @tc.desc: test the GetTag method when the type of the first parent tag, the second parent tag and the third parent
 *           tag are all structure, and the child tag is simple.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest064, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest064 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third", XMPTagType::STRUCTURE, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::STRUCTURE);

    const std::string childValue = "XmpMetadataTest.GetTagTest064_value1";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:first/dc:second/dc:third/dc:child", XMPTagType::SIMPLE,
        childValue, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest064 end";
}

/**
 * @tc.name: GetTagTest065
 * @tc.desc: test the GetTag method when the type of the first parent tag is alternate text, the child tag is simple
 *           with the tag witch the type is qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest065, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest065 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:title", XMPTagType::ALTERNATE_TEXT, "", getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::ALTERNATE_TEXT);

    const std::string childValue1 = "Default Title";
    ret = SetValueForTest(xmpMetadata, "dc:title[1]", XMPTagType::SIMPLE, childValue1);
    EXPECT_TRUE(ret);

    const std::string childValue2 = "中文标题";
    ret = SetValueForTest(xmpMetadata, "dc:title[2]", XMPTagType::SIMPLE, childValue2);
    EXPECT_TRUE(ret);

    const std::string qualValue1 = "x-default";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:title[1]/@xml:lang", XMPTagType::QUALIFIER, qualValue1, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::QUALIFIER);
    EXPECT_EQ(getTag.value, qualValue1);

    const std::string qualValue2 = "zh-CN";
    ret = SetValueAndGetTagForTest(xmpMetadata, "dc:title[2]/@xml:lang", XMPTagType::QUALIFIER, qualValue2, getTag);
    EXPECT_TRUE(ret);
    EXPECT_EQ(getTag.type, XMPTagType::QUALIFIER);
    EXPECT_EQ(getTag.value, qualValue2);

    uint32_t code = xmpMetadata.GetTag("dc:title[@xml:lang='x-default']", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue1);

    code = xmpMetadata.GetTag("dc:title[@xml:lang='zh-CN']", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest065 end";
}

/**
 * @tc.name: GetTagTest066
 * @tc.desc: test the GetTag method with other symbol when the type of the first parent tag is alternate text, the child
 *           tag is simple with the tag witch the type is qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest066, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest066 start";
    XMPMetadata xmpMetadata;
    XMPTag getTag;
    bool ret = SetValueAndGetTagForTest(xmpMetadata, "dc:title", XMPTagType::ALTERNATE_TEXT, "", getTag);
    EXPECT_TRUE(ret);

    const std::string childValue1 = "Default Title";
    ret = SetValueForTest(xmpMetadata, "dc:title[1]", XMPTagType::SIMPLE, childValue1);
    EXPECT_TRUE(ret);

    const std::string childValue2 = "中文标题";
    ret = SetValueForTest(xmpMetadata, "dc:title[2]", XMPTagType::SIMPLE, childValue2);
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:title[1]/?xml:lang", XMPTagType::QUALIFIER, "x-default");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:title[2]/?xml:lang", XMPTagType::QUALIFIER, "zh-CN");
    EXPECT_TRUE(ret);

    uint32_t code = xmpMetadata.GetTag("dc:title[?xml:lang='x-default']", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue1);

    code = xmpMetadata.GetTag("dc:title[?xml:lang=\"zh-CN\"]", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest066 end";
}

/**
 * @tc.name: GetTagTest067
 * @tc.desc: test the GetTag method with other symbol when the type of the first parent tag is structure, the child
 *           tag is ALTERNATE_TEXT and its element is simple with the tag which has qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest067, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest067 start";
    XMPMetadata xmpMetadata;
    bool ret = SetValueForTest(xmpMetadata, "dc:subject", XMPTagType::STRUCTURE, "");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:title", XMPTagType::ALTERNATE_TEXT, "");
    EXPECT_TRUE(ret);

    const std::string childValue1 = "Default Title";
    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:title[1]", XMPTagType::SIMPLE, childValue1);
    EXPECT_TRUE(ret);

    const std::string childValue2 = "中文标题";
    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:title[2]", XMPTagType::SIMPLE, childValue2);
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:title[1]/?xml:lang", XMPTagType::QUALIFIER, "x-default");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:title[2]/?xml:lang", XMPTagType::QUALIFIER, "zh-CN");
    EXPECT_TRUE(ret);

    XMPTag getTag;
    uint32_t code = xmpMetadata.GetTag("dc:subject/dc:title[?xml:lang='x-default']", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue1);

    code = xmpMetadata.GetTag("dc:subject/dc:title[?xml:lang=\"zh-CN\"]", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest067 end";
}

/**
 * @tc.name: GetTagTest068
 * @tc.desc: test the GetTag method with other symbol when the type of the first parent tag is structure, the child
 *           tag is simple with the tag witch the type is qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest068, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest068 start";
    XMPMetadata xmpMetadata;
    bool ret = SetValueForTest(xmpMetadata, "dc:subject", XMPTagType::STRUCTURE, "");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:child1", XMPTagType::SIMPLE, "childTag_1");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:child2", XMPTagType::SIMPLE, "childTag_2");
    EXPECT_TRUE(ret);

    const std::string qualValue1 = "25";
    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:child1/?xml:age", XMPTagType::QUALIFIER, qualValue1);
    EXPECT_TRUE(ret);

    const std::string qualValue2 = "30";
    ret = SetValueForTest(xmpMetadata, "dc:subject/dc:child2/?xml:age", XMPTagType::QUALIFIER, qualValue2);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    uint32_t code = xmpMetadata.GetTag("dc:subject/dc:child1/?xml:age", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::QUALIFIER);
    EXPECT_EQ(getTag.value, qualValue1);

    code = xmpMetadata.GetTag("dc:subject/dc:child2/?xml:age", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::QUALIFIER);
    EXPECT_EQ(getTag.value, qualValue2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest068 end";
}


/**
 * @tc.name: GetTagTest069
 * @tc.desc: test the GetTag method with other symbol when the type of the first parent tag is unordered array, the
 *           child tag is simple with the tag witch the type is qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, GetTagTest069, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest069 start";
    XMPMetadata xmpMetadata;
    bool ret = SetValueForTest(xmpMetadata, "dc:subject", XMPTagType::UNORDERED_ARRAY, "");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject[1]/dc:title", XMPTagType::ALTERNATE_TEXT, "");
    EXPECT_TRUE(ret);

    const std::string childValue1 = "Default Title";
    ret = SetValueForTest(xmpMetadata, "dc:subject[1]/dc:title[1]", XMPTagType::SIMPLE, childValue1);
    EXPECT_TRUE(ret);

    const std::string childValue2 = "中文标题";
    ret = SetValueForTest(xmpMetadata, "dc:subject[1]/dc:title[2]", XMPTagType::SIMPLE, childValue2);
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject[1]/dc:title[1]/@xml:lang", XMPTagType::QUALIFIER, "x-default");
    EXPECT_TRUE(ret);

    ret = SetValueForTest(xmpMetadata, "dc:subject[1]/dc:title[2]/@xml:lang", XMPTagType::QUALIFIER, "zh-CN");
    EXPECT_TRUE(ret);

    XMPTag getTag;
    uint32_t code = xmpMetadata.GetTag("dc:subject[1]/dc:title[@xml:lang='x-default']", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue1);

    code = xmpMetadata.GetTag("dc:subject[1]/dc:title[@xml:lang=\"zh-CN\"]", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, childValue2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest069 end";
}

/**
 * @tc.name: EnumerateTags001
 * @tc.desc: test the EnumerateTags method from root node.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags001 start";
    std::string parentPath;
    XMPMetadata xmpMetadata;
    std::vector<ExpectedTagTypeValue> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    uint32_t ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags001 end";
}

/**
 * @tc.name: EnumerateTags002
 * @tc.desc: test the EnumerateTags method when some items in array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags002 start";
    std::string parentPath;
    XMPMetadata xmpMetadata;
    std::vector<ExpectedTagTypeValue> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:unorderedArray";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    uint32_t ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    parentPath = "dc:orderedArray";
    callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    parentPath = "dc:alternateArray";
    callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags002 end";
}

/**
 * @tc.name: EnumerateTags003
 * @tc.desc: test the EnumerateTags method when some items in structure.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags003 start";
    std::string parentPath;
    XMPMetadata xmpMetadata;
    std::vector<ExpectedTagTypeValue> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:structure";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    uint32_t ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags003 end";
}

/**
 * @tc.name: EnumerateTags004
 * @tc.desc: test the EnumerateTags method when the alternate text has several simple tags with qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags004 start";
    std::string parentPath;
    XMPMetadata xmpMetadata;
    std::vector<ExpectedTagTypeValue> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:alternateText";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    uint32_t ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags004 end";
}

/**
 * @tc.name: EnumerateTags005
 * @tc.desc: test the EnumerateTags method when the a simple tag has several qualifier.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags005 start";
    std::string parentPath;
    XMPMetadata xmpMetadata;
    std::vector<ExpectedTagTypeValue> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:simple";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    uint32_t ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags005 end";
}

/**
 * @tc.name: EnumerateTags006
 * @tc.desc: test the EnumerateTags method from root with recursive true.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags006 start";
    std::string parentPath;
    XMPMetadata xmpMetadata;
    std::vector<ExpectedTagTypeValue> xmpTagVec;
    XMPEnumerateOption options;
    options.isRecursive = true;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    uint32_t ret = xmpMetadata.EnumerateTags(callback, parentPath, options);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags006 end";
}

/**
 * @tc.name: SetGetBlobTest001
 * @tc.desc: test the SetBlob and GetBlob method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetGetBlobTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest001 start";
    XMPMetadata xmpMetadata;
    uint32_t ret = xmpMetadata.SetBlob(XMP_BLOB_DATA, sizeof(XMP_BLOB_DATA));
    EXPECT_EQ(ret, SUCCESS);

    std::string buffer;
    ret = xmpMetadata.GetBlob(buffer);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest001 str is " << buffer;
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest001 end";
}

/**
 * @tc.name: SetGetBlobTest002
 * @tc.desc: test the SetBlob and GetBlob method when the source and buffer size is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetGetBlobTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest002 start";
    XMPMetadata xmpMetadata;
    uint32_t ret = xmpMetadata.SetBlob(nullptr, 0);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);

    std::string buffer;
    ret = xmpMetadata.GetBlob(buffer);
    EXPECT_EQ(ret, SUCCESS);

    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest002 str is " << buffer;
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest002 end";
}

/**
 * @tc.name: SplitOnceTest001
 * @tc.desc: test the SplitOnce method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SplitOnceTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SplitOnceTest001 start";
    auto ret = XMPHelper::SplitOnce(TEST_PATH, COLON);
    EXPECT_EQ(ret, RESULT_PAIR);

    ret = XMPHelper::SplitOnce(EMPTY_STRING, COLON);
    EXPECT_EQ(ret, ERROR_RESULT_PAIR);

    ret = XMPHelper::SplitOnce(TEST_PATH, EMPTY_STRING);
    EXPECT_EQ(ret, ERROR_RESULT_PAIR);

    std::string path = "test:test:path";
    ret = XMPHelper::SplitOnce(path, COLON);
    EXPECT_EQ(ret, std::make_pair(std::string("test"), std::string("test:path")));

    ret = XMPHelper::SplitOnce(path, "/");
    EXPECT_EQ(ret, ERROR_RESULT_PAIR);

    path = "testpath:";
    ret = XMPHelper::SplitOnce(path, COLON);
    EXPECT_EQ(ret, std::make_pair(std::string("testpath"), std::string("")));

    path = ":testpath";
    ret = XMPHelper::SplitOnce(path, COLON);
    EXPECT_EQ(ret, std::make_pair(std::string(""), std::string("testpath")));

    GTEST_LOG_(INFO) << "XmpMetadataTest: SplitOnceTest001 end";
}

/**
 * @tc.name: TrimTest001
 * @tc.desc: test the Trim method.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, TrimTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: TrimTest001 start";
    auto ret = XMPHelper::Trim(TEST_PATH, COLON);
    EXPECT_EQ(ret, "test:path");

    ret = XMPHelper::Trim(TEST_PATH, TEST_PATH);
    EXPECT_EQ(ret, "");

    ret = XMPHelper::Trim(TEST_PATH, ":path");
    EXPECT_EQ(ret, "es");

    ret = XMPHelper::Trim(TEST_PATH, "abc");
    EXPECT_EQ(ret, TEST_PATH);

    ret = XMPHelper::Trim(TEST_PATH, "t");
    EXPECT_EQ(ret, "est:path");

    GTEST_LOG_(INFO) << "XmpMetadataTest: TrimTest001 end";
}

/**
 * @tc.name: ExtractPropertyTest001
 * @tc.desc: test the ExtractProperty method with nested paths.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, ExtractPropertyTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: ExtractPropertyTest001 start";
    // Case 1: Nested path with Localization Text Selector
    std::string path1 = "dc:subject/dc:title[?xml:lang='x-default']";
    EXPECT_EQ(XMPHelper::ExtractProperty(path1), "dc:title[?xml:lang='x-default']");

    // Case 2: Nested path with Array Index and Localization Text Selector
    std::string path2 = "dc:subject[1]/dc:title[@xml:lang='x-default']";
    EXPECT_EQ(XMPHelper::ExtractProperty(path2), "dc:title[@xml:lang='x-default']");

    // Case 3: Nested path with Structure Field
    std::string path3 = "exif:Flash/exif:Fired";
    EXPECT_EQ(XMPHelper::ExtractProperty(path3), "exif:Fired");

    // Case 4: Deep nested path
    std::string path4 = "dc:first[1]/dc:second[1]/dc:third[1]";
    EXPECT_EQ(XMPHelper::ExtractProperty(path4), "dc:third[1]");

    // Case 5: Nested Qualifier (Selector)
    std::string path5 = "dc:description/dc:title[?book:lastUpdated='2023']";
    EXPECT_EQ(XMPHelper::ExtractProperty(path5), "dc:title[?book:lastUpdated='2023']");

    GTEST_LOG_(INFO) << "XmpMetadataTest: ExtractPropertyTest001 end";
}

/**
 * @tc.name: ExtractPropertyTest002
 * @tc.desc: test the ExtractProperty method .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, ExtractPropertyTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: ExtractPropertyTest002 start";
    EXPECT_EQ(XMPHelper::ExtractProperty(""), "");

    std::string path = "  test path  ";
    EXPECT_EQ(XMPHelper::ExtractProperty(path), "test path");

    EXPECT_EQ(XMPHelper::ExtractProperty("["), "[");
    EXPECT_EQ(XMPHelper::ExtractProperty("]"), "]");

    path = "testpath]";
    EXPECT_EQ(XMPHelper::ExtractProperty(path), path);

    path = "dc:title[invalid path";
    EXPECT_EQ(XMPHelper::ExtractProperty(path), path);

    path = "prop/?; rm -rf /";
    EXPECT_EQ(XMPHelper::ExtractProperty("prop/?; rm -rf /"), "; rm -rf /");

    EXPECT_EQ(XMPHelper::ExtractProperty("dc:subject/[2]"), "dc:subject[2]");
    EXPECT_EQ(XMPHelper::ExtractProperty("dc:subject*[2]"), "dc:subject[2]");
    EXPECT_EQ(XMPHelper::ExtractProperty("dc:subject/*[2]"), "dc:subject[2]");
    EXPECT_EQ(XMPHelper::ExtractProperty("dc:title[1]/@xml:lang"), "xml:lang");
    EXPECT_EQ(XMPHelper::ExtractProperty("dc:title[1]/?xml:lang"), "xml:lang");
    EXPECT_EQ(XMPHelper::ExtractProperty("dc:title[1]/?book:lastUpdated"), "book:lastUpdated");

    GTEST_LOG_(INFO) << "XmpMetadataTest: ExtractPropertyTest002 end";
}

/**
 * @tc.name: RemoveTagTest001
 * @tc.desc: test the RemoveTag method unordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RemoveTagTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest001 start";
    XMPMetadata xmpMetadata;
    bool ret = SetValueForTest(xmpMetadata, "dc:parent", XMPTagType::UNORDERED_ARRAY, "");
    EXPECT_TRUE(ret);

    const std::string value1 = "first";
    ret = SetValueForTest(xmpMetadata, "dc:parent[1]", XMPTagType::SIMPLE, value1);
    EXPECT_TRUE(ret);

    const std::string value2 = "second";
    ret = SetValueForTest(xmpMetadata, "dc:parent[2]", XMPTagType::SIMPLE, value2);
    EXPECT_TRUE(ret);

    const std::string value3 = "third";
    ret = SetValueForTest(xmpMetadata, "dc:parent[3]", XMPTagType::SIMPLE, value3);
    EXPECT_TRUE(ret);

    uint32_t code = xmpMetadata.RemoveTag("dc:parent[1]");
    EXPECT_EQ(code, SUCCESS);

    XMPTag getTag;
    code = xmpMetadata.GetTag("dc:parent[1]", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, value2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest001 end";
}

/**
 * @tc.name: RemoveTagTest002
 * @tc.desc: test the RemoveTag ordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RemoveTagTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest002 start";
    XMPMetadata xmpMetadata;
    bool ret = SetValueForTest(xmpMetadata, "dc:parent", XMPTagType::ORDERED_ARRAY, "");
    EXPECT_TRUE(ret);

    const std::string value1 = "first";
    ret = SetValueForTest(xmpMetadata, "dc:parent[1]", XMPTagType::SIMPLE, value1);
    EXPECT_TRUE(ret);

    const std::string value2 = "second";
    ret = SetValueForTest(xmpMetadata, "dc:parent[2]", XMPTagType::SIMPLE, value2);
    EXPECT_TRUE(ret);

    const std::string value3 = "third";
    ret = SetValueForTest(xmpMetadata, "dc:parent[3]", XMPTagType::SIMPLE, value3);
    EXPECT_TRUE(ret);

    uint32_t code = xmpMetadata.RemoveTag("dc:parent[1]");
    EXPECT_EQ(code, SUCCESS);

    XMPTag getTag;
    code = xmpMetadata.GetTag("dc:parent[1]", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, value2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest002 end";
}

/**
 * @tc.name: RemoveTagTest003
 * @tc.desc: test the RemoveTag method alternate array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, RemoveTagTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest003 start";
    XMPMetadata xmpMetadata;
    bool ret = SetValueForTest(xmpMetadata, "dc:parent", XMPTagType::ALTERNATE_ARRAY, "");
    EXPECT_TRUE(ret);

    const std::string value1 = "first";
    ret = SetValueForTest(xmpMetadata, "dc:parent[1]", XMPTagType::SIMPLE, value1);
    EXPECT_TRUE(ret);

    const std::string value2 = "second";
    ret = SetValueForTest(xmpMetadata, "dc:parent[2]", XMPTagType::SIMPLE, value2);
    EXPECT_TRUE(ret);

    const std::string value3 = "third";
    ret = SetValueForTest(xmpMetadata, "dc:parent[3]", XMPTagType::SIMPLE, value3);
    EXPECT_TRUE(ret);

    uint32_t code = xmpMetadata.RemoveTag("dc:parent[1]");
    EXPECT_EQ(code, SUCCESS);

    XMPTag getTag;
    code = xmpMetadata.GetTag("dc:parent[1]", getTag);
    EXPECT_EQ(code, SUCCESS);
    EXPECT_EQ(getTag.type, XMPTagType::SIMPLE);
    EXPECT_EQ(getTag.value, value2);

    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest003 end";
}
} // namespace Multimedia
} // namespace OHOS
