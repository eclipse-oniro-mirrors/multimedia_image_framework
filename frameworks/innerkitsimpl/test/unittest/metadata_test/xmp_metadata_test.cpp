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
    constexpr uint32_t XMP_BLOB_DATA_SIZE = 4096;
    constexpr uint32_t XMP_BLOB_SMALL_SIZE = 1;

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

static bool CompareXMPTag(const XMPTag &tag1, const XMPTag &tag2)
{
    bool ret = tag1.xmlns == tag2.xmlns && tag1.prefix == tag2.prefix && tag1.name == tag2.name &&
        tag1.value == tag2.value && tag1.type == tag2.type;
    if (!ret) {
        GTEST_LOG_(INFO) <<
            "\n CompareXMPTag: tag1.xmlns: " << tag1.xmlns << ", tag2.xmlns: " << tag2.xmlns <<
            "\n CompareXMPTag: tag1.prefix: " << tag1.prefix << ", tag2.prefix: " << tag2.prefix <<
            "\n CompareXMPTag: tag1.name: " << tag1.name << ", tag2.name: " << tag2.name <<
            "\n CompareXMPTag: tag1.value: " << tag1.value << ", tag2.value: " << tag2.value <<
            "\n CompareXMPTag: tag1.type: " << static_cast<int>(tag1.type) <<
            ", tag2.type: " << static_cast<int>(tag2.type);
    }
    return ret;
}

static bool CompareXMPTagNoLog(const XMPTag &tag1, const XMPTag &tag2)
{
    return tag1.xmlns == tag2.xmlns && tag1.prefix == tag2.prefix && tag1.name == tag2.name &&
        tag1.value == tag2.value && tag1.type == tag2.type;
}

static bool DoSetTagAndGetTag(std::string path, XMPTag inputTag, XMPTag &outputTag, XMPMetadata &xmpMetadata)
{
    bool ret = xmpMetadata.SetTag(path, inputTag);
    if (!ret) {
        GTEST_LOG_(INFO) << "DoSetTagAndGetTag: SetTag failed!";
        return false;
    }

    ret = xmpMetadata.GetTag(path, outputTag);
    if (!ret) {
        GTEST_LOG_(INFO) << "DoSetTagAndGetTag: GetTag failed!";
        return false;
    }
    return true;
}

static void ResetXMPTag(XMPTag &xmpTag)
{
    xmpTag.xmlns = "";
    xmpTag.prefix = "";
    xmpTag.name = "";
    xmpTag.type = XMPTagType::UNKNOWN;
    xmpTag.value = "";
}

static void InitTestXMPTag(XMPTag &xmpTag, XMPTagType tagType, std::string tagName, std::string tagValue = "")
{
    ResetXMPTag(xmpTag);
    if (tagType == XMPTagType::SIMPLE) {
        xmpTag.value = tagValue;
    }

    if (tagType == XMPTagType::QUALIFIER) {
        xmpTag.xmlns = NS_XML;
        xmpTag.prefix = PF_XML;
        xmpTag.value = tagValue;
    } else {
        xmpTag.xmlns = NS_DC;
        xmpTag.prefix = PF_DC;
    }
    xmpTag.type = tagType;
    xmpTag.name = tagName;
}

static void GetLastTag(XMPMetadata &xmpMetadata, std::string &path, XMPTag &lastTag,
    std::vector<XMPTag> &xmpTagVec)
{
    XMPTag parentTag;
    std::string lastTagPath;
    xmpMetadata.GetTag(path, parentTag);

    switch (parentTag.type) {
        case XMPTagType::UNORDERED_ARRAY:
        case XMPTagType::ORDERED_ARRAY:
        case XMPTagType::ALTERNATE_ARRAY:
            lastTagPath = path + "[last()]";
            xmpMetadata.GetTag(lastTagPath, lastTag);
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

static Media::XMPMetadata::EnumerateCallback InitTestCallback(std::vector<XMPTag> &xmpTagVec,
    XMPMetadata &xmpMetadata, std::string &parentPath)
{
    Media::XMPMetadata::EnumerateCallback callback =
        [&xmpTagVec, &xmpMetadata, &parentPath](const std::string &path, const XMPTag &tag) -> bool {
            GTEST_LOG_(INFO) <<
                "name: " << tag.name << ", type: " << static_cast<int>(tag.type) << ", value: " << tag.value << " in.";
            bool isTagFound = false;
            for(const XMPTag &it : xmpTagVec) {
                if (CompareXMPTagNoLog(it, tag)) {
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

            XMPTag lastTag;
            GetLastTag(xmpMetadata, parentPath, lastTag, xmpTagVec);

            if (CompareXMPTagNoLog(tag, lastTag)) {
                return false;
            }
            return true;
        };
    return callback;
}

static void InitTestChildTagsPart1(XMPMetadata &xmpMetadata, std::vector<XMPTag> &xmpTagVec)
{
    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "unorderedArray", "first");
    bool ret = xmpMetadata.SetTag("dc:unorderedArray[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::UNORDERED_ARRAY, "unorderedArray");
    ret = xmpMetadata.SetTag("dc:unorderedArray[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "unorderedArray", "firstChild");
    ret = xmpMetadata.SetTag("dc:unorderedArray[2][1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "unorderedArray", "secondChild");
    ret = xmpMetadata.SetTag("dc:unorderedArray[2][2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "orderedArray", "first");
    ret = xmpMetadata.SetTag("dc:orderedArray[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "orderedArray", "second");
    ret = xmpMetadata.SetTag("dc:orderedArray[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "alternateArray", "first");
    ret = xmpMetadata.SetTag("dc:alternateArray[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "alternateArray", "second");
    ret = xmpMetadata.SetTag("dc:alternateArray[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);
}

static void InitTestChildTagsPart2(XMPMetadata &xmpMetadata, std::vector<XMPTag> &xmpTagVec)
{
    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "title", "Default Title");
    bool ret = xmpMetadata.SetTag("dc:title[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "title", "中文标题");
    ret = xmpMetadata.SetTag("dc:title[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::QUALIFIER, "lang", "x-default");
    ret = xmpMetadata.SetTag("dc:title[1]/@xml:lang", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::QUALIFIER, "lang", "zh-CN");
    ret = xmpMetadata.SetTag("dc:title[2]/@xml:lang", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "first", "first");
    ret = xmpMetadata.SetTag("dc:structure/dc:first", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "second", "second");
    ret = xmpMetadata.SetTag("dc:structure/dc:second", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::QUALIFIER, "first", "first");
    ret = xmpMetadata.SetTag("dc:simple/?xml:first", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    InitTestXMPTag(childTag, XMPTagType::QUALIFIER, "second", "second");
    ret = xmpMetadata.SetTag("dc:simple/?xml:second", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);
}

static void InitTestXMPMetadataForEnumerate(XMPMetadata &xmpMetadata, std::vector<XMPTag> &xmpTagVec)
{
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "unorderedArray");
    bool ret = xmpMetadata.SetTag("dc:unorderedArray", baseTag);
    EXPECT_TRUE(ret);

    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "orderedArray");
    ret = xmpMetadata.SetTag("dc:orderedArray", baseTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(baseTag);

    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "alternateArray");
    ret = xmpMetadata.SetTag("dc:alternateArray", baseTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(baseTag);

    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_TEXT, "title");
    ret = xmpMetadata.SetTag("dc:title", baseTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(baseTag);

    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "structure");
    ret = xmpMetadata.SetTag("dc:structure", baseTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(baseTag);

    InitTestXMPTag(baseTag, XMPTagType::SIMPLE, "simple", "simple");
    ret = xmpMetadata.SetTag("dc:simple", baseTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(baseTag);

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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::ALTERNATE_TEXT;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest005 end";
}

/**
 * @tc.name: SetTagTest006
 * @tc.desc: test the SetTag method when the type of tag is structure.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest006 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.type = XMPTagType::STRUCTURE;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest006 end";
}

/**
 * @tc.name: SetTagTest007
 * @tc.desc: test the SetTag method when the type of tag is unordered array with value.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetTagTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetTagTest007 start";
    XMPMetadata xmpMetadata;
    XMPTag tag;
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest007";
    tag.type = XMPTagType::UNORDERED_ARRAY;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_FALSE(ret);
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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest001_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest002_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest003_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest004_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest005_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest006_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest007_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest008_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    GTEST_LOG_(INFO) << "XmpMetadataTest: GetTagTest008 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest009_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest010_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest011_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest012_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest013_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest014_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest015_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest016_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest017_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest018_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest019_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest020_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest021_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third","XmpMetadataTest.GetTagTest022_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest023_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest024_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest025_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest026_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest027_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest028_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest029_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest030_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest031_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest032_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest033_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest034_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest035_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest036_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest037_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest038_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest039_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest040_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest040_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest042_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest043_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest044_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest045_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest046_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest047_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest048_value1");

    ret = DoSetTagAndGetTag("dc:first[1]/dc:second/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest049_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest050_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest051_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest051_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest053_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest054_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest055_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest056_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest057_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest057_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest059_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::STRUCTURE;
    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest060_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second[1]/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::UNORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest061_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ORDERED_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest062_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    baseTag.type = XMPTagType::ALTERNATE_ARRAY;
    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third", "XmpMetadataTest.GetTagTest063_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third[1]", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "first");

    XMPTag getTag;
    bool ret = DoSetTagAndGetTag("dc:first", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "second";
    ret = DoSetTagAndGetTag("dc:first/dc:second", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    baseTag.name = "third";
    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third", baseTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(baseTag, getTag));

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child", "XmpMetadataTest.GetTagTest064_value1");

    ret = DoSetTagAndGetTag("dc:first/dc:second/dc:third/dc:child", childTag, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_TEXT, "title");

    bool ret = xmpMetadata.SetTag("dc:title", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "title", "Default Title");
    ret = xmpMetadata.SetTag("dc:title[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "title", "中文标题");
    ret = xmpMetadata.SetTag("dc:title[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    XMPTag qualTag_1;
    InitTestXMPTag(qualTag_1, XMPTagType::QUALIFIER, "lang", "x-default");
    ret = DoSetTagAndGetTag("dc:title[1]/@xml:lang", qualTag_1, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(qualTag_1, getTag));

    XMPTag qualTag_2;
    InitTestXMPTag(qualTag_2, XMPTagType::QUALIFIER, "lang", "zh-CN");
    ret = DoSetTagAndGetTag("dc:title[2]/@xml:lang", qualTag_2, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(qualTag_2, getTag));

    ret = xmpMetadata.GetTag("dc:title[@xml:lang='x-default']", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_1, getTag));

    ret = xmpMetadata.GetTag("dc:title[@xml:lang='zh-CN']", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_2, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_TEXT, "title");

    bool ret = xmpMetadata.SetTag("dc:title", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "title", "Default Title");
    ret = xmpMetadata.SetTag("dc:title[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "title", "中文标题");
    ret = xmpMetadata.SetTag("dc:title[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag qualTag;
    InitTestXMPTag(qualTag, XMPTagType::QUALIFIER, "lang", "x-default");
    ret = xmpMetadata.SetTag("dc:title[1]/?xml:lang", qualTag);
    EXPECT_TRUE(ret);

    qualTag.value = "zh-CN";
    ret = xmpMetadata.SetTag("dc:title[2]/?xml:lang", qualTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:title[?xml:lang='x-default']", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_1, getTag));

    ret = xmpMetadata.GetTag("dc:title[?xml:lang=\"zh-CN\"]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_2, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "subject");

    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_TEXT, "title");
    ret = xmpMetadata.SetTag("dc:subject/dc:title", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "title", "Default Title");
    ret = xmpMetadata.SetTag("dc:subject/dc:title[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "title", "中文标题");
    ret = xmpMetadata.SetTag("dc:subject/dc:title[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag qualTag;
    InitTestXMPTag(qualTag, XMPTagType::QUALIFIER, "lang", "x-default");
    ret = xmpMetadata.SetTag("dc:subject/dc:title[1]/?xml:lang", qualTag);
    EXPECT_TRUE(ret);

    qualTag.value = "zh-CN";
    ret = xmpMetadata.SetTag("dc:subject/dc:title[2]/?xml:lang", qualTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject/dc:title[?xml:lang='x-default']", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_1, getTag));

    ret = xmpMetadata.GetTag("dc:subject/dc:title[?xml:lang=\"zh-CN\"]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_2, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "subject");

    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "child1", "childTag_1");
    ret = xmpMetadata.SetTag("dc:subject/dc:child1", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "child2", "childTag_2");
    ret = xmpMetadata.SetTag("dc:subject/dc:child2", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag qualTag1;
    InitTestXMPTag(qualTag1, XMPTagType::QUALIFIER, "age", "25");
    ret = xmpMetadata.SetTag("dc:subject/dc:child1/?xml:age", qualTag1);
    EXPECT_TRUE(ret);

    XMPTag qualTag2;
    InitTestXMPTag(qualTag2, XMPTagType::QUALIFIER, "age", "30");
    ret = xmpMetadata.SetTag("dc:subject/dc:child2/?xml:age", qualTag2);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject/dc:child1/?xml:age", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(qualTag1, getTag));

    ret = xmpMetadata.GetTag("dc:subject/dc:child2/?xml:age", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(qualTag2, getTag));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "subject");

    bool ret = xmpMetadata.SetTag("dc:subject", baseTag);
    EXPECT_TRUE(ret);

    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_TEXT, "title");
    ret = xmpMetadata.SetTag("dc:subject[1]/dc:title", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "title", "Default Title");
    ret = xmpMetadata.SetTag("dc:subject[1]/dc:title[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "title", "中文标题");
    ret = xmpMetadata.SetTag("dc:subject[1]/dc:title[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag qualTag;
    InitTestXMPTag(qualTag, XMPTagType::QUALIFIER, "lang", "x-default");
    ret = xmpMetadata.SetTag("dc:subject[1]/dc:title[1]/@xml:lang", qualTag);
    EXPECT_TRUE(ret);

    qualTag.value = "zh-CN";
    ret = xmpMetadata.SetTag("dc:subject[1]/dc:title[2]/@xml:lang", qualTag);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:subject[1]/dc:title[@xml:lang='x-default']", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_1, getTag));

    ret = xmpMetadata.GetTag("dc:subject[1]/dc:title[@xml:lang=\"zh-CN\"]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(childTag_2, getTag));

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
    std::vector<XMPTag> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

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
    std::vector<XMPTag> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:unorderedArray";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

    parentPath = "dc:orderedArray";
    callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

    parentPath = "dc:alternateArray";
    callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

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
    std::vector<XMPTag> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:structure";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

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
    std::vector<XMPTag> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:alternateText";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

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
    std::vector<XMPTag> xmpTagVec;
    XMPEnumerateOption options;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    parentPath = "dc:simple";
    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

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
    std::vector<XMPTag> xmpTagVec;
    XMPEnumerateOption options;
    options.isRecursive = true;

    InitTestXMPMetadataForEnumerate(xmpMetadata, xmpTagVec);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    xmpMetadata.EnumerateTags(callback, parentPath, options);

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

    uint8_t buffer[XMP_BLOB_DATA_SIZE] = { 0 };
    ret = xmpMetadata.GetBlob(sizeof(buffer), buffer);
    EXPECT_EQ(ret, SUCCESS);

    std::string str(reinterpret_cast<char*>(buffer), strlen(reinterpret_cast<char*>(buffer)));
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest001 str is " << str;
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

    uint8_t buffer[XMP_BLOB_DATA_SIZE] = { 0 };
    ret = xmpMetadata.GetBlob(sizeof(buffer), buffer);
    EXPECT_EQ(ret, SUCCESS);

    std::string str(reinterpret_cast<char*>(buffer), strlen(reinterpret_cast<char*>(buffer)));
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest002 str is " << str;
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest002 end";
}

/**
 * @tc.name: SetGetBlobTest003
 * @tc.desc: test the SetBlob and GetBlob method when the buffer size is smaller than the source size.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, SetGetBlobTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest003 start";
    XMPMetadata xmpMetadata;
    uint32_t ret = xmpMetadata.SetBlob(XMP_BLOB_DATA, sizeof(XMP_BLOB_DATA));
    EXPECT_EQ(ret, SUCCESS);

    uint8_t buffer[XMP_BLOB_SMALL_SIZE] = { 0 };
    ret = xmpMetadata.GetBlob(sizeof(buffer), buffer);
    EXPECT_EQ(ret, ERR_IMAGE_INVALID_PARAMETER);
    GTEST_LOG_(INFO) << "XmpMetadataTest: SetGetBlobTest003 end";
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
    EXPECT_EQ(XMPHelper::ExtractProperty(path1), "dc:title");

    // Case 2: Nested path with Array Index and Localization Text Selector
    std::string path2 = "dc:subject[1]/dc:title[@xml:lang='x-default']";
    EXPECT_EQ(XMPHelper::ExtractProperty(path2), "dc:title");

    // Case 3: Nested path with Structure Field
    std::string path3 = "exif:Flash/exif:Fired";
    EXPECT_EQ(XMPHelper::ExtractProperty(path3), "exif:Fired");

    // Case 4: Deep nested path
    std::string path4 = "dc:first[1]/dc:second[1]/dc:third[1]";
    EXPECT_EQ(XMPHelper::ExtractProperty(path4), "dc:third");

    // Case 5: Nested Qualifier (Selector)
    std::string path5 = "dc:description/dc:title[?book:lastUpdated='2023']";
    EXPECT_EQ(XMPHelper::ExtractProperty(path5), "dc:title");

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

    EXPECT_EQ(XMPHelper::ExtractProperty("["), "");
    EXPECT_EQ(XMPHelper::ExtractProperty("]"), "]");

    path = "testpath]";
    EXPECT_EQ(XMPHelper::ExtractProperty(path), path);

    path = "dc:title[invalid path";
    EXPECT_EQ(XMPHelper::ExtractProperty(path), "dc:title");

    path = "prop/?; rm -rf /";
    EXPECT_EQ(XMPHelper::ExtractProperty("prop/?; rm -rf /"), "; rm -rf /");

    GTEST_LOG_(INFO) << "XmpMetadataTest: ExtractPropertyTest002 end";
}

/**
 * @tc.name: CreateXMPTagTest001
 * @tc.desc: test the CreateXMPTag method when tag is simple .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CreateXMPTagTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest001 start";
    XMPMetadata xmpMetadata;
    std::string tagPath = "dc:parent";
    std::string value = "test value";
    XMPTag outTag;

    bool ret = xmpMetadata.CreateXMPTag(tagPath, XMPTagType::SIMPLE, value, outTag);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest001 end";
}

/**
 * @tc.name: CreateXMPTagTest002
 * @tc.desc: test the CreateXMPTag method when tag is unordered array .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CreateXMPTagTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest002 start";
    XMPMetadata xmpMetadata;
    std::string tagPath = "dc:parent";
    std::string value = "";
    XMPTag outTag;

    bool ret = xmpMetadata.CreateXMPTag(tagPath, XMPTagType::UNORDERED_ARRAY, value, outTag);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest002 end";
}

/**
 * @tc.name: CreateXMPTagTest003
 * @tc.desc: test the CreateXMPTag method when tag is ordered array .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CreateXMPTagTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest003 start";
    XMPMetadata xmpMetadata;
    std::string tagPath = "dc:parent";
    std::string value = "";
    XMPTag outTag;

    bool ret = xmpMetadata.CreateXMPTag(tagPath, XMPTagType::ORDERED_ARRAY, value, outTag);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest003 end";
}

/**
 * @tc.name: CreateXMPTagTest004
 * @tc.desc: test the CreateXMPTag method when tag is alternate array .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CreateXMPTagTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest004 start";
    XMPMetadata xmpMetadata;
    std::string tagPath = "dc:parent";
    std::string value = "";
    XMPTag outTag;

    bool ret = xmpMetadata.CreateXMPTag(tagPath, XMPTagType::ALTERNATE_ARRAY, value, outTag);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest004 end";
}

/**
 * @tc.name: CreateXMPTagTest005
 * @tc.desc: test the CreateXMPTag method when tag is alternate array .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CreateXMPTagTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest005 start";
    XMPMetadata xmpMetadata;
    std::string tagPath = "dc:parent";
    std::string value = "";
    XMPTag outTag;

    bool ret = xmpMetadata.CreateXMPTag(tagPath, XMPTagType::ALTERNATE_TEXT, value, outTag);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest005 end";
}

/**
 * @tc.name: CreateXMPTagTest006
 * @tc.desc: test the CreateXMPTag method when tag is alternate array .
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CreateXMPTagTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest006 start";
    XMPMetadata xmpMetadata;
    std::string tagPath = "dc:parent";
    std::string value = "";
    XMPTag outTag;

    bool ret = xmpMetadata.CreateXMPTag(tagPath, XMPTagType::STRUCTURE, value, outTag);
    EXPECT_TRUE(ret);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CreateXMPTagTest006 end";
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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag("dc:parent", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "parent", "first");
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "parent", "second");
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag childTag_3;
    InitTestXMPTag(childTag_3, XMPTagType::SIMPLE, "parent", "third");
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag_3);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.RemoveTag("dc:parent[1]");
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:parent[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(getTag, childTag_2));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag("dc:parent", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "parent", "first");
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "parent", "second");
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag childTag_3;
    InitTestXMPTag(childTag_3, XMPTagType::SIMPLE, "parent", "third");
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag_3);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.RemoveTag("dc:parent[1]");
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:parent[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(getTag, childTag_2));

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
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag("dc:parent", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag_1;
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "parent", "first");
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "parent", "second");
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag childTag_3;
    InitTestXMPTag(childTag_3, XMPTagType::SIMPLE, "parent", "third");
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag_3);
    EXPECT_TRUE(ret);

    ret = xmpMetadata.RemoveTag("dc:parent[1]");
    EXPECT_TRUE(ret);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:parent[1]", getTag);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(getTag, childTag_2));

    GTEST_LOG_(INFO) << "XmpMetadataTest: RemoveTagTest003 end";
}
} // namespace Multimedia
} // namespace OHOS
