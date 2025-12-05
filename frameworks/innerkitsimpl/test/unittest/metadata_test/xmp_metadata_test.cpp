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

namespace {
    constexpr const int32_t XMP_ARRAY_COUNT_ONE = 1;
    constexpr const int32_t XMP_ARRAY_COUNT_TWO = 2;
    constexpr const int32_t XMP_ARRAY_COUNT_THREE = 3;
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

static void InitTestXMPTag(XMPTag &xmpTag, XMPTagType XMPTagType, std::string tagName)
{
    if (XMPTagType == XMPTagType::QUALIFIER) {
        xmpTag.xmlns = NS_XML;
        xmpTag.prefix = PF_XML;
    } else {
        xmpTag.xmlns = NS_DC;
        xmpTag.prefix = PF_DC;
    }
    xmpTag.type = XMPTagType;
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
            bool isTagFound = false;
            for(const XMPTag &it : xmpTagVec) {
                if (CompareXMPTagNoLog(it, tag)) {
                    isTagFound = true;
                    break;
                }
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
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
    tag.xmlns = NS_XMP_BASIC;
    tag.prefix = PF_XMP_BASIC;
    tag.name = "CreatorTool";
    tag.value = "XmpMetadataTest.SetTagTest007";
    tag.type = XMPTagType::STRUCTURE;
    bool ret = xmpMetadata.SetTag("xmp:CreatorTool", tag);
    EXPECT_TRUE(ret);
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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest001_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest002_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest003_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest004_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest005_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest006_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest007_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest008_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest009_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest010_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest011_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest012_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest013_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest014_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest015_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest016_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest017_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest018_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest019_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest020_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest021_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest022_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest023_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest024_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest025_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest026_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest027_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest028_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest029_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest030_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest031_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest032_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest033_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest034_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest035_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest036_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest037_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest038_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest039_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest040_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest040_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest042_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest043_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest044_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest045_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest046_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest047_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest048_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest049_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest050_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest051_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest051_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest053_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest054_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest055_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest056_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest057_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest057_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest059_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest060_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest061_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest062_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "third");
    childTag.value = "XmpMetadataTest.GetTagTest063_value1";

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
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "child");
    childTag.value = "XmpMetadataTest.GetTagTest064_value1";

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
    InitTestXMPTag(childTag_1, XMPTagType::SIMPLE, "title");
    childTag_1.value = "Default Title";
    ret = xmpMetadata.SetTag("dc:title[1]", childTag_1);
    EXPECT_TRUE(ret);

    XMPTag childTag_2;
    InitTestXMPTag(childTag_2, XMPTagType::SIMPLE, "title");
    childTag_2.value = "中文标题";
    ret = xmpMetadata.SetTag("dc:title[2]", childTag_2);
    EXPECT_TRUE(ret);

    XMPTag getTag;
    XMPTag qualTag_1;
    InitTestXMPTag(qualTag_1, XMPTagType::QUALIFIER, "lang");
    qualTag_1.value = "x-default";
    ret = DoSetTagAndGetTag("dc:title[1]/@xml:lang", qualTag_1, getTag, xmpMetadata);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(CompareXMPTag(qualTag_1, getTag));

    XMPTag qualTag_2;
    InitTestXMPTag(qualTag_2, XMPTagType::QUALIFIER, "lang");
    qualTag_2.value = "zh-CN";
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
 * @tc.name: CountArrayItems001
 * @tc.desc: test the CountArrayItems method when some items in unordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CountArrayItems001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CountArrayItems001 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag("dc:parent", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "parent");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag);
    EXPECT_TRUE(ret);

    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag);
    EXPECT_TRUE(ret);

    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag);
    EXPECT_TRUE(ret);

    int32_t count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_THREE);

    xmpMetadata.RemoveTag("dc:parent[2]");
    count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_TWO);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:parent[2]", getTag);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

    xmpMetadata.RemoveTag("dc:parent[2]");
    count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_ONE);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CountArrayItems001 end";
}

/**
 * @tc.name: CountArrayItems002
 * @tc.desc: test the CountArrayItems method when some items in ordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CountArrayItems002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CountArrayItems002 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag("dc:parent", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "parent");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag);
    EXPECT_TRUE(ret);

    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag);
    EXPECT_TRUE(ret);

    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag);
    EXPECT_TRUE(ret);

    int32_t count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_THREE);

    xmpMetadata.RemoveTag("dc:parent[2]");
    count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_TWO);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:parent[2]", getTag);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

    xmpMetadata.RemoveTag("dc:parent[2]");
    count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_ONE);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CountArrayItems002 end";
}

/**
 * @tc.name: CountArrayItems003
 * @tc.desc: test the CountArrayItems method when some items in alternate array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, CountArrayItems003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: CountArrayItems003 start";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag("dc:parent", baseTag);
    EXPECT_TRUE(ret);

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "parent");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag);
    EXPECT_TRUE(ret);

    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag);
    EXPECT_TRUE(ret);

    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag);
    EXPECT_TRUE(ret);

    int32_t count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_THREE);

    xmpMetadata.RemoveTag("dc:parent[2]");
    count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_TWO);

    XMPTag getTag;
    ret = xmpMetadata.GetTag("dc:parent[2]", getTag);
    EXPECT_TRUE(CompareXMPTag(childTag, getTag));

    xmpMetadata.RemoveTag("dc:parent[2]");
    count = xmpMetadata.CountArrayItems("dc:parent");
    EXPECT_EQ(count, XMP_ARRAY_COUNT_ONE);

    GTEST_LOG_(INFO) << "XmpMetadataTest: CountArrayItems003 end";
}

/**
 * @tc.name: EnumerateTags001
 * @tc.desc: test the EnumerateTags method when some items in unordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags001 start";
    std::string parentPath = "dc:parent";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::UNORDERED_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag(parentPath, baseTag);
    EXPECT_TRUE(ret);

    std::vector<XMPTag> xmpTagVec;

    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "parent");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    XMPEnumerateOption options;
    xmpMetadata.EnumerateTags(callback, parentPath, options);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags001 end";
}

/**
 * @tc.name: EnumerateTags002
 * @tc.desc: test the EnumerateTags method when some items in ordered array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags002 start";
    std::string parentPath = "dc:parent";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ORDERED_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag(parentPath, baseTag);
    EXPECT_TRUE(ret);

    std::vector<XMPTag> xmpTagVec;
    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "parent");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    XMPEnumerateOption options;
    xmpMetadata.EnumerateTags(callback, parentPath, options);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags002 end";
}

/**
 * @tc.name: EnumerateTags003
 * @tc.desc: test the EnumerateTags method when some items in alternate array.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags003 start";
    std::string parentPath = "dc:parent";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::ALTERNATE_ARRAY, "parent");
    bool ret = xmpMetadata.SetTag(parentPath, baseTag);
    EXPECT_TRUE(ret);

    std::vector<XMPTag> xmpTagVec;
    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "parent");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent[1]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent[2]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent[3]", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    XMPEnumerateOption options;
    xmpMetadata.EnumerateTags(callback, parentPath, options);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags003 end";
}

/**
 * @tc.name: EnumerateTags004
 * @tc.desc: test the EnumerateTags method when some items in structure.
 * @tc.type: FUNC
 */
HWTEST_F(XmpMetadataTest, EnumerateTags004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags004 start";
    std::string parentPath = "dc:parent";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::STRUCTURE, "parent");
    bool ret = xmpMetadata.SetTag(parentPath, baseTag);
    EXPECT_TRUE(ret);

    std::vector<XMPTag> xmpTagVec;
    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::SIMPLE, "first");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent/dc:first", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.name = "second";
    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent/dc:second", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.name = "third";
    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent/dc:third", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    XMPEnumerateOption options;
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
    std::string parentPath = "dc:parent";
    XMPMetadata xmpMetadata;
    XMPTag baseTag;
    InitTestXMPTag(baseTag, XMPTagType::SIMPLE, "parent");
    bool ret = xmpMetadata.SetTag(parentPath, baseTag);
    EXPECT_TRUE(ret);

    std::vector<XMPTag> xmpTagVec;
    XMPTag childTag;
    InitTestXMPTag(childTag, XMPTagType::QUALIFIER, "first");
    childTag.value = "first";
    ret = xmpMetadata.SetTag("dc:parent/?xml:first", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.name = "second";
    childTag.value = "second";
    ret = xmpMetadata.SetTag("dc:parent/?xml:second", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    childTag.name = "third";
    childTag.value = "third";
    ret = xmpMetadata.SetTag("dc:parent/?xml:third", childTag);
    EXPECT_TRUE(ret);
    xmpTagVec.push_back(childTag);

    Media::XMPMetadata::EnumerateCallback callback = InitTestCallback(xmpTagVec, xmpMetadata, parentPath);
    XMPEnumerateOption options;
    xmpMetadata.EnumerateTags(callback, parentPath, options);

    GTEST_LOG_(INFO) << "XmpMetadataTest: EnumerateTags005 end";
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
} // namespace Multimedia
} // namespace OHOS
