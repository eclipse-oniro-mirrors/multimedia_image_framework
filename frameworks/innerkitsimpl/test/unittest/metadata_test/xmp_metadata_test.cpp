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
    std::string namespaceURI = "http://ns.adobe.com/xap/1.0/";
    std::string preferredPrefix = "xap";
    std::string registeredPrefix;
    bool ret = xmpMetadata.RegisterNamespacePrefix(namespaceURI, preferredPrefix, registeredPrefix);
    EXPECT_TRUE(ret);
    EXPECT_EQ(registeredPrefix, preferredPrefix);
    GTEST_LOG_(INFO) << "XmpMetadataTest: RegisterNamespacePrefixTest001 end";
}

} // namespace Multimedia
} // namespace OHOS
