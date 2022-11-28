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
#include <fstream>
#include <dirent.h>
#include <iostream>
#include <sys/stat.h>
#include "hilog/log.h"
#include "log_tags.h"
#include "unistd.h"
#include "directory_ex.h"

using namespace testing::ext;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Multimedia {
class MockDirectoryExTest : public testing::Test {
public:
    MockDirectoryExTest() {}
    ~MockDirectoryExTest() {}
};

/**
 * @tc.name: ExtractFilePath001
 * @tc.desc: test ExtractFilePath
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, ExtractFilePath001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ExtractFilePath001 start";
    const string fileFullName = "a";
    string expath = ExtractFilePath(fileFullName);
    ASSERT_EQ(expath, "");
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ExtractFilePath001 end";
}

/**
 * @tc.name: ExtractFileName001
 * @tc.desc: test ExtractFileName
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, ExtractFileName001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ExtractFileName001 start";
    const std::string fileFullName = "a";
    string exfile = ExtractFileName(fileFullName);
    ASSERT_EQ(exfile, "a");
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ExtractFileName001 end";
}

/**
 * @tc.name: ForceCreateDirectory001
 * @tc.desc: test ForceCreateDirectory
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, ForceCreateDirectory001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ForceCreateDirectory001 start";
    const string path = "a";
    bool ex = ForceCreateDirectory(path);
    ASSERT_EQ(ex, true);
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ForceCreateDirectory001 end";
}

/**
 * @tc.name: ExtractFileExt001
 * @tc.desc: test ExtractFileExt
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, ExtractFileExt001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ExtractFileExt001 start";
    const string fileName = "a";
    string exFile = ExtractFilePath(fileName);
    ASSERT_EQ(exFile, "");
    GTEST_LOG_(INFO) << "MockDirectoryExTest: ExtractFileExt001 end";
}

/**
 * @tc.name: IncludeTrailingPathDelimiter001
 * @tc.desc: test IncludeTrailingPathDelimiter
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, IncludeTrailingPathDelimiter001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: IncludeTrailingPathDelimiter001 start";
    const std::string path = "";
    string includetra = IncludeTrailingPathDelimiter(path);
    ASSERT_EQ(includetra, "");
    GTEST_LOG_(INFO) << "MockDirectoryExTest: IncludeTrailingPathDelimiter001 end";
}

/**
 * @tc.name: GetDirFiles001
 * @tc.desc: test GetDirFiles
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, GetDirFiles001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: GetDirFiles001 start";
    const string canonicalPath = "a";
    vector<string> strFiles;
    GetDirFiles(canonicalPath, strFiles);
    GTEST_LOG_(INFO) << "MockDirectoryExTest: GetDirFiles001 end";
}

/**
 * @tc.name: PathToRealPath001
 * @tc.desc: test PathToRealPath
 * @tc.type: FUNC
 */
HWTEST_F(MockDirectoryExTest, PathToRealPath001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockDirectoryExTest: PathToRealPath001 start";
    const string path = "a";
    string realPath = "";
    bool ptr = PathToRealPath(path, realPath);
    ASSERT_EQ(ptr, true);
    GTEST_LOG_(INFO) << "MockDirectoryExTest: PathToRealPath001 end";
}
} // namespace Multimedia
} // namespace OHOS