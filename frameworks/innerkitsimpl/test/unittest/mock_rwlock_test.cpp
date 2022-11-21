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
#include <cassert>
#include "rwlock.h"

using namespace testing::ext;
using namespace OHOS::Utils;
namespace OHOS {
namespace Multimedia {
class MockRwlockTest : public testing::Test {
public:
    MockRwlockTest() {}
    ~MockRwlockTest() {}
};

/**
 * @tc.name: LockRead001
 * @tc.desc: test LockRead
 * @tc.type: FUNC
 */
HWTEST_F(MockRwlockTest, LockRead001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRwlockTest: LockRead001 start";
    RWLock rw;
    rw.LockRead();
    GTEST_LOG_(INFO) << "MockRwlockTest: LockRead001 end";
}

/**
 * @tc.name: UnLockRead001
 * @tc.desc: test UnLockRead
 * @tc.type: FUNC
 */
HWTEST_F(MockRwlockTest, UnLockRead001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRwlockTest: UnLockRead001 start";
    RWLock rw;
    rw.UnLockRead();
    GTEST_LOG_(INFO) << "MockRwlockTest: UnLockRead001 end";
}

/**
 * @tc.name: LockWrite001
 * @tc.desc: test LockWrite
 * @tc.type: FUNC
 */
HWTEST_F(MockRwlockTest, LockWrite001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRwlockTest: LockWrite001 start";
    RWLock rw;
    rw.LockWrite();
    GTEST_LOG_(INFO) << "MockRwlockTest: LockWrite001 end";
}

/**
 * @tc.name: UnLockWrite001
 * @tc.desc: test UnLockWrite
 * @tc.type: FUNC
 */
HWTEST_F(MockRwlockTest, UnLockWrite001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRwlockTest: UnLockWrite001 start";
    RWLock rw;
    rw.UnLockWrite();
    GTEST_LOG_(INFO) << "MockRwlockTest: UnLockWrite001 end";
}
} // namespace Multimedia
} // namespace OHOS