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
#include "refbase.h"

using namespace testing::ext;
namespace OHOS {
namespace Multimedia {
class MockRefbaseTest : public testing::Test {
public:
    MockRefbaseTest() {}
    ~MockRefbaseTest() {}
};
RefCounter *refs_ = nullptr;
/**
 * @tc.name: GetRefPtr001
 * @tc.desc: test GetRefPtr
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetRefPtr001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetRefPtr001 start";
    RefCounter *base = nullptr;
    void *cookie = nullptr;
    WeakRefCounter ref(base, cookie);
    ref.GetRefPtr();
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetRefPtr001 end";
}

/**
 * @tc.name: DecWeakRefCount001
 * @tc.desc: test DecWeakRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, DecWeakRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecWeakRefCount001 start";
    const void *objectId = nullptr;
    RefCounter *base = nullptr;
    void *cookie = nullptr;
    WeakRefCounter ref(base, cookie);
    ref.DecWeakRefCount(objectId);
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecWeakRefCount001 end";
}

/**
 * @tc.name: GetRefCount001
 * @tc.desc: test GetRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetRefCount001 start";
    RefCounter refs;
    int getref = refs.GetRefCount();
    ASSERT_EQ(getref, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetRefCount001 end";
}

/**
 * @tc.name: IncRefCount001
 * @tc.desc: test IncRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IncRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IncRefCount001 start";
    RefCounter refs;
    refs.IncRefCount();
    GTEST_LOG_(INFO) << "MockRefbaseTest: IncRefCount001 end";
}

/**
 * @tc.name: DecRefCount001
 * @tc.desc: test DecRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, DecRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecRefCount001 start";
    RefCounter refs;
    refs.DecRefCount();
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecRefCount001 end";
}

/**
 * @tc.name: SetCallback001
 * @tc.desc: test SetCallback
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, SetCallback001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: SetCallback001 start";
    RefCounter refs;
    const RefCounter::RefPtrCallback callback = nullptr;
    refs.SetCallback(callback);
    GTEST_LOG_(INFO) << "MockRefbaseTest: SetCallback001 end";
}

/**
 * @tc.name: RemoveCallback001
 * @tc.desc: test RemoveCallback
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, RemoveCallback001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: RemoveCallback001 start";
    RefCounter refs;
    refs.RemoveCallback();
    GTEST_LOG_(INFO) << "MockRefbaseTest: RemoveCallback001 end";
}

/**
 * @tc.name: IsRefPtrValid001
 * @tc.desc: test IsRefPtrValid
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IsRefPtrValid001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsRefPtrValid001 start";
    RefCounter refs;
    bool isref = refs.IsRefPtrValid();
    ASSERT_EQ(isref, false);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsRefPtrValid001 end";
}

/**
 * @tc.name: GetStrongRefCount001
 * @tc.desc: test GetStrongRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetStrongRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetStrongRefCount001 start";
    RefCounter refs;
    int getstref = refs.GetStrongRefCount();
    ASSERT_NE(getstref, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetStrongRefCount001 end";
}

/**
 * @tc.name: GetWeakRefCount001
 * @tc.desc: test GetWeakRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetWeakRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetWeakRefCount001 start";
    RefCounter refs;
    int getweakref = refs.GetWeakRefCount();
    ASSERT_EQ(getweakref, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetWeakRefCount001 end";
}

/**
 * @tc.name: SetAttemptAcquire002
 * @tc.desc: test SetAttemptAcquire
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, SetAttemptAcquire002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: SetAttemptAcquire002 start";
    RefCounter refs;
    refs.SetAttemptAcquire();
    GTEST_LOG_(INFO) << "MockRefbaseTest: SetAttemptAcquire002 end";
}

/**
 * @tc.name: IsAttemptAcquireSet001
 * @tc.desc: test IsAttemptAcquireSet
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IsAttemptAcquireSet001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsAttemptAcquireSet001 start";
    RefCounter refs;
    bool isattemp = refs.IsAttemptAcquireSet();
    ASSERT_EQ(isattemp, false);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsAttemptAcquireSet001 end";
}

/**
 * @tc.name: ClearAttemptAcquire001
 * @tc.desc: test ClearAttemptAcquire
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, ClearAttemptAcquire001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: ClearAttemptAcquire001 start";
    RefCounter refs;
    refs.ClearAttemptAcquire();
    GTEST_LOG_(INFO) << "MockRefbaseTest: ClearAttemptAcquire001 end";
}

/**
 * @tc.name: ExtendObjectLifetime001
 * @tc.desc: test ExtendObjectLifetime
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, ExtendObjectLifetime001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: ExtendObjectLifetime001 start";
    RefCounter refs;
    refs.ExtendObjectLifetime();
    GTEST_LOG_(INFO) << "MockRefbaseTest: ExtendObjectLifetime001 end";
}

/**
 * @tc.name: IsLifeTimeExtended001
 * @tc.desc: test IsLifeTimeExtended
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IsLifeTimeExtended001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsLifeTimeExtended001 start";
    RefCounter refs;
    bool islife = refs.IsLifeTimeExtended();
    ASSERT_EQ(islife, false);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsLifeTimeExtended001 end";
}

/**
 * @tc.name: AttemptIncStrongRef002
 * @tc.desc: test AttemptIncStrongRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, AttemptIncStrongRef002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: AttemptIncStrongRef002 start";
    const void *objectId;
    int outCount = 0;
    RefCounter refs;
    bool attempis = refs.AttemptIncStrongRef(objectId, outCount);
    ASSERT_EQ(attempis, true);
    GTEST_LOG_(INFO) << "MockRefbaseTest: AttemptIncStrongRef002 end";
}

/**
 * @tc.name: ExtendObjectLifetime002
 * @tc.desc: test ExtendObjectLifetime
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, ExtendObjectLifetime002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: ExtendObjectLifetime002 start";
    RefBase refb;
    refb.ExtendObjectLifetime();
    GTEST_LOG_(INFO) << "MockRefbaseTest: ExtendObjectLifetime002 end";
}

/**
 * @tc.name: IncStrongRef001
 * @tc.desc: test IncStrongRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IncStrongRef001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IncStrongRef001 start";
    const void *objectId;
    RefBase refb;
    refb.IncStrongRef(objectId);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IncStrongRef001 end";
}

/**
 * @tc.name: DecStrongRef001
 * @tc.desc: test DecStrongRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, DecStrongRef001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecStrongRef001 start";
    const void *objectId;
    RefBase refb;
    refb.DecStrongRef(objectId);
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecStrongRef001 end";
}

/**
 * @tc.name: GetSptrRefCount001
 * @tc.desc: test GetSptrRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetSptrRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetSptrRefCount001 start";
    RefBase refb;
    int getref = refb.GetSptrRefCount();
    ASSERT_NE(getref, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetSptrRefCount001 end";
}

/**
 * @tc.name: GetSptrRefCount002
 * @tc.desc: test GetSptrRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetSptrRefCount002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetSptrRefCount002 start";
    RefBase refb;
    int getref = refb.GetSptrRefCount();
    ASSERT_NE(getref, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetSptrRefCount002 end";
}

/**
 * @tc.name: CreateWeakRef001
 * @tc.desc: test CreateWeakRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, CreateWeakRef001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: CreateWeakRef001 start";
    void *cookie = nullptr;
    RefBase refb;
    WeakRefCounter *createwk = refb.CreateWeakRef(cookie);
    ASSERT_NE(createwk, nullptr);
    GTEST_LOG_(INFO) << "MockRefbaseTest: CreateWeakRef001 end";
}

/**
 * @tc.name: CreateWeakRef002
 * @tc.desc: test CreateWeakRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, CreateWeakRef002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: CreateWeakRef002 start";
    void *cookie = nullptr;
    RefBase refb;
    WeakRefCounter *createwk = refb.CreateWeakRef(cookie);
    ASSERT_NE(createwk, nullptr);
    GTEST_LOG_(INFO) << "MockRefbaseTest: CreateWeakRef002 end";
}

/**
 * @tc.name: IncWeakRef001
 * @tc.desc: test IncWeakRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IncWeakRef001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IncWeakRef001 start";
    const void *objectId;
    RefBase refb;
    refb.IncWeakRef(objectId);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IncWeakRef001 end";
}

/**
 * @tc.name: DecWeakRef001
 * @tc.desc: test DecWeakRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, DecWeakRef001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecWeakRef001 start";
    const void *objectId;
    RefBase refb;
    refb.DecWeakRef(objectId);
    GTEST_LOG_(INFO) << "MockRefbaseTest: DecWeakRef001 end";
}

/**
 * @tc.name: GetWptrRefCount001
 * @tc.desc: test GetWptrRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetWptrRefCount001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetWptrRefCount001 start";
    RefBase refb;
    int getwp = refb.GetWptrRefCount();
    ASSERT_EQ(getwp, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetWptrRefCount001 end";
}

/**
 * @tc.name: GetWptrRefCount002
 * @tc.desc: test GetWptrRefCount
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, GetWptrRefCount002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetWptrRefCount002 start";
    RefBase refb;
    int getwp = refb.GetWptrRefCount();
    ASSERT_EQ(getwp, 0);
    GTEST_LOG_(INFO) << "MockRefbaseTest: GetWptrRefCount002 end";
}

/**
 * @tc.name: AttemptAcquire001
 * @tc.desc: test AttemptAcquire
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, AttemptAcquire001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: AttemptAcquire001 start";
    const void *objectId;
    RefBase refb;
    bool attemp = refb.AttemptAcquire(objectId);
    ASSERT_EQ(attemp, true);
    GTEST_LOG_(INFO) << "MockRefbaseTest: AttemptAcquire001 end";
}

/**
 * @tc.name: AttemptIncStrongRef003
 * @tc.desc: test AttemptIncStrongRef
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, AttemptIncStrongRef003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: AttemptIncStrongRef003 start";
    const void *objectId;
    RefBase refb;
    bool attemp = refb.AttemptIncStrongRef(objectId);
    ASSERT_EQ(attemp, true);
    GTEST_LOG_(INFO) << "MockRefbaseTest: AttemptIncStrongRef003 end";
}

/**
 * @tc.name: IsAttemptAcquireSet002
 * @tc.desc: test IsAttemptAcquireSet
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IsAttemptAcquireSet002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsAttemptAcquireSet002 start";
    RefBase refb;
    bool isattemp = refb.IsAttemptAcquireSet();
    ASSERT_EQ(isattemp, false);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsAttemptAcquireSet002 end";
}

/**
 * @tc.name: IsExtendLifeTimeSet001
 * @tc.desc: test IsExtendLifeTimeSet
 * @tc.type: FUNC
 */
HWTEST_F(MockRefbaseTest, IsExtendLifeTimeSet001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsExtendLifeTimeSet001 start";
    RefBase refb;
    bool isextend = refb.IsExtendLifeTimeSet();
    ASSERT_EQ(isextend, false);
    GTEST_LOG_(INFO) << "MockRefbaseTest: IsExtendLifeTimeSet001 end";
}
} // namespace Multimedia
} // namespace OHOS