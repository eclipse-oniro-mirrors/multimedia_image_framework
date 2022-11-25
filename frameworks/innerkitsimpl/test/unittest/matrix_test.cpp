/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "image_type.h"
#include "matrix.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class MatrixTest : public testing::Test {
public:
    MatrixTest() {}
    ~MatrixTest() {}
};

/**
 * @tc.name: MatrixTest001
 * @tc.desc: SetTranslate
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest001 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 1;
    matrix_.SetTranslate(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest001 end";
}

/**
 * @tc.name: MatrixTest002
 * @tc.desc: SetTranslate
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest002 start";
    Matrix matrix_;
    float tx = 0;
    float ty = 1;
    matrix_.SetTranslate(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest002 end";
}

/**
 * @tc.name: MatrixTest003
 * @tc.desc: SetTranslate
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest003 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 0;
    matrix_.SetTranslate(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest003 end";
}

/**
 * @tc.name: MatrixTest004
 * @tc.desc: SetScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest004 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 1;
    matrix_.SetScale(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest004 end";
}

/**
 * @tc.name: MatrixTest005
 * @tc.desc: SetScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest005 start";
    Matrix matrix_;
    float tx = 0;
    float ty = 1;
    matrix_.SetScale(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest005 end";
}

/**
 * @tc.name: MatrixTest006
 * @tc.desc: SetScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest006 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 0;
    matrix_.SetScale(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest006 end";
}

/**
 * @tc.name: MatrixTest007
 * @tc.desc: SetScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest007 start";
    Matrix matrix_;
    float tx = 0.5;
    float ty = 1;
    matrix_.SetScale(tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest007 end";
}

/**
 * @tc.name: MatrixTest008
 * @tc.desc: SetRotate
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest007 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 1;
    float degrees = 90;
    matrix_.SetRotate(degrees, tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest008 end";
}

/**
 * @tc.name: MatrixTest009
 * @tc.desc: SetRotate
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest009 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 1;
    float degrees = 180;
    matrix_.SetRotate(degrees, tx, ty);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest009 end";
}

/**
 * @tc.name: MatrixTest0010
 * @tc.desc: SetSinCos
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0010 start";
    Matrix matrix_;
    float px = 1;
    float py = 1;
    float sinValue = 1;
    float cosValue = 0;
    matrix_.SetSinCos(sinValue, cosValue, px, py);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0010 end";
}

/**
 * @tc.name: MatrixTest0011
 * @tc.desc: SetConcat
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0011 start";
    Matrix matrix_;
    Matrix m;
    matrix_.SetConcat(m);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0011 end";
}

/**
 * @tc.name: MatrixTest0012
 * @tc.desc: SetTranslateAndScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0012 start";
    Matrix matrix_;
    float tx = 0;
    float ty = 0;
    float sx = 1;
    float sy = 1;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0012 end";
}

/**
 * @tc.name: MatrixTest0013
 * @tc.desc: SetTranslateAndScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0013 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 0;
    float sx = 1;
    float sy = 1;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0013 end";
}

/**
 * @tc.name: MatrixTest0014
 * @tc.desc: SetTranslateAndScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0014 start";
    Matrix matrix_;
    float tx = 0;
    float ty = 0;
    float sx = 0;
    float sy = 1;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0014 end";
}

/**
 * @tc.name: MatrixTest0015
 * @tc.desc: SetTranslateAndScale
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0015 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 1;
    float sx = 0;
    float sy = 0;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0015 end";
}

/**
 * @tc.name: MatrixTest0016
 * @tc.desc: Invert
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0016 start";
    Matrix matrix_;
    Matrix m;
    bool ret = matrix_.Invert(m);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0016 end";
}

/**
 * @tc.name: MatrixTest0017
 * @tc.desc: InvertForRotate
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0017 start";
    Matrix matrix_;
    Matrix m;
    bool ret = matrix_.InvertForRotate(m);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0017 end";
}

/**
 * @tc.name: MatrixTest0018
 * @tc.desc: IdentityXY
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0018 start";
    Matrix matrix_;
    Matrix m;
    float sx = 1;
    float sy = 1;
    Point pt;
    pt.x = 1;
    pt.y = 1;
    matrix_.IdentityXY(m, sx, sy, pt);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0018 end";
}

/**
 * @tc.name: MatrixTest0019
 * @tc.desc: ScaleXY
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0019 start";
    Matrix matrix_;
    Matrix m;
    float sx = 1;
    float sy = 1;
    Point pt;
    pt.x = 1;
    pt.y = 1;
    matrix_.ScaleXY(m, sx, sy, pt);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0019 end";
}

/**
 * @tc.name: MatrixTest0020
 * @tc.desc: TransXY
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0020, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0020 start";
    Matrix matrix_;
    Matrix m;
    float tx = 1;
    float ty = 1;
    Point pt;
    pt.x = 1;
    pt.y = 1;
    matrix_.TransXY(m, tx, ty, pt);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0020 end";
}

/**
 * @tc.name: MatrixTest0021
 * @tc.desc: RotXY
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0021, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0021 start";
    Matrix matrix_;
    Matrix m;
    float rx = 1;
    float ry = 1;
    Point pt;
    pt.x = 1;
    pt.y = 1;
    matrix_.RotXY(m, rx, ry, pt);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0021 end";
}

/**
 * @tc.name: MatrixTest0022
 * @tc.desc: Print
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0022, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0022 start";
    Matrix matrix_;
    matrix_.Print();
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0022 end";
}

/**
 * @tc.name: MatrixTest0023
 * @tc.desc: IdentityXY OperType is not 0
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0023, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0023 start";
    Matrix matrix_;
    Matrix m;
    float tx = 1;
    float ty = 1;
    m.SetTranslate(tx, ty);
    ASSERT_NE(m.GetOperType(), 0);

    float sx = 1;
    float sy = 1;
    Point pt;
    pt.x = 1;
    pt.y = 1;
    matrix_.IdentityXY(m, sx, sy, pt);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0023 end";
}

/**
 * @tc.name: MatrixTest0024
 * @tc.desc: Invert sx is 1e-7
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0024, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0024 start";
    Matrix matrix_;
    Matrix m;
    float tx = 0;
    float ty = 0;
    float sx = 1e-7;
    float sy = 1;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    bool ret = m.Invert(matrix_);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0024 end";
}

/**
 * @tc.name: MatrixTest0025
 * @tc.desc: Invert sy is 1e-7
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0025, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0025 start";
    Matrix matrix_;
    Matrix m;
    float tx = 0;
    float ty = 0;
    float sx = 1;
    float sy = 1e-7;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    bool ret = m.Invert(matrix_);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0025 end";
}

/**
 * @tc.name: MatrixTest0026
 * @tc.desc: InvertForRotate invDet is 0
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0026, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0026 start";
    Matrix matrix_;
    Matrix m;
    float tx = 0;
    float ty = 0;
    float sx = -1;
    float sy = 1;
    matrix_.SetTranslateAndScale(tx, ty, sx, sy);
    bool ret = m.InvertForRotate(matrix_);
    ASSERT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0026 end";
}

/**
 * @tc.name: MatrixTest0027
 * @tc.desc: SetConcat
 * @tc.type: FUNC
 */
HWTEST_F(MatrixTest, MatrixTest0027, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0027 start";
    Matrix matrix_;
    float tx = 1;
    float ty = 1;
    matrix_.SetTranslate(tx, ty);
    ASSERT_EQ(matrix_.GetOperType(), Matrix::OperType::TRANSLATE);
    Matrix m;
    matrix_.SetConcat(m);
    GTEST_LOG_(INFO) << "MatrixTest: MatrixTest0027 end";
}
}
}