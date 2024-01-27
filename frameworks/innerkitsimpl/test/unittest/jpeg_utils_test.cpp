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
#include "gtest/gtest.h"
#include "jpeg_utils.h"
#include "buffer_source_stream.h"
#include "image_packer.h"
#include "jpeg_decoder.h"

using namespace testing::ext;
namespace OHOS {
namespace ImagePlugin {
class JpegUtilsTest : public testing::Test {
public:
    JpegUtilsTest() {}
    ~JpegUtilsTest() {}
};

/**
 * @tc.name: FillInputBufferTest001
 * @tc.desc: Test of FillInputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, FillInputBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: FillInputBufferTest001 start";
    j_decompress_ptr dinfo = nullptr;
    boolean ret = ImagePlugin::FillInputBuffer(dinfo);
    EXPECT_EQ(ret, FALSE);
    GTEST_LOG_(INFO) << "JpegUtilsTest: FillInputBufferTest001 end";
}

/**
 * @tc.name: SkipInputDataTest001
 * @tc.desc: Test of SkipInputData
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, SkipInputDataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: SkipInputDataTest001 start";
    j_decompress_ptr dinfo = nullptr;
    long numBytes = 0;
    ImagePlugin::SkipInputData(dinfo, numBytes);
    GTEST_LOG_(INFO) << "JpegUtilsTest: SkipInputDataTest001 end";
}

/**
 * @tc.name: TermSrcStreamTest001
 * @tc.desc: Test of TermSrcStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, TermSrcStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: TermSrcStreamTest001 start";
    j_decompress_ptr dinfo = nullptr;
    ImagePlugin::TermSrcStream(dinfo);
    GTEST_LOG_(INFO) << "JpegUtilsTest: TermSrcStreamTest001 end";
}

/**
 * @tc.name: InitDstStreamTest001
 * @tc.desc: Test of InitDstStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, InitDstStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: InitDstStreamTest001 start";
    j_compress_ptr cinfo = nullptr;
    ImagePlugin::InitDstStream(cinfo);
    GTEST_LOG_(INFO) << "JpegUtilsTest: InitDstStreamTest001 end";
}

/**
 * @tc.name: EmptyOutputBufferTest001
 * @tc.desc: Test of EmptyOutputBuffer
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, EmptyOutputBufferTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: EmptyOutputBufferTest001 start";
    j_compress_ptr cinfo = nullptr;
    boolean ret = ImagePlugin::EmptyOutputBuffer(cinfo);
    ASSERT_EQ(ret, FALSE);
    GTEST_LOG_(INFO) << "JpegUtilsTest: EmptyOutputBufferTest001 end";
}

/**
 * @tc.name: TermDstStreamTest001
 * @tc.desc: Test of TermDstStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, TermDstStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: TermDstStreamTest001 start";
    j_compress_ptr cinfo = nullptr;
    ImagePlugin::TermDstStream(cinfo);
    GTEST_LOG_(INFO) << "JpegUtilsTest: TermDstStreamTest001 end";
}

/**
 * @tc.name: DoubleToStringTest001
 * @tc.desc: Test of DoubleToString
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, DoubleToStringTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: DoubleToStringTest001 start";
    double num = 128;
    std::string result = ImagePlugin::DoubleToString(num);
    EXPECT_EQ(result, "128.000000");
    GTEST_LOG_(INFO) << "JpegUtilsTest: DoubleToStringTest001 end";
}

/**
 * @tc.name: ErrorExitTest001
 * @tc.desc: Test of ErrorExit
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, ErrorExitTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: ErrorExitTest001 start";
    j_common_ptr dinfo = nullptr;
    ImagePlugin::ErrorExit(dinfo);
    EXPECT_EQ(dinfo, nullptr);
    GTEST_LOG_(INFO) << "JpegUtilsTest: ErrorExitTest001 end";
}

/**
 * @tc.name: OutputErrorMessageTest001
 * @tc.desc: Test of OutputErrorMessage
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, OutputErrorMessageTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: OutputErrorMessageTest001 start";
    j_common_ptr dinfo = nullptr;
    ImagePlugin::OutputErrorMessage(dinfo);
    EXPECT_EQ(dinfo, nullptr);
    GTEST_LOG_(INFO) << "JpegUtilsTest: OutputErrorMessageTest001 end";
}

/**
 * @tc.name: InitSrcStreamTest001
 * @tc.desc: Test of InitSrcStream
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, InitSrcStreamTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: InitSrcStreamTest001 start";
    j_decompress_ptr dinfo = nullptr;
    ImagePlugin::InitSrcStream(dinfo);
    EXPECT_EQ(dinfo, nullptr);
    GTEST_LOG_(INFO) << "JpegUtilsTest: InitSrcStreamTest001 end";
}

/**
 * @tc.name: SkipInputDataTest002
 * @tc.desc: Test of SkipInputData
 * @tc.type: FUNC
 */
HWTEST_F(JpegUtilsTest, SkipInputDataTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "JpegUtilsTest: SkipInputDataTest002 start";
    long numBytes = 0;
    j_decompress_ptr dinfo = (j_decompress_ptr)malloc(sizeof(jpeg_decompress_struct));
    dinfo->src = (JpegSrcMgr *)malloc(sizeof(JpegSrcMgr));
    JpegSrcMgr *src = static_cast<JpegSrcMgr *>(dinfo->src);
    src->inputStream = (InputDataStream *)malloc(sizeof(InputDataStream));
    ImagePlugin::SkipInputData(dinfo, numBytes);
    GTEST_LOG_(INFO) << "JpegUtilsTest: SkipInputDataTest002 end";
}
}
}