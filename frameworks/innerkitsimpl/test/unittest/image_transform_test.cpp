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
#include "basic_transformer.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
class ImageTransformTest : public testing::Test {
public:
    ImageTransformTest() {}
    ~ImageTransformTest() {}
};

/*
|255,255,0,0  0,0,0,0  255,0,255,0|
|0,0,0,0      0,0,0,0  0,0,0,0|
|0,0,0,0      0,0,0,0  0,0,0,0|
|255,0,0,255  0,0,0,0  255,163,213,234|
 */
void ConstructPixmapInfo(PixmapInfo &pixmapInfo)
{
    pixmapInfo.imageInfo.size.width = 3;
    pixmapInfo.imageInfo.size.height = 4;
    pixmapInfo.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    pixmapInfo.imageInfo.colorSpace = ColorSpace::SRGB;
    int32_t width = 3;
    int32_t height = 4;
    pixmapInfo.data = new uint8_t[width * height * 4];

    if (pixmapInfo.data == nullptr) {
        return;
    }
    pixmapInfo.bufferSize = width * height * 4;
    if (memset_s(pixmapInfo.data, sizeof(width * height * 4), 0, sizeof(width * height * 4)) != EOK) {
        ASSERT_NE(*pixmapInfo.data, 0);
    }
    for (int32_t i = 0; i < width * height; ++i) {
        int rb = i * 4;
        // the 0th item set red
        if (i == 0) {
            *(pixmapInfo.data + rb) = 255;
            *(pixmapInfo.data + rb + 1) = 255;
        }
        // the 2th item set green
        if (i == 2) {
            *(pixmapInfo.data + rb) = 255;
            *(pixmapInfo.data + rb + 2) = 255;
        }

        // the 9th item set blue
        if (i == 9) {
            *(pixmapInfo.data + rb) = 255;
            *(pixmapInfo.data + rb + 3) = 255;
        }

        // the 11th item rand
        if (i == 11) {
            *(pixmapInfo.data + rb) = 255;
            *(pixmapInfo.data + rb + 1) = 163;
            *(pixmapInfo.data + rb + 2) = 213;
            *(pixmapInfo.data + rb + 3) = 234;
        }
    }
}

/**
 * @tc.name: ImageTransformTest001
 * @tc.desc: the pixmap info scale 2.0f.
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform001_Scale2 start";

    PixmapInfo inPutInfo;
    ConstructPixmapInfo(inPutInfo);

    /**
     * @tc.steps: step1. construct pixel map info.
     * @tc.expected: step1. expect the pixel map width and height.
     */
    PixmapInfo outPutInfo(inPutInfo);
    BasicTransformer trans;
    trans.SetScaleParam(2.0f, 2.0f);
    trans.TransformPixmap(inPutInfo, outPutInfo);

    ASSERT_NE(outPutInfo.data, nullptr);
    EXPECT_EQ(outPutInfo.imageInfo.size.width, 6);
    EXPECT_EQ(outPutInfo.imageInfo.size.height, 8);
    EXPECT_EQ(outPutInfo.bufferSize, (uint32_t)(6 * 8 * 4));

    /**
     * @tc.steps: step2. scale 2 times.
     * @tc.expected: step2. expect four corner values.
     */
    for (int32_t i = 0; i < 6 * 8; ++i) {
        int rb = i * 4;
        // after scale 2.0, the 0th item change to 0th item
        if (i == 0) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 1)), 255);
        }

        // after scale 2.0, the 2th item change to 5th item
        if (i == 5) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 2)), 255);
        }

        // after scale 2.0, the 9th item change to 42th item
        if (i == 42) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 3)), 255);
        }

        // after scale 2.0, the 11th item change to 47th item
        if (i == 47) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 1)), 163);
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 2)), 213);
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 3)), 234);
        }
    }
    if (inPutInfo.data != nullptr) {
        free(inPutInfo.data);
        inPutInfo.data = nullptr;
    }
    if (outPutInfo.data != nullptr) {
        free(outPutInfo.data);
        outPutInfo.data = nullptr;
    }
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform001_Scale2 end";
}

/**
 * @tc.name: ImageTransformTest002
 * @tc.desc: the pixmap info rotate 90 at the center point.
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform002_Rotate90 start";

    PixmapInfo inPutInfo;
    ConstructPixmapInfo(inPutInfo);

    /**
     * @tc.steps: step1. construct pixel map info.
     * @tc.expected: step1. expect the pixel map width and height.
     */
    PixmapInfo outPutInfo(inPutInfo);
    BasicTransformer trans;
    trans.SetRotateParam(90, (float)(inPutInfo.imageInfo.size.width / 2), (float)(inPutInfo.imageInfo.size.height / 2));
    trans.TransformPixmap(inPutInfo, outPutInfo);

    ASSERT_NE(outPutInfo.data, nullptr);
    EXPECT_EQ(outPutInfo.imageInfo.size.width, 4);
    EXPECT_EQ(outPutInfo.imageInfo.size.height, 3);
    EXPECT_EQ(outPutInfo.bufferSize, (uint32_t)(4 * 3 * 4));

    /**
     * @tc.steps: step2. rotate 90.
     * @tc.expected: step2. expect four corner values.
     */
    for (int32_t i = 0; i < 4 * 3; ++i) {
        int rb = i * 4;
        // after rotate 90, the 0th change to 9th
        if (i == 0) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 3)), 255);
        }

        // after rotate 90, the 3th item change to 0th item
        if (i == 3) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 1)), 255);
        }

        // after rotate 90, the 11th item change to 2th item
        if (i == 11) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 2)), 255);
        }
    }
    if (inPutInfo.data != nullptr) {
        free(inPutInfo.data);
        inPutInfo.data = nullptr;
    }
    if (outPutInfo.data != nullptr) {
        free(outPutInfo.data);
        outPutInfo.data = nullptr;
    }
    GTEST_LOG_(INFO) << "ImageTransforTest: ImageTransfor002_Rotate90 end";
}

/**
 * @tc.name: ImageTransformTest003
 * @tc.desc: the pixmap info rotate 180 at the center point.
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform003_Rotate180 start";

    /**
     * @tc.steps: step1. construct pixel map info.
     * @tc.expected: step1. expect the pixel map width and height.
     */
    PixmapInfo inPutInfo;
    ConstructPixmapInfo(inPutInfo);

    PixmapInfo outPutInfo(inPutInfo);
    BasicTransformer trans;
    trans.SetRotateParam(180, (float)(inPutInfo.imageInfo.size.width / 2),
                         (float)(inPutInfo.imageInfo.size.height / 2));
    trans.TransformPixmap(inPutInfo, outPutInfo);

    ASSERT_NE(outPutInfo.data, nullptr);
    EXPECT_EQ(outPutInfo.imageInfo.size.width, 3);
    EXPECT_EQ(outPutInfo.imageInfo.size.height, 4);
    EXPECT_EQ(outPutInfo.bufferSize, (uint32_t)(3 * 4 * 4));

    /**
     * @tc.steps: step2. rotate 180.
     * @tc.expected: step2. expect four corner values.
     */
    for (int32_t i = 0; i < 3 * 4; ++i) {
        int rb = i * 4;
        // after rotate 180, the 0th change to 11th
        if (i == 0) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 1)), 163);
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 2)), 213);
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 3)), 234);
        }

        // after rotate 180, the 2th item change to 9th item
        if (i == 2) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 3)), 255);
        }

        // after rotate 180, the 9th item change to 2th item
        if (i == 9) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 2)), 255);
        }

        // after rotate 180, the 11th item change to 0th item
        if (i == 11) {
            EXPECT_EQ((int32_t)(*(outPutInfo.data + rb + 1)), 255);
        }
    }
    if (inPutInfo.data != nullptr) {
        free(inPutInfo.data);
        inPutInfo.data = nullptr;
    }
    if (outPutInfo.data != nullptr) {
        free(outPutInfo.data);
        outPutInfo.data = nullptr;
    }
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform003_Rotate180 end";
}

/**
 * @tc.name: ImageTransformTest004
 * @tc.desc:ResetParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform004 start";
    BasicTransformer trans;
    trans.ResetParam();
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform004 end";
}

/**
 * @tc.name: ImageTransformTest005
 * @tc.desc:SetTranslateParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform005 start";
    BasicTransformer trans;
    float sx = 0.5;
    float sy = 0.5;
    trans.SetTranslateParam(sx, sy);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform005 end";
}

/**
 * @tc.name: ImageTransformTest006
 * @tc.desc:SetTranslateParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest006, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform006 start";
    BasicTransformer trans;
    float sx = -1;
    float sy = 0.5;
    trans.SetTranslateParam(sx, sy);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform006 end";
}

/**
 * @tc.name: ImageTransformTest007
 * @tc.desc:SetTranslateParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest007, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform007 start";
    BasicTransformer trans;
    float sx = 1;
    float sy = -1;
    trans.SetTranslateParam(sx, sy);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform007 end";
}

/**
 * @tc.name: ImageTransformTest008
 * @tc.desc:SetTranslateParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest008, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform008 start";
    BasicTransformer trans;
    float sx = -1;
    float sy = 0.5;
    trans.SetTranslateParam(sx, sy);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform008 end";
}

/**
 * @tc.name: ImageTransformTest009
 * @tc.desc:SetTranslateParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest009, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform009 start";
    BasicTransformer trans;
    float sx = -1;
    float sy = -1;
    trans.SetTranslateParam(sx, sy);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform009 end";
}

/**
 * @tc.name: ImageTransformTest0010
 * @tc.desc:GetDstDimension
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0010, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0010 start";
    BasicTransformer trans;
    PixmapInfo inPutInfo;
    ConstructPixmapInfo(inPutInfo);
    Size dstSize = inPutInfo.imageInfo.size;
    trans.GetDstDimension(inPutInfo.imageInfo.size, dstSize);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0010 end";
}

/**
 * @tc.name: ImageTransformTest0011
 * @tc.desc:SetScaleParam
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0011, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0011 start";
    BasicTransformer trans;
    trans.SetScaleParam(2.0f, 2.0f);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0011 end";
}

/**
 * @tc.name: ImageTransformTest0012
 * @tc.desc:TransformPixmap pixelBytes is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0012, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0012 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::UNKNOWN;
    inPutInfo.imageInfo.size.width = 3;
    inPutInfo.imageInfo.size.height = 4;
    inPutInfo.imageInfo.colorSpace = ColorSpace::SRGB;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    BasicTransformer trans;
    uint32_t res = trans.TransformPixmap(inPutInfo, outPutInfo);
    ASSERT_EQ(res, ERR_IMAGE_INVALID_PIXEL);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0012 end";
}

/**
 * @tc.name: ImageTransformTest0013
 * @tc.desc:TransformPixmap
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0013, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0013 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 0;
    inPutInfo.imageInfo.size.height = 0;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    BasicTransformer trans;
    uint32_t res = trans.TransformPixmap(inPutInfo, outPutInfo);
    ASSERT_EQ(res, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0013 end";
}

/**
 * @tc.name: ImageTransformTest0014
 * @tc.desc:TransformPixmap inPutInfo.imageInfo.size.height is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0014, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0014 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 1;
    inPutInfo.imageInfo.size.height = 0;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    BasicTransformer trans;
    uint32_t res = trans.TransformPixmap(inPutInfo, outPutInfo);
    ASSERT_EQ(res, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0014 end";
}

/**
 * @tc.name: ImageTransformTest0015
 * @tc.desc:TransformPixmap inPutInfo.imageInfo.size.width is 0
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0015, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0015 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 0;
    inPutInfo.imageInfo.size.height = 1;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    BasicTransformer trans;
    uint32_t res = trans.TransformPixmap(inPutInfo, outPutInfo);
    ASSERT_EQ(res, ERR_IMAGE_ALLOC_MEMORY_FAILED);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0015 end";
}

/**
 * @tc.name: ImageTransformTest0016
 * @tc.desc:TransformPixmap bufferSize > PIXEL_MAP_MAX_RAM_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0016, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0016 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 1024 * 100;
    inPutInfo.imageInfo.size.height = 1024 * 10;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    PixmapInfo outPutInfo;
    ASSERT_EQ(outPutInfo.data, nullptr);
    BasicTransformer trans;
    trans.TransformPixmap(inPutInfo, outPutInfo);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0016 end";
}

/**
 * @tc.name: ImageTransformTest0017
 * @tc.desc:TransformPixmap
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0017, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0017 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 3;
    inPutInfo.imageInfo.size.height = 4;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::ARGB_8888;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    ASSERT_EQ(outPutInfo.data, nullptr);
    BasicTransformer trans;
    trans.TransformPixmap(inPutInfo, outPutInfo);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0017 end";
}

/**
 * @tc.name: ImageTransformTest0018
 * @tc.desc:TransformPixmap RGB_888
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0018, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0018 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 3;
    inPutInfo.imageInfo.size.height = 4;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::RGB_888;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    outPutInfo.imageInfo.size.width = 3;
    outPutInfo.imageInfo.size.height = 4;
    outPutInfo.imageInfo.pixelFormat = PixelFormat::RGB_888;

    BasicTransformer trans;
    trans.TransformPixmap(inPutInfo, outPutInfo);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0018 end";
}

/**
 * @tc.name: ImageTransformTest0019
 * @tc.desc:TransformPixmap ALPHA_8
 * @tc.type: FUNC
 */
HWTEST_F(ImageTransformTest, ImageTransformTest0019, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0019 start";
    PixmapInfo inPutInfo;
    inPutInfo.imageInfo.size.width = 3;
    inPutInfo.imageInfo.size.height = 4;
    inPutInfo.imageInfo.pixelFormat = PixelFormat::ALPHA_8;
    int32_t width = 3;
    int32_t height = 4;
    inPutInfo.data = new uint8_t[width * height * 4];
    PixmapInfo outPutInfo;
    outPutInfo.imageInfo.size.width = 3;
    outPutInfo.imageInfo.size.height = 4;
    outPutInfo.imageInfo.pixelFormat = PixelFormat::ALPHA_8;

    BasicTransformer trans;
    trans.TransformPixmap(inPutInfo, outPutInfo);
    GTEST_LOG_(INFO) << "ImageTransformTest: ImageTransform0019 end";
}
} // namespace Multimedia
} // namespace OHOS
