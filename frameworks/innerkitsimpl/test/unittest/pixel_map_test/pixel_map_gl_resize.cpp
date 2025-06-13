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
#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <chrono>
#include <thread>
#include "image_source.h"
#include "image_type.h"
#include "image_utils.h"
#include "image_system_properties.h"
#include "media_errors.h"
#include "pixel_map.h"
#include "pixel_convert_adapter.h"
#include "post_proc.h"
#include "pixel_map_program_manager.h"
#include "basic_transformer.h"
#include "image_log.h"
#include "memory_manager.h"
 
using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Multimedia {
const int32_t NUM_512 = 512;
const uint32_t ANGLE90 = 90;
const uint32_t ANGLE0 = 0;
const uint32_t ANGLE180 = 180;
const uint32_t ANGLE183 = 183;
const int32_t NUM_2 = 2;
const int32_t NUM_4 = 4;
static void GetPixelMapInfo(PixelMap &source, Size &size, GLenum &glFormat, int &perPixelSize)
{
    size = {
        .width = source.GetWidth(),
        .height = source.GetHeight(),
    };
    glFormat = GL_RGBA;
    perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::RGBA_8888);
    PixelFormat originFormat = source.GetPixelFormat();
    switch (originFormat) {
        case PixelFormat::RGBA_8888:
            glFormat = GL_RGBA;
            break;
        case PixelFormat::RGB_565:
            glFormat = GL_RGB565;
            perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::RGB_565);
            break;
        case PixelFormat::RGB_888:
            glFormat = GL_RGB;
            perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::RGB_888);
            break;
        case PixelFormat::BGRA_8888:
            glFormat = GL_BGRA_EXT;
            break;
        case PixelFormat::ALPHA_8:
            glFormat = GL_ALPHA8_EXT;
            perPixelSize = ImageUtils::GetPixelBytes(PixelFormat::ALPHA_8);
            break;
        default:
            IMAGE_LOGE("slr_gpu %{public}s format %{public}d is not support! ", __func__, originFormat);
            break;
    }
}

static bool PixelMapPostProcWithGL(PixelMap &sourcePixelMap, GPUTransformData &trans)
{
    Size &desiredSize = trans.targetInfo_.size;
    Size sourceSize;
    GLenum glFormat = GL_RGBA;
    int perPixelSize = ImageUtils::GetPixelBytes(sourcePixelMap.GetPixelFormat());
    GetPixelMapInfo(sourcePixelMap, sourceSize, glFormat, perPixelSize);
    AllocatorType allocType = sourcePixelMap.GetAllocatorType();
    size_t buffersize = static_cast<size_t>(4 * desiredSize.width * desiredSize.height); // 4: 4 bytes per pixel
    MemoryData memoryData = {nullptr, buffersize, "PixelMapPostProcWithGL", desiredSize};
    std::unique_ptr<AbsMemory> dstMemory = MemoryManager::CreateMemory(allocType, memoryData);
    if (dstMemory == nullptr || dstMemory->data.data == nullptr) {
        return false;
    }
    int outputStride = 4 * desiredSize.width;
    if (allocType == AllocatorType::DMA_ALLOC) {
        SurfaceBuffer* sbBuffer = reinterpret_cast<SurfaceBuffer*>(dstMemory->extend.data);
        outputStride = sbBuffer->GetStride();
        buffersize = static_cast<uint32_t>(sbBuffer->GetStride() * desiredSize.height);
    }
    PixelMapProgramManager::BuildShader();
    bool ret = true;
    auto program = PixelMapProgramManager::GetInstance().GetProgram();
    if (program == nullptr) {
        ret = false;
    } else {
        trans.targetInfo_.stride = outputStride;
        trans.targetInfo_.pixelBytes = perPixelSize;
        trans.targetInfo_.outdata = dstMemory->data.data;
        trans.targetInfo_.context = dstMemory->extend.data;
        trans.glFormat = glFormat;
        trans.isDma = allocType == AllocatorType::DMA_ALLOC ? true : false;
        program->SetGPUTransformData(trans);
        ret = PixelMapProgramManager::GetInstance().ExecutProgram(program);
    }
    if (!ret) {
        dstMemory->Release();
        return false;
    }
    sourcePixelMap.SetPixelsAddr(dstMemory->data.data, dstMemory->extend.data,
        desiredSize.height * outputStride, allocType, nullptr);
    ImageInfo info;
    info.size = desiredSize;
    info.pixelFormat = PixelFormat::RGBA_8888;
    info.alphaType = AlphaType::IMAGE_ALPHA_TYPE_UNPREMUL;
    sourcePixelMap.SetImageInfo(info, true);
    return true;
}

bool RotateInRectangularSteps(PixelMap &pixelMap, float degrees)
{
    IMAGE_LOGI("slr_gpu RotateInRectangularSteps in :%{public}f", degrees);
    GPUTransformData gpuTransform;
    ImageInfo imageInfo;
    pixelMap.GetImageInfo(imageInfo);
    GlCommon::Mat4 tmpMat4;
    std::array<float, 3> axis = { 0.0f, 0.0f, 1.0f }; // capacity 3
    float angle = degrees * M_PI / 180.f; // degrees 180
    gpuTransform.targetInfo_.size = {
        std::abs(imageInfo.size.width * std::cos(angle)) + std::abs(imageInfo.size.height * std::sin(angle)),
        std::abs(imageInfo.size.height * std::cos(angle)) + std::abs(imageInfo.size.width * std::sin(angle))
    };
    degrees = std::fmod(degrees, 360.f); // degrees 360
    degrees = std::fmod(360.f - degrees, 360.f); // degrees 360
    gpuTransform.rotateTrans = GlCommon::Mat4(tmpMat4, degrees, axis);
    gpuTransform.rotateDegreeZ = degrees;
    gpuTransform.sourceInfo_ = {
        .size = imageInfo.size,
        .stride = pixelMap.GetRowStride(),
        .pixelBytes = ImageUtils::GetPixelBytes(pixelMap.GetPixelFormat()),
        .addr = pixelMap.GetPixels(),
        .context = pixelMap.GetFd(),
    };
    gpuTransform.transformationType = TransformationType::ROTATE;
    if (PixelMapPostProcWithGL(pixelMap, gpuTransform)) {
        IMAGE_LOGI("slr_gpu RotateInRectangularSteps success");
        return true;
    }
    return false;
}

bool ScalePixelMapWithGPU(PixelMap &pixelMap, const Size &desiredSize)
{
    if (!ImageSystemProperties::GetGenThumbWithGpu()) {
        PostProc postProc;
        return postProc.ScalePixelMapEx(desiredSize, pixelMap, option);
    }

    IMAGE_LOGI("slr_gpu ScalePixelMapWithGPU:wh(%{public}d,%{public}d)->(%{public}d,%{public}d)",
        pixelMap.GetWidth(), pixelMap.GetHeight(), desiredSize.width, desiredSize.height);
    GPUTransformData gpuTransform;
    gpuTransform.targetInfo_.size = desiredSize;
    ImageInfo imageInfo;
    pixelMap.GetImageInfo(imageInfo);
    gpuTransform.sourceInfo_ = {
        .size = imageInfo.size,
        .stride = pixelMap.GetRowStride(),
        .pixelBytes = ImageUtils::GetPixelBytes(pixelMap.GetPixelFormat()),
        .addr = pixelMap.GetPixels(),
        .context = pixelMap.GetFd(),
    };
    gpuTransform.transformationType = TransformationType::SCALE;
    if (PixelMapPostProcWithGL(pixelMap, gpuTransform)) {
        IMAGE_LOGI("slr_gpu ScalePixelMapWithGPU success");
        return true;
    }
    return false;
}

class PixelMapTest : public testing::Test {
public:
    PixelMapTest() {}
    ~PixelMapTest() {}
};
/**
 * @tc.name: gl_resize001
 * @tc.desc: Scale Dma PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, gl_resize001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: gl_resize001 start";
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_512;
    options.size.height = NUM_512;
    options.srcPixelFormat = PixelFormat::RGBA_8888;
    options.pixelFormat = PixelFormat::RGBA_8888;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    options.useDMA = true;
    int32_t width = options.size.width;
    std::map<PixelFormat, std::string>::iterator iter;
    // ARGB_8888 to others
    options.srcPixelFormat = PixelFormat::ARGB_8888;
    uint32_t colorLength = NUM_512 * NUM_512 * NUM_4;    // w:2 * h:3 * pixelByte:4
    uint8_t buffer[NUM_512 * NUM_512 * NUM_4] = { 0 };    // w:2 * h:3 * pixelByte:4
    for (int i = 0; i < colorLength; i += NUM_4) {
        buffer[i] = 0x78;
        buffer[i + 1] = 0x83;
        buffer[i + 2] = 0xDF;
        buffer[i + 3] = 0x52;
    }
    uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
    options.pixelFormat = PixelFormat::RGBA_8888;
    
    std::unique_ptr<PixelMap> pixelMap = nullptr;
    pixelMap = PixelMap::Create(color, colorLength, offset, width, options);
    EXPECT_NE(nullptr, pixelMap);
    EXPECT_EQ(ScalePixelMapWithGPU(*(pixelMap.get()),
        {pixelMap->GetWidth() * NUM_2, pixelMap->GetHeight() * NUM_2}), true);
    EXPECT_EQ(ScalePixelMapWithGPU(*(pixelMap.get()),
        {pixelMap->GetWidth() / NUM_2, pixelMap->GetHeight() / NUM_2}), true);

    EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE90), true);
    EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE180), true);
    EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE183), true);
    EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE0), true);
    GTEST_LOG_(INFO) << "PixelMapTest: gl_resize001 end";
}

/**
 * @tc.name: gl_resize002
 * @tc.desc: Scale Ashmem PixelMap
 * @tc.type: FUNC
 */
HWTEST_F(PixelMapTest, gl_resize002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "PixelMapTest: gl_resize002 start";
    const int32_t offset = 0;
    InitializationOptions options;
    options.size.width = NUM_512;
    options.size.height = NUM_512;
    options.srcPixelFormat = PixelFormat::RGBA_8888;
    options.pixelFormat = PixelFormat::RGBA_8888;
    options.alphaType = AlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    int32_t width = options.size.width;
    for (int p = 0; p < 6; p++) {
        uint32_t colorLength = NUM_512 * NUM_512 * NUM_4;    // w:2 * h:3 * pixelByte:4
        uint8_t buffer[NUM_512 * NUM_512 * NUM_4] = { 0 };    // w:2 * h:3 * pixelByte:4
        for (int i = 0; i < colorLength; i += NUM_4) {
            buffer[i] = 0x78;
            buffer[i + 1] = 0x83;
            buffer[i + 2] = 0xDF;
            buffer[i + 3] = 0x52;
        }
        uint32_t *color = reinterpret_cast<uint32_t *>(buffer);
        options.pixelFormat = PixelFormat(p);
        std::unique_ptr<PixelMap> pixelMap = nullptr;
        pixelMap = PixelMap::Create(color, colorLength, offset, width, options);
        if (pixelMap == nullptr) {
            continue;
        }
        if (pixelMap->GetPixelFormat() == PixelFormat::RGBA_8888) {
            EXPECT_EQ(ScalePixelMapWithGPU(*(pixelMap.get()),
                {pixelMap->GetWidth() * NUM_2, pixelMap->GetHeight() * NUM_2}), true);
            EXPECT_EQ(ScalePixelMapWithGPU(*(pixelMap.get()),
                {pixelMap->GetWidth() / NUM_2, pixelMap->GetHeight() / NUM_2}), true);
            EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE90), true);
            EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE180), true);
            EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE183), true);
            EXPECT_EQ(RotateInRectangularSteps(*(pixelMap.get()), ANGLE0), true);
        } else {
            ScalePixelMapWithGPU(*(pixelMap.get()),
               {pixelMap->GetWidth() * NUM_2, pixelMap->GetHeight() * NUM_2});
            ScalePixelMapWithGPU(*(pixelMap.get()),
               {pixelMap->GetWidth() / NUM_2, pixelMap->GetHeight() / NUM_2});
            RotateInRectangularSteps(*(pixelMap.get()), ANGLE90);
            RotateInRectangularSteps(*(pixelMap.get()), ANGLE180);
            RotateInRectangularSteps(*(pixelMap.get()), ANGLE183);
            RotateInRectangularSteps(*(pixelMap.get()), ANGLE0);
        }
    }
    GTEST_LOG_(INFO) << "PixelMapTest: gl_resize002 end";
}

}
}
