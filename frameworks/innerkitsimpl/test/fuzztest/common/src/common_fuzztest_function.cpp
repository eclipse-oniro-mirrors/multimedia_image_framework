/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "common_fuzztest_function.h"

#define private public
#define protected public

#include <chrono>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>

#include "pixel_yuv.h"
#include "image_packer.h"
#include "media_errors.h"
#include "image_log.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "COMMON_FUZZTEST_FUNCTION"

static const int FOUR_BYTES_PER_PIXEL = 4;
static const int NUM_TWO = 2;
using namespace OHOS::Media;

int ConvertDataToFd(const uint8_t* data, size_t size, std::string encodeFormat)
{
    if (size < FOUR_BYTES_PER_PIXEL) {
        return -1;
    }
    int picturePixels = size / FOUR_BYTES_PER_PIXEL;
    InitializationOptions opts = {};
    if (picturePixels % NUM_TWO == 0) {
        opts.size.width = picturePixels / NUM_TWO;
        opts.size.height = NUM_TWO;
    } else {
        opts.size.width = picturePixels;
        opts.size.height = 1;
    }
    auto pixelMap = PixelMap::Create(reinterpret_cast<const uint32_t*>(data),
        static_cast<uint32_t>(picturePixels) * FOUR_BYTES_PER_PIXEL, opts);
    if (pixelMap == nullptr) {
        return -1;
    }

    std::string pathName = "/data/local/tmp/testFile_" + GetNowTimeStr() + ".dat";
    IMAGE_LOGI("%{public}s pathName is %{public}s", __func__, pathName.c_str());
    std::remove(pathName.c_str());
    int fd = open(pathName.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return -1;
    }
    ImagePacker packer;
    PackOption option;
    option.format = encodeFormat;
    packer.StartPacking(fd, option);
    packer.AddImage(*(pixelMap.get()));
    uint32_t errorCode = packer.FinalizePacking();
    if (errorCode != SUCCESS) {
        return -1;
    }
    return fd;
}

std::string GetNowTimeStr()
{
    auto now = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());
    return std::to_string(us.count());
}

bool WriteDataToFile(const uint8_t* data, size_t size, const std::string& filename)
{
    IMAGE_LOGI("%{public}s %{public}s IN", __func__, filename.c_str());
    std::ifstream file(filename);
    bool isFileExists = file.good();
    file.close();
    if (isFileExists) {
        std::remove(filename.c_str());
    }
    std::ofstream newFile(filename);
    if (!newFile.is_open()) {
        IMAGE_LOGI("%{public}s failed, new file: %{public}s error", __func__, filename.c_str());
        return false;
    }
    newFile.write(reinterpret_cast<const char*>(data), size);
    newFile.close();
    IMAGE_LOGI("%{public}s %{public}s SUCCESS", __func__, filename.c_str());
    return true;
}

void PixelMapTest001(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    pixelMap->SetTransformered(pixelMap->isTransformered_);
    ImageInfo info;
    pixelMap->GetYUVByteCount(info);
    pixelMap->GetAllocatedByteCount(info);
    InitializationOptions initOpts;
    initOpts.size = {pixelMap->GetWidth(), pixelMap->GetHeight()};
    initOpts.editable = true;
    auto emptyPixelMap = PixelMap::Create(initOpts);
    Rect srcRect;
    int32_t errorCode;
    PixelMap::Create(*(emptyPixelMap.get()), srcRect, initOpts, errorCode);
    pixelMap->resize(1, 1);
    pixelMap->CopyPixelMap(*pixelMap, *(emptyPixelMap.get()));
    PixelFormat fromat = PixelFormat::RGBA_8888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGBA_1010102;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::BGRA_8888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::ARGB_8888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::ALPHA_8;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGB_565;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGB_888;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::NV21;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::YCRCB_P010;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::CMYK;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::RGBA_F16;
    pixelMap->GetPixelFormatDetail(fromat);
    fromat =  PixelFormat::ASTC_4x4;
    pixelMap->GetPixelFormatDetail(fromat);
    pixelMap->GetPixel8(0, 0);
    pixelMap->GetPixel16(0, 0);
    pixelMap->GetPixel32(0, 0);
    pixelMap->GetPixel(0, 0);
    uint32_t color = 0;
    pixelMap->GetARGB32Color(0, 0, color);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PixelMapTest002(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    pixelMap->GetPixelBytes();
    pixelMap->GetRowBytes();
    pixelMap->GetByteCount();
    pixelMap->GetWidth();
    pixelMap->GetHeight();
    TransformData transformData;
    pixelMap->GetTransformData(transformData);
    pixelMap->SetTransformData(transformData);
    pixelMap->GetBaseDensity();
    ImageInfo imageInfo;
    pixelMap->GetImageInfo(imageInfo);
    pixelMap->GetPixelFormat();
    pixelMap->GetColorSpace();
    pixelMap->GetAlphaType();
    pixelMap->GetPixels();
    pixelMap->IsHdr();
    uint32_t color = 0;
    pixelMap->GetARGB32ColorA(color);
    pixelMap->GetARGB32ColorR(color);
    pixelMap->GetARGB32ColorG(color);
    pixelMap->GetARGB32ColorB(color);
    pixelMap->IsStrideAlignment();
    pixelMap->GetAllocatorType();
    pixelMap->GetFd();
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpace(OHOS::ColorManager::ColorSpaceName::SRGB);
    pixelMap->ApplyColorSpace(grColorSpace);
#endif
    pixelMap->ResetConfig(pixelMap->imageInfo_.size, pixelMap->imageInfo_.pixelFormat);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PixelYuvTest001(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (pixelMap == nullptr) {
        IMAGE_LOGE("pixelMap is nullptr");
        return;
    }
    auto pixelYuv = reinterpret_cast<PixelYuv*>(pixelMap);
    pixelYuv->resize(0.1f, 0.1f);
    Rect rect = {};
    rect.top = 0;
    rect.left = 0;
    int32_t numTwo = 2;
    rect.width = numTwo;
    rect.height = numTwo;
    pixelYuv->crop(rect);
    pixelYuv->scale(0.5f, 0.5f);
    pixelYuv->resize(0.5f, 0.5f);
    int32_t dstW = pixelYuv->GetWidth() * 0.5f;
    int32_t dstH = pixelYuv->GetHeight() * 0.5f;
    pixelYuv->scale(dstW, dstH);
    pixelYuv->resize(dstW, dstH);
    pixelYuv->flip(false, false);
    pixelYuv->flip(true, false);
    pixelYuv->flip(true, true);
    pixelYuv->flip(false, true);
    pixelYuv->translate(0.5f, 0.5f);
    pixelYuv->rotate(0.2f);
#ifdef IMAGE_COLORSPACE_FLAG
    OHOS::ColorManager::ColorSpace grColorSpace(OHOS::ColorManager::ColorSpaceName::DISPLAY_P3);
    pixelYuv->ApplyColorSpace(grColorSpace);
#endif
    pixelYuv->GetPixel8(numTwo, numTwo);
    pixelYuv->GetPixel16(numTwo, numTwo);
    pixelYuv->GetPixel32(numTwo, numTwo);
    uint32_t color = 0;
    pixelYuv->GetARGB32Color(numTwo, numTwo, color);
    pixelYuv->GetARGB32ColorA(color);
    pixelYuv->GetARGB32ColorR(color);
    pixelYuv->GetARGB32ColorG(color);
    pixelYuv->GetARGB32ColorB(color);
    pixelYuv->SetAlpha(0.5f);
    pixelYuv->getPixelBytesNumber();
    pixelYuv->GetByteCount();
    pixelYuv->translate(0.5f, 0.5f);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}

void PixelYuvTest002(PixelMap* pixelMap)
{
    IMAGE_LOGI("%{public}s IN", __func__);
    if (pixelMap == nullptr) {
        IMAGE_LOGE("pixelMap is nullptr");
        return;
    }
    auto pixelYuv = reinterpret_cast<PixelYuv*>(pixelMap);
    const uint64_t bufferSize = static_cast<uint64_t>(pixelYuv->GetByteCount());
    auto srcBuffer = std::make_unique<uint8_t[]>(bufferSize);
    uint8_t* srcPtr = srcBuffer.get();
    const uint32_t offset = 0;
    const uint32_t stride = 0;
    const Rect region;
    const Position pos;
    pixelYuv->WritePixels(srcPtr, bufferSize, offset, stride, region);
    pixelYuv->WritePixels(srcPtr, bufferSize);
    pixelYuv->ReadPixels(bufferSize, offset, stride, region, srcPtr);
    pixelYuv->ReadPixels(bufferSize, srcPtr);
    pixelYuv->translate(0.5f, 0.5f);
    uint32_t dstPixel = 0;
    pixelYuv->ReadPixel(pos, dstPixel);
    const uint32_t color = 0;
    pixelYuv->WritePixels(color);
    pixelYuv->WritePixel(pos, dstPixel);
    IMAGE_LOGI("%{public}s SUCCESS", __func__);
}
