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
 
#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HISPEED_IMAGE_MANAGER_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HISPEED_IMAGE_MANAGER_H
 
#include <cstdint>
#include <vector>
#include "image_type.h"
#include "include/core/SkImageInfo.h"
 
namespace OHOS::ImagePlugin {
struct PlEncodeOptions;
struct HevcSoftDecodeParam;
}  // namespace OHOS::ImagePlugin
 
namespace OHOS::Media {
class PixelMap;
class Picture;
}  // namespace OHOS::Media
 
typedef bool (*WriteFunc)(void* opaque, const void* buffer, size_t size);
typedef void (*FlushFunc)(void* opaque);
 
using YuvJpegEncoder = void*;
using YuvJpegEncoderCreateFunc = YuvJpegEncoder (*)(void);
using YuvJpegEncoderSetQualityFunc = int (*)(YuvJpegEncoder encoder, int quality);
using YuvJpegEncoderSetSubsamplingFunc = int (*)(YuvJpegEncoder encoder, int subsampling);
using YuvJpegEncoderSetIccMetadataFunc = int (*)(YuvJpegEncoder encoder, const uint8_t* data, size_t size);
using YuvJpegEncoderEncodeFunc = int (*)(YuvJpegEncoder encoder, const uint8_t* yuvData, int width, int height,
                                         int yuvFormat, WriteFunc write, FlushFunc flush, void* opaque);
using YuvJpegEncoderDestroyFunc = void (*)(YuvJpegEncoder encoder);
using Yuv10ToRgb8888Func = int (*)(const uint16_t* srcY, int srcStrideY, const uint16_t* srcUv, int srcStrideUv,
                                   uint8_t* dstArgb, int dstStrideArgb, int width, int height, const int* yuvConstant);
using Yuv10ToRgb10Func = int (*)(const uint16_t* srcY, int srcStrideY, const uint16_t* srcUv, int srcStrideUv,
                                 uint8_t* dstAr30, int dstStrideAr30, int width, int height, const int* yuvConstant);
 
#define HSD_BT601_LIMIT (0)
#define HSD_BT601_FULL (1)
#define HSD_BT709_LIMIT (2)
#define HSD_BT709_FULL (3)
#define HSD_BT2020_LIMIT (4)
#define HSD_BT2020_FULL (5)
#define NUM_OF_YUV_CONSTANTS (6)
 
namespace OHOS {
namespace Media {
class HispeedImageManager {
public:
    static HispeedImageManager& GetInstance()
    {
        static HispeedImageManager instance;
        return instance;
    }
    YuvJpegEncoder InitJpegEncoder(uint8_t quality);
    void JpegEncoderAppendICC(YuvJpegEncoder encoder, SkImageInfo info);
    uint32_t DoEncodeJpeg(void *skStream, OHOS::Media::PixelMap* pixelMap, uint8_t quality, SkImageInfo info);
 
    void DestroyJpegEncoder(YuvJpegEncoder encoder);
    bool P010ToARGB(const uint8_t* srcBuffer, const YUVDataInfo& yDInfo, DestConvertInfo& destInfo);
    bool P010ToAR30(const uint8_t* srcBuffer, const YUVDataInfo& yDInfo, DestConvertInfo& destInfo);
private:
    HispeedImageManager();
    ~HispeedImageManager();
    HispeedImageManager(const HispeedImageManager&) = delete;
    HispeedImageManager& operator=(const HispeedImageManager&) = delete;
 
    bool LoadHispeedImageSo();
    void UnloadHispeedImageSo();
    bool LoadYuvJpegEncoderSym();
    bool LoadYuvConvertSym();
    void YuvConvertPara(const YUVDataInfo& yuvInfo, SrcConvertParam& srcParam, DestConvertParam& destParam,
                       DestConvertInfo& destInfo);
    const int* GetYuvCoeffFromDest(const DestConvertParam &destParam);
    bool isHispeedImageSoOpened_;
    void* hispeedImageSoHandle_;
    YuvJpegEncoderCreateFunc jpegEncoderCreateFunc_;
    YuvJpegEncoderSetQualityFunc jpegEncoderSetQualityFunc_;
    YuvJpegEncoderSetSubsamplingFunc jpegEncoderSetSubsamplingFunc_;
    YuvJpegEncoderSetIccMetadataFunc jpegEncoderSetICCMetadataFunc_;
    YuvJpegEncoderEncodeFunc jpegEncoderEncodeFunc_;
    YuvJpegEncoderDestroyFunc jpegEncoderDestroyFunc_;
    Yuv10ToRgb8888Func yuv10ToRgb8888Func_;
    Yuv10ToRgb10Func yuv10ToRgb10Func_;
    int* yuvConstants[NUM_OF_YUV_CONSTANTS];
};
}  // namespace Media
}  // namespace OHOS
 
#endif  // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_HISPEED_IMAGE_MANAGER_H