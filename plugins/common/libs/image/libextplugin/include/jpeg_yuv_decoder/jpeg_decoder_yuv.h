/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_JPEG_DECODER_YUV_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_JPEG_DECODER_YUV_H

#include <string>

#include "abs_image_decoder.h"
#include "jpeg_yuvdata_converter.h"
#include "jpeglib.h"
#include "turbojpeg.h"

namespace OHOS {
namespace ImagePlugin {

typedef int (*FUNC_I4xxToI420)(const YuvPlaneInfo& src, const YuvPlaneInfo& dest);
typedef int (*FUNC_I4xxToNV21)(const YuvPlaneInfo& src, const YuvPlaneInfo& dest);

struct ConverterPair {
    FUNC_I4xxToI420 to420Func = nullptr;
    FUNC_I4xxToNV21 toNV21Func = nullptr;
};

enum class JpegYuvFmt {
    OutFmt_YU12 = 1,
    OutFmt_YV12,
    OutFmt_NV12,
    OutFmt_NV21,
};

enum JpegYuvDecodeError {
    JpegYuvDecodeError_Unknown = -1,
    JpegYuvDecodeError_Success = 0,
    JpegYuvDecodeError_InvalidParameter,
    JpegYuvDecodeError_DecodeFailed,
    JpegYuvDecodeError_BadImage,
    JpegYuvDecodeError_SubSampleNotSupport,
    JpegYuvDecodeError_MemoryMallocFailed,
    JpegYuvDecodeError_MemoryNotEnoughToSaveResult,
    JpegYuvDecodeError_ConvertError,
};

struct JpegDecoderYuvParameter {
    uint32_t jpgwidth_ = 0;
    uint32_t jpgheight_ = 0;
    const uint8_t *jpegBuffer_ = nullptr;
    uint32_t jpegBufferSize_ = 0;
    uint8_t *yuvBuffer_ = nullptr;
    uint32_t yuvBufferSize_ = 0;
    JpegYuvFmt outfmt_ = JpegYuvFmt::OutFmt_YU12;
    uint32_t outwidth_ = 0;
    uint32_t outheight_ = 0;
};

struct JpegScaleFactor {
    uint32_t num;
    uint32_t denom;
};

typedef int (*FUNC_I444ToI420)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_u,
    int dst_stride_u, uint8_t* dst_v, int dst_stride_v, int width, int height);
typedef int (*FUNC_I444ToNV21)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_vu,
    int dst_stride_vu, int width, int height);
typedef int (*FUNC_I422ToI420)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_u,
    int dst_stride_u, uint8_t* dst_v, int dst_stride_v, int width, int height);
typedef int (*FUNC_I422ToNV21)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_vu,
    int dst_stride_vu, int width, int height);
typedef int (*FUNC_I420ToNV21)(const uint8_t* src_y, int src_stride_y, const uint8_t* src_u, int src_stride_u,
    const uint8_t* src_v, int src_stride_v, uint8_t* dst_y, int dst_stride_y, uint8_t* dst_vu,
    int dst_stride_vu, int width, int height);
typedef int (*FUNC_I400ToI420)(const uint8_t* src_y, int src_stride_y, uint8_t* dst_y, int dst_stride_y,
    uint8_t* dst_u, int dst_stride_u, uint8_t* dst_v, int dst_stride_v, int width, int height);

struct LibYuvConvertFuncs {
    FUNC_I444ToI420 I444ToI420 = nullptr;
    FUNC_I444ToNV21 I444ToNV21 = nullptr;
    FUNC_I422ToI420 I422ToI420 = nullptr;
    FUNC_I422ToNV21 I422ToNV21 = nullptr;
    FUNC_I420ToNV21 I420ToNV21 = nullptr;
    FUNC_I400ToI420 I400ToI420 = nullptr;
};

class JpegDecoderYuv {
public:
    JpegDecoderYuv();
    static bool LoadLibYuv();
    static void UnloadLibYuv();
    static LibYuvConvertFuncs& GetLibyuvConverter() { return libyuvFuncs_; }
    int DoDecode(DecodeContext &context, JpegDecoderYuvParameter &decodeParameter);
    static bool GetScaledSize(uint32_t jpgwidth, uint32_t jpgheight, uint32_t &width, uint32_t &height);
    static uint32_t GetYuvOutSize(uint32_t width, uint32_t height);

protected:
    static void InitPlaneOutInfoTo420(uint32_t width, uint32_t height, YuvPlaneInfo &info);
    static void InitPlaneOutInfoTo420NV(uint32_t width, uint32_t height, YuvPlaneInfo &info);
    static void FillJpgOutYuvInfo(YuvPlaneInfo& info, uint32_t width, uint32_t height, uint8_t* data, int samp);
    static uint32_t Get420OutPlaneWidth(YuvComponentIndex com, int imageWidth);
    static uint32_t Get420OutPlaneHeight(YuvComponentIndex com, int imageHeight);
    static uint32_t Get420OutPlaneSize(YuvComponentIndex com, int imageWidth, int imageHeight);
    static uint32_t GetJpegDecompressedYuvSize(uint32_t width, uint32_t height, int subsample);
    static void InitYuvDataOutInfoTo420(uint32_t width, uint32_t height, PlYuvDataInfo &info);
    static void InitYuvDataOutInfoTo420NV(uint32_t width, uint32_t height, PlYuvDataInfo &info);
    static void InitYuvDataOutInfo(uint32_t width, uint32_t height, PlYuvDataInfo &info);
    static bool IsYU12YV12Format(JpegYuvFmt fmt);
    static tjscalingfactor GetScaledFactor(uint32_t jpgwidth, uint32_t jpgheight, uint32_t width, uint32_t height);
    static void JpegCalculateOutputSize(uint32_t jpgwidth, uint32_t jpgheight, uint32_t& width, uint32_t& height);
    bool IsSupportedSubSample(int jpegSubsamp);
    bool IsOutSizeValid(uint32_t outwidth, uint32_t outheight);
    bool CanFastDecodeFrom420to420(uint32_t width, uint32_t height, uint32_t jpgYuvSizeOut, int subsamp);
    int DecodeHeader(tjhandle dehandle, int& retSubsamp);
    int DoDecodeToYuvPlane(DecodeContext &context, tjhandle dehandle, uint32_t outw, uint32_t outh);
    int DecodeFrom420To420(DecodeContext &context, tjhandle dehandle, uint32_t width, uint32_t height);
    bool ValidateParameter(YuvPlaneInfo &srcPlaneInfo, ConverterPair &converter);
    int ConvertFrom4xx(YuvPlaneInfo &srcPlaneInfo, ConverterPair &converter);
    int ConvertFromGray(YuvPlaneInfo &srcPlaneInfo);

protected:
    JpegDecoderYuvParameter decodeParameter_;
    static void* dlHandler_;
    static LibYuvConvertFuncs libyuvFuncs_;
};

}
}
#endif