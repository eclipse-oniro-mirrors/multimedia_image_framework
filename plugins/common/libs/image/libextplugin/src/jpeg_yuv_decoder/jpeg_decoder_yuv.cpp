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

#include "jpeg_decoder_yuv.h"

#include <dlfcn.h>
#include <map>
#include <mutex>
#include <utility>

#include "image_log.h"
#include "securec.h"
#include "jpegint.h"

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::Media;

const std::string YUV_LIB_PATH = "libyuv.z.so";

void* JpegDecoderYuv::dlHandler_ = nullptr;
LibYuvConvertFuncs JpegDecoderYuv::libyuvFuncs_ = { nullptr };

__attribute__((destructor)) void JpgYuvDeinitLibyuv()
{
    JpegDecoderYuv::UnloadLibYuv();
}

#define AVERAGE_FACTOR 2

static const std::map<int, ConverterPair> CONVERTER_MAP = {
    {TJSAMP_444, {&I444ToI420_wrapper, &I444ToNV21_wrapper}},
    {TJSAMP_422, {&I422ToI420_wrapper, &I422ToNV21_wrapper}},
    {TJSAMP_420, {&I420ToI420_wrapper, &I420ToNV21_wrapper}},
    {TJSAMP_440, {&I440ToI420_wrapper, &I440ToNV21_wrapper}},
    {TJSAMP_411, {&I411ToI420_wrapper, &I411ToNV21_wrapper}}
};

JpegDecoderYuv::JpegDecoderYuv()
{
    static std::once_flag flag;
    std::function<void()> func = std::bind(&JpegDecoderYuv::LoadLibYuv);
    std::call_once(flag, func);
}

bool JpegDecoderYuv::LoadLibYuv()
{
    dlHandler_ = dlopen(YUV_LIB_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (dlHandler_ == nullptr) {
        IMAGE_LOGE("JpegDecoderYuv LoadLibYuv, failed");
        return false;
    }
    IMAGE_LOGI("JpegDecoderYuv LoadLibYuv, success");
    libyuvFuncs_.I444ToI420 = (FUNC_I444ToI420)dlsym(dlHandler_, "I444ToI420");
    libyuvFuncs_.I444ToNV21 = (FUNC_I444ToNV21)dlsym(dlHandler_, "I444ToNV21");
    libyuvFuncs_.I422ToI420 = (FUNC_I422ToI420)dlsym(dlHandler_, "I422ToI420");
    libyuvFuncs_.I422ToNV21 = (FUNC_I422ToNV21)dlsym(dlHandler_, "I422ToNV21");
    libyuvFuncs_.I420ToNV21 = (FUNC_I420ToNV21)dlsym(dlHandler_, "I420ToNV21");
    libyuvFuncs_.I400ToI420 = (FUNC_I400ToI420)dlsym(dlHandler_, "I400ToI420");
    return true;
}

void JpegDecoderYuv::UnloadLibYuv()
{
    IMAGE_LOGI("JpegDecoderYuv UnloadLibYuv");
    memset_s(&libyuvFuncs_, sizeof(libyuvFuncs_), 0, sizeof(libyuvFuncs_));
    if (dlHandler_) {
        dlclose(dlHandler_);
        dlHandler_ = nullptr;
    }
}

bool JpegDecoderYuv::IsSupportedSubSample(int jpegSubsamp)
{
    bool ret = false;
    switch (jpegSubsamp) {
        case TJSAMP_444:
        case TJSAMP_422:
        case TJSAMP_420:
        case TJSAMP_440:
        case TJSAMP_411:
        case TJSAMP_GRAY: {
            ret = true;
            break;
        }
        default: {
            ret = false;
            break;
        }
    }
    return ret;
}

tjscalingfactor JpegDecoderYuv::GetScaledFactor(uint32_t jpgwidth, uint32_t jpgheight, uint32_t width, uint32_t height)
{
    tjscalingfactor factor = { 1, 1};
    if (jpgwidth == 0 || jpgheight == 0) {
        return factor;
    }
    if (width == 0 || height == 0) {
        return factor;
    }

    int NUMSF = 0;
    tjscalingfactor* sf = tjGetScalingFactors(&NUMSF);
    if (sf == nullptr || NUMSF == 0) {
        return factor;
    }
    for (int i = 0; i < NUMSF; i++) {
        uint32_t scaledw = TJSCALED(jpgwidth, sf[i]);
        uint32_t scaledh = TJSCALED(jpgheight, sf[i]);
        if ((scaledw <= width && scaledh <= height) || i == NUMSF - 1) {
            factor.num = sf[i].num;
            factor.denom = sf[i].denom;
            break;
        }
    }
    return factor;
}

bool JpegDecoderYuv::GetScaledSize(uint32_t jpgwidth, uint32_t jpgheight, uint32_t &width, uint32_t &height)
{
    if (jpgwidth == 0 || jpgheight == 0) {
        return false;
    }
    uint32_t reqWidth = width;
    uint32_t reqHeight = height;
    if (reqWidth == 0 || reqHeight == 0) {
        width = jpgwidth;
        height = jpgheight;
        return true;
    }
    tjscalingfactor factor = JpegDecoderYuv::GetScaledFactor(jpgwidth, jpgheight, width, height);
    width = TJSCALED(jpgwidth, factor);
    height = TJSCALED(jpgheight, factor);
    return true;
}

void JpegDecoderYuv::JpegCalculateOutputSize(uint32_t jpgwidth, uint32_t jpgheight, uint32_t& width, uint32_t& height)
{
    tjscalingfactor factor = JpegDecoderYuv::GetScaledFactor(jpgwidth, jpgheight, width, height);
    jpeg_decompress_struct dinfo = { 0 };
    dinfo.image_width = jpgwidth;
    dinfo.image_height = jpgheight;
    dinfo.global_state = DSTATE_READY;
    dinfo.num_components = 0;
    dinfo.scale_num = factor.num;
    dinfo.scale_denom = factor.denom;
    jpeg_calc_output_dimensions(&dinfo);
    width = dinfo.output_width;
    height = dinfo.output_height;
}

uint32_t JpegDecoderYuv::Get420OutPlaneWidth(YuvComponentIndex com, int imageWidth)
{
    if (imageWidth == 0) {
        return 0;
    }
    if (com == YCOM) {
        return imageWidth;
    } else {
        return (imageWidth + 1) / AVERAGE_FACTOR;
    }
}

uint32_t JpegDecoderYuv::Get420OutPlaneHeight(YuvComponentIndex com, int imageHeight)
{
    if (imageHeight == 0) {
        return 0;
    }
    if (com == YCOM) {
        return imageHeight;
    } else {
        return (imageHeight + 1) / AVERAGE_FACTOR;
    }
}

uint32_t JpegDecoderYuv::Get420OutPlaneSize(YuvComponentIndex com, int imageWidth, int imageHeight)
{
    if (imageWidth == 0 || imageHeight == 0) {
        return 0;
    }
    if (com == UVCOM) {
        uint32_t size = Get420OutPlaneSize(UCOM, imageWidth, imageHeight);
        size += Get420OutPlaneSize(VCOM, imageWidth, imageHeight);
        return size;
    } else {
        return Get420OutPlaneWidth(com, imageWidth) * Get420OutPlaneHeight(com, imageHeight);
    }
}

uint32_t JpegDecoderYuv::GetYuvOutSize(uint32_t width, uint32_t height)
{
    if (width == 0 || height == 0) {
        return 0;
    }
    uint32_t size = Get420OutPlaneSize(YCOM, width, height);
    size += Get420OutPlaneSize(UCOM, width, height);
    size += Get420OutPlaneSize(VCOM, width, height);
    return size;
}

uint32_t JpegDecoderYuv::GetJpegDecompressedYuvSize(uint32_t width, uint32_t height, int subsample)
{
    if (width == 0 || height == 0) {
        return 0;
    }
    int totalSizeForDecodeData = 0;
    for (int i = 0; i < YUVCOMPONENT_MAX - 1; i++) {
        if (subsample == TJSAMP_GRAY && i != YCOM) {
            break;
        }
        unsigned long planesize = tjPlaneSizeYUV(i, width, 0, height, subsample);
        if (planesize != (unsigned long)-1) {
            totalSizeForDecodeData += planesize;
        }
    }
    return totalSizeForDecodeData;
}

void JpegDecoderYuv::InitYuvDataOutInfoTo420(uint32_t width, uint32_t height, PlYuvDataInfo &info)
{
    if (width == 0 || height == 0) {
        return;
    }
    info.imageSize.width = width;
    info.imageSize.height = height;
    info.y_width = Get420OutPlaneWidth(YCOM, width);
    info.y_height = Get420OutPlaneHeight(YCOM, height);
    info.uv_width = Get420OutPlaneWidth(UCOM, width);
    info.uv_height = Get420OutPlaneHeight(UCOM, height);
    info.y_stride = info.y_width;
    info.u_stride = info.uv_width;
    info.v_stride = info.uv_width;
}

void JpegDecoderYuv::InitYuvDataOutInfoTo420NV(uint32_t width, uint32_t height, PlYuvDataInfo &info)
{
    if (width == 0 || height == 0) {
        return;
    }
    info.imageSize.width = width;
    info.imageSize.height = height;
    info.y_width = Get420OutPlaneWidth(YCOM, width);
    info.y_height = Get420OutPlaneHeight(YCOM, height);
    info.uv_width = Get420OutPlaneWidth(UCOM, width);
    info.uv_height = Get420OutPlaneHeight(UCOM, height);
    info.y_stride = info.y_width;
    info.uv_stride = info.uv_width + info.uv_width;
}

void JpegDecoderYuv::InitYuvDataOutInfo(uint32_t width, uint32_t height, PlYuvDataInfo &info)
{
    memset_s(&info, sizeof(info), 0, sizeof(info));
    info.imageSize.width = width;
    info.imageSize.height = height;
}

void JpegDecoderYuv::InitPlaneOutInfoTo420(uint32_t width, uint32_t height, YuvPlaneInfo &info)
{
    if (width == 0 || height == 0) {
        return;
    }
    info.imageWidth = width;
    info.imageHeight = height;
    info.planeWidth[YCOM] = Get420OutPlaneWidth(YCOM, width);
    info.strides[YCOM] = info.planeWidth[YCOM];
    info.planeWidth[UCOM] = Get420OutPlaneWidth(UCOM, width);
    info.strides[UCOM] = info.planeWidth[UCOM];
    info.planeWidth[VCOM] = Get420OutPlaneWidth(VCOM, width);
    info.strides[VCOM] = info.planeWidth[VCOM];
    info.planeHeight[YCOM] = Get420OutPlaneHeight(YCOM, height);
    info.planeHeight[UCOM] = Get420OutPlaneHeight(UCOM, height);
    info.planeHeight[VCOM] = Get420OutPlaneHeight(VCOM, height);
}

void JpegDecoderYuv::InitPlaneOutInfoTo420NV(uint32_t width, uint32_t height, YuvPlaneInfo &info)
{
    if (width == 0 || height == 0) {
        return;
    }
    info.imageWidth = width;
    info.imageHeight = height;
    info.planeWidth[YCOM] = Get420OutPlaneWidth(YCOM, width);
    info.strides[YCOM] = info.planeWidth[YCOM];
    info.planeHeight[YCOM] = Get420OutPlaneHeight(YCOM, height);
    info.planeWidth[UVCOM] = Get420OutPlaneWidth(UCOM, width);
    info.strides[UVCOM] = Get420OutPlaneWidth(UCOM, width) + Get420OutPlaneWidth(VCOM, width);
    info.planeHeight[UVCOM] = Get420OutPlaneHeight(UCOM, height);
}

bool JpegDecoderYuv::IsYU12YV12Format(JpegYuvFmt fmt)
{
    if (fmt == JpegYuvFmt::OutFmt_YU12 ||
        fmt == JpegYuvFmt::OutFmt_YV12) {
        return true;
    } else {
        return false;
    }
}

int JpegDecoderYuv::DoDecode(DecodeContext &context, JpegDecoderYuvParameter &decodeParameter)
{
    decodeParameter_ = decodeParameter;
    uint32_t outwidth = decodeParameter.outwidth_;
    uint32_t outheight = decodeParameter_.outheight_;
    IMAGE_LOGD("JpegDecoderYuv DoDecode outFmt %{public}d, yuvBufferSize %{public}d, outSize (%{public}d, %{public}d)",
        decodeParameter.outfmt_, decodeParameter_.yuvBufferSize_, outwidth, outheight);
    JpegDecoderYuv::InitYuvDataOutInfo(outwidth, outheight, context.yuvInfo);
    if (decodeParameter_.jpegBuffer_ == nullptr || decodeParameter_.yuvBuffer_ == nullptr) {
        IMAGE_LOGE("JpegDecoderYuv DoDecode, null buffer");
        return JpegYuvDecodeError_InvalidParameter;
    }
    if (outwidth == 0 || outheight == 0) {
        IMAGE_LOGE("JpegDecoderYuv DoDecode, outSize zero");
        return JpegYuvDecodeError_InvalidParameter;
    }

    tjhandle dehandle = tjInitDecompress();
    if (nullptr == dehandle) {
        return JpegYuvDecodeError_DecodeFailed;
    }
    int ret = DoDecodeToYuvPlane(context, dehandle, outwidth, outheight);
    tjDestroy(dehandle);
    if (ret == JpegYuvDecodeError_Success) {
        if (JpegDecoderYuv::IsYU12YV12Format(decodeParameter_.outfmt_)) {
            JpegDecoderYuv::InitYuvDataOutInfoTo420(outwidth, outheight, context.yuvInfo);
        } else {
            JpegDecoderYuv::InitYuvDataOutInfoTo420NV(outwidth, outheight, context.yuvInfo);
        }
    }
    return ret;
}

bool JpegDecoderYuv::IsOutSizeValid(uint32_t outwidth, uint32_t outheight)
{
    uint32_t jpgwidth = decodeParameter_.jpgwidth_;
    uint32_t jpgheight = decodeParameter_.jpgheight_;
    uint32_t caledOutputWidth = outwidth;
    uint32_t caledOutputHeight = outheight;
    JpegCalculateOutputSize(jpgwidth, jpgheight, caledOutputWidth, caledOutputHeight);
    if (caledOutputWidth != outwidth || caledOutputHeight != outheight) {
        return false;
    }
    return true;
}

void JpegDecoderYuv::FillJpgOutYuvInfo(YuvPlaneInfo& info, uint32_t width, uint32_t height, uint8_t* data, int samp)
{
    info.imageWidth = width;
    info.imageHeight = height;
    for (int i = 0; i < YUVCOMPONENT_MAX - 1; i++) {
        info.planeWidth[i] = info.strides[i] = tjPlaneWidth(i, width, samp);
        info.planeHeight[i] = tjPlaneHeight(i, height, samp);
        if (samp == TJSAMP_GRAY && i != YCOM) {
            break;
        }
    }
    info.planes[YCOM] = data;
    if (samp != TJSAMP_GRAY) {
        info.planes[UCOM] = info.planes[YCOM] + info.planeWidth[YCOM] * info.planeHeight[YCOM];
        info.planes[VCOM] = info.planes[UCOM] + info.planeWidth[UCOM] * info.planeHeight[UCOM];
    }
}

bool JpegDecoderYuv::CanFastDecodeFrom420to420(uint32_t width, uint32_t height, uint32_t jpgYuvSizeOut, int subsamp)
{
    if (subsamp == TJSAMP_420 && JpegDecoderYuv::IsYU12YV12Format(decodeParameter_.outfmt_)) {
        if (jpgYuvSizeOut == decodeParameter_.yuvBufferSize_ &&
            Get420OutPlaneWidth(YCOM, width) == (uint32_t)tjPlaneWidth(YCOM, width, TJSAMP_420) &&
            Get420OutPlaneHeight(YCOM, height) == (uint32_t)tjPlaneHeight(YCOM, height, TJSAMP_420)) {
            return true;
        }
    }
    return false;
}

int JpegDecoderYuv::DecodeHeader(tjhandle dehandle, int& retSubsamp)
{
    if (nullptr == dehandle) {
        return JpegYuvDecodeError_DecodeFailed;
    }
    int width = 0;
    int height = 0;
    int jpegSubsamp = 0;
    int jpegColorSpace = 0;
    int ret = tjDecompressHeader3(dehandle,
        decodeParameter_.jpegBuffer_,
        decodeParameter_.jpegBufferSize_, &width,
        &height, &jpegSubsamp, &jpegColorSpace);
    retSubsamp = jpegSubsamp;
    decodeParameter_.jpgwidth_ = width;
    decodeParameter_.jpgheight_ = height;
    if (ret != 0) {
        IMAGE_LOGE("JpegDecoderYuv tjDecompressHeader3, failed");
        return JpegYuvDecodeError_DecodeFailed;
    }
    if (width == 0 || height == 0) {
        IMAGE_LOGE("JpegDecoderYuv tjDecompressHeader3, image size zero");
        return JpegYuvDecodeError_BadImage;
    }
    if (!IsSupportedSubSample(jpegSubsamp)) {
        IMAGE_LOGE("JpegDecoderYuv tjDecompressHeader3, subsample %{public}d not supported", jpegSubsamp);
        return JpegYuvDecodeError_SubSampleNotSupport;
    }
    return JpegYuvDecodeError_Success;
}

int JpegDecoderYuv::DoDecodeToYuvPlane(DecodeContext &context, tjhandle dehandle, uint32_t outw, uint32_t outh)
{
    int jpegSubsamp = 0;
    int ret = DecodeHeader(dehandle, jpegSubsamp);
    if (ret != JpegYuvDecodeError_Success) {
        return ret;
    }
    if (!IsOutSizeValid(outw, outh)) {
        IMAGE_LOGE("JpegDecoderYuv DoDecodeToYuvPlane, pre calcualted out size wrong");
        return JpegYuvDecodeError_InvalidParameter;
    }
    int width = outw;
    int height = outh;
    int totalSizeForDecodeData = GetJpegDecompressedYuvSize(width, height, jpegSubsamp);
    if (CanFastDecodeFrom420to420(width, height, totalSizeForDecodeData, jpegSubsamp)) {
        return DecodeFrom420To420(context, dehandle, width, height);
    }
    std::unique_ptr<uint8_t[]> yuvBuffer = std::make_unique<uint8_t[]>(totalSizeForDecodeData);
    unsigned char* data = reinterpret_cast<unsigned char*>(yuvBuffer.get());

    YuvPlaneInfo jpegOutYuvInfo = { 0 };
    FillJpgOutYuvInfo(jpegOutYuvInfo, width, height, data, jpegSubsamp);
    ret = tjDecompressToYUVPlanes(dehandle, decodeParameter_.jpegBuffer_, decodeParameter_.jpegBufferSize_,
        jpegOutYuvInfo.planes, width, nullptr, height, 0);
    if (ret != 0) {
        IMAGE_LOGE("JpegDecoderYuv tjDecompressToYUVPlanes failed, ret %{public}d", ret);
        return JpegYuvDecodeError_DecodeFailed;
    }
    if (jpegSubsamp == TJSAMP_GRAY) {
        return ConvertFromGray(jpegOutYuvInfo);
    }
    ConverterPair convertFunc = { nullptr, nullptr};
    auto iter = CONVERTER_MAP.find(jpegSubsamp);
    if (iter != CONVERTER_MAP.end()) {
        convertFunc = iter->second;
    }
    return ConvertFrom4xx(jpegOutYuvInfo, convertFunc);
}

int JpegDecoderYuv::DecodeFrom420To420(DecodeContext &context, tjhandle dehandle, uint32_t width, uint32_t height)
{
    uint32_t outSize = JpegDecoderYuv::GetJpegDecompressedYuvSize(width, height, TJSAMP_420);
    if (outSize != decodeParameter_.yuvBufferSize_) {
        IMAGE_LOGE("JpegDecoderYuv ConvertFrom4xx yuvBufferSize not correct");
        return JpegYuvDecodeError_MemoryNotEnoughToSaveResult;
    }

    unsigned char* dstPlanes[YUVCOMPONENT_MAX] = { 0 };
    if (decodeParameter_.outfmt_ == JpegYuvFmt::OutFmt_YU12) {
        dstPlanes[YCOM] = decodeParameter_.yuvBuffer_;
        dstPlanes[UCOM] = dstPlanes[YCOM] + tjPlaneSizeYUV(YCOM, width, 0, height, TJSAMP_420);
        dstPlanes[VCOM] = dstPlanes[UCOM] + tjPlaneSizeYUV(UCOM, width, 0, height, TJSAMP_420);
    } else if (decodeParameter_.outfmt_ == JpegYuvFmt::OutFmt_YV12) {
        dstPlanes[YCOM] = decodeParameter_.yuvBuffer_;
        dstPlanes[VCOM] = dstPlanes[YCOM] + tjPlaneSizeYUV(YCOM, width, 0, height, TJSAMP_420);
        dstPlanes[UCOM] = dstPlanes[VCOM] + tjPlaneSizeYUV(VCOM, width, 0, height, TJSAMP_420);
    }
    IMAGE_LOGD("JpegDecoderYuv DecodeFrom420ToYuv decode to 420 directly");
    int ret = tjDecompressToYUVPlanes(dehandle,
        decodeParameter_.jpegBuffer_,
        decodeParameter_.jpegBufferSize_,
        dstPlanes, width,
        nullptr, height, 0);
    if (ret != 0) {
        IMAGE_LOGE("JpegDecoderYuv DecodeFrom420ToYuv tjDecompressToYUVPlanes failed, ret %{public}d", ret);
    }
    return ret != 0 ? JpegYuvDecodeError_DecodeFailed : JpegYuvDecodeError_Success;
}

bool JpegDecoderYuv::ValidateParameter(YuvPlaneInfo &srcPlaneInfo, ConverterPair &converter)
{
    uint32_t width = srcPlaneInfo.imageWidth;
    uint32_t height = srcPlaneInfo.imageHeight;
    if (srcPlaneInfo.planes[YCOM] == nullptr || srcPlaneInfo.planes[UCOM] == nullptr ||
            srcPlaneInfo.planes[VCOM] == nullptr) {
        return false;
    }
    if (width == 0 || height == 0) {
        return false;
    }
    if (converter.to420Func == nullptr || converter.toNV21Func == nullptr) {
        return false;
    }
    if (srcPlaneInfo.planeWidth[YCOM] == 0 || srcPlaneInfo.planeWidth[UCOM] == 0 ||
            srcPlaneInfo.planeWidth[VCOM] == 0) {
        return false;
    }
    if (srcPlaneInfo.planeHeight[YCOM] == 0 || srcPlaneInfo.planeHeight[UCOM] == 0 ||
            srcPlaneInfo.planeHeight[VCOM] == 0) {
        return false;
    }

    uint32_t outSize = JpegDecoderYuv::GetYuvOutSize(width, height);
    if (outSize > decodeParameter_.yuvBufferSize_) {
        IMAGE_LOGE("JpegDecoderYuv ValidateParameter yuvBufferSize not enough");
        return false;
    }

    return true;
}

int JpegDecoderYuv::ConvertFrom4xx(YuvPlaneInfo &srcPlaneInfo, ConverterPair &converter)
{
    if (!ValidateParameter(srcPlaneInfo, converter)) {
        return JpegYuvDecodeError_ConvertError;
    }
    uint32_t width = srcPlaneInfo.imageWidth;
    uint32_t height = srcPlaneInfo.imageHeight;
    unsigned char* outYData = decodeParameter_.yuvBuffer_;
    unsigned char* outUData = outYData + Get420OutPlaneSize(YCOM, width, height);
    unsigned char* outVData = outUData + Get420OutPlaneSize(UCOM, width, height);
    unsigned char* outUVData = outUData;
    YuvPlaneInfo dest = { 0 };
    int ret = JpegYuvDecodeError_ConvertError;
    switch (decodeParameter_.outfmt_) {
        case JpegYuvFmt::OutFmt_YU12:
        case JpegYuvFmt::OutFmt_YV12: {
            JpegDecoderYuv::InitPlaneOutInfoTo420(width, height, dest);
            dest.planes[YCOM] = outYData;
            if (decodeParameter_.outfmt_ == JpegYuvFmt::OutFmt_YU12) {
                dest.planes[UCOM] = outUData;
                dest.planes[VCOM] = outVData;
            } else {
                dest.planes[UCOM] = outVData;
                dest.planes[VCOM] = outUData;
            }
            ret = converter.to420Func(srcPlaneInfo, dest);
            break;
        }
        case JpegYuvFmt::OutFmt_NV12: {
            YuvPlaneInfo srcYVU = srcPlaneInfo;
            srcYVU.planes[UCOM] = srcPlaneInfo.planes[VCOM];
            srcYVU.planes[VCOM] = srcPlaneInfo.planes[UCOM];
            JpegDecoderYuv::InitPlaneOutInfoTo420NV(width, height, dest);
            dest.planes[YCOM] = outYData;
            dest.planes[UVCOM] = outUVData;
            ret = converter.toNV21Func(srcYVU, dest);
            break;
        }
        case JpegYuvFmt::OutFmt_NV21: {
            JpegDecoderYuv::InitPlaneOutInfoTo420NV(width, height, dest);
            dest.planes[YCOM] = outYData;
            dest.planes[UVCOM] = outUVData;
            ret = converter.toNV21Func(srcPlaneInfo, dest);
            break;
        }
    }
    return ret == 0 ? JpegYuvDecodeError_Success : JpegYuvDecodeError_ConvertError;
}

int JpegDecoderYuv::ConvertFromGray(YuvPlaneInfo &srcPlaneInfo)
{
    uint32_t width = srcPlaneInfo.imageWidth;
    uint32_t height = srcPlaneInfo.imageHeight;
    if (srcPlaneInfo.planes[YCOM] == nullptr) {
        return JpegYuvDecodeError_ConvertError;
    }
    if (width == 0 || height == 0) {
        return JpegYuvDecodeError_ConvertError;
    }
    if (srcPlaneInfo.planeWidth[YCOM] == 0 || srcPlaneInfo.planeHeight[YCOM] == 0) {
        return JpegYuvDecodeError_ConvertError;
    }
    uint32_t outSize = JpegDecoderYuv::GetYuvOutSize(width, height);
    if (outSize > decodeParameter_.yuvBufferSize_) {
        IMAGE_LOGE("JpegDecoderYuv ConvertFromGray yuvBufferSize not enough %{public}d", outSize);
        return JpegYuvDecodeError_MemoryNotEnoughToSaveResult;
    }

    unsigned char* outYData = decodeParameter_.yuvBuffer_;
    unsigned char* outUData = outYData + Get420OutPlaneSize(YCOM, width, height);
    unsigned char* outVData = outUData + Get420OutPlaneSize(UCOM, width, height);
    YuvPlaneInfo dest = { 0 };
    JpegDecoderYuv::InitPlaneOutInfoTo420(width, height, dest);
    dest.planes[YCOM] = outYData;
    dest.planes[UCOM] = outUData;
    dest.planes[VCOM] = outVData;
    int ret = I400ToI420_wrapper(srcPlaneInfo, dest);
    return ret == 0 ? JpegYuvDecodeError_Success : JpegYuvDecodeError_ConvertError;
}

}
}

