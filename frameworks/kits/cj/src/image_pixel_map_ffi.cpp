/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "cj_color_manager.h"
#include "cj_ffi/cj_common_ffi.h"
#include "image_ffi.h"
#include "image_log.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "media_errors.h"
#include "pixel_map_impl.h"
#include "pixel_map_napi.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Media {
extern "C" {
static Rect ParseCRegion(CRegion region)
{
    Rect rt = {
        .left = region.x,
        .top = region.y,
        .width = region.size.width,
        .height = region.size.height,
    };
    return rt;
}

static InitializationOptions ParsePixelMapCInitializationOptions(CInitializationOptionsV2 opts)
{
    InitializationOptions option;
    option.alphaType = AlphaType(opts.alphaType);
    option.editable = opts.editable;
    option.srcPixelFormat = PixelFormat(opts.srcPixelFormat);
    option.pixelFormat = PixelFormat(opts.pixelFormat);
    option.scaleMode = ScaleMode(opts.scaleMode);
    option.size.height = opts.height;
    option.size.width = opts.width;
    return option;
}

FFI_EXPORT int64_t FfiOHOSCreatePixelMap(uint8_t* colors, uint32_t colorLength, CInitializationOptions opts)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSCreatePixelMap start");
    InitializationOptions option;
    option.alphaType = AlphaType(opts.alphaType);
    option.editable = opts.editable;
    option.pixelFormat = PixelFormat(opts.pixelFormat);
    option.scaleMode = ScaleMode(opts.scaleMode);
    option.size.height = opts.height;
    option.size.width = opts.width;
    std::unique_ptr<PixelMap> ptr_ =
        PixelMapImpl::CreatePixelMap(reinterpret_cast<uint32_t*>(colors), colorLength, option);
    if (!ptr_) {
        return INIT_FAILED;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(ptr_));
    if (!native) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreatePixelMap failed");
        return INIT_FAILED;
    }
    IMAGE_LOGD("[PixelMap] FfiOHOSCreatePixelMap success");
    return native->GetID();
}

FFI_EXPORT int64_t FfiOHOSCreatePixelMapV2(uint8_t* colors, uint32_t colorLength, CInitializationOptionsV2 opts)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSCreatePixelMapV2 start");
    InitializationOptions option = ParsePixelMapCInitializationOptions(opts);
    std::unique_ptr<PixelMap> ptr_ =
        PixelMapImpl::CreatePixelMap(reinterpret_cast<uint32_t*>(colors), colorLength, option);
    if (!ptr_) {
        return INIT_FAILED;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(ptr_));
    if (!native) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreatePixelMapV2 failed");
        return INIT_FAILED;
    }
    IMAGE_LOGD("[PixelMap] FfiOHOSCreatePixelMapV2 success");
    return native->GetID();
}

FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMap(CInitializationOptionsV2 opts)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePixelMap start");
    InitializationOptions option = ParsePixelMapCInitializationOptions(opts);
    std::unique_ptr<PixelMap> ptr_ = PixelMapImpl::CreatePixelMap(option);
    if (!ptr_) {
        return INIT_FAILED;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(ptr_));
    if (!native) {
        IMAGE_LOGE("[ImageSource] FfiImagePixelMapImplCreatePixelMap failed");
        return INIT_FAILED;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePixelMap success");
    return native->GetID();
}

FFI_EXPORT uint32_t FfiOHOSPixelMapRelease(int64_t id)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapRelease start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    std::shared_ptr<PixelMap> ptr_ = instance->GetRealPixelMap();
    ptr_.reset();
    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapRelease success");
    return SUCCESS_CODE;
}

FFI_EXPORT int64_t FfiOHOSCreateAlphaPixelMap(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSCreateAlphaPixelMap start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return 0;
    }
    std::shared_ptr<PixelMap> ptr_ = instance->GetRealPixelMap();
    if (!ptr_) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("[PixelMap] ptr is nullptr!");
        return 0;
    }
    InitializationOptions opts;
    opts.pixelFormat = PixelFormat::ALPHA_8;
    auto tmpPixelMap = PixelMapImpl::CreateAlphaPixelMap(*ptr_, opts);
    if (!tmpPixelMap) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        IMAGE_LOGE("[PixelMap] tmpPixelMap is nullptr!");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(tmpPixelMap));
    if (!native) {
        IMAGE_LOGE("[ImageSource] FfiOHOSCreateAlphaPixelMap failed");
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    IMAGE_LOGD("[PixelMap] FfiOHOSCreateAlphaPixelMap success");
    *errCode = SUCCESS_CODE;
    return native->GetID();
}

FFI_EXPORT uint32_t FfiOHOSReadPixelsToBuffer(int64_t id, uint64_t bufferSize, uint8_t* dst)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSReadPixelsToBuffer start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->ReadPixelsToBuffer(bufferSize, dst);
    IMAGE_LOGD("[PixelMap] FfiOHOSReadPixelsToBuffer success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSWriteBufferToPixels(int64_t id, uint8_t* source, uint64_t bufferSize)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSWriteBufferToPixels start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->WriteBufferToPixels(source, bufferSize);
    IMAGE_LOGD("[PixelMap] FfiOHOSWriteBufferToPixels success");
    return ret;
}

FFI_EXPORT int32_t FfiOHOSGetDensity(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetDensity start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    int32_t ret = instance->GetDensity();
    *errCode = SUCCESS_CODE;
    IMAGE_LOGD("[PixelMap] FfiOHOSGetDensity success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSOpacity(int64_t id, float percent)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSOpacity start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->Opacity(percent);
    IMAGE_LOGD("[PixelMap] FfiOHOSOpacity success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSCrop(int64_t id, CRegion rect)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSCrop start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    Rect rt = ParseCRegion(rect);
    uint32_t ret = instance->Crop(rt);
    IMAGE_LOGD("[PixelMap] FfiOHOSCrop success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSGetPixelBytesNumber(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetPixelBytesNumber start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    uint32_t ret = instance->GetPixelBytesNumber();
    *errCode = SUCCESS_CODE;
    IMAGE_LOGD("[PixelMap] FfiOHOSGetPixelBytesNumber success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSGetBytesNumberPerRow(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetBytesNumberPerRow start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }
    uint32_t ret = instance->GetBytesNumberPerRow();
    *errCode = SUCCESS_CODE;
    IMAGE_LOGD("[PixelMap] FfiOHOSGetBytesNumberPerRow success");
    return ret;
}

FFI_EXPORT CImageInfo FfiOHOSGetImageInfo(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetImageInfo start");
    CImageInfo ret = {};
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ImageInfo info;
    instance->GetImageInfo(info);
    ret.height = info.size.height;
    ret.width = info.size.width;
    ret.density = info.baseDensity;
    IMAGE_LOGD("[PixelMap] FfiOHOSGetImageInfo success");
    return ret;
}

static CImageInfoV2 ParsePixelMapImageInfo(ImageInfo info, PixelMap* pixelMap)
{
    CImageInfoV2 ret = {};
    ret.height = info.size.height;
    ret.width = info.size.width;
    ret.density = info.baseDensity;
    ret.pixelFormat = static_cast<int32_t>(info.pixelFormat);
    ret.alphaType = static_cast<int32_t>(info.alphaType);
    ret.stride = static_cast<int32_t>(pixelMap->GetRowStride());
    ret.mimeType = Utils::MallocCString(info.encodedFormat);
    ret.isHdr = pixelMap->IsHdr();
    return ret;
}

FFI_EXPORT CImageInfoV2 FfiOHOSGetImageInfoV2(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetImageInfoV2 start");
    CImageInfoV2 ret = {};
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ImageInfo info;
    instance->GetImageInfo(info);
    ret = ParsePixelMapImageInfo(info, instance->GetRealPixelMap().get());
    IMAGE_LOGD("[PixelMap] FfiOHOSGetImageInfoV2 success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSScale(int64_t id, float xAxis, float yAxis)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSScale start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Scale(xAxis, yAxis);
    IMAGE_LOGD("[PixelMap] FfiOHOSScale success");
    return SUCCESS_CODE;
}

static AntiAliasingOption ParseAntiAliasingOption(int32_t val)
{
    if (val <= static_cast<int32_t>(AntiAliasingOption::SPLINE)) {
        return AntiAliasingOption(val);
    }
    return AntiAliasingOption::NONE;
}

FFI_EXPORT uint32_t FfiImagePixelMapImplScale(int64_t id, float xAxis, float yAxis, int32_t antiAliasing)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplScale start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    AntiAliasingOption option = ParseAntiAliasingOption(antiAliasing);
    instance->Scale(xAxis, yAxis, option);
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplScale success");
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSFlip(int64_t id, bool xAxis, bool yAxis)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSFlip start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Flip(xAxis, yAxis);
    IMAGE_LOGD("[PixelMap] FfiOHOSFlip success");
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSRotate(int64_t id, float degrees)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSRotate start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Rotate(degrees);
    IMAGE_LOGD("[PixelMap] FfiOHOSRotate success");
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSTranslate(int64_t id, float xAxis, float yAxis)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSTranslate start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->Translate(xAxis, yAxis);
    IMAGE_LOGD("[PixelMap] FfiOHOSTranslate success");
    return SUCCESS_CODE;
}

FFI_EXPORT uint32_t FfiOHOSReadPixels(int64_t id, CPositionArea area)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSReadPixels start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    Rect rt = ParseCRegion(area.region);
    uint32_t ret = instance->ReadPixels(area.bufferSize, area.offset, area.stride, rt, area.dst);
    IMAGE_LOGD("[PixelMap] FfiOHOSReadPixels success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSWritePixels(int64_t id, CPositionArea area)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSWritePixels start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    Rect rt = ParseCRegion(area.region);
    uint32_t ret = instance->WritePixels(area.dst, area.bufferSize, area.offset, area.stride, rt);
    IMAGE_LOGD("[PixelMap] FfiOHOSWritePixels success");
    return ret;
}

FFI_EXPORT bool FfiOHOSGetIsEditable(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetIsEditable start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    bool ret = false;
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ret = instance->GetIsEditable();
    *errCode = SUCCESS_CODE;
    IMAGE_LOGD("[PixelMap] FfiOHOSGetIsEditable success");
    return ret;
}

FFI_EXPORT bool FfiOHOSGetIsStrideAlignment(int64_t id, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSGetIsStrideAlignment start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    bool ret = false;
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return ret;
    }
    ret = instance->GetIsStrideAlignment();
    *errCode = SUCCESS_CODE;
    IMAGE_LOGD("[PixelMap] FfiOHOSGetIsStrideAlignment success");
    return ret;
}

FFI_EXPORT uint32_t FfiOHOSPixelMapSetColorSpace(int64_t id, int64_t colorSpaceId)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapSetColorSpace start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] PixelMapImpl instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(colorSpaceId);
    if (!colorSpace) {
        IMAGE_LOGE("[PixelMap] CjColorManager instance not exist %{public}" PRId64, colorSpaceId);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    uint32_t ret = instance->SetColorSpace(colorSpace->GetColorSpaceToken());
    IMAGE_LOGD("[PixelMap] FFfiOHOSPixelMapSetColorSpace success");
    return ret;
}

FFI_EXPORT int64_t FfiOHOSPixelMapGetColorSpace(int64_t id, int32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapGetColorSpace start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_DATA_ABNORMAL;
        return 0;
    }
    auto colorSpace = instance->GetColorSpace();
    if (!colorSpace) {
        *errCode = ERR_IMAGE_DATA_UNSUPPORT;
        return 0;
    }
    auto native = FFIData::Create<ColorManager::CjColorManager>(colorSpace);
    if (!native) {
        *errCode = ERR_IMAGE_INIT_ABNORMAL;
        return 0;
    }

    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapGetColorSpace success");
    *errCode = SUCCESS_CODE;
    return native->GetID();
}

FFI_EXPORT uint32_t FfiOHOSPixelMapApplyColorSpace(int64_t id, int64_t colorSpaceId)
{
    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapApplyColorSpace start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance || !instance->GetRealPixelMap()) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    auto colorSpace = FFIData::GetData<ColorManager::CjColorManager>(colorSpaceId);
    if (!colorSpace) {
        IMAGE_LOGE("[PixelMap] CjColorManager instance not exist %{public}" PRId64, colorSpaceId);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    uint32_t ret = instance->ApplyColorSpace(colorSpace->GetColorSpaceToken());
    IMAGE_LOGD("[PixelMap] FfiOHOSPixelMapApplyColorSpace success");
    return ret;
}

FFI_EXPORT uint32_t FfiImagePixelMapImplCreatePremultipliedPixelMap(int64_t srcId, int64_t dstId)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePremultipliedPixelMap start");
    auto src = FFIData::GetData<PixelMapImpl>(srcId);
    auto dst = FFIData::GetData<PixelMapImpl>(dstId);
    if (!src || !dst) {
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePremultipliedPixelMap success");
    return PixelMapImpl::CreatePremultipliedPixelMap(src->GetRealPixelMap(), dst->GetRealPixelMap());
}

FFI_EXPORT uint32_t FfiImagePixelMapImplCreateUnpremultipliedPixelMap(int64_t srcId, int64_t dstId)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreateUnpremultipliedPixelMap start");
    auto src = FFIData::GetData<PixelMapImpl>(srcId);
    auto dst = FFIData::GetData<PixelMapImpl>(dstId);
    if (!src || !dst) {
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreateUnpremultipliedPixelMap success");
    return PixelMapImpl::CreateUnpremultipliedPixelMap(src->GetRealPixelMap(), dst->GetRealPixelMap());
}

FFI_EXPORT uint32_t FfiImagePixelMapImplSetTransferDetached(int64_t id, bool detached)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplSetTransferDetached start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    instance->SetTransferDetach(detached);
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplSetTransferDetached success");
    return SUCCESS;
}

FFI_EXPORT uint32_t FfiImagePixelMapImplToSdr(int64_t id)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplToSdr start");
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (!instance) {
        IMAGE_LOGE("[PixelMap] instance not exist %{public}" PRId64, id);
        return ERR_IMAGE_INIT_ABNORMAL;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplToSdr success");
    return instance->ToSdr();
}

FFI_EXPORT uint32_t FfiImagePixelMapImplMarshalling(int64_t id, int64_t rpcId)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplMarshalling in");
    auto pixelMap = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMap) {
        IMAGE_LOGE("[PixelMap] pixelMap not exist %{public}" PRId64, id);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplMarshalling out");
    return pixelMap->Marshalling(rpcId);
}

FFI_EXPORT int64_t FfiImagePixelMapImplUnmarshalling(int64_t id, int64_t rpcId, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplUnmarshalling in");
    auto pixelMap = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMap) {
        IMAGE_LOGE("[PixelMap] pixelMap not exist %{public}" PRId64, id);
        *errCode = ERR_IMAGE_INVALID_PARAMETER;
        return 0;
    }
    auto retPixelMap = pixelMap->Unmarshalling(rpcId, *errCode);
    if (!retPixelMap) {
        IMAGE_LOGE("[PixelMap] retPixelMap is nullptr!");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(retPixelMap));
    if (!native) {
        IMAGE_LOGE("[PixelMap] native is nullptr!");
        *errCode = ERR_IMAGE_NAPI_ERROR;
        return 0;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplUnmarshalling out");
    return native->GetID();
}

FFI_EXPORT uint32_t FfiImagePixelMapImplConvertPixelMapFormat(int64_t id, int32_t targetFormat)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplConvertPixelMapFormat in");
    auto pixelMap = FFIData::GetData<PixelMapImpl>(id);
    if (!pixelMap) {
        IMAGE_LOGE("[PixelMap] pixelMap not exist %{public}" PRId64, id);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplConvertPixelMapFormat out");
    PixelFormat format = PixelFormat(targetFormat);
    return pixelMap->ConvertPixelMapFormat(format);
}

FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMapFromSurface(
    char* surfaceId, CRegion rect, size_t argc, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePixelMapFromSurface in");
    Rect rt = ParseCRegion(rect);
    auto pixelMap = PixelMapImpl::CreatePixelMapFromSurface(surfaceId, rt, argc, *errCode);
    if (!pixelMap) {
        IMAGE_LOGE("[PixelMap] pixelMap is nullptr!");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(pixelMap));
    if (!native) {
        IMAGE_LOGE("[PixelMap] native is nullptr!");
        *errCode = ERR_IMAGE_PIXELMAP_CREATE_FAILED;
        return 0;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePixelMapFromSurface out");
    return native->GetID();
}

FFI_EXPORT int64_t FfiImagePixelMapImplCreatePixelMapFromParcel(int64_t rpcId, uint32_t* errCode)
{
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePixelMapFromParcel in");
    auto pixelMap = PixelMapImpl::CreatePixelMapFromParcel(rpcId, *errCode);
    if (!pixelMap) {
        IMAGE_LOGE("[PixelMap] pixelMap is nullptr!");
        return 0;
    }
    auto native = FFIData::Create<PixelMapImpl>(move(pixelMap));
    if (!native) {
        IMAGE_LOGE("[PixelMap] native is nullptr!");
        *errCode = ERR_IMAGE_NAPI_ERROR;
        return 0;
    }
    IMAGE_LOGD("[PixelMap] FfiImagePixelMapImplCreatePixelMapFromParcel out");
    return native->GetID();
}

FFI_EXPORT napi_value FfiConvertPixelMap2Napi(napi_env env, uint64_t id)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    auto instance = FFIData::GetData<PixelMapImpl>(id);
    if (instance == nullptr || instance->GetRealPixelMap() == nullptr) {
        IMAGE_LOGE("[PixelMap]: instance not exist %{public}" PRId64, id);
        return undefined;
    }

    napi_value result = PixelMapNapi::CreatePixelMap(env, instance->GetRealPixelMap());
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, result, &type) != napi_ok || type == napi_undefined) {
        IMAGE_LOGE("[PixelMap]: create napiobj failed.");
        return undefined;
    }
    PixelMapNapi* pixelMapNapi = nullptr;
    napi_status status = napi_unwrap(env, result, reinterpret_cast<void**>(&pixelMapNapi));
    if (status != napi_ok || pixelMapNapi == nullptr) {
        IMAGE_LOGE("[PixelMap]: unwrap failed");
        return undefined;
    }
    pixelMapNapi->setPixelNapiEditable(instance->GetPixelMapImplEditable());
    pixelMapNapi->SetTransferDetach(instance->GetTransferDetach());
    return result;
}

FFI_EXPORT int64_t FfiCreatePixelMapFromNapi(napi_env env, napi_value pixelmap)
{
    if (env == nullptr || pixelmap == nullptr) {
        IMAGE_LOGE("[PixelMap]: parameter nullptr!");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, pixelmap, &type) != napi_ok || type != napi_object) {
        IMAGE_LOGE("[PixelMap]: parameter napi value type is not object!");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    PixelMapNapi* obj = nullptr;
    napi_status status = napi_unwrap(env, pixelmap, reinterpret_cast<void**>(&obj));
    if (status != napi_ok || obj == nullptr) {
        IMAGE_LOGE("[PixelMap]: unwrap failed");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    std::shared_ptr<PixelMap>* nativeObj = obj->GetPixelMap();
    if (nativeObj == nullptr) {
        IMAGE_LOGE("[PixelMap]: native pixelmap has released.");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    auto native = FFIData::Create<PixelMapImpl>(*nativeObj, obj->GetPixelNapiEditable(), obj->GetTransferDetach());
    if (native == nullptr) {
        IMAGE_LOGE("[PixelMap]: Create ffidata failed.");
        return ERR_IMAGE_INIT_ABNORMAL;
    }

    return native->GetID();
}
}
} // namespace Media
} // namespace OHOS