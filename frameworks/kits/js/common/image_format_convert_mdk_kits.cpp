/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "image_format_convert_mdk_kits.h"
#include <map>
#include <memory>
#include "image_mdk_common.h"
#include "pixel_map_napi.h"
#include "common_utils.h"
#include "hilog/log.h"
#include "log_tags.h"

namespace OHOS {
namespace Media {
using OHOS::HiviewDFX::HiLog;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_TAG_DOMAIN_ID_IMAGE, "ImageFormatConvertMdk"};

using ImageConvertFunc = int32_t(*)(ImageFormatConvertArgs*);

#ifdef __cplusplus
extern "C" {
#endif

static bool IsMatchType(int32_t type, PixelFormat format)
{
    if (type == YUV_TYPE) {
        switch (format) {
            case PixelFormat::NV21:
            case PixelFormat::NV12:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else if (type == RGB_TYPE) {
        switch (format) {
            case PixelFormat::ARGB_8888:
            case PixelFormat::RGB_565:
            case PixelFormat::RGBA_8888:
            case PixelFormat::BGRA_8888:
            case PixelFormat::RGB_888:
            case PixelFormat::RGBA_F16:{
                return true;
            }
            default:{
                return false;
            }
        }
    } else {
        return false;
    }
}

static int32_t ImageConvertExec(ImageFormatConvertArgs *args)
{
    if (args == nullptr || args->srcPixelMap == nullptr) {
        HiLog::Error(LABEL, "parameter is invalid!");
        return IMAGE_RESULT_INVALID_PARAMETER;
    }

    PixelFormat srcPixelFormat = args->srcPixelMap->GetPixelFormat();
    if (!IsMatchType(args->srcFormatType, srcPixelFormat) ||
        !IsMatchType(args->destFormatType, args->destPixelFormat)) {
        HiLog::Error(LABEL, "format mismatch");
        return IMAGE_RESULT_INVALID_PARAMETER;
    }

    uint32_t ret = ImageFormatConvert::ConvertImageFormat(args->srcPixelMap, args->destPixelFormat);
    if (ret != IMAGE_RESULT_SUCCESS) {
        HiLog::Error(LABEL, "fail to convert format");
        return ret;
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageConvertJsToCPixelMap(ImageFormatConvertArgs *args)
{
    if (args == nullptr) {
        HiLog::Error(LABEL, "parameter is invalid!");
        return IMAGE_RESULT_INVALID_PARAMETER;
    }

    args->srcPixelMap = PixelMapNapi::GetPixelMap(args->env, args->pixelMapValue);
    if (args->srcPixelMap == nullptr) {
        return IMAGE_RESULT_MEDIA_NULL_POINTER;
    }
    return IMAGE_RESULT_SUCCESS;
}

static int32_t ImageConvertCToJsPixelMap(ImageFormatConvertArgs *args)
{
    if (args == nullptr || args->destPixelMap == nullptr || args->result == nullptr) {
        HiLog::Error(LABEL, "parameter is invalid!");
        return IMAGE_RESULT_INVALID_PARAMETER;
    }

    napi_get_undefined(args->env, args->result);
    *(args->result) = PixelMapNapi::CreatePixelMap(args->env, args->destPixelMap);
    napi_valuetype valueType;
    napi_typeof(args->env, *(args->result), &valueType);
    if (valueType != napi_object) {
        return IMAGE_RESULT_MEDIA_JNI_NEW_OBJ_FAILED;
    }
    return IMAGE_RESULT_SUCCESS;
}

static const std::map<int32_t, ImageConvertFunc> g_Functions = {
    {CTX_FUNC_IMAGE_CONVERT_EXEC, ImageConvertExec},
    {CTX_FUNC_IMAGE_CONVERT_JS_TO_C_PIXEL_MAP, ImageConvertJsToCPixelMap},
    {CTX_FUNC_IMAGE_CONVERT_C_TO_JS_PIXEL_MAP, ImageConvertCToJsPixelMap}
};

MIDK_EXPORT
int32_t ImageConvertNativeCall(int32_t mode, ImageFormatConvertArgs *args)
{
    auto funcSearch = g_Functions.find(mode);
    if (funcSearch == g_Functions.end()) {
        return IMAGE_RESULT_INVALID_PARAMETER;
    }
    return funcSearch->second(args);
}

#ifdef __cplusplus
};
#endif
} // Media
} // OHOS