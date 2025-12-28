/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "image_napi_utils.h"
#include <securec.h>
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include <unistd.h>
#include "image_log.h"
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM) && defined(HICHECKER_ENABLE)
#include "hichecker.h"
#endif

namespace OHOS {
namespace Media {
const size_t NUM0 = 0;
const size_t NUM1 = 1;
const int DEFAULT_CAPACITY = 3;
const int DEFAULT_WIDTH = 1920;
const int DEFAULT_HEIGHT = 1080;
const int ARGS0 = 0;
const int ARGS1 = 1;
const int ARGS3 = 3;
const int ARGS4 = 4;
const int PARAM0 = 0;
const int PARAM1 = 1;
const int PARAM2 = 2;
const int PARAM3 = 3;

bool ImageNapiUtils::GetBufferByName(napi_env env, napi_value root, const char* name, void **res, size_t* len)
{
    napi_value tempValue = nullptr;

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_named_property(env, root, name, &tempValue)), false);

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_arraybuffer_info(env, tempValue, res, len)), false);

    return true;
}

bool ImageNapiUtils::GetUint32ByName(napi_env env, napi_value root, const char* name, uint32_t *res)
{
    napi_value tempValue = nullptr;

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_named_property(env, root, name, &tempValue)), false);

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_value_uint32(env, tempValue, res)), false);

    return true;
}

bool ImageNapiUtils::GetInt32ByName(napi_env env, napi_value root, const char* name, int32_t *res)
{
    napi_value tempValue = nullptr;

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_named_property(env, root, name, &tempValue)), false);

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_value_int32(env, tempValue, res)), false);

    return true;
}

bool ImageNapiUtils::GetDoubleByName(napi_env env, napi_value root, const char* name, double *res)
{
    napi_value tempValue = nullptr;

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_named_property(env, root, name, &tempValue)), false);

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_value_double(env, tempValue, res)), false);

    return true;
}

bool ImageNapiUtils::GetBoolByName(napi_env env, napi_value root, const char* name, bool *res)
{
    napi_value tempValue = nullptr;

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_named_property(env, root, name, &tempValue)), false);

    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_value_bool(env, tempValue, res)), false);

    return true;
}

bool ImageNapiUtils::GetNodeByName(napi_env env, napi_value root, const char* name, napi_value *res)
{
    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_named_property(env, root, name, res)), false);

    return true;
}

bool ImageNapiUtils::GetUtf8String(napi_env env, napi_value root, std::string &res, bool eof)
{
    size_t bufferSize = NUM0;
    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_value_string_utf8(env, root, nullptr,
        NUM0, &bufferSize)) && bufferSize > NUM0, false);

    size_t resultSize = NUM0;
    if (eof) {
        bufferSize = bufferSize + NUM1;
    }
    std::vector<char> buffer(bufferSize);
    IMG_NAPI_CHECK_RET(IMG_IS_OK(napi_get_value_string_utf8(env, root, &(buffer[NUM0]),
        bufferSize, &resultSize)) && resultSize > NUM0, false);
    res.assign(buffer.begin(), buffer.end());
    return true;
}

bool ImageNapiUtils::CreateArrayBuffer(napi_env env, void* src, size_t srcLen, napi_value *res)
{
    if (src == nullptr || srcLen == 0) {
        return false;
    }

    void *nativePtr = nullptr;
    if (napi_create_arraybuffer(env, srcLen, &nativePtr, res) != napi_ok || nativePtr == nullptr) {
        return false;
    }

    if (memcpy_s(nativePtr, srcLen, src, srcLen) != EOK) {
        return false;
    }
    return true;
}

bool ImageNapiUtils::CreateNapiInt32(napi_env env, int32_t value, napi_value &root)
{
    if (napi_create_int32(env, value, &root) != napi_ok) {
        return false;
    }
    return true;
}

bool ImageNapiUtils::CreateNapiDouble(napi_env env, double value, napi_value &root)
{
    if (napi_create_double(env, value, &root) != napi_ok) {
        return false;
    }
    return true;
}

napi_valuetype ImageNapiUtils::getType(napi_env env, napi_value root)
{
    napi_valuetype res = napi_undefined;
    napi_typeof(env, root, &res);
    return res;
}

static bool ParseSize(napi_env env, napi_value root, int32_t &width, int32_t &height)
{
    if (!GET_INT32_BY_NAME(root, "width", width) || !GET_INT32_BY_NAME(root, "height", height)) {
        return false;
    }
    return true;
}

static bool ParseImageReceiverOptions(napi_env env, napi_value options,
    int32_t &width, int32_t &height, int32_t &capacity)
{
    napi_value sizeObj = nullptr;
    if (!GET_NODE_BY_NAME(options, "size", sizeObj)) {
        IMAGE_LOGD("no size in options");
        width = DEFAULT_WIDTH;
        height = DEFAULT_HEIGHT;
    } else {
        if (!ParseSize(env, sizeObj, width, height)) {
            IMAGE_LOGD("ParseSize error");
            return false;
        }
        IMAGE_LOGD("size: width=%{public}d, height=%{public}d", width, height);
    }
    if (!GET_INT32_BY_NAME(options, "capacity", capacity)) {
        capacity = DEFAULT_CAPACITY;
    }
    return true;
}

static bool ParseImageCreatorReceiverArgsInner(napi_env env, size_t argc,
    napi_value argv[], int32_t args[], std::string &errMsg)
{
    if (argc == ARGS0) {
        args[PARAM0] = DEFAULT_WIDTH;
        args[PARAM1] = DEFAULT_HEIGHT;
        args[PARAM2] = DEFAULT_CAPACITY;
    } else {
        napi_valuetype type = ImageNapiUtils::getType(env, argv[PARAM0]);
        if (type != napi_object || !ParseImageReceiverOptions(env, argv[PARAM0],
            args[PARAM0], args[PARAM1], args[PARAM2])) {
            errMsg = "Invalid arg ";
            errMsg.append(std::to_string(PARAM0)).append(",type:").append(std::to_string(type));
            return false;
        }
    }
    return true;
}

bool ImageNapiUtils::ParseImageCreatorReceiverArgs(napi_env env, size_t argc,
    napi_value argv[], int32_t args[], std::string &errMsg)
{
    if ((argc != ARGS0) && (argc != ARGS1) && (argc != ARGS3) && (argc != ARGS4)) {
        errMsg = "Invalid arg counts ";
        errMsg.append(std::to_string(argc));
        return false;
    }
    if (argc == ARGS0 || argc == ARGS1) {
        return ParseImageCreatorReceiverArgsInner(env, argc, argv, args, errMsg);
    }
    if (argc == ARGS3) {
        napi_valuetype argvType0 = ImageNapiUtils::getType(env, argv[PARAM0]);
        if (argvType0 != napi_object || !ParseSize(env, argv[PARAM0], args[PARAM0], args[PARAM1])) {
            errMsg = "Invalid arg ";
            errMsg.append(std::to_string(PARAM0)).append(",type:").append(std::to_string(argvType0));
            return false;
        }
        napi_valuetype argvType1 = ImageNapiUtils::getType(env, argv[PARAM1]);
        if (argvType1 != napi_number || napi_get_value_int32(env, argv[PARAM1], &(args[PARAM2])) != napi_ok) {
            errMsg = "Invalid arg ";
            errMsg.append(std::to_string(PARAM1)).append(",type:").append(std::to_string(argvType1));
            return false;
        }
        napi_valuetype argvType2 = ImageNapiUtils::getType(env, argv[PARAM2]);
        if (argvType2 != napi_number || napi_get_value_int32(env, argv[PARAM2], &(args[PARAM3])) != napi_ok) {
            errMsg = "Invalid arg ";
            errMsg.append(std::to_string(PARAM2)).append(",type:").append(std::to_string(argvType2));
            return false;
        }
        return true;
    }
    for (size_t i = PARAM0; i < argc; i++) {
        napi_valuetype argvType = ImageNapiUtils::getType(env, argv[i]);
        if (argvType != napi_number) {
            errMsg = "Invalid arg ";
            errMsg.append(std::to_string(i)).append(" type ").append(std::to_string(argvType));
            return false;
        }

        napi_status status = napi_get_value_int32(env, argv[i], &(args[i]));
        if (status != napi_ok) {
            errMsg = "fail to get arg ";
            errMsg.append(std::to_string(i)).append(" : ").append(std::to_string(status));
            return false;
        }
    }
    return true;
}

const std::set<AuxiliaryPictureType> &ImageNapiUtils::GetNapiSupportedAuxiliaryPictureType()
{
    static const std::set<AuxiliaryPictureType> auxTypes = {
        AuxiliaryPictureType::GAINMAP,
        AuxiliaryPictureType::DEPTH_MAP,
        AuxiliaryPictureType::UNREFOCUS_MAP,
        AuxiliaryPictureType::LINEAR_MAP,
        AuxiliaryPictureType::FRAGMENT_MAP,
        AuxiliaryPictureType::THUMBNAIL,
    };
    return auxTypes;
}

void ImageNapiUtils::HicheckerReport()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM) && defined(HICHECKER_ENABLE)
    uint32_t pid = getpid();
    uint32_t tid = gettid();
    std::string cautionMsg = "Trigger: pid = " + std::to_string(pid) + ", tid = " + std::to_string(tid);
    HiviewDFX::HiChecker::NotifySlowProcess(cautionMsg);
#endif
}

void ImageNapiUtils::CreateErrorObj(napi_env env, napi_value &errorObj,
    const int32_t errCode, const std::string errMsg)
{
    napi_value outErrorCode = nullptr;
    napi_value outErrorMsg = nullptr;
    napi_status status = napi_create_string_utf8(env, std::to_string(errCode).c_str(),
        NAPI_AUTO_LENGTH, &outErrorCode);
    if (status != napi_ok) {
        return;
    }

    status = napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &outErrorMsg);
    if (status != napi_ok) {
        return;
    }

    status = napi_create_error(env, outErrorCode, outErrorMsg, &errorObj);
    if (status != napi_ok) {
        napi_get_undefined(env, &errorObj);
    }
}

napi_value ImageNapiUtils::ThrowExceptionError(napi_env env, const int32_t errCode,
    const std::string errMsg)
{
    napi_value result = nullptr;
    napi_status status = napi_throw_error(env, std::to_string(errCode).c_str(), errMsg.c_str());
    if (status == napi_ok) {
        napi_get_undefined(env, &result);
    }
    return result;
}

void ImageNapiUtils::CleanUpConstructorContext(void* data)
{
    if (data == nullptr) {
        return;
    }
    auto ctorContext = reinterpret_cast<NapiConstructorContext*>(data);
    napi_delete_reference(ctorContext->env_, ctorContext->ref_);
    ctorContext->env_ = nullptr;
    ctorContext->ref_ = nullptr;
    delete ctorContext;
}

bool ImageNapiUtils::IsSystemApp()
{
    static bool isSys = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetSelfTokenID());
    return isSys;
}
}  // namespace Media
}  // namespace OHOS
