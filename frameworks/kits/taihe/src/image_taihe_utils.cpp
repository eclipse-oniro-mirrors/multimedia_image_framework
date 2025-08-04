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

#include "image_log.h"
#include "image_taihe_utils.h"

namespace ANI::Image {
constexpr char CLASS_NAME_BUSINESSERROR[] = "L@ohos/base/BusinessError;";

void ImageTaiheUtils::HicheckerReport()
{
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM) && defined(HICHECKER_ENABLE)
    uint32_t pid = getpid();
    uint32_t tid = gettid();
    std::string cautionMsg = "Trigger: pid = " + std::to_string(pid) + ", tid = " + std::to_string(tid);
    HiviewDFX::HiChecker::NotifySlowProcess(cautionMsg);
#endif
}

void ImageTaiheUtils::ThrowExceptionError(const std::string &errMsg)
{
    IMAGE_LOGE("errMsg: %{public}s", errMsg.c_str());
    taihe::set_error(errMsg);
}

void ImageTaiheUtils::ThrowExceptionError(const int32_t errCode, const std::string &errMsg)
{
    IMAGE_LOGE("errCode: %{public}d, errMsg: %{public}s", errCode, errMsg.c_str());
    taihe::set_business_error(errCode, errMsg);
}

bool ImageTaiheUtils::GetPropertyInt(ani_env *env, ani_object obj, const std::string &name, int32_t &value)
{
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr || obj == nullptr, false, "%{public}s param is nullptr", __func__);
    ani_int result {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_GetPropertyByName_Int(obj, name.c_str(), &result), false,
        "%{public}s Object_GetPropertyByName_Int failed.", __func__);
    value = static_cast<int32_t>(result);
    return true;
}

bool ImageTaiheUtils::GetPropertyLong(ani_env *env, ani_object obj, const std::string &name, int64_t &value)
{
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr || obj == nullptr, false, "%{public}s param is nullptr", __func__);
    ani_long result {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_GetPropertyByName_Long(obj, name.c_str(), &result), false,
        "%{public}s Object_GetPropertyByName_Long failed.", __func__);
    value = static_cast<int64_t>(result);
    return true;
}

bool ImageTaiheUtils::GetPropertyDouble(ani_env *env, ani_object obj, const std::string &name, double &value)
{
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr || obj == nullptr, false, "%{public}s param is nullptr", __func__);
    ani_double result {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_GetPropertyByName_Double(obj, name.c_str(), &result), false,
        "%{public}s Object_GetPropertyByName_Long failed.", __func__);
    value = static_cast<double>(result);
    return true;
}

ani_object ImageTaiheUtils::ToBusinessError(ani_env *env, int32_t code, const std::string &message)
{
    ani_object err {};
    ani_class cls {};
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr, nullptr, "get_env failed");
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->FindClass(CLASS_NAME_BUSINESSERROR, &cls), err,
        "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
    ani_method ctor {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":V", &ctor), err,
        "find method BusinessError constructor failed");
    ani_object error {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->Object_New(cls, ctor, &error), err,
        "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
    CHECK_ERROR_RETURN_RET_LOG(
        ANI_OK != env->Object_SetPropertyByName_Double(error, "code", static_cast<ani_double>(code)), err,
        "set property BusinessError.code failed");
    ani_string messageRef {};
    CHECK_ERROR_RETURN_RET_LOG(ANI_OK != env->String_NewUTF8(message.c_str(), message.size(), &messageRef), err,
        "new message string failed");
    CHECK_ERROR_RETURN_RET_LOG(
        ANI_OK != env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)), err,
        "set property BusinessError.message failed");
    return error;
}

OHOS::Media::SourceOptions ImageTaiheUtils::ParseSourceOptions(SourceOptions const& options)
{
    OHOS::Media::SourceOptions opts {};
    opts.baseDensity = options.sourceDensity;
    OHOS::Media::PixelFormat pixelFormat = OHOS::Media::PixelFormat::UNKNOWN;
    if (options.sourcePixelFormat.has_value()) {
        pixelFormat = static_cast<OHOS::Media::PixelFormat>(options.sourcePixelFormat->get_value());
    }
    opts.pixelFormat = pixelFormat;
    OHOS::Media::Size size {};
    if (options.sourceSize.has_value()) {
        size.width = options.sourceSize.value().width;
        size.height = options.sourceSize.value().height;
    }
    opts.size = size;
    return opts;
}

ImageInfo ImageTaiheUtils::ToTaiheImageInfo(const OHOS::Media::ImageInfo &src, bool isHdr)
{
    Size size {
        .width = src.size.width,
        .height = src.size.height,
    };

    PixelMapFormat::key_t pixelFormatKey;
    GetEnumKeyByValue<PixelMapFormat>(static_cast<int32_t>(src.pixelFormat), pixelFormatKey);
    AlphaType::key_t alphaTypeKey;
    GetEnumKeyByValue<AlphaType>(static_cast<int32_t>(src.alphaType), alphaTypeKey);

    ImageInfo result {
        .size = size,
        .pixelFormat = PixelMapFormat(pixelFormatKey),
        .alphaType = AlphaType(alphaTypeKey),
        .mimeType = src.encodedFormat,
        .isHdr = isHdr,
    };
    return result;
}

array<string> ImageTaiheUtils::ToTaiheArrayString(const std::vector<std::string> &src)
{
    std::vector<::taihe::string> vec;
    for (const auto &item : src) {
        vec.emplace_back(item);
    }
    return array<string>(vec);
}

array<uint8_t> ImageTaiheUtils::CreateTaiheArrayBuffer(uint8_t* src, size_t srcLen)
{
    if (src == nullptr || srcLen == 0) {
        return array<uint8_t>(0);
    }
    return array<uint8_t>(copy_data_t{}, src, srcLen);
}

uintptr_t ImageTaiheUtils::GetUndefinedPtr(ani_env *env)
{
    ani_ref undefinedRef {};
    env->GetUndefined(&undefinedRef);
    ani_object undefinedObj = static_cast<ani_object>(undefinedRef);
    return reinterpret_cast<uintptr_t>(undefinedObj);
}

OHOS::MessageParcel* ImageTaiheUtils::UnwrapMessageParcel(uintptr_t sequence)
{
    ani_env* env = get_env();
    CHECK_ERROR_RETURN_RET_LOG(env == nullptr, nullptr, "get_env failed");
    ani_long messageParcel{};
    ani_status status = env->Object_CallMethodByName_Long(reinterpret_cast<ani_object>(sequence), "getNativePtr",
        nullptr, &messageParcel);
    if (status != ANI_OK) {
        IMAGE_LOGE("UnwrapMessageParcel failed, status: %{public}d", status);
        return nullptr;
    }
    return reinterpret_cast<OHOS::MessageParcel*>(messageParcel);
}

template <typename EnumType, typename ValueType>
bool ImageTaiheUtils::GetEnumKeyByValue(ValueType value, typename EnumType::key_t &key)
{
    for (size_t index = 0; index < std::size(EnumType::table); ++index) {
        if (EnumType::table[index] == value) {
            key = static_cast<typename EnumType::key_t>(index);
            return true;
        }
    }
    return false;
}

template <typename T>
bool ImageTaiheUtils::IsValidPtr(T data)
{
    return !data.is_error();
}

template
bool ImageTaiheUtils::GetEnumKeyByValue<ImageFormat, int32_t>(int32_t value, typename ImageFormat::key_t &key);

template
bool ImageTaiheUtils::GetEnumKeyByValue<PixelMapFormat, int32_t>(int32_t value, typename PixelMapFormat::key_t &key);

template
bool ImageTaiheUtils::GetEnumKeyByValue<AlphaType, int32_t>(int32_t value, typename AlphaType::key_t &key);

template
bool ImageTaiheUtils::GetEnumKeyByValue<PropertyKey, std::string>(std::string value, typename PropertyKey::key_t &key);

template
bool ImageTaiheUtils::GetEnumKeyByValue<AuxiliaryPictureType, int32_t>(int32_t value,
    typename AuxiliaryPictureType::key_t &key);

template
bool ImageTaiheUtils::GetEnumKeyByValue<ComponentType, int32_t>(int32_t value, typename ComponentType::key_t &key);

template
bool ImageTaiheUtils::IsValidPtr<weak::PixelMap>(weak::PixelMap data);

template
bool ImageTaiheUtils::IsValidPtr<weak::ImageSource>(weak::ImageSource data);

template
bool ImageTaiheUtils::IsValidPtr<weak::Picture>(weak::Picture data);
} // namespace ANI::Image