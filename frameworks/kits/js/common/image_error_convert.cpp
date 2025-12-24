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

#include "image_error_convert.h"

#include "image_common.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
std::pair<int32_t, std::string> ImageErrorConvert::CreatePictureAtIndexMakeErrMsg(uint32_t errorCode)
{
    switch (errorCode) {
        case ERR_IMAGE_SOURCE_DATA:
        case ERR_IMAGE_SOURCE_DATA_INCOMPLETE:
        case ERR_IMAGE_GET_DATA_ABNORMAL:
        case ERR_IMAGE_DATA_ABNORMAL:
            return std::make_pair<int32_t, std::string>(IMAGE_BAD_SOURCE, "Bad image source.");
        case ERR_IMAGE_MISMATCHED_FORMAT:
        case ERR_IMAGE_UNKNOWN_FORMAT:
        case ERR_IMAGE_DECODE_HEAD_ABNORMAL:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_MIMETYPE, "Unsupported mimetype.");
        case ERR_IMAGE_TOO_LARGE:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_TOO_LARGE, "Image too large.");
        case ERR_IMAGE_INVALID_PARAMETER:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_OPTIONS, "Unsupported options.");
        default:
            return std::make_pair<int32_t, std::string>(IMAGE_DECODE_FAILED, "Decode failed.");
    }
}

std::pair<int32_t, std::string> ImageErrorConvert::ModifyImagePropertiesEnhancedMakeErrMsg(uint32_t errorCode,
    std::string &exMessage)
{
    switch (errorCode) {
        case ERR_MEDIA_VALUE_INVALID:
        case ERR_IMAGE_DECODE_EXIF_UNSUPPORT:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_METADATA,
                "Unsupported metadata." + exMessage);
        case ERR_IMAGE_SOURCE_DATA:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_MIMETYPE,
                "Unsupported MIME type.");
        case ERR_MEDIA_WRITE_PARCEL_FAIL:
        default:
            return std::make_pair(ERR_IMAGE_WRITE_PROPERTY_FAILED,
                "Failed to write image properties to the file.");
    }
}

std::pair<int32_t, std::string> ImageErrorConvert::ModifyImagePropertyArrayMakeErrMsg(uint32_t errorCode,
    std::string exMessage)
{
    switch (errorCode) {
        case ERR_IMAGE_INVALID_PARAMETER:
        case ERR_MEDIA_VALUE_INVALID:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_INVALID_PARAMETER,
                "Invalid parameter.");
        case ERR_IMAGE_SOURCE_DATA:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_MIMETYPE,
                "unsupported mime type.");
        case ERR_MEDIA_WRITE_PARCEL_FAIL:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_MIMETYPE,
                "Failed to write EXIF data to the file. The file may be read-only or inaccessible.");
        case ERR_IMAGE_DECODE_EXIF_UNSUPPORT:
        default:
            return std::make_pair(IMAGE_SOURCE_UNSUPPORTED_METADATA,
                "unsupported metadata."  + exMessage);
    }
}

std::pair<int32_t, std::string> ImageErrorConvert::CreateThumbnailMakeErrMsg(uint32_t errorCode)
{
    switch (errorCode) {
        case ERR_IMAGE_MISMATCHED_FORMAT:
        case ERR_IMAGE_UNKNOWN_FORMAT:
        case ERR_IMAGE_DECODE_HEAD_ABNORMAL:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_UNSUPPORTED_MIMETYPE, "Unsupported mimetype.");
        case ERR_IMAGE_TOO_LARGE:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_TOO_LARGE, "Image too large.");
        case ERR_IMAGE_INVALID_PARAMETER:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_INVALID_PARAMETER, "Unsupported options.");
        case ERR_NOT_CARRY_THUMBNAIL:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_NOT_CARRY_THUMBNAIL, "not carry thumbnail.");
        case ERR_GENERATE_THUMBNAIL_FAILED:
            return std::make_pair<int32_t, std::string>(IMAGE_SOURCE_GENERATE_THUMBNAIL_FAILED,
                "Generate thumbnail failed.");
        default:
            return std::make_pair<int32_t, std::string>(IMAGE_DECODE_FAILED, "Decode failed.");
    }
}
}  // namespace Media
}  // namespace OHOS
