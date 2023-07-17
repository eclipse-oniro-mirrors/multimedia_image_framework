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

/**
 * @addtogroup image
 * @{
 *
 * @brief Provides APIs for access to the image interface.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 10
 * @version 2.0
 */

/**
 * @file image_mdk_common.h
 *
 * @brief Declares the common enums and structs used by the image interface.
 *
 * @since 10
 * @version 2.0
 */

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_COMMON_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_COMMON_H_
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerates the return values that may be used by the interface.
 *
 * @since 10
 * @version 2.0
 */
enum {
    IMAGE_RESULT_SUCCESS = 0,                                          // Operation success
    IMAGE_RESULT_BAD_PARAMETER = -1,                                   // Invalid parameter
    IMAGE_RESULT_BASE_MEDIA_ERR_OFFSET = BASE_MEDIA_ERR_OFFSET,        // Operation failed
    IMAGE_RESULT_ERR_IPC = BASE_MEDIA_ERR_OFFSET + 1,                  // ipc error
    IMAGE_RESULT_ERR_SHAMEM_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 2,     // sharememory error
    IMAGE_RESULT_ERR_SHAMEM_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 3, // sharememory error
    IMAGE_RESULT_DECODE_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 4,          // image decode error
    IMAGE_RESULT_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 5,            // image input data error
    IMAGE_RESULT_MALLOC_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 6,          // image malloc error
    IMAGE_RESULT_DATA_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 7,           // image type unsupported
    IMAGE_RESULT_INIT_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 8,            // image init error
    IMAGE_RESULT_GET_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 9,        // image get data error
    IMAGE_RESULT_TOO_LARGE = BASE_MEDIA_ERR_OFFSET + 10,               // image data too large
    IMAGE_RESULT_TRANSFORM = BASE_MEDIA_ERR_OFFSET + 11,               // image transform error
    IMAGE_RESULT_COLOR_CONVERT = BASE_MEDIA_ERR_OFFSET + 12,           // image color convert error
    IMAGE_RESULT_CROP = BASE_MEDIA_ERR_OFFSET + 13,                    // crop error
    IMAGE_RESULT_SOURCE_DATA = BASE_MEDIA_ERR_OFFSET + 14,             // image source data error
    IMAGE_RESULT_SOURCE_DATA_INCOMPLETE = BASE_MEDIA_ERR_OFFSET + 15,  // image source data incomplete
    IMAGE_RESULT_MISMATCHED_FORMAT = BASE_MEDIA_ERR_OFFSET + 16,       // image mismatched format
    IMAGE_RESULT_UNKNOWN_FORMAT = BASE_MEDIA_ERR_OFFSET + 17,          // image unknown format
    IMAGE_RESULT_SOURCE_UNRESOLVED = BASE_MEDIA_ERR_OFFSET + 18,       // image source unresolved
    IMAGE_RESULT_INVALID_PARAMETER = BASE_MEDIA_ERR_OFFSET + 19,       // image invalid parameter
    IMAGE_RESULT_DECODE_FAILED = BASE_MEDIA_ERR_OFFSET + 20,           // decode fail
    IMAGE_RESULT_PLUGIN_REGISTER_FAILED = BASE_MEDIA_ERR_OFFSET + 21,  // register plugin fail
    IMAGE_RESULT_PLUGIN_CREATE_FAILED = BASE_MEDIA_ERR_OFFSET + 22,    // create plugin fail
    IMAGE_RESULT_ENCODE_FAILED = BASE_MEDIA_ERR_OFFSET + 23,           // image encode fail
    IMAGE_RESULT_ADD_PIXEL_MAP_FAILED = BASE_MEDIA_ERR_OFFSET + 24,    // image add pixel map fail
    IMAGE_RESULT_HW_DECODE_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 25,     // image hardware decode unsupported
    IMAGE_RESULT_DECODE_HEAD_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 26,    // image decode head error
    IMAGE_RESULT_DECODE_EXIF_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 27,   // image decode exif unsupport
    IMAGE_RESULT_PROPERTY_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 28,      // image property not exist
    
    IMAGE_RESULT_MEDIA_DATA_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 30,               // media type unsupported
    IMAGE_RESULT_MEDIA_TOO_LARGE = BASE_MEDIA_ERR_OFFSET + 31,                    // media data too large
    IMAGE_RESULT_MEDIA_MALLOC_FAILED = BASE_MEDIA_ERR_OFFSET + 32,                // media malloc memory failed
    IMAGE_RESULT_MEDIA_END_OF_STREAM = BASE_MEDIA_ERR_OFFSET + 33,                // media end of stream error
    IMAGE_RESULT_MEDIA_IO_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 34,                  // media io error
    IMAGE_RESULT_MEDIA_MALFORMED = BASE_MEDIA_ERR_OFFSET + 35,                    // media malformed error
    IMAGE_RESULT_MEDIA_BUFFER_TOO_SMALL = BASE_MEDIA_ERR_OFFSET + 36,             // media buffer too small error
    IMAGE_RESULT_MEDIA_OUT_OF_RANGE = BASE_MEDIA_ERR_OFFSET + 37,                 // media out of range error
    IMAGE_RESULT_MEDIA_STATUS_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 38,              // media status abnormal error
    IMAGE_RESULT_MEDIA_VALUE_INVALID = BASE_MEDIA_ERR_OFFSET + 39,                // media value invalid
    IMAGE_RESULT_MEDIA_NULL_POINTER = BASE_MEDIA_ERR_OFFSET + 40,                 // media error operation
    IMAGE_RESULT_MEDIA_INVALID_OPERATION = BASE_MEDIA_ERR_OFFSET + 41,            // media invalid operation
    IMAGE_RESULT_MEDIA_ERR_PLAYER_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 42,          // media init error
    IMAGE_RESULT_MEDIA_EARLY_PREPARE = BASE_MEDIA_ERR_OFFSET + 43,                // media early prepare
    IMAGE_RESULT_MEDIA_SEEK_ERR = BASE_MEDIA_ERR_OFFSET + 44,                     // media rewind error
    IMAGE_RESULT_MEDIA_PERMISSION_DENIED = BASE_MEDIA_ERR_OFFSET + 45,            // media permission denied
    IMAGE_RESULT_MEDIA_DEAD_OBJECT = BASE_MEDIA_ERR_OFFSET + 46,                  // media dead object
    IMAGE_RESULT_MEDIA_TIMED_OUT = BASE_MEDIA_ERR_OFFSET + 47,                    // media time out
    IMAGE_RESULT_MEDIA_TRACK_NOT_ALL_SUPPORTED = BASE_MEDIA_ERR_OFFSET + 48,      // media track subset support
    IMAGE_RESULT_MEDIA_ADAPTER_INIT_FAILED = BASE_MEDIA_ERR_OFFSET + 49,                // media recorder adapter init failed
    IMAGE_RESULT_MEDIA_WRITE_PARCEL_FAIL = BASE_MEDIA_ERR_OFFSET + 50,            // write parcel failed
    IMAGE_RESULT_MEDIA_READ_PARCEL_FAIL = BASE_MEDIA_ERR_OFFSET + 51,             // read parcel failed
    IMAGE_RESULT_MEDIA_NO_AVAIL_BUFFER = BASE_MEDIA_ERR_OFFSET + 52,              // read parcel failed
    IMAGE_RESULT_MEDIA_INVALID_PARAM = BASE_MEDIA_ERR_OFFSET + 53,                // media function found invalid param
    IMAGE_RESULT_MEDIA_CODEC_ADAPTER_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 54,      // media zcodec adapter not init
    IMAGE_RESULT_MEDIA_CREATE_CODEC_ADAPTER_FAILED = BASE_MEDIA_ERR_OFFSET + 55,  // media create zcodec adapter failed
    IMAGE_RESULT_MEDIA_CODEC_ADAPTER_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 56,       // media adapter inner not init
    IMAGE_RESULT_MEDIA_ZCODEC_CREATE_FAILED = BASE_MEDIA_ERR_OFFSET + 57,         // media adapter inner not init
    IMAGE_RESULT_MEDIA_ZCODEC_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 58,             // media zcodec not exist
    IMAGE_RESULT_MEDIA_JNI_CLASS_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 59,          // media jni class not found
    IMAGE_RESULT_MEDIA_JNI_METHOD_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 60,         // media jni method not found
    IMAGE_RESULT_MEDIA_JNI_NEW_OBJ_FAILED = BASE_MEDIA_ERR_OFFSET + 61,           // media jni obj new failed
    IMAGE_RESULT_MEDIA_JNI_COMMON_ERROR = BASE_MEDIA_ERR_OFFSET + 62,             // media jni normal error
    IMAGE_RESULT_MEDIA_DISTRIBUTE_NOT_SUPPORT = BASE_MEDIA_ERR_OFFSET + 63,       // media distribute not support
    IMAGE_RESULT_MEDIA_SOURCE_NOT_SET = BASE_MEDIA_ERR_OFFSET + 64,               // media source not set
    IMAGE_RESULT_MEDIA_RTSP_ADAPTER_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 65,        // media rtsp adapter not init
    IMAGE_RESULT_MEDIA_RTSP_ADAPTER_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 66,       // media rtsp adapter not exist
    IMAGE_RESULT_MEDIA_RTSP_SURFACE_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 67,       // media rtsp surface not support
    IMAGE_RESULT_MEDIA_RTSP_CAPTURE_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 68,        // media rtsp capture init error
    IMAGE_RESULT_MEDIA_RTSP_SOURCE_URL_INVALID = BASE_MEDIA_ERR_OFFSET + 69,      // media rtsp source url invalid
    IMAGE_RESULT_MEDIA_RTSP_VIDEO_TRACK_NOT_FOUND = BASE_MEDIA_ERR_OFFSET + 70,   // media rtsp can't find video track
    IMAGE_RESULT_MEDIA_RTSP_CAMERA_NUM_REACH_MAX = BASE_MEDIA_ERR_OFFSET + 71,    // rtsp camera num reach to max num
    IMAGE_RESULT_MEDIA_SET_VOLUME = BASE_MEDIA_ERR_OFFSET + 72,                   // media set volume error
    IMAGE_RESULT_MEDIA_NUMBER_OVERFLOW = BASE_MEDIA_ERR_OFFSET + 73,              // media number operation overflow
    IMAGE_RESULT_MEDIA_DIS_PLAYER_UNSUPPORTED = BASE_MEDIA_ERR_OFFSET + 74,       // media distribute player unsupporteded
    IMAGE_RESULT_MEDIA_DENCODE_ICC_FAILED = BASE_MEDIA_ERR_OFFSET + 75,           // image dencode ICC fail
    IMAGE_RESULT_MEDIA_ENCODE_ICC_FAILED = BASE_MEDIA_ERR_OFFSET + 76,            // image encode ICC fail
	
	IMAGE_RESULT_MEDIA_READ_PIXELMAP_FAILED = BASE_MEDIA_ERR_OFFSET + 150,        // read pixelmap failed
    IMAGE_RESULT_MEDIA_WRITE_PIXELMAP_FAILED = BASE_MEDIA_ERR_OFFSET + 151,       // write pixelmap failed
    IMAGE_RESULT_MEDIA_PIXELMAP_NOT_ALLOW_MODIFY = BASE_MEDIA_ERR_OFFSET + 152,   // pixelmap not allow modify
    IMAGE_RESULT_MEDIA_CONFIG_FAILED = BASE_MEDIA_ERR_OFFSET + 153,               // config error
	IMAGE_RESULT_MEDIA_UNKNOWN = BASE_MEDIA_ERR_OFFSET + 200,                     // media unknown error
};

/**
 * @brief Defines the image size.
 *
 * @since 10
 * @version 2.0
 */
struct OhosImageSize {
    /** Image width, in pixels. */
    int32_t width;
    /** Image height, in pixels. */
    int32_t height;
};

#ifdef __cplusplus
};
#endif
/** @} */

#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_COMMON_H_