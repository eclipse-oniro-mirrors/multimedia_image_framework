/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_INCLUDE_MEDIA_ERRORS_H
#define INTERFACES_INNERKITS_INCLUDE_MEDIA_ERRORS_H

#include <cstdint>
#include "errors.h"
#include "modules.h"

namespace OHOS {
namespace Media {
constexpr int32_t BASE_MEDIA_ERR_OFFSET = ErrCodeOffset(SUBSYS_MULTIMEDIA, MODULE_MEDIA);

/* Media defined errors */
const int32_t ERR_MEDIA_INVALID_VALUE = -1;                                    // invalid size
const uint32_t SUCCESS = 0;                                                    // Operation success
const uint32_t ERROR = BASE_MEDIA_ERR_OFFSET;                                  // Operation failed
const uint32_t ERR_IPC = BASE_MEDIA_ERR_OFFSET + 1;                            // ipc error
const uint32_t ERR_SHAMEM_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 2;               // sharememory error
const uint32_t ERR_SHAMEM_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 3;           // sharememory error
const uint32_t ERR_IMAGE_DECODE_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 4;          // image decode error
const uint32_t ERR_IMAGE_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 5;            // image input data error
const uint32_t ERR_IMAGE_MALLOC_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 6;          // image malloc error
const uint32_t ERR_IMAGE_DATA_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 7;           // image type unsupported
const uint32_t ERR_IMAGE_INIT_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 8;            // image init error
const uint32_t ERR_IMAGE_GET_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 9;        // image get data error
const uint32_t ERR_IMAGE_TOO_LARGE = BASE_MEDIA_ERR_OFFSET + 10;               // image data too large
const uint32_t ERR_IMAGE_TRANSFORM = BASE_MEDIA_ERR_OFFSET + 11;               // image transform error
const uint32_t ERR_IMAGE_COLOR_CONVERT = BASE_MEDIA_ERR_OFFSET + 12;           // image color convert error
const uint32_t ERR_IMAGE_CROP = BASE_MEDIA_ERR_OFFSET + 13;                    // crop error
const uint32_t ERR_IMAGE_SOURCE_DATA = BASE_MEDIA_ERR_OFFSET + 14;             // image source data error
const uint32_t ERR_IMAGE_SOURCE_DATA_INCOMPLETE = BASE_MEDIA_ERR_OFFSET + 15;  // image source data incomplete
const uint32_t ERR_IMAGE_MISMATCHED_FORMAT = BASE_MEDIA_ERR_OFFSET + 16;       // image mismatched format
const uint32_t ERR_IMAGE_UNKNOWN_FORMAT = BASE_MEDIA_ERR_OFFSET + 17;          // image unknown format
const uint32_t ERR_IMAGE_SOURCE_UNRESOLVED = BASE_MEDIA_ERR_OFFSET + 18;       // image source unresolved
const uint32_t ERR_IMAGE_INVALID_PARAMETER = BASE_MEDIA_ERR_OFFSET + 19;       // image invalid parameter
const uint32_t ERR_IMAGE_DECODE_FAILED = BASE_MEDIA_ERR_OFFSET + 20;           // decode fail
const uint32_t ERR_IMAGE_PLUGIN_REGISTER_FAILED = BASE_MEDIA_ERR_OFFSET + 21;  // register plugin fail
const uint32_t ERR_IMAGE_PLUGIN_CREATE_FAILED = BASE_MEDIA_ERR_OFFSET + 22;    // create plugin fail
const uint32_t ERR_IMAGE_ENCODE_FAILED = BASE_MEDIA_ERR_OFFSET + 23;           // image encode fail
const uint32_t ERR_IMAGE_ADD_PIXEL_MAP_FAILED = BASE_MEDIA_ERR_OFFSET + 24;    // image add pixel map fail
const uint32_t ERR_IMAGE_HW_DECODE_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 25;     // image hardware decode unsupported
const uint32_t ERR_IMAGE_DECODE_HEAD_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 26;    // image decode head error
const uint32_t ERR_IMAGE_DECODE_EXIF_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 27;   // image decode exif unsupport
const uint32_t ERR_IMAGE_PROPERTY_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 28;     // image property not exist

const uint32_t ERR_IMAGE_DESIRED_PIXELFORMAT_UNSUPPORTED = BASE_MEDIA_ERR_OFFSET + 29; // desired format unsupported
const int32_t ERR_MEDIA_DATA_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 30;               // media type unsupported
const int32_t ERR_MEDIA_TOO_LARGE = BASE_MEDIA_ERR_OFFSET + 31;                    // media data too large
const int32_t ERR_MEDIA_MALLOC_FAILED = BASE_MEDIA_ERR_OFFSET + 32;                // media malloc memory failed
const int32_t ERR_MEDIA_END_OF_STREAM = BASE_MEDIA_ERR_OFFSET + 33;                // media end of stream error
const int32_t ERR_MEDIA_IO_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 34;                  // media io error
const int32_t ERR_MEDIA_MALFORMED = BASE_MEDIA_ERR_OFFSET + 35;                    // media malformed error
const int32_t ERR_MEDIA_BUFFER_TOO_SMALL = BASE_MEDIA_ERR_OFFSET + 36;             // media buffer too small error
const int32_t ERR_MEDIA_OUT_OF_RANGE = BASE_MEDIA_ERR_OFFSET + 37;                 // media out of range error
const int32_t ERR_MEDIA_STATUS_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 38;              // media status abnormal error
const int32_t ERR_MEDIA_VALUE_INVALID = BASE_MEDIA_ERR_OFFSET + 39;                // media value invalid
const int32_t ERR_MEDIA_NULL_POINTER = BASE_MEDIA_ERR_OFFSET + 40;                 // media error operation
const int32_t ERR_MEDIA_INVALID_OPERATION = BASE_MEDIA_ERR_OFFSET + 41;            // media invalid operation
const int32_t ERR_PLAYER_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 42;                    // media init error
const int32_t ERR_MEDIA_EARLY_PREPARE = BASE_MEDIA_ERR_OFFSET + 43;                // media early prepare
const int32_t ERR_MEDIA_SEEK_ERR = BASE_MEDIA_ERR_OFFSET + 44;                     // media rewind error
const int32_t ERR_MEDIA_PERMISSION_DENIED = BASE_MEDIA_ERR_OFFSET + 45;            // media permission denied
const int32_t ERR_MEDIA_DEAD_OBJECT = BASE_MEDIA_ERR_OFFSET + 46;                  // media dead object
const int32_t ERR_MEDIA_TIMED_OUT = BASE_MEDIA_ERR_OFFSET + 47;                    // media time out
const int32_t ERR_MEDIA_TRACK_NOT_ALL_SUPPORTED = BASE_MEDIA_ERR_OFFSET + 48;      // media track subset support
const int32_t ERR_RECORDER_ADAPTER_INIT_FAILED = BASE_MEDIA_ERR_OFFSET + 49;       // media recorder adapter init failed
const int32_t ERR_MEDIA_WRITE_PARCEL_FAIL = BASE_MEDIA_ERR_OFFSET + 50;            // write parcel failed
const int32_t ERR_MEDIA_READ_PARCEL_FAIL = BASE_MEDIA_ERR_OFFSET + 51;             // read parcel failed
const int32_t ERR_MEDIA_NO_AVAIL_BUFFER = BASE_MEDIA_ERR_OFFSET + 52;              // read parcel failed
const int32_t ERR_MEDIA_INVALID_PARAM = BASE_MEDIA_ERR_OFFSET + 53;                // media function found invalid param
const int32_t ERR_MEDIA_CODEC_ADAPTER_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 54;      // media zcodec adapter not init
const int32_t ERR_MEDIA_CREATE_CODEC_ADAPTER_FAILED = BASE_MEDIA_ERR_OFFSET + 55;  // media create zcodec adapter failed
const int32_t ERR_MEDIA_CODEC_ADAPTER_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 56;       // media adapter inner not init
const int32_t ERR_MEDIA_ZCODEC_CREATE_FAILED = BASE_MEDIA_ERR_OFFSET + 57;         // media adapter inner not init
const int32_t ERR_MEDIA_ZCODEC_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 58;             // media zcodec not exist
const int32_t ERR_MEDIA_JNI_CLASS_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 59;          // media jni class not found
const int32_t ERR_MEDIA_JNI_METHOD_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 60;         // media jni method not found
const int32_t ERR_MEDIA_JNI_NEW_OBJ_FAILED = BASE_MEDIA_ERR_OFFSET + 61;           // media jni obj new failed
const int32_t ERR_MEDIA_JNI_COMMON_ERROR = BASE_MEDIA_ERR_OFFSET + 62;             // media jni normal error
const int32_t ERR_MEDIA_DISTRIBUTE_NOT_SUPPORT = BASE_MEDIA_ERR_OFFSET + 63;       // media distribute not support
const int32_t ERR_MEDIA_SOURCE_NOT_SET = BASE_MEDIA_ERR_OFFSET + 64;               // media source not set
const int32_t ERR_MEDIA_RTSP_ADAPTER_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 65;        // media rtsp adapter not init
const int32_t ERR_MEDIA_RTSP_ADAPTER_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 66;       // media rtsp adapter not exist
const int32_t ERR_MEDIA_RTSP_SURFACE_UNSUPPORT = BASE_MEDIA_ERR_OFFSET + 67;       // media rtsp surface not support
const int32_t ERR_MEDIA_RTSP_CAPTURE_NOT_INIT = BASE_MEDIA_ERR_OFFSET + 68;        // media rtsp capture init error
const int32_t ERR_MEDIA_RTSP_SOURCE_URL_INVALID = BASE_MEDIA_ERR_OFFSET + 69;      // media rtsp source url invalid
const int32_t ERR_MEDIA_RTSP_VIDEO_TRACK_NOT_FOUND = BASE_MEDIA_ERR_OFFSET + 70;   // media rtsp can't find video track
const int32_t ERR_MEDIA_RTSP_CAMERA_NUM_REACH_MAX = BASE_MEDIA_ERR_OFFSET + 71;    // rtsp camera num reach to max num
const int32_t ERR_MEDIA_SET_VOLUME = BASE_MEDIA_ERR_OFFSET + 72;                   // media set volume error
const int32_t ERR_MEDIA_NUMBER_OVERFLOW = BASE_MEDIA_ERR_OFFSET + 73;              // media number operation overflow
const int32_t ERR_MEDIA_DIS_PLAYER_UNSUPPORTED = BASE_MEDIA_ERR_OFFSET + 74;  // media distribute player unsupporteded
const uint32_t ERR_IMAGE_DENCODE_ICC_FAILED = BASE_MEDIA_ERR_OFFSET + 75;          // image dencode ICC fail
const uint32_t ERR_IMAGE_ENCODE_ICC_FAILED = BASE_MEDIA_ERR_OFFSET + 76;           // image encode ICC fail
const int32_t ERR_DMA_NOT_EXIST = BASE_MEDIA_ERR_OFFSET + 77;
const int32_t ERR_DMA_DATA_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 78;
const int32_t ERR_SURFACEBUFFER_REFERENCE_FAILED = BASE_MEDIA_ERR_OFFSET + 79;
const int32_t ERR_SURFACEBUFFER_UNREFERENCE_FAILED = BASE_MEDIA_ERR_OFFSET + 80;
const uint32_t ERR_IMAGE_NAPI_ERROR = BASE_MEDIA_ERR_OFFSET + 81; // napi environmental abnormality
const uint32_t ERR_IMAGE_PIXELMAP_CREATE_FAILED = BASE_MEDIA_ERR_OFFSET + 82; // pixelmap create failed
// unmarshalling bufferSize parcelling error
const uint32_t ERR_IMAGE_BUFFER_SIZE_PARCEL_ERROR = BASE_MEDIA_ERR_OFFSET + 83;
const uint32_t ERR_IMAGE_GET_FD_BAD = BASE_MEDIA_ERR_OFFSET + 84; // fd acquisition failed
const uint32_t ERR_IMAGE_AI_UNSUPPORTED = BASE_MEDIA_ERR_OFFSET + 85;
const uint32_t ERR_IMAGE_AI_ONLY_SR_SUCCESS = BASE_MEDIA_ERR_OFFSET + 86;
const uint32_t ERR_IMAGE_AI_UNNECESSARY = BASE_MEDIA_ERR_OFFSET + 87;

const uint32_t ERR_IMAGE_READ_PIXELMAP_FAILED = BASE_MEDIA_ERR_OFFSET + 150; // read pixelmap failed
const uint32_t ERR_IMAGE_WRITE_PIXELMAP_FAILED = BASE_MEDIA_ERR_OFFSET + 151; // write pixelmap failed
const uint32_t ERR_IMAGE_PIXELMAP_NOT_ALLOW_MODIFY = BASE_MEDIA_ERR_OFFSET + 152; // pixelmap not allow modify
const uint32_t ERR_IMAGE_CONFIG_FAILED = BASE_MEDIA_ERR_OFFSET + 153; // config error
const uint32_t IMAGE_RESULT_JNI_ENV_ABNORMAL = BASE_MEDIA_ERR_OFFSET + 154; // Abnormal JNI environment
const uint32_t IMAGE_RESULT_SURFAC_GRALLOC_BUFFER_FAILED = BASE_MEDIA_ERR_OFFSET + 155; // gralloc buffer failed
const uint32_t IMAGE_RESULT_CREATE_SURFAC_FAILED = BASE_MEDIA_ERR_OFFSET + 156; // create graphicsurface failed
// Failed to obtain parameters for graphicsurface
const uint32_t IMAGE_RESULT_SURFAC_GET_PARAMETER_FAILED = BASE_MEDIA_ERR_OFFSET + 157;
const uint32_t IMAGE_RESULT_GET_SURFAC_FAILED = BASE_MEDIA_ERR_OFFSET + 158; // get graphicsurface failed
const uint32_t IMAGE_RESULT_SURFAC_ACQUIRE_BUFFER_FAILED = BASE_MEDIA_ERR_OFFSET + 159; // Acquire Buffer failed
const uint32_t IMAGE_RESULT_SURFAC_REQUEST_BUFFER_FAILED = BASE_MEDIA_ERR_OFFSET + 160; // request Buffer failed
const uint32_t IMAGE_RESULT_REGISTER_LISTENER_FAILED = BASE_MEDIA_ERR_OFFSET + 161; // Failed to register listener
const uint32_t IMAGE_RESULT_REGISTER_BUFFER_FAILED = BASE_MEDIA_ERR_OFFSET + 162; // Failed to register buffer
const uint32_t IMAGE_RESULT_FREAD_FAILED = BASE_MEDIA_ERR_OFFSET + 163; // read file failed
const uint32_t IMAGE_RESULT_PEEK_FAILED = BASE_MEDIA_ERR_OFFSET + 164; // peek file failed
const uint32_t IMAGE_RESULT_SEEK_FAILED = BASE_MEDIA_ERR_OFFSET + 165; // seek file failed
const uint32_t IMAGE_RESULT_STREAM_SIZE_ERROR = BASE_MEDIA_ERR_OFFSET + 166; // stream bad
const uint32_t IMAGE_RESULT_FILE_FD_ERROR = BASE_MEDIA_ERR_OFFSET + 167; // file fd is bad
const uint32_t IMAGE_RESULT_FILE_DAMAGED = BASE_MEDIA_ERR_OFFSET + 168; // file damaged
const uint32_t IMAGE_RESULT_CREATE_DECODER_FAILED = BASE_MEDIA_ERR_OFFSET + 169; // create decoder failed
const uint32_t IMAGE_RESULT_CREATE_ENCODER_FAILED = BASE_MEDIA_ERR_OFFSET + 170; // create encoder failed
const uint32_t IMAGE_RESULT_CHECK_FORMAT_ERROR = BASE_MEDIA_ERR_OFFSET + 171; // check format failed
const uint32_t IMAGE_RESULT_THIRDPART_THIRDPARTSKIA_ERROR = BASE_MEDIA_ERR_OFFSET + 172; // thirdpartskia error
const uint32_t IMAGE_RESULT_HW_DECODE_FAILED = BASE_MEDIA_ERR_OFFSET + 173; // hard decode failed
const uint32_t IMAGE_RESULT_ALLOCATER_TYPE_ERROR = BASE_MEDIA_ERR_OFFSET + 174; // hard decode failed
const uint32_t IMAGE_RESULT_ALPHA_TYPE_ERROR = BASE_MEDIA_ERR_OFFSET + 175; // hard decode failed
const uint32_t IMAGE_RESULT_INDEX_INVALID = BASE_MEDIA_ERR_OFFSET + 176; // invalid index
const uint32_t IMAGE_RESULT_SAVE_DATA_TO_FILE_FAILED = BASE_MEDIA_ERR_OFFSET + 177; // save data to file failed
const uint32_t ERR_EXIF_DECODE_FAILED = BASE_MEDIA_ERR_OFFSET + 178; // exif decode fail

const int32_t ERR_MEDIA_UNKNOWN = BASE_MEDIA_ERR_OFFSET + 200;  // media unknown error
const int32_t ERR_RESOURCE_UNAVAILABLE = 501; // Resource Unavailable
const int32_t COMMON_ERR_INVALID_PARAMETER = 401; // Common error，Invalid parameter
const int32_t ERR_MEDIA_NO_EXIF_DATA = 402; // no exif_data info
}  // namespace Media
}  // namespace OHOS
#endif  // INTERFACES_INNERKITS_INCLUDE_MEDIA_ERRORS_H
