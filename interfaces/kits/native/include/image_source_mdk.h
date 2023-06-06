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
 * @brief Provides access image functions.
 *
 * @Syscap SystemCapability.Multimedia.Image
 * @since 11
 * @version 4.0
 */

/**
 * @file image_source_mdk.h
 *
 * @brief Declares function to decoding image source to pixel map.
 *
 * @since 11
 * @version 4.0
 */

#ifndef INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_SOURCE_MDK_H_
#define INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_SOURCE_MDK_H_
#include <cstdint>
#include "napi/native_api.h"
#include "image_mdk_common.h"
namespace OHOS {
namespace Media {
#ifdef __cplusplus
extern "C" {
#endif

struct ImageSourceNative_;

/**
 * @brief Defines native image source object for image source functions.
 *
 * @since 11
 * @version 4.0
 */
typedef struct ImageSourceNative_ ImageSourceNative;

/**
 * @brief Defines image property key of bits per sample
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_BITS_PER_SAMPLE = "BitsPerSample";

/**
 * @brief Defines image property key of orientation
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_ORIENTATION = "Orientation";

/**
 * @brief Defines image property key of image length
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_IMAGE_LENGTH = "ImageLength";

/**
 * @brief Defines image property key of image width
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_IMAGE_WIDTH = "ImageWidth";

/**
 * @brief Defines image property key of GPS latitude
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_GPS_LATITUDE = "GPSLatitude";

/**
 * @brief Defines image property key of GPS longitude
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_GPS_LONGITUDE = "GPSLongitude";

/**
 * @brief Defines image property key of GPS latitude ref
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_GPS_LATITUDE_REF = "GPSLatitudeRef";

/**
 * @brief Defines image property key of GPS longitude ref
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_GPS_LONGITUDE_REF = "GPSLongitudeRef";

/**
 * @brief Defines image property key of date time original
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_DATE_TIME_ORIGINAL = "DateTimeOriginal";

/**
 * @brief Defines image property key of exposure time
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_EXPOSURE_TIME = "ExposureTime";

/**
 * @brief Defines image property key of scene type
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_SCENE_TYPE = "SceneType";

/**
 * @brief Defines image property key of ISO speed ratings
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_ISO_SPEED_RATINGS = "ISOSpeedRatings";

/**
 * @brief Defines image property key of F number
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_F_NUMBER = "FNumber";

/**
 * @brief Defines image property key of compressed bits per pixel
 * for {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}.
 *
 * @since 11
 * @version 4.0
 */
const char* OHOS_IMAGE_PROPERTY_COMPRESSED_BITS_PER_PIXEL = "CompressedBitsPerPixel";

/**
 * @brief Defines image source decoding region options
 * {@link OhosImageDecodingOps}, {@link OH_ImageSource_CreatePixelMap} and
 * {@link OH_ImageSource_CreatePixelMapList}.
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageRegion {
    /** Start point x, in pixels. */
    int32_t x;
    /** Start point y, in pixels. */
    int32_t y;
    /** Region width, in pixels. */
    int32_t width;
    /** Region height, in pixels. */
    int32_t height;
};

/**
 * @brief Defines image source options infomation
 * {@link OH_ImageSource_Create} and {@link OH_ImageSource_CreateIncremental}.
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceOps {
    /** Image source pixel density. */
    int32_t density;
    /** Image source pixel format, used to describe YUV buffer usually. */
    int32_t pixelFormat;
    /** Image source pixel size of width and height. */
    struct OhosImageSize size;
};

/**
 * @brief Defines image source decoding options {@link OH_ImageSource_CreatePixelMap} and
 * {@link OH_ImageSource_CreatePixelMapList}.
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageDecodingOps {
    /** Defines output pixel map editable. */
    int8_t editable;
    /** Defines output pixel format. */
    int32_t pixelFormat;
    /** Defines decoding target pixel density. */
    int32_t fitDensity;
    /** Defines decoding index of image source. */
    uint32_t index;
    /** Defines decoding sample size option. */
    uint32_t sampleSize;
    /** Defines decoding rotate option. */
    uint32_t rotate;
    /** Defines decoding target pixel size of width and height. */
    struct OhosImageSize size;
    /** Defines image source pixel region for decoding. */
    struct OhosImageRegion region;
};

/**
 * @brief Defines image source information {@link OH_ImageSource_GetImageInfo}.
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceInfo {
    /** Image source pixel format, set by {@link OH_ImageSource_Create}.*/
    int32_t pixelFormat;
    /** Image source color space.*/
    int32_t colorSpace;
    /** Image source alpha type.*/
    int32_t alphaType;
    /** Image source density, set by {@link OH_ImageSource_Create}.*/
    int32_t density;
    /** Image source pixel size of width and height.*/
    struct OhosImageSize size;
};

/**
 * @brief Defines image source input resource, accept one type once only. {@link OH_ImageSource_Create}
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSource {
    /** Image source uri resource, accept file uri or base64 uri.*/
    char* uri = nullptr;
    /** Image source uri resource length.*/
    size_t uriSize = 0;
    /** Image source file descriptor resource.*/
    int32_t fd = -1;
    /** Image source buffer resource, accept formatted package buffer or base64 buffer.*/
    uint8_t* buffer = nullptr;
    /** Image source buffer resource.*/
    size_t bufferSize = 0;
};

/**
 * @brief Defines image source delay time list. {@link OH_ImageSource_GetDelayTime}
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceDelayTimeList {
    /** Image source delay time list head.*/
    int32_t* delayTimeList;
    /** Image source delay time list size.*/
    size_t size = 0;
};

/**
 * @brief Defines image source supported format string.
 * {@link OhosImageSourceSupportedFormatList} and {@link OH_ImageSource_GetSupportedFormats}
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceSupportedFormat {
    /** Image source supported format string head.*/
    char* format = nullptr;
    /** Image source supported format string size.*/
    size_t size = 0;
};

/**
 * @brief Defines image source supported format string list. {@link OH_ImageSource_GetSupportedFormats}
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceSupportedFormatList {
    /** Image source supported format string list head.*/
    struct OhosImageSourceSupportedFormat** supportedFormatList = nullptr;
    /** Image source supported format string list size.*/
    size_t size = 0;
};
/**
 * @brief Defines image source property key and value string.
 * {@link OH_ImageSource_GetImageProperty} and {@link OH_ImageSource_ModifyImageProperty}
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceProperty {
    /** Image source property key and value string head.*/
    char* value = nullptr;
    /** Image source property key and value string size.*/
    size_t size = 0;
};

/**
 * @brief Defines image source update data options. {@link OH_ImageSource_UpdateData}
 *
 * @since 11
 * @version 4.0
 */
struct OhosImageSourceUpdateData {
    /** Image source update data buffer.*/
    uint8_t* buffer = nullptr;
    /** Image source update data buffer size.*/
    size_t bufferSize = 0;
    /** Image source offset of update data buffer.*/
    uint32_t offset = 0;
    /** Image source update data length in update data buffer.*/
    uint32_t updateLength = 0;
    /** Image source update data is completed in this session.*/
    int8_t isCompleted = 0;
};

/**
 * @brief Obtains JavaScript Native API <b>ImageSource</b> object by a given infomations
 * {@link OhosImageSource} and {@link OhosImageSourceOps} structure.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param src Indicates infomations of creating a image source. For details, see {@link OhosImageSource}.
 * @param ops Indicates options for creating a image source. See {@link OhosImageSourceOps}.
 * @param res Indicates the pointer to JavaScript Native API <b>ImageSource</b> object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link OhosImageSource}, {@link OhosImageSourceOps}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_Create(napi_env env, struct OhosImageSource* src,
    struct OhosImageSourceOps* ops, napi_value *res);

/**
 * @brief Obtains JavaScript Native API <b>ImageSource</b> object for incremental type
 * by a given infomations {@link OhosImageSource} and {@link OhosImageSourceOps} structure, the
 * image data should updated by {@link OH_ImageSource_UpdateData}.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param src Indicates infomations of creating a image source, there only accept buffer type.
 * For details, see {@link OhosImageSource}.
 * @param ops Indicates options for creating a image source. See {@link OhosImageSourceOps}.
 * @param res Indicates the pointer to JavaScript Native API <b>ImageSource</b> object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link OhosImageSource}, {@link OhosImageSourceOps}, {@link OH_ImageSource_UpdateData}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_CreateIncremental(napi_env env, struct OhosImageSource* source,
    struct OhosImageSourceOps* ops, napi_value *res);

/**
 * @brief Get all the supported decoding format meta tags.
 *
 * @param res Indicates the pointer of list to <b>OhosImageSourceSupportedFormatList</b> structure.
 * when the <b>supportedFormatList</b> is nullptr and <b>size</b> is 0 in res as input, it will return the
 * supported formats size by <b>size</b> in res.
 * For getting all format tags, it needs enough space larger than result size in <b>supportedFormatList</b>,
 * and alse enough space for every <b>format</b> in {@link OhosImageSourceSupportedFormat} item.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link OhosImageSourceSupportedFormatList}, {@link OhosImageSourceSupportedFormat}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_GetSupportedFormats(struct OhosImageSourceSupportedFormatList* res);
/**
 * @brief Unwrap native {@link ImageSourceNative} value from input JavaScript Native API
 * <b>ImageSource</b> object.
 *
 * @param env Indicates the pointer to the JNI environment.
 * @param source Indicates JavaScript Native API <b>ImageSource</b> object.
 * @return Returns {@link ImageSourceNative} pointer if the operation is successful;
 * returns nullptr result if the operation fails.
 * @see {@link ImageSourceNative}, {@link OH_ImageSource_Release}
 * @since 11
 * @version 4.0
 */
ImageSourceNative* OH_ImageSource_InitNative(napi_env env, napi_value source);

/**
 * @brief Decoding the JavaScript Native API <b>PixelMap</b> object from <b>ImageSource</b>
 * by a given options {@link OhosImageDecodingOps}structure.
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param ops Indicates options for decoding the image source. See {@link OhosImageDecodingOps}.
 * @param res Indicates the pointer to JavaScript Native API <b>PixelMap</b> object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageDecodingOps}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_CreatePixelMap(const ImageSourceNative* native,
    struct OhosImageDecodingOps* ops, napi_value *res);

/**
 * @brief Decoding all the JavaScript Native API <b>PixelMap</b> object list from <b>ImageSource</b>
 * by a given options {@link OhosImageDecodingOps}structure.
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param ops Indicates options for decoding the image source. See {@link OhosImageDecodingOps}.
 * @param res Indicates the pointer to JavaScript Native API <b>PixelMap</b> list object.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageDecodingOps}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_CreatePixelMapList(const ImageSourceNative* native,
    struct OhosImageDecodingOps* ops, napi_value *res);

/**
 * @brief Get the delay time list from some <b>ImageSource</b> such as GIF image source
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param res Indicates the pointer to delay time list {@link OhosImageSourceDelayTimeList}.
 * when the <b>delayTimeList</b> is nullptr and <b>size</b> is 0 in res as input, it will return the
 * delay time list size by <b>size</b> in res.
 * For getting delay times, it needs enough space larger than result size in <b>delayTimeList</b>.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageSourceDelayTimeList}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_GetDelayTime(const ImageSourceNative* native,
    struct OhosImageSourceDelayTimeList* res);

/**
 * @brief Get the frame count from <b>ImageSource</b>
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param res Indicates the pointer to frame count.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_GetFrameCount(const ImageSourceNative* native, uint32_t *res);

/**
 * @brief Get the image source informations by index from <b>ImageSource</b>
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param index Indicates the frame index.
 * @param res Indicates the pointer to image source infomation {@link OhosImageSourceInfo}.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageSourceInfo}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_GetImageInfo(const ImageSourceNative* native, int32_t index,
    struct OhosImageSourceInfo* info);

/**
 * @brief Get the image source property by key from <b>ImageSource</b>
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param key Indicates the pointer to property key {@link OhosImageSourceProperty}
 * @param value Indicates the pointer to property value {@link OhosImageSourceProperty} as result.
 * when the <b>value</b> is nullptr and <b>size</b> is 0 in value as input, it will return the
 * property value size by <b>size</b> in value.
 * For getting property value, it needs enough space larger than result size in <b>value</b>.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageSourceProperty}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_GetImageProperty(const ImageSourceNative* native,
    struct OhosImageSourceProperty* key, struct OhosImageSourceProperty* value);

/**
 * @brief Modify the image source property by key for <b>ImageSource</b>
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param key Indicates the pointer to property key {@link OhosImageSourceProperty}
 * @param value Indicates the pointer to property value {@link OhosImageSourceProperty} for modify.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageSourceProperty}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_ModifyImageProperty(const ImageSourceNative* native,
    struct OhosImageSourceProperty* key, struct OhosImageSourceProperty* value);

/**
 * @brief Update source data for incremental type <b>ImageSource</b>
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @param data Indicates the pointer to update data informations {@link OhosImageSourceUpdateData}
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OhosImageSourceUpdateData}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_UpdateData(const ImageSourceNative* native, struct OhosImageSourceUpdateData* data);


/**
 * @brief Release native image source <b>ImageSourceNative</b>
 *
 * @param native Indicates the pointer to native {@link ImageSourceNative} value.
 * @return Returns {@link OHOS_IMAGE_RESULT_SUCCESS} if the operation is successful;
 * returns other result codes if the operation fails.
 * @see {@link ImageSourceNative}, {@link OH_ImageSource_Create}, {@link OH_ImageSource_CreateIncremental}
 * @since 11
 * @version 4.0
 */
int32_t OH_ImageSource_Release(ImageSourceNative* native);
#ifdef __cplusplus
};
#endif
/** @} */
} // namespace Media
} // namespace OHOS
#endif // INTERFACES_KITS_NATIVE_INCLUDE_IMAGE_SOURCE_MDK_H_