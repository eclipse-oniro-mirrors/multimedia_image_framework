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

#include "ani_color_space_object_convertor.h"
#include "image_common.h"
#include "image_dfx.h"
#include "image_error_convert.h"
#include "image_log.h"
#include "image_source_taihe.h"
#include "image_source_taihe_ani.h"
#include "image_taihe_utils.h"
#include "image_trace.h"
#include "image_type.h"
#include "media_errors.h"
#include "picture_taihe.h"
#include "pixel_map_taihe.h"
#include "exif_metadata_formatter.h"
#include "xmp_metadata_taihe.h"

using namespace ANI::Image;
using JpegYuvDecodeError = OHOS::ImagePlugin::JpegYuvDecodeError;

namespace {
    constexpr int INVALID_FD = -1;
    constexpr uint32_t NUM_0 = 0;
}

namespace ANI::Image {
static const std::string FILE_URL_PREFIX = "file://";
thread_local std::string ImageSourceImpl::filePath_ = "";
thread_local int ImageSourceImpl::fileDescriptor_ = -1;
thread_local void* ImageSourceImpl::fileBuffer_ = nullptr;
thread_local size_t ImageSourceImpl::fileBufferSize_ = 0;

static std::mutex imageSourceCrossThreadMutex_;

struct ImageSourceTaiheContext {
    ImageSourceImpl *thisPtr;
    uint32_t status;
    std::string pathName = "";
    int fdIndex = INVALID_FD;
    void* sourceBuffer = nullptr;
    size_t sourceBufferSize = NUM_0;
    std::string keyStr;
    std::string valueStr;
    std::vector<std::string> keyStrArray;
    std::vector<std::pair<std::string, std::string>> kVStrArray;
    std::string defaultValueStr;
    void *updataBuffer = nullptr;
    size_t updataBufferSize = NUM_0;
    uint32_t updataBufferOffset = NUM_0;
    uint32_t updataLength = NUM_0;
    bool isCompleted = false;
    bool isSuccess = false;
    uint32_t index = 0;
    bool isBatch = false;
    OHOS::Media::DecodeOptions decodeOpts;
    std::shared_ptr<OHOS::Media::ImageSource> rImageSource;
    std::shared_ptr<OHOS::Media::PixelMap> rPixelMap;
    std::string errMsg;
    std::multimap<std::int32_t, std::string> errMsgArray;
    std::unique_ptr<std::vector<std::unique_ptr<OHOS::Media::PixelMap>>> pixelMaps;
    std::unique_ptr<std::vector<int32_t>> delayTimes;
#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
    OHOS::Media::DecodingOptionsForPicture decodingOptsForPicture;
    std::shared_ptr<OHOS::Media::Picture> rPicture;
#endif
    OHOS::Media::DecodingOptionsForThumbnail decodingOptsForThumbnail;
};

static const std::map<int32_t, Image_ErrorCode> ERROR_CODE_MAP = {
    {OHOS::Media::ERR_IMAGE_INVALID_PARAMETER, Image_ErrorCode::IMAGE_BAD_PARAMETER},
    {OHOS::Media::COMMON_ERR_INVALID_PARAMETER, Image_ErrorCode::IMAGE_BAD_PARAMETER},
    {JpegYuvDecodeError::JpegYuvDecodeError_InvalidParameter, Image_ErrorCode::IMAGE_BAD_PARAMETER},
    {OHOS::Media::ERR_IMAGE_SOURCE_DATA, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {OHOS::Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {OHOS::Media::ERR_IMAGE_GET_DATA_ABNORMAL, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {OHOS::Media::ERR_IMAGE_DATA_ABNORMAL, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {OHOS::Media::ERROR, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {JpegYuvDecodeError::JpegYuvDecodeError_BadImage, Image_ErrorCode::IMAGE_BAD_SOURCE},
    {OHOS::Media::ERR_IMAGE_MISMATCHED_FORMAT, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE},
    {OHOS::Media::ERR_IMAGE_UNKNOWN_FORMAT, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE},
    {OHOS::Media::ERR_IMAGE_DECODE_HEAD_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE},
    {OHOS::Media::ERR_IMAGE_TOO_LARGE, Image_ErrorCode::IMAGE_SOURCE_TOO_LARGE},
    {OHOS::Media::ERR_MEDIA_INVALID_OPERATION, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE},
    {OHOS::Media::IMAGE_RESULT_FORMAT_CONVERT_FAILED, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {OHOS::Media::ERR_MEDIA_FORMAT_UNSUPPORT, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {OHOS::Media::ERR_IMAGE_PIXELMAP_CREATE_FAILED, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {JpegYuvDecodeError::JpegYuvDecodeError_ConvertError, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {OHOS::Media::ERR_IMAGE_CROP, Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS},
    {OHOS::Media::ERR_IMAGE_DECODE_FAILED, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {OHOS::Media::ERR_IMAGE_DECODE_ABNORMAL, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {OHOS::Media::ERR_IMAGE_PLUGIN_CREATE_FAILED, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {JpegYuvDecodeError::JpegYuvDecodeError_DecodeFailed, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {JpegYuvDecodeError::JpegYuvDecodeError_MemoryNotEnoughToSaveResult, Image_ErrorCode::IMAGE_DECODE_FAILED},
    {OHOS::Media::ERR_IMAGE_MALLOC_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {OHOS::Media::ERR_IMAGE_DATA_UNSUPPORT, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {OHOS::Media::ERR_DMA_NOT_EXIST, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {OHOS::Media::ERR_DMA_DATA_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED},
    {OHOS::Media::ERR_SHAMEM_DATA_ABNORMAL, Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED}
};

static const std::map<Image_ErrorCode, std::string> ERROR_CODE_MESSAGE_MAP = {
    {Image_ErrorCode::IMAGE_BAD_PARAMETER, "Parameter error. Possible causes:"
        "1.Mandatory parameters are left unspecified. 2.Incorrect parameter types. 3.Parameter verification failed."},
    {Image_ErrorCode::IMAGE_BAD_SOURCE, "Bad source. e.g.,1.Image has invalid width or height."
        "2.Image source incomplete. 3.Read image data failed. 4. Codec create failed."
        "5.The sourceOption specifies an odd width, causing the YUV420 PixelMap conversion to RGBA failed."},
    {Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_MIMETYPE, "Unsupported mimetype."},
    {Image_ErrorCode::IMAGE_SOURCE_TOO_LARGE, "Image too large."},
    {Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE, "Unsupported allocator type. e.g.,"
        "use share memory to decode a HDR image as only DMA supported hdr metadata."},
    {Image_ErrorCode::IMAGE_SOURCE_UNSUPPORTED_OPTIONS, "Unsupported options. e.g.,"
        "1.Convert image into desired pixelFormat failed. 2.Crop pixelMap failed."},
    {Image_ErrorCode::IMAGE_DECODE_FAILED, "Decode failed. e.g.,Decode image header failed."},
    {Image_ErrorCode::IMAGE_SOURCE_ALLOC_FAILED, "Memory allocation failed."}
};

static Image_ErrorCode ConvertToErrorCode(int32_t errorCode)
{
    Image_ErrorCode apiErrorCode = Image_ErrorCode::IMAGE_DECODE_FAILED;
    auto iter = ERROR_CODE_MAP.find(errorCode);
    if (iter != ERROR_CODE_MAP.end()) {
        apiErrorCode = iter->second;
    }
    return apiErrorCode;
}

static std::string GetErrorCodeMsg(Image_ErrorCode apiErrorCode)
{
    std::string errMsg = "Decode failed.";
    auto iter = ERROR_CODE_MESSAGE_MAP.find(apiErrorCode);
    if (iter != ERROR_CODE_MESSAGE_MAP.end()) {
        errMsg = iter->second;
    }
    return errMsg;
}

ImageSourceImpl::ImageSourceImpl() {}

ImageSourceImpl::ImageSourceImpl(std::shared_ptr<OHOS::Media::ImageSource> imageSource)
{
    nativeImgSrc = imageSource;
}

ImageSourceImpl::ImageSourceImpl(std::shared_ptr<OHOS::Media::ImageSource> imageSource,
    std::shared_ptr<OHOS::Media::IncrementalPixelMap> incPixelMap)
{
    nativeImgSrc = imageSource;
    navIncPixelMap_ = incPixelMap;
}

ImageSourceImpl::ImageSourceImpl(int64_t aniPtr)
{
    OHOS::Media::ImageSourceTaiheAni *imageSourceAni = reinterpret_cast<OHOS::Media::ImageSourceTaiheAni *>(aniPtr);
    if (imageSourceAni != nullptr && imageSourceAni->nativeImgSrc != nullptr) {
        nativeImgSrc = imageSourceAni->nativeImgSrc;
    } else {
        ImageTaiheUtils::ThrowExceptionError("aniPtr is invalid or nativeImgSrc is nullptr");
    }
}

ImageSourceImpl::~ImageSourceImpl()
{
    ReleaseSync();
}

int64_t ImageSourceImpl::GetImplPtr()
{
    return static_cast<int64_t>(reinterpret_cast<uintptr_t>(this));
}

optional<ImageInfo> ImageSourceImpl::GetImageInfoWithIndexCallback(int32_t index)
{
    return GetImageInfoInner(::taihe::optional<int32_t>::make(index), false);
}

optional<ImageInfo> ImageSourceImpl::GetImageInfoWithCallback()
{
    return GetImageInfoInner(::taihe::optional<int32_t>::make(), false);
}

optional<ImageInfo> ImageSourceImpl::GetImageInfoReturnsPromise(optional_view<int32_t> index)
{
    return GetImageInfoInner(index, false);
}

optional<ImageInfo> ImageSourceImpl::GetImageInfoSync(optional_view<int32_t> index)
{
    return GetImageInfoInner(index, true);
}

optional<ImageInfo> ImageSourceImpl::GetImageInfoInner(optional_view<int32_t> index, bool isSync)
{
    optional<ImageInfo> res = optional<ImageInfo>(std::nullopt);

    if (nativeImgSrc == nullptr) {
        IMAGE_LOGE("nativeImgSrc is nullptr");
        return res;
    }

    int32_t indexValue = NUM_0;
    if (index.has_value()) {
        indexValue = index.value() >= NUM_0 ? index.value() : NUM_0;
    }

    OHOS::Media::ImageInfo imageinfo;
    uint32_t ret = nativeImgSrc->GetImageInfo(indexValue, imageinfo);
    if (ret != OHOS::Media::SUCCESS) {
        if (isSync) {
            IMAGE_LOGE("Inner GetImageInfo failed");
        } else {
            ImageTaiheUtils::ThrowExceptionError("Inner GetImageInfo failed");
        }
    } else {
        bool isHdr = nativeImgSrc->IsHdrImage();
        auto taiheImageInfo = ImageTaiheUtils::ToTaiheImageInfo(imageinfo, isHdr);
        res = optional<ImageInfo>(std::in_place, taiheImageInfo);
    }

    return res;
}

static bool ParseRotate(DecodingOptions const& options, OHOS::Media::DecodeOptions &dst, std::string &errMsg)
{
    if (options.rotate.has_value()) {
        dst.rotateNewDegrees = options.rotate.value();
        if (dst.rotateNewDegrees >= 0 && dst.rotateNewDegrees <= 360) { // 360 is the maximum rotation angle.
            dst.rotateDegrees = static_cast<float>(dst.rotateNewDegrees);
            IMAGE_LOGD("rotateDegrees: %{public}f", dst.rotateDegrees);
        } else {
            IMAGE_LOGD("Invalid rotate %{public}d", dst.rotateNewDegrees);
            errMsg = "DecodeOptions mismatch";
            return false;
        }
    }
    return true;
}

static OHOS::Media::Rect ParseDesiredRegion(DecodingOptions const& options)
{
    OHOS::Media::Rect rect {};
    if (options.desiredRegion.has_value()) {
        auto &region = options.desiredRegion.value();
        rect.left = region.x;
        rect.top = region.y;
        rect.width = region.size.width;
        rect.height = region.size.height;
        IMAGE_LOGD("desiredRegion: %{public}d, %{public}d, %{public}d, %{public}d",
            rect.left, rect.top, rect.width, rect.height);
    }
    return rect;
}

static bool IsAstc(int32_t val)
{
    if (val >= static_cast<int32_t>(OHOS::Media::PixelFormat::ASTC_4x4) &&
        val <= static_cast<int32_t>(OHOS::Media::PixelFormat::ASTC_8x8)) {
        return true;
    }
    return false;
}

static bool IsSupportPixelFormat(int32_t val)
{
    if (IsAstc(val)) {
        return true;
    }
    if (val >= static_cast<int32_t>(OHOS::Media::PixelFormat::UNKNOWN) &&
        val < static_cast<int32_t>(OHOS::Media::PixelFormat::EXTERNAL_MAX)) {
        return true;
    }

    return false;
}

static OHOS::Media::PixelFormat ParsePixelFormat(int32_t val)
{
    if (IsAstc(val)) {
        return OHOS::Media::PixelFormat(val);
    }
    if (val < static_cast<int32_t>(OHOS::Media::PixelFormat::EXTERNAL_MAX)) {
        return OHOS::Media::PixelFormat(val);
    }

    return OHOS::Media::PixelFormat::UNKNOWN;
}

static bool ParsePixelFormat(optional<PixelMapFormat> val, OHOS::Media::PixelFormat &dst, const std::string &name,
    std::string &errMsg)
{
    if (!val.has_value()) {
        IMAGE_LOGD("no %{public}s", name.c_str());
    } else {
        int32_t pixelFormat = val->get_value();
        if (IsSupportPixelFormat(pixelFormat)) {
            dst = ParsePixelFormat(pixelFormat);
            IMAGE_LOGD("PixelFormat: %{public}d", dst);
        } else {
            IMAGE_LOGD("Invalid %{public}s %{public}d", name.c_str(), pixelFormat);
            errMsg = "DecodeOptions mismatch";
            return false;
        }
    }
    return true;
}

static void ParseDesiredColorSpace(DecodingOptions const& options, OHOS::Media::DecodeOptions &dst)
{
    if (options.desiredColorSpace.has_value()) {
        ani_object desiredColorSpaceObj = reinterpret_cast<ani_object>(options.desiredColorSpace.value());
        dst.desiredColorSpaceInfo = OHOS::ColorManager::GetColorSpaceByAniObject(get_env(), desiredColorSpaceObj);
        IMAGE_LOGD("desiredColorSpace parse finished");
    }
    if (dst.desiredColorSpaceInfo == nullptr) {
        IMAGE_LOGD("no desiredColorSpace");
    }
}

static OHOS::Media::DecodeDynamicRange ParseDynamicRange(DecodingOptions const& options)
{
    if (options.desiredDynamicRange.has_value()) {
        int32_t desiredDynamicRange = options.desiredDynamicRange->get_value();
        if (desiredDynamicRange <= static_cast<int32_t>(OHOS::Media::DecodeDynamicRange::HDR)) {
            IMAGE_LOGD("desiredDynamicRange: %{public}d", desiredDynamicRange);
            return OHOS::Media::DecodeDynamicRange(desiredDynamicRange);
        }
    }
    return OHOS::Media::DecodeDynamicRange::SDR;
}

static OHOS::Media::ResolutionQuality ParseResolutionQuality(DecodingOptions const& options)
{
    if (options.resolutionQuality.has_value()) {
        int32_t resolutionQuality = options.resolutionQuality->get_value();
        if (resolutionQuality <= static_cast<int32_t>(OHOS::Media::ResolutionQuality::HIGH) &&
            (resolutionQuality >= static_cast<int32_t>(OHOS::Media::ResolutionQuality::UNKNOWN))) {
            IMAGE_LOGD("resolutionQuality: %{public}d", resolutionQuality);
            return OHOS::Media::ResolutionQuality(resolutionQuality);
        }
    }
    return OHOS::Media::ResolutionQuality::UNKNOWN;
}

static inline bool IsCropStrategyVaild(int32_t strategy)
{
    return strategy >= static_cast<int32_t>(OHOS::Media::CropAndScaleStrategy::SCALE_FIRST) &&
        strategy <= static_cast<int32_t>(OHOS::Media::CropAndScaleStrategy::CROP_FIRST);
}

static void ParseCropAndScaleStrategy(DecodingOptions const& options, OHOS::Media::DecodeOptions &dst)
{
    if (options.cropAndScaleStrategy.has_value() && IsCropStrategyVaild(options.cropAndScaleStrategy->get_value())) {
        IMAGE_LOGI("The strategy has taken effect");
        dst.cropAndScaleStrategy = OHOS::Media::CropAndScaleStrategy(options.cropAndScaleStrategy->get_value());
        IMAGE_LOGD("cropAndScaleStrategy: %{public}d", dst.cropAndScaleStrategy);
        return;
    }
    IMAGE_LOGI("default cropAndScaleStrategy");
}

static void ParseReusePixelMap(DecodingOptions const& options, OHOS::Media::DecodeOptions &dst)
{
    if (options.reusePixelmap.has_value()) {
        PixelMap etsPixelMap = options.reusePixelmap.value();
        std::shared_ptr<OHOS::Media::PixelMap> rPixelMap = PixelMapImpl::GetPixelMap(etsPixelMap);
        if (rPixelMap != nullptr) {
            dst.reusePixelmap = rPixelMap;
            IMAGE_LOGD("reusePixelmap parse finished");
        }
    }
}

static bool ParseDecodeOptions2(DecodingOptions const& options, OHOS::Media::DecodeOptions &dst, std::string &errMsg)
{
    if (!ParsePixelFormat(options.desiredPixelFormat, dst.desiredPixelFormat, "desiredPixelFormat", errMsg) ||
        !ParsePixelFormat(options.photoDesiredPixelFormat, dst.photoDesiredPixelFormat,
        "photoDesiredPixelFormat", errMsg)) {
        return false;
    }

    if (options.fitDensity.has_value()) {
        dst.fitDensity = options.fitDensity.value();
        IMAGE_LOGD("fitDensity: %{public}d", dst.fitDensity);
    }

    if (options.fillColor.has_value()) {
        dst.SVGOpts.fillColor.isValidColor = true;
        dst.SVGOpts.fillColor.color = options.fillColor.value();
        IMAGE_LOGD("fillColor: %{public}d", dst.SVGOpts.fillColor.color);
    }

    if (options.SVGResize.has_value()) {
        dst.SVGOpts.SVGResize.isValidPercentage = true;
        dst.SVGOpts.SVGResize.resizePercentage = options.SVGResize.value();
        IMAGE_LOGD("SVGResize: %{public}d", dst.SVGOpts.SVGResize.resizePercentage);
    }

    ParseDesiredColorSpace(options, dst);
    if (dst.desiredColorSpaceInfo == nullptr) {
        IMAGE_LOGD("no desiredColorSpace");
    }

    dst.desiredDynamicRange = ParseDynamicRange(options);
    dst.resolutionQuality = ParseResolutionQuality(options);
    ParseCropAndScaleStrategy(options, dst);
    ParseReusePixelMap(options, dst);
    return true;
}

static bool ParseDecodeOptions(DecodingOptions const& options, OHOS::Media::DecodeOptions &dst, uint32_t &index,
    std::string &errMsg)
{
    if (options.index.has_value()) {
        index = options.index.value();
        IMAGE_LOGD("index: %{public}d", index);
    }

    if (options.sampleSize.has_value()) {
        dst.sampleSize = options.sampleSize.value();
        IMAGE_LOGD("sampleSize: %{public}d", dst.sampleSize);
    }

    CHECK_ERROR_RETURN_RET_LOG(!ParseRotate(options, dst, errMsg), false, "%{public}s ParseRotate failed", __func__);

    if (options.editable.has_value()) {
        dst.editable = options.editable.value();
        IMAGE_LOGD("editable: %{public}d", dst.editable);
    }

    if (options.desiredSize.has_value()) {
        dst.desiredSize.width = options.desiredSize.value().width;
        dst.desiredSize.height = options.desiredSize.value().height;
        IMAGE_LOGD("desiredSize: %{public}d, %{public}d", dst.desiredSize.width, dst.desiredSize.height);
    }

    dst.CropRect = ParseDesiredRegion(options);
    return ParseDecodeOptions2(options, dst, errMsg);
}

static std::shared_ptr<OHOS::Media::PixelMap> CreatePixelMapInner(ImageSourceImpl *const thisPtr,
    std::shared_ptr<OHOS::Media::ImageSource> imageSource, uint32_t index, OHOS::Media::DecodeOptions decodeOpts,
    uint32_t &status)
{
    if (thisPtr == nullptr || imageSource == nullptr) {
        IMAGE_LOGE("Invailed args");
        status = OHOS::Media::ERROR;
    }

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap;
    auto incPixelMap = (thisPtr == nullptr) ? nullptr : thisPtr->GetIncrementalPixelMap();
    if (incPixelMap != nullptr) {
        IMAGE_LOGD("Get Incremental PixelMap!!!");
        pixelMap = incPixelMap;
    } else {
        decodeOpts.invokeType = OHOS::Media::JS_INTERFACE;
        pixelMap = (imageSource == nullptr) ? nullptr : imageSource->CreatePixelMapEx((index >= NUM_0) ? index : NUM_0,
            decodeOpts, status);
    }

    if (status != OHOS::Media::SUCCESS || pixelMap == nullptr) {
        IMAGE_LOGE("Create PixelMap error");
    }

    return pixelMap;
}

static void CreatePixelMapExecute(std::unique_ptr<ImageSourceTaiheContext> &taiheContext)
{
    IMAGE_LOGD("CreatePixelMapExecute IN");
    if (taiheContext == nullptr) {
        IMAGE_LOGE("%{public}s taiheContext is nullptr", __func__);
        return;
    }

    if (taiheContext->errMsg.size() > 0) {
        IMAGE_LOGE("%{public}s errMsg: %{public}s", __func__, taiheContext->errMsg.c_str());
        taiheContext->status = OHOS::Media::ERROR;
        return;
    }

    taiheContext->rPixelMap = CreatePixelMapInner(taiheContext->thisPtr, taiheContext->rImageSource,
        taiheContext->index, taiheContext->decodeOpts, taiheContext->status);

    if (taiheContext->status != OHOS::Media::SUCCESS) {
        taiheContext->errMsg = "Create PixelMap error";
        IMAGE_LOGE("Create PixelMap error");
    }
    IMAGE_LOGD("CreatePixelMapExecute OUT");
}

static optional<PixelMap> CreatePixelMapComplete(std::unique_ptr<ImageSourceTaiheContext> &taiheContext, bool isSync)
{
    IMAGE_LOGD("CreatePixelMapComplete IN");
    if (taiheContext->status == OHOS::Media::SUCCESS && taiheContext->rPixelMap != nullptr) {
        auto pixelMap = PixelMapImpl::CreatePixelMap(taiheContext->rPixelMap);
        return optional<PixelMap>(std::in_place, pixelMap);
    }
    if (!isSync) {
        ImageTaiheUtils::ThrowExceptionError(taiheContext->errMsg);
    }
    IMAGE_LOGD("CreatePixelMapComplete OUT");
    return optional<PixelMap>(std::nullopt);
}

optional<PixelMap> ImageSourceImpl::CreatePixelMapSyncWithOptions(optional_view<DecodingOptions> options, bool isSync)
{
    std::unique_ptr<ImageSourceTaiheContext> taiheContext = std::make_unique<ImageSourceTaiheContext>();
    taiheContext->rImageSource = nativeImgSrc;
    if (taiheContext->rImageSource == nullptr) {
        IMAGE_LOGE("%{public}s nativeImgSrc is nullptr", __func__);
        return optional<PixelMap>(std::nullopt);
    }

    taiheContext->thisPtr = this;
    if (taiheContext->thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return optional<PixelMap>(std::nullopt);
    }

    DecodingOptions decodingOptions = options.value_or(DecodingOptions {});
    if (!ParseDecodeOptions(decodingOptions, taiheContext->decodeOpts, taiheContext->index,
        taiheContext->errMsg)) {
        IMAGE_LOGE("%{public}s ParseDecodeOptions failed", __func__);
    }

    ImageTaiheUtils::HicheckerReport();
    CreatePixelMapExecute(taiheContext);
    return CreatePixelMapComplete(taiheContext, isSync);
}

optional<PixelMap> ImageSourceImpl::CreatePixelMapWithOptionsCallback(DecodingOptions const& options)
{
    return CreatePixelMapSyncWithOptions(optional<DecodingOptions>(std::in_place, options), false);
}

optional<PixelMap> ImageSourceImpl::CreatePixelMapWithCallback()
{
    return CreatePixelMapSyncWithOptions(optional<DecodingOptions>(std::nullopt), false);
}

optional<PixelMap> ImageSourceImpl::CreatePixelMapReturnsPromise(optional_view<DecodingOptions> options)
{
    return CreatePixelMapSyncWithOptions(options, false);
}

optional<PixelMap> ImageSourceImpl::CreatePixelMapSync(optional_view<DecodingOptions> options)
{
    return CreatePixelMapSyncWithOptions(options, true);
}

static void CreatePixelMapUsingAllocatorSyncExecute(std::unique_ptr<ImageSourceTaiheContext> &taiheContext)
{
    if (taiheContext == nullptr) {
        IMAGE_LOGE("%{public}s taiheContext is nullptr", __func__);
        return;
    }

    taiheContext->rPixelMap = CreatePixelMapInner(taiheContext->thisPtr, taiheContext->rImageSource,
        taiheContext->index, taiheContext->decodeOpts, taiheContext->status);
    if (taiheContext->status != OHOS::Media::SUCCESS) {
        Image_ErrorCode apiErrorCode = ConvertToErrorCode(taiheContext->status);
        std::string apiErrorMsg = GetErrorCodeMsg(apiErrorCode);
        taiheContext->errMsgArray.emplace(apiErrorCode, apiErrorMsg);
    }
}

static optional<PixelMap> CreatePixelMapUsingAllocatorSyncComplete(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    if (context->status == OHOS::Media::SUCCESS && context->rPixelMap != nullptr) {
        auto res = PixelMapImpl::CreatePixelMap(context->rPixelMap);
        return optional<PixelMap>(std::in_place, res);
    }
    for (const auto &[errorCode, errMsg] : context->errMsgArray) {
        ImageTaiheUtils::ThrowExceptionError(errorCode, errMsg);
    }
    return optional<PixelMap>(std::nullopt);
}

static optional<PixelMap> CreatePixelMapThrowErrorComplete(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    IMAGE_LOGD("CreatePixelMapThrowErrorComplete IN");
    if (context->status == OHOS::Media::SUCCESS && context->rPixelMap != nullptr) {
        auto res = PixelMapImpl::CreatePixelMap(context->rPixelMap);
        return optional<PixelMap>(std::in_place, res);
    }
    for (const auto &[errorCode, errMsg] : context->errMsgArray) {
        ImageTaiheUtils::ThrowExceptionError(errorCode, errMsg);
    }
    IMAGE_LOGD("CreatePixelMapThrowErrorComplete OUT");
    return optional<PixelMap>(std::nullopt);
}

optional<PixelMap> ImageSourceImpl::CreatePixelMapUsingAllocatorSync(optional_view<DecodingOptions> options,
    optional_view<AllocatorType> allocatorType)
{
    std::unique_ptr<ImageSourceTaiheContext> taiheContext = std::make_unique<ImageSourceTaiheContext>();
    taiheContext->rImageSource = nativeImgSrc;
    if (taiheContext->rImageSource == nullptr) {
        IMAGE_LOGE("%{public}s nativeImgSrc is nullptr", __func__);
        return optional<PixelMap>(std::nullopt);
    }

    taiheContext->thisPtr = this;
    if (taiheContext->thisPtr == nullptr) {
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
        return optional<PixelMap>(std::nullopt);
    }

    DecodingOptions opts = options.value_or(DecodingOptions {});
    if (!ParseDecodeOptions(opts, taiheContext->decodeOpts, taiheContext->index,
        taiheContext->errMsg)) {
        IMAGE_LOGE("DecodeOptions mismatch.");
        ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "DecodeOptions mismatch.");
        return optional<PixelMap>(std::nullopt);
    }

    int32_t allocatorTypeInner = allocatorType.value_or(AllocatorType::key_t::AUTO);
    if (!taiheContext->rImageSource->IsSupportAllocatorType(taiheContext->decodeOpts, allocatorTypeInner)) {
        IMAGE_LOGE("Unsupported allocator type.");
        ImageTaiheUtils::ThrowExceptionError(IMAGE_SOURCE_UNSUPPORTED_ALLOCATOR_TYPE, "Unsupported allocator type.");
        return optional<PixelMap>(std::nullopt);
    }

    CreatePixelMapUsingAllocatorSyncExecute(taiheContext);
    return CreatePixelMapUsingAllocatorSyncComplete(taiheContext);
}

optional<PixelMap> ImageSourceImpl::CreateWideGamutSdrPixelMapSync()
{
    ImageTaiheUtils::HicheckerReport();
    std::unique_ptr<ImageSourceTaiheContext> context = std::make_unique<ImageSourceTaiheContext>();
    context->decodeOpts.isCreateWideGamutSdrPixelMap = true;
    context->decodeOpts.desiredDynamicRange = OHOS::Media::DecodeDynamicRange::AUTO;
    context->rPixelMap = CreatePixelMapInner(this, nativeImgSrc, context->index, context->decodeOpts, context->status);
    return CreatePixelMapComplete(context, false);
}

static bool CheckAsyncContext(std::unique_ptr<ImageSourceTaiheContext> &taiheContext, bool check)
{
    if (taiheContext == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return false;
    }

    if (check) {
        if (taiheContext->errMsg.size() > 0) {
            IMAGE_LOGE("mismatch args");
            taiheContext->status = OHOS::Media::ERROR;
            return false;
        }

        if (taiheContext->rImageSource == nullptr) {
            IMAGE_LOGE("empty context rImageSource");
            taiheContext->status = OHOS::Media::ERROR;
            return false;
        }
    }

    return true;
}

static void CreatePixelMapListSyncWithOptionsExecute(std::unique_ptr<ImageSourceTaiheContext> &taiheContext)
{
    if (!CheckAsyncContext(taiheContext, true)) {
        IMAGE_LOGE("check taiheContext fail");
        return;
    }

    taiheContext->pixelMaps = nullptr;
    uint32_t errorCode = 0;
    uint32_t frameCount = taiheContext->rImageSource->GetFrameCount(errorCode);
    if ((errorCode == OHOS::Media::SUCCESS) && (taiheContext->index >= NUM_0) && (taiheContext->index < frameCount)) {
        taiheContext->decodeOpts.invokeType = OHOS::Media::JS_INTERFACE;
        taiheContext->pixelMaps = taiheContext->rImageSource->CreatePixelMapList(taiheContext->decodeOpts, errorCode);
    }

    if ((errorCode == OHOS::Media::SUCCESS) && taiheContext->pixelMaps != nullptr) {
        taiheContext->status = OHOS::Media::SUCCESS;
    } else {
        IMAGE_LOGE("Create PixelMap List error, error=%{public}u", errorCode);
        taiheContext->errMsg = "Create PixelMap List error";
        taiheContext->status = (errorCode != OHOS::Media::SUCCESS) ? errorCode : OHOS::Media::ERROR;
    }
}

static array<PixelMap> CreatePixelMapListSyncWithOptionsComplete(std::unique_ptr<ImageSourceTaiheContext> &taiheContext)
{
    if (!CheckAsyncContext(taiheContext, false)) {
        IMAGE_LOGE("check taiheContext fail");
        return array<PixelMap>(nullptr, 0);
    }

    std::vector<PixelMap> result;
    if (taiheContext->status == OHOS::Media::SUCCESS && taiheContext->pixelMaps != nullptr) {
        IMAGE_LOGD("CreatePixelMapListSyncWithOptionsComplete array");
        for (auto &pixelMap : *taiheContext->pixelMaps.get()) {
            result.emplace_back(PixelMapImpl::CreatePixelMap(std::move(pixelMap)));
        }
    } else {
        std::string errMsg = (taiheContext->errMsg.size() > 0) ? taiheContext->errMsg : "error status, no message";
        IMAGE_LOGD("Operation failed code:%{public}d, msg:%{public}s", taiheContext->status, errMsg.c_str());
        ImageTaiheUtils::ThrowExceptionError(taiheContext->status, errMsg);
    }
    return array<PixelMap>(result);
}

array<PixelMap> ImageSourceImpl::CreatePixelMapListSyncWithOptions(DecodingOptions const& options)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::CreatePixelMapListSyncWithOptions");
    std::unique_ptr<ImageSourceTaiheContext> taiheContext = std::make_unique<ImageSourceTaiheContext>();
    taiheContext->rImageSource = nativeImgSrc;
    if (taiheContext->rImageSource == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_DATA_ABNORMAL, "nativeImgSrc is nullptr");
        return array<PixelMap>(nullptr, 0);
    }

    taiheContext->thisPtr = this;
    if (taiheContext->thisPtr == nullptr) {
        taiheContext->errMsg = "thisPtr is nullptr";
        IMAGE_LOGE("%{public}s thisPtr is nullptr", __func__);
    }

    if (!ParseDecodeOptions(options, taiheContext->decodeOpts, taiheContext->index,
        taiheContext->errMsg)) {
        IMAGE_LOGE("%{public}s DecodeOptions mismatch.", __func__);
    }

    ImageTaiheUtils::HicheckerReport();
    CreatePixelMapListSyncWithOptionsExecute(taiheContext);
    return CreatePixelMapListSyncWithOptionsComplete(taiheContext);
}

array<PixelMap> ImageSourceImpl::CreatePixelMapListSync()
{
    return CreatePixelMapListSyncWithOptions({});
}

array<PixelMap> ImageSourceImpl::CreatePixelMapListSyncWithOptionalOptions(optional_view<DecodingOptions> options)
{
    return CreatePixelMapListSyncWithOptions(options.value_or(DecodingOptions {}));
}

array<int32_t> ImageSourceImpl::GetDelayTimeListSync()
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::GetDelayTimeListSync");

    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_DATA_ABNORMAL, "nativeImgSrc is nullptr.");
        return array<int32_t>(0);
    }

    uint32_t errorCode = 0;
    auto delayTimes = nativeImgSrc->GetDelayTime(errorCode);
    if ((errorCode != OHOS::Media::SUCCESS) || (delayTimes == nullptr)) {
        IMAGE_LOGE("Get DelayTime error, error=%{public}u", errorCode);
        ImageTaiheUtils::ThrowExceptionError((errorCode != OHOS::Media::SUCCESS) ? errorCode : OHOS::Media::ERROR,
            "Get DelayTime error");
        return array<int32_t>(0);
    }

    return array<int32_t>(taihe::copy_data_t{}, delayTimes->data(), delayTimes->size());
}

array<int32_t> ImageSourceImpl::GetDisposalTypeListSync()
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::GetDisposalTypeListSync");

    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_DATA_ABNORMAL, "nativeImgSrc is nullptr.");
        return array<int32_t>(0);
    }

    uint32_t errorCode = 0;
    auto disposalTypeList = nativeImgSrc->GetDisposalType(errorCode);
    if ((errorCode != OHOS::Media::SUCCESS) || (disposalTypeList == nullptr)) {
        IMAGE_LOGE("Get DisposalType error, error=%{public}u", errorCode);
        ImageTaiheUtils::ThrowExceptionError((errorCode != OHOS::Media::SUCCESS) ? errorCode : OHOS::Media::ERROR,
            "Get DisposalType error");
        return array<int32_t>(0);
    }

    return array<int32_t>(taihe::copy_data_t{}, disposalTypeList->data(), disposalTypeList->size());
}

int32_t ImageSourceImpl::GetFrameCountSync()
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::GetFrameCountSync");

    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_DATA_ABNORMAL, "nativeImgSrc is nullptr.");
        return 0;
    }

    uint32_t errorCode = 0;
    auto frameCount = nativeImgSrc->GetFrameCount(errorCode);
    if (errorCode != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Get FrameCount error, error=%{public}u", errorCode);
        ImageTaiheUtils::ThrowExceptionError(errorCode, "Get FrameCount error");
        return 0;
    }

    return frameCount;
}

static bool ParsePropertyOptions(std::unique_ptr<ImageSourceTaiheContext> &context,
    optional_view<ImagePropertyOptions> &options)
{
    if (!options->index.has_value()) {
        IMAGE_LOGD("no index");
        return false;
    }
    context->index = options->index.value();
    if (!options->defaultValue.has_value()) {
        IMAGE_LOGD("no defaultValue");
    } else {
        context->defaultValueStr = options->defaultValue.value();
    }
    return true;
}

static void GenerateErrMsg(std::unique_ptr<ImageSourceTaiheContext> &context, std::string &errMsg)
{
    if (context == nullptr) {
        return;
    }
    switch (context->status) {
        case OHOS::Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT:
            errMsg = "The image does not support EXIF decoding.";
            break;
        case OHOS::Media::ERROR:
            errMsg = "The operation failed.";
            break;
        case OHOS::Media::ERR_IMAGE_DATA_UNSUPPORT:
            errMsg = "The image data is not supported.";
            break;
        case OHOS::Media::ERR_IMAGE_SOURCE_DATA:
            errMsg = "The image source data is incorrect.";
            break;
        case OHOS::Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE:
            errMsg = "The image source data is incomplete.";
            break;
        case OHOS::Media::ERR_IMAGE_MISMATCHED_FORMAT:
            errMsg = "The image format does not mastch.";
            break;
        case OHOS::Media::ERR_IMAGE_UNKNOWN_FORMAT:
            errMsg = "Unknown image format.";
            break;
        case OHOS::Media::ERR_IMAGE_INVALID_PARAMETER:
            errMsg = "Invalid image parameter.";
            break;
        case OHOS::Media::ERR_IMAGE_DECODE_FAILED:
            errMsg = "Failed to decode the image.";
            break;
        case OHOS::Media::ERR_IMAGE_PLUGIN_CREATE_FAILED:
            errMsg = "Failed to create the image plugin.";
            break;
        case OHOS::Media::ERR_IMAGE_DECODE_HEAD_ABNORMAL:
            errMsg = "Failed to decode the image header.";
            break;
        case OHOS::Media::ERR_MEDIA_VALUE_INVALID:
            errMsg = "The EXIF value is invalid.";
            break;
        default:
            errMsg = "There is unknown error happened.";
    }
}

string ImageSourceImpl::GetImagePropertyReturnsPromise(PropertyKey key, optional_view<ImagePropertyOptions> options)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::GetImagePropertyReturnsPromise");

    std::unique_ptr<ImageSourceTaiheContext> context = std::make_unique<ImageSourceTaiheContext>();
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "empty native rImageSource");
        return context->valueStr;
    }

    if (options.has_value() && !ParsePropertyOptions(context, options)) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "PropertyOptions mismatch");
        return context->valueStr;
    }

    context->keyStr = std::string(key.get_value());
    context->status = nativeImgSrc->GetImagePropertyString(context->index, context->keyStr, context->valueStr);
    if (context->status != OHOS::Media::SUCCESS) {
        if (!context->defaultValueStr.empty()) {
            return context->defaultValueStr;
        }
        std::string errMsg;
        GenerateErrMsg(context, errMsg);
        ImageTaiheUtils::ThrowExceptionError(context->status, errMsg);
    }
    return context->valueStr;
}

optional<string> ImageSourceImpl::GetImagePropertySync(PropertyKey key)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::GetImagePropertySync");
    IMAGE_LOGD("GetImagePropertySync IN");

    std::string propertyKey = key.get_value();
    std::string value = "";

    if (nativeImgSrc != nullptr) {
        uint32_t ret = nativeImgSrc->GetImagePropertyStringBySync(NUM_0, propertyKey, value);
        if (ret == OHOS::Media::ERR_IMAGE_PROPERTY_NOT_EXIST) {
            IMAGE_LOGE("%{public}s: Unsupported metadata, errorCode=%{public}u", __func__, ret);
            ImageTaiheUtils::ThrowExceptionError(IMAGE_SOURCE_UNSUPPORTED_METADATA, "Unsupported metadata");
        }
        if (ret == OHOS::Media::ERR_IMAGE_SOURCE_DATA) {
            IMAGE_LOGE("%{public}s: Unsupported MIME type, errorCode=%{public}u", __func__, ret);
            ImageTaiheUtils::ThrowExceptionError(IMAGE_SOURCE_UNSUPPORTED_MIMETYPE, "Unsupported MIME type");
        }
        if (ret == OHOS::Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
            IMAGE_LOGE("%{public}s: Bad source, errorCode=%{public}u", __func__, ret);
            ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_SOURCE, "Bad source");
        }
        return optional<string>(std::in_place, value);
    } else {
        ImageTaiheUtils::ThrowExceptionError("empty native image source");
        return optional<string>(std::nullopt);
    }
}

static void GetImagePropertiesExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }
    uint32_t status = OHOS::Media::SUCCESS;
    for (auto keyStrIt = context->keyStrArray.begin(); keyStrIt != context->keyStrArray.end(); ++keyStrIt) {
        std::string valueStr = "";
        status = context->rImageSource->GetImagePropertyString(0, *keyStrIt, valueStr);
        if (status == OHOS::Media::SUCCESS) {
            context->kVStrArray.emplace_back(std::make_pair(*keyStrIt, valueStr));
        } else {
            context->kVStrArray.emplace_back(std::make_pair(*keyStrIt, ""));
            context->errMsgArray.insert(std::make_pair(status, *keyStrIt));
            IMAGE_LOGE("errCode: %{public}u , exif key: %{public}s", status, keyStrIt->c_str());
        }
    }
    context->status = context->kVStrArray.size() == context->errMsgArray.size() ?
        OHOS::Media::ERROR : OHOS::Media::SUCCESS;
}

static PropertyValue CreatePropertyValue(const std::string& valueStr)
{
    if (!valueStr.empty()) {
        return PropertyValue::make_type_string(valueStr);
    } else {
        return PropertyValue::make_type_null();
    }
}

map<string, PropertyValue> CreatePropertiesRecord(
    std::vector<std::pair<std::string, std::string>> recordParameters)
{
    map<string, PropertyValue> result;
    for (size_t index = 0; index < recordParameters.size(); ++index) {
        PropertyValue value = CreatePropertyValue(recordParameters[index].second);
        result.emplace(recordParameters[index].first, value);
    }

    IMAGE_LOGD("Get record parameters info success.");
    return result;
}

void CreateObtainErrorArray(std::multimap<std::int32_t, std::string> errMsgArray)
{
    for (auto it = errMsgArray.begin(); it != errMsgArray.end(); ++it) {
        std::string errMsg;
        int32_t errCode = it->first;
        if (errCode == OHOS::Media::ERR_IMAGE_DECODE_ABNORMAL) {
            errMsg = "The image source data is incorrect! exif key: " + it->second;
        } else if (errCode == OHOS::Media::ERR_IMAGE_UNKNOWN_FORMAT) {
            errMsg = "Unknown image format! exif key: " + it->second;
        } else if (errCode == OHOS::Media::ERR_IMAGE_DECODE_FAILED) {
            errMsg = "Failed to decode the image! exif key: " + it->second;
        } else {
            errCode = OHOS::Media::ERROR;
            errMsg = "There is generic taihe failure! exif key: " + it->second;
        }
        ImageTaiheUtils::ThrowExceptionError(errCode, errMsg);
    }

    IMAGE_LOGD("Create obtain error array success.");
}

std::vector<std::string> GetStringArrayArgument(array_view<PropertyKey> key)
{
    std::vector<std::string> keyStrArray;

    for (uint32_t i = 0; i < key.size(); i++) {
        keyStrArray.emplace_back(key[i].get_value());
    }

    IMAGE_LOGD("Get string argument success.");
    return keyStrArray;
}

map<string, PropertyValue> ImageSourceImpl::GetImagePropertiesSync(array_view<PropertyKey> key)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::GetImagePropertiesSync");

    map<string, PropertyValue> result;
    std::unique_ptr<ImageSourceTaiheContext> context = std::make_unique<ImageSourceTaiheContext>();
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "empty native rImageSource");
        return result;
    }
    context->rImageSource = nativeImgSrc;
    context->keyStrArray = GetStringArrayArgument(key);
    if (context->keyStrArray.size() == 0) return result;

    GetImagePropertiesExecute(context);

    if (context->status == OHOS::Media::SUCCESS) {
        result = CreatePropertiesRecord(context->kVStrArray);
    } else {
        CreateObtainErrorArray(context->errMsgArray);
    }
    return result;
}

void CreateModifyErrorArray(std::multimap<std::int32_t, std::string> errMsgArray)
{
    for (auto it = errMsgArray.rbegin(); it != errMsgArray.rend(); ++it) {
        if (it->first == OHOS::Media::ERR_MEDIA_WRITE_PARCEL_FAIL) {
            ImageTaiheUtils::ThrowExceptionError(it->first,
                "Create Fd without write permission! exif key: " + it->second);
        } else if (it->first == OHOS::Media::ERR_MEDIA_OUT_OF_RANGE) {
            ImageTaiheUtils::ThrowExceptionError(it->first,
                "The given buffer size is too small to add new exif data! exif key: " + it->second);
        } else if (it->first == OHOS::Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
            ImageTaiheUtils::ThrowExceptionError(it->first,
                "The image does not support EXIF decoding. exif key: " + it->second);
        } else if (it->first == OHOS::Media::ERR_MEDIA_VALUE_INVALID) {
            ImageTaiheUtils::ThrowExceptionError(it->first, it->second);
        } else {
            ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERROR,
                "There is generic taihe failure! exif key: " + it->second);
        }
    }

    IMAGE_LOGD("Create modify error array success.");
}

static void ModifyImagePropertyComplete(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("context is nullptr");
        return;
    }

    if (context->status == OHOS::Media::SUCCESS) {
        IMAGE_LOGI("ModifyImageProperty success.");
        return;
    }

    if (context->isBatch) {
        CreateModifyErrorArray(context->errMsgArray);
    } else {
        if (context->status == OHOS::Media::ERR_MEDIA_WRITE_PARCEL_FAIL) {
            if (context->fdIndex != INVALID_FD) {
                ImageTaiheUtils::ThrowExceptionError(context->status, "Create Fd without write permission!");
            } else {
                ImageTaiheUtils::ThrowExceptionError(context->status,
                    "The EXIF data failed to be written to the file.");
            }
        } else if (context->status == OHOS::Media::ERR_MEDIA_OUT_OF_RANGE) {
            ImageTaiheUtils::ThrowExceptionError(context->status,
                "The given buffer size is too small to add new exif data!");
        } else if (context->status == OHOS::Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT) {
            ImageTaiheUtils::ThrowExceptionError(context->status,
                "The exif data format is not standard, so modify it failed!");
        } else if (context->status == OHOS::Media::ERR_MEDIA_VALUE_INVALID) {
            ImageTaiheUtils::ThrowExceptionError(context->status, context->errMsg);
        } else {
            ImageTaiheUtils::ThrowExceptionError(context->status,
                "There is generic taihe failure!");
        }
    }
}

static uint32_t CheckExifDataValue(const std::string &key, const std::string &value, std::string &errorInfo)
{
    auto status = static_cast<uint32_t>(OHOS::Media::ExifMetadatFormatter::Validate(key, value));
    if (status != OHOS::Media::SUCCESS) {
        errorInfo = key + " has invalid exif value: ";
        errorInfo.append(value);
    }
    return status;
}

static void ModifyImagePropertyExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }
    IMAGE_LOGD("ModifyImagePropertyExecute CheckExifDataValue");
    uint32_t status = CheckExifDataValue(context->keyStr, context->valueStr, context->errMsg);
    IMAGE_LOGD("ModifyImagePropertyExecute Check ret status: %{public}d", status);
    if (status != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("There is invalid exif data parameter");
        context->status = status;
        return;
    }
    context->status = context->rImageSource->ModifyImagePropertyEx(context->index, context->keyStr, context->valueStr);
}

void ImageSourceImpl::ModifyImagePropertySync(PropertyKey key, string_view value)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::ModifyImagePropertySync");

    std::unique_ptr<ImageSourceTaiheContext> context = std::make_unique<ImageSourceTaiheContext>();
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "empty native rImageSource");
        return;
    }
    context->rImageSource = nativeImgSrc;

    context->keyStr = std::string(key.get_value());
    context->valueStr = std::string(value);

    context->pathName = ImageSourceImpl::filePath_;
    context->fdIndex = ImageSourceImpl::fileDescriptor_;
    context->sourceBuffer = ImageSourceImpl::fileBuffer_;
    context->sourceBufferSize = ImageSourceImpl::fileBufferSize_;

    ModifyImagePropertyExecute(context);
    ModifyImagePropertyComplete(context);
}

static void ModifyImagePropertiesExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }
    uint32_t status = OHOS::Media::SUCCESS;
    for (auto recordIterator = context->kVStrArray.begin(); recordIterator != context->kVStrArray.end();
        ++recordIterator) {
        IMAGE_LOGD("CheckExifDataValue");
        status = CheckExifDataValue(recordIterator->first, recordIterator->second, context->errMsg);
        IMAGE_LOGD("Check ret status: %{public}d", status);
        if (status != OHOS::Media::SUCCESS) {
            IMAGE_LOGE("There is invalid exif data parameter");
            context->errMsgArray.insert(std::make_pair(status, context->errMsg));
            continue;
        }
        status = context->rImageSource->ModifyImagePropertyEx(0, recordIterator->first, recordIterator->second);
        if (status != OHOS::Media::SUCCESS) {
            context->errMsgArray.insert(std::make_pair(status, recordIterator->first));
        }
    }
    context->status = context->errMsgArray.size() > 0 ? OHOS::Media::ERROR : OHOS::Media::SUCCESS;
}

std::vector<std::pair<std::string, std::string>> GetRecordArgument(map_view<string, PropertyValue> records)
{
    std::vector<std::pair<std::string, std::string>> kVStrArray;

    for (const auto& [key, value] : records) {
        std::string valueStr;
        if (value.holds_type_string()) {
            valueStr = std::string(value.get_type_string_ref());
        } else if (value.holds_type_null()) {
            valueStr = "";
        }
        kVStrArray.push_back(std::make_pair(std::string(key), valueStr));
    }

    IMAGE_LOGD("Get record argument success.");
    return kVStrArray;
}

void ImageSourceImpl::ModifyImagePropertiesSync(map_view<string, PropertyValue> records)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::ModifyImagePropertiesSync");

    std::unique_ptr<ImageSourceTaiheContext> context = std::make_unique<ImageSourceTaiheContext>();
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "empty native rImageSource");
        return;
    }
    context->rImageSource = nativeImgSrc;

    context->kVStrArray = GetRecordArgument(records);
    if (context->kVStrArray.size() == 0) return;
    context->isBatch = true;

    context->pathName = ImageSourceImpl::filePath_;
    context->fdIndex = ImageSourceImpl::fileDescriptor_;
    context->sourceBuffer = ImageSourceImpl::fileBuffer_;
    context->sourceBufferSize = ImageSourceImpl::fileBufferSize_;

    ModifyImagePropertiesExecute(context);
    ModifyImagePropertyComplete(context);
}

static void UpdateDataExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    if (context == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }

    uint8_t *buffer = static_cast<uint8_t*>(context->updataBuffer);
    if (context->updataBufferOffset < context->updataBufferSize) {
        buffer = buffer + context->updataBufferOffset;
    }

    uint32_t lastSize = context->updataBufferSize - context->updataBufferOffset;
    uint32_t size = context->updataLength < lastSize ? context->updataLength : lastSize;

    uint32_t res = context->rImageSource->UpdateData(buffer, size,
                                                     context->isCompleted);
    context->isSuccess = res == 0;
    if (context->isSuccess && context->thisPtr != nullptr) {
        auto incPixelMap = context->thisPtr->GetIncrementalPixelMap();
        if (incPixelMap != nullptr) {
            uint8_t decodeProgress = 0;
            uint32_t err = incPixelMap->PromoteDecoding(decodeProgress);
            if (!(err == OHOS::Media::SUCCESS ||
                (err == OHOS::Media::ERR_IMAGE_SOURCE_DATA_INCOMPLETE && !context->isCompleted))) {
                IMAGE_LOGE("UpdateData PromoteDecoding error");
                context->isSuccess = false;
            }
            if (context->isCompleted) {
                incPixelMap->DetachFromDecoding();
            }
        }
    }
}

static void ModifyImagePropertiesEnhancedExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    IMAGE_LOGI("ModifyImagePropertiesEnhanced start.");
    auto start = std::chrono::high_resolution_clock::now();
    if (context == nullptr || context->rImageSource == nullptr) {
        IMAGE_LOGE("empty context");
        return;
    }

    context->status = context->rImageSource->ModifyImagePropertiesEx(0, context->kVStrArray);
    if (context->status != OHOS::Media::SUCCESS) {
        auto unsupportedKeys = context->rImageSource->GetModifyExifUnsupportedKeys();
        if (!unsupportedKeys.empty()) {
            context->errMsg = "Failed to modify unsupported keys:";
            for (auto &key : unsupportedKeys) {
                context->errMsg.append(" ").append(key);
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    IMAGE_LOGI("ModifyImagePropertiesEnhanced end, cost: %{public}llu ms", duration.count());
}

void ImageSourceImpl::ModifyImagePropertiesEnhancedSync(map_view<string, PropertyValue> records)
{
    OHOS::Media::ImageTrace imageTrace("ImageSourceImpl::ModifyImagePropertiesEnhancedSync");

    std::unique_ptr<ImageSourceTaiheContext> context = std::make_unique<ImageSourceTaiheContext>();
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::ERR_IMAGE_WRITE_PROPERTY_FAILED, "empty native rImageSource");
        return;
    }
    context->rImageSource = nativeImgSrc;

    context->kVStrArray = GetRecordArgument(records);
    if (context->kVStrArray.size() == 0) return;

    context->pathName = ImageSourceImpl::filePath_;
    context->fdIndex = ImageSourceImpl::fileDescriptor_;
    context->sourceBuffer = ImageSourceImpl::fileBuffer_;
    context->sourceBufferSize = ImageSourceImpl::fileBufferSize_;

    ModifyImagePropertiesEnhancedExecute(context);

    if (context->status != OHOS::Media::SUCCESS) {
        const auto &[errCode, errMsg] = OHOS::Media::ImageErrorConvert::ModifyImagePropertiesEnhancedMakeErrMsg(
            context->status, context->errMsg);
        ImageTaiheUtils::ThrowExceptionError(errCode, errMsg);
    }
}

void ImageSourceImpl::UpdateDataSync(array_view<uint8_t> buf, bool isFinished, int32_t offset, int32_t length)
{
    std::unique_ptr<ImageSourceTaiheContext> taiheContext = std::make_unique<ImageSourceTaiheContext>();
    taiheContext->thisPtr = this;
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("empty native rImageSource");
        return;
    }
    taiheContext->rImageSource = nativeImgSrc;
    if (buf.empty()) {
        ImageTaiheUtils::ThrowExceptionError("empty buf");
        return;
    }
    taiheContext->updataBuffer = buf.data();
    taiheContext->updataBufferSize = buf.size();

    taiheContext->isCompleted = isFinished;
    taiheContext->updataBufferOffset = static_cast<uint32_t>(offset);
    taiheContext->updataLength = static_cast<uint32_t>(length);

    UpdateDataExecute(taiheContext);
    if (!taiheContext->isSuccess) {
        ImageTaiheUtils::ThrowExceptionError("UpdateDataExecute error");
    }
}

void ImageSourceImpl::ReleaseSync()
{
    if (!isRelease) {
        if (nativeImgSrc != nullptr) {
            nativeImgSrc = nullptr;
        }
        isRelease = true;
    }
}

#if !defined(IOS_PLATFORM) && !defined(ANDROID_PLATFORM)
static bool ParseDecodingOptionsForPicture(DecodingOptionsForPicture const& options,
    OHOS::Media::DecodingOptionsForPicture &dst)
{
    constexpr size_t maxAuxTypeCnt = 32U;
    size_t auxPicTypeCount = std::min(options.desiredAuxiliaryPictures.size(), maxAuxTypeCnt);
    for (size_t i = 0; i < auxPicTypeCount; i++) {
        int32_t type = options.desiredAuxiliaryPictures[i];
        if (ImageTaiheUtils::GetTaiheSupportedAuxTypes().count(static_cast<OHOS::Media::AuxiliaryPictureType>(type))) {
            dst.desireAuxiliaryPictures.emplace(OHOS::Media::AuxiliaryPictureType(type));
            IMAGE_LOGD("desireAuxiliaryPictures[%{public}zu]: %{public}d", i, type);
        } else {
            IMAGE_LOGE("unknown auxiliary picture type: %{public}d", type);
            return false;
        }
    }
    return true;
}

static void CreatePictureExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    IMAGE_LOGD("CreatePictureExecute IN");
    uint32_t errorCode;
    context->rPicture = context->rImageSource->CreatePicture(context->decodingOptsForPicture, errorCode);
    if (context->rPicture != nullptr) {
        context->status = OHOS::Media::SUCCESS;
    } else {
        context->status = errorCode;
    }
    IMAGE_LOGD("CreatePictureExecute OUT");
}

static optional<Picture> CreatePictureComplete(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    IMAGE_LOGD("CreatePictureComplete IN");
    if (context->status != OHOS::Media::SUCCESS || context->rPicture == nullptr) {
        std::pair<int32_t, std::string> errorMsg(static_cast<int32_t>(IMAGE_DECODE_FAILED), "Create Picture error");
        context->errMsgArray.insert(errorMsg);
        for (const auto &[errorCode, errMsg] : context->errMsgArray) {
            ImageTaiheUtils::ThrowExceptionError(errorCode, errMsg);
        }
        return optional<Picture>(std::nullopt);
    }
    IMAGE_LOGD("CreatePictureComplete OUT");
    auto res = PictureImpl::CreatePicture(context->rPicture);
    return optional<Picture>(std::in_place, res);
}

optional<Picture> ImageSourceImpl::CreatePictureSync(optional_view<DecodingOptionsForPicture> options)
{
    std::unique_ptr<ImageSourceTaiheContext> taiheContext = std::make_unique<ImageSourceTaiheContext>();
    taiheContext->thisPtr = this;
    if (nativeImgSrc == nullptr) {
        IMAGE_LOGE("empty native rImageSource");
        return optional<Picture>(std::nullopt);
    }
    taiheContext->rImageSource = nativeImgSrc;

    if (!options.has_value()) {
        taiheContext->decodingOptsForPicture.desireAuxiliaryPictures = {
            ImageTaiheUtils::GetTaiheSupportedAuxTypes().begin(),
            ImageTaiheUtils::GetTaiheSupportedAuxTypes().end()
        };
    } else {
        if (!ParseDecodingOptionsForPicture(options.value(), taiheContext->decodingOptsForPicture)) {
            ImageTaiheUtils::ThrowExceptionError(IMAGE_BAD_PARAMETER, "DecodingOptionsForPicture mismatch");
            return optional<Picture>(std::nullopt);
        }
    }

    CreatePictureExecute(taiheContext);
    return CreatePictureComplete(taiheContext);
}

optional<Picture> ImageSourceImpl::CreatePictureAtIndexSync(int32_t index)
{
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("empty native rImageSource");
        return optional<Picture>(std::nullopt);
    }

    uint32_t errCode = OHOS::Media::ERR_MEDIA_INVALID_VALUE;
    auto picture = nativeImgSrc->CreatePictureAtIndex(index, errCode);
    if (errCode != OHOS::Media::SUCCESS || picture == nullptr) {
        auto errMsg = OHOS::Media::ImageErrorConvert::CreatePictureAtIndexMakeErrMsg(errCode);
        ImageTaiheUtils::ThrowExceptionError(errMsg.first, errMsg.second);
        return optional<Picture>(std::nullopt);
    }
    auto res = make_holder<PictureImpl, Picture>(std::move(picture));
    return optional<Picture>(std::in_place, res);
}

static bool IsSizeInvalid(const OHOS::Media::Size &size)
{
    return size.width < 0 || size.height < 0;
}

static void ParseDecodeOptionsForThumbnail(optional_view<DecodingOptionsForThumbnail> options,
    OHOS::Media::DecodingOptionsForThumbnail &dOpts)
{
    if (!options.has_value()) {
        IMAGE_LOGD("no options");
        return;
    }

    if (options.value().desiredSize.has_value()) {
        dOpts.desiredSize.width = options.value().desiredSize.value().width;
        dOpts.desiredSize.height = options.value().desiredSize.value().height;
        if (IsSizeInvalid(dOpts.desiredSize)) {
            IMAGE_LOGE("%{public}s: desiredSize is invalid, size: (%{public}d, %{public}d)",
                __func__, dOpts.desiredSize.width, dOpts.desiredSize.height);
            return;
        }
    }
    dOpts.needGenerate = options.value().needGenerate.value_or(false);
}

static void CreateThumbnailExecute(std::unique_ptr<ImageSourceTaiheContext> &context)
{
    IMAGE_LOGD("CreateThumbnailExecute IN");
    context->rPixelMap = context->rImageSource->CreateThumbnail(context->decodingOptsForThumbnail, context->status);
    if (context->status != OHOS::Media::SUCCESS) {
        context->errMsgArray.emplace(OHOS::Media::ImageErrorConvert::CreateThumbnailMakeErrMsg(context->status));
    }
    IMAGE_LOGD("CreateThumbnailExecute OUT");
}

optional<PixelMap> ImageSourceImpl::CreateThumbnailSync(optional_view<DecodingOptionsForThumbnail> options)
{
    if (nativeImgSrc == nullptr) {
        ImageTaiheUtils::ThrowExceptionError("nativeImgSrc is nullptr");
        return optional<PixelMap>(std::nullopt);
    }

    std::unique_ptr<ImageSourceTaiheContext> taiheContext = std::make_unique<ImageSourceTaiheContext>();
    taiheContext->rImageSource = nativeImgSrc;
    ParseDecodeOptionsForThumbnail(options, taiheContext->decodingOptsForThumbnail);

    CreateThumbnailExecute(taiheContext);
    return CreatePixelMapThrowErrorComplete(taiheContext);
}
#endif

array<string> ImageSourceImpl::GetSupportedFormats()
{
    std::set<std::string> formats;
    nativeImgSrc->GetSupportedFormats(formats);
    std::vector<std::string> vec(formats.begin(), formats.end());
    return ImageTaiheUtils::ToTaiheArrayString(vec);
}

#ifdef XMP_TOOLKIT_SDK_ENABLE
NullableXMPMetadata ImageSourceImpl::ReadXMPMetadataSync()
{
    CHECK_ERROR_RETURN_RET_LOG(nativeImgSrc == nullptr, NullableXMPMetadata::make_type_null(),
        "fail to get nativeImgSrc");

    uint32_t errorCode = OHOS::Media::ERROR;
    auto xmpMetadata = nativeImgSrc->ReadXMPMetadata(errorCode);
    if (errorCode != OHOS::Media::SUCCESS) {
        return NullableXMPMetadata::make_type_null();
    }
    CHECK_ERROR_RETURN_RET(errorCode != OHOS::Media::SUCCESS, NullableXMPMetadata::make_type_null());
    CHECK_ERROR_RETURN_RET_LOG(xmpMetadata == nullptr, NullableXMPMetadata::make_type_null(),
        "%{public}s xmpMetadata is nullptr", __func__);

    auto res = make_holder<XMPMetadataImpl, XMPMetadata>(xmpMetadata);
    return NullableXMPMetadata::make_type_xmpMetadata(res);
}

void ImageSourceImpl::WriteXMPMetadataSync(XMPMetadata xmpMetadata)
{
    CHECK_ERROR_RETURN_LOG(nativeImgSrc == nullptr, "fail to get nativeImgSrc");

    XMPMetadataImpl* thisPtr = reinterpret_cast<XMPMetadataImpl*>(xmpMetadata->GetImplPtr());
    CHECK_ERROR_RETURN_LOG(thisPtr == nullptr, "%{public}s xmpMetadataImpl is nullptr", __func__);

    auto nativeXMPMetadata = thisPtr->GetNativeXMPMetadata();
    CHECK_ERROR_RETURN_LOG(nativeXMPMetadata == nullptr, "fail to get xmpMetadata");

    uint32_t errorCode = nativeImgSrc->WriteXMPMetadata(nativeXMPMetadata);
    CHECK_ERROR_RETURN_LOG(errorCode != OHOS::Media::SUCCESS, "%{public}s WriteXMPMetadata failed", __func__);
}
#endif

static std::string FileUrlToRawPath(const std::string &path)
{
    if (path.size() > FILE_URL_PREFIX.size() &&
        (path.compare(0, FILE_URL_PREFIX.size(), FILE_URL_PREFIX) == 0)) {
        return path.substr(FILE_URL_PREFIX.size());
    }
    return path;
}

optional<ImageSource> CreateImageSourceByUriOption(string_view uri, SourceOptions const& options)
{
    OHOS::Media::SourceOptions opts = ImageTaiheUtils::ParseSourceOptions(options);
    uint32_t errorCode = OHOS::Media::ERR_MEDIA_INVALID_VALUE;
    std::string rawPath = FileUrlToRawPath(std::string(uri));

    std::shared_ptr<OHOS::Media::ImageSource> imageSource =
        OHOS::Media::ImageSource::CreateImageSource(rawPath, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("CreateImageSourceExec error, errorCode: %{public}d", errorCode);
        return optional<ImageSource>(std::nullopt);
    }
    {
        std::lock_guard<std::mutex> lock(imageSourceCrossThreadMutex_);
        ImageSourceImpl::filePath_ = rawPath;
        ImageSourceImpl::fileDescriptor_ = INVALID_FD;
        ImageSourceImpl::fileBuffer_ = nullptr;
        ImageSourceImpl::fileBufferSize_ = NUM_0;
    }
    auto res = make_holder<ImageSourceImpl, ImageSource>(imageSource);
    return optional<ImageSource>(std::in_place, res);
}

optional<ImageSource> CreateImageSourceByUri(string_view uri)
{
    SourceOptions opts {};
    return CreateImageSourceByUriOption(uri, opts);
}

optional<ImageSource> CreateImageSourceByFdOption(double fd, SourceOptions const& options)
{
    int32_t fdInt = static_cast<int32_t>(fd);
    OHOS::Media::SourceOptions opts = ImageTaiheUtils::ParseSourceOptions(options);
    uint32_t errorCode = OHOS::Media::ERR_MEDIA_INVALID_VALUE;
    std::shared_ptr<OHOS::Media::ImageSource> imageSource =
        OHOS::Media::ImageSource::CreateImageSource(fdInt, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("CreateImageSourceExec error, errorCode: %{public}d", errorCode);
        return optional<ImageSource>(std::nullopt);
    }
    {
        std::lock_guard<std::mutex> lock(imageSourceCrossThreadMutex_);
        ImageSourceImpl::filePath_ = "";
        ImageSourceImpl::fileDescriptor_ = fdInt;
        ImageSourceImpl::fileBuffer_ = nullptr;
        ImageSourceImpl::fileBufferSize_ = NUM_0;
    }
    auto res = make_holder<ImageSourceImpl, ImageSource>(imageSource);
    return optional<ImageSource>(std::in_place, res);
}

optional<ImageSource> CreateImageSourceByFd(int32_t fd)
{
    SourceOptions opts {};
    return CreateImageSourceByFdOption(fd, opts);
}

optional<ImageSource> CreateImageSourceByArrayBufferOption(array_view<uint8_t> buf, SourceOptions const& options)
{
    OHOS::Media::SourceOptions opts = ImageTaiheUtils::ParseSourceOptions(options);
    uint32_t errorCode = OHOS::Media::ERR_MEDIA_INVALID_VALUE;
    uint8_t *bufPtr = const_cast<uint8_t *>(buf.data());
    std::shared_ptr<OHOS::Media::ImageSource> imageSource =
        OHOS::Media::ImageSource::CreateImageSource(bufPtr, buf.size(), opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("CreateImageSourceExec error, errorCode: %{public}d", errorCode);
        return optional<ImageSource>(std::nullopt);
    }
    {
        std::lock_guard<std::mutex> lock(imageSourceCrossThreadMutex_);
        ImageSourceImpl::filePath_ = "";
        ImageSourceImpl::fileDescriptor_ = INVALID_FD;
        ImageSourceImpl::fileBuffer_ = bufPtr;
        ImageSourceImpl::fileBufferSize_ = buf.size();
    }
    auto res = make_holder<ImageSourceImpl, ImageSource>(imageSource);
    return optional<ImageSource>(std::in_place, res);
}

optional<ImageSource> CreateImageSourceByArrayBuffer(array_view<uint8_t> buf)
{
    SourceOptions opts {};
    return CreateImageSourceByArrayBufferOption(buf, opts);
}

optional<ImageSource> CreateIncrementalSourceByArrayBufferOption(
    array_view<uint8_t> buf, optional_view<SourceOptions> options)
{
    OHOS::Media::IncrementalSourceOptions incOpts;
    SourceOptions etsOpts = options.value_or(SourceOptions {});
    incOpts.sourceOptions = ImageTaiheUtils::ParseSourceOptions(etsOpts);

    incOpts.incrementalMode = OHOS::Media::IncrementalMode::INCREMENTAL_DATA;
    uint32_t errorCode = 0;
    std::shared_ptr<OHOS::Media::ImageSource> imageSource =
        OHOS::Media::ImageSource::CreateIncrementalImageSource(incOpts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("%{public}s error, errorCode: %{public}d", __func__, errorCode);
        return optional<ImageSource>(std::nullopt);
    }

    OHOS::Media::DecodeOptions decodeOpts;
    std::shared_ptr<OHOS::Media::IncrementalPixelMap> navIncPixelMap =
        imageSource->CreateIncrementalPixelMap(0, decodeOpts, errorCode);

    if (errorCode != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("CreateIncrementalImageSource error, errorCode: %{public}d", errorCode);
        return optional<ImageSource>(std::nullopt);
    }

    auto res = make_holder<ImageSourceImpl, ImageSource>(imageSource, navIncPixelMap);
    return optional<ImageSource>(std::in_place, res);
}

optional<ImageSource> CreateIncrementalSourceByArrayBuffer(array_view<uint8_t> buf)
{
    optional_view<SourceOptions> optionalView;
    return CreateIncrementalSourceByArrayBufferOption(buf, optionalView);
}

optional<ImageSource> CreateImageSourceByRawFileDescriptorOption(
    uintptr_t rawfile, optional_view<SourceOptions> options)
{
    int32_t fd;
    int64_t offset;
    int64_t length;
    ani_env *env = ::taihe::get_env();
    ani_object rawfileObj = reinterpret_cast<ani_object>(rawfile);
    if (!ImageTaiheUtils::GetPropertyInt(env, rawfileObj, "fd", fd) ||
        !ImageTaiheUtils::GetPropertyLong(env, rawfileObj, "offset", offset) ||
        !ImageTaiheUtils::GetPropertyLong(env, rawfileObj, "length", length)) {
        ImageTaiheUtils::ThrowExceptionError(OHOS::Media::COMMON_ERR_INVALID_PARAMETER, "GetProperty failed");
        IMAGE_LOGD("RawFileDescriptor mismatch");
        return optional<ImageSource>(std::nullopt);
    }
    SourceOptions etsOpts = options.value_or(SourceOptions {});
    OHOS::Media::SourceOptions opts = ImageTaiheUtils::ParseSourceOptions(etsOpts);

    uint32_t errorCode = OHOS::Media::ERR_MEDIA_INVALID_VALUE;
    int32_t fileSize = static_cast<int32_t>(offset) + static_cast<int32_t>(length);
    std::shared_ptr<OHOS::Media::ImageSource> imageSource = OHOS::Media::ImageSource::CreateImageSource(
        fd, static_cast<int32_t>(offset), fileSize, opts, errorCode);
    if (imageSource == nullptr) {
        IMAGE_LOGE("CreateImageSourceExec error, errorCode: %{public}d", errorCode);
        return optional<ImageSource>(std::nullopt);
    }
    {
        std::lock_guard<std::mutex> lock(imageSourceCrossThreadMutex_);
        ImageSourceImpl::filePath_ = "";
        ImageSourceImpl::fileDescriptor_ = INVALID_FD;
        ImageSourceImpl::fileBuffer_ = nullptr;
        ImageSourceImpl::fileBufferSize_ = NUM_0;
    }
    auto res = make_holder<ImageSourceImpl, ImageSource>(imageSource);
    return optional<ImageSource>(std::in_place, res);
}

ImageSource CreateImageSourceByPtr(int64_t ptr)
{
    return taihe::make_holder<ImageSourceImpl, ImageSource>(ptr);
}

array<string> GetImageSourceSupportedFormats()
{
    std::set<std::string> formats;
    uint32_t ret = OHOS::Media::ImageSource::GetSupportedFormats(formats);
    if (ret != OHOS::Media::SUCCESS) {
        IMAGE_LOGE("Fail to get decode supported formats");
    }
    return ImageTaiheUtils::ToTaiheArrayString(std::vector(formats.begin(), formats.end()));
}
} // namespace ANI::Image

TH_EXPORT_CPP_API_CreateImageSourceByUri(CreateImageSourceByUri);
TH_EXPORT_CPP_API_CreateImageSourceByUriOption(CreateImageSourceByUriOption);
TH_EXPORT_CPP_API_CreateImageSourceByFd(CreateImageSourceByFd);
TH_EXPORT_CPP_API_CreateImageSourceByFdOption(CreateImageSourceByFdOption);
TH_EXPORT_CPP_API_CreateImageSourceByArrayBuffer(CreateImageSourceByArrayBuffer);
TH_EXPORT_CPP_API_CreateImageSourceByArrayBufferOption(CreateImageSourceByArrayBufferOption);
TH_EXPORT_CPP_API_CreateImageSourceByRawFileDescriptorOption(CreateImageSourceByRawFileDescriptorOption);
TH_EXPORT_CPP_API_CreateIncrementalSourceByArrayBuffer(CreateIncrementalSourceByArrayBuffer);
TH_EXPORT_CPP_API_CreateIncrementalSourceByArrayBufferOption(CreateIncrementalSourceByArrayBufferOption);
TH_EXPORT_CPP_API_CreateImageSourceByPtr(CreateImageSourceByPtr);
TH_EXPORT_CPP_API_GetImageSourceSupportedFormats(GetImageSourceSupportedFormats);