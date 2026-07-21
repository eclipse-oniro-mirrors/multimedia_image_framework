/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "png_metadata_parser.h"
#include <algorithm>
#include <limits>

#include "image_log.h"
#include "image_type.h"
#include "input_data_stream.h"
#include "png.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "PngMetadataParser"

namespace OHOS {
namespace Media {

constexpr static int PNG_UNITS_METER = 1;
constexpr static double PNG_GAMMA_INVALID_MIN = 0.0;
constexpr static double PNG_GAMMA_VALID_MAX = 1000.0;
constexpr static int MAX_NUM_TEXT = 1024;

static const std::unordered_map<std::string, std::string> PNG_KEY_TO_LIBPNG_KEY_MAP = {
    {PNG_METADATA_KEY_TITLE, "Title"},
    {PNG_METADATA_KEY_DESCRIPTION, "Description"},
    {PNG_METADATA_KEY_COMMENT, "Comment"},
    {PNG_METADATA_KEY_DISCLAIMER, "Disclaimer"},
    {PNG_METADATA_KEY_WARNING, "Warning"},
    {PNG_METADATA_KEY_AUTHOR, "Author"},
    {PNG_METADATA_KEY_COPYRIGHT, "Copyright"},
    {PNG_METADATA_KEY_CREATION_TIME, "Creation Time"},
    {PNG_METADATA_KEY_MODIFICATION_TIME, "Modification Time"},
    {PNG_METADATA_KEY_SOFTWARE, "Software"}
};


static bool IsValidGamma(double gamma)
{
    return gamma > PNG_GAMMA_INVALID_MIN && gamma <= PNG_GAMMA_VALID_MAX;
}

static bool SafeUint32ToInt32(png_uint_32 value, int32_t& result)
{
    bool cond = (value > static_cast<png_uint_32>(std::numeric_limits<int32_t>::max()));
    CHECK_ERROR_RETURN_RET_LOG(cond, false,
        "%{public}s: value %{public}u exceeds int32_t max", __func__, value);
    result = static_cast<int32_t>(value);
    return true;
}

static jmp_buf* SafePngSetLongjmpFn(png_structp png_ptr)
{
#ifdef PNG_SETJMP_SUPPORTED
    if (png_ptr != nullptr) {
        return png_set_longjmp_fn(png_ptr, longjmp, sizeof(jmp_buf));
    }
#endif
    return nullptr;
}

static int SafeSetJmp(png_structp png_ptr) {
    auto jmpBuf = SafePngSetLongjmpFn(png_ptr);
    return jmpBuf == nullptr ? -1 : setjmp(*jmpBuf);
}

static void SafeLongJmp(png_structp png_ptr) {
    auto jmpBuf = SafePngSetLongjmpFn(png_ptr);
    if (jmpBuf != nullptr) {
        longjmp(*jmpBuf, 1);
    }
}

static void PngErrorExit(png_structp pngPtr, png_const_charp message)
{
    IMAGE_LOGE("PNG error: %{public}s", message);
    SafeLongJmp(pngPtr);
}

static void PngWarning(png_structp pngPtr, png_const_charp message)
{
    IMAGE_LOGW("PNG warning: %{public}s", message);
}

static void PngReadFunc(png_structp pngPtr, png_bytep data, png_size_t length)
{
    OHOS::ImagePlugin::InputDataStream* stream =
        static_cast<OHOS::ImagePlugin::InputDataStream*>(png_get_io_ptr(pngPtr));
    if (stream == nullptr) {
        IMAGE_LOGE("%{public}s: stream is nullptr", __func__);
        SafeLongJmp(pngPtr);
    }
    uint32_t readSize = 0;
    uint32_t desiredSize = static_cast<uint32_t>(length);
    bool ret = stream->Read(desiredSize, reinterpret_cast<uint8_t*>(data), desiredSize, readSize);
    if (!ret) {
        IMAGE_LOGE("%{public}s: Read operation failed, desired=%{public}u", __func__, desiredSize);
        SafeLongJmp(pngPtr);
    }
    if (readSize < desiredSize) {
        IMAGE_LOGE("%{public}s: Unexpected EOF, desired=%{public}u, actual=%{public}u", __func__, desiredSize,
            readSize);
        SafeLongJmp(pngPtr);
    }
}

PngMetadataParser::PngMetadataParser() = default;

PngMetadataParser::~PngMetadataParser()
{
    if (pngStructPtr_ != nullptr) {
        png_destroy_read_struct(&pngStructPtr_, &pngInfoPtr_, nullptr);
        pngStructPtr_ = nullptr;
        pngInfoPtr_ = nullptr;
    }
}

bool PngMetadataParser::ReadPngInfo(ImagePlugin::InputDataStream *stream)
{
    CHECK_ERROR_RETURN_RET_LOG(SafeSetJmp(pngStructPtr_), false, "PNG lib error during header decode");
    png_set_read_fn(pngStructPtr_, stream, PngReadFunc);
    png_read_info(pngStructPtr_, pngInfoPtr_);
    return true;
}

bool PngMetadataParser::SetupPngReading(ImagePlugin::InputDataStream *stream)
{
    CHECK_ERROR_RETURN_RET_LOG(stream == nullptr, false, "%{public}s: stream is nullptr", __func__);

    if (pngStructPtr_ || pngInfoPtr_) {
        png_destroy_read_struct(&pngStructPtr_, &pngInfoPtr_, nullptr);
        pngStructPtr_ = nullptr;
        pngInfoPtr_ = nullptr;
    }

    const uint32_t savedPos = stream->Tell();

    auto handleError = [&](const char* msg, bool needCleanup = false) -> bool {
        if (needCleanup) {
            png_destroy_read_struct(&pngStructPtr_, &pngInfoPtr_, nullptr);
            pngStructPtr_ = nullptr;
            pngInfoPtr_ = nullptr;
        }
        IMAGE_LOGE("%s", msg);
        stream->Seek(savedPos);
        return false;
    };

    if (!stream->Seek(0)) {
        return handleError("Seek to 0 failed");
    }

    pngStructPtr_ = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, PngErrorExit, PngWarning);
    if (!pngStructPtr_) {
        return handleError("Failed to create PNG read struct");
    }

    pngInfoPtr_ = png_create_info_struct(pngStructPtr_);
    if (!pngInfoPtr_) {
        return handleError("Failed to create PNG info struct", true);
    }

    if (!ReadPngInfo(stream)) {
        return handleError("Failed to read PNG info", true);
    }

    // libpng >= 1.6.55 no longer sets PNG_INFO_cHRM from sRGB chunk.
    // When the PNG has sRGB but no cHRM, populate cHRM via png_set_sRGB_gAMA_and_cHRM()
    // so that png_get_cHRM() works consistently with older libpng versions.
    int sRGBIntent = 0;
    if (png_get_sRGB(pngStructPtr_, pngInfoPtr_, &sRGBIntent) != 0 &&
        png_get_valid(pngStructPtr_, pngInfoPtr_, PNG_INFO_cHRM) == 0) {
        png_set_sRGB_gAMA_and_cHRM(pngStructPtr_, pngInfoPtr_, sRGBIntent);
    }

    stream->Seek(savedPos);
    return true;
}

bool PngMetadataParser::GetPhysProperty(const std::string &key, int32_t &value)
{
    png_uint_32 xPixelsPerMeter = 0;
    png_uint_32 yPixelsPerMeter = 0;
    int unitType = 0;
    bool pHYsRet = png_get_pHYs(pngStructPtr_, pngInfoPtr_, &xPixelsPerMeter, &yPixelsPerMeter, &unitType);
    CHECK_ERROR_RETURN_RET_LOG(!pHYsRet, false, "%{public}s: pHYs chunk not found in PNG", __func__);
    if (unitType != PNG_UNITS_METER) {
        IMAGE_LOGW("%{public}s: pHYs unit type %{public}d is not meter (PNG_UNITS_METER=%{public}d), ignoring",
            __func__, unitType, PNG_UNITS_METER);
        return false;
    }
    if (key == PNG_METADATA_KEY_X_PIXELS_PER_METER) {
        return SafeUint32ToInt32(xPixelsPerMeter, value);
    } else if (key == PNG_METADATA_KEY_Y_PIXELS_PER_METER) {
        return SafeUint32ToInt32(yPixelsPerMeter, value);
    }
    return false;
}

bool PngMetadataParser::GetGammaPropertyDouble(double &value)
{
    double gamma = 0.0;
    bool gammaRet = png_get_gAMA(pngStructPtr_, pngInfoPtr_, &gamma);
    if (!gammaRet) {
        IMAGE_LOGW("%{public}s: gAMA chunk not found in PNG", __func__);
        return false;
    }
    bool validGamma = IsValidGamma(gamma);
    CHECK_ERROR_RETURN_RET_LOG(!validGamma, false, "%{public}s: invalid gamma value: %{public}f", __func__, gamma);
    value = gamma;
    return true;
}

bool PngMetadataParser::GetInterlaceProperty(int32_t &value)
{
    value = png_get_interlace_type(pngStructPtr_, pngInfoPtr_);
    return true;
}

bool PngMetadataParser::GetSrgbProperty(int32_t &value)
{
    int sRGBIntent = 0;
    bool sRGBRet = png_get_sRGB(pngStructPtr_, pngInfoPtr_, &sRGBIntent);
    if (sRGBRet) {
        value = sRGBIntent;
        return true;
    }
    IMAGE_LOGW("%{public}s: sRGB chunk not found in PNG", __func__);
    return false;
}

bool PngMetadataParser::GetPropertyDouble(const std::string &key, double &value)
{
    bool cond = (pngStructPtr_ == nullptr) || (pngInfoPtr_ == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "pngStructPtr_ or pngInfoPtr_ is null");
    CHECK_ERROR_RETURN_RET_LOG(SafeSetJmp(pngStructPtr_), false, "PNG lib error during property get");
    if (key == PNG_METADATA_KEY_GAMMA) {
        return GetGammaPropertyDouble(value);
    }
    return false;
}

bool PngMetadataParser::GetPropertyInt(const std::string &key, int32_t &value)
{
    if (pngStructPtr_ == nullptr || pngInfoPtr_ == nullptr) {
        IMAGE_LOGE("pngStructPtr_ or pngInfoPtr_ is null");
        return false;
    }
    if (SafeSetJmp(pngStructPtr_)) {
        IMAGE_LOGE("PNG lib error during property get");
        return false;
    }
    if (key == PNG_METADATA_KEY_X_PIXELS_PER_METER || key == PNG_METADATA_KEY_Y_PIXELS_PER_METER) {
        return GetPhysProperty(key, value);
    }
    if (key == PNG_METADATA_KEY_INTERLACE_TYPE) {
        return GetInterlaceProperty(value);
    }
    if (key == PNG_METADATA_KEY_SRGB_INTENT) {
        return GetSrgbProperty(value);
    }

    return false;
}

bool PngMetadataParser::GetChromaticitiesProperty(std::string &value)
{
    double whitePointX = 0.0;
    double whitePointY = 0.0;
    double redX = 0.0;
    double redY = 0.0;
    double greenX = 0.0;
    double greenY = 0.0;
    double blueX = 0.0;
    double blueY = 0.0;
    if (png_get_cHRM(pngStructPtr_, pngInfoPtr_, &whitePointX, &whitePointY, &redX, &redY, &greenX, &greenY, &blueX,
        &blueY) != 0) {
        value = std::to_string(whitePointX) + "," + std::to_string(whitePointY) + "," +
                std::to_string(redX) + "," + std::to_string(redY) + "," +
                std::to_string(greenX) + "," + std::to_string(greenY) + "," +
                std::to_string(blueX) + "," + std::to_string(blueY);
        return true;
    }
    IMAGE_LOGW("%{public}s: cHRM chunk not found in PNG", __func__);
    return false;
}

std::string PngMetadataParser::GetTextKeyword(const std::string &key)
{
    auto iter = PNG_KEY_TO_LIBPNG_KEY_MAP.find(key);
    if (iter != PNG_KEY_TO_LIBPNG_KEY_MAP.end()) {
        return iter->second;
    }
    return "";
}

bool PngMetadataParser::FindTextProperty(const std::string &targetKeyword, std::string &value)
{
    png_textp textPtr = nullptr;
    int numText = 0;
    bool textRet = png_get_text(pngStructPtr_, pngInfoPtr_, &textPtr, &numText);
    if (!textRet || numText > MAX_NUM_TEXT) {
        return false;
    }
    for (int i = 0; i < numText; i++) {
        if (textPtr[i].key == nullptr || textPtr[i].text == nullptr) {
            continue;
        }
        std::string keyword = textPtr[i].key;
        if (keyword == targetKeyword) {
            value = textPtr[i].text;
            return true;
        }
    }
    return false;
}

bool PngMetadataParser::GetTextProperty(const std::string &key, std::string &value)
{
    std::string targetKeyword = GetTextKeyword(key);
    if (targetKeyword.empty()) {
        return false;
    }
    bool found = FindTextProperty(targetKeyword, value);
    if (!found) {
        IMAGE_LOGW("%{public}s: Text chunk '%{public}s' not found in PNG", __func__, key.c_str());
    }
    return found;
}

bool PngMetadataParser::GetPropertyString(const std::string &key, std::string &value)
{
    bool cond = (pngStructPtr_ == nullptr) || (pngInfoPtr_ == nullptr);
    CHECK_ERROR_RETURN_RET_LOG(cond, false, "%{public}s: pngStructPtr_ or pngInfoPtr_ is null", __func__);
    CHECK_ERROR_RETURN_RET_LOG(SafeSetJmp(pngStructPtr_), false,
        "%{public}s: PNG lib error during property get", __func__);
    if (key == PNG_METADATA_KEY_CHROMATICITIES) {
        return GetChromaticitiesProperty(value);
    } else {
        return GetTextProperty(key, value);
    }
}

} // namespace Media
} // namespace OHOS
