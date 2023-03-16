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

#include "jpeg_decoder.h"
#include <map>
#include "jerror.h"
#include "media_errors.h"
#include "string_ex.h"
#ifndef _WIN32
#include "securec.h"
#else
#include "memory.h"
#endif

namespace OHOS {
namespace ImagePlugin {
using namespace OHOS::HiviewDFX;
using namespace MultimediaPlugin;
using namespace Media;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "JpegDecoder" };
static constexpr uint32_t PL_ICC_MARKER = JPEG_APP0 + 2;
static constexpr uint32_t PL_MARKER_LENGTH_LIMIT = 0xFFFF;
namespace {
constexpr uint32_t NUM_100 = 100;
constexpr uint32_t PIXEL_BYTES_RGB_565 = 2;
constexpr uint32_t MARKER_SIZE = 2;
constexpr uint32_t MARKER_LENGTH = 2;
constexpr uint8_t MARKER_LENGTH_0_OFFSET = 0;
constexpr uint8_t MARKER_LENGTH_1_OFFSET = 1;
constexpr uint32_t MARKER_LENGTH_SHIFT = 8;
constexpr uint8_t JPG_MARKER_PREFIX_OFFSET = 0;
constexpr uint8_t JPG_MARKER_CODE_OFFSET = 1;
constexpr uint8_t JPG_MARKER_PREFIX = 0XFF;
constexpr uint8_t JPG_MARKER_SOI = 0XD8;
constexpr uint8_t JPG_MARKER_SOS = 0XDA;
constexpr uint8_t JPG_MARKER_RST = 0XD0;
constexpr uint8_t JPG_MARKER_RST0 = 0XD0;
constexpr uint8_t JPG_MARKER_RSTN = 0XD7;
constexpr uint8_t JPG_MARKER_APP = 0XE0;
constexpr uint8_t JPG_MARKER_APP0 = 0XE0;
constexpr uint8_t JPG_MARKER_APPN = 0XEF;
constexpr size_t TIMES_LEN = 19;
constexpr size_t DATE_LEN = 10;
const std::string BITS_PER_SAMPLE = "BitsPerSample";
const std::string ORIENTATION = "Orientation";
const std::string IMAGE_LENGTH = "ImageLength";
const std::string IMAGE_WIDTH = "ImageWidth";
const std::string GPS_LATITUDE = "GPSLatitude";
const std::string GPS_LONGITUDE = "GPSLongitude";
const std::string GPS_LATITUDE_REF = "GPSLatitudeRef";
const std::string GPS_LONGITUDE_REF = "GPSLongitudeRef";
const std::string DATE_TIME_ORIGINAL = "DateTimeOriginal";
const std::string DATE_TIME_ORIGINAL_MEDIA = "DateTimeOriginalForMedia";
const std::string EXPOSURE_TIME = "ExposureTime";
const std::string F_NUMBER = "FNumber";
const std::string ISO_SPEED_RATINGS = "ISOSpeedRatings";
const std::string SCENE_TYPE = "SceneType";
const std::string COMPRESSED_BITS_PER_PIXEL = "CompressedBitsPerPixel";
static const std::map<std::string, uint32_t> PROPERTY_INT = {
    {"Top-left", 0},
    {"Bottom-right", 180},
    {"Right-top", 90},
    {"Left-bottom", 270},
};
constexpr uint32_t JPEG_APP1_SIZE = 2;
constexpr uint32_t ADDRESS_4 = 4;
constexpr int OFFSET_8 = 8;
} // namespace

PluginServer &JpegDecoder::pluginServer_ = DelayedRefSingleton<PluginServer>::GetInstance();

JpegSrcMgr::JpegSrcMgr(InputDataStream *stream) : inputStream(stream)
{
    init_source = InitSrcStream;
    fill_input_buffer = FillInputBuffer;
    skip_input_data = SkipInputData;
    resync_to_restart = jpeg_resync_to_restart;
    term_source = TermSrcStream;
}

JpegDecoder::JpegDecoder() : srcMgr_(nullptr)
{
    CreateDecoder();
#if !defined(_WIN32) && !defined(_APPLE) && !defined(_ANDROID) && !defined(_IOS)
    CreateHwDecompressor();
#endif
}

void JpegDecoder::CreateDecoder()
{
    // create decompress struct
    jpeg_create_decompress(&decodeInfo_);

    // set error output
    decodeInfo_.err = jpeg_std_error(&jerr_);
    jerr_.error_exit = ErrorExit;
    if (decodeInfo_.err == nullptr) {
        HiLog::Error(LABEL, "create jpeg decoder failed.");
        return;
    }
    decodeInfo_.err->output_message = &OutputErrorMessage;
}

JpegDecoder::~JpegDecoder()
{
    jpeg_destroy_decompress(&decodeInfo_);
    if (hwJpegDecompress_ != nullptr) {
        delete hwJpegDecompress_;
        hwJpegDecompress_ = nullptr;
    }
}

void JpegDecoder::SetSource(InputDataStream &sourceStream)
{
    srcMgr_.inputStream = &sourceStream;
    state_ = JpegDecodingState::SOURCE_INITED;
}

uint32_t JpegDecoder::GetImageSize(uint32_t index, PlSize &size)
{
    if (index >= JPEG_IMAGE_NUM) {
        HiLog::Error(LABEL, "decode image index:[%{public}u] out of range:[%{public}u].", index, JPEG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < JpegDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "get image size failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ >= JpegDecodingState::BASE_INFO_PARSED) {
        size.width = decodeInfo_.image_width;
        size.height = decodeInfo_.image_height;
        return Media::SUCCESS;
    }
    // only state JpegDecodingState::SOURCE_INITED and JpegDecodingState::BASE_INFO_PARSING can go here.
    uint32_t ret = DecodeHeader();
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "decode header error on get image size, ret:%{public}u.", ret);
        state_ = JpegDecodingState::BASE_INFO_PARSING;
        return ret;
    }
    size.width = decodeInfo_.image_width;
    size.height = decodeInfo_.image_height;
    state_ = JpegDecodingState::BASE_INFO_PARSED;
    return Media::SUCCESS;
}

J_COLOR_SPACE JpegDecoder::GetDecodeFormat(PlPixelFormat format, PlPixelFormat &outputFormat)
{
    outputFormat = format;
    J_COLOR_SPACE colorSpace = JCS_UNKNOWN;
    switch (format) {
        case PlPixelFormat::UNKNOWN:
        case PlPixelFormat::RGBA_8888: {
            colorSpace = JCS_EXT_RGBA;
            outputFormat = PlPixelFormat::RGBA_8888;
            break;
        }
        case PlPixelFormat::BGRA_8888: {
            colorSpace = JCS_EXT_BGRA;
            outputFormat = PlPixelFormat::BGRA_8888;
            break;
        }
        case PlPixelFormat::ARGB_8888: {
            colorSpace = JCS_EXT_ARGB;
            break;
        }
        case PlPixelFormat::ALPHA_8: {
            colorSpace = JCS_GRAYSCALE;
            break;
        }
        case PlPixelFormat::RGB_565: {
            colorSpace = JCS_RGB;
            outputFormat = PlPixelFormat::RGB_888;
            break;
        }
        case PlPixelFormat::RGB_888: {
            // NOTICE: libjpeg make BE as default when we are LE
            colorSpace = JCS_EXT_BGR;
            break;
        }
        default: {
            colorSpace = JCS_EXT_RGBA;
            outputFormat = PlPixelFormat::RGBA_8888;
            break;
        }
    }
    return colorSpace;
}

uint32_t JpegDecoder::SetDecodeOptions(uint32_t index, const PixelDecodeOptions &opts, PlImageInfo &info)
{
    if (index >= JPEG_IMAGE_NUM) {
        HiLog::Error(LABEL, "decode image index:[%{public}u] out of range:[%{public}u].", index, JPEG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < JpegDecodingState::SOURCE_INITED) {
        HiLog::Error(LABEL, "set decode options failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ >= JpegDecodingState::IMAGE_DECODING) {
        FinishOldDecompress();
        state_ = JpegDecodingState::SOURCE_INITED;
    }
    if (state_ < JpegDecodingState::BASE_INFO_PARSED) {
        uint32_t ret = DecodeHeader();
        if (ret != Media::SUCCESS) {
            state_ = JpegDecodingState::BASE_INFO_PARSING;
            HiLog::Error(LABEL, "decode header error on set decode options:%{public}u.", ret);
            return ret;
        }
        state_ = JpegDecodingState::BASE_INFO_PARSED;
    }
    // only state JpegDecodingState::BASE_INFO_PARSED can go here.
    uint32_t ret = StartDecompress(opts);
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "start decompress failed on set decode options:%{public}u.", ret);
        return ret;
    }
    info.pixelFormat = outputFormat_;
    info.size.width = decodeInfo_.output_width;
    info.size.height = decodeInfo_.output_height;
    info.alphaType = PlAlphaType::IMAGE_ALPHA_TYPE_OPAQUE;
    opts_ = opts;
    state_ = JpegDecodingState::IMAGE_DECODING;
    return Media::SUCCESS;
}

uint32_t JpegDecoder::GetRowBytes()
{
    uint32_t pixelBytes =
        (decodeInfo_.out_color_space == JCS_RGB565) ? PIXEL_BYTES_RGB_565 : decodeInfo_.out_color_components;
    return decodeInfo_.output_width * pixelBytes;
}

uint32_t JpegDecoder::DoSwDecode(DecodeContext &context) __attribute__((no_sanitize("cfi")))
{
    if (setjmp(jerr_.setjmp_buffer)) {
        HiLog::Error(LABEL, "decode image failed.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    uint32_t rowStride = GetRowBytes();
    if (context.pixelsBuffer.buffer == nullptr) {
        uint64_t byteCount = static_cast<uint64_t>(rowStride) * decodeInfo_.output_height;
        if (context.allocatorType == Media::AllocatorType::SHARE_MEM_ALLOC) {
#if !defined(_WIN32) && !defined(_APPLE) && !defined(_ANDROID) && !defined(_IOS)
            int fd = AshmemCreate("JPEG RawData", byteCount);
            if (fd < 0) {
                return ERR_SHAMEM_DATA_ABNORMAL;
            }
            int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
            if (result < 0) {
                ::close(fd);
                return ERR_SHAMEM_DATA_ABNORMAL;
            }
            void* ptr = ::mmap(nullptr, byteCount, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (ptr == MAP_FAILED) {
                ::close(fd);
                return ERR_SHAMEM_DATA_ABNORMAL;
            }
            context.pixelsBuffer.buffer = ptr;
            void *fdBuffer = new int32_t();
            if (fdBuffer == nullptr) {
                HiLog::Error(LABEL, "new fdBuffer fail");
                ::munmap(ptr, byteCount);
                ::close(fd);
                context.pixelsBuffer.buffer = nullptr;
                return ERR_SHAMEM_DATA_ABNORMAL;
            }
            *static_cast<int32_t *>(fdBuffer) = fd;
            context.pixelsBuffer.context = fdBuffer;
            context.pixelsBuffer.bufferSize = byteCount;
            context.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
            context.freeFunc = nullptr;
#endif
        } else {
            void *outputBuffer = malloc(byteCount);
            if (outputBuffer == nullptr) {
                HiLog::Error(LABEL, "alloc output buffer size:[%{public}llu] error.",
                             static_cast<unsigned long long>(byteCount));
                return ERR_IMAGE_MALLOC_ABNORMAL;
            }
            context.pixelsBuffer.buffer = outputBuffer;
            context.pixelsBuffer.context = nullptr;
            context.pixelsBuffer.bufferSize = byteCount;
            context.allocatorType = AllocatorType::HEAP_ALLOC;
            context.freeFunc = nullptr;
        }
    }
    uint8_t *base = static_cast<uint8_t *>(context.pixelsBuffer.buffer);
    if (base == nullptr) {
        HiLog::Error(LABEL, "decode image buffer is null.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    srcMgr_.inputStream->Seek(streamPosition_);
    uint8_t *buffer = nullptr;
    while (decodeInfo_.output_scanline < decodeInfo_.output_height) {
        buffer = base + rowStride * decodeInfo_.output_scanline;
        uint32_t readLineNum = jpeg_read_scanlines(&decodeInfo_, &buffer, RW_LINE_NUM);
        if (readLineNum < RW_LINE_NUM) {
            streamPosition_ = srcMgr_.inputStream->Tell();
            HiLog::Error(LABEL, "read line fail, read num:%{public}u, total read num:%{public}u.", readLineNum,
                         decodeInfo_.output_scanline);
            return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
        }
    }
    streamPosition_ = srcMgr_.inputStream->Tell();

#ifdef IMAGE_COLORSPACE_FLAG
    // parser icc profile info
    uint32_t iccPaseredResult = iccProfileInfo_.ParsingICCProfile(&decodeInfo_);
    if (iccPaseredResult == OHOS::Media::ERR_IMAGE_DENCODE_ICC_FAILED) {
        HiLog::Error(LABEL, "dencode image icc error.");
        return iccPaseredResult;
    }
#endif

    return Media::SUCCESS;
}

uint32_t JpegDecoder::Decode(uint32_t index, DecodeContext &context)
{
    if (index >= JPEG_IMAGE_NUM) {
        HiLog::Error(LABEL, "decode image index:[%{public}u] out of range:[%{public}u].", index, JPEG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ < JpegDecodingState::IMAGE_DECODING) {
        HiLog::Error(LABEL, "decode failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }
    if (state_ > JpegDecodingState::IMAGE_DECODING) {
        FinishOldDecompress();
        state_ = JpegDecodingState::SOURCE_INITED;
        uint32_t ret = DecodeHeader();
        if (ret != Media::SUCCESS) {
            state_ = JpegDecodingState::BASE_INFO_PARSING;
            HiLog::Error(LABEL, "decode header error on decode:%{public}u.", ret);
            return ret;
        }
        state_ = JpegDecodingState::BASE_INFO_PARSED;
        ret = StartDecompress(opts_);
        if (ret != Media::SUCCESS) {
            HiLog::Error(LABEL, "start decompress failed on decode:%{public}u.", ret);
            return ret;
        }
        state_ = JpegDecodingState::IMAGE_DECODING;
    }
    // only state JpegDecodingState::IMAGE_DECODING can go here.
    if (hwJpegDecompress_ != nullptr) {
        srcMgr_.inputStream->Seek(streamPosition_);
        uint32_t ret = hwJpegDecompress_->Decompress(&decodeInfo_, srcMgr_.inputStream, context);
        if (ret == Media::SUCCESS) {
            state_ = JpegDecodingState::IMAGE_DECODED;
            HiLog::Debug(LABEL, "jpeg hardware decode success.");
            return ret;
        }
    }
    uint32_t ret = DoSwDecode(context);
    if (ret == Media::SUCCESS) {
        state_ = JpegDecodingState::IMAGE_DECODED;
        HiLog::Debug(LABEL, "jpeg software decode success.");
        return Media::SUCCESS;
    }
    if (ret == ERR_IMAGE_SOURCE_DATA_INCOMPLETE && opts_.allowPartialImage) {
        state_ = JpegDecodingState::IMAGE_PARTIAL;
        context.ifPartialOutput = true;
        return Media::SUCCESS;
    }
    state_ = JpegDecodingState::IMAGE_ERROR;
    return ret;
}

void JpegDecoder::Reset()
{
    srcMgr_.inputStream = nullptr;
}

uint32_t JpegDecoder::PromoteIncrementalDecode(uint32_t index, ProgDecodeContext &progContext)
{
    progContext.totalProcessProgress = 0;
    if (index >= JPEG_IMAGE_NUM) {
        HiLog::Error(LABEL, "decode image index:[%{public}u] out of range:[%{public}u].", index, JPEG_IMAGE_NUM);
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    if (state_ != JpegDecodingState::IMAGE_DECODING) {
        HiLog::Error(LABEL, "incremental decode failed for state %{public}d.", state_);
        return ERR_MEDIA_INVALID_OPERATION;
    }

    uint32_t ret = DoSwDecode(progContext.decodeContext);
    if (ret == Media::SUCCESS) {
        state_ = JpegDecodingState::IMAGE_DECODED;
    }
    // get promote decode progress, in percentage: 0~100.
    progContext.totalProcessProgress =
        decodeInfo_.output_height == 0 ? 0 : (decodeInfo_.output_scanline * NUM_100) / decodeInfo_.output_height;
    HiLog::Debug(LABEL, "incremental decode progress %{public}u.", progContext.totalProcessProgress);
    return ret;
}

void JpegDecoder::CreateHwDecompressor()
{
    std::map<std::string, AttrData> capabilities;
    const std::string format = "image/jpeg";
    capabilities.insert(std::map<std::string, AttrData>::value_type("encodeFormat", AttrData(format)));
    hwJpegDecompress_ = pluginServer_.CreateObject<AbsImageDecompressComponent>(
        AbsImageDecompressComponent::SERVICE_DEFAULT, capabilities);
    if (hwJpegDecompress_ == nullptr) {
        HiLog::Error(LABEL, "get hardware jpeg decompress component failed.");
        return;
    }
}

void JpegDecoder::FinishOldDecompress()
{
    if (state_ < JpegDecodingState::IMAGE_DECODING) {
        return;
    }
    jpeg_destroy_decompress(&decodeInfo_);
    CreateDecoder();
}

bool JpegDecoder::IsMarker(uint8_t rawMarkerPrefix, uint8_t rawMarkderCode, uint8_t markerCode)
{
    if (rawMarkerPrefix != JPG_MARKER_PREFIX) {
        return false;
    }

    // RSTn, n from 0 to 7
    if (rawMarkderCode >= JPG_MARKER_RST0 && rawMarkderCode <= JPG_MARKER_RSTN && markerCode == JPG_MARKER_RST) {
        return true;
    }

    // APPn, n from 0 to 15
    if (rawMarkderCode >= JPG_MARKER_APP0 && rawMarkderCode <= JPG_MARKER_APPN && markerCode == JPG_MARKER_APP) {
        return true;
    }

    if (rawMarkderCode == markerCode) {
        return true;
    }
    return false;
}

bool JpegDecoder::FindMarker(InputDataStream &stream, uint8_t marker)
{
    uint8_t buffer[MARKER_SIZE] = { 0 };
    uint32_t readSize = 0;
    stream.Seek(0);
    while (true) {
        uint32_t cur = stream.Tell();
        if (!stream.Seek(cur + MARKER_SIZE)) {
            return false;
        }
        stream.Seek(cur);

        // read marker code
        stream.Read(MARKER_SIZE, buffer, sizeof(buffer), readSize);
        if (readSize != MARKER_SIZE) {
            return false;
        }

        uint8_t markerPrefix = buffer[JPG_MARKER_PREFIX_OFFSET];
        uint8_t markerCode = buffer[JPG_MARKER_CODE_OFFSET];
        if (IsMarker(markerPrefix, markerCode, JPG_MARKER_SOS)) {
            return true;
        }

        if (IsMarker(markerPrefix, markerCode, JPG_MARKER_SOI) || IsMarker(markerPrefix, markerCode, JPG_MARKER_RST)) {
            continue;
        }

        cur = stream.Tell();
        if (!stream.Seek(cur + MARKER_LENGTH)) {
            return false;
        }
        stream.Seek(cur);
        // read marker length
        stream.Read(MARKER_LENGTH, buffer, sizeof(buffer), readSize);
        if (readSize != MARKER_LENGTH) {
            return false;
        }
        // skip data, length = sizeof(length) + sizeof(data)
        uint32_t length = (buffer[MARKER_LENGTH_0_OFFSET] << MARKER_LENGTH_SHIFT) + buffer[MARKER_LENGTH_1_OFFSET];
        if (!stream.Seek(cur + length)) {
            return false;
        }
    }
}

uint32_t JpegDecoder::DecodeHeader()
{
    if (setjmp(jerr_.setjmp_buffer)) {
        HiLog::Error(LABEL, "get image size failed.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    if (state_ == JpegDecodingState::SOURCE_INITED) {
        srcMgr_.inputStream->Seek(0);
    } else {
        srcMgr_.inputStream->Seek(streamPosition_);
    }
    decodeInfo_.src = &srcMgr_;

    /**
     * The function jpeg_read_header() shall read the JPEG datastream until the first SOS marker is encountered
     * incremental decoding should have enough data(contains SOS marker) before calling jpeg_read_header.
     */
    if (!srcMgr_.inputStream->IsStreamCompleted()) {
        uint32_t curPos = srcMgr_.inputStream->Tell();
        while (true) {
            if (!FindMarker(*srcMgr_.inputStream, JPG_MARKER_SOS)) {
                srcMgr_.inputStream->Seek(curPos);
                return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
            }
            srcMgr_.inputStream->Seek(curPos);
            break;
        }
    }

    // call jpeg_save_markers, use to get ICC profile.
    jpeg_save_markers(&decodeInfo_, PL_ICC_MARKER, PL_MARKER_LENGTH_LIMIT);
    int32_t ret = jpeg_read_header(&decodeInfo_, false);
    streamPosition_ = srcMgr_.inputStream->Tell();
    if (ret == JPEG_SUSPENDED) {
        HiLog::Debug(LABEL, "image input data incomplete, decode header error:%{public}u.", ret);
        return ERR_IMAGE_SOURCE_DATA_INCOMPLETE;
    } else if (ret != JPEG_HEADER_OK) {
        HiLog::Error(LABEL, "image type is not jpeg, decode header error:%{public}u.", ret);
        return ERR_IMAGE_GET_DATA_ABNORMAL;
    }
    return Media::SUCCESS;
}

uint32_t JpegDecoder::StartDecompress(const PixelDecodeOptions &opts)
{
    if (setjmp(jerr_.setjmp_buffer)) {
        HiLog::Error(LABEL, "set output image info failed.");
        return ERR_IMAGE_DECODE_ABNORMAL;
    }
    // set decode options
    if (decodeInfo_.jpeg_color_space == JCS_CMYK || decodeInfo_.jpeg_color_space == JCS_YCCK) {
        // can't support CMYK to alpha8 convert
        if (opts.desiredPixelFormat == PlPixelFormat::ALPHA_8) {
            HiLog::Error(LABEL, "can't support colorspace CMYK to alpha convert.");
            return ERR_IMAGE_UNKNOWN_FORMAT;
        }
        HiLog::Debug(LABEL, "jpeg colorspace is CMYK.");
        decodeInfo_.out_color_space = JCS_CMYK;
        outputFormat_ = PlPixelFormat::CMYK;
    } else {
        decodeInfo_.out_color_space = GetDecodeFormat(opts.desiredPixelFormat, outputFormat_);
        if (decodeInfo_.out_color_space == JCS_UNKNOWN) {
            HiLog::Error(LABEL, "set jpeg output color space invalid.");
            return ERR_IMAGE_UNKNOWN_FORMAT;
        }
    }
    srcMgr_.inputStream->Seek(streamPosition_);
    if (jpeg_start_decompress(&decodeInfo_) != TRUE) {
        streamPosition_ = srcMgr_.inputStream->Tell();
        HiLog::Error(LABEL, "jpeg start decompress failed, invalid input.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }
    streamPosition_ = srcMgr_.inputStream->Tell();
    return Media::SUCCESS;
}

bool JpegDecoder::ParseExifData()
{
    HiLog::Debug(LABEL, "ParseExifData enter");
    uint32_t curPos = srcMgr_.inputStream->Tell();
    srcMgr_.inputStream->Seek(0);
    unsigned long fsize = static_cast<unsigned long>(srcMgr_.inputStream->GetStreamSize());
    if (fsize <= 0) {
        HiLog::Error(LABEL, "Get stream size failed");
        return false;
    }
    unsigned char *buf = new unsigned char[fsize];
    uint32_t readSize = 0;
    srcMgr_.inputStream->Read(fsize, buf, fsize, readSize);
    HiLog::Debug(LABEL, "parsing EXIF: fsize %{public}lu", fsize);

    int code = exifInfo_.ParseExifData(buf, fsize);
    delete[] buf;
    srcMgr_.inputStream->Seek(curPos);
    if (code) {
        HiLog::Error(LABEL, "Error parsing EXIF: code %{public}d", code);
        return false;
    }
    return true;
}

uint32_t JpegDecoder::GetImagePropertyInt(uint32_t index, const std::string &key, int32_t &value)
{
    HiLog::Debug(LABEL, "[GetImagePropertyInt] enter jpeg plugin, key:%{public}s", key.c_str());
    if (IsSameTextStr(key, ACTUAL_IMAGE_ENCODED_FORMAT)) {
        HiLog::Error(LABEL, "[GetImagePropertyInt] this key is used to check the original format of raw image!");
        return Media::ERR_MEDIA_VALUE_INVALID;
    }

    if (!exifInfo_.IsExifDataParsed()) {
        if (!ParseExifData()) {
            HiLog::Error(LABEL, "[GetImagePropertyInt] Parse exif data failed!");
            return Media::ERROR;
        }
    }
    if (IsSameTextStr(key, ORIENTATION)) {
        if (PROPERTY_INT.find(exifInfo_.orientation_) != PROPERTY_INT.end()) {
            value = PROPERTY_INT.at(exifInfo_.orientation_);
        } else {
            HiLog::Error(LABEL, "[GetImagePropertyInt] The ORIENTATION parameter is not supported int32_t");
            HiLog::Error(LABEL, "[GetImagePropertyInt] The exifinfo:%{public}s is not found",
                exifInfo_.orientation_.c_str());
            return Media::ERR_MEDIA_VALUE_INVALID;
        }
    } else {
        HiLog::Error(LABEL, "[GetImagePropertyInt] The key:%{public}s is not supported int32_t", key.c_str());
        return Media::ERR_MEDIA_VALUE_INVALID;
    }
    return Media::SUCCESS;
}

uint32_t JpegDecoder::GetImagePropertyString(uint32_t index, const std::string &key, std::string &value)
{
    HiLog::Debug(LABEL, "[GetImagePropertyString] enter jpeg plugin, key:%{public}s", key.c_str());
    if (IsSameTextStr(key, ACTUAL_IMAGE_ENCODED_FORMAT)) {
        HiLog::Error(LABEL, "[GetImagePropertyString] this key is used to check the original format of raw image!");
        return Media::ERR_MEDIA_VALUE_INVALID;
    }

    if (!exifInfo_.IsExifDataParsed()) {
        if (!ParseExifData()) {
            HiLog::Error(LABEL, "[GetImagePropertyString] Parse exif data failed!");
            return Media::ERROR;
        }
    }

    if (IsSameTextStr(key, BITS_PER_SAMPLE)) {
        value = exifInfo_.bitsPerSample_;
    } else if (IsSameTextStr(key, ORIENTATION)) {
        value = exifInfo_.orientation_;
    } else if (IsSameTextStr(key, IMAGE_LENGTH)) {
        value = exifInfo_.imageLength_;
    } else if (IsSameTextStr(key, IMAGE_WIDTH)) {
        value = exifInfo_.imageWidth_;
    } else if (IsSameTextStr(key, GPS_LATITUDE)) {
        value = exifInfo_.gpsLatitude_;
    } else if (IsSameTextStr(key, GPS_LONGITUDE)) {
        value = exifInfo_.gpsLongitude_;
    } else if (IsSameTextStr(key, GPS_LATITUDE_REF)) {
        value = exifInfo_.gpsLatitudeRef_;
    } else if (IsSameTextStr(key, GPS_LONGITUDE_REF)) {
        value = exifInfo_.gpsLongitudeRef_;
    } else if (IsSameTextStr(key, DATE_TIME_ORIGINAL)) {
        value = exifInfo_.dateTimeOriginal_;
    } else if (IsSameTextStr(key, DATE_TIME_ORIGINAL_MEDIA)) {
        FormatTimeStamp(value, exifInfo_.dateTimeOriginal_);
    } else if (IsSameTextStr(key, EXPOSURE_TIME)) {
        value = exifInfo_.exposureTime_;
    } else if (IsSameTextStr(key, F_NUMBER)) {
        value = exifInfo_.fNumber_;
    } else if (IsSameTextStr(key, ISO_SPEED_RATINGS)) {
        value = exifInfo_.isoSpeedRatings_;
    } else if (IsSameTextStr(key, SCENE_TYPE)) {
        value = exifInfo_.sceneType_;
    } else if (IsSameTextStr(key, COMPRESSED_BITS_PER_PIXEL)) {
        value = exifInfo_.compressedBitsPerPixel_;
    } else {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    if (IsSameTextStr(value, EXIFInfo::DEFAULT_EXIF_VALUE)) {
        HiLog::Error(LABEL, "[GetImagePropertyString] enter jpeg plugin, ifd and entry are not matched!");
        return Media::ERR_MEDIA_VALUE_INVALID;
    }
    HiLog::Debug(LABEL, "[GetImagePropertyString] enter jpeg plugin, value:%{public}s", value.c_str());
    return Media::SUCCESS;
}

void InitOriginalTimes(std::string &dataTime)
{
    for (size_t i = 0; i < dataTime.size() && i < TIMES_LEN; i++) {
        if ((dataTime[i] < '0' || dataTime[i] > '9') && dataTime[i] != ' ') {
            if (i < DATE_LEN) {
                dataTime[i] = '-';
            } else {
                dataTime[i] = ':';
            }
        }
    }
}

std::string SetOriginalTimes(std::string &dataTime)
{
    InitOriginalTimes(dataTime);
    std::string data = "";
    std::string time = "";
    std::string::size_type position = dataTime.find(" ");
    if (position == dataTime.npos) {
        data = dataTime;
        if (data.find("-") == data.npos) {
            data += "-01-01";
        } else if (data.find_first_of("-") == data.find_last_of("-")) {
            data += "-01";
        }
        time += " 00:00:00";
    } else {
        data = dataTime.substr(0, position);
        time = dataTime.substr(position);
        if (data.find("-") == data.npos) {
            data += "-01-01";
        } else if (data.find_first_of("-") == data.find_last_of("-")) {
            data += "-01";
        }
        if (time.find(":") == data.npos) {
            time += ":00:00";
        } else if (time.find_first_of(":") == time.find_last_of(":")) {
            time += ":00";
        } else {
            std::string timeTmp = time;
            time = timeTmp.substr(0, time.find("."));
        }
    }
    return data + time;
}

void JpegDecoder::FormatTimeStamp(std::string &value, std::string &src)
{
    value = "";
    if (!IsSameTextStr(src, "")) {
        value = SetOriginalTimes(src);
    }
}

ExifTag JpegDecoder::getExifTagFromKey(const std::string &key)
{
    if (IsSameTextStr(key, BITS_PER_SAMPLE)) {
        return EXIF_TAG_BITS_PER_SAMPLE;
    } else if (IsSameTextStr(key, ORIENTATION)) {
        return EXIF_TAG_ORIENTATION;
    } else if (IsSameTextStr(key, IMAGE_LENGTH)) {
        return EXIF_TAG_IMAGE_LENGTH;
    } else if (IsSameTextStr(key, IMAGE_WIDTH)) {
        return EXIF_TAG_IMAGE_WIDTH;
    } else if (IsSameTextStr(key, GPS_LATITUDE)) {
        return EXIF_TAG_GPS_LATITUDE;
    } else if (IsSameTextStr(key, GPS_LONGITUDE)) {
        return EXIF_TAG_GPS_LONGITUDE;
    } else if (IsSameTextStr(key, GPS_LATITUDE_REF)) {
        return EXIF_TAG_GPS_LATITUDE_REF;
    } else if (IsSameTextStr(key, GPS_LONGITUDE_REF)) {
        return EXIF_TAG_GPS_LONGITUDE_REF;
    } else if (IsSameTextStr(key, DATE_TIME_ORIGINAL)) {
        return EXIF_TAG_DATE_TIME_ORIGINAL;
    } else if (IsSameTextStr(key, EXPOSURE_TIME)) {
        return EXIF_TAG_EXPOSURE_TIME;
    } else if (IsSameTextStr(key, F_NUMBER)) {
        return EXIF_TAG_FNUMBER;
    } else if (IsSameTextStr(key, ISO_SPEED_RATINGS)) {
        return EXIF_TAG_ISO_SPEED_RATINGS;
    } else if (IsSameTextStr(key, SCENE_TYPE)) {
        return EXIF_TAG_SCENE_TYPE;
    } else if (IsSameTextStr(key, COMPRESSED_BITS_PER_PIXEL)) {
        return EXIF_TAG_COMPRESSED_BITS_PER_PIXEL;
    } else {
        return EXIF_TAG_PRINT_IMAGE_MATCHING;
    }
}

uint32_t JpegDecoder::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const std::string &path)
{
    HiLog::Debug(LABEL, "[ModifyImageProperty] with path:%{public}s, key:%{public}s, value:%{public}s",
        path.c_str(), key.c_str(), value.c_str());
    ExifTag tag = getExifTagFromKey(key);
    if (tag == EXIF_TAG_PRINT_IMAGE_MATCHING) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint32_t ret = exifInfo_.ModifyExifData(tag, value, path);
    if (ret != Media::SUCCESS) {
        return ret;
    }
    return Media::SUCCESS;
}

uint32_t JpegDecoder::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, const int fd)
{
    HiLog::Debug(LABEL, "[ModifyImageProperty] with fd:%{public}d, key:%{public}s, value:%{public}s",
        fd, key.c_str(), value.c_str());
    ExifTag tag = getExifTagFromKey(key);
    if (tag == EXIF_TAG_PRINT_IMAGE_MATCHING) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint32_t ret = exifInfo_.ModifyExifData(tag, value, fd);
    if (ret != Media::SUCCESS) {
        return ret;
    }
    return Media::SUCCESS;
}

uint32_t JpegDecoder::ModifyImageProperty(uint32_t index, const std::string &key,
    const std::string &value, uint8_t *data, uint32_t size)
{
    HiLog::Debug(LABEL, "[ModifyImageProperty] with key:%{public}s, value:%{public}s",
        key.c_str(), value.c_str());
    ExifTag tag = getExifTagFromKey(key);
    if (tag == EXIF_TAG_PRINT_IMAGE_MATCHING) {
        return Media::ERR_IMAGE_DECODE_EXIF_UNSUPPORT;
    }

    uint32_t ret = exifInfo_.ModifyExifData(tag, value, data, size);
    if (ret != Media::SUCCESS) {
        return ret;
    }
    return Media::SUCCESS;
}

uint32_t JpegDecoder::GetFilterArea(const int &privacyType, std::vector<std::pair<uint32_t, uint32_t>> &ranges)
{
    HiLog::Debug(LABEL, "[GetFilterArea] with privacyType:%{public}d ", privacyType);
    if (srcMgr_.inputStream == nullptr) {
        HiLog::Error(LABEL, "[GetFilterArea] srcMgr_.inputStream is nullptr.");
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }
    uint32_t curPos = srcMgr_.inputStream->Tell();
    srcMgr_.inputStream->Seek(ADDRESS_4);
    // app1SizeBuf is used to get value of EXIF data size
    uint8_t *app1SizeBuf = new uint8_t[JPEG_APP1_SIZE];
    uint32_t readSize = 0;
    if (!srcMgr_.inputStream->Read(JPEG_APP1_SIZE, app1SizeBuf, JPEG_APP1_SIZE, readSize)) {
        HiLog::Error(LABEL, "[GetFilterArea] get app1 size failed.");
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }
    uint32_t app1Size =
        static_cast<unsigned int>(app1SizeBuf[1]) | static_cast<unsigned int>(app1SizeBuf[0] << OFFSET_8);
    delete[] app1SizeBuf;
    uint32_t fsize = static_cast<uint32_t>(srcMgr_.inputStream->GetStreamSize());
    if (app1Size > fsize) {
        HiLog::Error(LABEL, "[GetFilterArea] file format is illegal.");
        return Media::ERR_MEDIA_INVALID_OPERATION;
    }

    srcMgr_.inputStream->Seek(0);
    uint32_t bufSize = app1Size + ADDRESS_4;
    // buf is from image file head to exif data end
    uint8_t *buf = new uint8_t[bufSize];
    srcMgr_.inputStream->Read(bufSize, buf, bufSize, readSize);
    uint32_t ret = exifInfo_.GetFilterArea(buf, bufSize, privacyType, ranges);
    delete[] buf;
    srcMgr_.inputStream->Seek(curPos);
    if (ret != Media::SUCCESS) {
        HiLog::Error(LABEL, "[GetFilterArea]: failed to get area, errno %{public}d", ret);
        return ret;
    }
    return Media::SUCCESS;
}

#ifdef IMAGE_COLORSPACE_FLAG
OHOS::ColorManager::ColorSpace JpegDecoder::getGrColorSpace()
{
    OHOS::ColorManager::ColorSpace grColorSpace = iccProfileInfo_.getGrColorSpace();
    return grColorSpace;
}

bool JpegDecoder::IsSupportICCProfile()
{
    bool isSupportICCProfile = iccProfileInfo_.IsSupportICCProfile();
    return isSupportICCProfile;
}
#endif
} // namespace ImagePlugin
} // namespace OHOS
