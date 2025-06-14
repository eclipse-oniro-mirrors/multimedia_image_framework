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

#ifndef FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_UTILS_H
#define FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_UTILS_H

#include <cstdlib>
#include <cstdio>
#include <string>
#include "image_type.h"
#include "iosfwd"

namespace OHOS { namespace MultimediaPlugin { class PluginServer; } }
namespace OHOS { namespace ImagePlugin { struct DecodeContext; } }
namespace OHOS {
namespace Media {
const std::string IMAGE_ENCODE_FORMAT = "encodeFormat";
constexpr uint32_t MALLOC_MAX_LENTH = 0x40000000;
constexpr int32_t APIVERSION_13 = 13;
constexpr int32_t APIVERSION_20 = 20;
class PixelMap;
struct InitializationOptions;

class ImageUtils {
public:
    static bool GetFileSize(const std::string &pathName, size_t &size);
    static bool GetFileSize(const int fd, size_t &size);
    static bool GetInputStreamSize(std::istream &inputStream, size_t &size);
    static int32_t GetPixelBytes(const PixelFormat &pixelFormat);
    static int32_t GetRowDataSizeByPixelFormat(const int32_t &width, const PixelFormat &format);
    static bool PathToRealPath(const std::string &path, std::string &realPath);
    static bool FloatCompareZero(float src);
    static AlphaType GetValidAlphaTypeByFormat(const AlphaType &dstType, const PixelFormat &format);
    static AllocatorType GetPixelMapAllocatorType(const Size &size, const PixelFormat &format, bool preferDma);
    static bool IsValidImageInfo(const ImageInfo &info);
    static bool IsValidAuxiliaryInfo(const std::shared_ptr<PixelMap> &pixelMap, const AuxiliaryPictureInfo &info);
    static bool IsAstc(PixelFormat format);
    static bool IsWidthAligned(const int32_t &width);
    static bool IsSizeSupportDma(const Size &size);
    static bool IsFormatSupportDma(const PixelFormat &format);
    static bool Is10Bit(const PixelFormat &format);
    static MultimediaPlugin::PluginServer& GetPluginServer();
    static bool CheckMulOverflow(int32_t width, int32_t bytesPerPixel);
    static bool CheckMulOverflow(int32_t width, int32_t height, int32_t bytesPerPixel);
    static void BGRAToARGB(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount);
    static void ARGBToBGRA(uint8_t* srcPixels, uint8_t* dstPixels, uint32_t byteCount);
    static int32_t SurfaceBuffer_Reference(void* buffer);
    static int32_t SurfaceBuffer_Unreference(void* buffer);
    static void DumpPixelMap(PixelMap* pixelMap, std::string customFileName, uint64_t imageId = 0);
    static void DumpPixelMapIfDumpEnabled(std::unique_ptr<PixelMap>& pixelMap, uint64_t imageId = 0);
    static void DumpPixelMapIfDumpEnabled(PixelMap& pixelMap, std::string func);
    static void DumpPixelMapBeforeEncode(PixelMap& pixelMap);
    static void DumpDataIfDumpEnabled(const char* data, const size_t& totalSize, const std::string& fileSuffix = "dat",
        uint64_t imageId = 0);
    static uint64_t GetNowTimeMilliSeconds();
    static uint64_t GetNowTimeMicroSeconds();
    static std::string GetCurrentProcessName();
    static bool SetInitializationOptionAutoMem(InitializationOptions &option);
    static bool SetInitializationOptionDmaMem(InitializationOptions &option);
    static bool SetInitializationOptionAllocatorType(InitializationOptions &option, int32_t allocatorType);
    // BytesToXXX and xxxToBytes function will modify the offset value.
    static uint16_t BytesToUint16(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian = true);
    static uint32_t BytesToUint32(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian = true);
    static int32_t BytesToInt32(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian = true);
    static float BytesToFloat(uint8_t* bytes, uint32_t& offset, uint32_t size, bool isBigEndian = true);
    static void Uint16ToBytes(uint16_t data, std::vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian = true);
    static void Uint32ToBytes(uint32_t data, std::vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian = true);
    static void FloatToBytes(float data, std::vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian = true);
    static void Int32ToBytes(int32_t data, std::vector<uint8_t>& bytes, uint32_t& offset, bool isBigEndian = true);
    static void ArrayToBytes(const uint8_t* data, uint32_t length, std::vector<uint8_t>& bytes, uint32_t& offset);
    static void FlushSurfaceBuffer(PixelMap* pixelMap);
    static void FlushContextSurfaceBuffer(ImagePlugin::DecodeContext& context);
    static void InvalidateContextSurfaceBuffer(ImagePlugin::DecodeContext& context);
    static bool IsAuxiliaryPictureTypeSupported(AuxiliaryPictureType auxiliaryPictureType);
    static bool IsAuxiliaryPictureEncoded(AuxiliaryPictureType type);
    static bool IsMetadataTypeSupported(MetadataType metadataType);
    static const std::set<AuxiliaryPictureType> GetAllAuxiliaryPictureType();
    static size_t GetAstcBytesCount(const ImageInfo& imageInfo);
    static bool StrToUint32(const std::string& str, uint32_t& value);
    static bool IsInRange(uint32_t value, uint32_t minValue, uint32_t maxValue);
    static bool IsInRange(int32_t value, int32_t minValue, int32_t maxValue);
    static bool IsEven(int32_t value);
    static bool HasOverflowed(uint32_t num1, uint32_t num2);
    static int32_t GetAPIVersion();
    static std::string GetEncodedHeifFormat();
    static void UpdateSdrYuvStrides(const ImageInfo &imageInfo, YUVStrideInfo &dstStrides,
        void *context, AllocatorType dstType);
    static bool CanReusePixelMap(ImagePlugin::DecodeContext& context, int width,
        int height, const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool CanReusePixelMapHdr(ImagePlugin::DecodeContext& context, int width,
        int height, const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool CanReusePixelMapSdr(ImagePlugin::DecodeContext& context, int width,
        int height, const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool IsHdrPixelMapReuseSuccess(ImagePlugin::DecodeContext& context, int width,
        int height, const std::shared_ptr<PixelMap> &reusePixelmap);
    static void SetContextHdr(ImagePlugin::DecodeContext& context, uint32_t format);
    static void SetReuseContextBuffer(ImagePlugin::DecodeContext& context,
        AllocatorType type, uint8_t* ptr, uint64_t count, void* fd);
    static bool IsSdrPixelMapReuseSuccess(ImagePlugin::DecodeContext& context, int width,
        int height, const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool IsReuseYUV(ImagePlugin::DecodeContext& context, const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool IsReuseRGB(ImagePlugin::DecodeContext& context, const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool IsYUV(PixelFormat format);
    static bool IsRGBX(PixelFormat format);
    static bool PixelMapCreateCheckFormat(PixelFormat format);
    static bool CheckTlvSupportedFormat(PixelFormat format);
    static uint16_t GetReusePixelRefCount(const std::shared_ptr<PixelMap> &reusePixelmap);
    static bool CheckRowDataSizeIsVaild(int32_t &rowDataSize, ImageInfo &imgInfo);
    static bool CheckBufferSizeIsVaild(int32_t &bufferSize, uint64_t &expectedBufferSize,
        AllocatorType &allocatorType);
    static bool GetAlignedNumber(int32_t& number, int32_t align);

    template<typename T>
    static bool CheckMulOverflow(const T& num1, const T& num2)
    {
        if (num1 == 0 || num2 == 0) {
            return true;
        }
        T mulNum = num1 * num2;
        if ((mulNum / num1) != num2) {
            return true;
        }
        return false;
    }

    template<typename T>
    static bool CheckMulOverflow(const T& num1, const T& num2, const T& num3)
    {
        if (num1 == 0 || num2 == 0 || num3 == 0) {
            return true;
        }
        T mulNum1 = num1 * num2;
        if ((mulNum1 / num1) != num2) {
            return true;
        }
        T mulNum2 = mulNum1 * num3;
        if ((mulNum2 / num3) != mulNum1) {
            return true;
        }
        return false;
    }
    static uint16_t GetRGBA1010102ColorR(uint32_t color);
    static uint16_t GetRGBA1010102ColorG(uint32_t color);
    static uint16_t GetRGBA1010102ColorB(uint32_t color);
    static uint16_t GetRGBA1010102ColorA(uint32_t color);
private:
    static uint32_t RegisterPluginServer();
    static uint32_t SaveDataToFile(const std::string& fileName, const char* data, const size_t& totalSize);
    static std::string GetLocalTime();
    static std::string GetPixelMapName(PixelMap* pixelMap);
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_INNERKITSIMPL_UTILS_INCLUDE_IMAGE_UTILS_H
