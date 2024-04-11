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
#include "gif_encoder.h"
#include "image_log.h"
#include "image_trace.h"
#include "media_errors.h"
#include "securec.h"
#include <iostream>
#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "GifEncoder"

namespace OHOS {
namespace ImagePlugin {
using namespace MultimediaPlugin;
using namespace Media;

const int BITS_IN_BYTE = 8;
const int BITS_PER_PRIM_COLOR = 5;
const int RED_COORDINATE = 10;
const int GREEN_COORDINATE = 5;
const int BLUE_COORDINATE = 0;
const int R_IN_RGB = 0;
const int G_IN_RGB = 1;
const int B_IN_RGB = 2;
const int COLOR_OF_GIF = 256;
const int COLOR_MAP_SIZE = 256;
const int COLOR_ARRAY_SIZE = 32768;
const int EXTENSION_INTRODUCER = 0x21;
const int APPLICATION_EXTENSION_LABEL = 0xFF;
const int GRAPHIC_CONTROL_LABEL = 0xF9;
const int IMAGE_SEPARATOR = 0x2C;
const int LZ_BITS = 12;
const int CLEAR_CODE = 256;
const int LZ_MAX_CODE = 4095;
const int FLUSH_OUTPUT = 4096;
const int FIRST_CODE = 4097;
const int DEFAULT_DELAY_TIME = 100;
const int DEFAULT_DISPOSAL_TYPE = 1;
const int DISPOSAL_METHOD_SHIFT_BIT = 2;

const uint8_t GIF89_STAMP[] = {0x47, 0x49, 0x46, 0x38, 0x39, 0x61};
const uint8_t applicationIdentifier[] = {0x4E, 0x45, 0x54, 0x53, 0x43, 0x41, 0x50, 0x45};
const uint8_t applicationAuthenticationCode[] = {0x32, 0x2E, 0x30};

static int g_sortRGBAxis = 0;

#pragma pack(1)
typedef struct LogicalScreenDescriptor {
    uint16_t LogicalScreenWidth;
    uint16_t LogicalScreenHeight;
    uint8_t PackedFields;
    uint8_t BackgroundColorIndex;
    uint8_t PixelAspectRatio;
} LogicalScreenDescriptor;

typedef struct ApplicationExtension {
    uint8_t ExtensionIntroducer;
    uint8_t ExtensionLabel;
    uint8_t BlockSize;
    uint8_t ApplicationIdentifier[8];
    uint8_t ApplicationAuthenticationCode[3];
    uint8_t ApplicationDataSize;
    uint8_t ApplicationDataIndex;
    uint16_t LoopTime;
    uint8_t BlockTerminator;
} ApplicationExtension;

typedef struct GraphicControlExtension {
    uint8_t ExtensionIntroducer;
    uint8_t GraphicControlLabel;
    uint8_t BlockSize;
    uint8_t PackedFields;
    uint16_t DelayTime;
    uint8_t TransparentColorIndex;
    uint8_t BlockTerminator;
} GraphicControlExtension;

typedef struct ImageDescriptor {
    uint8_t ImageSeparator;
    uint16_t ImageLeftPosition;
    uint16_t ImageTopPosition;
    uint16_t ImageWidth;
    uint16_t ImageHeight;
    uint8_t PackedFields;
} ImageDescriptor;

typedef struct ColorInput {
    const uint8_t *redInput;
    const uint8_t *greenInput;
    const uint8_t *blueInput;
} ColorInput;
#pragma pack()

GifEncoder::GifEncoder()
{
    IMAGE_LOGD("create IN");

    IMAGE_LOGD("create OUT");
}

GifEncoder::~GifEncoder()
{
    IMAGE_LOGD("release IN");

    pixelMaps_.clear();

    IMAGE_LOGD("release OUT");
}

uint32_t GifEncoder::StartEncode(OutputDataStream &outputStream, PlEncodeOptions &option)
{
    IMAGE_LOGD("StartEncode IN, quality=%{public}u, numberHint=%{public}u",
        option.quality, option.numberHint);

    pixelMaps_.clear();
    outputStream_ = &outputStream;
    encodeOpts_ = option;

    IMAGE_LOGD("StartEncode OUT");
    return SUCCESS;
}

uint32_t GifEncoder::AddImage(Media::PixelMap &pixelMap)
{
    IMAGE_LOGD("AddImage IN");

    if (pixelMap.GetPixels() == nullptr) {
        IMAGE_LOGE("AddImage failed, invalid pixelMap.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    pixelMaps_.push_back(&pixelMap);
    IMAGE_LOGD("AddImage OUT");
    return SUCCESS;
}

uint32_t GifEncoder::FinalizeEncode()
{
    ImageTrace imageTrace("GifEncoder::FinalizeEncode");
    IMAGE_LOGD("FinalizeEncode IN");

    if (pixelMaps_.empty()) {
        IMAGE_LOGE("FinalizeEncode, no pixel map input.");
        return ERR_IMAGE_INVALID_PARAMETER;
    }

    uint32_t errorCode = ERROR;
    errorCode = DoEncode();
    if (errorCode != SUCCESS) {
        IMAGE_LOGE("FinalizeEncode, encode failed=%{public}u.", errorCode);
    }

    IMAGE_LOGD("FinalizeEncode OUT");
    return errorCode;
}

uint32_t GifEncoder::DoEncode()
{
    IMAGE_LOGD("DoEncode IN");

    WriteFileInfo();

    for (int index = 0; index < pixelMaps_.size(); index++) {
        InitDictionary();
        WriteFrameInfo(index);
        processFrame(index);
    }

    IMAGE_LOGD("DoEncode OUT");
    return SUCCESS;
}

uint32_t GifEncoder::WriteFileInfo()
{
    if (!Write(GIF89_STAMP, sizeof(GIF89_STAMP))) {
        IMAGE_LOGE("Write to buffer error.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    LogicalScreenDescriptor lsd;
    memset_s(&lsd, sizeof(LogicalScreenDescriptor), 0, sizeof(LogicalScreenDescriptor));
    for (auto pixelMap : pixelMaps_) {
        if (lsd.LogicalScreenWidth < static_cast<uint16_t>(pixelMap->GetWidth())) {
            lsd.LogicalScreenWidth = static_cast<uint16_t>(pixelMap->GetWidth());
        }
        if (lsd.LogicalScreenHeight < static_cast<uint16_t>(pixelMap->GetHeight())) {
            lsd.LogicalScreenHeight = static_cast<uint16_t>(pixelMap->GetHeight());
        }
    }
    if (!Write((const uint8_t*)&lsd, sizeof(LogicalScreenDescriptor))) {
        IMAGE_LOGE("Write to buffer error.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    ApplicationExtension ae;
    memset_s(&ae, sizeof(ApplicationExtension), 0, sizeof(ApplicationExtension));
    ae.ExtensionIntroducer = EXTENSION_INTRODUCER;
    ae.ExtensionLabel = APPLICATION_EXTENSION_LABEL;
    ae.BlockSize = 0x0B;
    memcpy_s(&ae.ApplicationIdentifier, sizeof(ae.ApplicationIdentifier),
             &applicationIdentifier, sizeof(ae.ApplicationIdentifier));
    memcpy_s(&ae.ApplicationAuthenticationCode, sizeof(ae.ApplicationIdentifier),
             &applicationAuthenticationCode, sizeof(ae.ApplicationAuthenticationCode));
    ae.ApplicationDataSize = 0x03;
    ae.ApplicationDataIndex = 0x01;
    ae.LoopTime = encodeOpts_.loop;
    ae.BlockTerminator = 0x00;
    if (!Write((const uint8_t*)&ae, sizeof(ApplicationExtension))) {
        IMAGE_LOGE("Write to buffer error.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    return SUCCESS;
}

uint32_t GifEncoder::WriteFrameInfo(int index)
{
    GraphicControlExtension gce;
    memset_s(&gce, sizeof(GraphicControlExtension), 0, sizeof(GraphicControlExtension));
    gce.ExtensionIntroducer = EXTENSION_INTRODUCER;
    gce.GraphicControlLabel = GRAPHIC_CONTROL_LABEL;
    gce.BlockSize = 0x04;
    gce.PackedFields = 0x00;
    gce.PackedFields |= (((index < encodeOpts_.disposalTypes.size() ?
        encodeOpts_.disposalTypes[index] : DEFAULT_DISPOSAL_TYPE) & 0x07) << DISPOSAL_METHOD_SHIFT_BIT);
    gce.DelayTime = index < encodeOpts_.delayTimes.size() ? encodeOpts_.delayTimes[index] : DEFAULT_DELAY_TIME;
    gce.TransparentColorIndex = 0x00;
    gce.BlockTerminator = 0x00;
    if (!Write((const uint8_t*)&gce, sizeof(GraphicControlExtension))) {
        IMAGE_LOGE("Write to buffer error.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    ImageDescriptor id;
    memset_s(&id, sizeof(ImageDescriptor), 0, sizeof(ImageDescriptor));
    id.ImageSeparator = IMAGE_SEPARATOR;
    id.ImageLeftPosition = 0x0000;
    id.ImageTopPosition = 0x0000;
    id.ImageWidth = static_cast<uint16_t>(pixelMaps_[index]->GetWidth());
    id.ImageHeight = static_cast<uint16_t>(pixelMaps_[index]->GetHeight());
    id.PackedFields = 0x87;
    if (!Write((const uint8_t*)&id, sizeof(ImageDescriptor))) {
        IMAGE_LOGE("Write to buffer error.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    return SUCCESS;
}

uint32_t GifEncoder::processFrame(int index)
{
    ColorType *colorMap = (ColorType *)malloc(sizeof(ColorType) * COLOR_MAP_SIZE);
    if (colorMap == NULL) {
        IMAGE_LOGE("Failed to allocate memory.");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    uint16_t width = static_cast<uint16_t>(pixelMaps_[index]->GetWidth());
    uint16_t height = static_cast<uint16_t>(pixelMaps_[index]->GetHeight());
    uint64_t frameSize = width * height;
    uint8_t *colorBuffer = (uint8_t *)malloc(frameSize);
    if (colorBuffer == NULL) {
        IMAGE_LOGE("Failed to allocate memory.");
        free(colorMap);
        return ERR_IMAGE_ENCODE_FAILED;
    }
    if (colorQuantize(index, width, height, colorBuffer, colorMap)) {
        IMAGE_LOGE("Failed to quantize color.");
        free(colorBuffer);
        free(colorMap);
        return ERR_IMAGE_ENCODE_FAILED;
    }
    for (int j = 0; j < COLOR_MAP_SIZE; j++) {
        Write(&(colorMap[j].red), 1);
        Write(&(colorMap[j].green), 1);
        Write(&(colorMap[j].blue), 1);
    }

    if (LZWEncodeFrame(colorBuffer, width, height)) {
        IMAGE_LOGE("Failed to encode frame.");
        free(colorBuffer);
        free(colorMap);
        return ERR_IMAGE_ENCODE_FAILED;
    }

    free(colorBuffer);
    free(colorMap);

    return SUCCESS;
}

uint32_t GifEncoder::colorQuantize(int index, uint16_t width, uint16_t height,
                                   uint8_t *outputBuffer, ColorType *outputColorMap)
{
    uint8_t *redBuffer = NULL;
    uint8_t *greenBuffer = NULL;
    uint8_t *blueBuffer = NULL;
    uint64_t frameSize = width * height;
    if ((redBuffer = (uint8_t *)malloc(frameSize)) == NULL ||
        (greenBuffer = (uint8_t *)malloc(frameSize)) == NULL ||
        (blueBuffer = (uint8_t *)malloc(frameSize)) == NULL) {
        IMAGE_LOGE("Failed to allocate memory.");
        return ERR_IMAGE_ENCODE_FAILED;
    }

    if (separateRGB(index, width, height, redBuffer, greenBuffer, blueBuffer)) {
        IMAGE_LOGE("Failed to separate RGB, aborted.");
        free(redBuffer);
        free(greenBuffer);
        free(blueBuffer);
        return ERR_IMAGE_ENCODE_FAILED;
    }

    if (doColorQuantize(width, height, redBuffer, greenBuffer, blueBuffer, outputBuffer, outputColorMap)) {
        IMAGE_LOGE("Failed to quantize buffer, aborted.");
        free(redBuffer);
        free(greenBuffer);
        free(blueBuffer);
        return ERR_IMAGE_ENCODE_FAILED;
    }

    free(redBuffer);
    free(greenBuffer);
    free(blueBuffer);

    return SUCCESS;
}

uint32_t GifEncoder::separateRGB(int index, uint16_t width, uint16_t height,
                                 uint8_t *redBuffer, uint8_t *greenBuffer, uint8_t *blueBuffer)
{
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            uint32_t pixelColor;
            if (!pixelMaps_[index]->GetARGB32Color(x, y, pixelColor)) {
                IMAGE_LOGE("Failed to get rgb value.");
                return ERR_IMAGE_ENCODE_FAILED;
            }
            redBuffer[y * width + x] = pixelMaps_[index]->GetARGB32ColorR(pixelColor);
            greenBuffer[y * width + x] = pixelMaps_[index]->GetARGB32ColorG(pixelColor);
            blueBuffer[y * width + x] = pixelMaps_[index]->GetARGB32ColorB(pixelColor);
        }
    }

    return SUCCESS;
}

void InitColorCube(ColorCoordinate *colorCoordinate, uint16_t width, uint16_t height,
                   ColorInput *colorInput)
{
    for (int i = 0; i < COLOR_ARRAY_SIZE; i++) {
        colorCoordinate[i].rgb[R_IN_RGB] = (i >> RED_COORDINATE) & 0x1F;
        colorCoordinate[i].rgb[G_IN_RGB] = (i >> GREEN_COORDINATE) & 0x1F;
        colorCoordinate[i].rgb[B_IN_RGB] = (i >> BLUE_COORDINATE) & 0x1F;
        colorCoordinate[i].pixelNum = 0;
    }

    for (int i = 0; i < (int)(width * height); i++) {
        uint16_t index = ((colorInput->redInput[i] >> (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) << RED_COORDINATE) +
                 ((colorInput->greenInput[i] >> (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) << GREEN_COORDINATE) +
                 ((colorInput->blueInput[i] >> (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) << BLUE_COORDINATE);
        colorCoordinate[index].pixelNum++;
    }
}

void InitColorSubdivMap(ColorSubdivMap* colorSubdivMap, uint16_t width, uint16_t height)
{
    for (int i = 0; i < COLOR_OF_GIF; i++) {
        for (int j = 0; j < NUM_OF_RGB; j++) {
            colorSubdivMap[i].rgbMin[j] = 0;
            colorSubdivMap[i].rgbWidth[j] = 0xFF;
        }
        colorSubdivMap[i].coordinate = NULL;
        colorSubdivMap[i].pixelNum = 0;
        colorSubdivMap[i].colorNum = 0;
    }
    colorSubdivMap[0].pixelNum = ((long)width) * height;
}

void InitForQuantize(ColorCoordinate *colorCoordinate, ColorSubdivMap* colorSubdivMap)
{
    ColorCoordinate* coordinate;
    for (int i = 0; i < COLOR_ARRAY_SIZE; i++) {
        if (colorCoordinate[i].pixelNum > 0) {
            if (colorSubdivMap[0].colorNum == 0) {
                coordinate = &colorCoordinate[i];
                colorSubdivMap[0].coordinate = &colorCoordinate[i];
                colorSubdivMap[0].colorNum++;
            } else {
                coordinate->next = &colorCoordinate[i];
                coordinate = &colorCoordinate[i];
                colorSubdivMap[0].colorNum++;
            }
        }
    }
    coordinate->next = NULL;
}

uint32_t GifEncoder::doColorQuantize(uint16_t width, uint16_t height,
                                     const uint8_t *redInput, const uint8_t *greenInput, const uint8_t *blueInput,
                                     uint8_t *outputBuffer, ColorType *outputColorMap)
{
    uint32_t colorSubdivMapSize = 1;
    ColorSubdivMap colorSubdivMap[COLOR_OF_GIF];

    ColorCoordinate *colorCoordinate = (ColorCoordinate *)malloc(sizeof(ColorCoordinate) * COLOR_ARRAY_SIZE);
    if (colorCoordinate == NULL) {
        return ERR_IMAGE_ENCODE_FAILED;
    }

    ColorInput colorInput;
    colorInput.redInput = redInput;
    colorInput.greenInput = greenInput;
    colorInput.blueInput = blueInput;
    InitColorCube(colorCoordinate, width, height, &colorInput);
    InitColorSubdivMap(colorSubdivMap, width, height);
    InitForQuantize(colorCoordinate, colorSubdivMap);

    if (BuildColorSubdivMap(colorSubdivMap, &colorSubdivMapSize)) {
        free(colorCoordinate);
        return ERR_IMAGE_ENCODE_FAILED;
    }
    if (colorSubdivMapSize < COLOR_MAP_SIZE) {
        memset_s(outputColorMap, sizeof(ColorType) * COLOR_MAP_SIZE, 0, sizeof(ColorType) * COLOR_MAP_SIZE);
    }

    for (int i = 0; i < colorSubdivMapSize; i++) {
        if (colorSubdivMap[i].colorNum > 0) {
            ColorCoordinate *coordinate = colorSubdivMap[i].coordinate;
            long red = 0;
            long green = 0;
            long blue = 0;
            while (coordinate) {
                red += coordinate->rgb[R_IN_RGB];
                green += coordinate->rgb[G_IN_RGB];
                blue += coordinate->rgb[B_IN_RGB];
                coordinate->newColorIndex = i;
                coordinate = coordinate->next;
            }
            outputColorMap[i].red = (red << (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) / colorSubdivMap[i].colorNum;
            outputColorMap[i].green = (green << (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) / colorSubdivMap[i].colorNum;
            outputColorMap[i].blue = (blue << (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) / colorSubdivMap[i].colorNum;
        }
    }
    for (int i = 0; i < ((long)width) * height; i++) {
        uint32_t index = ((redInput[i] >> (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) << RED_COORDINATE) +
            ((greenInput[i] >> (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) << GREEN_COORDINATE) +
            ((blueInput[i] >> (BITS_IN_BYTE - BITS_PER_PRIM_COLOR)) << BLUE_COORDINATE);
        outputBuffer[i] = colorCoordinate[index].newColorIndex;
    }

    free(colorCoordinate);

    return SUCCESS;
}

int32_t SortCmpRtn(const void *Entry1, const void *Entry2)
{
    ColorCoordinate *entry1 = (*((ColorCoordinate **)Entry1));
    ColorCoordinate *entry2 = (*((ColorCoordinate **)Entry2));

    int32_t hash1 = entry1->rgb[(g_sortRGBAxis + R_IN_RGB)] * COLOR_OF_GIF * COLOR_OF_GIF +
                entry1->rgb[(g_sortRGBAxis + G_IN_RGB) % NUM_OF_RGB] * COLOR_OF_GIF +
                entry1->rgb[(g_sortRGBAxis + B_IN_RGB) % NUM_OF_RGB];
    int32_t hash2 = entry2->rgb[(g_sortRGBAxis + R_IN_RGB)] * COLOR_OF_GIF * COLOR_OF_GIF +
                entry2->rgb[(g_sortRGBAxis + G_IN_RGB) % NUM_OF_RGB] * COLOR_OF_GIF +
                entry2->rgb[(g_sortRGBAxis + B_IN_RGB) % NUM_OF_RGB];

    return (hash1 - hash2);
}


uint32_t PrepareSort(ColorSubdivMap *colorSubdivMap, uint32_t colorSubdivMapSize)
{
    int maxSize = -1;
    int index = -1;
    for (int i = 0; i < colorSubdivMapSize; i++) {
        for (int j = 0; j < NUM_OF_RGB; j++) {
            if (((int)colorSubdivMap[i].rgbWidth[j] > maxSize) && (colorSubdivMap[i].colorNum > 1)) {
                maxSize = colorSubdivMap[i].rgbWidth[j];
                index = i;
                g_sortRGBAxis = j;
            }
        }
    }
    return index;
}

void doSort(ColorCoordinate **sortArray, ColorSubdivMap *colorSubdivMap, uint32_t index)
{
    int i;
    ColorCoordinate *colorCoordinate = nullptr;
    for (i = 0, colorCoordinate = colorSubdivMap[index].coordinate;
         i < colorSubdivMap[index].colorNum && colorCoordinate != NULL;
         i++, colorCoordinate = colorCoordinate->next) {
        sortArray[i] = colorCoordinate;
    }
    qsort(sortArray, colorSubdivMap[index].colorNum, sizeof(ColorCoordinate *), SortCmpRtn);
}

void SubdivColorByPartition(ColorCoordinate *colorCoordinate, ColorSubdivMap *colorSubdivMap,
    uint32_t colorSubdivMapSize, int index)
{
    long sum = (colorSubdivMap[index].pixelNum >> 1) - colorCoordinate->pixelNum;
    uint32_t colorNum = 1;
    long pixelNum = colorCoordinate->pixelNum;
    while (colorCoordinate->next != NULL &&
        (sum -= colorCoordinate->next->pixelNum) >= 0 &&
           colorCoordinate->next->next != NULL) {
        colorCoordinate = colorCoordinate->next;
        colorNum++;
        pixelNum += colorCoordinate->pixelNum;
    }
    uint32_t MaxColor = colorCoordinate->rgb[g_sortRGBAxis] << (BITS_IN_BYTE - BITS_PER_PRIM_COLOR);
    uint32_t MinColor = colorCoordinate->next->rgb[g_sortRGBAxis] << (BITS_IN_BYTE - BITS_PER_PRIM_COLOR);
    colorSubdivMap[colorSubdivMapSize].coordinate = colorCoordinate->next;
    colorCoordinate->next = NULL;
    colorSubdivMap[colorSubdivMapSize].pixelNum = colorSubdivMap[index].pixelNum - pixelNum;
    colorSubdivMap[index].pixelNum = pixelNum;
    colorSubdivMap[colorSubdivMapSize].colorNum = colorSubdivMap[index].colorNum - colorNum;
    colorSubdivMap[index].colorNum = colorNum;
    for (int i = 0; i < NUM_OF_RGB; i++) {
        colorSubdivMap[colorSubdivMapSize].rgbMin[i] = colorSubdivMap[index].rgbMin[i];
        colorSubdivMap[colorSubdivMapSize].rgbWidth[i] = colorSubdivMap[index].rgbWidth[i];
    }
    colorSubdivMap[colorSubdivMapSize].rgbWidth[g_sortRGBAxis] =
        colorSubdivMap[colorSubdivMapSize].rgbMin[g_sortRGBAxis] +
        colorSubdivMap[colorSubdivMapSize].rgbWidth[g_sortRGBAxis] - MinColor;
    colorSubdivMap[colorSubdivMapSize].rgbMin[g_sortRGBAxis] = MinColor;
    colorSubdivMap[index].rgbWidth[g_sortRGBAxis] = MaxColor - colorSubdivMap[index].rgbMin[g_sortRGBAxis];
}

uint32_t GifEncoder::BuildColorSubdivMap(ColorSubdivMap *colorSubdivMap, uint32_t *colorSubdivMapSize)
{
    int index = 0;
    ColorCoordinate **sortArray;

    while (*colorSubdivMapSize < COLOR_MAP_SIZE) {
        index = PrepareSort(colorSubdivMap, *colorSubdivMapSize);
        if (index < 0) {
            return SUCCESS;
        }
        sortArray = (ColorCoordinate **)malloc(sizeof(ColorCoordinate *) * colorSubdivMap[index].colorNum);
        if (sortArray == NULL) {
            return ERR_IMAGE_ENCODE_FAILED;
        }
        doSort(sortArray, colorSubdivMap, index);

        for (int i = 0; i < colorSubdivMap[index].colorNum - 1; i++) {
            sortArray[i]->next = sortArray[i + 1];
        }
        sortArray[colorSubdivMap[index].colorNum - 1]->next = NULL;
        colorSubdivMap[index].coordinate = sortArray[0];
        ColorCoordinate *colorCoordinate = sortArray[0];
        free(sortArray);
        SubdivColorByPartition(colorCoordinate, colorSubdivMap, *colorSubdivMapSize, index);
        (*colorSubdivMapSize)++;
    }

    return SUCCESS;
}

void GifEncoder::InitDictionary()
{
    lastCode_ = FIRST_CODE;
    clearCode_ = CLEAR_CODE;
    eofCode_ = clearCode_ + 1;
    runningCode_ = eofCode_ + 1;
    runningBits_ = BITS_IN_BYTE + 1;
    maxCode_ = 1 << runningBits_;
    crntShiftState_ = 0;
    crntShiftDWord_ = 0;
    memset_s(dictionary_, sizeof(uint32_t) * DICTIONARY_SIZE, 0xFF, sizeof(uint32_t) * DICTIONARY_SIZE);
}

int GifEncoder::IsInDictionary(uint32_t Key)
{
    int key = ((Key >> LZ_BITS) ^ Key) & 0x1FFF;
    uint32_t DKey;
    while ((DKey = (dictionary_[key] >> LZ_BITS)) != 0xFFFFFL) {
        if (Key == DKey) {
            return (dictionary_[key] & 0x0FFF);
        }
        key = (key + 1) & 0x1FFF;
    }
    return -1;
}
 
void GifEncoder::AddToDictionary(uint32_t Key, int Code)
{
    int key = ((Key >> LZ_BITS) ^ Key) & 0x1FFF;
    while ((dictionary_[key] >> LZ_BITS) != 0xFFFFFL) {
        key = (key + 1) & 0x1FFF;
    }
    dictionary_[key] = (Key << LZ_BITS) | (Code & 0x0FFF);
}

uint32_t GifEncoder::LZWEncodeFrame(uint8_t *outputBuffer, uint16_t width, uint16_t height)
{
    uint8_t *pTmp = outputBuffer;
    uint8_t bitsPerPixel = BITS_IN_BYTE;
    Write((const uint8_t*)&bitsPerPixel, 1);
    LZWWriteOut(clearCode_);
    for (int j = 0; j < height; j++) {
        if (LZWEncode(pTmp, width)) {
            IMAGE_LOGE("Failed to encode, aborted.");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        pTmp += width;
    }
    if (LZWWriteOut(lastCode_)) {
        IMAGE_LOGE("Failed to write lastCode, aborted.");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    if (LZWWriteOut(eofCode_)) {
        IMAGE_LOGE("Failed to write EOFCode, aborted.");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    if (LZWWriteOut(FLUSH_OUTPUT)) {
        IMAGE_LOGE("Failed to write flushCode, aborted.");
        return ERR_IMAGE_ENCODE_FAILED;
    }
    return SUCCESS;
}

uint32_t GifEncoder::LZWEncode(uint8_t *buffer, int length)
{
    int i = 0;
    int curChar;
    if (lastCode_ == FIRST_CODE) {
        curChar = buffer[i++];
    } else {
        curChar = lastCode_;
    }
    while (i < length) {
        uint8_t Pixel = buffer[i++];
        int newChar;
        uint32_t newKey = (((uint32_t)curChar) << BITS_IN_BYTE) + Pixel;
        if ((newChar = IsInDictionary(newKey)) >= 0) {
            curChar = newChar;
            continue;
        }
        if (LZWWriteOut(curChar)) {
            IMAGE_LOGE("Failed to write.");
            return ERR_IMAGE_ENCODE_FAILED;
        }
        curChar = Pixel;
        if (runningCode_ >= LZ_MAX_CODE) {
            if (LZWWriteOut(clearCode_)) {
                IMAGE_LOGE("Failed to write.");
                return ERR_IMAGE_ENCODE_FAILED;
            }
            runningCode_ = eofCode_ + 1;
            runningBits_ = BITS_IN_BYTE + 1;
            maxCode_ = 1 << runningBits_;
            memset_s(dictionary_, sizeof(uint32_t) * DICTIONARY_SIZE, 0xFF, sizeof(uint32_t) * DICTIONARY_SIZE);
        } else {
            AddToDictionary(newKey, runningCode_++);
        }
    }
    lastCode_ = curChar;
    return SUCCESS;
}

uint32_t GifEncoder::LZWWriteOut(int Code)
{
    uint32_t ret = SUCCESS;
    if (Code == FLUSH_OUTPUT) {
        while (crntShiftState_ > 0) {
            if (LZWBufferOutput(crntShiftDWord_ & 0xFF)) {
                ret = ERROR;
            }
            crntShiftDWord_ >>= BITS_IN_BYTE;
            crntShiftState_ -= BITS_IN_BYTE;
        }
        crntShiftState_ = 0;
        if (LZWBufferOutput(FLUSH_OUTPUT)) {
            ret = ERROR;
        }
    } else {
        crntShiftDWord_ |= ((long)Code) << crntShiftState_;
        crntShiftState_ += runningBits_;
        while (crntShiftState_ >= BITS_IN_BYTE) {
            if (LZWBufferOutput(crntShiftDWord_ & 0xFF)) {
                ret = ERROR;
            }
            crntShiftDWord_ >>= BITS_IN_BYTE;
            crntShiftState_ -= BITS_IN_BYTE;
        }
    }
    if (runningCode_ >= maxCode_ && Code <= LZ_MAX_CODE) {
        maxCode_ = 1 << ++runningBits_;
    }
    return ret;
}

uint32_t GifEncoder::LZWBufferOutput(int character)
{
    if (character == FLUSH_OUTPUT) {
        if (outputLZWBuffer_[0] != 0 && !Write(outputLZWBuffer_, outputLZWBuffer_[0] + 1)) {
            return ERR_IMAGE_ENCODE_FAILED;
        }
        outputLZWBuffer_[0] = 0;
        if (!Write(outputLZWBuffer_, 1)) {
            return ERR_IMAGE_ENCODE_FAILED;
        }
    } else {
        if (outputLZWBuffer_[0] == 0xFF) {
            if (!Write(outputLZWBuffer_, outputLZWBuffer_[0] + 1)) {
                return ERR_IMAGE_ENCODE_FAILED;
            }
            outputLZWBuffer_[0] = 0;
        }
        outputLZWBuffer_[++outputLZWBuffer_[0]] = character;
    }
    return SUCCESS;
}

bool GifEncoder::Write(const uint8_t* data, size_t data_size)
{
    return outputStream_->Write(data, data_size);
}

} // namespace ImagePlugin
} // namespace OHOS