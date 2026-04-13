/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include "common_fuzztest_function.h"
#include "image_log.h"
#include "image_xmp_metadata_fuzz.h"
#include "media_errors.h"
#include "xmp_metadata.h"

namespace OHOS {
namespace Media {
namespace {
static constexpr size_t MAX_RANDOM_URI_LENGTH = 100;
static constexpr size_t MAX_RANDOM_PREFIX_LENGTH = 20;
static constexpr size_t SHORT_URI_LENGTH = 50;
static constexpr size_t MAX_ROOT_PATH_LENGTH = 10;

enum class PathChoice : uint8_t {
    VALID = 0,
    INVALID = 1,
    RANDOM = 2,
};

static constexpr uint8_t PATH_CHOICE_COUNT = 3;

static constexpr int32_t TAG_TYPE_MIN = 0;
static constexpr int32_t TAG_TYPE_MAX = 6;

enum class MetadataAction : uint8_t {
    REGISTER_NAMESPACE_PREFIX = 0,
    SET_VALUE = 1,
    GET_TAG = 2,
    REMOVE_TAG = 3,
    ENUMERATE_TAGS = 4,
    SET_BLOB = 5,
    GET_BLOB = 6,
};

static constexpr uint8_t METADATA_ACTION_COUNT = 7;

const std::vector<std::string> VALID_XMP_PATHS = {
    "xmp:CreatorTool",
    "xmp:CreateDate",
    "xmp:ModifyDate",
    "dc:title",
    "dc:creator",
    "dc:description",
    "dc:subject",
    "exif:ExposureTime",
    "exif:FNumber",
    "exif:ISOSpeedRatings",
    "exif:FocalLength",
    "tiff:ImageWidth",
    "tiff:ImageHeight",
    "tiff:Orientation",

    "dc:title[?xml:lang=\"zh-CN\"]",
    "dc:subject[dc:source=\"network\"]",

    "dc:subject[1]",
    "xmp:Keywords[3]",
    "dc:creator[5]",

    "exif:Flash/exif:Fired",
    "exif:GPS/exif:Latitude",
    "dc:first[1]/dc:second[1]/dc:third[1]",

    "dc:title[1]/?book:lastUpdated",
};

const std::vector<std::string> INVALID_XMP_PATHS = {
    "",
    "invalid_path",
    ":",
    "dc:",
    ":title",
    "a:b:c",
    "test[unclosed",
    "test]/closed",
    "/a/b/c",
    "a/b/c",
    "very/long/path/with/many/levels/of/nesting",

    "dc:title[@xml:lang=\"en-US\"]",
    "dc:title[1]/@xml:lang",
};

const std::vector<std::pair<std::string, std::string>> KNOWN_XMP_NAMESPACES = {
    {"http://purl.org/dc/elements/1.1/", "dc"},
    {"http://ns.adobe.com/xap/1.0/", "xmp"},
    {"http://ns.adobe.com/exif/1.0/", "exif"},
    {"http://ns.adobe.com/tiff/1.0/", "tiff"},
    {"http://ns.adobe.com/photoshop/1.0/", "photoshop"},
    {"http://ns.adobe.com/xap/1.0/rights/", "xmpRights"},
    {"http://creativecommons.org/ns#", "cc"},
};
}

FuzzedDataProvider* FDP;

static std::string PickPath(const std::vector<std::string> &pool)
{
    if (FDP == nullptr || pool.empty()) {
        return "";
    }
    size_t idx = FDP->ConsumeIntegralInRange<size_t>(0, pool.size() - 1);
    return pool[idx];
}

static std::string BuildPathForFuzz()
{
    if (FDP == nullptr) {
        return "";
    }
    uint8_t choiceRaw = FDP->ConsumeIntegral<uint8_t>() % PATH_CHOICE_COUNT;
    PathChoice choice = static_cast<PathChoice>(choiceRaw);
    if (choice == PathChoice::VALID) {
        return PickPath(VALID_XMP_PATHS);
    }
    if (choice == PathChoice::INVALID) {
        return PickPath(INVALID_XMP_PATHS);
    }
    return FDP->ConsumeRandomLengthString(SHORT_URI_LENGTH);
}

static XMPTagType BuildTagTypeForFuzz()
{
    if (FDP == nullptr) {
        return XMPTagType::STRING;
    }
    return static_cast<XMPTagType>(FDP->ConsumeIntegralInRange<int32_t>(TAG_TYPE_MIN, TAG_TYPE_MAX));
}

static std::string BuildValueForTagType(XMPTagType tagType)
{
    if (tagType == XMPTagType::UNORDERED_ARRAY ||
        tagType == XMPTagType::ORDERED_ARRAY ||
        tagType == XMPTagType::ALTERNATE_ARRAY ||
        tagType == XMPTagType::ALTERNATE_TEXT ||
        tagType == XMPTagType::STRUCTURE) {
        return "";
    }
    if (FDP == nullptr) {
        return "";
    }
    return FDP->ConsumeRandomLengthString(MAX_RANDOM_URI_LENGTH);
}

void ImageXMPMetadataRegisterNamespacePrefixFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }

    std::shared_ptr<XMPMetadata> metadata = std::make_shared<XMPMetadata>();
    std::string uri;
    std::string prefix;
    if (FDP->ConsumeProbability<float>() < 0.3f) {
        if (!KNOWN_XMP_NAMESPACES.empty()) {
            size_t idx = FDP->ConsumeIntegralInRange<size_t>(0, KNOWN_XMP_NAMESPACES.size() - 1);
            uri = KNOWN_XMP_NAMESPACES[idx].first;
            prefix = KNOWN_XMP_NAMESPACES[idx].second;
        } else {
            uri = FDP->ConsumeRandomLengthString(SHORT_URI_LENGTH);
            prefix = FDP->ConsumeRandomLengthString(SHORT_URI_LENGTH);
        }
    } else {
        uri = FDP->ConsumeRandomLengthString(MAX_RANDOM_URI_LENGTH);
        prefix = FDP->ConsumeRandomLengthString(MAX_RANDOM_PREFIX_LENGTH);
    }
    if (FDP->ConsumeProbability<float>() < 0.1f) {
        if (FDP->ConsumeBool()) uri = "";
        else prefix = "";
    }

    std::string errMsg;
    uint32_t regResult = metadata->RegisterNamespacePrefix(uri, prefix, errMsg);
    IMAGE_LOGI("[FUZZ] %{public}s: uri=[%{public}.64s] prefix=[%{public}.64s] ret=%{public}u",
        __func__, uri.c_str(), prefix.c_str(), regResult);
    if (FDP->ConsumeBool()) {
        std::string conflictErrMsg;
        if (FDP->ConsumeBool()) {
            (void)metadata->RegisterNamespacePrefix(uri, prefix, conflictErrMsg);
        } else {
            std::string conflictPrefix = prefix + "_conflict";
            (void)metadata->RegisterNamespacePrefix(uri, conflictPrefix, conflictErrMsg);
        }
    }
}

void XMPMetadataSetValueFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    auto metadata = std::make_shared<XMPMetadata>();
    std::string path = BuildPathForFuzz();
    XMPTagType tagType = BuildTagTypeForFuzz();
    std::string value = BuildValueForTagType(tagType);

    uint32_t setResult = metadata->SetValue(path, tagType, value);
    IMAGE_LOGI("[FUZZ] %{public}s: path=[%{public}.64s] type=%{public}d value=[%{public}.64s] ret=%{public}u",
        __func__, path.c_str(), static_cast<int>(tagType), value.c_str(), setResult);
}

void ImageXMPMetadataGetTagFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    
    auto metadata = std::make_shared<XMPMetadata>();
    XMPTag outputTag;
    std::string path = BuildPathForFuzz();
    uint32_t getResult = metadata->GetTag(path, outputTag);
    IMAGE_LOGI("[FUZZ] %{public}s: path=[%{public}.64s] ret=%{public}u", __func__, path.c_str(), getResult);
    if (FDP->ConsumeBool()) {
        XMPTagType tagType = BuildTagTypeForFuzz();
        std::string value = BuildValueForTagType(tagType);
        (void)metadata->SetValue(path, tagType, value);
        (void)metadata->GetTag(path, outputTag);
    }
}

void ImageXMPMetadataRemoveTagFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }

    auto metadata = std::make_shared<XMPMetadata>();
    std::string path = BuildPathForFuzz();
    uint32_t rmResult = metadata->RemoveTag(path);
    IMAGE_LOGI("[FUZZ] %{public}s: path=[%{public}.64s] ret=%{public}u", __func__, path.c_str(), rmResult);
    if (FDP->ConsumeBool()) {
        std::string value = FDP->ConsumeRandomLengthString(MAX_RANDOM_URI_LENGTH);
        uint32_t setResult = metadata->SetValue(path, XMPTagType::STRING, value);
        if (setResult == SUCCESS) {
            (void)metadata->RemoveTag(path);
            if (FDP->ConsumeBool()) {
                XMPTag checkTag;
                (void)metadata->GetTag(path, checkTag);
            }
        }
    }
}

void ImageXMPMetadataEnumerateTagsFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    
    auto metadata = std::make_shared<XMPMetadata>();
    if (FDP->ConsumeBool()) {
        (void)metadata->SetValue(PickPath(VALID_XMP_PATHS), XMPTagType::STRING,
            FDP->ConsumeRandomLengthString(MAX_ROOT_PATH_LENGTH));
        (void)metadata->SetValue(PickPath(VALID_XMP_PATHS), XMPTagType::STRING,
            FDP->ConsumeRandomLengthString(MAX_ROOT_PATH_LENGTH));
    }

    bool stopEarly = FDP->ConsumeBool();
    auto callback = [stopEarly](const std::string&, const XMPTag&) {
        return !stopEarly;
    };
    
    std::string rootPath;
    uint8_t choice = FDP->ConsumeIntegral<uint8_t>() % 3;
    if (choice == 0) {
        rootPath = "";
    } else if (choice == 1) {
        rootPath = "xmp:";
    } else {
        rootPath = FDP->ConsumeRandomLengthString(MAX_ROOT_PATH_LENGTH);
    }
    XMPEnumerateOptions options = {FDP->ConsumeBool(), FDP->ConsumeBool()};
    uint32_t enumResult = metadata->EnumerateTags(callback, rootPath, options);
    IMAGE_LOGI("[FUZZ] %{public}s: rootPath=[%{public}.64s] ret=%{public}u", __func__, rootPath.c_str(), enumResult);
}

void ImageXMPMetadataGetBlobFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    
    auto metadata = std::make_shared<XMPMetadata>();
    
    if (FDP->ConsumeBool()) {
        (void)metadata->SetValue(PickPath(VALID_XMP_PATHS), XMPTagType::STRING, "value");
    }
    
    std::string buffer;
    uint32_t blobResult = metadata->GetBlob(buffer);
    IMAGE_LOGI("[FUZZ] %{public}s: ret=%{public}u", __func__, blobResult);
}

void ImageXMPMetadataSetBlobFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::shared_ptr<XMPMetadata> metadata = std::make_shared<XMPMetadata>();

    size_t dataSize = FDP->ConsumeIntegralInRange<size_t>(0, 4096);
    std::vector<uint8_t> randomData = FDP->ConsumeBytes<uint8_t>(dataSize);

    uint32_t result = metadata->SetBlob(randomData.data(), randomData.size());
    IMAGE_LOGI("[FUZZ] %{public}s: dataSize=%{public}zu ret=%{public}u", __func__, dataSize, result);

    if (FDP->ConsumeBool()) {
        metadata->SetBlob(nullptr, MAX_RANDOM_URI_LENGTH);
    }

    if (FDP->ConsumeBool()) {
        uint8_t dummy = 0;
        metadata->SetBlob(&dummy, 0);
    }

    if (result == SUCCESS && FDP->ConsumeBool()) {
        size_t newSize = FDP->ConsumeIntegralInRange<size_t>(1, 1000);
        auto newData = FDP->ConsumeBytes<uint8_t>(newSize);
        metadata->SetBlob(newData.data(), newData.size());
    }
    
    if (result == SUCCESS) {
        XMPTag tag;
        for (const auto &path : VALID_XMP_PATHS) {
            if (FDP->ConsumeBool()) {
                continue;
            }
            metadata->GetTag(path, tag);
        }
    }
}
} // namespace Media
} // namespace OHOS

 /* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < COMMON_OPT_SIZE) {
        return 0;
    }
    FuzzedDataProvider opt_fdp(data + size - COMMON_OPT_SIZE, COMMON_OPT_SIZE);
    uint8_t actionRaw = opt_fdp.ConsumeIntegral<uint8_t>() % OHOS::Media::METADATA_ACTION_COUNT;
    OHOS::Media::MetadataAction action = static_cast<OHOS::Media::MetadataAction>(actionRaw);
    size_t testDataSize = size - COMMON_OPT_SIZE;
    const uint8_t* testData = data;
    FuzzedDataProvider test_fdp(testData, testDataSize);
    OHOS::Media::FDP = &test_fdp;
    IMAGE_LOGI("[FUZZ] %{public}s: action=%{public}u size=%{public}zu", __func__, actionRaw, size);

    switch (action) {
        case OHOS::Media::MetadataAction::REGISTER_NAMESPACE_PREFIX:
            OHOS::Media::ImageXMPMetadataRegisterNamespacePrefixFuzzTest();
            break;
        case OHOS::Media::MetadataAction::SET_VALUE:
            OHOS::Media::XMPMetadataSetValueFuzzTest();
            break;
        case OHOS::Media::MetadataAction::GET_TAG:
            OHOS::Media::ImageXMPMetadataGetTagFuzzTest();
            break;
        case OHOS::Media::MetadataAction::REMOVE_TAG:
            OHOS::Media::ImageXMPMetadataRemoveTagFuzzTest();
            break;
        case OHOS::Media::MetadataAction::ENUMERATE_TAGS:
            OHOS::Media::ImageXMPMetadataEnumerateTagsFuzzTest();
            break;
        case OHOS::Media::MetadataAction::SET_BLOB:
            OHOS::Media::ImageXMPMetadataSetBlobFuzzTest();
            break;
        case OHOS::Media::MetadataAction::GET_BLOB:
            OHOS::Media::ImageXMPMetadataGetBlobFuzzTest();
            break;
        default:
            break;
    }
    
    return 0;
}