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
#include <string>
#include <vector>
#include <cstdint>
#include <string_view>

#include "common_fuzztest_function.h"
#include "image_log.h"
#include "image_xmp_helper_fuzz.h"
#include "xmp_helper.h"

namespace OHOS {
namespace Media {
namespace {
static constexpr size_t MAX_INITIAL_INPUT_LENGTH = 1024;
static constexpr size_t MIN_BYTES_FOR_PATH_MUTATION = 2;
static constexpr size_t MIN_BYTES_FOR_TYPE_GENERATION = 5;
static constexpr size_t MIN_BYTES_FOR_LONG_STRING = 100;
static constexpr size_t SHORT_STRING_MAX_LEN = 10;
static constexpr size_t PATH_COMPONENT_LEN = 8;
static constexpr size_t MEDIUM_STRING_LEN = 6;
static constexpr size_t LONG_STRING_MIN_LEN = 100;
static constexpr size_t LONG_STRING_MAX_LEN = 2048;
static constexpr char RANDOM_CHAR_SET[] = "abc123[]/?@:_-.\n\t";
static constexpr size_t RANDOM_CHAR_SET_MAX_INDEX = sizeof(RANDOM_CHAR_SET) - 2;
static constexpr uint8_t GENERATION_TYPE_COUNT = 4;
static constexpr size_t MAX_DELIMITER_LENGTH = 64;
static constexpr size_t MAX_PROPERTY_PART_LENGTH = 15;
static constexpr size_t REMAIN_BYTES = 30;

enum class FuzzAction : uint8_t {
    SPLIT_ONCE = 0,
    TRIM = 1,
    EXTRACT_PROPERTY = 2,
    EXTRACT_SPLIT_PROPERTY = 3,
    GET_PARENT_PROPERTY = 4,
    NORMALIZE_NAMESPACE_PREFIX = 5,
};

enum class TypedPathKind : uint8_t {
    PREFIX_NAME = 0,
    ARRAY_ITEM = 1,
    STRUCT_FIELD = 2,
    QUALIFIER = 3,
};

static constexpr uint8_t FUZZ_ACTION_COUNT = 6;

const std::vector<std::string> TEST_PATHS = {
    "dc:title",
    "dc:title[@xml:lang=\"en-US\"]",
    "xmp:CreatorTool",
    "exif:Flash/exif:Fired",
    "dc:subject[2]",
    "dc:title[1]/?book:lastUpdated",
    "",
    "   ",
    ":",
    "dc:",
    ":title",
    "no_colon",
    "a:b:c",
};

const std::vector<std::string_view> TYPICAL_PATHS = {
    "xmp:CreatorTool", "dc:title[@xml:lang=\"en\"]", "exif:Flash/exif:Fired",
    "dc:subject[2]", "meta[1]/@xml:lang", "", "   ", "a[b[c]"
};

}

FuzzedDataProvider* FDP;
void XMPHelperSplitOnceFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::string path = FDP->ConsumeRandomLengthString(MAX_INITIAL_INPUT_LENGTH);
    std::string delim = FDP->ConsumeRandomLengthString(MAX_DELIMITER_LENGTH);
    auto result = XMPHelper::SplitOnce(path, delim);
    IMAGE_LOGI("[FUZZ] %{public}s: path=[%{public}.64s] delim=[%{public}.64s]", __func__, path.c_str(), delim.c_str());
    (void)result;
}

void XMPHelperTrimFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::string strInput = FDP->ConsumeRandomLengthString(MAX_INITIAL_INPUT_LENGTH);
    std::string trimInput = FDP->ConsumeRandomLengthString(MAX_DELIMITER_LENGTH);
    std::string result = XMPHelper::Trim(strInput, trimInput);
    IMAGE_LOGI("[FUZZ] %{public}s: input=[%{public}.64s] trim=[%{public}.64s] result=[%{public}.64s]", __func__,
        strInput.c_str(), trimInput.c_str(), result.c_str());
    (void)result;
}

static void MutateSingleCharacter(FuzzedDataProvider *fdp, std::string &str)
{
    size_t pos = fdp->ConsumeIntegralInRange<size_t>(0, str.size() - 1);
    char c = fdp->ConsumeIntegral<char>();
    str[pos] = c;
}

static void TestRandomInput(FuzzedDataProvider *fdp)
{
    std::string rawInput = fdp->ConsumeRandomLengthString(MAX_INITIAL_INPUT_LENGTH);
    std::string result = XMPHelper::ExtractProperty(rawInput);
    IMAGE_LOGI("[FUZZ] %{public}s: rawInput=[%{public}.64s] result=[%{public}.64s]", __func__,
        rawInput.c_str(), result.c_str());
    (void)result;
}

static void AppendRandomString(FuzzedDataProvider *fdp, std::string &str)
{
    str += fdp->ConsumeRandomLengthString(SHORT_STRING_MAX_LEN);
}

void TestTypicalPathMutation(FuzzedDataProvider *fdp)
{
    if (fdp->remaining_bytes() < MIN_BYTES_FOR_PATH_MUTATION || !fdp->ConsumeBool()) {
        return;
    }
    size_t pathIdx = fdp->ConsumeIntegralInRange<size_t>(0, TYPICAL_PATHS.size() - 1);
    std::string base = std::string(TYPICAL_PATHS[pathIdx]);
    if (!base.empty() && fdp->ConsumeBool()) {
        MutateSingleCharacter(fdp, base);
    } else if (fdp->ConsumeBool()) {
        AppendRandomString(fdp, base);
    }
    std::string result = XMPHelper::ExtractProperty(base);
    IMAGE_LOGI("[FUZZ] %{public}s: base=[%{public}.64s] result=[%{public}.64s]", __func__,
        base.c_str(), result.c_str());
    (void)result;
}

static std::string GenerateTypedPath(FuzzedDataProvider *fdp, uint8_t type)
{
    TypedPathKind kind = static_cast<TypedPathKind>(type);
    switch (kind) {
        case TypedPathKind::PREFIX_NAME:
            return fdp->ConsumeRandomLengthString(SHORT_STRING_MAX_LEN) + ":" +
                   fdp->ConsumeRandomLengthString(SHORT_STRING_MAX_LEN);
        case TypedPathKind::ARRAY_ITEM:
            return fdp->ConsumeRandomLengthString(PATH_COMPONENT_LEN) + "[" +
                   fdp->ConsumeRandomLengthString(PATH_COMPONENT_LEN) + "]";
        case TypedPathKind::STRUCT_FIELD:
            return fdp->ConsumeRandomLengthString(MEDIUM_STRING_LEN) + "/" +
                   fdp->ConsumeRandomLengthString(MEDIUM_STRING_LEN);
        case TypedPathKind::QUALIFIER:
            return fdp->ConsumeRandomLengthString(MEDIUM_STRING_LEN) + "/?" +
                   fdp->ConsumeRandomLengthString(MEDIUM_STRING_LEN);
        default:
            return "";
    }
}

static void TestTypedGeneration(FuzzedDataProvider *fdp)
{
    if (fdp->remaining_bytes() < MIN_BYTES_FOR_TYPE_GENERATION || !fdp->ConsumeBool()) {
        return;
    }
    uint8_t type = fdp->ConsumeIntegral<uint8_t>() % GENERATION_TYPE_COUNT;
    std::string generated = GenerateTypedPath(fdp, type);
    std::string result = XMPHelper::ExtractProperty(generated);
    IMAGE_LOGI("[FUZZ] %{public}s: generated=[%{public}.64s] result=[%{public}.64s]", __func__,
        generated.c_str(), result.c_str());
    (void)result;
}

static std::string GenerateLongString(FuzzedDataProvider *fdp)
{
    size_t len = fdp->ConsumeIntegralInRange<size_t>(LONG_STRING_MIN_LEN, LONG_STRING_MAX_LEN);
    std::string longStr;

    while (len-- > 0 && fdp->remaining_bytes() > 0) {
        size_t idx = fdp->ConsumeIntegralInRange<size_t>(0, RANDOM_CHAR_SET_MAX_INDEX);
        longStr += RANDOM_CHAR_SET[idx];
    }

    return longStr;
}

static void TestLongString(FuzzedDataProvider *fdp)
{
    if (fdp->remaining_bytes() <= MIN_BYTES_FOR_LONG_STRING || !fdp->ConsumeBool()) {
        return;
    }
    
    std::string longStr = GenerateLongString(fdp);
    std::string result = XMPHelper::ExtractProperty(longStr);
    IMAGE_LOGI("[FUZZ] %{public}s: longStrLen=%{public}zu result=[%{public}.64s]", __func__,
        longStr.length(), result.c_str());
    (void)result;
}

void XMPHelperExtractPropertyFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    IMAGE_LOGI("[FUZZ] %{public}s: entry", __func__);
    TestRandomInput(FDP);
    TestTypicalPathMutation(FDP);
    TestTypedGeneration(FDP);
    TestLongString(FDP);
}

void XMPHelperExtractSplitPropertyFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    if (!TEST_PATHS.empty()) {
        size_t idx = FDP->ConsumeIntegralInRange<size_t>(0, TEST_PATHS.size() - 1);
        auto result = XMPHelper::ExtractSplitProperty(TEST_PATHS[idx]);
        if (!result.first.empty() || !result.second.empty()) {
            IMAGE_LOGI("[FUZZ] %{public}s: known result first=[%{public}.64s] second=[%{public}.64s]",
                __func__, result.first.c_str(), result.second.c_str());
        }
    }
    if (FDP->remaining_bytes() > SHORT_STRING_MAX_LEN) {
        std::string namespacePart = FDP->ConsumeRandomLengthString(SHORT_STRING_MAX_LEN);
        std::string propertyPart = FDP->ConsumeRandomLengthString(MAX_PROPERTY_PART_LENGTH);
        std::string pathWithNamespace = namespacePart + ":" + propertyPart;
        if (FDP->ConsumeBool()) {
            pathWithNamespace += "[1]";
        }
        if (FDP->ConsumeBool()) {
            pathWithNamespace = "prefix/" + pathWithNamespace;
        }
        auto result = XMPHelper::ExtractSplitProperty(pathWithNamespace);
        IMAGE_LOGI("[FUZZ] %{public}s: ns path=[%{public}.64s] result first=[%{public}.64s] second=[%{public}.64s]",
            __func__, pathWithNamespace.c_str(), result.first.c_str(), result.second.c_str());
    }
    if (FDP->remaining_bytes() > REMAIN_BYTES) {
        std::string knownNamespace = FDP->ConsumeRandomLengthString(PATH_COMPONENT_LEN);
        std::string knownProperty = FDP->ConsumeRandomLengthString(REMAIN_BYTES - PATH_COMPONENT_LEN);
        std::string knownPath = knownNamespace + ":" + knownProperty;
        if (FDP->ConsumeBool()) {
            knownPath += "[@attr=\"value\"]";
        }
        auto result = XMPHelper::ExtractSplitProperty(knownPath);
        if (!result.first.empty() && !result.second.empty()) {
            IMAGE_LOGI("[FUZZ] %{public}s: attr result first=[%{public}.64s] second=[%{public}.64s]",
                __func__, result.first.c_str(), result.second.c_str());
        }
    }
    std::string randomPath = FDP->ConsumeRemainingBytesAsString();
    auto randomResult = XMPHelper::ExtractSplitProperty(randomPath);
    IMAGE_LOGI("[FUZZ] %{public}s: random path=[%{public}.64s] result first=[%{public}.64s] second=[%{public}.64s]",
        __func__, randomPath.c_str(), randomResult.first.c_str(), randomResult.second.c_str());
    (void)randomResult;
}

void XMPHelperGetParentPropertyFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    if (!TEST_PATHS.empty()) {
        size_t idx = FDP->ConsumeIntegralInRange<size_t>(0, TEST_PATHS.size() - 1);
        std::string parent = XMPHelper::GetParentProperty(TEST_PATHS[idx]);
        IMAGE_LOGI("[FUZZ] %{public}s: known parent=[%{public}.64s]", __func__, parent.c_str());
        (void)parent;
    }
    std::string randomPath = FDP->ConsumeRandomLengthString(MAX_INITIAL_INPUT_LENGTH);
    std::string parent = XMPHelper::GetParentProperty(randomPath);
    IMAGE_LOGI("[FUZZ] %{public}s: random parent=[%{public}.64s]", __func__, parent.c_str());
    (void)parent;
}

void XMPHelperNormalizeNamespacePrefixFuzzTest()
{
    if (FDP == nullptr) {
        return;
    }
    std::string prefix = FDP->ConsumeRandomLengthString(SHORT_STRING_MAX_LEN);
    if (FDP->ConsumeBool()) {
        prefix += ":";
    }
    std::string normalized = XMPHelper::NormalizeNamespacePrefix(prefix);
    IMAGE_LOGI("[FUZZ] %{public}s: prefix=[%{public}.64s] normalized=[%{public}.64s]", __func__,
        prefix.c_str(), normalized.c_str());
    (void)normalized;
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
    uint8_t actionRaw = opt_fdp.ConsumeIntegral<uint8_t>() % OHOS::Media::FUZZ_ACTION_COUNT;
    OHOS::Media::FuzzAction action = static_cast<OHOS::Media::FuzzAction>(actionRaw);

    size_t testDataSize = size - COMMON_OPT_SIZE;
    const uint8_t* testData = data;

    FuzzedDataProvider test_fdp(testData, testDataSize);
    OHOS::Media::FDP = &test_fdp;
    IMAGE_LOGI("[FUZZ] %{public}s: action=%{public}u size=%{public}zu", __func__, actionRaw, size);

    switch (action) {
        case OHOS::Media::FuzzAction::SPLIT_ONCE:
            OHOS::Media::XMPHelperSplitOnceFuzzTest();
            break;
        case OHOS::Media::FuzzAction::TRIM:
            OHOS::Media::XMPHelperTrimFuzzTest();
            break;
        case OHOS::Media::FuzzAction::EXTRACT_PROPERTY:
            OHOS::Media::XMPHelperExtractPropertyFuzzTest();
            break;
        case OHOS::Media::FuzzAction::EXTRACT_SPLIT_PROPERTY:
            OHOS::Media::XMPHelperExtractSplitPropertyFuzzTest();
            break;
        case OHOS::Media::FuzzAction::GET_PARENT_PROPERTY:
            OHOS::Media::XMPHelperGetParentPropertyFuzzTest();
            break;
        case OHOS::Media::FuzzAction::NORMALIZE_NAMESPACE_PREFIX:
            OHOS::Media::XMPHelperNormalizeNamespacePrefixFuzzTest();
            break;
        default:
            break;
    }
    
    return 0;
}