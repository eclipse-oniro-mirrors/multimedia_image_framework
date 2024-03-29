/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "xmp_parser.h"

#include <cstdlib>
#include "image_log.h"
#include "image_mime_type.h"
#include "include/core/SkData.h"
#include "include/core/SkStream.h"
#include "include/utils/SkParse.h"
#include "src/xml/SkDOM.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_IMAGE

#undef LOG_TAG
#define LOG_TAG "XmpParser"

namespace OHOS {
namespace Media {
using namespace std;
static const string XMP_CONTAINER_URI = "http://ns.google.com/photos/1.0/container/";
static const string XMP_ITEM_URI = "http://ns.google.com/photos/1.0/container/item/";
static const string ADOBE_GAIN_MAP_URI = "http://ns.adobe.com/hdr-gain-map/1.0/";
static const string APPLE_HDR_GAIN_MAP_URI = "http://ns.apple.com/HDRGainMap/1.0/";
static const string ISO_HDR_GAIN_MAP_URI = "http://www.iso.org/standard/86775/gainmap/1.0/";

static const string CONTAINER_DIRECTORY_NAME = "Directory";
static const char* PRIMARY_VALUE = "Primary";
static const char* GAINMAP_VALUE = "GainMap";

static const string ITEM_SEMANTIC_NAME = "Semantic";
static const string ITEM_MIME_NAME = "Mime";
static const string ITEM_LENGTH = "Length";

static const std::string XMLNS_PREFIX = "xmlns:";
static const char* XMP_META_ELEMENT_TAG = "x:xmpmeta";
static const char* XMP_RDF_ELEMENT_TAG = "rdf:RDF";
static const char* XMP_RDF_DESC_ELEMENT_TAG = "rdf:Description";
static const char* XMP_RDF_SEQ_ELEMENT_TAG = "rdf:Seq";
static const char* XMP_RDF_LI_ELEMENT_TAG = "rdf:li";
static const char* XMP_BOOL_FALSE = "False";
static const char* XMP_BOOL_TRUE = "True";
static const char* XMP_GAIN_MAP_METADATA_VERSION = "1.0";

const uint8_t THREE_COMPONENT_NUM = 3;
const uint8_t ONE_COMPONENT_NUM = 1;
enum UltraMetadata {
    VERSION = 0,
    GAINMAP_MIN,
    GAINMAP_MAX,
    GAMMA,
    OFFSET_SDR,
    OFFSET_HDR,
    HDR_CAPACITY_MIN,
    HDR_CAPACITY_MAX,
    BASE_RENDITION_HDR,
};
enum ISOMetadata {
    VERSION_TAG = 0,
    PER_COM_MIN_GAINMAP,
    PER_COM_MAX_GAINMAP,
    PER_COM_BASE_OFFSET,
    PER_COM_ALT_OFFSET,
    PER_COM_GAMMA,
    BASE_HDR_HEADROOM,
    ALT_HDR_HEADROOM,
    NUM_OF_COM,
};

string ULTRA_METADATA_NAME_STR[BASE_RENDITION_HDR + 1] = {
    "Version", "GainMapMin", "GainMapMax", "Gamma", "OffsetSDR",
    "OffsetHDR", "HDRCapacityMin", "HDRCapacityMax", "BaseRenditionIsHDR"
};
string ISO_METADATA_NAME_STR[NUM_OF_COM + 1] = {
    "Versiontag", "PerComponentMinGainmapValues", "PerComponentMaxGainmapValues",
    "PerComponentBaselineOffset", "PerComponenetAlternateOffset", "PerComponentGamma",
    "BaselineHDRheadroom", "AlternateHDRheadroom", "NumberOfComponent"
};
const string APPLE_HDR_GAIN_MAP_VERSION_NAME = "HDRGainMapVersion";
const string APPLE_HDR_GAIN_MAP_HEADROOM_NAME = "HDRGainMapHeadroom";

static vector<string> GetUltraMetadataAttrName(const string prefix)
{
    vector<string> names(BASE_RENDITION_HDR + 1);
    for (int i = 0; i <= BASE_RENDITION_HDR; i++) {
        names[i] = prefix + ":" + ULTRA_METADATA_NAME_STR[i];
    }
    return names;
}

static vector<string> GetISOMetadataAttrName(const string prefix)
{
    vector<string> names(NUM_OF_COM + 1);
    for (int i = 0; i <= NUM_OF_COM; i++) {
        names[i] = prefix + ":" + ISO_METADATA_NAME_STR[i];
    }
    return names;
}

static bool StringToDouble(const char* str, double value)
{
    char* end;
    value = strtod(str, &end);
    if (str == end) {
        return false;
    }
    return true;
}

static const char* GetElementValue(SkDOM& dom, const SkDOMNode* node)
{
    const SkDOMNode* valueNode = dom.getFirstChild(node);
    if (!valueNode) {
        return nullptr;
    }
    if (dom.getType(valueNode) != SkDOM::kText_Type) {
        return nullptr;
    }
    return dom.getName(valueNode);
}

static bool GetBoolValue(SkDOM& dom, const SkDOMNode* node, string name, bool& value)
{
    const char* valueStr = dom.findAttr(node, name.c_str());
    if (!valueStr) {
        valueStr = GetElementValue(dom, node);
        if (!valueStr) {
            return false;
        }
    }
    uint32_t len = strlen(valueStr);
    if (len == strlen(XMP_BOOL_TRUE) && strcmp(valueStr, XMP_BOOL_TRUE) == 0) {
        value = true;
        return true;
    };
    if (len == strlen(XMP_BOOL_FALSE) && strcmp(valueStr, XMP_BOOL_FALSE) == 0) {
        value = false;
        return true;
    };
    return false;
}

static bool GetDoubleValue(SkDOM& dom, const SkDOMNode* node, string name, double& value)
{
    const char* valueStr = dom.findAttr(node, name.c_str());
    if (!valueStr) {
        valueStr = GetElementValue(dom, node);
        if (!valueStr) {
            return false;
        }
    }
    return StringToDouble(valueStr, value);
}

static bool GetMetadataArrayValue(SkDOM& dom, const SkDOMNode* node, string name, vector<double>& value)
{
    const SkDOMNode* arrayElement = dom.getFirstChild(node, name.c_str());
    if (!arrayElement) {
        return false;
    }
    const SkDOMNode* seqElement = dom.getFirstChild(arrayElement, XMP_RDF_SEQ_ELEMENT_TAG);
    if (!seqElement) {
        return false;
    }
    const SkDOMNode* liElement = dom.getFirstChild(seqElement, XMP_RDF_LI_ELEMENT_TAG);
    uint8_t index = 0;
    while (liElement) {
        if (index > THREE_COMPONENT_NUM - 1) {
            return false;
        }
        double tmp;
        if (GetDoubleValue(dom, liElement, name, tmp)) {
            value[index] = tmp;
        }
        index++;
        liElement = dom.getNextSibling(liElement, XMP_RDF_LI_ELEMENT_TAG);
    }
    if (index != THREE_COMPONENT_NUM) {
        return false;
    }
    return true;
}

static bool GetMetadataValue(SkDOM& dom, const SkDOMNode* node, string name, vector<double>& value, uint8_t& num)
{
    double perValue;
    if (GetDoubleValue(dom, node, name, perValue)) {
        value = {perValue, perValue, perValue};
        num = ONE_COMPONENT_NUM;
        return true;
    }
    if (GetMetadataArrayValue(dom, node, name, value)) {
        num = THREE_COMPONENT_NUM;
        return true;
    }
    return false;
}

static bool CheckVectorStringEmpty(const vector<string>& strs)
{
    for (const auto& item : strs) {
        if (item.empty()) {
            return false;
        }
    }
    return true;
}

bool XmpParser::BuildDom(const uint8_t* data, uint32_t size)
{
    sk_sp<SkData> xmpData = SkData::MakeWithoutCopy(data, size);
    auto stream = SkMemoryStream::Make(xmpData);
    if (!xmpDom_.build(*stream)) {
        return false;
    }
    return true;
}

static const char* GetAttrName(const SkDOMNode* node, const char* value)
{
    if (!node) {
        return nullptr;
    }
    const SkDOM::Attr* start = node->attrs();
    const SkDOM::Attr* end = start + node->fAttrCount;

    while (start < end) {
        if (!strcmp(start->fValue, value)) {
            return start->fName;
        }
        start += 1;
    }
    return nullptr;
}

static void GetPrefixes(const SkDOMNode* node, vector<string> uris, vector<string>& prefixes)
{
    uint32_t size = uris.size();
    for (uint32_t i = 0; i < size; i++) {
        const char* name = GetAttrName(node, uris[i].c_str());
        if (!name) {
            continue;
        }
        if (strlen(name) < XMLNS_PREFIX.length() ||
            (memcmp(name, XMLNS_PREFIX.c_str(), XMLNS_PREFIX.length()) != 0)) {
                continue;
        }
        string prefix = string(name);
        uint32_t prefixLen = XMLNS_PREFIX.length();
        if (prefix.length() < prefixLen) {
            continue;
        }
        prefix.erase(0, prefixLen);
        prefixes[i] = prefix;
    }
}

static vector<string> ParsePrefixes(SkDOM& dom, vector<string> uris, const SkDOMNode** outNode)
{
    vector<string> prefixes(uris.size());
    auto root = dom.getRootNode();
    if (!root) {
        return prefixes;
    }
    auto rootName = dom.getName(root);
    if (!rootName || (strcmp(rootName, XMP_META_ELEMENT_TAG) != 0)) {
        return prefixes;
    }
    // prefix need check rdf:RDF element and rdf:Description element.
    const SkDOMNode* rdfElement = dom.getFirstChild(root, XMP_RDF_ELEMENT_TAG);
    if (!rdfElement) {
        return prefixes;
    }
    GetPrefixes(rdfElement, uris, prefixes);
    const SkDOMNode* rdfDescElement = dom.getFirstChild(rdfElement, XMP_RDF_DESC_ELEMENT_TAG);
    if (!rdfDescElement) {
        return prefixes;
    }
    GetPrefixes(rdfDescElement, uris, prefixes);
    *outNode = rdfDescElement;
    return prefixes;
}

//// parse base image xmp
bool XmpParser::ParseBaseImageXmp(const uint8_t* data, uint32_t size, uint8_t& gainMapIndex)
{
    if (!BuildDom(data, size)) {
        return false;
    }
    vector<string> uris = { XMP_CONTAINER_URI, XMP_ITEM_URI };
    const SkDOMNode* element = nullptr;
    vector<string> prefixes = ParsePrefixes(xmpDom_, uris, &element);
    if (!CheckVectorStringEmpty(prefixes)) {
        IMAGE_LOGD("parse base image prefixes failed");
        return false;
    }
    string containerPrefix = prefixes[0];
    string itemPrefix = prefixes[1];
    string directoryName = containerPrefix + ":" + CONTAINER_DIRECTORY_NAME;
    const SkDOMNode* directoryElement = xmpDom_.getFirstChild(element, directoryName.c_str());
    if (!directoryElement) {
        IMAGE_LOGD("get directory element failed");
        return false;
    }
    const SkDOMNode* seqElement = xmpDom_.getFirstChild(directoryElement, XMP_RDF_SEQ_ELEMENT_TAG);
    if (!seqElement) {
        IMAGE_LOGD("get seq element failed");
        return false;
    }
    gainMapIndex = GetGainMapIndex(seqElement, containerPrefix, itemPrefix);
    return gainMapIndex != 0;
}

uint8_t XmpParser::GetGainMapIndex(const SkDOMNode* element, string& containerPrefix, string& itemPrefix)
{
    uint8_t index = 0;
    uint8_t gainMapIndex = 0;
    string mimeName = itemPrefix + ":" + ITEM_MIME_NAME;
    string semanticName = itemPrefix + ":" + ITEM_SEMANTIC_NAME;
    string item = containerPrefix + ":" + itemPrefix;
    auto liElement = xmpDom_.getFirstChild(element, XMP_RDF_LI_ELEMENT_TAG);
    while (liElement) {
        const SkDOMNode* itemNode = xmpDom_.getFirstChild(liElement, item.c_str());
        if (!itemNode) {
            return 0;
        }
        const char* mimeValue = xmpDom_.findAttr(itemNode, mimeName.c_str());
        if (!mimeValue || strcmp(mimeValue, IMAGE_JPEG_FORMAT.c_str()) != 0) {
            continue;
        }
        const char* semanticValue = xmpDom_.findAttr(itemNode, semanticName.c_str());
        // if the first image is not Primary, the xmp data is error.
        if (index == 0 && (strcmp(semanticValue, PRIMARY_VALUE) != 0)) {
            return 0;
        } else if (index != 0 && strcmp(semanticValue, GAINMAP_VALUE) == 0) {
            gainMapIndex = index;
            break;
        }
        index++;
        liElement = xmpDom_.getNextSibling(liElement, XMP_RDF_LI_ELEMENT_TAG);
    }
    return gainMapIndex;
}

/// parse ISO hdr metadata
static bool ParseISOMetadata(SkDOM& dom, IsoMetadata& metadata)
{
    vector<string> uris = { ISO_HDR_GAIN_MAP_URI };
    const SkDOMNode* element = nullptr;
    vector<string> prefixes = ParsePrefixes(dom, uris, &element);
    string prefix = prefixes[0];
    if (prefix.empty()) {
        IMAGE_LOGD("parse iso metadata prefix failed");
        return false;
    }
    vector<string> metaNames = GetISOMetadataAttrName(prefix);
    const char* version = dom.findAttr(element, metaNames[VERSION_TAG].c_str());
    if (!version) {
        IMAGE_LOGD("parse iso metadata version failed");
        return false;
    }
    const char* comNum = dom.findAttr(element, metaNames[NUM_OF_COM].c_str());
    if (!comNum) {
        IMAGE_LOGD("parse iso metadata component number failed");
        metadata.numberOfComponents = atoi(comNum);
    }
    if (!GetDoubleValue(dom, element, metaNames[ALT_HDR_HEADROOM], metadata.hdrCapacityMax)) {
        IMAGE_LOGD("parse iso metadata hdrCapacityMax failed");
        return false;
    }
    uint8_t num;
    GetDoubleValue(dom, element, metaNames[BASE_HDR_HEADROOM], metadata.hdrCapacityMin);
    if (!GetMetadataValue(dom, element, metaNames[PER_COM_MAX_GAINMAP], metadata.gainMapMax, num)) {
        IMAGE_LOGD("parse iso metadata gainMapMax failed");
        return false;
    }
    GetMetadataValue(dom, element, metaNames[PER_COM_ALT_OFFSET], metadata.offsetHdr, num);
    GetMetadataValue(dom, element, metaNames[PER_COM_BASE_OFFSET], metadata.offsetSdr, num);
    GetMetadataValue(dom, element, metaNames[PER_COM_GAMMA], metadata.gamma, num);
    GetMetadataValue(dom, element, metaNames[PER_COM_MIN_GAINMAP], metadata.gainMapMin, num);
    return true;
}

static bool ParseUltraMetadata(SkDOM& dom, IsoMetadata& metadata)
{
    vector<string> uris = { ADOBE_GAIN_MAP_URI };
    const SkDOMNode* element = nullptr;
    vector<string> prefixes = ParsePrefixes(dom, uris, &element);
    string prefix = prefixes[0];
    if (prefix.empty()) {
        IMAGE_LOGD("parse ultra metadata prefix failed");
        return false;
    }
    vector<string> metaNames = GetUltraMetadataAttrName(prefix);
    const char* version = dom.findAttr(element, metaNames[VERSION].c_str());
    if (!version || (strcmp(version, XMP_GAIN_MAP_METADATA_VERSION) != 0)) {
        IMAGE_LOGD("parse ultra metadata version failed");
        return false;
    }
    if (!GetDoubleValue(dom, element, metaNames[HDR_CAPACITY_MAX], metadata.hdrCapacityMax)) {
        IMAGE_LOGD("parse ultra metadata hdrCapacityMax failed");
        return false;
    }
    uint8_t num;
    if (!GetMetadataValue(dom, element, metaNames[GAINMAP_MAX], metadata.gainMapMax, num)) {
        IMAGE_LOGD("parse ultra metadata gainMapMax failed");
        return false;
    }
    metadata.numberOfComponents = num;
    GetBoolValue(dom, element, metaNames[BASE_RENDITION_HDR], metadata.baseIsHdr);
    GetDoubleValue(dom, element, metaNames[HDR_CAPACITY_MIN], metadata.hdrCapacityMin);
    GetMetadataValue(dom, element, metaNames[OFFSET_HDR], metadata.offsetHdr, num);
    GetMetadataValue(dom, element, metaNames[OFFSET_SDR], metadata.offsetSdr, num);
    GetMetadataValue(dom, element, metaNames[GAMMA], metadata.gamma, num);
    GetMetadataValue(dom, element, metaNames[GAINMAP_MIN], metadata.gainMapMin, num);
    return true;
}

static bool ParseAppleMetadata(SkDOM& dom, IsoMetadata& metadata)
{
    vector<string> uris = { APPLE_HDR_GAIN_MAP_URI };
    const SkDOMNode* element = nullptr;
    vector<string> prefixes = ParsePrefixes(dom, uris, &element);
    string prefix = prefixes[0];
    if (prefix.empty()) {
        IMAGE_LOGD("parse apple metadata prefix failed");
        return false;
    }
    string versionName = prefix + ":" + APPLE_HDR_GAIN_MAP_VERSION_NAME;
    string headroomName = prefix + ":" + APPLE_HDR_GAIN_MAP_HEADROOM_NAME;
    const SkDOMNode* versionElement = dom.getFirstChild(element, versionName.c_str());
    if (!versionElement) {
        return false;
    }
    const char* version = GetElementValue(dom, versionElement);
    if (!version) {
        return false;
    }
    const SkDOMNode* headroomElement = dom.getFirstChild(element, headroomName.c_str());
    if (!headroomElement) {
        return false;
    }
    if (!GetDoubleValue(dom, headroomElement, headroomName, metadata.hdrCapacityMax)) {
        IMAGE_LOGD("parse apple metadata headroom value failed");
        return false;
    }
    metadata.numberOfComponents = 1;
    return true;
}

bool XmpParser::ParseGainMapMetadata(const uint8_t* data, uint32_t size, IsoMetadata& metadata)
{
    if (!BuildDom(data, size)) {
        return false;
    }
    if (ParseISOMetadata(xmpDom_, metadata)) {
        return true;
    }
    if (ParseUltraMetadata(xmpDom_, metadata)) {
        return true;
    }
    if (ParseAppleMetadata(xmpDom_, metadata)) {
        return true;
    }
    return false;
}
} // namespace Media
} // namespace OHOS