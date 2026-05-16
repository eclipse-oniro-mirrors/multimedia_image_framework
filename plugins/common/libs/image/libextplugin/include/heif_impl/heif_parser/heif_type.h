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

#ifndef PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_TYPE_H
#define PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_TYPE_H

#include <vector>
#include <map>
#include "heif_utils.h"

namespace OHOS {
namespace ImagePlugin {
static const uint32_t BOX_TYPE_FTYP = fourcc_to_code("ftyp");
static const uint32_t BOX_TYPE_META = fourcc_to_code("meta");
static const uint32_t BOX_TYPE_HDLR = fourcc_to_code("hdlr");
static const uint32_t BOX_TYPE_ILOC = fourcc_to_code("iloc");
static const uint32_t BOX_TYPE_PITM = fourcc_to_code("pitm");
static const uint32_t BOX_TYPE_INFE = fourcc_to_code("infe");
static const uint32_t BOX_TYPE_IINF = fourcc_to_code("iinf");
static const uint32_t BOX_TYPE_PTIM = fourcc_to_code("ptim");
static const uint32_t BOX_TYPE_IPRP = fourcc_to_code("iprp");
static const uint32_t BOX_TYPE_AUXC = fourcc_to_code("auxC");
static const uint32_t BOX_TYPE_AUXL = fourcc_to_code("auxl");
static const uint32_t BOX_TYPE_IPCO = fourcc_to_code("ipco");
static const uint32_t BOX_TYPE_IPMA = fourcc_to_code("ipma");
static const uint32_t BOX_TYPE_ISPE = fourcc_to_code("ispe");
static const uint32_t BOX_TYPE_PIXI = fourcc_to_code("pixi");
static const uint32_t BOX_TYPE_COLR = fourcc_to_code("colr");
static const uint32_t BOX_TYPE_NCLX = fourcc_to_code("nclx");
static const uint32_t BOX_TYPE_HVCC = fourcc_to_code("hvcC");
static const uint32_t BOX_TYPE_IROT = fourcc_to_code("irot");
static const uint32_t BOX_TYPE_IMIR = fourcc_to_code("imir");
static const uint32_t BOX_TYPE_IREF = fourcc_to_code("iref");
static const uint32_t BOX_TYPE_IDAT = fourcc_to_code("idat");
static const uint32_t BOX_TYPE_MDAT = fourcc_to_code("mdat");
static const uint32_t BOX_TYPE_UUID = fourcc_to_code("uuid");
static const uint32_t BOX_TYPE_THMB = fourcc_to_code("thmb");
static const uint32_t BOX_TYPE_DIMG = fourcc_to_code("dimg");
static const uint32_t BOX_TYPE_CDSC = fourcc_to_code("cdsc");

static const uint32_t BOX_TYPE_MOOV = fourcc_to_code("moov");
static const uint32_t BOX_TYPE_MVHD = fourcc_to_code("mvhd");
static const uint32_t BOX_TYPE_TRAK = fourcc_to_code("trak");
static const uint32_t BOX_TYPE_TKHD = fourcc_to_code("tkhd");
static const uint32_t BOX_TYPE_MDIA = fourcc_to_code("mdia");
static const uint32_t BOX_TYPE_MDHD = fourcc_to_code("mdhd");
static const uint32_t BOX_TYPE_MINF = fourcc_to_code("minf");
static const uint32_t BOX_TYPE_VMHD = fourcc_to_code("vmhd");
static const uint32_t BOX_TYPE_DINF = fourcc_to_code("dinf");
static const uint32_t BOX_TYPE_DREF = fourcc_to_code("dref");
static const uint32_t BOX_TYPE_STBL = fourcc_to_code("stbl");
static const uint32_t BOX_TYPE_STSD = fourcc_to_code("stsd");
static const uint32_t BOX_TYPE_HVC1 = fourcc_to_code("hvc1");
static const uint32_t BOX_TYPE_STTS = fourcc_to_code("stts");
static const uint32_t BOX_TYPE_STSC = fourcc_to_code("stsc");
static const uint32_t BOX_TYPE_STCO = fourcc_to_code("stco");
static const uint32_t BOX_TYPE_STSZ = fourcc_to_code("stsz");
static const uint32_t BOX_TYPE_STSS = fourcc_to_code("stss");

static const uint32_t BOX_TYPE_CLLI = fourcc_to_code("clli");
static const uint32_t BOX_TYPE_MDCV = fourcc_to_code("mdcv");
static const uint32_t BOX_TYPE_IT35 = fourcc_to_code("it35");

static const uint32_t BOX_TYPE_RLOC = fourcc_to_code("rloc");
static const uint32_t BOX_TYPE_GRPL = fourcc_to_code("grpl");

static const uint32_t BOX_TYPE_AV1C = fourcc_to_code("av1C");
static const uint32_t BOX_TYPE_AV01 = fourcc_to_code("av01");

static const uint32_t HANDLER_TYPE_PICT = fourcc_to_code("pict");

static const uint32_t ITEM_TYPE_MIME = fourcc_to_code("mime");
static const uint32_t ITEM_TYPE_URI = fourcc_to_code("uri ");

static const uint32_t COLOR_TYPE_PROF = fourcc_to_code("prof");
static const uint32_t COLOR_TYPE_RICC = fourcc_to_code("rICC");

static const uint32_t HEIF_BRAND_TYPE_MSF1 = fourcc_to_code("msf1");

static const uint32_t AVIF_BRAND_TYPE_AVIF = fourcc_to_code("avif");
static const uint32_t AVIF_BRAND_TYPE_AVIS = fourcc_to_code("avis");

// For Cr3 raw format
static const uint32_t CR3_FILE_TYPE_CRX = fourcc_to_code("crx ");  // Cr3 major brand
static const uint32_t CR3_BOX_TYPE_PRVW = fourcc_to_code("PRVW");  // Preview in JPEG format
static const uint32_t CR3_BOX_TYPE_MOOV = fourcc_to_code("moov");  // Movie box
static const uint32_t CR3_BOX_TYPE_CMT1 = fourcc_to_code("CMT1");  // Exif IFD0 in TIFF format
static const uint32_t CR3_BOX_TYPE_CMT2 = fourcc_to_code("CMT2");  // Exif ExifIFD in TIFF format
static const uint32_t CR3_BOX_TYPE_CMT3 = fourcc_to_code("CMT3");  // Canon Maker notes in TIFF format
static const uint32_t CR3_BOX_TYPE_CMT4 = fourcc_to_code("CMT4");  // Exif GPS IFD in TIFF format

typedef uint32_t heif_item_id;

typedef uint32_t heif_brand;

enum HeifBoxVersion {
    HEIF_BOX_VERSION_ZERO = 0,
    HEIF_BOX_VERSION_ONE = 1,
    HEIF_BOX_VERSION_TWO = 2,
    HEIF_BOX_VERSION_THREE = 3,
};

enum class HeifColorFormat {
    UNDEDEFINED = 255,
    YCBCR = 0,
    RGB = 1,
    MONOCHROME = 2
};

enum class HeifPixelFormat {
    UNDEFINED = 255,
    MONOCHROME = 0,
    YUV420 = 1,
    YUV422 = 2,
    YUV444 = 3,
};

enum class HeifTransformMirrorDirection : uint8_t {
    VERTICAL = 0,
    HORIZONTAL = 1,
    INVALID = 2,
};

typedef uint32_t heif_property_id;

struct HeifMetadata {
    heif_item_id itemId;
    std::string itemType;
    std::string contentType;
    std::string itemUriType;
    std::vector<uint8_t> mData;
};

struct HeifFragmentMetadata {
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t horizontalOffset = 0;
    uint32_t verticalOffset = 0;
};

constexpr static uint32_t PRIMARY_IMAGE_ITEM_ID = 1;
constexpr static uint32_t GAINMAP_IMAGE_ITEM_ID = 2;
constexpr static uint32_t TMAP_IMAGE_ITEM_ID = 3;
constexpr static uint32_t EXIF_META_ITEM_ID = 4;
constexpr static uint32_t DEPTH_MAP_ITEM_ID = 5;
constexpr static uint32_t UNREFOCUS_MAP_ITEM_ID = 6;
constexpr static uint32_t LINEAR_MAP_ITEM_ID = 7;
constexpr static uint32_t FRAGMENT_MAP_ITEM_ID = 8;
constexpr static uint32_t XTSTYLE_META_ITEM_ID = 9;
constexpr static uint32_t RFDATAB_META_ITEM_ID = 10;
constexpr static uint32_t STDATA_META_ITEM_ID = 11;
constexpr static uint32_t XDRAW4K_META_ITEM_ID = 12;
constexpr static uint32_t PRIVATE_META_ITEM_ID = 13;
constexpr static uint32_t RFDATAN_META_ITEM_ID = 14;
constexpr static uint32_t RFDATAS_META_ITEM_ID = 15;
constexpr static uint32_t HDRSNAP_META_ITEM_ID = 16;
constexpr static uint32_t SNAP_MAP_ITEM_ID = 17;
constexpr static uint32_t SNAP_GAINMAP_ITEM_ID = 18;
constexpr static uint32_t PAN_MAP_ITEM_ID = 19;
constexpr static uint32_t PAN_GAINMAP_ITEM_ID = 20;
constexpr static uint32_t DFXDATA_META_ITEM_ID = 21;
 
static const std::string COMPRESS_TYPE_TMAP = "tmap";
static const std::string COMPRESS_TYPE_HEVC = "hevc";
static const std::string COMPRESS_TYPE_NONE = "none";
 
static const std::string DEFAULT_ASHMEM_TAG = "Heif Encoder Default";
static const std::string ICC_ASHMEM_TAG = "Heif Encoder Property";
static const std::string IT35_ASHMEM_TAG = "Heif Encoder IT35";
static const std::string OUTPUT_ASHMEM_TAG = "Heif Encoder Output";
static const std::string IMAGE_DATA_TAG = "Heif Encoder Image";
static const std::string HDR_GAINMAP_TAG = "Heif Encoder Gainmap";
static const std::string EXIF_ASHMEM_TAG = "Heif Encoder Exif";
static const std::string XTSTYLE_ASHMEM_TAG = "Heif Encoder XtStyle";
static const std::string RFDATAB_ASHMEM_TAG = "Heif Encoder RfDataB";
static const std::string STDATA_ASHMEM_TAG = "Heif Encoder STData";
static const std::string XDRAW4K_ASHMEM_TAG = "Heif Encoder 4KXDRAW";
static const std::string PRIVATE_ASHMEM_TAG = "Heif Encoder Private";
static const std::string RFDATAN_ASHMEM_TAG = "Heif Encoder RfDataN";
static const std::string RFDATAS_ASHMEM_TAG = "Heif Encoder RfDataS";
static const std::string HDRSNAP_ASHMEM_TAG = "Heif Encoder HDRSnap";
static const std::string DFXDATA_ASHMEM_TAG = "Heif Encoder DfxData";
 
static const std::string GAINMAP_IMAGE_ITEM_NAME = "Gain map Image";
static const std::string DEPTH_MAP_ITEM_NAME =  "Depth Map Image";
static const std::string UNREFOCUS_MAP_ITEM_NAME = "Unrefocus Map Image";
static const std::string LINEAR_MAP_ITEM_NAME = "Linear Map Image";
static const std::string FRAGMENT_MAP_ITEM_NAME = "Fragment Map Image";
static const std::string SNAP_MAP_ITEM_NAME = "Snap Map Image";
static const std::string SNAP_GAINMAP_ITEM_NAME = "Snap Gainmap Image";
static const std::string PAN_MAP_ITEM_NAME = "Pan Map Image";
static const std::string PAN_GAINMAP_ITEM_NAME = "Pan Map Image";
static const std::string XTSTYLE_METADATA_ITEM_NAME = "urn:com:huawei:photo:5:1:0:meta:xtstyle";
static const std::string RFDATAB_METADATA_ITEM_NAME = "RfDataB\0";
static const std::string STDATA_METADATA_ITEM_NAME = "STData\0";
static const std::string XDRAW4K_METADATA_ITEM_NAME = "XDRAW4K";
static const std::string PRIVATE_METADATA_ITEM_NAME = "PRIVATE";
static const std::string RFDATAN_METADATA_ITEM_NAME = "RfDataN\0";
static const std::string RFDATAS_METADATA_ITEM_NAME = "RfDataS\0";
static const std::string HDRSNAP_METADATA_ITEM_NAME = "SnpHdrM\0";
static const std::string DFXDATA_METADATA_ITEM_NAME = "DfxData\0";
 
 
enum class HeifMetadataType : int32_t {
    UNKNOWN = 0,
    EXIF = 1,
    FRAGMENT = 2,
    XTSTYLE = 3,
    RFDATAB = 4,
    GIF = 5,
    STDATA = 6,
    RESMAP = 7,
    XDRAW4K = 8,
    PRIVATE = 9,
    RFDATAN = 10,
    RFDATAS = 11,
    HDRSNAP = 12,
    DFXDATA = 13,
};
 
struct HeifBlobMetadataEncodeInfo {
    HeifMetadataType type;
    uint32_t itemId;
    std::string ashmemTag;
    std::string itemName;
};
 
static const std::vector<HeifBlobMetadataEncodeInfo> HEIF_BLOB_INFOS = {
    { HeifMetadataType::XTSTYLE,  XTSTYLE_META_ITEM_ID,  XTSTYLE_ASHMEM_TAG,  XTSTYLE_METADATA_ITEM_NAME },
    { HeifMetadataType::RFDATAB,  RFDATAB_META_ITEM_ID,  RFDATAB_ASHMEM_TAG,  RFDATAB_METADATA_ITEM_NAME },
    { HeifMetadataType::STDATA,   STDATA_META_ITEM_ID,   STDATA_ASHMEM_TAG,   STDATA_METADATA_ITEM_NAME  },
    { HeifMetadataType::XDRAW4K,  XDRAW4K_META_ITEM_ID,  XDRAW4K_ASHMEM_TAG,  XDRAW4K_METADATA_ITEM_NAME },
    { HeifMetadataType::PRIVATE,  PRIVATE_META_ITEM_ID,  PRIVATE_ASHMEM_TAG,  PRIVATE_METADATA_ITEM_NAME },
    { HeifMetadataType::RFDATAN,  RFDATAN_META_ITEM_ID,  RFDATAN_ASHMEM_TAG,  RFDATAN_METADATA_ITEM_NAME },
    { HeifMetadataType::RFDATAS,  RFDATAS_META_ITEM_ID,  RFDATAS_ASHMEM_TAG,  RFDATAS_METADATA_ITEM_NAME },
    { HeifMetadataType::HDRSNAP,  HDRSNAP_META_ITEM_ID,  HDRSNAP_ASHMEM_TAG,  HDRSNAP_METADATA_ITEM_NAME },
    { HeifMetadataType::DFXDATA,  DFXDATA_META_ITEM_ID,  DFXDATA_ASHMEM_TAG,  DFXDATA_METADATA_ITEM_NAME },
};
} // namespace ImagePlugin
} // namespace OHOS

#endif // PLUGINS_COMMON_LIBS_IMAGE_LIBEXTPLUGIN_INCLUDE_HEIF_PARSER_HEIF_TYPE_H
