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

#include "hardware/jpeg_hw_tile_decoder.h"

#include "surface_type.h"
#include "surface_buffer.h"

#include "image_utils.h"
#include "image_mime_type.h"
#include "image_func_timer.h"
#include "image_plugin_type.h"
#include "buffer_source_stream.h"
#include "image_log.h"
#include "include/codec/SkCodec.h"
#include "src/codec/SkJpegCodec.h"
#include "src/codec/SkJpegDecoderMgr.h"
#include "jpeglib.h"
#include "securec.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN LOG_TAG_DOMAIN_ID_PLUGIN

#undef LOG_TAG
#define LOG_TAG "JpegHwTileDecoder"

#define ALIGN_DOWN(n, align) ((n) / (align) * (align))
#define ALIGN_UP(n, align) (((n) + (align) - 1) / (align) * (align))
#define DIV_ROUND_UP(a, b) (((a) + (b) - 1) / (b))

#define EXCLUDE(cond)     \
    do {                  \
        if (cond) {       \
            return false; \
        }                 \
    } while (0)

#define REQUIRE(cond)     \
    do {                  \
        if (!(cond)) {    \
            return false; \
        }                 \
    } while (0)

#define REQUIRE_LOG(cond, ...)                  \
    do {                                        \
        if (!(cond)) {                          \
            HILOG_DEBUG(LOG_CORE, __VA_ARGS__); \
            return false;                       \
        }                                       \
    } while (0)

namespace OHOS {
namespace ImagePlugin {
using namespace Media;
using namespace OHOS::HDI::Base;
using namespace JpegHwTile;

#define SUCCESS OHOS::Media::SUCCESS

namespace {
constexpr static uint32_t NUM_0 = 0;
constexpr static uint32_t NUM_1 = 1;
constexpr static uint32_t NUM_2 = 2;
constexpr static uint32_t NUM_3 = 3;
constexpr static uint32_t NUM_4 = 4;
constexpr static uint32_t NUM_5 = 5;
constexpr static uint32_t NUM_6 = 6;
constexpr static uint32_t NUM_8 = 8;
constexpr static uint32_t NUM_12 = 12;
constexpr static uint32_t NUM_4k = 4 * 1024;
constexpr static uint32_t NUM_8k = 8 * 1024;
constexpr static uint32_t NUM_16k = 16 * 1024;
constexpr static uint32_t NUM_12k = 12 * 1024;
constexpr static uint32_t MCU_WIDTH = 16; // default value of baseline, interleaved and 420 jpeg MCU width
constexpr static uint32_t MCU_HEIGHT = 16; // default value of baseline, interleaved and 420 jpeg MCU height
constexpr static uint32_t MIN_BIG_IMAGE_WIDTH = 10240; // target width lower bound
constexpr static uint32_t MIN_BIG_IMAGE_HEIGHT = 10240; // target height lower bound
constexpr static uint32_t MAX_SUPPORT_IMAGE_AREA = 8192 * 8192; // max area supported by hardware decoder
constexpr static uint32_t MAX_NUM_MCU_IN_RST = 48;
constexpr static uint32_t MIN_NUM_MCU_IN_RST = 32;
constexpr static int32_t MAX_V_SAMP_FACTOR = 2;
constexpr static int32_t MAX_H_SAMP_FACTOR = 2;
constexpr static uint32_t MAX_NUM_HUFF_TBLS = 4;
constexpr static uint8_t FFCode = 0xFF;
constexpr static uint8_t MARK_EOI = 0xD9;
constexpr static uint8_t MARK_SOF0 = 0xC0;
constexpr static uint8_t MARK_SOS = 0xDA;
constexpr static uint8_t JPEG_MARKER_DHT = 0xC4;
constexpr static uint8_t JPEG_MARKER_DRI = 0xDD;
constexpr static uint8_t RSTs[] = { 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7 };
constexpr static uint32_t NUM_END_EXTRA_BYTES = NUM_8 * NUM_8 * NUM_8;


constexpr static uint32_t DEFAULT_SCALE_SIZE = 1;
constexpr static uint32_t DOUBLE_SCALE_SIZE = 2;
constexpr static uint32_t FOURTH_SCALE_SIZE = 4;
constexpr static uint32_t MAX_SCALE_SIZE = 8;
constexpr static float HALF = 0.5;
constexpr static float QUARTER = 0.25;
constexpr static float ONE_EIGHTH = 0.125;
}

static inline float Max(float a, float b)
{
    return (a > b) ? a : b;
}

enum class TableClass : uint8_t {
    DC_TABLE = 0,
    AC_TABLE,
};

enum class TableComponent : uint8_t {
    LUMA = 0,
    CHROMA,
};

namespace {
constexpr uint8_t HUFF_LOOKHEAD = 8;
constexpr uint8_t MAX_DC_CATEGORY = 12;
constexpr uint8_t MAX_HUFFCODE_LENGTH = 16;
constexpr uint8_t MAX_NUM_DC_HUFFCODE = MAX_DC_CATEGORY;
constexpr uint8_t MAX_NUM_AC_HUFFCODE = 0xA2;
constexpr uint8_t MAX_NUM_HUFFCODE = MAX_NUM_AC_HUFFCODE;
}

struct HuffTable {
    TableClass tc;
    TableComponent th;

    uint32_t numCodes = 0;
    uint32_t HUFFVAL[MAX_NUM_HUFFCODE] = {0};
    uint32_t HUFFSIZE[MAX_NUM_HUFFCODE] = {0};
    uint32_t HUFFCODE[MAX_NUM_HUFFCODE] = {0};

    int32_t MAXCODE[MAX_HUFFCODE_LENGTH + 1] = {-1};
    int32_t MINCODE[MAX_HUFFCODE_LENGTH + 1] = {-1};
    uint32_t VALPTR[MAX_HUFFCODE_LENGTH + 1] = {-1};

    struct {
        uint8_t size = HUFF_LOOKHEAD + 1;
        uint8_t value = 0;
    } HUFFLUT_DEC[1 << HUFF_LOOKHEAD];

    struct {
        uint32_t bits = 0;
        uint32_t n = 0;
    } HUFFLUT_ENC_DC[MAX_DC_CATEGORY];

    HuffTable()
        : tc(TableClass::DC_TABLE), th(TableComponent::LUMA) {}
    HuffTable(TableClass tcParam, TableComponent thParam)
        : tc(tcParam), th(thParam) {}
};

struct HuffTables {
    HuffTables() {}
    HuffTable& GetTable(TableClass tc, TableComponent th)
    {
        if (tc == TableClass::DC_TABLE && th == TableComponent::LUMA) {
            return tables[NUM_0];
        } else if (tc == TableClass::DC_TABLE && th == TableComponent::CHROMA) {
            return tables[NUM_1];
        } else if (tc == TableClass::AC_TABLE && th == TableComponent::LUMA) {
            return tables[NUM_2];
        } else {
            return tables[NUM_3];
        }
    }
private:
    HuffTable tables[4];  // 2 DC tables and 2 AC tables in baseline process
};

class JpegHuff {
public:
    static bool Parse(uint8_t* jpg, size_t jpgLen, HuffTables& tables)
    {
        auto jpgSource = UserBufferSourceStream::Create(jpg, jpgLen);
        REQUIRE(jpgSource && jpgSource->Seek(2));  // skip SOI
        StreamBuffer buf;
        for (bool meetSOS = false; meetSOS == false;) {
            REQUIRE(jpgSource->Read(4, buf) && buf.dataHead && buf.dataSize == 4);
            REQUIRE(buf.dataHead[0] == FFCode);
            if (buf.dataHead[1] == JPEG_MARKER_DHT) {
                REQUIRE(jpgSource->Read(1 + MAX_HUFFCODE_LENGTH, buf) && buf.dataHead &&
                    buf.dataSize == 1 + MAX_HUFFCODE_LENGTH);
                TableClass tc = static_cast<TableClass>(buf.dataHead[0] >> 4);
                TableComponent th = static_cast<TableComponent>(buf.dataHead[0] & 0x0f);
                REQUIRE((tc == TableClass::DC_TABLE || tc == TableClass::AC_TABLE) &&
                        (th == TableComponent::LUMA || th == TableComponent::CHROMA));
                HuffTable& table = tables.GetTable(tc, th);
                table.tc = tc;
                table.th = th;
                auto BITS = buf.dataHead + 1;
                table.numCodes = 0;
                for (uint32_t i = 0; i < MAX_HUFFCODE_LENGTH; i++) {
                    table.numCodes += BITS[i];
                }
                if (tc == TableClass::DC_TABLE) {
                    REQUIRE(table.numCodes <= MAX_NUM_DC_HUFFCODE);
                } else if (tc == TableClass::AC_TABLE) {
                    REQUIRE(table.numCodes <= MAX_NUM_AC_HUFFCODE);
                }
                REQUIRE(jpgSource->Read(table.numCodes, buf) && buf.dataHead &&
                    buf.dataSize == table.numCodes);
                auto HUFFVAL = buf.dataHead;
                Build(table, BITS, HUFFVAL);
                BuildLUT(table);
            } else if (buf.dataHead[1] == MARK_SOS) {
                meetSOS = true;
            } else {
                uint16_t length = (static_cast<uint16_t>(buf.dataHead[2]) << 8 | buf.dataHead[3]) - NUM_2;
                REQUIRE(jpgSource->Seek(jpgSource->Tell() + length));
            }
        }
        return true;
    }

private:
    static void Build(HuffTable& table, const uint8_t* BITS, const uint8_t* HUFFVAL)
    {
        uint32_t CODE = 0;
        uint32_t codeIdx = 0;
        for (uint32_t i = 1; i <= MAX_HUFFCODE_LENGTH; i++) {
            for (uint32_t j = 0; j < BITS[i - 1]; j++) {
                table.HUFFSIZE[codeIdx] = i;
                table.HUFFCODE[codeIdx++] = CODE++;
            }
            CODE <<= 1;
        }
        for (uint32_t i = 0; i < table.numCodes; i++) {
            table.HUFFVAL[i] = HUFFVAL[i];
        }
        for (uint32_t i = 1, j = 0; i <= MAX_HUFFCODE_LENGTH; i++) {
            if (BITS[i - 1]) {
                table.VALPTR[i] = j;
                table.MINCODE[i] = static_cast<int32_t>(table.HUFFCODE[j]);
                j += BITS[i - 1] - 1;
                table.MAXCODE[i] = static_cast<int32_t>(table.HUFFCODE[j++]);
            }
        }
    }

    static void BuildLUT(HuffTable& table)
    {
        for (uint32_t i = 0; i < table.numCodes; i++) {
            auto code = table.HUFFCODE[i];
            auto size = table.HUFFSIZE[i];
            if (size > HUFF_LOOKHEAD) {
                break;
            }
            uint32_t start = (code & ((1U << size) - 1)) << (HUFF_LOOKHEAD - size);
            uint32_t end = start | ((1U << (HUFF_LOOKHEAD - size)) - 1);
            for (uint32_t j = start; j <= end; j++) {
                table.HUFFLUT_DEC[j].size = size;
                table.HUFFLUT_DEC[j].value = table.HUFFVAL[i];
            }
        }
        if (table.tc != TableClass::DC_TABLE) {
            return;
        }
        for (uint8_t category = 0; category < MAX_DC_CATEGORY; category++) {
            for (uint32_t i = 0; i < table.numCodes; i++) {
                if (table.HUFFVAL[i] == category) {
                    table.HUFFLUT_ENC_DC[category].bits = table.HUFFCODE[i];
                    table.HUFFLUT_ENC_DC[category].n = table.HUFFSIZE[i];
                }
            }
        }
    }
};

namespace {
constexpr uint32_t NUM_AC_COEFF = 63;
constexpr uint32_t NUM_DATAUNIT = 6;
}

// do not call it with 0 !!!
static inline uint32_t CLZ(uint32_t a)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_clz(a);
#else
    uint32_t count = 0;
    uint32_t mask = 1 << 31;
    while ((a & mask) == 0) {
        count++;
        mask >>= 1;
    }
    return count;
#endif
}

struct DataUnit {
    struct Code {
        uint32_t bits = 0;
        uint32_t n = 0;
    };
    Code dc_code;
    int32_t dc_value = 0;
    int32_t pre_du_dc_value = 0;
    Code ac[NUM_AC_COEFF];
    uint32_t ac_num = 0;

    uint32_t comp;  // comp: Y = 0, Cb = 1, Cr = 2
    uint32_t idx;

    bool EncodeDC(HuffTable& table)
    {
        int32_t diff = dc_value - pre_du_dc_value;
        uint8_t category = diff ? static_cast<uint32_t>(32 - CLZ(std::abs(diff))) : 0;
        REQUIRE_LOG(category < MAX_DC_CATEGORY, "diff out of category range, category(%{public}u)", category);
        dc_code.bits = table.HUFFLUT_ENC_DC[category].bits;
        dc_code.n = table.HUFFLUT_ENC_DC[category].n;

        if (category == 0) {
            return true;
        } else {
            uint32_t addlBits = diff > 0 ?  static_cast<uint32_t>(diff) : static_cast<uint32_t>(diff) - 1;
            uint32_t mask = (1U << category) - 1;
            dc_code.bits = (dc_code.bits << category) | (addlBits & mask);
            dc_code.n += category;
            return true;
        }
    }
};

struct MCU {
    DataUnit dus[NUM_DATAUNIT];

    MCU()
    {
        dus[NUM_0].comp = NUM_0;
        dus[NUM_1].comp = NUM_0;
        dus[NUM_2].comp = NUM_0;
        dus[NUM_3].comp = NUM_0;
        dus[NUM_4].comp = NUM_1;
        dus[NUM_5].comp = NUM_2;

        dus[NUM_0].idx = NUM_0;
        dus[NUM_1].idx = NUM_1;
        dus[NUM_2].idx = NUM_2;
        dus[NUM_3].idx = NUM_3;
        dus[NUM_4].idx = NUM_0;
        dus[NUM_5].idx = NUM_0;
    }

    bool BeIndependent(MCU& other, HuffTables& tables)
    {
        other = *this;
        for (uint32_t comp = 0; comp < NUM_3; comp++) {
            HuffTable& table = comp ? tables.GetTable(TableClass::DC_TABLE, TableComponent::CHROMA) :
                                      tables.GetTable(TableClass::DC_TABLE, TableComponent::LUMA);
            DataUnit& du = other.GetFirstDU(comp);
            du.pre_du_dc_value = 0;
            REQUIRE(du.EncodeDC(table));
        }
        return true;
    }
    bool BeDependent(MCU& other, HuffTables& tables)
    {
        other = *this;
        for (uint32_t comp = 0; comp < NUM_3; comp++) {
            HuffTable& table = comp ? tables.GetTable(TableClass::DC_TABLE, TableComponent::CHROMA) :
                                      tables.GetTable(TableClass::DC_TABLE, TableComponent::LUMA);
            DataUnit& du = other.GetFirstDU(comp);
            REQUIRE(du.EncodeDC(table));
        }
        return true;
    }
protected:
    DataUnit& GetFirstDU(uint32_t comp)
    {
        if (comp == 0) {
            return dus[0];
        } else if (comp == 1) {
            return dus[NUM_4];
        } else {
            return dus[NUM_5];
        }
    }
};

#define PEEK_N_BITS(n) \
    (((fifo) >> ((numHeldBits) - (n))) & ((1U << (n)) - 1))

#define DROP_N_BITS(n) \
    (numHeldBits -= (n))

#define READ_N_BITS(n) \
    ((fifo >> ((numHeldBits) -= (n))) & ((1U << (n)) - 1))

#define CHECK_FIFO(n)            \
    do {                         \
        if (numHeldBits < (n)) { \
            FILL_FIFO();         \
        }                        \
    } while (0)

#ifdef UNLIKELY
#   undef UNLIKELY
#endif

#if defined(__GNUC__) || defined(__clang__)
#   define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#   define UNLIKELY(x) (x)
#endif

#define FILL_FIFO()                                                           \
    do {                                                                      \
        numHeldBytes = (numHeldBits + 7) / 8;                                 \
        shiftBytes = 4 - numHeldBytes;                                        \
        fifo = static_cast<uint64_t>(fifo) << (8 * shiftBytes);               \
        numHeldBits += 8 * shiftBytes;                                        \
        REQUIRE_LOG(pos + shiftBytes <= jpgLen, "no more bits to read");      \
        for (int32_t i = static_cast<int32_t>(shiftBytes - 1); i >= 0; i--) { \
            readByte = jpg[pos++];                                            \
            if (UNLIKELY(readByte == 0xff && jpg[pos] == 0x00)) {             \
                ++pos;                                                        \
            }                                                                 \
            fifo |= (static_cast<uint32_t>(readByte)) << (i * 8);             \
        }                                                                     \
    } while (0)

#define HUFF_DECODE(htbl, code, value_)                                          \
    do {                                                                         \
        CHECK_FIFO(HUFF_LOOKHEAD);                                               \
        look = PEEK_N_BITS(HUFF_LOOKHEAD);                                       \
        if ((readSize = (htbl)->HUFFLUT_DEC[look].size) < (HUFF_LOOKHEAD + 1)) { \
            DROP_N_BITS(readSize);                                               \
            code = look >> (HUFF_LOOKHEAD - readSize);                           \
            value_ = (htbl)->HUFFLUT_DEC[look].value;                            \
        } else {                                                                 \
            HUFF_DECODE_SLOW(htbl, code, value_);                                \
        }                                                                        \
    } while (0)

#define HUFF_DECODE_SLOW(htbl, code, value_)                                                \
    do {                                                                                    \
        CHECK_FIFO(MAX_HUFFCODE_LENGTH);                                                    \
        for (tmpReadSize = 9; tmpReadSize <= MAX_HUFFCODE_LENGTH; tmpReadSize++) {          \
            look = PEEK_N_BITS(tmpReadSize);                                                \
            if (static_cast<int32_t>(look) <= (htbl)->MAXCODE[tmpReadSize]) {               \
                DROP_N_BITS(readSize = tmpReadSize);                                        \
                code = look;                                                                \
                value_ = (htbl)->HUFFVAL[(htbl)->VALPTR[tmpReadSize] + look -               \
                                    static_cast<uint32_t>((htbl)->MINCODE[tmpReadSize])];   \
                break;                                                                      \
            }                                                                               \
        }                                                                                   \
    } while (0)

struct Bitstream {
    uint8_t* jpg;
    size_t jpgLen;
    size_t pos;
    uint32_t fifo;
    uint32_t numHeldBits;

    Bitstream()
        : jpg(nullptr), jpgLen(0), pos(0), fifo(0), numHeldBits(0) {}
    Bitstream(uint8_t* jpg_, size_t jpgLen_)
        : jpg(jpg_), jpgLen(jpgLen_), pos(0), fifo(0), numHeldBits(0) {}
};

class IECS : public Bitstream {
    uint32_t rst = 0;
    uint32_t mcuCnt = 0;
    int32_t preDUDC[3] = {0};
    HuffTable* dcHtbl[3] = {nullptr};
    HuffTable* acHtbl[3] = {nullptr};

    // for bitstream use
    uint32_t numHeldBytes = 0;
    uint32_t shiftBytes = 0;
    uint32_t readByte = 0;

    // for huffdec use
    uint32_t look = 0;
    uint32_t readSize = 0;
    uint32_t tmpReadSize = 0;
    uint32_t SSSSCode = 0;
    uint32_t SSSSValue = 0;
    uint32_t RRRRSSSSCode = 0;
    uint32_t RRRRSSSSValue = 0;
    uint32_t RRRRValue = 0;
    uint32_t addlBits = 0;
    uint32_t acCnt = 0;

public:
    // A bitstream slightly larger than the JPEG stream is required here to facilitate the decoding process!
    IECS() {}
    IECS(uint8_t* jpg_, size_t jpgLen_, HuffTables& tables)
        : Bitstream(jpg_, jpgLen_)
    {
        dcHtbl[NUM_0] = &tables.GetTable(TableClass::DC_TABLE, TableComponent::LUMA);
        dcHtbl[NUM_1] = &tables.GetTable(TableClass::DC_TABLE, TableComponent::CHROMA);
        dcHtbl[NUM_2] = &tables.GetTable(TableClass::DC_TABLE, TableComponent::CHROMA);
        acHtbl[NUM_0] = &tables.GetTable(TableClass::AC_TABLE, TableComponent::LUMA);
        acHtbl[NUM_1] = &tables.GetTable(TableClass::AC_TABLE, TableComponent::CHROMA);
        acHtbl[NUM_2] = &tables.GetTable(TableClass::AC_TABLE, TableComponent::CHROMA);
    }

    void RePos(size_t pos_, uint16_t rst_)
    {
        pos = pos_;
        fifo = 0;
        numHeldBits = 0;
        rst = rst_;
        mcuCnt = 0;
    }

    bool DecodeMCU(MCU& mcu)
    {
        for (uint32_t blkIdx = 0; blkIdx < NUM_DATAUNIT; blkIdx++) {
            DataUnit& du = mcu.dus[blkIdx];
            // DC
            HUFF_DECODE(dcHtbl[du.comp], SSSSCode, SSSSValue);
            REQUIRE_LOG(tmpReadSize <= MAX_HUFFCODE_LENGTH, "DC Decoding error");
            CHECK_FIFO(SSSSValue);
            addlBits = READ_N_BITS(SSSSValue);
            du.pre_du_dc_value = preDUDC[du.comp];
            int32_t pred_dc_value = (mcuCnt || du.idx) ? du.pre_du_dc_value : 0;
            du.dc_value = EXTEND(addlBits, SSSSValue) + pred_dc_value;
            preDUDC[du.comp] = du.dc_value;

            du.dc_code.n = readSize + SSSSValue;
            du.dc_code.bits = (SSSSCode << SSSSValue) | addlBits;

            // AC
            du.ac_num = 0;
            acCnt = 0;
            while (acCnt < NUM_AC_COEFF) {
                HUFF_DECODE(acHtbl[du.comp], RRRRSSSSCode, RRRRSSSSValue);
                REQUIRE_LOG(tmpReadSize <= MAX_HUFFCODE_LENGTH, "AC Decoding error");
                RRRRValue = RRRRSSSSValue >> NUM_4;
                SSSSValue = RRRRSSSSValue & 0x0f;
                acCnt = RRRRSSSSValue ? acCnt + RRRRValue + 1 : NUM_AC_COEFF;
                CHECK_FIFO(SSSSValue);
                addlBits = READ_N_BITS(SSSSValue);
                du.ac[du.ac_num].bits = (RRRRSSSSCode << SSSSValue) | addlBits;
                du.ac[du.ac_num++].n = readSize + SSSSValue;
            }
            REQUIRE_LOG(acCnt == NUM_AC_COEFF, "AC Parsing Failed");
        }
        if (++mcuCnt == rst) {
            REQUIRE_LOG(SeekToNextRst(), "SeekToNextRst error");
            mcuCnt = 0;
        }
        return true;
    }

    bool SeekToNextRst()
    {
        DROP_N_BITS(numHeldBits & 7);
        CHECK_FIFO(NUM_2 * NUM_8);
        uint16_t twoBytes = PEEK_N_BITS(NUM_2 * NUM_8);
        REQUIRE_LOG((twoBytes & 0xfff8u) == 0xffd0 || twoBytes == 0xffd9,
            "two bytes(0x%{public}02X%{public}02X) to be discarded are not RST or EOI", twoBytes >> 8, twoBytes & 0x0f);
        DROP_N_BITS(NUM_2 * NUM_8);
        return true;
    }

    std::optional<DataUnit::Code> FindCode(HuffTable& htbl, uint32_t value)
    {
        for (uint32_t i = 0; i < htbl.numCodes; i++) {
            if (htbl.HUFFVAL[i] == value) {
                return DataUnit::Code {
                    .bits = htbl.HUFFCODE[i],
                    .n = htbl.HUFFSIZE[i]
                };
            }
        }
        return std::nullopt;
    }

    std::optional<MCU> GenerateDummyMCU()
    {
        MCU mcu;
        for (uint32_t blkIdx = 0; blkIdx < NUM_6; blkIdx++) {
            auto& du = mcu.dus[blkIdx];
            auto code = FindCode(*dcHtbl[du.comp], 0);
            if (!code) {
                return std::nullopt;
            }
            du.dc_code = *code;
            code = FindCode(*acHtbl[du.comp], 0);
            if (!code) {
                return std::nullopt;
            }
            du.ac_num = 1;
            du.ac[0] = *code;
        }
        return mcu;
    }

private:
    int32_t EXTEND(uint32_t V, uint32_t T)
    {
        uint32_t Vt = 1 << T;
        if (V < (Vt >> 1)) {
            return static_cast<int32_t>(V) - static_cast<int32_t>(Vt) + 1;
        } else {
            return static_cast<int32_t>(V);
        }
    }
};

#define WRITE_BYTE(byte)                \
    do {                                \
        jpg[pos++] = byte;              \
        if (UNLIKELY((byte) == 0xff)) { \
            jpg[pos++] = 0x00;          \
        }                               \
    } while (0)

#define WRITE_BYTE_NOSTUFFING(byte)     \
    do {                                \
        REQUIRE(pos < jpgLen);          \
        jpg[pos++] = byte;              \
    } while (0)

#define FLUSH_FIFO()                                                                                      \
    do {                                                                                                  \
        REQUIRE_LOG((numHeldBits % 8) == 0 && (numHeldBits / 8) + pos < jpgLen, "no more bits to write"); \
        for (uint32_t i = 0; i < numHeldBits; i += 8) {                                                   \
            WRITE_BYTE(static_cast<uint8_t>((fifo >> (24 - i)) & 0xff));                                  \
        }                                                                                                 \
    } while (0)

#define WRITE_N_BITS(bits, n)                                             \
    do {                                                                  \
        tmpNumHeldBits = numHeldBits + (n);                               \
        if (tmpNumHeldBits < 32) {                                        \
            fifo |= (bits) << (32 - tmpNumHeldBits);                      \
            numHeldBits = tmpNumHeldBits;                                 \
        } else {                                                          \
            uint32_t nextNumHeldBits = tmpNumHeldBits % 32;               \
            fifo |= ((bits) >> nextNumHeldBits);                          \
            numHeldBits = 32;                                             \
            FLUSH_FIFO();                                                 \
            fifo = static_cast<uint64_t>(bits) << (32 - nextNumHeldBits); \
            numHeldBits = nextNumHeldBits;                                \
        }                                                                 \
    } while (0)

#define WRITE_ALIGN_ONES()                         \
    do {                                           \
        uint8_t numOnes = (32 - numHeldBits) % 8;  \
        WRITE_N_BITS((1 << numOnes) - 1, numOnes); \
        FLUSH_FIFO();                              \
        fifo = 0;                                  \
        numHeldBits = 0;                           \
    } while (0)

class OECS : public Bitstream {
    // for bitstream use
    uint32_t tmpNumHeldBits = 0;

public:
    OECS(uint8_t* jpg_, size_t jpgLen_)
        : Bitstream(jpg_, jpgLen_), tmpNumHeldBits(0) {}

    void RePos(size_t pos_)
    {
        pos = pos_;
        fifo = 0;
        numHeldBits = 0;
        tmpNumHeldBits = 0;
    }

    bool WriteMCU(const MCU& mcu)
    {
        for (uint32_t blkIdx = 0; blkIdx < NUM_DATAUNIT; blkIdx++) {
            auto& du = mcu.dus[blkIdx];
            WRITE_N_BITS(du.dc_code.bits, du.dc_code.n);
            for (uint32_t i = 0; i < du.ac_num; i++) {
                WRITE_N_BITS(du.ac[i].bits, du.ac[i].n);
            }
        }
        return true;
    }

    bool WriteRST(uint8_t byte)
    {
        WRITE_ALIGN_ONES();
        WRITE_BYTE_NOSTUFFING(FFCode);
        WRITE_BYTE_NOSTUFFING(byte);
        return true;
    }

    size_t Tell()
    {
        return pos;
    }

    bool WriteNBits(uint32_t bits, uint32_t n)
    {
        WRITE_N_BITS(bits, n);
        return true;
    }
};

SUBJPEG_DATA::~SUBJPEG_DATA()
{
    if (ctx.pixelsBuffer.buffer) {
        const_cast<ExtDecoder*>(extDecoder)->ReleaseOutputBuffer(ctx, ctx.allocatorType);
    }
}

bool RSTBasedDecoder::IsSupport(DecodeContext& dctx, const ExtDecoder* extDecoder)
{
#if defined(JPEG_HW_DECODE_ENABLE) && !defined(CROSS_PLATFORM)
    SkCodec* codec = extDecoder->codec_.get();
    REQUIRE_LOG(codec, "extDecoder->codec_ is nullptr");
    REQUIRE_LOG((SkEncodedImageFormat)codec->getEncodedFormat() == SkEncodedImageFormat::kJPEG, "source is not jpg");
    auto dinfo = static_cast<SkJpegCodec*>(codec)->decoderMgr()->dinfo();
    REQUIRE_LOG(dinfo, "dinfo is nullptr");
    REQUIRE_LOG(dctx.allocatorType == Media::AllocatorType::DMA_ALLOC, "not DMA memory mode");
    REQUIRE_LOG(dctx.ifSourceCompleted, "source data incomplete");
    REQUIRE_LOG(dinfo->restart_interval >= MIN_NUM_MCU_IN_RST && dinfo->restart_interval <= MAX_NUM_MCU_IN_RST,
        "rst value not support");
    auto image_width = dinfo->image_width;
    auto image_height = dinfo->image_height;
    REQUIRE_LOG(CheckResolution(image_width, image_height),
        "not support image w&h(%{public}d, %{public}d)", image_width, image_height);
    // roughly determine if it is baseline mode based on some features
    REQUIRE_LOG(dinfo->data_precision == static_cast<int32_t>(NUM_8) && dinfo->progressive_mode == false &&
        dinfo->arith_code == false, "precision(%{public}d), progressive(%{public}d) or arith(%{public}d) not support",
        dinfo->data_precision, dinfo->progressive_mode, dinfo->arith_code);
    uint32_t dcTablesCount = 0;
    uint32_t acTablesCount = 0;
    for (uint32_t i = 0; i < MAX_NUM_HUFF_TBLS; i++) {
        if (dinfo->dc_huff_tbl_ptrs[i] != NULL) {
            ++dcTablesCount;
        }
        if (dinfo->ac_huff_tbl_ptrs[i] != NULL) {
            ++acTablesCount;
        }
    }
    REQUIRE_LOG(dcTablesCount <= NUM_2 && acTablesCount <= NUM_2, "not baseline");
    REQUIRE_LOG(dinfo->max_h_samp_factor == MAX_H_SAMP_FACTOR &&
        dinfo->max_v_samp_factor == MAX_V_SAMP_FACTOR, "not 420 jpg");
    REQUIRE_LOG(dinfo->num_components == static_cast<int32_t>(NUM_3) &&
        dinfo->comps_in_scan == static_cast<int32_t>(NUM_3), "non-interleaved format jpeg not support");
    jpg.extDecoder = extDecoder;
    jpg.dinfo = dinfo;
    jpg.ctx = &dctx;
    subJpg.extDecoder = extDecoder;
    return true;
#else
    return false;
#endif
}

bool RSTBasedDecoder::Init()
{
    jpg.streamSize = jpg.extDecoder->stream_->GetStreamSize();
    REQUIRE_LOG(jpg.streamSize > 0 && jpg.streamSize <= UINT32_MAX, "copy jpg failed");
    // alloc a stream slightly larger than the JPEG stream to facilitate the bitstream decoding process
    REQUIRE_LOG(jpg.streamData = std::make_unique<uint8_t[]>(jpg.streamSize + NUM_END_EXTRA_BYTES),
                "create jpg failed, make_unique error");
    auto tempPos = jpg.extDecoder->stream_->Tell();
    REQUIRE_LOG(jpg.extDecoder->stream_->Seek(0), "BufferSourceStream seek failed");
    uint32_t actualReadSize = 0;
    bool res = jpg.extDecoder->stream_->Peek(jpg.streamSize, jpg.streamData.get(), jpg.streamSize, actualReadSize);
    REQUIRE_LOG(jpg.extDecoder->stream_->Seek(tempPos), "BufferSourceStream seek failed");
    REQUIRE_LOG(res && actualReadSize == jpg.streamSize, "BufferSourceStream copy failed");

    // precisely determine if it is baseline mode
    REQUIRE(IsBaselineDCT());
    jpg.imageWidthPad16 = ALIGN_UP(jpg.dinfo->image_width, MCU_WIDTH);
    jpg.imageHeightPad16 = ALIGN_UP(jpg.dinfo->image_height, MCU_HEIGHT);
    REQUIRE_LOG(hwDecoder = std::make_unique<JpegHardwareDecoder>(), "create JpegHardwareDecoder failed");
    isAligned = ((jpg.imageWidthPad16 / MCU_WIDTH) % jpg.dinfo->restart_interval) == 0;

    REQUIRE(ParseRSTs());
    if (!isAligned) {
        jpg.tables = std::make_shared<HuffTables>();
        REQUIRE(ParseDHTs());
    }
    return true;
}

bool RSTBasedDecoder::CheckResolution(uint32_t image_width, uint32_t image_height)
{
    constexpr int32_t maxLength = 32 * 1024;
    constexpr int32_t minLength = 10 * 1024;

    auto side = image_width > image_height ? image_width : image_height;
    REQUIRE(side > minLength && side <= maxLength);

    auto hwDecoder = std::make_unique<JpegHardwareDecoder>();
    REQUIRE_LOG(hwDecoder, "create JpegHardwareDecoder failed");
    REQUIRE_LOG(hwDecoder->IsHardwareDecodeSupported(IMAGE_JPEG_FORMAT,
                    {NUM_8k, NUM_8k}),
                "the jpeg hardware decoder doesn't support 8192x8192");

    constexpr int32_t maxLengthJ = 15 * 1000;
    REQUIRE_LOG(hwDecoder->IsHardwareDecodeSupported(IMAGE_JPEG_FORMAT,
                    {maxLengthJ, static_cast<uint64_t>(NUM_8k) * NUM_8k / maxLengthJ}),
                "the jpeg hardware decoder doesn't support 15000x4473");

    REQUIRE_LOG(hwDecoder->IsHardwareDecodeSupported(IMAGE_JPEG_FORMAT,
                    {static_cast<uint64_t>(NUM_8k) * NUM_8k / maxLengthJ, maxLengthJ}),
                "the jpeg hardware decoder doesn't support 4473x15000");
    return true;
}

bool RSTBasedDecoder::IsBaselineDCT()
{
    auto jSrc = UserBufferSourceStream::Create(jpg.streamData.get(), jpg.streamSize);
    REQUIRE_LOG(jSrc && jSrc->Seek(NUM_2), "create UserBufferSourceStream failed or seek failed");
    StreamBuffer buf {};
    StreamBuffer tmpBuf {};
    bool isBaselineDCT = false;
    bool meetSOS = false;
    while (!meetSOS) {
        REQUIRE_LOG(jSrc->Read(NUM_4, buf) && buf.dataHead && buf.dataSize == NUM_4, "read failed");
        REQUIRE_LOG(buf.dataHead[0] == FFCode, "not 0xFF");
        if (buf.dataHead[1] == JPEG_MARKER_DRI) {
            REQUIRE_LOG(jSrc->Peek(NUM_2, tmpBuf) && tmpBuf.dataHead && tmpBuf.dataSize == NUM_2, "DRI error");
            jpg.RiPos = jSrc->Tell();
        } else if (buf.dataHead[1] == MARK_SOF0) {
            isBaselineDCT = true;
            REQUIRE_LOG(jSrc->Peek(NUM_5, tmpBuf) && tmpBuf.dataHead && tmpBuf.dataSize == NUM_5, "SOF error");
            jpg.YPos = jSrc->Tell() + NUM_1;
        } else if (buf.dataHead[1] == MARK_SOS) {
            meetSOS = true;
        } else if (buf.dataHead[1] == FFCode) {
            IMAGE_LOGD("do not yet support handling streams with marker with many 0xFF");
            return false;
        } else {}
        uint16_t length = (static_cast<uint16_t>(buf.dataHead[2]) << NUM_8 | buf.dataHead[3]) - NUM_2;
        REQUIRE_LOG(jSrc->Seek(jSrc->Tell() + length), "skip segment failed");
    }
    jpg.ECSStartPos = jSrc->Tell();
    return isBaselineDCT;
}

bool RSTBasedDecoder::ParseRSTs()
{
    std::vector<size_t> rstPositions;
    size_t numRST = DIV_ROUND_UP(jpg.imageWidthPad16 * jpg.imageHeightPad16,
                                 MCU_WIDTH * MCU_HEIGHT * jpg.dinfo->restart_interval);
    rstPositions.reserve(numRST + 1);  // rstPositions[-1] is the position of 0xff 0xd9
    rstPositions.push_back(jpg.ECSStartPos);
    uint32_t rstCnt = 0;
    bool meetEOI = false;
    uint8_t* streamData = jpg.streamData.get();
    for (size_t i = jpg.ECSStartPos; i < jpg.streamSize && meetEOI == false; i += NUM_8) {
        // Since extra bytes are allocated, it is guaranteed that 8 bytes can be fetched
        // at the end of the stream without any out-of-bounds access.
        uint64_t dt = *reinterpret_cast<const uint64_t*>(streamData + i);
        if (!((~dt - 0x0101010101010101ULL) & dt & 0x8080808080808080ULL)) {
            continue;
        }
        for (uint8_t j = 0; j < NUM_8; j++) {
            if (streamData[i + j] != 0xff) {
                continue;
            }
            // Since extra bytes are allocated, it is guaranteed that additional one byte can be fetched
            uint8_t nextByte = streamData[i + j + 1];
            if (nextByte == 0x00) {
                continue;
            } else if (nextByte == RSTs[rstCnt]) {
                rstPositions.push_back(i + j + NUM_2);
                rstCnt = (rstCnt + 1) % NUM_8;
            } else if (UNLIKELY(nextByte == MARK_EOI)) {
                meetEOI = true;
                rstPositions.push_back(i + j + NUM_2);
                break;
            } else {
                REQUIRE_LOG(false, "the jpeg stream is corrupt");
            }
        }
    }
    REQUIRE_LOG(meetEOI && rstPositions.size() == numRST + 1, "Invalid RST bitstream");
    jpg.rstPositions = std::move(rstPositions);
    return true;
}

bool RSTBasedDecoder::ParseDHTs()
{
    REQUIRE_LOG(JpegHuff::Parse(jpg.streamData.get(), jpg.streamSize, *jpg.tables), "Parsing DHT failed");
    HuffTable* table = &jpg.tables->GetTable(TableClass::DC_TABLE, TableComponent::LUMA);
    REQUIRE_LOG(table->numCodes > 0 && table->numCodes <= MAX_NUM_DC_HUFFCODE,
        "Incorrect number of LUMA DC codewords, num(%{public}d)", table->numCodes);
    table = &jpg.tables->GetTable(TableClass::DC_TABLE, TableComponent::CHROMA);
    REQUIRE_LOG(table->numCodes > 0 && table->numCodes <= MAX_NUM_DC_HUFFCODE,
        "Incorrect number of CHROMA DC codewords, num(%{public}d)", table->numCodes);
    table = &jpg.tables->GetTable(TableClass::AC_TABLE, TableComponent::LUMA);
    REQUIRE_LOG(table->numCodes > 0 && table->numCodes <= MAX_NUM_AC_HUFFCODE,
        "Incorrect number of LUMA AC codewords, num(%{public}d)", table->numCodes);
    table = &jpg.tables->GetTable(TableClass::AC_TABLE, TableComponent::CHROMA);
    REQUIRE_LOG(table->numCodes > 0 && table->numCodes <= MAX_NUM_AC_HUFFCODE,
        "Incorrect number of CHROMA AC codewords, num(%{public}d)", table->numCodes);

    REQUIRE_LOG(jpg.tables->GetTable(TableClass::DC_TABLE, TableComponent::LUMA).numCodes == MAX_NUM_DC_HUFFCODE &&
        jpg.tables->GetTable(TableClass::DC_TABLE, TableComponent::CHROMA).numCodes == MAX_NUM_DC_HUFFCODE,
        "A complete DC Huffman table is required due to the algorithmic requirements. LUMA DC(%{public}u entries) "
        "CHROMA DC(%{public}u entries)", jpg.tables->GetTable(TableClass::DC_TABLE, TableComponent::LUMA).numCodes,
        jpg.tables->GetTable(TableClass::DC_TABLE, TableComponent::CHROMA).numCodes);
    return true;
}

bool RSTBasedDecoder::DoHardWareDecode()
{
    auto subJpgStream = BufferSourceStream::CreateSourceStream(subJpg.streamData, subJpg.streamSize, true);
    REQUIRE_LOG(subJpgStream, "create subJpgStream failed");
#ifdef USE_M133_SKIA
    auto subJpgCodec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(subJpgStream.get()),
        nullptr, nullptr, SkCodec::SelectionPolicy::kPreferAnimation);
#else
    auto subJpgCodec = SkCodec::MakeFromStream(std::make_unique<ExtStream>(subJpgStream.get()));
#endif
    REQUIRE_LOG(subJpgCodec, "subJpgCodec MakeFromStream failed");
    OHOS::HDI::Codec::Image::V2_1::CodecImageBuffer outputBuffer;
    BufferHandle *handle = (static_cast<SurfaceBuffer*>(subJpg.ctx.pixelsBuffer.context))->GetBufferHandle();
    outputBuffer.buffer = new NativeBuffer(handle);
    outputBuffer.fenceFd = -1;
    uint32_t res = hwDecoder->Decode(subJpgCodec.get(), subJpgStream.get(),
        {subJpg.origSize.width(), subJpg.origSize.height()}, subJpg.sampleSize, outputBuffer);
    REQUIRE_LOG(res == SUCCESS, "subJpg hardware decode failed, err=%{public}d", res);
    return true;
}

inline uint32_t RSTBasedDecoder::GetScaledValue(uint32_t val, PixelFormat fmt)
{
    if (fmt == PixelFormat::NV21) {
        return (val / subJpg.sampleSize) / NUM_2 * NUM_2;
    } else {
        return val / subJpg.sampleSize;
    }
}

inline SkIPoint RSTBasedDecoder::MapToScaledPoint(int32_t x, int32_t y, PixelFormat fmt)
{
    return SkIPoint::Make(GetScaledValue(x, fmt), GetScaledValue(y, fmt));
}

inline SkISize RSTBasedDecoder::MapToScaledSize(int32_t origWidth, int32_t origHeight, PixelFormat fmt)
{
    return SkISize::Make(GetScaledValue(origWidth, fmt), GetScaledValue(origHeight, fmt));
}

bool JpegHwRegionDecoder::IsSupport(DecodeContext& dctx, const ExtDecoder* extDecoder)
{
    REQUIRE(RSTBasedDecoder::IsSupport(dctx, extDecoder));
    auto& dinfo = jpg.dinfo;
    REQUIRE_LOG(extDecoder->cropAndScaleStrategy_ == OHOS::Media::CropAndScaleStrategy::CROP_FIRST,
        "not CROP_FIRST strategy");
    REQUIRE_LOG(dctx.info.pixelFormat == PixelFormat::RGBA_8888,
        "JpegHwRegionDecoder only support RGBA8888");

    auto hwDecoder = std::make_unique<JpegHardwareDecoder>();
    REQUIRE_LOG(hwDecoder, "create JpegHardwareDecoder failed");
    int32_t extensionWidthLength = ((jpg.imageWidthPad16 / MCU_WIDTH) % jpg.dinfo->restart_interval) == 0 ?
        static_cast<int32_t>(jpg.dinfo->restart_interval * MCU_WIDTH) : static_cast<int32_t>(MCU_WIDTH);
    int32_t minProbSubJpegWidth = ALIGN_UP(extDecoder->dstSubset_.width(), extensionWidthLength);
    int32_t minProbSubJpegHeight = ALIGN_UP(extDecoder->dstSubset_.height(), static_cast<int32_t>(MCU_HEIGHT));
    REQUIRE_LOG(hwDecoder->IsHardwareDecodeSupported(IMAGE_JPEG_FORMAT,
                    {minProbSubJpegWidth, minProbSubJpegHeight}),
                "subJpg min prob resolution not support");
    int32_t maxProbSubJpegWidth = minProbSubJpegWidth + extensionWidthLength;
    int32_t maxProbSubJpegHeight = minProbSubJpegHeight + static_cast<int32_t>(MCU_HEIGHT);
    REQUIRE_LOG(hwDecoder->IsHardwareDecodeSupported(IMAGE_JPEG_FORMAT,
                    {maxProbSubJpegWidth, maxProbSubJpegHeight}),
                "subJpg max prob resolution not support");
    REQUIRE_LOG(static_cast<uint32_t>(maxProbSubJpegWidth * maxProbSubJpegHeight) <=
        MAX_SUPPORT_IMAGE_AREA, "subJpg max prob area too large");
    return true;
}

bool JpegHwRegionDecoder::DoTileDecode()
{
    SkIRect decodeSubset = jpg.extDecoder->dstSubset_;
    ImageFuncTimer imageFuncTimer("%s, decodeSubset: left:%d, top:%d, width:%d, height:%d, sampleSize:%d", __func__,
        decodeSubset.left(), decodeSubset.top(), decodeSubset.width(), decodeSubset.height(),
        static_cast<uint32_t>(const_cast<ExtDecoder*>(subJpg.extDecoder)->GetSoftwareScaledSize(
            subJpg.extDecoder->regionDesiredSize_.width, subJpg.extDecoder->regionDesiredSize_.height)));
    bool ret = false;
    if (RSTBasedDecoder::Init() && SplitRegion() && CombineIntoJpeg() && DecodeSubJpg() && CropTarget()) {
        ret = true;
    }
    if (!ret) {
        if (jpg.ctx->pixelsBuffer.buffer) {
            const_cast<ExtDecoder*>(jpg.extDecoder)->ReleaseOutputBuffer(*jpg.ctx, jpg.ctx->allocatorType);
        }
        IMAGE_LOGD("JpegHwRegionDecode failed");
    }
    return ret;
}

bool JpegHwRegionDecoder::SplitRegion()
{
    subJpg.sampleSize = static_cast<uint32_t>(const_cast<ExtDecoder*>(subJpg.extDecoder)->GetSoftwareScaledSize(
        subJpg.extDecoder->regionDesiredSize_.width, subJpg.extDecoder->regionDesiredSize_.height));
    auto& cropRegion = jpg.extDecoder->dstSubset_;
    uint32_t rst = static_cast<uint32_t>(jpg.dinfo->restart_interval);
    uint32_t n = isAligned ? rst : 1;
    subJpg.origLT = SkIPoint::Make(ALIGN_DOWN(cropRegion.x(), n * MCU_WIDTH), ALIGN_DOWN(cropRegion.y(), MCU_HEIGHT));
    subJpg.origSize = SkISize::Make(ALIGN_UP(cropRegion.x() + cropRegion.width(), n * MCU_WIDTH) - subJpg.origLT.x(),
                                    ALIGN_UP(cropRegion.y() + cropRegion.height(), MCU_HEIGHT) - subJpg.origLT.y());
    uint16_t numMCULines = static_cast<uint32_t>(subJpg.origSize.height()) / MCU_HEIGHT;
    subJpg.regionDecInfo.entries = vector<RegionDecInfo::MCULineInfo>(numMCULines);
    for (uint16_t i = 0; i < numMCULines; i++) {
        auto& mcuLineInfo = subJpg.regionDecInfo.entries[i];
        uint16_t mcuLineTop = static_cast<uint32_t>(subJpg.origLT.y()) + i * MCU_HEIGHT;
        mcuLineInfo.startRstIdx = (mcuLineTop * jpg.imageWidthPad16 +
                                   static_cast<uint32_t>(subJpg.origLT.x()) * MCU_HEIGHT) /
                                   (MCU_WIDTH * MCU_HEIGHT * rst);
        mcuLineInfo.mcuOffset = ((mcuLineTop * jpg.imageWidthPad16 +
                                   static_cast<uint32_t>(subJpg.origLT.x()) * MCU_HEIGHT) /
                                   (MCU_WIDTH * MCU_HEIGHT)) % rst;
        subJpg.regionDecInfo.maxOffset = subJpg.regionDecInfo.maxOffset < mcuLineInfo.mcuOffset ?
                                    mcuLineInfo.mcuOffset : subJpg.regionDecInfo.maxOffset;
    }
    return true;
}

bool JpegHwRegionDecoder::CombineIntoJpegAligned()
{
    auto& streamData = subJpg.streamData;
    auto& streamSize = subJpg.streamSize;
    streamData = jpg.streamData.get();
    streamSize = jpg.rstPositions[0];
    uint32_t numRST = static_cast<uint32_t>(subJpg.origSize.width()) / (jpg.dinfo->restart_interval * MCU_WIDTH);
    uint8_t rstCounter = 0;
    errno_t err;
    for (auto& mcuLineInfo : subJpg.regionDecInfo.entries) {
        REQUIRE_LOG((mcuLineInfo.startRstIdx + numRST) < jpg.rstPositions.size(), "rstIdx out of bounds");
        for (uint32_t i = 0; i < numRST; i++) {
            size_t intervalStart = jpg.rstPositions[mcuLineInfo.startRstIdx + i];
            size_t intervalEnd = jpg.rstPositions[mcuLineInfo.startRstIdx + i + 1];
            size_t copyLen = intervalEnd - intervalStart - NUM_2;
            err = memmove_s(streamData + streamSize, jpg.streamSize - streamSize,
                            jpg.streamData.get() + intervalStart, copyLen);
            REQUIRE_LOG(err == EOK, "ECS data memmove failed, errno:%{public}d", err);
            streamSize += copyLen;
            err = memmove_s(streamData + streamSize, jpg.streamSize - streamSize, &FFCode, NUM_1);
            REQUIRE_LOG(err == EOK, "FFCode set failed, errno:%{public}d", err);
            ++streamSize;
            err = memmove_s(streamData + streamSize, jpg.streamSize - streamSize, &RSTs[rstCounter], NUM_1);
            REQUIRE_LOG(err == EOK, "RST marker set failed, errno:%{public}d", err);
            ++streamSize;
            rstCounter = (rstCounter + 1) % NUM_8;
        }
    }
    return true;
}

bool JpegHwRegionDecoder::CombineIntoJpegNonAligned()
{
    IECS iecs(jpg.streamData.get(), jpg.streamSize + NUM_8, *jpg.tables);
    constexpr uint32_t protectedDist = 10 * MCU_WIDTH;
    bool isLTInFirstMCULine = static_cast<uint32_t>(jpg.extDecoder->dstSubset_.y()) < MCU_HEIGHT ? true : false;
    bool isCrossBoundary = static_cast<uint32_t>(jpg.dinfo->image_width - jpg.extDecoder->dstSubset_.width()) <
        (jpg.dinfo->restart_interval * MCU_WIDTH + protectedDist) ? true : false;
    std::unique_ptr<uint8_t[]> tempJpgStream = nullptr;
    if (isLTInFirstMCULine && isCrossBoundary) {
        size_t rstIdx = subJpg.regionDecInfo.entries.back().startRstIdx +
            DIV_ROUND_UP(jpg.dinfo->image_width, jpg.dinfo->restart_interval * MCU_WIDTH) + 1;
        size_t tempJpgStreamSize = jpg.rstPositions[rstIdx];
        REQUIRE_LOG(tempJpgStream = std::make_unique<uint8_t[]>(tempJpgStreamSize), "malloc tempJpgStreamSize failed");
        errno_t err = memcpy_s(tempJpgStream.get(), tempJpgStreamSize, jpg.streamData.get(), tempJpgStreamSize);
        REQUIRE_LOG(err == EOK, "memcpy_s tempJpgStreamSize failed");
        iecs = IECS(tempJpgStream.get(), tempJpgStreamSize, *jpg.tables);
    }
    OECS oecs(jpg.streamData.get(), jpg.streamSize);
    oecs.RePos(jpg.rstPositions[0]);
    uint32_t numMCUs = static_cast<uint32_t>(subJpg.origSize.width()) / MCU_WIDTH;
    auto mcus = std::make_unique<MCU[]>(subJpg.regionDecInfo.maxOffset + numMCUs);
    REQUIRE_LOG(mcus, "create mcus failed");
    MCU tempMCU;
    uint8_t rstCounter = 0;
    for (auto& mcuLineInfo : subJpg.regionDecInfo.entries) {
        iecs.RePos(jpg.rstPositions[mcuLineInfo.startRstIdx], jpg.dinfo->restart_interval);
        for (size_t i = 0; i < mcuLineInfo.mcuOffset + numMCUs; i++) {
            REQUIRE(iecs.DecodeMCU(mcus[i]));
        }
        REQUIRE(mcus[mcuLineInfo.mcuOffset].BeIndependent(tempMCU, *jpg.tables));
        REQUIRE(oecs.WriteMCU(tempMCU));
        for (size_t i = mcuLineInfo.mcuOffset + 1; i < mcuLineInfo.mcuOffset + numMCUs; i++) {
            if (i % jpg.dinfo->restart_interval == 0) {
                REQUIRE(mcus[i].BeDependent(tempMCU, *jpg.tables));
                REQUIRE(oecs.WriteMCU(tempMCU));
            } else {
                REQUIRE(oecs.WriteMCU(mcus[i]));
            }
        }
        REQUIRE(oecs.WriteRST(RSTs[rstCounter]));
        rstCounter = (rstCounter + 1) % NUM_8;
    }
    subJpg.streamData = jpg.streamData.get();
    subJpg.streamSize = oecs.Tell();
    return true;
}

bool JpegHwRegionDecoder::CombineIntoJpeg()
{
    if (isAligned) {
        REQUIRE(CombineIntoJpegAligned());
    } else {
        REQUIRE(CombineIntoJpegNonAligned());
    }
    auto& streamData = subJpg.streamData;
    REQUIRE_LOG(subJpg.streamSize, "subJpg len should not be 0");
    streamData[subJpg.streamSize - 1] = MARK_EOI;
    REQUIRE_LOG(subJpg.origSize.width() <= UINT16_MAX && subJpg.origSize.height() <= UINT16_MAX, "subJpg size err");
    streamData[jpg.YPos] = (static_cast<uint32_t>(subJpg.origSize.height()) >> NUM_8) & 0xff;
    streamData[jpg.YPos + NUM_1] = static_cast<uint32_t>(subJpg.origSize.height()) & 0xff;
    streamData[jpg.YPos + NUM_2] = (static_cast<uint32_t>(subJpg.origSize.width()) >> NUM_8) & 0xff;
    streamData[jpg.YPos + NUM_3] = static_cast<uint32_t>(subJpg.origSize.width()) & 0xff;
    if (!isAligned) {
        streamData[jpg.RiPos] = ((static_cast<uint32_t>(subJpg.origSize.width()) / MCU_WIDTH) >> NUM_8) & 0xff;
        streamData[jpg.RiPos + 1] = (static_cast<uint32_t>(subJpg.origSize.width()) / MCU_WIDTH) & 0xff;
    }

    ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<char*>(subJpg.streamData), subJpg.streamSize, "subjpeg");
    return true;
}

bool JpegHwRegionDecoder::DecodeSubJpg()
{
    subJpg.ctx = *jpg.ctx;
    auto scaledSizeSubJpg = MapToScaledSize(subJpg.origSize.width(), subJpg.origSize.height(), PixelFormat::RGBA_8888);
    subJpg.ctxSizeInfo = jpg.extDecoder->dstInfo_.makeWH(scaledSizeSubJpg.width(), scaledSizeSubJpg.height());
    uint64_t byteCount = subJpg.ctxSizeInfo.computeMinByteSize();
    REQUIRE_LOG(!SkImageInfo::ByteSizeOverflowed(byteCount), "%{public}s too large region size: %{public}llu",
        __func__, static_cast<unsigned long long>(byteCount));
    uint32_t res = const_cast<ExtDecoder*>(jpg.extDecoder)->DmaMemAlloc(subJpg.ctx, byteCount, subJpg.ctxSizeInfo);
    REQUIRE_LOG(res == SUCCESS, "subjpgCtx DMA buffer alloc failed");

    SkIRect cropRegion = jpg.extDecoder->dstSubset_;
    auto scaledCropSize = MapToScaledSize(cropRegion.width(), cropRegion.height(), PixelFormat::RGBA_8888);
    jpg.ctxSizeInfo = jpg.extDecoder->dstInfo_.makeWH(static_cast<int>(scaledCropSize.width()),
                                                      static_cast<int>(scaledCropSize.height()));
    res = const_cast<ExtDecoder*>(jpg.extDecoder)->DmaMemAlloc(*jpg.ctx, jpg.ctxSizeInfo.computeMinByteSize(),
                                                               jpg.ctxSizeInfo);
    REQUIRE_LOG(res == SUCCESS, "dctx DMA buffer alloc failed");

    REQUIRE_LOG(hwDecoder->InitDecoder(), "failed to init jpeg hardware decoder");

    REQUIRE(DoHardWareDecode());
    return true;
}

bool JpegHwRegionDecoder::CropTarget()
{
    uint8_t* src = static_cast<uint8_t *>(subJpg.ctx.pixelsBuffer.buffer);
    REQUIRE_LOG(src, "src pixel buffer is nullptr");
    SurfaceBuffer* subJpgSbBuffer = reinterpret_cast<SurfaceBuffer*>(subJpg.ctx.pixelsBuffer.context);
    REQUIRE_LOG(subJpgSbBuffer, "sub surface buffer is nullptr");
    uint64_t srcStride = static_cast<uint64_t>(subJpgSbBuffer->GetStride());
    ImageUtils::InvalidateContextSurfaceBuffer(subJpg.ctx);

    uint8_t* dst = static_cast<uint8_t *>(jpg.ctx->pixelsBuffer.buffer);
    REQUIRE_LOG(dst, "dst pixel buffer is nullptr");
    SurfaceBuffer* dstSbBuffer = reinterpret_cast<SurfaceBuffer*>(jpg.ctx->pixelsBuffer.context);
    REQUIRE_LOG(dstSbBuffer, "dst surface buffer is nullptr");
    uint64_t dstStride = static_cast<uint64_t>(dstSbBuffer->GetStride());

    SkIRect cropRegion = jpg.extDecoder->dstSubset_;
    auto scaledPointCropRegion = MapToScaledPoint(cropRegion.x(), cropRegion.y(), PixelFormat::RGBA_8888);
    auto scaledPointSubJpg = MapToScaledPoint(subJpg.origLT.x(), subJpg.origLT.y(), PixelFormat::RGBA_8888);
    auto pointOffset = scaledPointCropRegion - scaledPointSubJpg;
    src += static_cast<uint32_t>(pointOffset.x()) * NUM_4 + static_cast<uint32_t>(pointOffset.y()) * srcStride;
    size_t copyLen = static_cast<size_t>(jpg.ctxSizeInfo.width()) * NUM_4;
    auto copyRows = jpg.ctxSizeInfo.height();
    for (int32_t row = 0; row < copyRows; row++) {
        errno_t err = memcpy_s(dst, copyLen, src, copyLen);
        REQUIRE_LOG(err == EOK, "target pixel copy failed, errno:%{public}d", err);
        src += srcStride;
        dst += dstStride;
    }
    jpg.ctx->outInfo.size.width = jpg.ctxSizeInfo.width();
    jpg.ctx->outInfo.size.height = jpg.ctxSizeInfo.height();
    IMAGE_LOGD("JpegHwRegionDecode success");
    return true;
}

static inline bool Is16k(uint32_t width, uint32_t height)
{
    return (width == NUM_16k && height == NUM_12k) ||
           (width == NUM_12k && height == NUM_16k);
}

bool JpegHwFullDecoder::IsSupport16k()
{
    REQUIRE_LOG(jpg.dinfo->restart_interval == MIN_NUM_MCU_IN_RST, "rst must be 32 in 16k");

    if (jpg.ctx->info.pixelFormat == PixelFormat::RGBA_8888) {
        auto sampleSize = GetSampleSize(jpg.extDecoder->regionDesiredSize_.width,
                                        jpg.extDecoder->regionDesiredSize_.height,
                                        jpg.dinfo->image_width, jpg.dinfo->image_height);
        REQUIRE_LOG(sampleSize != 1, "16k rgba with raw resolution decode not support");
    }
    int32_t subjpgWidth = static_cast<int32_t>(jpg.dinfo->image_width / NUM_2);
    int32_t subjpgHeight = static_cast<int32_t>(jpg.dinfo->image_height / NUM_2);
    auto hwDecoder = std::make_unique<JpegHardwareDecoder>();
    REQUIRE_LOG(hwDecoder, "create JpegHardwareDecoder failed");
    REQUIRE_LOG(hwDecoder->IsHardwareDecodeSupported(IMAGE_JPEG_FORMAT,
                    {subjpgWidth, subjpgHeight}),
                "16k subJpg max prob resolution not support");
    REQUIRE_LOG(static_cast<uint32_t>(subjpgWidth * subjpgHeight) <= MAX_SUPPORT_IMAGE_AREA,
                "16k subJpg area too large");
    return true;
}

bool JpegHwFullDecoder::IsSupport(DecodeContext& dctx, const ExtDecoder* extDecoder)
{
    REQUIRE(RSTBasedDecoder::IsSupport(dctx, extDecoder));
    auto& dinfo = jpg.dinfo;
    if (static_cast<uint64_t>(dinfo->image_width * dinfo->image_height) > NUM_16k * NUM_16k) {
        auto sampleSize = GetSampleSize(jpg.extDecoder->regionDesiredSize_.width,
                                        jpg.extDecoder->regionDesiredSize_.height,
                                        dinfo->image_width, dinfo->image_height);
        REQUIRE_LOG(sampleSize > 1, "Area above 16384x16384 onlu support downsampling decoding");
    }
    if (Is16k(dinfo->image_width, dinfo->image_height) && dctx.info.pixelFormat == PixelFormat::RGBA_8888) {
        REQUIRE(IsSupport16k());
    } else {
        REQUIRE_LOG(jpg.ctx->info.pixelFormat == PixelFormat::NV21, "only support NV21");
    }
    return true;
}

bool JpegHwFullDecoder::DoTileDecode()
{
    ImageFuncTimer imageFuncTimer("%s, sampleSize:%u", __func__, GetSampleSize(jpg.extDecoder->regionDesiredSize_.width,
        jpg.extDecoder->regionDesiredSize_.height, jpg.dinfo->image_width, jpg.dinfo->image_height));
    bool ret = false;
    if (Init() && DecodeFull()) {
        ret = true;
        const_cast<ExtDecoder*>(jpg.extDecoder)->UpdateHardWareDecodeInfo(*jpg.ctx, jpg.ctxSizeInfo);
    }
    if (!ret) {
        if (jpg.ctx->pixelsBuffer.buffer) {
            const_cast<ExtDecoder*>(jpg.extDecoder)->ReleaseOutputBuffer(*jpg.ctx, jpg.ctx->allocatorType);
        }
        IMAGE_LOGD("JpegHwFullDecode failed");
    }
    return ret;
}

bool JpegHwFullDecoder::Init()
{
    REQUIRE(RSTBasedDecoder::Init());
    if (!isAligned) {
        REQUIRE(ProcessLastECS());
    }
    REQUIRE_LOG(subStreamForFull = std::make_unique<uint8_t[]>(jpg.streamSize),
                "create subJpg failed! make_unique error");
    subJpg.streamData = subStreamForFull.get();
    return true;
}

bool JpegHwFullDecoder::ProcessLastECS()
{
    auto posLastECS = jpg.rstPositions[jpg.rstPositions.size() - 2];
    uint32_t numRemain = (jpg.imageWidthPad16 * jpg.imageHeightPad16) %
                         (MCU_WIDTH * MCU_HEIGHT * jpg.dinfo->restart_interval) / (MCU_WIDTH * MCU_HEIGHT);
    if (numRemain == 0) {
        return true;
    }
    auto mcus = std::make_unique<MCU[]>(numRemain);
    REQUIRE_LOG(mcus, "create mcus failed");

    IECS iecs(jpg.streamData.get(), jpg.streamSize + NUM_8, *jpg.tables);
    iecs.RePos(posLastECS, jpg.dinfo->restart_interval);
    for (uint32_t i = 0; i < numRemain; i++) {
        REQUIRE(iecs.DecodeMCU(mcus[i]));
    }
    REQUIRE(iecs.SeekToNextRst());

    OECS oecs(jpg.streamData.get(), jpg.streamSize + NUM_END_EXTRA_BYTES);
    oecs.RePos(posLastECS);
    for (uint32_t i = 0; i < numRemain; i++) {
        REQUIRE(oecs.WriteMCU(mcus[i]));
    }
    for (uint32_t i = 0; i < jpg.dinfo->restart_interval - numRemain; i++) {
        auto temp = iecs.GenerateDummyMCU();
        REQUIRE_LOG(temp, "generate dummy mcu failed");
        REQUIRE(oecs.WriteMCU(*temp));
    }
    REQUIRE(oecs.WriteRST(RSTs[0]));
    jpg.streamData.get()[oecs.Tell() - 1] = MARK_EOI;
    jpg.rstPositions[jpg.rstPositions.size() - 1] = oecs.Tell();
    return true;
}

enum class SplitPattern : uint32_t {
    SIZE_2NxN = 0, SIZE_Nx2N,
    SIZE_3NxN,     SIZE_Nx3N,
    SIZE_2Nx2N,
    SIZE_3Nx2N,    SIZE_2Nx3N,
    SIZE_3Nx3N,
    SIZE_4Nx2N,    SIZE_2Nx4N,
    SIZE_4Nx3N,    SIZE_3Nx4N,
    SIZE_5Nx3N,    SIZE_3Nx5N,
    SIZE_5Nx5N,
};

static SplitPattern CalcPatternNormal(uint32_t width, uint32_t height)
{
    constexpr uint32_t SUB_REGION_WIDTH = 8 * 1024;
    constexpr uint32_t SUB_REGION_HEIGHT = 6 * 1024;
    SplitPattern pattern;
    uint64_t num_sub_img = DIV_ROUND_UP(width * height, SUB_REGION_WIDTH * SUB_REGION_HEIGHT);
    if (num_sub_img <= NUM_2) {
        pattern = width >= height ? SplitPattern::SIZE_2NxN : SplitPattern::SIZE_Nx2N;
    } else if (num_sub_img <= NUM_4) {
        pattern = SplitPattern::SIZE_2Nx2N;
    } else if (num_sub_img <= NUM_6) {
        pattern = width >= height ? SplitPattern::SIZE_3Nx2N : SplitPattern::SIZE_2Nx3N;
    } else if (num_sub_img <= NUM_8) {
        pattern = SplitPattern::SIZE_3Nx3N;
    } else if (num_sub_img <= NUM_12) {
        pattern = width >= height ? SplitPattern::SIZE_4Nx3N : SplitPattern::SIZE_3Nx4N;
    } else {
        pattern = SplitPattern::SIZE_5Nx5N;
    }
    return pattern;
}

static SplitPattern CalcPatternOneSideOver24k(uint32_t width, uint32_t height)
{
    constexpr uint32_t SUB_REGION_WIDTH = 8 * 1024;
    constexpr uint32_t SUB_REGION_HEIGHT = 6 * 1024;
    SplitPattern pattern;
    uint64_t num_sub_img = DIV_ROUND_UP(width * height, SUB_REGION_WIDTH * SUB_REGION_HEIGHT);
    if (num_sub_img <= NUM_2) {
        pattern = width >= height ? SplitPattern::SIZE_3NxN : SplitPattern::SIZE_Nx3N;
    } else if (num_sub_img <= NUM_4) {
        pattern = width >= height ? SplitPattern::SIZE_3Nx2N : SplitPattern::SIZE_2Nx3N;
    } else if (num_sub_img <= NUM_6) {
        pattern = width >= height ? SplitPattern::SIZE_4Nx2N : SplitPattern::SIZE_2Nx4N;
    } else if (num_sub_img <= NUM_8) {
        pattern = width >= height ? SplitPattern::SIZE_4Nx3N : SplitPattern::SIZE_3Nx4N;
    } else if (num_sub_img <= NUM_12) {
        pattern = width >= height ? SplitPattern::SIZE_5Nx3N : SplitPattern::SIZE_3Nx5N;
    } else {
        pattern = SplitPattern::SIZE_5Nx5N;
    }
    return pattern;
}

using Regions = std::vector<std::vector<SkIRect>>;
static Regions CreateRegions(SplitPattern pattern)
{
    if (pattern == SplitPattern::SIZE_2NxN) {
        return Regions(NUM_2, std::vector<SkIRect>(NUM_1));
    } else if (pattern == SplitPattern::SIZE_Nx2N) {
        return Regions(NUM_1, std::vector<SkIRect>(NUM_2));
    } else if (pattern == SplitPattern::SIZE_3NxN) {
        return Regions(NUM_3, std::vector<SkIRect>(NUM_1));
    } else if (pattern == SplitPattern::SIZE_Nx3N) {
        return Regions(NUM_1, std::vector<SkIRect>(NUM_3));
    } else if (pattern == SplitPattern::SIZE_2Nx2N) {
        return Regions(NUM_2, std::vector<SkIRect>(NUM_2));
    } else if (pattern == SplitPattern::SIZE_3Nx2N) {
        return Regions(NUM_3, std::vector<SkIRect>(NUM_2));
    } else if (pattern == SplitPattern::SIZE_2Nx3N) {
        return Regions(NUM_2, std::vector<SkIRect>(NUM_3));
    } else if (pattern == SplitPattern::SIZE_3Nx3N) {
        return Regions(NUM_3, std::vector<SkIRect>(NUM_3));
    } else if (pattern == SplitPattern::SIZE_4Nx2N) {
        return Regions(NUM_4, std::vector<SkIRect>(NUM_2));
    } else if (pattern == SplitPattern::SIZE_2Nx4N) {
        return Regions(NUM_2, std::vector<SkIRect>(NUM_4));
    } else if (pattern == SplitPattern::SIZE_4Nx3N) {
        return Regions(NUM_4, std::vector<SkIRect>(NUM_3));
    } else if (pattern == SplitPattern::SIZE_3Nx4N) {
        return Regions(NUM_3, std::vector<SkIRect>(NUM_4));
    } else if (pattern == SplitPattern::SIZE_5Nx3N) {
        return Regions(NUM_5, std::vector<SkIRect>(NUM_3));
    } else if (pattern == SplitPattern::SIZE_3Nx5N) {
        return Regions(NUM_3, std::vector<SkIRect>(NUM_5));
    } else {
        return Regions(NUM_5, std::vector<SkIRect>(NUM_5));
    }
}

static Regions SplitFull(uint32_t width, uint32_t height)
{
    constexpr uint32_t MAX_SIDE_LENGTH = 24 * 1024;
    SplitPattern pattern;
    if (width <= MAX_SIDE_LENGTH && height <= MAX_SIDE_LENGTH) {
        pattern = CalcPatternNormal(width, height);
    } else if ((width > MAX_SIDE_LENGTH && height <= MAX_SIDE_LENGTH) ||
               (width <= MAX_SIDE_LENGTH && height > MAX_SIDE_LENGTH)) {
        pattern = CalcPatternOneSideOver24k(width, height);
    } else {
        pattern = SplitPattern::SIZE_5Nx5N;
    }

    auto regions = CreateRegions(pattern);
    auto num_col = regions.size();
    auto num_row = regions[0].size();
    auto width_sub_img = ALIGN_UP(DIV_ROUND_UP(width, num_col), MCU_WIDTH);
    auto height_sub_img = ALIGN_UP(DIV_ROUND_UP(height, num_row), MCU_HEIGHT);
    for (uint32_t row = 0; row < num_row - 1; row++) {
        for (uint32_t col = 0; col < num_col - 1; col++) {
            regions[col][row] =
                SkIRect::MakeXYWH(col * width_sub_img, row * height_sub_img, width_sub_img, height_sub_img);
        }
    }
    for (uint32_t col = 0; col < num_col - 1; col++) {
        regions[col][num_row - 1] =
            SkIRect::MakeXYWH(col * width_sub_img, (num_row - 1) * height_sub_img,
                width_sub_img, height - (num_row - 1) * height_sub_img);
    }
    for (uint32_t row = 0; row < num_row - 1; row++) {
        regions[num_col - 1][row] =
            SkIRect::MakeXYWH((num_col - 1) * width_sub_img, row * height_sub_img,
                width - (num_col - 1) * width_sub_img, height_sub_img);
    }
    regions[num_col - 1][num_row - 1] =
        SkIRect::MakeXYWH((num_col - 1) * width_sub_img, (num_row - 1) * height_sub_img,
            width - (num_col - 1) * width_sub_img, height - (num_row - 1) * height_sub_img);
    return regions;
}

bool JpegHwFullDecoder::AllocDMACtx()
{
    auto splittedRegions = SplitFull(jpg.dinfo->image_width, jpg.dinfo->image_height);
    subJpg.ctx = *jpg.ctx;
    auto scaledSizeCtx = MapToScaledSize(
        splittedRegions[0][0].width() + NUM_2 * jpg.dinfo->restart_interval * MCU_WIDTH,
        splittedRegions[0][0].height() + NUM_2 * MCU_HEIGHT, subJpg.ctx.info.pixelFormat);
    subJpg.ctxSizeInfo = jpg.extDecoder->info_.makeWH(ALIGN_UP(scaledSizeCtx.width(), NUM_8 * NUM_3),
                                                      ALIGN_UP(scaledSizeCtx.height(), NUM_8 * NUM_3));
    uint64_t byteCount = 0;
    if (subJpg.ctx.info.pixelFormat == PixelFormat::NV21) {
        byteCount = static_cast<uint64_t>(ImageUtils::GetYUVByteCount(
            {{subJpg.ctxSizeInfo.width(), subJpg.ctxSizeInfo.height()}, PixelFormat::NV21}));
    } else {
        byteCount = static_cast<uint64_t>(subJpg.ctxSizeInfo.height()) *
                    static_cast<uint64_t>(subJpg.ctxSizeInfo.width()) *
                    static_cast<uint64_t>(subJpg.ctxSizeInfo.bytesPerPixel());
    }
    REQUIRE_LOG(!SkImageInfo::ByteSizeOverflowed(byteCount),
                "%{public}s too large region size: %{public}llu", __func__, static_cast<unsigned long long>(byteCount));
    REQUIRE_LOG(const_cast<ExtDecoder*>(jpg.extDecoder)->DmaMemAlloc(subJpg.ctx, byteCount, subJpg.ctxSizeInfo)
                == SUCCESS, "subJpg ctx DMA buffer alloc failed");

    auto scaledFullSize = MapToScaledSize(jpg.dinfo->image_width, jpg.dinfo->image_height, jpg.ctx->info.pixelFormat);
    jpg.ctxSizeInfo = jpg.extDecoder->info_.makeWH(scaledFullSize.width(), scaledFullSize.height());
    if (jpg.ctx->info.pixelFormat == PixelFormat::NV21) {
        byteCount = static_cast<uint64_t>(ImageUtils::GetYUVByteCount(
            {{jpg.ctxSizeInfo.width(), jpg.ctxSizeInfo.height()}, PixelFormat::NV21}));
    } else {
        byteCount = static_cast<uint64_t>(jpg.ctxSizeInfo.height()) * static_cast<uint64_t>(jpg.ctxSizeInfo.width()) *
                    static_cast<uint64_t>(jpg.ctxSizeInfo.bytesPerPixel());
    }
    REQUIRE_LOG(!SkImageInfo::ByteSizeOverflowed(byteCount),
        "%{public}s too large region size: %{public}llu", __func__, static_cast<unsigned long long>(byteCount));
    REQUIRE_LOG(const_cast<ExtDecoder*>(jpg.extDecoder)->DmaMemAlloc(*jpg.ctx, byteCount, jpg.ctxSizeInfo) == SUCCESS,
        "dctx DMA buffer alloc failed");
    return true;
}

bool JpegHwFullDecoder::DecodeFull()
{
    auto splittedRegions = SplitFull(jpg.dinfo->image_width, jpg.dinfo->image_height);

    subJpg.sampleSize = GetSampleSize(jpg.extDecoder->regionDesiredSize_.width,
                                      jpg.extDecoder->regionDesiredSize_.height,
                                      jpg.dinfo->image_width, jpg.dinfo->image_height);

    REQUIRE(AllocDMACtx());

    REQUIRE_LOG(hwDecoder->InitDecoder(), "failed to init jpeg hardware decoder");

    errno_t err = memcpy_s(subJpg.streamData, jpg.streamSize - jpg.rstPositions[0],
                           jpg.streamData.get(), jpg.rstPositions[0]);
    REQUIRE_LOG(err == EOK, "memcpy_s failed!");
    subJpg.streamSize = jpg.rstPositions[0];

    auto numCol = splittedRegions.size();
    auto numRow = splittedRegions[0].size();
    for (uint32_t row = 0; row < numRow; row++) {
        for (uint32_t col = 0; col < numCol; col++) {
            auto& region = splittedRegions[col][row];
            if (!(CreateSub(region) && RSTBasedDecoder::DoHardWareDecode() && MergeRegion(region))) {
                REQUIRE_LOG(false, "[%{public}u, %{public}u, %{public}u, %{public}u]",
                    region.x(), region.y(), region.width(), region.height());
            }
        }
    }
    IMAGE_LOGD("JpegHwFullDecode success");
    return true;
}

static std::vector<FullDecInfo::MCULineInfo> CreateInfo(const SkIRect& region, uint32_t width, uint32_t height,
                                                        uint32_t rst)
{
    width = ALIGN_UP(width, MCU_WIDTH);
    height = ALIGN_UP(height, MCU_HEIGHT);
    uint32_t region_top = ALIGN_DOWN(static_cast<uint32_t>(region.y()), MCU_HEIGHT);
    uint32_t region_bottom = ALIGN_UP(static_cast<uint32_t>(region.y() + region.height()), MCU_HEIGHT);
    uint32_t num_mcu_lines = (region_bottom - region_top) / MCU_HEIGHT;
    std::vector<FullDecInfo::MCULineInfo> lines(num_mcu_lines);
    for (uint32_t idx = 0; idx < num_mcu_lines; idx++) {
        uint32_t mcu_line_top = region_top + MCU_HEIGHT * idx;
        auto& line = lines[idx];
        line.startRSTIdx = (mcu_line_top * width + static_cast<uint32_t>(region.x()) * MCU_HEIGHT) /
                            (MCU_WIDTH * MCU_HEIGHT * rst);
        line.endRSTIdx = (mcu_line_top * width +
                        (static_cast<uint32_t>(region.x()) + static_cast<uint32_t>(region.width()) - 1) * MCU_HEIGHT) /
                        (MCU_WIDTH * MCU_HEIGHT * rst) + 1;
        line.cropOffsetX = (static_cast<uint32_t>(region.x()) / MCU_WIDTH +
                            mcu_line_top / MCU_HEIGHT * (width / MCU_WIDTH)) - line.startRSTIdx * rst;
        line.cropOffsetX *= MCU_WIDTH;
        line.cropOffsetX += static_cast<uint32_t>(region.x()) % MCU_WIDTH;
    }
    return lines;
}

bool JpegHwFullDecoder::CreateSub(const SkIRect& subRegion)
{
    auto& streamData = subJpg.streamData;
    auto& streamSize = subJpg.streamSize;
    streamSize = jpg.rstPositions[0];
    subJpg.fullDecInfo.entries = CreateInfo(subRegion, jpg.imageWidthPad16, jpg.imageHeightPad16,
                                            jpg.dinfo->restart_interval);
    uint32_t numMCULine = subJpg.fullDecInfo.entries.size();
    REQUIRE_LOG(numMCULine > 0, "CreateInfo error");
    uint32_t numRSTs = 0;
    for (uint32_t line = 0; line < numMCULine; line++) {
        auto& info = subJpg.fullDecInfo.entries[line];
        auto tempNum = info.endRSTIdx - info.startRSTIdx;
        numRSTs = tempNum > numRSTs ? tempNum : numRSTs;
    }
    auto& info = subJpg.fullDecInfo.entries[numMCULine - 1];
    auto numR = info.endRSTIdx - info.startRSTIdx;
    if (UNLIKELY(info.endRSTIdx == (jpg.rstPositions.size() - 1) && numR < numRSTs)) {
        info.startRSTIdx -= numRSTs - numR;
        info.cropOffsetX += (numRSTs - numR) * jpg.dinfo->restart_interval * MCU_WIDTH;
    }

    uint8_t rstCounter = 0;
    errno_t err;
    for (uint32_t line = 0; line < numMCULine; line++) {
        auto& info = subJpg.fullDecInfo.entries[line];
        for (uint32_t i = 0; i < numRSTs; i++) {
            size_t intervalStart = jpg.rstPositions[info.startRSTIdx + i];
            size_t intervalEnd = jpg.rstPositions[info.startRSTIdx + i + 1];
            size_t copyLen = intervalEnd - intervalStart - NUM_2;
            err = memmove_s(streamData + streamSize, jpg.streamSize - streamSize,
                            jpg.streamData.get() + intervalStart, copyLen);
            REQUIRE_LOG(err == EOK, "ECS data memmove failed, errno:%{public}d", err);
            streamSize += copyLen;
            err = memmove_s(streamData + streamSize, jpg.streamSize - streamSize, &FFCode, NUM_1);
            REQUIRE_LOG(err == EOK, "FFCode set failed, errno:%{public}d", err);
            ++streamSize;
            err = memmove_s(streamData + streamSize, jpg.streamSize - streamSize, &RSTs[rstCounter], NUM_1);
            REQUIRE_LOG(err == EOK, "RST marker set failed, errno:%{public}d", err);
            ++streamSize;
            rstCounter = (rstCounter + 1) % NUM_8;
        }
    }
    streamData[streamSize - 1] = MARK_EOI;
    subJpg.origSize = SkISize::Make(numRSTs * jpg.dinfo->restart_interval * MCU_WIDTH, numMCULine * MCU_HEIGHT);
    streamData[jpg.YPos] = (static_cast<uint32_t>(subJpg.origSize.height()) >> NUM_8) & 0xff;
    streamData[jpg.YPos + NUM_1] = static_cast<uint32_t>(subJpg.origSize.height()) & 0xff;
    streamData[jpg.YPos + NUM_2] = (static_cast<uint32_t>(subJpg.origSize.width()) >> NUM_8) & 0xff;
    streamData[jpg.YPos + NUM_3] = static_cast<uint32_t>(subJpg.origSize.width()) & 0xff;

    ImageUtils::DumpDataIfDumpEnabled(reinterpret_cast<char*>(subJpg.streamData), subJpg.streamSize, "subjpeg");
    return true;
}

bool JpegHwFullDecoder::MergeRegionNV21(uint8_t* src, uint64_t srcStride, uint8_t* dst, uint64_t dstStride,
                                        const SkIRect& subRegion)
{
    auto& info = subJpg.fullDecInfo.entries;
    auto scaledPointSubRegion = MapToScaledPoint(subRegion.x(), subRegion.y(), subJpg.ctx.info.pixelFormat);
    auto scaledSizeSubRegion = MapToScaledSize(subRegion.width(), subRegion.height(), subJpg.ctx.info.pixelFormat);

    dst += static_cast<uint64_t>(scaledPointSubRegion.x()) +
            static_cast<uint64_t>(scaledPointSubRegion.y()) * dstStride;
    size_t copyLen = static_cast<size_t>(scaledSizeSubRegion.width());
    uint32_t srcStartRow = GetScaledValue(subRegion.y() % MCU_HEIGHT, PixelFormat::NV21);
    uint32_t srcEndRow = GetScaledValue(subRegion.y() % MCU_HEIGHT + subRegion.height(), PixelFormat::NV21);
    uint32_t scaledMCUHeight = GetScaledValue(MCU_HEIGHT, PixelFormat::NV21);

    errno_t err;
    for (uint32_t srcRow = srcStartRow, dstRow = 0; srcRow < srcEndRow; srcRow++, dstRow++) {
        err = memcpy_s(dst + dstRow * dstStride, copyLen,
                       src + srcRow * srcStride +
                       GetScaledValue(info[srcRow / scaledMCUHeight].cropOffsetX, PixelFormat::NV21),
                       copyLen);
        REQUIRE_LOG(err == EOK, "target pixel copy failed. errno:%{public}d", err);
    }

    dst = static_cast<uint8_t*>(jpg.ctx->pixelsBuffer.buffer) +
          static_cast<uint32_t>(jpg.ctxSizeInfo.height()) * dstStride +
          static_cast<uint32_t>(scaledPointSubRegion.x()) +
          static_cast<uint32_t>(scaledPointSubRegion.y()) * dstStride / NUM_2;
    src += static_cast<uint64_t>(subJpg.ctxSizeInfo.height()) * srcStride;
    srcStartRow /= NUM_2;
    srcEndRow /= NUM_2;
    for (uint32_t srcRow = srcStartRow, dstRow = 0; srcRow < srcEndRow; srcRow++, dstRow++) {
        err = memcpy_s(dst + dstRow * dstStride, copyLen,
                       src + srcRow * srcStride +
                       GetScaledValue(info[srcRow * NUM_2 / scaledMCUHeight].cropOffsetX, PixelFormat::NV21),
                       copyLen);
        REQUIRE_LOG(err == EOK, "target pixel copy failed. errno:%{public}d", err);
    }
    return true;
}

bool JpegHwFullDecoder::MergeRegionRGBA(uint8_t* src, uint64_t srcStride, uint8_t* dst, uint64_t dstStride,
                                        const SkIRect& subRegion)
{
    auto& info = subJpg.fullDecInfo.entries;
    auto scaledPointSubRegion = MapToScaledPoint(subRegion.x(), subRegion.y(), subJpg.ctx.info.pixelFormat);
    auto scaledSizeSubRegion = MapToScaledSize(subRegion.width(), subRegion.height(), subJpg.ctx.info.pixelFormat);

    dst += static_cast<uint32_t>(scaledPointSubRegion.x()) * NUM_4 +
            static_cast<uint32_t>(scaledPointSubRegion.y()) * dstStride;
    size_t copyLen = static_cast<size_t>(scaledSizeSubRegion.width()) * NUM_4;
    uint32_t srcStartRow = GetScaledValue(subRegion.y() % MCU_HEIGHT, PixelFormat::RGBA_8888);
    uint32_t srcEndRow = GetScaledValue(subRegion.y() % MCU_HEIGHT + subRegion.height(), PixelFormat::RGBA_8888);
    uint32_t scaledMCUHeight = GetScaledValue(MCU_HEIGHT, PixelFormat::RGBA_8888);

    errno_t err;
    for (uint32_t srcRow = srcStartRow, dstRow = 0; srcRow < srcEndRow; srcRow++, dstRow++) {
        err = memcpy_s(dst + dstRow * dstStride, copyLen,
                       src + srcRow * srcStride +
                       GetScaledValue(info[srcRow / scaledMCUHeight].cropOffsetX, PixelFormat::RGBA_8888) * NUM_4,
                       copyLen);
        REQUIRE_LOG(err == EOK, "target pixel copy failed. errno:%{public}d", err);
    }
    return true;
}

bool JpegHwFullDecoder::MergeRegion(const SkIRect& subRegion)
{
    uint8_t* src = static_cast<uint8_t*>(subJpg.ctx.pixelsBuffer.buffer);
    REQUIRE_LOG(src, "src pixel buffer is nullptr");
    SurfaceBuffer* subJpgSbBuffer = reinterpret_cast<SurfaceBuffer*>(subJpg.ctx.pixelsBuffer.context);
    REQUIRE_LOG(subJpgSbBuffer, "sub surface buffer is nullptr");
    uint64_t srcStride = static_cast<uint64_t>(subJpgSbBuffer->GetStride());
    ImageUtils::InvalidateContextSurfaceBuffer(subJpg.ctx);

    uint8_t* dst = static_cast<uint8_t*>(jpg.ctx->pixelsBuffer.buffer);
    REQUIRE_LOG(dst, "dst pixel buffer is nullptr");
    SurfaceBuffer* dstSbBuffer = reinterpret_cast<SurfaceBuffer*>(jpg.ctx->pixelsBuffer.context);
    REQUIRE_LOG(dstSbBuffer, "full surface buffer is nullptr");
    uint64_t dstStride = static_cast<uint64_t>(dstSbBuffer->GetStride());

    if (jpg.ctx->info.pixelFormat == PixelFormat::NV21) {
        REQUIRE(MergeRegionNV21(src, srcStride, dst, dstStride, subRegion));
    } else if (jpg.ctx->info.pixelFormat == PixelFormat::RGBA_8888) {
        REQUIRE(MergeRegionRGBA(src, srcStride, dst, dstStride, subRegion));
    }
    return true;
}

uint32_t JpegHwFullDecoder::GetSampleSize(int32_t dwidth, int32_t dheight, int32_t origWidth, int32_t origHeight)
{
    uint32_t sampleSize = 0;
    float finalScale = Max(static_cast<float>(dwidth) / origWidth,
                           static_cast<float>(dheight) / origHeight);
    if (finalScale > HALF) {
        sampleSize = DEFAULT_SCALE_SIZE;
    } else if (finalScale > QUARTER) {
        sampleSize = DOUBLE_SCALE_SIZE;
    } else if (finalScale > ONE_EIGHTH) {
        sampleSize = FOURTH_SCALE_SIZE;
    } else {
        sampleSize = MAX_SCALE_SIZE;
    }
    return sampleSize;
}

} // namespace ImagePlugin
} // namespace OHOS