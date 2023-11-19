/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "astc_utils.h"

#include "hilog/log.h"
#include "log_tags.h"
namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_TAG_DOMAIN_ID_PLUGIN, "AstcUtils"};\

constexpr uint8_t BIT_SHIFT_8BITS = 8;
constexpr uint8_t BIT_SHIFT_16BITS = 16;
constexpr uint8_t BIT_SHIFT_24BITS = 24;
constexpr uint8_t BYTES_MASK = 0xFF;

constexpr uint8_t HALF_BYTES_MASK = 0xF;
constexpr uint8_t GLOBAL_WH_NUM_CL = 2;

// Hash seed used for generate a mixed hash value
constexpr uint8_t HASH_MAGIC_SEED_BIT = 15;
constexpr uint32_t HASH_MAGIC_SEED = 0xEEDE0891;
constexpr uint8_t HASH_SEED_1 = 5;
constexpr uint8_t HASH_SEED_2 = 16;
constexpr uint8_t HASH_SEED_3 = 7;
constexpr uint8_t HASH_SEED_4 = 3;
constexpr uint8_t HASH_SEED_5 = 6;
constexpr uint8_t HASH_SEED_6 = 17;

// Random number seeds used to generate multiple partition partition pattern decisions
constexpr uint8_t SEED_MAGIC_NUM_01 = 4;
constexpr uint8_t SEED_MAGIC_NUM_02 = 12;
constexpr uint8_t SEED_MAGIC_NUM_03 = 20;
constexpr uint8_t SEED_MAGIC_NUM_04 = 28;
constexpr uint8_t SEED_MAGIC_NUM_05 = 18;
constexpr uint8_t SEED_MAGIC_NUM_06 = 22;
constexpr uint8_t SEED_MAGIC_NUM_07 = 26;
constexpr uint8_t SEED_MAGIC_NUM_08 = 30;
constexpr uint8_t SEED_MAGIC_NUM_09 = 2;

// Constant of the shift value.
constexpr uint8_t SEED_MAGIC_2 = 2;
constexpr uint8_t SEED_MAGIC_3 = 3;
constexpr uint8_t SEED_MAGIC_4 = 4;
constexpr uint8_t SEED_MAGIC_5 = 5;
constexpr uint8_t SEED_MAGIC_6 = 6;
constexpr uint8_t SEED_MAGIC_7 = 7;
constexpr uint8_t SEED_MAGIC_8 = 8;
constexpr uint8_t SEED_MAGIC_10 = 10;
constexpr uint8_t SEED_MAGIC_14 = 14;

constexpr uint8_t MASK_4TH_BIT = 0x10;
constexpr uint8_t MASK_LOW7BIT = 0x3F;

constexpr uint8_t PARTITION_COUNT_1 = 1;
constexpr uint8_t PARTITION_COUNT_2 = 2;
constexpr uint8_t PARTITION_COUNT_3 = 3;
constexpr uint8_t PARTITION_COUNT_4 = 4;

constexpr uint8_t SEED_NUM = 12;
}

uint32_t AstcUtils::SeedMixHash(uint32_t seed)
{
    seed ^= seed >> HASH_MAGIC_SEED_BIT;
    seed *= HASH_MAGIC_SEED;
    seed ^= seed >> HASH_SEED_1;
    seed += seed << HASH_SEED_2;
    seed ^= seed >> HASH_SEED_3;
    seed ^= seed >> HASH_SEED_4;
    seed ^= seed << HASH_SEED_5;
    seed ^= seed >> HASH_SEED_6;
    return seed;
}

void AstcUtils::CalSeedNum(uint8_t seedn[SEED_NUM], uint32_t num)
{
    // Pointer to iterate through the 'seedn' array
    uint8_t *seed = seedn;

    // Extract 8-bit parts from 'num' and store them in 'seedn'
    *seed++ = num & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_01) & HALF_BYTES_MASK;
    *seed++ = (num >> BIT_SHIFT_8BITS) & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_02) & HALF_BYTES_MASK;
    *seed++ = (num >> BIT_SHIFT_16BITS) & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_03) & HALF_BYTES_MASK;
    *seed++ = (num >> BIT_SHIFT_24BITS) & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_04) & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_05) & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_06) & HALF_BYTES_MASK;
    *seed++ = (num >> SEED_MAGIC_NUM_07) & HALF_BYTES_MASK;
    *seed++ = ((num >> SEED_MAGIC_NUM_08) | (num << SEED_MAGIC_NUM_09)) & HALF_BYTES_MASK;

    // Square each element in the 'seedn' array
    for (int i = 0; i < SEED_NUM; i++) {
        seedn[i] *= seedn[i];
    }
}

uint8_t AstcUtils::CalPartition(int32_t blockWidth, int32_t partitionA, int32_t partitionB,
    int32_t partitionC, int32_t partitionD)
{
    // Limits the input partition values to 7 bits each
    partitionA &= MASK_LOW7BIT;
    partitionB &= MASK_LOW7BIT;
    partitionC &= MASK_LOW7BIT;
    partitionD &= MASK_LOW7BIT;

    // Modifies partition values based on the block width
    if (blockWidth <= PARTITION_COUNT_3) {
        partitionD = 0;
    }
    if (blockWidth <= PARTITION_COUNT_2) {
        partitionC = 0;
    }
    if (blockWidth <= PARTITION_COUNT_1) {
        partitionB = 0;
    }

    uint8_t selectedPartition;
    // Selects the partition based on the magnitude of partition values
    if (partitionA >= partitionB && partitionA >= partitionC &&  partitionA >= partitionD) {
        selectedPartition = 0;
    } else if (partitionB >= partitionC &&  partitionB >= partitionD) {
        selectedPartition = PARTITION_COUNT_1;
    } else if (partitionC >= partitionD) {
        selectedPartition = PARTITION_COUNT_2;
    } else {
        selectedPartition = PARTITION_COUNT_3;
    }

    return selectedPartition;
}

uint8_t AstcUtils::SelectPartition(int32_t seed, int32_t x, int32_t y, int32_t partitionCount, bool smallBlock)
{
    // Adjust coordinates for small blocks if necessary
    if (smallBlock) {
        x <<= 1;
        y <<= 1;
    }

    // Modify seed based on partition count
    seed += (partitionCount - 1) << SEED_MAGIC_10;

    // Generate a hash value using the modified seed
    uint32_t num = SeedMixHash(seed);

    // Calculate seed numbers from the hash value
    uint8_t seedn[SEED_NUM];
    CalSeedNum(seedn, num);

    // Determine shift values based on seed and partition count
    int32_t sh1, sh2;
    if (seed & 1) {
        sh1 = (seed & SEED_MAGIC_2 ? SEED_MAGIC_4 : SEED_MAGIC_5);
        sh2 = (partitionCount == PARTITION_COUNT_3 ? SEED_MAGIC_6 : SEED_MAGIC_5);
    } else {
        sh1 = (partitionCount == PARTITION_COUNT_3 ? SEED_MAGIC_6 : SEED_MAGIC_5);
        sh2 = (seed & SEED_MAGIC_2 ? SEED_MAGIC_4 : SEED_MAGIC_5);
    }
    int32_t sh3 = (seed & MASK_4TH_BIT) ? sh1 : sh2;

    // Right-shift elements in the seedn array based on shift values
    int i;
    for (i = 0; i < SEED_MAGIC_8; i += SEED_MAGIC_2) {
        seedn[i] >>= sh1;
        seedn[i + 1] >>= sh2;
    }
    for (; i < SEED_NUM; i++) {
        seedn[i] >>= sh3;
    }

    // Calculate linear combinations based on modified coordinates, seedn values, and hash value
    int32_t a = seedn[0] * x + seedn[1] * y + (num >> SEED_MAGIC_14);
    int32_t b = seedn[SEED_MAGIC_2] * x + seedn[SEED_MAGIC_3] * y + (num >> SEED_MAGIC_10);
    int32_t c = seedn[SEED_MAGIC_4] * x + seedn[SEED_MAGIC_5] * y + (num >> SEED_MAGIC_6);
    int32_t d = seedn[SEED_MAGIC_6] * x + seedn[SEED_MAGIC_7] * y + (num >> SEED_MAGIC_2);

    // Use the calculated values to select and return a partition index
    return CalPartition(partitionCount, a, b, c, d);
}
} // namespace Media
} // namespace OHOS