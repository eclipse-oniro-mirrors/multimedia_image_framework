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


constexpr char ASTCCL_6X6_SRC[] = R"ASTCCL6x6(
#define LARGE_FLOAT (1e38f)

#define DIM (6)
#define BLOCK_SIZE (36)
#define PIXEL_MAX_VALUE (255.0f)
#define PHYSICAL_BLOCK_BYTES (16)
#define MAX_GRID (BLOCK_SIZE)
#define MAX_GRID_POINT_TEXEL_2D (4)
#define BLOCK_MAX_PARTITIONS (3)

#define ENABLE_2PART (1)
#define ENABLE_3PART (0)
#define REFINE_ITERS_1PART (2)
#define REFINE_ITERS_PART (1)

typedef enum
{
	QUANT_2 = 0,
	QUANT_3 = 1,
	QUANT_4 = 2,
	QUANT_5 = 3,
	QUANT_6 = 4,
	QUANT_8 = 5,
	QUANT_10 = 6,
	QUANT_12 = 7,
	QUANT_16 = 8,
	QUANT_20 = 9,
	QUANT_24 = 10,
	QUANT_32 = 11,
	QUANT_40 = 12,
	QUANT_48 = 13,
	QUANT_64 = 14,
} QuantMethod;

#define EP_INTEGER (3)
typedef struct {
    uint blockmodeIdx;
    uint gridW;
    uint gridH;
    uint gridNum;
    QuantMethod wQuant;
    uint wBits;

    uint epBits;
    uint cemBits;
    QuantMethod epQuant;
} Mode;

#define NUM_PREDEF_BM_1PART (6)
__constant Mode PREDEF_BM_1PART[NUM_PREDEF_BM_1PART] = {
    {111, 5, 6, 30, QUANT_6, 78, 33, 4, QUANT_40},
    {737, 5, 5, 25, QUANT_10, 84, 27, 4, QUANT_20},
    {355, 6, 5, 30, QUANT_6, 78, 33, 4, QUANT_40},
    {280, 6, 6, 36, QUANT_5, 84, 27, 4, QUANT_20},
    {589, 4, 6, 24, QUANT_10, 80, 31, 4, QUANT_32},
    {833, 6, 4, 24, QUANT_10, 80, 31, 4, QUANT_32}
};

#define NUM_PREDEF_BM_2PART (3)
__constant Mode PREDEF_BM_2PART[NUM_PREDEF_BM_2PART] = {
    {125, 5, 6, 30, QUANT_3, 48, 51, 6, QUANT_16},
    {241, 5, 5, 25, QUANT_3, 40, 59, 6, QUANT_24},
    {369, 6, 5, 30, QUANT_3, 48, 51, 6, QUANT_16},
};

#define NUM_PREDEF_BM_3PART (3)
__constant Mode PREDEF_BM_3PART[NUM_PREDEF_BM_3PART] = {
    {125, 5, 6, 30, QUANT_3, 48, 51, 6, QUANT_6},
    {241, 5, 5, 25, QUANT_3, 40, 59, 6, QUANT_8},
    {369, 6, 5, 30, QUANT_3, 48, 51, 6, QUANT_6},
};

typedef struct {
    uint partitionCount;
    uint partitioningIdx;
    uchar partitioningPattern[BLOCK_SIZE];
} PartitionInfo;

__constant PartitionInfo PREDEF_PARTITION_INFO_1PART = {1, 0, {0}};

#define NUM_PARTITIONING_2PART (8)
__constant PartitionInfo PREDEF_PARTITION_INFO_2PART[NUM_PARTITIONING_2PART] = {
    {2, 132,
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
    {2, 19,
        {0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1}},
    {2, 136,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
    {2, 78,
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
    {2, 28,
        {0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1}},
    {2, 67,
        {0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1}},
    {2, 116,
        {0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0}},
    {2, 210,
        {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1}}
};

#define NUM_PARTITIONING_3PART (10)
__constant PartitionInfo PREDEF_PARTITION_INFO_3PART[NUM_PARTITIONING_3PART] = {
    {3, 0,
        {2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1}},
    {3, 8,
        {1, 2, 2, 2, 2, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
    {3, 11,
        {0, 1, 2, 1, 1, 1, 0, 1, 2, 1, 1, 1, 0, 1, 2, 1, 1, 1, 0, 1, 2, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1}},
    {3, 14,
        {0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}},
    {3, 15,
        {0, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 2, 0, 0, 1, 1, 1, 2}},
    {3, 17,
        {2, 2, 2, 0, 1, 1, 2, 2, 2, 0, 1, 2, 2, 2, 0, 0, 1, 2, 2, 2, 0, 1, 1, 2, 2, 0, 0, 1, 1, 2, 2, 0, 0, 1, 2, 2}},
    {3, 18,
        {1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1}},
    {3, 19,
        {2, 2, 2, 0, 1, 1, 2, 2, 2, 0, 1, 1, 2, 2, 2, 0, 1, 1, 2, 2, 2, 0, 1, 1, 2, 2, 2, 0, 1, 1, 2, 2, 2, 0, 1, 1}},
    {3, 23,
        {0, 0, 0, 2, 1, 1, 0, 0, 0, 2, 1, 1, 0, 0, 0, 2, 1, 1, 0, 0, 0, 2, 1, 1, 0, 0, 0, 2, 1, 1, 0, 0, 0, 2, 1, 1}},
    {3, 26,
        {0, 0, 2, 2, 1, 1, 0, 0, 1, 1, 1, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 2, 2, 2}}
};

#define NUM_WEIGHT_QUANT_METHOD (6)
#define MAX_WEIGHT_QUANT_METHOD (10)
__constant int wqScramble[NUM_WEIGHT_QUANT_METHOD][MAX_WEIGHT_QUANT_METHOD] = {
    {0, 1, 2, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 3, 4, 0, 0, 0, 0, 0},
    {0, 2, 4, 5, 3, 1, 0, 0, 0, 0},
    {0, 2, 4, 6, 8, 9, 7, 5, 3, 1},
    {0, 1, 2, 3, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 0, 0}
};

__constant int wqUnscramble[NUM_WEIGHT_QUANT_METHOD][MAX_WEIGHT_QUANT_METHOD] = {
    {0, 1, 2, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 3, 4, 0, 0, 0, 0, 0},
    {0, 5, 1, 4, 2, 3, 0, 0, 0, 0},
    {0, 9, 1, 8, 2, 7, 3, 6, 4, 5},
    {0, 1, 2, 3, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 0, 0}
};

__constant int wqUnquant[NUM_WEIGHT_QUANT_METHOD][MAX_WEIGHT_QUANT_METHOD] = {
    {0, 32, 64, 0, 0, 0, 0, 0, 0, 0},
    {0, 16, 32, 48, 64, 0, 0, 0, 0, 0},
    {0, 64, 12, 52, 25, 39, 0, 0, 0, 0},
    {0, 64, 7, 57, 14, 50, 21, 43, 28, 36},
    {0, 21, 43, 64, 0, 0, 0, 0, 0, 0},
    {0, 9, 18, 27, 37, 46, 55, 64}
};

#define NUM_WQ (6)
__constant int wqLevels[NUM_WEIGHT_QUANT_METHOD] = {3, 5, 6, 10, 4, 8};
__constant int wqBits[NUM_WQ] = {0, 0, 1, 1, 2, 3};
__constant int wqTrits[NUM_WQ] = {1, 0, 1, 0, 0, 0};
__constant int wqQuints[NUM_WQ] = {0, 1, 0, 1, 0, 0};

#define NUM_CQ (7)
__constant int cqLevels[NUM_CQ] = {6, 8, 16, 20, 32, 40, 24};
__constant int cqBits[NUM_CQ] = {1, 3, 4, 2, 5, 3, 3};
__constant int cqTrits[NUM_CQ] = {1, 0, 0, 0, 0, 0, 1};
__constant int cqQuints[7] = {0, 0, 0, 1, 0, 1, 0};

__constant uchar cqNearest[NUM_CQ][256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11,
        11, 11, 11, 11, 11,
    11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15,
        15, 15, 15, 15,
    0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
        2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 10, 10, 10, 10, 10, 10, 10, 10, 10,
    10, 10, 10, 10, 10, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
        18, 18, 18, 18,
    19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 11,
        11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4,
    4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8,
    8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 11, 12,
    12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15,
        15, 15, 15, 15,
    16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18, 18, 18, 18, 18, 18, 19, 19, 19, 19,
        19, 19, 19, 19,
    19, 20, 20, 20, 20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23,
        23, 23, 23, 23,
    23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26, 26, 26, 26, 26, 26, 27, 27,
        27, 27, 27, 27,
    27, 27, 27, 28, 28, 28, 28, 28, 28, 28, 28, 29, 29, 29, 29, 29, 29, 29, 29, 30, 30, 30, 30, 30, 30, 30, 30, 31,
        31, 31, 31, 31,
    0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 24, 24, 24, 24, 24, 24, 24, 32, 32, 32, 32, 32, 32, 2, 2, 2,
    2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 18, 18, 18, 18, 18, 18, 18, 26, 26, 26, 26, 26, 26, 34, 34, 34, 34, 34, 34,
        34, 4, 4,
    4, 4, 4, 4, 12, 12, 12, 12, 12, 12, 12, 20, 20, 20, 20, 20, 20, 28, 28, 28, 28, 28, 28, 28, 36, 36, 36, 36, 36,
        36, 6, 6,
    6, 6, 6, 6, 6, 14, 14, 14, 14, 14, 14, 22, 22, 22, 22, 22, 22, 22, 30, 30, 30, 30, 30, 30, 38, 38, 38, 38, 38,
        38, 38, 38,
    39, 39, 39, 39, 39, 39, 39, 31, 31, 31, 31, 31, 31, 31, 23, 23, 23, 23, 23, 23, 15, 15, 15, 15, 15, 15, 15,
        7, 7, 7, 7, 7,
    7, 37, 37, 37, 37, 37, 37, 37, 29, 29, 29, 29, 29, 29, 21, 21, 21, 21, 21, 21, 21, 13, 13, 13, 13, 13, 13,
        5, 5, 5, 5, 5,
    5, 5, 35, 35, 35, 35, 35, 35, 27, 27, 27, 27, 27, 27, 27, 19, 19, 19, 19, 19, 19, 11, 11, 11, 11, 11, 11,
        11, 3, 3, 3, 3,
    3, 3, 33, 33, 33, 33, 33, 33, 33, 25, 25, 25, 25, 25, 25, 17, 17, 17, 17, 17, 17, 17, 9, 9, 9, 9, 9, 9, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
        4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
        20, 6, 6,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 22, 22, 22, 22, 22, 22, 22, 22, 22,
        22, 22, 22,
    23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 7, 7, 7, 7, 7,
        7, 7, 7, 7,
    7, 7, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 5, 5, 5, 5,
        5, 5, 5, 5,
    5, 5, 5, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 3, 3, 3,
        3, 3, 3, 3,
    3, 3, 3, 3, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 1, 1, 1, 1, 1, 1,
};

__constant int cqUnquant[NUM_CQ][40] = {
    {0, 255, 51, 204, 102, 153},
    {0, 36, 73, 109, 146, 182, 219, 255},
    {0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255},
    {0, 255, 67, 188, 13, 242, 80, 175, 27, 228, 94, 161, 40, 215, 107, 148, 54, 201, 121, 134},
    {0, 8, 16, 24, 33, 41, 49, 57, 66, 74, 82, 90, 99, 107, 115, 123, 132, 140, 148, 156, 165, 173, 181, 189,
        198, 206, 214, 222, 231, 239, 247, 255},
    {0, 255, 32, 223, 65, 190, 97, 158, 6, 249, 39, 216, 71, 184, 104, 151, 13, 242, 45, 210,
        78, 177, 110, 145, 19, 236, 52, 203, 84, 171, 117, 138, 26, 229, 58, 197, 91, 164, 123, 132},
    {0, 255, 33, 222, 66, 189, 99, 156, 11, 244, 44, 211, 77, 178, 110, 145, 22, 233, 55, 200, 88, 167, 121, 134}
};

int WqIndex(QuantMethod quant)
{
    switch (quant) {
    case QUANT_3:  return 0;
    case QUANT_5:  return 1;
    case QUANT_6:  return 2;
    case QUANT_10: return 3;
    case QUANT_4:  return 4;
    case QUANT_8:  return 5;
    default:       return 0;
    }
}

int CqIndex(QuantMethod quant)
{
    switch (quant) {
    case QUANT_6:  return 0;
    case QUANT_8:  return 1;
    case QUANT_16: return 2;
    case QUANT_20: return 3;
    case QUANT_32: return 4;
    case QUANT_40: return 5;
    case QUANT_24: return 6;
    default:       return 0;
    }
}

__constant unsigned char trits[243] = {
    0, 1, 2, 4, 5, 6, 8, 9, 10,
    16, 17, 18, 20, 21, 22, 24, 25, 26,
    3, 7, 15, 19, 23, 27, 12, 13, 14,
    32, 33, 34, 36, 37, 38, 40, 41, 42,
    48, 49, 50, 52, 53, 54, 56, 57, 58,
    35, 39, 47, 51, 55, 59, 44, 45, 46,
    64, 65, 66, 68, 69, 70, 72, 73, 74,
    80, 81, 82, 84, 85, 86, 88, 89, 90,
    67, 71, 79, 83, 87, 91, 76, 77, 78,
    128, 129, 130, 132, 133, 134, 136, 137, 138,
    144, 145, 146, 148, 149, 150, 152, 153, 154,
    131, 135, 143, 147, 151, 155, 140, 141, 142,
    160, 161, 162, 164, 165, 166, 168, 169, 170,
    176, 177, 178, 180, 181, 182, 184, 185, 186,
    163, 167, 175, 179, 183, 187, 172, 173, 174,
    192, 193, 194, 196, 197, 198, 200, 201, 202,
    208, 209, 210, 212, 213, 214, 216, 217, 218,
    195, 199, 207, 211, 215, 219, 204, 205, 206,
    96, 97, 98, 100, 101, 102, 104, 105, 106,
    112, 113, 114, 116, 117, 118, 120, 121, 122,
    99, 103, 111, 115, 119, 123, 108, 109, 110,
    224, 225, 226, 228, 229, 230, 232, 233, 234,
    240, 241, 242, 244, 245, 246, 248, 249, 250,
    227, 231, 239, 243, 247, 251, 236, 237, 238,
    28, 29, 30, 60, 61, 62, 92, 93, 94,
    156, 157, 158, 188, 189, 190, 220, 221, 222,
    31, 63, 127, 159, 191, 255, 252, 253, 254
};

__constant unsigned char quints[125] = {
    0, 1, 2, 3, 4, 8, 9, 10, 11, 12,
    16, 17, 18, 19, 20, 24, 25, 26, 27, 28,
    5, 13, 21, 29, 6, 32, 33, 34, 35, 36,
    40, 41, 42, 43, 44, 48, 49, 50, 51, 52,
    56, 57, 58, 59, 60, 37, 45, 53, 61, 14,
    64, 65, 66, 67, 68, 72, 73, 74, 75, 76,
    80, 81, 82, 83, 84, 88, 89, 90, 91, 92,
    69, 77, 85, 93, 22, 96, 97, 98, 99, 100,
    104, 105, 106, 107, 108, 112, 113, 114, 115, 116,
    120, 121, 122, 123, 124, 101, 109, 117, 125, 30,
    102, 103, 70, 71, 38, 110, 111, 78, 79, 46,
    118, 119, 86, 87, 54, 126, 127, 94, 95, 62,
    39, 47, 55, 63, 31
};

void TexelToGrid(uint x, uint y, uint gridW, uint gridH, uint gridIdx[4], int gridCoeff[4])
{
    int xfp = ((1024 + DIM / 2) / (DIM - 1)) * (int)x * (int)(gridW - 1) + 32;
    int yfp = ((1024 + DIM / 2) / (DIM - 1)) * (int)y * (int)(gridH - 1) + 32;
    xfp >>= 6;
    yfp >>= 6;
    int fx = xfp & 15;
    int fy = yfp & 15;
    int ix = xfp >> 4;
    int iy = yfp >> 4;
    int prod = (fx * fy + 8) >> 4;
    gridIdx[0] = (uint)(ix + iy * (int)gridW);
    gridIdx[1] = gridIdx[0] + 1;
    gridIdx[2] = gridIdx[0] + gridW;
    gridIdx[3] = gridIdx[2] + 1;
    gridCoeff[3] = prod;
    gridCoeff[1] = fx - prod;
    gridCoeff[2] = fy - prod;
    gridCoeff[0] = 16 - fx - fy + prod;
}

void UpsampleGrid(const float gridWeights[MAX_GRID], uint gridW, uint gridH, float texelWeights[BLOCK_SIZE])
{
    uint gridIdx[4] = {0};
    int gridCoeff[4] = {0};
    for (uint y = 0; y < DIM; ++y) {
        for (uint x = 0; x < DIM; ++x) {
            uint t = y * DIM + x;
            TexelToGrid(x, y, gridW, gridH, gridIdx, gridCoeff);
            float acc = 0.0f;
            for (uint i = 0; i < 4; ++i) {
                if (gridCoeff[i] != 0) {
                    acc += gridWeights[gridIdx[i]] * (float)gridCoeff[i];
                }
            }
            texelWeights[t] = acc * (1.0f / 16.0f);
        }
    }
}

void computeAvgsAndDirs3Comp(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi,
                             float4 avg[BLOCK_MAX_PARTITIONS], float4 dir[BLOCK_MAX_PARTITIONS])
{
    float4 zero = {0.0f, 0.0f, 0.0f, 0.0f};
    for (uint p = 0; p < pi->partitionCount; ++p) {
        avg[p] = zero;
        dir[p] = zero;
        uint count = 0;
        for (uint t = 0; t < BLOCK_SIZE; ++t) {
            if (pi->partitioningPattern[t] != p) {
                continue;
            }
            avg[p] += blk[t];
            count++;
        }
        float invCount = 1.0f / (float)max(count, (uint)1);
        avg[p] *= invCount;

        float4 sumX = zero;
        float4 sumY = zero;
        float4 sumZ = zero;
        for (uint t = 0; t < BLOCK_SIZE; ++t) {
            if (pi->partitioningPattern[t] != p) {
                continue;
            }
            float4 d = blk[t] - avg[p];
            int4 tdm0 = d.xxxx > zero;
            sumX += select(zero, d, tdm0);
            int4 tdm1 = d.yyyy > zero;
            sumY += select(zero, d, tdm1);
            int4 tdm2 = d.zzzz > zero;
            sumZ += select(zero, d, tdm2);
        }
        float dotX = dot(sumX, sumX);
        float dotY = dot(sumY, sumY);
        float dotZ = dot(sumZ, sumZ);

        dir[p] = sumX;
        float maxDot = dotX;

        int mask = dotY > maxDot;
        dir[p] = select(dir[p], sumY, (int4)(-mask));
        maxDot = mask ? dotY : maxDot;

        mask = dotZ > maxDot;
        dir[p] = select(dir[p], sumZ, (int4)(-mask));
    }
}

void Normalize3(float4* v)
{
    float len = length(v->xyz);
    if (len > 1e-20f) {
        v->xyz /= len;
    } else {
        v->xyz = (float3)(0.577350269f);
    }
}

void ComputeIdealColorsAndWeights3Comp(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi,
                                       float idealWeights[BLOCK_SIZE],
                                       float4 idealEP0[BLOCK_MAX_PARTITIONS], float4 idealEP1[BLOCK_MAX_PARTITIONS],
                                       float weightErrScale[BLOCK_SIZE])
{
    float4 avgs[BLOCK_MAX_PARTITIONS];
    float4 dirs[BLOCK_MAX_PARTITIONS];
    computeAvgsAndDirs3Comp(blk, pi, avgs, dirs);

    float4 zero = {0.0f, 0.0f, 0.0f, 0.0f};
    for (uint p = 0; p < pi->partitionCount; ++p) {
        float4 avg = avgs[p];
        float4 dir = dirs[p];

        if (dir.x + dir.y + dir.z < 0.0f) {
            dir.xyz = -dir.xyz;
        }
        Normalize3(&dir);

        float low = 1e10f;
        float high = -1e10f;
        for (uint t = 0; t < BLOCK_SIZE; ++t) {
            if (pi->partitioningPattern[t] != p) {
                continue;
            }
            float param = dot(blk[t] - avg, dir);
            idealWeights[t] = param;
            low = fmin(low, param);
            high = fmax(high, param);
        }
        if (high <= low) {
            low = 0.0f;
            high = 1e-7f;
        }

        float length = high - low;
        float lengthSq = length * length;
        float scale = 1.0f / length;
        for (uint t = 0; t < BLOCK_SIZE; ++t) {
            if (pi->partitioningPattern[t] != p) {
                continue;
            }
            float w = clamp((idealWeights[t] - low) * scale, 0.0f, 1.0f);
            idealWeights[t] = w;
            weightErrScale[t] = lengthSq;
        }
        idealEP0[p] = avg + dir * low;
        idealEP1[p] = avg + dir * high;
    }
}

void ComputeGridIdealWeights(const float idealWeights[BLOCK_SIZE], uint gridW, uint gridH,
                             const float weightErrScale[BLOCK_SIZE], float gridIdealWeights[MAX_GRID])
{
    uint gridNum = gridW * gridH;
    float gridAcc[MAX_GRID];
    float coeffSum[MAX_GRID];
    for (uint g = 0; g < gridNum; ++g) {
        gridAcc[g] = 0.0f;
        coeffSum[g] = 1e-10f;
    }

    uint gridIdx[4] = {0};
    int gridCoeff[4] = {0};
    for (uint y = 0; y < DIM; ++y) {
        for (uint x = 0; x < DIM; ++x) {
            uint t = y * DIM + x;
            TexelToGrid(x, y, gridW, gridH, gridIdx, gridCoeff);
            for (uint i = 0; i < 4; ++i) {
                if (gridCoeff[i] == 0) {
                    continue;
                }
                uint gIdx = gridIdx[i];
                float gCoeff = (float)gridCoeff[i] * (1.0f / 16.0f);
                float cw = gCoeff * weightErrScale[t];
                gridAcc[gIdx] += idealWeights[t] * cw;
                coeffSum[gIdx] += cw;
            }
        }
    }
    for (uint g = 0; g < gridNum; ++g) {
        gridIdealWeights[g] = gridAcc[g] / coeffSum[g];
    }

    float infill[BLOCK_SIZE];
    UpsampleGrid(gridIdealWeights, gridW, gridH, infill);

    float gridDiff[MAX_GRID];
    float den[MAX_GRID];
    for (uint g = 0; g < gridNum; ++g) {
        gridDiff[g] = 0.0f;
        den[g] = 1e-10f;
    }
    for (uint y = 0; y < DIM; ++y) {
        for (uint x = 0; x < DIM; ++x) {
            uint t = y * DIM + x;
            float d = idealWeights[t] - infill[t];
            TexelToGrid(x, y, gridW, gridH, gridIdx, gridCoeff);
            for (uint i = 0; i < 4; ++i) {
                if (gridCoeff[i] == 0) {
                    continue;
                }
                uint gIdx = gridIdx[i];
                float gCoeff = (float)gridCoeff[i] * (1.0f / 16.0f);
                gridDiff[gIdx] += weightErrScale[t] * gCoeff * d;
                den[gIdx] += weightErrScale[t] * gCoeff * gCoeff;
            }
        }
    }

    for (uint g = 0; g < gridNum; ++g) {
        gridIdealWeights[g] += clamp(gridDiff[g] / den[g], -0.25f, 0.25f);
    }
}

void QuantAndIUnquantGridWeights(const float gridIdealWeights[MAX_GRID], uint gridNum, QuantMethod quant,
                                 uchar gridQuantWeights[MAX_GRID], float gridUnquantWeights[MAX_GRID])
{
    int wqIdx = WqIndex(quant);
    int wqLevel = wqLevels[wqIdx];
    __constant int* wqScrambleArr = wqScramble[wqIdx];
    __constant int* wqUnquantArr = wqUnquant[wqIdx];
    for (uint g = 0; g < gridNum; ++g) {
        float gt = clamp(gridIdealWeights[g],  0.0f, 1.0f);
        int bestQ = 0;
        float bestD = LARGE_FLOAT;
        float bestU = 0.0f;
        for (int q = 0; q < wqLevel; ++q) {
            int sq = wqScrambleArr[q];
            float u = (float)wqUnquantArr[sq] * (1.0f / 64.0f);
            float d = fabs(u - gt);
            if (d < bestD || (d == bestD && u > bestU)) {
                bestD = d;
                bestQ = q;
                bestU = u;
            }
        }
        int sq = wqScrambleArr[bestQ];
        gridQuantWeights[g] = (uchar)sq;
        gridUnquantWeights[g] = (float)wqUnquantArr[sq] * (1.0f / 64.0f);
    }
}

int QuantizeColorLevel(float v, int cq)
{
    float vc = clamp(v, 0.0f, PIXEL_MAX_VALUE);
    int lo = (int)floor(vc);
    int hi = min(lo + 1, 255);
    int ql = (int)cqNearest[cq][lo];
    int qh = (int)cqNearest[cq][hi];
    float ul = (float)cqUnquant[cq][ql];
    float uh = (float)cqUnquant[cq][qh];
    float dl = fabs(ul - vc);
    float dh = fabs(uh - vc);
    if (dh < dl || (dh == dl && uh > ul)) {
        return qh;
    }
    return ql;
}

void PackCEM8(const float4 ep0, const float4 ep1, int cq, uchar4* qEP0, uchar4* qEP1, float4* uqEP0, float4* uqEP1)
{
    uchar4 qEP0Best;
    uchar4 qEP1Best;
    float4 uqEP0Best;
    float4 uqEP1Best;

    __constant int* cqUnquantArr = cqUnquant[cq];

    // direct
    float4 e0 = ep0;
    float4 e1 = ep1;
    uchar4 qe0;
    uchar4 qe1;
    for (int guard = 0; guard < 32; ++guard) {
        qe0 = (uchar4)(QuantizeColorLevel(e0.x, cq), QuantizeColorLevel(e0.y, cq), QuantizeColorLevel(e0.z, cq), 0);
        qe1 = (uchar4)(QuantizeColorLevel(e1.x, cq), QuantizeColorLevel(e1.y, cq), QuantizeColorLevel(e1.z, cq), 0);
        float s0 = (float)(cqUnquantArr[qe0.x] + cqUnquantArr[qe0.y] + cqUnquantArr[qe0.z]);
        float s1 = (float)(cqUnquantArr[qe1.x] + cqUnquantArr[qe1.y] + cqUnquantArr[qe1.z]);
        if (s0 <= s1) {
            break;
        }
        e0 = (float4)((e0 - 0.2f).xyz, 0.0f);
        e1 = (float4)((e1 + 0.2f).xyz, 0.0f);
    }

    qEP0Best = qe0;
    qEP1Best = qe1;
    uqEP0Best = (float4)(cqUnquantArr[qe0.x], cqUnquantArr[qe0.y], cqUnquantArr[qe0.z], 0.0f);
    uqEP1Best= (float4)(cqUnquantArr[qe1.x], cqUnquantArr[qe1.y], cqUnquantArr[qe1.z], 0.0f);

    float bestErr = dot((ep0 - uqEP0Best).xyz, (ep0 - uqEP0Best).xyz) +
                    dot((ep1 - uqEP1Best).xyz, (ep1 - uqEP1Best).xyz);

    // blue contraction
    float4 b0 = (float4)(2.0f * ep0.x - ep0.z, 2.0f * ep0.y - ep0.z, ep0.z, 0.0f);
    float4 b1 = (float4)(2.0f * ep1.x - ep1.z, 2.0f * ep1.y - ep1.z, ep1.z, 0.0f);
    bool inRange = all(b0.xyz >= 0.0f) && all(b0.xyz <= PIXEL_MAX_VALUE) &&
                   all(b1.xyz >= 0.0f) && all(b1.xyz <= PIXEL_MAX_VALUE);
    if (inRange) {
        uchar4 bq0 = (uchar4)(QuantizeColorLevel(b0.x, cq), QuantizeColorLevel(b0.y, cq),
                              QuantizeColorLevel(b0.z, cq), 0);
        uchar4 bq1 = (uchar4)(QuantizeColorLevel(b1.x, cq), QuantizeColorLevel(b1.y, cq),
                              QuantizeColorLevel(b1.z, cq), 0);
        float s0 = (float)(cqUnquantArr[bq0.x] + cqUnquantArr[bq0.y] + cqUnquantArr[bq0.z]);
        float s1 = (float)(cqUnquantArr[bq1.x] + cqUnquantArr[bq1.y] + cqUnquantArr[bq1.z]);
        if (s1 > s0) {
            float4 u0 = (float4)(cqUnquantArr[bq1.x], cqUnquantArr[bq1.y], cqUnquantArr[bq1.z], 0.0f);
            float4 u1 = (float4)(cqUnquantArr[bq0.x], cqUnquantArr[bq0.y], cqUnquantArr[bq0.z], 0.0f);
            float4 d0 = (float4)((u0.x + u0.z) * 0.5f, (u0.y + u0.z) * 0.5f, u0.z, 0.0f);
            float4 d1 = (float4)((u1.x + u1.z) * 0.5f, (u1.y + u1.z) * 0.5f, u1.z, 0.0f);
            float4 diff0 = ep0 - d0;
            float4 diff1 = ep1 - d1;
            float bcErr = dot(diff0.xyz, diff0.xyz) + dot(diff1.xyz, diff1.xyz);
            if (bcErr < bestErr) {
                qEP0Best = bq1;
                qEP1Best = bq0;
                uqEP0Best = d0;
                uqEP1Best = d1;
            }
        }
    }
    *qEP0 = qEP0Best;
    *qEP1 = qEP1Best;
    *uqEP0 = uqEP0Best;
    *uqEP1 = uqEP1Best;
}

void RecomputeIdealColors(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi,
                          const float recWeights[BLOCK_SIZE],
                          float4 idealEP0[BLOCK_MAX_PARTITIONS], float4 idealEP1[BLOCK_MAX_PARTITIONS])
{
    for (uint p = 0; p < pi->partitionCount; ++p) {
        float left = 0.0f;
        float middle = 0.0f;
        float right = 0.0f;
        float4 cx = {0.0f, 0.0f, 0.0f, 0.0f};
        float4 cy = {0.0f, 0.0f, 0.0f, 0.0f};
        float4 sum = {0.0f, 0.0f, 0.0f, 0.0f};
        float wmin = 1.0f;
        float wmax = 0.0f;
        uint count = 0;

        for (uint t = 0; t < BLOCK_SIZE; ++t) {
            if (pi->partitioningPattern[t] != p) {
                continue;
            }
            float w = recWeights[t];
            float om = 1.0f - w;
            left += om * om;
            middle += om * w;
            right += w * w;
            cx += om * blk[t];
            cy += w * blk[t];
            sum += blk[t];
            wmin = fmin(wmin, w);
            wmax = fmax(wmax, w);
            count++;
        }
        if (count == 0) {
            continue;
        }

        if (wmin >= wmax * 0.999f) {
            // all weights equal: both endpoints become the partition mean
            float inv = 1.0f / (float)count;
            float4 mean = sum * inv;
            idealEP0[p] = mean;
            idealEP1[p] = mean;
            continue;
        }

        float det = left * right - middle * middle;
        float mss = left * left + 2.0f * middle * middle + right * right;
        if (fabs(det) > mss * 1e-4f) {
            float4 a0;
            float4 b0;
            bool valid = true;
            a0 = (right * cx - middle * cy) / det;
            b0 = (left * cy - middle * cx) / det;
            valid = valid && all(a0 == a0) && all(b0 == b0);
            if (valid) {
                idealEP0[p] = a0;
                idealEP1[p] = b0;
            }
        }
    }
}

void BuildGridMap(uint gridW, uint gridH, uint gridPointTexelCount[MAX_GRID],
                  uint gridPointTexelList[MAX_GRID][MAX_GRID_POINT_TEXEL_2D],
                  float gridPointTexelContribList[MAX_GRID][MAX_GRID_POINT_TEXEL_2D])
{
    for (uint y = 0; y < DIM; ++y) {
        for (uint x = 0; x < DIM; ++x) {
            uint t = y * DIM + x;
            uint gridIdx[4] = {0};
            int gridCoeff[4] = {0};
            TexelToGrid(x, y, gridW, gridH, gridIdx, gridCoeff);
            for (uint i = 0; i < 4; ++i) {
                if (gridCoeff[i] == 0) {
                    continue;
                }
                uint g = gridIdx[i];
                uint slot = gridPointTexelCount[g];
                if (slot < MAX_GRID_POINT_TEXEL_2D) {
                    gridPointTexelList[g][slot] = t;
                    gridPointTexelContribList[g][slot] = (float)gridCoeff[i] * (1.0f / 16.0f);
                    gridPointTexelCount[g] = slot + 1;
                }
            }
        }
    }
}

bool RealignWeights(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi, QuantMethod quant,
                    const float4 uqEP0[BLOCK_MAX_PARTITIONS], const float4 uqEP1[BLOCK_MAX_PARTITIONS],
                    const uint gridPointTexelCount[MAX_GRID],
                    const uint gridPointTexelList[MAX_GRID][MAX_GRID_POINT_TEXEL_2D],
                    const float gridPointTexelContribList[MAX_GRID][MAX_GRID_POINT_TEXEL_2D],
                    uchar gridQuantWeights[MAX_GRID], float gridUnquantWeights[MAX_GRID], float recWeights[BLOCK_SIZE])
{
    bool adjustments = false;
    int wqIdx = WqIndex(quant);
    int wqLevel = wqLevels[wqIdx];
    __constant int* wqScrambleArr = wqScramble[wqIdx];
    __constant int* wqUnscrambleArr = wqUnscramble[wqIdx];
    __constant int* wqUnquantArr = wqUnquant[wqIdx];

    const float4 ed[BLOCK_MAX_PARTITIONS] = {uqEP1[0] - uqEP0[0], uqEP1[1] - uqEP0[1], uqEP1[2] - uqEP0[2]};
    const float edDot[BLOCK_MAX_PARTITIONS] = {dot(ed[0], ed[0]), dot(ed[1], ed[1]), dot(ed[2], ed[2])};

    for (uint g = 0; g < MAX_GRID; ++g) {
        uint count = gridPointTexelCount[g];
        if (count == 0) {
            continue;
        }
        int qBase = wqUnscrambleArr[gridQuantWeights[g]];
        float baseGW = gridUnquantWeights[g];
        float downGW = baseGW;
        float upGW = baseGW;
        if (qBase > 0) {
            downGW = (float)wqUnquantArr[wqScrambleArr[qBase - 1]] * (1.0f / 64.0f);
        }
        if (qBase < wqLevel - 1) {
            upGW = (float)wqUnquantArr[wqScrambleArr[qBase + 1]] * (1.0f / 64.0f);
        }

        float errorBase = 0.0f;
        float errorDown = 0.0f;
        float errorUp = 0.0f;
        for (uint tIdx = 0; tIdx < count; ++tIdx) {
            uint t = gridPointTexelList[g][tIdx];
            float coeff = gridPointTexelContribList[g][tIdx];
            uint p = pi->partitioningPattern[t];

            float baseW = recWeights[t];
            float4 baseRes = (uqEP0[p] + baseW * ed[p]) - blk[t];
            float baseError = dot(baseRes, baseRes);

            // err(baseW+ dw) = baseError + 2*dw*dot(baseRes, ed) + dw^2*dot(ed, ed)
            float dotResEd = dot(baseRes, ed[p]);
            float dwd = coeff * (downGW - baseGW);
            float dwu = coeff * (upGW - baseGW);
            errorBase += baseError;
            errorDown += baseError + 2.0f * dwd * dotResEd + dwd * dwd * edDot[p];
            errorUp += baseError + 2.0f * dwu * dotResEd + dwu * dwu * edDot[p];
        }

        int qNew = -1;
        float newGW = baseGW;
        if (errorUp < errorBase && errorUp < errorDown && qBase < wqLevel - 1) {
            qNew = qBase + 1;
            newGW = upGW;
        } else if (errorDown < errorBase && qBase > 0) {
            qNew = qBase - 1;
            newGW = downGW;
        }
        if (qNew < 0) {
            continue;
        }

        gridQuantWeights[g] = (uchar)wqScrambleArr[qNew];
        gridUnquantWeights[g] = newGW;
        float delta = newGW - baseGW;
        for (uint tIdx = 0; tIdx < count; ++tIdx) {
            uint t = gridPointTexelList[g][tIdx];
            recWeights[t] += gridPointTexelContribList[g][tIdx] * delta;
        }
        adjustments = true;
    }

    return adjustments;
}

float ComputeBlockError(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi,
                        const float recWeights[BLOCK_SIZE],
                        const float4 uqEP0[BLOCK_MAX_PARTITIONS], const float4 uqEP1[BLOCK_MAX_PARTITIONS])
{
    float err = 0.0f;
    for (uint t = 0; t < BLOCK_SIZE; ++t) {
        float w = recWeights[t];
        uint p = pi->partitioningPattern[t];
        float4 rec = uqEP0[p] + w * (uqEP1[p] - uqEP0[p]);
        float4 d = blk[t] - rec;
        err += dot(d, d);
    }
    return err;
}

void KmeansInit(const float4 blk[BLOCK_SIZE], uint partitionCount,
                float4 clusterCenters[BLOCK_MAX_PARTITIONS])
{
    uint clustersSelected = 0;

    uint sample = 145897 % BLOCK_SIZE;
    float4 color = blk[sample];
    clusterCenters[clustersSelected++] = color;

    float distanceSum = 0.0f;
    float distances[BLOCK_SIZE];
    for (uint i = 0; i < BLOCK_SIZE; ++i) {
        color = blk[i];
        float4 diff = color - clusterCenters[clustersSelected - 1];
        float distance = dot(diff, diff);
        distanceSum += distance;
        distances[i] = distance;
    }

    const float clusterCutoffs[9] = {
        0.626220f, 0.932770f, 0.275454f,
        0.318558f, 0.240113f, 0.009190f,
        0.347661f, 0.731960f, 0.156391f
    };
    uint cutoff = (clustersSelected - 1) + 3 * (partitionCount - 2);
    while (true) {
        float summa = 0.0f;
        float distanceCutoff = distanceSum * clusterCutoffs[cutoff++];
        for (sample = 0; sample < BLOCK_SIZE; ++sample) {
            summa += distances[sample];
            if (summa >= distanceCutoff) {
                break;
            }
        }

        sample = min(sample, (uint)(BLOCK_SIZE - 1));
        color = blk[sample];
        clusterCenters[clustersSelected++] = color;
        if (clustersSelected >= partitionCount) {
            break;
        }

        distanceSum = 0.0f;
        for (uint i = 0; i < BLOCK_SIZE; ++i) {
            float4 diff = blk[i] - color;
            float distance = dot(diff, diff);
            distance = fmin(distance, distances[i]);
            distanceSum += distance;
            distances[i] = distance;
        }
    }
}

void KmeansUpdate(const float4 blk[BLOCK_SIZE], uint partitionCount,
                  float4 clusterCenters[BLOCK_MAX_PARTITIONS],
                  const uint texelCluster[BLOCK_SIZE])
{
    float4 colorSum[BLOCK_MAX_PARTITIONS] = {
        (float4)(0.0f, 0.0f, 0.0f, 0.0f),
        (float4)(0.0f, 0.0f, 0.0f, 0.0f),
        (float4)(0.0f, 0.0f, 0.0f, 0.0f)
    };
    uint partitionTexelCount[BLOCK_MAX_PARTITIONS] = {0};

    for (uint i = 0; i < BLOCK_SIZE; ++i) {
        uint cluster = texelCluster[i];
        colorSum[cluster] += blk[i];
        partitionTexelCount[cluster]++;
    }

    for (uint i = 0; i < partitionCount; ++i) {
        float scale = 1.0f / (float)max(partitionTexelCount[i], (uint)1);
        clusterCenters[i] = colorSum[i] * scale;
    }
}

void KmeansAssign(const float4 blk[BLOCK_SIZE], uint partitionCount,
                  const float4 clusterCenters[BLOCK_MAX_PARTITIONS],
                  uint texelCluster[BLOCK_SIZE])
{
    uint partitionTexelCount[BLOCK_MAX_PARTITIONS] = {0};

    for (uint i = 0; i < BLOCK_SIZE; ++i) {
        float bestDistance = LARGE_FLOAT;
        uint bestPartition = 0;

        float4 color = blk[i];
        for (uint j = 0; j < partitionCount; ++j) {
            float4 diff = color - clusterCenters[j];
            float distance = dot(diff, diff);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestPartition = j;
            }
        }

        texelCluster[i] = bestPartition;
        partitionTexelCount[bestPartition]++;
    }

    bool problemCase;
    do {
        problemCase = false;
        for (uint i = 0; i < partitionCount; ++i) {
            if (partitionTexelCount[i] == 0) {
                partitionTexelCount[texelCluster[i]]--;
                partitionTexelCount[i]++;
                texelCluster[i] = i;
                problemCase = true;
            }
        }
    } while (problemCase);
}

bool ShouldSkipPartitionSearch(const float4 clusterCenters[BLOCK_MAX_PARTITIONS],
                               const uint texelCluster[BLOCK_SIZE],
                               uint partitionCount)
{
    uint clusterCounts[BLOCK_MAX_PARTITIONS] = {0};
    for (uint i = 0; i < BLOCK_SIZE; ++i) {
        clusterCounts[texelCluster[i]]++;
    }

    float minClusterRatio = (partitionCount == 3) ? 0.08f : 0.10f;
    for (uint i = 0; i < partitionCount; ++i) {
        float ratio = (float)(clusterCounts[i]) / (float)(BLOCK_SIZE);
        if (ratio < minClusterRatio) {
            return true;
        }
    }

    float minCenterDistance = LARGE_FLOAT;
    for (uint i = 0; i < partitionCount; ++i) {
        for (uint j = i + 1; j < partitionCount; ++j) {
            float4 diff = clusterCenters[i] - clusterCenters[j];
            minCenterDistance = fmin(minCenterDistance, dot(diff, diff));
        }
    }

    return minCenterDistance < 400.0f;
}

void ScorePartitionCandidate(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi, float* uncorCError)
{
    float4 avgs[BLOCK_MAX_PARTITIONS];
    float4 dirs[BLOCK_MAX_PARTITIONS];
    computeAvgsAndDirs3Comp(blk, pi, avgs, dirs);

    const float weightImprecision = 0.05f * 0.05f;
    float uncorCErr = 0.0f;
    for (uint p = 0; p < pi->partitionCount; ++p) {
        float4 dir = dirs[p];
        float4 avg = avgs[p];

        float4 diffCDirN = dir;
        Normalize3(&diffCDirN);

        float4 diffCOffset = avg - diffCDirN * dot(avg, diffCDirN);

        float low = 1e10f;
        float high = -1e10f;
        uint count = 0;
        for (uint t = 0; t < BLOCK_SIZE; ++t) {
            if (pi->partitioningPattern[t] != p) {
                continue;
            }
            // uncorrelated color projection
            float uparam = dot(blk[t].xyz, diffCDirN.xyz);

            low = fmin(low, uparam);
            high = fmax(high, uparam);

            float4 diffCMod = diffCOffset + uparam * diffCDirN - blk[t] ;
            uncorCErr += dot(diffCMod.xyz, diffCMod.xyz);

            ++count;
        }
        float lineLength = fmax(high - low, 1e-7f);
        float imprecision = lineLength * lineLength * weightImprecision * (float)count;
        uncorCErr += imprecision;
    }
    *uncorCError = uncorCErr;
}

uint FindBestPartitioning(const float4 blk[BLOCK_SIZE], uint partitionCount, int outIdx[2])
{
    float4 clusterCenters[BLOCK_MAX_PARTITIONS];
    uint texelCluster[BLOCK_SIZE];
    KmeansInit(blk, partitionCount, clusterCenters);
    for (uint i = 0; i < 2; ++i) {
        KmeansAssign(blk, partitionCount, clusterCenters, texelCluster);
        KmeansUpdate(blk, partitionCount, clusterCenters, texelCluster);
    }
    KmeansAssign(blk, partitionCount, clusterCenters, texelCluster);

    if (ShouldSkipPartitionSearch(clusterCenters, texelCluster, partitionCount)) {
        return 0;
    }

    __constant const PartitionInfo* candArr = (partitionCount == 3) ?
        PREDEF_PARTITION_INFO_3PART : PREDEF_PARTITION_INFO_2PART;
    uint candNum = (partitionCount == 3) ? NUM_PARTITIONING_3PART : NUM_PARTITIONING_2PART;

    float bestUncor = LARGE_FLOAT;
    int bestUncorIdx = -1;
    for (uint c = 0; c < candNum; ++c) {
        float uncorError;
        ScorePartitionCandidate(blk, &candArr[c], &uncorError);
        if (uncorError < bestUncor) {
            bestUncor = uncorError;
            bestUncorIdx = (int)c;
        }
    }

    if (bestUncorIdx < 0) {
        return 0;
    }
    outIdx[0] = bestUncorIdx;
    return 1;
}

void WriteBits(uchar block[PHYSICAL_BLOCK_BYTES], uint value, int count, int bitOffset)
{
    for (int i = 0; i < count; ++i) {
        if ((value >> i) & 1u) {
            int bit = bitOffset + i;
            block[bit >> 3] |= (uchar)(1 << (bit & 7));
        }
    }
}

void EncodeIse(uchar block[PHYSICAL_BLOCK_BYTES], int bitPos, const uchar* values,
               int count, int bits, int useTrits, int useQuints)
{
    int mask = (1 << bits) - 1;
    int i = 0;
    if (useTrits) {
        int full = count / 5;
        const int tbits[5] = {2, 2, 1, 2, 1};
        const int tshift[5] = {0, 2, 4, 5, 7};
        for (int j = 0; j < full; ++j) {
            int i0 = values[i + 0] >> bits;
            int i1 = values[i + 1] >> bits;
            int i2 = values[i + 2] >> bits;
            int i3 = values[i + 3] >> bits;
            int i4 = values[i + 4] >> bits;
            int t = trits[i4 * 81 + i3 * 27 + i2 * 9 + i1 * 3 + i0];
            for (int e = 0; e < 5; ++e) {
                uint pack = (uint)((values[i] & mask) |
                    (((t >> tshift[e]) & ((1 << tbits[e]) - 1)) << bits));
                WriteBits(block, pack, bits + tbits[e], bitPos);
                bitPos += bits + tbits[e];
                i++;
            }
        }
        if (i != count) {
            int i0 = values[i] >> bits;
            int i1 = (i + 1 < count) ? (values[i + 1] >> bits) : 0;
            int i2 = (i + 2 < count) ? (values[i + 2] >> bits) : 0;
            int i3 = (i + 3 < count) ? (values[i + 3] >> bits) : 0;
            int t = trits[i3 * 27 + i2 * 9 + i1 * 3 + i0];
            const int tbits[4] = {2, 2, 1, 2};
            const int tshift[4] = {0, 2, 4, 5};
            for (int e = 0; i < count; ++i, ++e) {
                uint pack = (uint)((values[i] & mask) |
                    (((t >> tshift[e]) & ((1 << tbits[e]) - 1)) << bits));
                WriteBits(block, pack, bits + tbits[e], bitPos);
                bitPos += bits + tbits[e];
            }
        }
    } else if (useQuints) {
        int full = count / 3;
        const int qbits[3] = {3, 2, 2};
        const int qshift[3] = {0, 3, 5};
        for (int j = 0; j < full; ++j) {
            int i0 = values[i + 0] >> bits;
            int i1 = values[i + 1] >> bits;
            int i2 = values[i + 2] >> bits;
            int t = quints[i2 * 25 + i1 * 5 + i0];
            for (int e = 0; e < 3; ++e) {
                uint pack = (uint)((values[i] & mask) |
                    (((t >> qshift[e]) & ((1 << qbits[e]) - 1)) << bits));
                WriteBits(block, pack, bits + qbits[e], bitPos);
                bitPos += bits + qbits[e];
                i++;
            }
        }
        if (i != count) {
            int i0 = values[i] >> bits;
            int i1 = (i + 1 < count) ? (values[i + 1] >> bits) : 0;
            int t = quints[i1 * 5 + i0];
            const int qbits[2] = {3, 2};
            const int qshift[2] = {0, 3};
            for (int e = 0; i < count; ++i, ++e) {
                uint pack = (uint)((values[i] & mask) |
                    (((t >> qshift[e]) & ((1 << qbits[e]) - 1)) << bits));
                WriteBits(block, pack, bits + qbits[e], bitPos);
                bitPos += bits + qbits[e];
            }
        }
    } else {
        for (i = 0; i < count; ++i) {
            WriteBits(block, (uint)values[i], bits, bitPos);
            bitPos += bits;
        }
    }
}

void WriteBitstream(__constant const Mode* mode, __constant const PartitionInfo* pi,
                    uchar qw[BLOCK_SIZE], uchar4 qep0[BLOCK_MAX_PARTITIONS], uchar4 qep1[BLOCK_MAX_PARTITIONS],
                    uchar out[PHYSICAL_BLOCK_BYTES])
{
    int wq = WqIndex(mode->wQuant);
    int cq = CqIndex(mode->epQuant);

    uchar block[PHYSICAL_BLOCK_BYTES] = {0};
    uchar wbuf[PHYSICAL_BLOCK_BYTES] = {0};
    EncodeIse(wbuf, 0, qw, (int)mode->gridNum, wqBits[wq], wqTrits[wq], wqQuints[wq]);
    for (int j = 0; j < PHYSICAL_BLOCK_BYTES; ++j) {
        for (int k = 0; k < 8; ++k) {
            int wbit = j * 8 + k;
            if (wbit >= (int)mode->wBits) {
                break;
            }
            if (wbuf[j] & (1 << k)) {
                int bbit = 127 - wbit;
                block[bbit >> 3] |= (uchar)(1 << (bbit & 7));
            }
        }
    }

    uint partitionCount = pi->partitionCount;
    int pos;
    WriteBits(block, mode->blockmodeIdx & 0x7FF, 11, 0);
    WriteBits(block, partitionCount - 1, 2, 11);
    if (partitionCount == 1) {
        WriteBits(block, 8, 4, 13);
        pos = 17;
    } else {
        WriteBits(block, pi->partitioningIdx & 0x3F, 6, 13);
        WriteBits(block, (pi->partitioningIdx >> 6) & 0xF, 4, 19);
        WriteBits(block, (uint)(32), 6, 23);
        pos = 29;
    }

    uchar colorVals[BLOCK_MAX_PARTITIONS * EP_INTEGER * 2];
    for (uint p = 0; p < partitionCount; ++p) {
        colorVals[p * EP_INTEGER * 2 + 0] = qep0[p].x;
        colorVals[p * EP_INTEGER * 2 + 1] = qep1[p].x;
        colorVals[p * EP_INTEGER * 2 + 2] = qep0[p].y;
        colorVals[p * EP_INTEGER * 2 + 3] = qep1[p].y;
        colorVals[p * EP_INTEGER * 2 + 4] = qep0[p].z;
        colorVals[p * EP_INTEGER * 2 + 5] = qep1[p].z;
    }
    EncodeIse(block, pos, colorVals, (int)(EP_INTEGER * 2 * partitionCount),
              cqBits[cq], cqTrits[cq], cqQuints[cq]);

    for (int i = 0; i < PHYSICAL_BLOCK_BYTES; ++i) {
        out[i] = block[i];
    }
}

typedef struct {
    float err;
    __constant const Mode* mode;
    __constant const PartitionInfo* pi;
    uchar qw[BLOCK_SIZE];
    uchar4 qep0[BLOCK_MAX_PARTITIONS];
    uchar4 qep1[BLOCK_MAX_PARTITIONS];
} BestState;

void InitBestState(BestState* best)
{
    best->err = LARGE_FLOAT;
    best->mode = 0;
    best->pi = 0;
}

void UpdateBestState(BestState* best, float err, __constant const Mode* mode, __constant const PartitionInfo* pi,
                     const uchar qw[BLOCK_SIZE], const uchar4 qep0[BLOCK_MAX_PARTITIONS],
                     const uchar4 qep1[BLOCK_MAX_PARTITIONS])
{
    if (err >= best->err) {
        return;
    }
    best->err = err;
    best->mode = mode;
    best->pi = pi;
    for (uint t = 0; t < BLOCK_SIZE; ++t) {
        best->qw[t] = qw[t];
    }
    for (uint p = 0; p < BLOCK_MAX_PARTITIONS; ++p) {
        best->qep0[p] = qep0[p];
        best->qep1[p] = qep1[p];
    }
}

void EncodeOneCandidate(const float4 blk[BLOCK_SIZE], __constant const Mode* mode, __constant const PartitionInfo* pi,
                        const float idealWeights[BLOCK_SIZE],
                        const float4 idealEP0[BLOCK_MAX_PARTITIONS], const float4 idealEP1[BLOCK_MAX_PARTITIONS],
                        const float weightErrScale[BLOCK_SIZE],
                        BestState* best)
{
    float gridIdealWeights[MAX_GRID];
    ComputeGridIdealWeights(idealWeights, mode->gridW, mode->gridH, weightErrScale, gridIdealWeights);

    uchar gridQuantWeights[MAX_GRID];
    float gridUnquantWeights[MAX_GRID];
    QuantAndIUnquantGridWeights(gridIdealWeights, mode->gridNum, mode->wQuant, gridQuantWeights, gridUnquantWeights);

    float recWeights[BLOCK_SIZE];
    UpsampleGrid(gridUnquantWeights, mode->gridW, mode->gridH, recWeights);

    uint gridPointTexelCount[MAX_GRID] = {0};
    uint gridPointTexelList[MAX_GRID][MAX_GRID_POINT_TEXEL_2D];
    float gridPointTexelContribList[MAX_GRID][MAX_GRID_POINT_TEXEL_2D];
    BuildGridMap(mode->gridW, mode->gridH, gridPointTexelCount, gridPointTexelList, gridPointTexelContribList);

    float4 ep0[BLOCK_MAX_PARTITIONS] = {idealEP0[0], idealEP0[1], idealEP0[2]};
    float4 ep1[BLOCK_MAX_PARTITIONS] = {idealEP1[0], idealEP1[1], idealEP1[2]};
    int iterations = (pi->partitionCount == 1) ? REFINE_ITERS_1PART : REFINE_ITERS_PART;
    for (int iter = 0; iter < iterations; ++iter) {
        RecomputeIdealColors(blk, pi, recWeights, ep0, ep1);
        uchar4 qep0[BLOCK_MAX_PARTITIONS];
        uchar4 qep1[BLOCK_MAX_PARTITIONS];
        float4 uqEP0[BLOCK_MAX_PARTITIONS];
        float4 uqEP1[BLOCK_MAX_PARTITIONS];
        for (uint p = 0; p < pi->partitionCount; ++p) {
            PackCEM8(ep0[p], ep1[p], CqIndex(mode->epQuant), &qep0[p], &qep1[p], &uqEP0[p], &uqEP1[p]);
        }
        float err = ComputeBlockError(blk, pi, recWeights, uqEP0, uqEP1);
        UpdateBestState(best, err, mode, pi, gridQuantWeights, qep0, qep1);

        bool adjusted = RealignWeights(blk, pi, mode->wQuant, uqEP0, uqEP1,
                                       gridPointTexelCount, gridPointTexelList, gridPointTexelContribList,
                                       gridQuantWeights, gridUnquantWeights, recWeights);
        if (!adjusted) {
            break;
        }
        err = ComputeBlockError(blk, pi, recWeights, uqEP0, uqEP1);
        UpdateBestState(best, err, mode, pi, gridQuantWeights, qep0, qep1);
    }
}

float CompressBlock1Plane(const float4 blk[BLOCK_SIZE], __constant const PartitionInfo* pi,
                          uchar out[PHYSICAL_BLOCK_BYTES])
{
    BestState best;
    InitBestState(&best);

    float idealWeights[BLOCK_SIZE];
    float4 idealEP0[BLOCK_MAX_PARTITIONS];
    float4 idealEP1[BLOCK_MAX_PARTITIONS];
    float weightErrScale[BLOCK_SIZE];
    ComputeIdealColorsAndWeights3Comp(blk, pi, idealWeights, idealEP0, idealEP1, weightErrScale);

    uint numBM = NUM_PREDEF_BM_1PART;
    __constant const Mode* modeArr = PREDEF_BM_1PART;
    if (pi->partitionCount == 2) {
        numBM = NUM_PREDEF_BM_2PART;
        modeArr = PREDEF_BM_2PART;
    }
    if (pi->partitionCount == 3) {
        numBM = NUM_PREDEF_BM_3PART;
        modeArr = PREDEF_BM_3PART;
    }

    for (uint m = 0; m < numBM; ++m) {
        EncodeOneCandidate(blk, &modeArr[m], pi, idealWeights, idealEP0, idealEP1, weightErrScale, &best);
    }

    WriteBitstream(best.mode, best.pi, best.qw, best.qep0, best.qep1, out);

    return best.err;
}

void CopyPhysicalBlk(uchar* src, uchar* dst)
{
    uint4 temp = vload4(0, (uint*)(src));
    vstore4(temp, 0, (uint*)(dst));
}

void CompressBlock(const float4 blkIn[BLOCK_SIZE], uchar outBest[PHYSICAL_BLOCK_BYTES], float* errBest)
{
    uchar outTemp[PHYSICAL_BLOCK_BYTES] = {0};

    *errBest = CompressBlock1Plane(blkIn, &PREDEF_PARTITION_INFO_1PART, outTemp);
    CopyPhysicalBlk(outTemp, outBest);

#if (ENABLE_2PART)
    do {
        int candIdx[2];
        uint candCount = FindBestPartitioning(blkIn, 2, candIdx);
        for (uint c = 0; c < candCount; ++c) {
            outTemp[0] = 0;
            float errTemp = CompressBlock1Plane(blkIn, &PREDEF_PARTITION_INFO_2PART[candIdx[c]], outTemp);
            if (errTemp < *errBest) {
                *errBest = errTemp;
                CopyPhysicalBlk(outTemp, outBest);
            }
        }
    } while (0);
#endif

#if (ENABLE_3PART)
    do {
        int candIdx[2];
        uint candCount = FindBestPartitioning(blkIn, 3, candIdx);
        for (uint c = 0; c < candCount; ++c) {
            outTemp[0] = 0;
            float errTemp = CompressBlock1Plane(blkIn, &PREDEF_PARTITION_INFO_3PART[candIdx[c]], outTemp);
            if (errTemp < *errBest) {
                *errBest = errTemp;
                CopyPhysicalBlk(outTemp, outBest);
            }
        }
    } while (0);
#endif
}

void GetBlockFromImage(read_only image2d_t inputImage, int width, int height, float4 texels[BLOCK_SIZE])
{
    const uint2 blkPos = (uint2)(get_global_id(0), get_global_id(1));

    uint2 blkLTPos = (uint2)(blkPos.x * DIM, blkPos.y * DIM);

    for (int row = 0; row < DIM; ++row) {
        for (int col = 0; col < DIM; ++col) {
            int2 pixelPos = (int2)(blkLTPos.x + col, blkLTPos.y + row);
            if (pixelPos.x >= width) {
                pixelPos.x = width - 1;
            }
            if (pixelPos.y >= height) {
                pixelPos.y = height - 1;
            }
            // input image is CL_RGBA / CL_UNSIGNED_INT8, so ui values are 0..255
            uint4 uintTexel = read_imageui(inputImage, pixelPos);
            float4 texel = convert_float4(uintTexel);
            texel.w = 0.0f;
            texels[row * DIM + col] = texel;
        }
    }
}

__kernel void AstcCl(read_only image2d_t inputImage, __global uint4* astcArr,
                     __global uint* errs, int width, int height)
{
    const uint blocksX = (uint)((width + DIM - 1) / DIM);
    const uint blocksY = (uint)((height + DIM - 1) / DIM);
    const uint2 blkPos = (uint2)(get_global_id(0), get_global_id(1));

    if (blkPos.x >= blocksX || blkPos.y >= blocksY) {
        return;
    }

    uint blkIdx = blkPos.x + blkPos.y * blocksX;
    uint blockNum = blocksX * blocksY;
    if (blkIdx >= blockNum) {
        return;
    }

    float4 texels[BLOCK_SIZE];
    GetBlockFromImage(inputImage, width, height, texels);

    uchar best[PHYSICAL_BLOCK_BYTES] = {0};
    float bestErr;

    CompressBlock(texels, best, &bestErr);

    astcArr[blkIdx] = *(uint4*)(best);
    errs[blkIdx] = (bestErr < 1.0e9f) ? (uint)bestErr : 0u;
}

)ASTCCL6x6";
