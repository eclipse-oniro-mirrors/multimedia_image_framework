/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "media_errors.h"
#include "blob_metadata.h"
#include "parcel.h"
#include "ashmem.h"
#include <fcntl.h>
#include <unistd.h>

using namespace testing::ext;
using namespace OHOS::Media;
namespace OHOS {
namespace Media {
static constexpr int32_t INVALID_RESULT = -1;
static constexpr uint8_t METADATA_SAMPLE_BYTE = 1;
static constexpr size_t INDEX_ONE = 1;
static constexpr size_t INDEX_TWO = 2;
static constexpr size_t TEST_BLOB_DATA_SIZE = 5000;
static constexpr size_t TEST_ASHMEM_SIZE = 1024;
static constexpr uint64_t INVALID_BLOB_METADATA_LENGTH = 21 * 1024 * 1024;

class BlobMetadataTest : public testing::Test {
public:
    BlobMetadataTest() {}
    ~BlobMetadataTest() {}
};

/**
 * @tc.name: BlobMetadataTest001
 * @tc.desc: Test BlobMetadata when blobMetadata data is not nullptr and dataSize is more than zero
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, BlobMetadataTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: BlobMetadataTest001 start";
    BlobMetadata sourceBlob;
    uint8_t sourceData[] = { 0, 0 };
    uint32_t sourceSize = sizeof(sourceData);
    uint32_t ret = sourceBlob.SetBlob(sourceData, sourceSize);
    ASSERT_EQ(ret, SUCCESS);
    ASSERT_EQ(sourceBlob.GetBlobSize(), sourceSize);

    BlobMetadata copiedBlob(sourceBlob);
    ASSERT_EQ(copiedBlob.GetBlobSize(), sourceSize);
    uint8_t* copiedDataPtr = copiedBlob.GetBlobPtr();
    ASSERT_NE(copiedDataPtr, nullptr);
    GTEST_LOG_(INFO) << "BlobMetadataTest: BlobMetadataTest001 end";
}

/**
 * @tc.name: operatorTest001
 * @tc.desc: Test operator= covering assignment from a non-empty object to an empty one, and self-assignment
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, operatorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: operatorTest001 start";
    BlobMetadata blob;
    uint8_t data[] = {0, 0};
    blob.SetBlob(data, sizeof(data));
    ASSERT_EQ(blob.GetBlobSize(), sizeof(data));

    BlobMetadata emptyBlob;
    blob = emptyBlob;
    ASSERT_EQ(blob.GetBlobSize(), 0);
    ASSERT_EQ(blob.GetBlobPtr(), nullptr);

    BlobMetadata &blobRef = blob;
    blob = blobRef;
    ASSERT_EQ(blob.GetBlobSize(), 0);
    ASSERT_EQ(blob.GetBlobPtr(), nullptr);
    GTEST_LOG_(INFO) << "BlobMetadataTest: operatorTest001 end";
}

/**
 * @tc.name: operatorTest002
 * @tc.desc: Test operator= covering assignment from a non-empty object to another non-empty object
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, operatorTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: operatorTest002 start";
    BlobMetadata blob;
    uint8_t data[] = {0, 0};
    blob.SetBlob(data, sizeof(data));
    ASSERT_EQ(blob.GetBlobSize(), sizeof(data));

    BlobMetadata sourceBlob;
    uint8_t sourceData[] = {METADATA_SAMPLE_BYTE, METADATA_SAMPLE_BYTE, METADATA_SAMPLE_BYTE};
    sourceBlob.SetBlob(sourceData, sizeof(sourceData));
    ASSERT_EQ(sourceBlob.GetBlobSize(), sizeof(sourceData));

    blob = sourceBlob;
    ASSERT_EQ(blob.GetBlobSize(), sizeof(sourceData));
    uint8_t* blobDataPtr = blob.GetBlobPtr();
    ASSERT_NE(blobDataPtr, nullptr);
    ASSERT_EQ(blobDataPtr[0], METADATA_SAMPLE_BYTE);
    ASSERT_EQ(blobDataPtr[INDEX_ONE], METADATA_SAMPLE_BYTE);
    ASSERT_EQ(blobDataPtr[INDEX_TWO], METADATA_SAMPLE_BYTE);
    GTEST_LOG_(INFO) << "BlobMetadataTest: operatorTest002 end";
}

/**
 * @tc.name: ReadDataFromAshmemTest001
 * @tc.desc: Test ReadDataFromAshmem when blobMetadataPtr is invalid
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, ReadDataFromAshmemTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadDataFromAshmemTest001 start";
    Parcel parcel;
    std::unique_ptr<BlobMetadata> blobMetadataPtr =std::make_unique<BlobMetadata>(MetadataType::RFDATAB);
    blobMetadataPtr->dataSize_ = INVALID_BLOB_METADATA_LENGTH;
    blobMetadataPtr->data_ = new uint8_t[INDEX_ONE];
    bool ret = BlobMetadata::ReadDataFromAshmem(parcel, blobMetadataPtr, nullptr);
    ASSERT_FALSE(ret);

    blobMetadataPtr->dataSize_ = 0;
    ret = BlobMetadata::ReadDataFromAshmem(parcel, blobMetadataPtr, nullptr);
    ASSERT_FALSE(ret);

    blobMetadataPtr->data_ = nullptr;
    ret = BlobMetadata::ReadDataFromAshmem(parcel, blobMetadataPtr, nullptr);
    ASSERT_FALSE(ret);

    blobMetadataPtr = nullptr;
    ret = BlobMetadata::ReadDataFromAshmem(parcel, blobMetadataPtr, nullptr);
    ASSERT_FALSE(ret);
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadDataFromAshmemTest001 end";
}

/**
 * @tc.name: ReadDataFromAshmemTest002
 * @tc.desc: Test ReadDataFromAshmem when parcel not contain fd
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, ReadDataFromAshmemTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadDataFromAshmemTest002 start";
    Parcel parcel;
    std::unique_ptr<BlobMetadata> blobMetadataPtr =std::make_unique<BlobMetadata>(MetadataType::RFDATAB);
    blobMetadataPtr->dataSize_ = TEST_BLOB_DATA_SIZE;
    blobMetadataPtr->data_ = new uint8_t[blobMetadataPtr->dataSize_];
    std::fill(blobMetadataPtr->data_, blobMetadataPtr->data_ + blobMetadataPtr->dataSize_, 0);
    bool ret = BlobMetadata::ReadDataFromAshmem(parcel, blobMetadataPtr, nullptr);
    ASSERT_FALSE(ret);
    delete[] blobMetadataPtr->data_;
    blobMetadataPtr->data_ = nullptr;
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadDataFromAshmemTest002 end";
}

/**
 * @tc.name: ReadDataFromAshmemTest003
 * @tc.desc: Test ReadDataFromAshmem when ashmem is not same as dataSize
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, ReadDataFromAshmemTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadDataFromAshmemTest003 start";
    Parcel parcel;
    std::unique_ptr<BlobMetadata> blobMetadataPtr =std::make_unique<BlobMetadata>(MetadataType::RFDATAB);
    blobMetadataPtr->dataSize_ = TEST_BLOB_DATA_SIZE;
    blobMetadataPtr->data_ = new uint8_t[blobMetadataPtr->dataSize_];
    std::fill(blobMetadataPtr->data_, blobMetadataPtr->data_ + blobMetadataPtr->dataSize_, 0);
    int fd = AshmemCreate("BlobMetadata", TEST_ASHMEM_SIZE);
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(BlobMetadata::WriteFileDescriptor(parcel, fd));
    close(fd);
    bool ret = BlobMetadata::ReadDataFromAshmem(parcel, blobMetadataPtr, nullptr);
    ASSERT_FALSE(ret);
    delete[] blobMetadataPtr->data_;
    blobMetadataPtr->data_ = nullptr;
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadDataFromAshmemTest003 end";
}

/**
 * @tc.name: ReadFileDescriptorTest001
 * @tc.desc: Test ReadFileDescriptor expect return -1 when descriptor is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, ReadFileDescriptorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadFileDescriptorTest001 start";
    Parcel parcel;
    int ret = BlobMetadata::ReadFileDescriptor(parcel);
    ASSERT_EQ(ret, INVALID_RESULT);
    GTEST_LOG_(INFO) << "BlobMetadataTest: ReadFileDescriptorTest001 end";
}

/**
 * @tc.name: WriteFileDescriptorTest001
 * @tc.desc: Test WriteFileDescriptor when dupfd is less than zero
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, WriteFileDescriptorTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: WriteFileDescriptorTest001 start";
    Parcel parcel;
    int fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    close(fd);
    bool ret = BlobMetadata::WriteFileDescriptor(parcel, fd);
    ASSERT_FALSE(ret);
    GTEST_LOG_(INFO) << "BlobMetadataTest: WriteFileDescriptorTest001 end";
}

/**
 * @tc.name: MarshallingTest001
 * @tc.desc: Test Marshalling when dataSize_ is invalid
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, MarshallingTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: MarshallingTest001 start";
    Parcel parcel;
    std::unique_ptr<BlobMetadata> blobMetadataPtr =std::make_unique<BlobMetadata>(MetadataType::RFDATAB);
    blobMetadataPtr->data_ = new uint8_t[INDEX_ONE];
    blobMetadataPtr->dataSize_ = INVALID_BLOB_METADATA_LENGTH;
    bool ret = blobMetadataPtr->Marshalling(parcel);
    ASSERT_FALSE(ret);
    delete[] blobMetadataPtr->data_;
    blobMetadataPtr->data_ = nullptr;
    GTEST_LOG_(INFO) << "BlobMetadataTest: MarshallingTest001 end";
}

/**
 * @tc.name: MarshallingTest002
 * @tc.desc: Test Marshalling when dataSize_ is zero
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, MarshallingTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: MarshallingTest002 start";
    Parcel parcel;
    std::unique_ptr<BlobMetadata> blobMetadataPtr =std::make_unique<BlobMetadata>(MetadataType::RFDATAB);
    blobMetadataPtr->data_ = new uint8_t[INDEX_ONE];
    blobMetadataPtr->dataSize_ = 0;
    bool ret = blobMetadataPtr->Marshalling(parcel);
    ASSERT_FALSE(ret);
    delete[] blobMetadataPtr->data_;
    blobMetadataPtr->data_ = nullptr;
    GTEST_LOG_(INFO) << "BlobMetadataTest: MarshallingTest002 end";
}

/**
 * @tc.name: UnmarshallingTest001
 * @tc.desc: Test Unmarshalling expect return nullptr when parcel is empty
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, UnmarshallingTest001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest001 start";
    Parcel parcel;
    BlobMetadata *ret = BlobMetadata::Unmarshalling(parcel);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest001 end";
}

/**
 * @tc.name: UnmarshallingTest002
 * @tc.desc: Test Unmarshalling when dataSize is zero
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, UnmarshallingTest002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest002 start";
    Parcel parcel;
    parcel.WriteUint32(static_cast<uint32_t>(MetadataType::RFDATAB));
    parcel.WriteUint32(0);
    PICTURE_ERR error;
    BlobMetadata *ret = BlobMetadata::Unmarshalling(parcel, error);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest002 end";
}

/**
 * @tc.name: UnmarshallingTest003
 * @tc.desc: Test Unmarshalling when dataSize is more than MAX_BLOB_METADATA_LENGTH
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, UnmarshallingTest003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest003 start";
    Parcel parcel;
    parcel.WriteUint32(static_cast<uint32_t>(MetadataType::RFDATAB));
    parcel.WriteUint32(INVALID_BLOB_METADATA_LENGTH);
    PICTURE_ERR error;
    BlobMetadata *ret = BlobMetadata::Unmarshalling(parcel, error);
    ASSERT_EQ(ret, nullptr);
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest003 end";
}

/**
 * @tc.name: UnmarshallingTest004
 * @tc.desc: Test Unmarshalling when dataSize is less than MAX_MARSHAL_BLOB_DATA_SIZE ReadDataFromParcel fails
 * @tc.type: FUNC
 */
HWTEST_F(BlobMetadataTest, UnmarshallingTest004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest004 start";
    Parcel parcel;
    parcel.WriteUint32(static_cast<uint32_t>(MetadataType::RFDATAB));
    parcel.WriteUint32(TEST_BLOB_DATA_SIZE);
    PICTURE_ERR error;
    BlobMetadata *ret = BlobMetadata::Unmarshalling(parcel, error);
    ASSERT_NE(ret, nullptr);
    GTEST_LOG_(INFO) << "BlobMetadataTest: UnmarshallingTest004 end";
}
}
}
