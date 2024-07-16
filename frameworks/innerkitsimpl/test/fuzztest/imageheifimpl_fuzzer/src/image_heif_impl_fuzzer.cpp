/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "image_heif_impl_fuzzer.h"

#include <cstdint>
#include <memory>
#include <string>

#define private public
#define protected public
#include "HeifDecoder.h"
#include "HeifDecoderImpl.h"
#include "heif_parser.h"
#include "heif_image.h"
#include "heif_stream.h"
#include "box/item_info_box.h"
#include "box/heif_box.h"
#include "box/basic_box.h"
#include "box/item_data_box.h"
#include "box/item_ref_box.h"
#include "box/item_property_box.h"
#include "box/item_property_basic_box.h"
#include "box/item_property_aux_box.h"
#include "box/item_property_color_box.h"
#include "box/item_property_display_box.h"
#include "box/item_property_hvcc_box.h"
#include "box/item_property_transform_box.h"
#include "include/core/SkStream.h"
#include "buffer_source_stream.h"
#include "ext_stream.h"

namespace OHOS {
namespace Media {
using namespace OHOS::ImagePlugin;

struct HeifStreamMock : public HeifStream {
public:
explicit HeifStreamMock(SkStream* stream) : fStream(stream) {}

~HeifStreamMock() override{}

size_t read(void* buffer, size_t size) override
{
    return fStream->read(buffer, size);
}

bool rewind() override
{
    return fStream->rewind();
}

bool seek(size_t position) override
{
    return fStream->seek(position);
}

bool hasLength() const override
{
    return fStream->hasLength();
}

size_t getLength() const override
{
    return fStream->getLength();
}

bool hasPosition() const override
{
    return fStream->hasPosition();
}

size_t getPosition() const override
{
    return fStream->getPosition();
}

private:
    std::unique_ptr<SkStream> fStream;
};

void HeifParserTest001(HeifParser &heifparse, const std::shared_ptr<HeifInputStream> &stream)
{
    std::shared_ptr<HeifParser> *out = nullptr;
    const void *data = nullptr;
    size_t size = 0;
    bool flag = false;
    HeifStreamWriter writer;
    heif_item_id itemId = 0xffff;
    std::vector<uint8_t> v1(1, 1);
    enum heif_header_option option = heif_no_header;
    std::vector<std::shared_ptr<HeifImage>> v2(1, nullptr);
    std::vector<heif_item_id> itemIdList(1, 0xffff);
    const uint8_t intdata8 = 0;
    uint32_t uint32data = 0;
    const std::shared_ptr<HeifImage> master_image = nullptr;
    int64_t int64data = 0;
    HeifStreamReader reader(stream, int64data, size);
    std::vector<std::shared_ptr<HeifBox>> v3(1, nullptr);
    std::shared_ptr<HeifImage> image = nullptr;
    const struct HeifIrefBox::Reference ref {.fromItemId = 0xFFFFFFFF};

    heifparse.MakeFromStream(stream, out);
    heifparse.MakeFromMemory(data, size, flag, out);
    heifparse.Write(writer);
    heifparse.GetImage(itemId);
    heifparse.GetPrimaryImage();
    heifparse.GetGainmapImage();
    heifparse.GetTmapImage();
    heifparse.GetItemType(itemId);
    heifparse.GetItemData(itemId, &v1, option);
    heifparse.GetTileImages(itemId, v2);
    heifparse.GetIdenImage(itemId, image);
    heifparse.GetAllItemId(itemIdList);
    heifparse.SetExifMetadata(master_image, &intdata8, uint32data);
    heifparse.UpdateExifMetadata(master_image, &intdata8, uint32data, itemId);
    heifparse.AssembleBoxes(reader);
    heifparse.GetPrimaryItemId();
    heifparse.HasItemId(itemId);
    heifparse.GetItemContentType(itemId);
    heifparse.GetItemUriType(itemId);
    heifparse.GetInfeBox(itemId);
    heifparse.GetAllProperties(itemId, v3);
    heifparse.ExtractDerivedImageProperties();
    heifparse.ExtractThumbnailImage(image, ref);
    heifparse.ExtractAuxImage(image, ref);
}

void HeifParserTest002(HeifParser &heifparse, const std::shared_ptr<HeifInputStream> &stream)
{
    std::shared_ptr<HeifImage> image = nullptr;
    const std::shared_ptr<HeifImage> master_image;
    uint8_t intdata8 = 0;
    uint32_t uint32data = 0;
    bool flag = false;
    heif_item_id itemId = 0xffff;
    const char *itemType = nullptr;
    const std::vector<uint8_t> v1(1, 1);
    const HvccConfig config = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::shared_ptr<HeifBox> heifbox = nullptr;
    const std::vector<heif_item_id> v2(1, 0xffff);
    const std::string type1 = "abc";
    const std::shared_ptr<const HeifColorProfile> Colorptr = nullptr;
    const heif_item_id id = 0xffff;
    const uint8_t constdata = 0;

    heifparse.ExtractNonMasterImages();
    heifparse.ExtractMetadata(v2);
    heifparse.GetNextItemId();
    heifparse.AddHvccProperty(itemId);
    heifparse.AppendHvccNalData(itemId, v1);
    heifparse.SetHvccConfig(itemId, config);
    heifparse.AddIspeProperty(itemId, uint32data, uint32data);
    heifparse.AddPixiProperty(itemId, intdata8, intdata8, intdata8);
    heifparse.AddProperty(itemId, heifbox, flag);
    heifparse.AppendIlocData(itemId, v1, intdata8);
    heifparse.SetPrimaryItemId(itemId);
    heifparse.AddReference(itemId, uint32data, v2);
    heifparse.SetAuxcProperty(itemId, type1);
    heifparse.SetColorProfile(itemId, Colorptr);
    heifparse.CheckExtentData();
    heifparse.SetPrimaryImage(master_image);
    heifparse.GetExifHeaderOffset(&constdata, uint32data);
    heifparse.SetMetadata(master_image, v1, itemType, itemType);
    heifparse.GetConstructMethod(id);
    heifparse.ExtractGainmap(v2);
    heifparse.ExtractDisplayData(image, itemId);
    heifparse.ExtractIT35Metadata(id);
    heifparse.ExtractISOMetadata(id);
    heifparse.ExtractGainmapImage(id);
}

void HeifImageTest001(std::shared_ptr<HeifImage> &heifimage)
{
    bool flag = false;
    uint32_t int32data = 0;
    int degrees = 0;
    enum HeifTransformMirrorDirection direction = HeifTransformMirrorDirection::VERTICAL;
    HeifColorFormat defaultColorFormat_ = HeifColorFormat::UNDEDEFINED;
    HeifPixelFormat defaultPixelFormat_ = HeifPixelFormat::UNDEFINED;
    heif_item_id itemId = 0xffff;
    const std::shared_ptr<HeifImage> const_img = nullptr;

    if (heifimage == nullptr) {
        return;
    }
    heifimage->GetItemId();
    heifimage->IsPrimaryImage();
    heifimage->SetPrimaryImage(flag);
    heifimage->GetOriginalWidth();
    heifimage->GetOriginalHeight();
    heifimage->SetOriginalSize(int32data, int32data);
    heifimage->GetRotateDegrees();
    heifimage->SetRotateDegrees(degrees);
    heifimage->GetMirrorDirection();
    heifimage->SetMirrorDirection(direction);
    heifimage->IsResolutionReverse();
    heifimage->GetWidth();
    heifimage->GetHeight();
    heifimage->GetLumaBitNum();
    heifimage->SetLumaBitNum(degrees);
    heifimage->GetChromaBitNum();
    heifimage->SetChromaBitNum(degrees);
    heifimage->GetDefaultColorFormat();
    heifimage->SetDefaultColorFormat(defaultColorFormat_);
    heifimage->GetDefaultPixelFormat();
    heifimage->SetDefaultPixelFormat(defaultPixelFormat_);
    heifimage->SetThumbnailImage(itemId);
    heifimage->AddThumbnailImage(const_img);
    heifimage->IsThumbnailImage();
    heifimage->GetThumbnailImages();
}

void HeifImageTest002(std::shared_ptr<HeifImage> &heifimage)
{
    heif_item_id itemId = 0xffff;
    std::shared_ptr<HeifImage> image = nullptr;
    std::string aux_type = "abc";
    std::shared_ptr<HeifMetadata> metadata = nullptr;
    const std::shared_ptr<const HeifColorProfile> const_profile = nullptr;
    std::vector<uint8_t> v1(1, 1);

    if (heifimage == nullptr) {
        return;
    }
    heifimage->IsAuxImage();
    heifimage->GetAuxImageType();
    heifimage->GetAuxImages();
    heifimage->SetAuxImage(itemId, aux_type);
    heifimage->AddAuxImage(image);
    heifimage->GetAllMetadata();
    heifimage->AddMetadata(metadata);
    heifimage->GetNclxColorProfile();
    heifimage->GetRawColorProfile();
    heifimage->SetColorProfile(const_profile);
    heifimage->SetGainmapMasterImage(itemId);
    heifimage->AddGainmapImage(image);
    heifimage->GetGainmapImage();
    heifimage->SetTmapBoxId(itemId);
    heifimage->SetStaticMetadata(v1, v1);
    heifimage->SetUWAInfo(v1);
    heifimage->SetISOMetadata(v1);
    heifimage->GetDisplayInfo();
    heifimage->GetLightInfo();
    heifimage->GetUWAInfo();
    heifimage->GetISOMetadata();
}

void HeifStreamTest001(std::shared_ptr<HeifBufferInputStream> &heifbuffstream, HeifStreamReader &heifstreamreader)
{
    size_t size = 0;
    int64_t int64data = 0;
    void *data = nullptr;
    uint8_t uint8data = 0;
    bool flag = false;
    enum heif_error errMsg = heif_error_ok;

    int64data = heifbuffstream->Tell();
    heifbuffstream->CheckSize(size, int64data);
    heifbuffstream->Read(data, size);
    heifbuffstream->Seek(int64data);

    heifstreamreader.Read8();
    heifstreamreader.Read16();
    heifstreamreader.Read32();
    heifstreamreader.Read64();
    heifstreamreader.ReadData(&uint8data, size);
    heifstreamreader.ReadString();
    flag = heifstreamreader.CheckSize(size);
    heifstreamreader.SkipEnd();
    flag = heifstreamreader.IsAtEnd();
    flag = heifstreamreader.HasError();
    heifstreamreader.SetError(flag);
    errMsg = heifstreamreader.GetError();
    heifstreamreader.GetStream();
    size = heifstreamreader.GetRemainSize();
}

void HeifStreamTest002(HeifStreamWriter &heifstreamwriter)
{
    uint8_t uint8data = 0;
    uint16_t uint16data = 0;
    uint32_t uint32data = 0;
    uint64_t uint64data = 0;
    int sizenum = 0;
    const std::string const_ptr = "abcd";
    size_t size = 0;
    heifstreamwriter.CheckSize(size);
    heifstreamwriter.Write8(uint8data);
    heifstreamwriter.Write16(uint16data);
    heifstreamwriter.Write32(uint32data);
    heifstreamwriter.Write64(uint64data);
    heifstreamwriter.Write(sizenum, uint64data);
    heifstreamwriter.Write(const_ptr);
    const std::vector<uint8_t> v1(1, 1);
    heifstreamwriter.Write(v1);
    heifstreamwriter.Skip(size);
    heifstreamwriter.Insert(size);
    heifstreamwriter.GetDataSize();
    heifstreamwriter.GetPos();
    heifstreamwriter.SetPos(size);
    heifstreamwriter.SetPositionToEnd();
    heifstreamwriter.GetData();
}

void itemInfoBoxTest001(HeifIinfBox &heifIinfbox, std::shared_ptr<HeifInfeBox> &heifinfebox,
    HeifPtimBox &heifptimbox, HeifStreamReader&reader, HeifStreamWriter &writer)
{
    heif_item_id itemId = 0xffff;
    bool flag = false;
    const std::string const_type = "abc";

    heifIinfbox.InferFullBoxVersion();
    heifIinfbox.Write(writer);
    heifIinfbox.ParseContent(reader);

    if (heifinfebox == nullptr) {
        return;
    }
    heifinfebox->IsHidden();
    heifinfebox->SetHidden(flag);
    heifinfebox->GetItemId();
    heifinfebox->SetItemId(itemId);
    heifinfebox->GetItemType();

    heifinfebox->SetItemType(const_type);
    heifinfebox->SetItemName(const_type);
    heifinfebox->GetContentType();
    heifinfebox->GetContentEncoding();
    heifinfebox->SetContentType(const_type);
    heifinfebox->SetContentEncoding(const_type);
    heifinfebox->InferFullBoxVersion();
    heifinfebox->Write(writer);
    heifinfebox->GetItemUriType();
    heifinfebox->ParseContent(reader);
    
    heifptimbox.GetItemId();
    heifptimbox.SetItemId(itemId);
    heifptimbox.InferFullBoxVersion();
    heifptimbox.Write(writer);
    heifptimbox.ParseContent(reader);
}

void HeifBoxTest001(std::shared_ptr<HeifBox> &heifbox, std::shared_ptr<HeifFullBox> &heiffullbox,
    HeifStreamReader &reader, HeifStreamWriter &writer)
{
    std::shared_ptr<HeifBox> *result = nullptr;
    uint32_t type = 0;
    const HeifBox box;
    const std::shared_ptr<HeifBox> const_box = nullptr;
    size_t size = 0;
    uint8_t version = 0;

    if (heifbox == nullptr) {
        return;
    }
    heifbox->MakeFromReader(reader, result);
    heifbox->Write(writer);
    heifbox->GetBoxSize();
    heifbox->GetHeaderSize();
    heifbox->GetBoxType();
    heifbox->SetBoxType(type);
    heifbox->GetBoxUuidType();
    heifbox->ParseHeader(reader);
    heifbox->SetHeaderInfo(box);
    heifbox->InferHeaderSize();
    heifbox->InferFullBoxVersion();
    heifbox->InferAllFullBoxVersion();
    heifbox->GetChildren();
    heifbox->AddChild(const_box);
    heifbox->ParseContent(reader);
    heifbox->ReadChildren(reader);
    heifbox->WriteChildren(writer);
    heifbox->ReserveHeader(writer);
    heifbox->WriteCalculatedHeader(writer, size);
    heifbox->WriteHeader(writer, size);

    if (heiffullbox == nullptr) {
        return;
    }
    heiffullbox->InferFullBoxVersion();
    heiffullbox->ParseFullHeader(reader);
    heiffullbox->GetVersion();
    heiffullbox->SetVersion(version);
    heiffullbox->GetFlags();
    heiffullbox->SetFlags(type);
    heiffullbox->ReserveHeader(writer);
    heiffullbox->WriteHeader(writer, size);
}

void BasicBoxTest001(HeifFtypBox *heifftypbox, HeifMetaBox *heifmetabox,
    HeifHdlrBox *heifhdlrbox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    if (heifftypbox == nullptr) {
        return;
    }
    heifftypbox->Write(writer);
    heifftypbox->ParseContent(reader);

    if (heifmetabox == nullptr) {
        return;
    }
    heifmetabox->ParseContent(reader);

    if (heifhdlrbox == nullptr) {
        return;
    }
    heifhdlrbox->GetHandlerType();
    heifhdlrbox->Write(writer);
    heifhdlrbox->ParseContent(reader);
}

void ItemDataBoxTest001(HeifIlocBox *heifilocbox, HeifIdatBox *heifidatbox,
    HeifStreamReader &reader, HeifStreamWriter &writer)
{
    const HeifIlocBox::Item const_item;
    const std::shared_ptr<HeifInputStream> const_stream = nullptr;
    const std::shared_ptr<HeifIdatBox> const_idat = nullptr;
    std::vector<uint8_t> dest(1, 1);
    heif_item_id itemId = 0xffff;
    const std::vector<uint8_t> const_data(1, 1);
    uint8_t uint8data = 0;
    HeifIlocBox::Item item;
    int indexSize = 0;
    uint64_t uint64data = 0;

    if (heifilocbox == nullptr) {
        return;
    }
    heifilocbox->GetItems();
    heifilocbox->ReadData(const_item, const_stream, const_idat, &dest);
    heifilocbox->AppendData(itemId, const_data, uint8data);
    heifilocbox->UpdateData(itemId, const_data, uint8data);
    heifilocbox->InferFullBoxVersion();
    heifilocbox->Write(writer);
    heifilocbox->WriteMdatBox(writer);
    heifilocbox->ReadToExtentData(item, const_stream, const_idat);
    heifilocbox->ParseContent(reader);
    heifilocbox->ParseExtents(item, reader, indexSize, indexSize, indexSize);
    heifilocbox->PackIlocHeader(writer);

    if (heifidatbox == nullptr) {
        return;
    }
    heifidatbox->ReadData(const_stream, uint64data, uint64data, dest);
    heifidatbox->AppendData(const_data);
    heifidatbox->Write(writer);
    heifidatbox->ParseContent(reader);
}

void ItemRefBoxTest001(HeifIrefBox *heifirefbox, HeifStreamReader &reader,
    HeifStreamWriter &writer)
{
    heif_item_id itemId = 0xffff;
    uint32_t uint32data = 0;
    const std::vector<heif_item_id> v1(1, 0xffff);
    struct HeifIrefBox::Reference ref {.fromItemId = 0xFFFFFFFF};

    if (heifirefbox == nullptr) {
        return;
    }
    heifirefbox->HasReferences(itemId);
    heifirefbox->GetReferences(itemId, uint32data);
    heifirefbox->GetReferencesFrom(itemId);
    heifirefbox->AddReferences(itemId, uint32data, v1);
    heifirefbox->ParseContent(reader);
    heifirefbox->Write(writer);
    heifirefbox->InferFullBoxVersion();
    heifirefbox->ParseItemRef(reader, ref);
}

void ItemPropertyBoxTest001(HeifIprpBox *heifiprpbox, HeifIpcoBox *heifipcobox,
    HeifIpmaBox *heifipmabox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    heif_item_id itemId = 0xffff;
    const std::shared_ptr<HeifIpmaBox> const_box_ptr = nullptr;
    std::vector<std::shared_ptr<HeifBox>> v1(1, nullptr);
    uint32_t uint32data = 0;
    PropertyAssociation assoc;
    const HeifIpmaBox const_box;

    if (heifiprpbox == nullptr) {
        return;
    }
    heifiprpbox->ParseContent(reader);

    if (heifipcobox == nullptr) {
        return;
    }
    heifipcobox->GetProperties(itemId, const_box_ptr, v1);
    heifipcobox->GetProperty(itemId, const_box_ptr, uint32data);
    heifipcobox->ParseContent(reader);

    if (heifipmabox == nullptr) {
        return;
    }
    heifipmabox->GetProperties(itemId);
    heifipmabox->AddProperty(itemId, assoc);
    heifipmabox->InferFullBoxVersion();
    heifipmabox->Write(writer);
    heifipmabox->MergeImpaBoxes(const_box);
    heifipmabox->ParseContent(reader);
}

void ItemPropertyBasicBoxTest001(HeifIspeBox *heifispebox, HeifPixiBox *heifpixibox,
    HeifStreamReader &reader, HeifStreamWriter &writer)
{
    uint32_t uint32data = 0;
    int channel = 0;
    uint8_t uint8data = 0;

    if (heifispebox == nullptr) {
        return;
    }
    heifispebox->GetWidth();
    heifispebox->GetHeight();
    heifispebox->SetDimension(uint32data, uint32data);
    heifispebox->Write(writer);
    heifispebox->ParseContent(reader);

    if (heifpixibox == nullptr) {
        return;
    }
    heifpixibox->GetChannelNum();
    heifpixibox->GetBitNum(channel);
    heifpixibox->AddBitNum(uint8data);
    heifpixibox->Write(writer);
    heifpixibox->ParseContent(reader);
}

void ItemPropertyAuxBoxTest001(HeifAuxcBox *heifauxcbox, HeifStreamReader &reader,
    HeifStreamWriter &writer)
{
    const std::string const_type = "abc";

    if (heifauxcbox == nullptr) {
        return;
    }
    heifauxcbox->GetAuxType();
    heifauxcbox->SetAuxType(const_type);
    heifauxcbox->GetAuxSubtypes();
    heifauxcbox->ParseContent(reader);
    heifauxcbox->Write(writer);
}

void ItemPropertyColorBoxTest001(const std::shared_ptr<const HeifRawColorProfile> &heifrawcolorprofile,
    const std::shared_ptr<const HeifNclxColorProfile> &heifnclxcolorprofile,
    HeifColrBox *heifcolrbox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    const std::shared_ptr<const HeifColorProfile> const_prof = nullptr;

    if (heifrawcolorprofile == nullptr) {
        return;
    }
    heifrawcolorprofile->GetProfileType();
    heifrawcolorprofile->GetData();
    heifrawcolorprofile->Write(writer);

    if (heifnclxcolorprofile == nullptr) {
        return;
    }
    heifnclxcolorprofile->GetProfileType();
    heifnclxcolorprofile->Write(writer);
    heifnclxcolorprofile->GetColorPrimaries();
    heifnclxcolorprofile->GetTransferCharacteristics();
    heifnclxcolorprofile->GetMatrixCoefficients();
    heifnclxcolorprofile->GetFullRangeFlag();

    if (heifcolrbox == nullptr) {
        return;
    }
    heifcolrbox->GetColorProfileType();
    heifcolrbox->GetColorProfile();
    heifcolrbox->SetColorProfile(const_prof);
    heifcolrbox->Write(writer);
    heifcolrbox->ParseContent(reader);
}

void ItemPropertyDisplayBoxTest001(HeifMdcvBox *heifmdcvbox, HeifClliBox *heifcllibox,
    HeifStreamReader &reader,  HeifStreamWriter &writer)
{
    DisplayColourVolume colourVolume;
    ContentLightLevelInfo lightLevel;

    if (heifmdcvbox == nullptr) {
        return;
    }
    heifmdcvbox->GetColourVolume();
    heifmdcvbox->SetColourVolume(colourVolume);
    heifmdcvbox->ParseContent(reader);
    heifmdcvbox->Write(writer);

    if (heifcllibox == nullptr) {
        return;
    }
    heifcllibox->GetLightLevel();
    heifcllibox->SetLightLevel(lightLevel);
    heifcllibox->ParseContent(reader);
    heifcllibox->Write(writer);
}

void ItemPropertyHvccBoxTest001(HeifHvccBox *heifhvccbox, HeifStreamReader &reader,
    HeifStreamWriter &writer)
{
    std::vector<uint8_t> v1(1, 1);
    const HvccConfig config = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::vector<uint8_t> v2(1, 1);
    std::vector<std::vector<uint8_t>> v3(1, v1);

    if (heifhvccbox == nullptr) {
        return;
    }
    heifhvccbox->GetHeaders(&v1);
    heifhvccbox->SetConfig(config);
    heifhvccbox->GetConfig();
    heifhvccbox->AppendNalData(v2);
    heifhvccbox->Write(writer);
    heifhvccbox->ParseContent(reader);
    heifhvccbox->ParseNalUnitArray(reader, v3);
}

void ItemPropertyTransformBoxTest001(HeifIrotBox *heifirotbox,
    HeifImirBox *heifimirbox, HeifStreamReader &reader, HeifStreamWriter &writer)
{
    int rot = 0;
    HeifTransformMirrorDirection dir = HeifTransformMirrorDirection::VERTICAL;

    if (heifirotbox == nullptr) {
        return;
    }
    heifirotbox->GetRotDegree();
    heifirotbox->SetRotDegree(rot);
    heifirotbox->ParseContent(reader);
    heifirotbox->Write(writer);

    if (heifimirbox == nullptr) {
        return;
    }
    heifimirbox->GetDirection();
    heifimirbox->SetDirection(dir);
    heifimirbox->ParseContent(reader);
    heifimirbox->Write(writer);
}

void HeifImplFuzzTest001(const uint8_t* data, size_t size)
{
    // HeifDecodeImpl.cpp create/init/fuzztest
    auto heifdecoder = CreateHeifDecoderImpl();
    void *obj = dynamic_cast<void*>(heifdecoder);
    HeifDecoderImpl *heifdecoderimpl = static_cast<HeifDecoderImpl*>(obj);
    std::unique_ptr<InputDataStream> stream_ = BufferSourceStream::CreateSourceStream(data, size);
    auto skStream = std::make_unique<ExtStream>(stream_.release());
    HeifFrameInfo heifInfo;
    heifdecoderimpl->init(new HeifStreamMock(skStream.release()), &heifInfo);

    // heif_parse.cpp create/init/fuzztest
    bool needCopy;
    auto heifbuffstream = std::make_shared<HeifBufferInputStream>(data, size, needCopy);
    auto heifparse = HeifParser(heifbuffstream);
    HeifParserTest001(heifparse, heifbuffstream);
    HeifParserTest001(heifparse, heifbuffstream);

    // heif_image.cpp create/init/fuzztest
    std::shared_ptr<HeifImage> heifimage = heifparse.GetGainmapImage();
    HeifImageTest001(heifimage);
    HeifImageTest002(heifimage);

    // heif_stream.cpp create/init/fuzztest
    int64_t start = 0;
    auto heifstreamreader = HeifStreamReader(heifbuffstream, start, size);
    auto heifstreamwriter = HeifStreamWriter();
    HeifStreamTest001(heifbuffstream, heifstreamreader);
    HeifStreamTest002(heifstreamwriter);

    // heif_utils.cpp create/init/fuzztest
    uint32_t uint32data = 0;
    code_to_fourcc(uint32data);

    // item_info_box.cpp create/init/fuzztest
    const char* itemType = "abc";
    bool hidden = false;
    std::shared_ptr<HeifInfeBox> heifinfebox = heifparse.AddItem(itemType, hidden);
    auto heifIinfbox = HeifIinfBox();
    auto heifptimbox = HeifPtimBox();
    itemInfoBoxTest001(heifIinfbox, heifinfebox, heifptimbox, heifstreamreader, heifstreamwriter);

    // heif_box.cpp create/init/fuzztest
    std::shared_ptr<HeifFullBox> heiffullbox = heifinfebox;
    std::shared_ptr<HeifBox> heifbox = heiffullbox;
    HeifBoxTest001(heifbox, heiffullbox, heifstreamreader, heifstreamwriter);

    // basic_box.cpp create/init/fuzztest
    HeifBox *temp_heifbox = heifbox.get();
    void *obj_heifbox = dynamic_cast<void *>(temp_heifbox);
    auto heifftypbox = static_cast<HeifFtypBox *>(obj_heifbox);
    HeifFullBox *temp_heiffullbox = heiffullbox.get();
    void *obj_heiffullbox = dynamic_cast<void *>(temp_heiffullbox);
    auto heifmetabox = static_cast<HeifMetaBox *>(obj_heiffullbox);
    auto heifhdlrbox = static_cast<HeifHdlrBox *>(obj_heiffullbox);
    BasicBoxTest001(heifftypbox, heifmetabox, heifhdlrbox, heifstreamreader, heifstreamwriter);

    // item_data_box.cpp create/init/fuzztest
    auto heifilocbox = static_cast<HeifIlocBox *>(obj_heiffullbox);
    auto heifidatbox = static_cast<HeifIdatBox *>(obj_heifbox);
    ItemDataBoxTest001(heifilocbox, heifidatbox, heifstreamreader, heifstreamwriter);

    // item_ref_box.cpp create/init/fuzztest
    auto heifirefbox = static_cast<HeifIrefBox *>(obj_heiffullbox);
    ItemRefBoxTest001(heifirefbox, heifstreamreader, heifstreamwriter);
}

void HeifImplFuzzTest002(const uint8_t *data, size_t size)
{
    bool flag;
    const char *itemType = "abc";
    int64_t start = 0;
    auto heifbuffstream = std::make_shared<HeifBufferInputStream>(data, size, flag);
    auto heifparse = HeifParser(heifbuffstream);
    std::shared_ptr<HeifInfeBox> heifinfebox = heifparse.AddItem(itemType, flag);
    std::shared_ptr<HeifFullBox> heiffullbox = heifinfebox;
    std::shared_ptr<HeifBox> heifbox = heiffullbox;
    HeifBox *temp_heifbox = heifbox.get();
    void *obj_heifbox = dynamic_cast<void *>(temp_heifbox);
    HeifFullBox *temp_heiffullbox = heiffullbox.get();
    void *obj_heiffullbox = dynamic_cast<void *>(temp_heiffullbox);
    auto heifstreamreader = HeifStreamReader(heifbuffstream, start, size);
    auto heifstreamwriter = HeifStreamWriter();

    // item_property_box.cpp create/init/fuzztest
    auto heifiprpbox = static_cast<HeifIprpBox *>(obj_heifbox);
    auto heifipcobox = static_cast<HeifIpcoBox *>(obj_heifbox);
    auto heifipmabox = static_cast<HeifIpmaBox *>(obj_heiffullbox);
    ItemPropertyBoxTest001(heifiprpbox, heifipcobox, heifipmabox, heifstreamreader, heifstreamwriter);

    // item_property_basic_box.cpp create/init/fuzztest
    auto heifispebox = static_cast<HeifIspeBox *>(obj_heiffullbox);
    auto heifpixibox = static_cast<HeifPixiBox *>(obj_heiffullbox);
    ItemPropertyBasicBoxTest001(heifispebox, heifpixibox, heifstreamreader, heifstreamwriter);

    // item_property_aux_box.cpp create/init/fuzztest
    auto heifauxcbox = static_cast<HeifAuxcBox *>(obj_heiffullbox);
    ItemPropertyAuxBoxTest001(heifauxcbox, heifstreamreader, heifstreamwriter);

    // item_property_color_box.cpp create/init/fuzztest
    std::shared_ptr<HeifImage> heifimage = heifparse.GetGainmapImage();
    if (heifimage != nullptr) {
        auto heifrawcolorprofile = heifimage->GetRawColorProfile();
        auto heifnclxcolorprofile = heifimage->GetNclxColorProfile();
        auto heifcolrbox = static_cast<HeifColrBox *>(obj_heifbox);
        ItemPropertyColorBoxTest001(heifrawcolorprofile, heifnclxcolorprofile, heifcolrbox,
            heifstreamreader, heifstreamwriter);
    }

    // item_property_display_box.cpp create/init/fuzztest
    auto heifmdcvbox = static_cast<HeifMdcvBox *>(obj_heifbox);
    auto heifcllibox = static_cast<HeifClliBox *>(obj_heifbox);
    ItemPropertyDisplayBoxTest001(heifmdcvbox, heifcllibox, heifstreamreader, heifstreamwriter);

    // item_property_hvcc_box.cpp create/init/fuzztest
    auto heifhvccbox = static_cast<HeifHvccBox *>(obj_heifbox);
    ItemPropertyHvccBoxTest001(heifhvccbox, heifstreamreader, heifstreamwriter);

    // item_property_transform_box.cpp create/init/fuzztest
    auto heifirotbox = static_cast<HeifIrotBox *>(obj_heifbox);
    auto heifimirbox = static_cast<HeifImirBox *>(obj_heifbox);
    ItemPropertyTransformBoxTest001(heifirotbox, heifimirbox, heifstreamreader, heifstreamwriter);
}

} // namespace Media
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::Media::HeifImplFuzzTest001(data, size);
    OHOS::Media::HeifImplFuzzTest002(data, size);
    return 0;
}