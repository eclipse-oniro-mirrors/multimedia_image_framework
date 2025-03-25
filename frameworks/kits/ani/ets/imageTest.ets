/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

import { image } from "../ets/@ohos.multimedia.image.ets";

function main() {
  // test createPixemap & getImageInfo
  console.log("Test PixelMap START");
   const opts: image.InitializationOptions = {
     size: { width: 480, height: 360 },
     editable: true,
     pixelFormat: 4,
   };
  let pixelMap:image.PixelMap = image.createPixelMapSync(opts);

  if (pixelMap != undefined) {
    console.log("Create PixelMap success");
  }

  const retImageInfo: image.ImageInfo = pixelMap.getImageInfoSync();
  console.log("Get image info: ", retImageInfo.size.width, retImageInfo.size.height, retImageInfo.pixelFormat, retImageInfo.mimeType);
  pixelMap.getImageInfo()
    .then((imageInfo: image.ImageInfo) => {
      console.log("ASYNC Get image info: ", imageInfo.size.width, imageInfo.size.height, imageInfo.pixelFormat, imageInfo.mimeType);
    });
  
  const rowBytes = pixelMap.getBytesNumberPerRow();
  console.log("PixelMap bytes per row: " + rowBytes);
  const totalBytes = pixelMap.getPixelBytesNumber();
  console.log("PixelMap total bytes: " + totalBytes);

  if (retImageInfo.isHdr) {
      console.log("Test PixelMap hdr ");
  } else {
      console.log("Test PixelMap not hdr ");
  }

  pixelMap.scaleSync(2, 2);
  const scaledInfo = pixelMap.getImageInfoSync();
  console.log("Scaled image info: ", scaledInfo.size.width, scaledInfo.size.height);
  const region: image.Region = {
    size: { width: 512, height: 512 },
    x: 0,
    y: 0
  };
  pixelMap.cropSync(region);
  const croppedInfo = pixelMap.getImageInfoSync();
  console.log("Cropped image info: ", croppedInfo.size.width, croppedInfo.size.height);
  pixelMap.flipSync(true, true);
  const flippedInfo = pixelMap.getImageInfoSync();
  console.log("Flipped image info: ", flippedInfo.size.width, flippedInfo.size.height);

  const alphaPixelMap = pixelMap.createAlphaPixelmapSync();
  if (alphaPixelMap != undefined) {
    console.log("Create alpha PixelMap success");
  }
  const alphaImageInfo = alphaPixelMap.getImageInfoSync();
  console.log("Alpha get image info: ", alphaImageInfo.size.width, alphaImageInfo.size.height, alphaImageInfo.pixelFormat, alphaImageInfo.alphaType);
  pixelMap.createAlphaPixelmap()
    .then((alphaPixelMap: image.PixelMap) => {
      const alphaImageInfo = alphaPixelMap.getImageInfoSync();
      console.log("ASYNC Alpha get image info: ", alphaImageInfo.size.width, alphaImageInfo.size.height, alphaImageInfo.pixelFormat, alphaImageInfo.alphaType);
    })

  let imageSource: image.ImageSource = image.createImageSource("/data/local/tmp/test.png");
  if (imageSource != undefined) {
    console.log("Create ImageSource by URI success");
  }
  let imageSource2: image.ImageSource = image.createImageSource(1);
  if (imageSource2 != undefined) {
    console.log("Create ImageSource by FD success");
  }
  
  let imagesourceImageInfo: image.ImageInfo  = imageSource.getImageInfoSync(1);
  console.log("Test ImageSource.getImageInfoSync width: ", imagesourceImageInfo.size.width, imagesourceImageInfo.size.height, imagesourceImageInfo.pixelFormat, imagesourceImageInfo.density, imagesourceImageInfo.mimeType);
  imageSource.getImageInfo(1)
    .then((imageInfo: image.ImageInfo) => {
      console.log("ASYNC ImageSource get image info:", imageInfo.size.width, imageInfo.size.height, imageInfo.pixelFormat, imageInfo.density, imageInfo.mimeType);
    });
  const decodeOpt: image.DecodingOptions = {
      editable: 1,
  };
  let pixelmap2: image.PixelMap = imageSource.createPixelMapSync(decodeOpt);
  if (pixelmap2 != undefined) {
    console.log("Create imageSource.createPixelMapSync success");
  }
  imageSource.createPixelMap(decodeOpt)
    .then((pixelmap2: image.PixelMap) => {
      if (pixelmap2 != undefined) {
        console.log("ASYNC Create imageSource PixelMap success")
      }
    });
  pixelmap2.release()
    .then((): void => console.log("ASYNC Release PixelMap success"));

  imageSource.modifyImageProperty("Orientation", "Right-top");
  let map: Record<string, string> = {
    "Orientation": "Right-top",
    "Software" : "",
    "test" : "xxxxx",
    };
  imageSource.modifyImageProperties(map);
  let array:Array<string> = new Array<string>(4);
    array[0] = "aa"
    array[1] = "bb"
    array[2] = "cc"
    array[3] = "dd"
  let propertys: Record<string, string> = imageSource.getImageProperties(array);
  console.log("Create imageSource.getImageProperties :" + propertys);
  imageSource.release();

  console.log("TEST ImagePacker begin");
  const imagePacker = image.createImagePacker();
  let packOpts: image.PackingOption = new image.PackingOption(); 
  packOpts.format = "image/jpeg";
  packOpts.quality = 90;
  let packBuffer: ArrayBuffer = imagePacker.packing(pixelMap, packOpts);
  console.log("TEST ImagePacker end, bufferSize: " + packBuffer.byteLength);
  imagePacker.release();

  console.log("TEST pixelMap readPixelsToBuffer begin");
  let arrayBuffer: ArrayBuffer = new ArrayBuffer(opts.size.width * opts.size.height * 4);
  pixelMap.readPixelsToBufferSync(arrayBuffer);
  console.log("Read pixels to buffer success, size: " + arrayBuffer.byteLength); 
  pixelMap.readPixelsToBuffer(arrayBuffer)
    .then((): void => console.log("ASYNC Read pixels to buffer success, size: " + arrayBuffer.byteLength));

  console.log("TEST Picture begin");
  const picture = image.createPicture(pixelMap);
  if (picture != undefined) {
    console.log("Create picture success");
  }
  const picturePixelMap = picture.getMainPixelmap();
  const pictureInfo = picturePixelMap.getImageInfoSync();
  console.log("Picture PixelMap get image info: ", pictureInfo.size.width, pictureInfo.size.height, pictureInfo.pixelFormat, pictureInfo.alphaType);
  
  const regionAsync: image.Region = {
    size: { width: 1, height: 1 },
    x: 256,
    y: 256
  }
  pixelMap.crop(regionAsync)
    .then((): void => {
      const croppedInfo = pixelMap.getImageInfoSync();
      console.log("ASYNC Cropped image info: ", croppedInfo.size.width, croppedInfo.size.height);
    });

  console.log("====== Sync methods completed ======")
}