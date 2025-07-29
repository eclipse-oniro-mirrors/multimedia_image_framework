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

import { image } from "./@ohos.multimedia.image.ets";

function main() {
  // test createPixemap & getImageInfo
  console.println("Test PixelMap START");
  const opts: image.InitializationOptions = {
    size: { width: 480, height: 360 },
    srcPixelFormat: image.PixelMapFormat.RGBA_8888,
    pixelFormat: image.PixelMapFormat.BGRA_8888,
    editable: true,
    alphaType: image.AlphaType.UNPREMUL,
    scaleMode: image.ScaleMode.FIT_TARGET_SIZE
  };
  let pixelMap:image.PixelMap = image.createPixelMapSync(opts);

  if (pixelMap != undefined) {
    console.println("Create PixelMap success");
  }

  const retImageInfo: image.ImageInfo = pixelMap.getImageInfoSync();
  console.println(`Get image info: ${retImageInfo.size.width}, ${retImageInfo.size.height}, ${retImageInfo.pixelFormat}, ${retImageInfo.alphaType}`);
  pixelMap.getImageInfo()
    .then((imageInfo: image.ImageInfo) => {
      console.println(`ASYNC Get image info: ${imageInfo.size.width}, ${imageInfo.size.height}, ${imageInfo.pixelFormat}, ${imageInfo.alphaType}`);
    });
  
  const rowBytes = pixelMap.getBytesNumberPerRow();
  console.println("PixelMap bytes per row: " + rowBytes);
  const totalBytes = pixelMap.getPixelBytesNumber();
  console.println("PixelMap total bytes: " + totalBytes);

  if (retImageInfo.isHdr) {
      console.println("Test PixelMap HDR");
  } else {
      console.println("Test PixelMap not HDR");
  }

  pixelMap.scaleSync(2, 2);
  const scaledInfo = pixelMap.getImageInfoSync();
  console.println(`Scaled image info: ${scaledInfo.size.width}, ${scaledInfo.size.height}`);
  const region: image.Region = {
    size: { width: 512, height: 512 },
    x: 0,
    y: 0
  };
  pixelMap.cropSync(region);
  const croppedInfo = pixelMap.getImageInfoSync();
  console.println(`Cropped image info: ${croppedInfo.size.width}, ${croppedInfo.size.height}`);
  pixelMap.flipSync(true, true);
  const flippedInfo = pixelMap.getImageInfoSync();
  console.println(`Flipped image info: ${flippedInfo.size.width}, ${flippedInfo.size.height}`);

  const alphaPixelMap = pixelMap.createAlphaPixelmapSync();
  if (alphaPixelMap != undefined) {
    console.println("Create alpha PixelMap success");
  }
  const alphaImageInfo = alphaPixelMap.getImageInfoSync();
  console.println(`Alpha get image info: ${alphaImageInfo.size.width}, ${alphaImageInfo.size.height}, ${alphaImageInfo.pixelFormat}, ${alphaImageInfo.alphaType}`);
  pixelMap.createAlphaPixelmap()
    .then((alphaPixelMap: image.PixelMap) => {
      const alphaImageInfo = alphaPixelMap.getImageInfoSync();
      console.println(`ASYNC Alpha get image info: ${alphaImageInfo.size.width}, ${alphaImageInfo.size.height}, ${alphaImageInfo.pixelFormat}, ${alphaImageInfo.alphaType}`);
    })

  let imageSource: image.ImageSource = image.createImageSource("/data/local/tmp/test.png");
  if (imageSource != undefined) {
    console.println("Create ImageSource by URI success");
  }
  
  let imagesourceImageInfo: image.ImageInfo = imageSource.getImageInfoSync(0);
  console.println(`Image source image info: ${imagesourceImageInfo.size.width}, ${imagesourceImageInfo.size.height}, ${imagesourceImageInfo.pixelFormat}, ${imagesourceImageInfo.density}, ${imagesourceImageInfo.mimeType}`);
  imageSource.getImageInfo(0)
    .then((imageInfo: image.ImageInfo) => {
      console.println(`ASYNC Image source image info: ${imageInfo.size.width}, ${imageInfo.size.height}, ${imageInfo.pixelFormat}, ${imageInfo.density}, ${imageInfo.mimeType}`);
    });
  
  const desiredSize: image.Size | undefined = { width: 60, height: 60 };
  const desiredRegion: image.Region | undefined = {
    size: { width: 60, height: 60 },
    x: 0,
    y: 0
  };
  const decodeOpt: image.DecodingOptions = {
    index: 0,
    sampleSize: 1,
    rotate: 0,
    editable: true,
    desiredSize,
    desiredRegion,
    desiredPixelFormat: image.PixelMapFormat.RGBA_8888,
    fitDensity: 1
  };
  let pixelmap2: image.PixelMap = imageSource.createPixelMapSync(decodeOpt);
  if (pixelmap2 != undefined) {
    console.println("Create imageSource.createPixelMapSync success");
  }
  imageSource.createPixelMap(decodeOpt)
    .then((pixelmap2: image.PixelMap) => {
      if (pixelmap2 != undefined) {
        console.println("ASYNC Create imageSource PixelMap success")
      }
    });
  pixelmap2.release()
    .then((): void => console.println("ASYNC Release PixelMap success"));

  imageSource.modifyImageProperty("Orientation", "Right-top");
  const map: Record<string, string | null> = {
    "Artist": "CQY",
    "Make": "Huawei",
    "Gamma": "0.9",
  };
  imageSource.modifyImageProperties(map)
    .then((): void => {
      let array: Array<string> = new Array<string>(4);
      array[0] = "Orientation";
      array[1] = "Artist";
      array[2] = "Make";
      array[3] = "Gamma";
      imageSource.getImageProperties(array)
        .then((properties: Record<string, string | null>): void => {
          console.println("ASYNC Get image properties: " + properties);
        });
    })

  console.println("TEST ImagePacker begin");
  const imagePacker = image.createImagePacker();
  console.println("ImagePacker supported formats: " + imagePacker.supportedFormats);
  let packOpts: image.PackingOption = new image.PackingOption(); 
  packOpts.format = "image/jpeg";
  packOpts.quality = 90;
  let packBuffer: ArrayBuffer = imagePacker.packing(pixelMap, packOpts);
  console.println("TEST ImagePacker end, bufferSize: " + packBuffer.byteLength);
  imagePacker.release();

  console.println("TEST pixelMap readPixelsToBuffer begin");
  let arrayBuffer: ArrayBuffer = new ArrayBuffer(opts.size.width * opts.size.height * 4);
  pixelMap.readPixelsToBufferSync(arrayBuffer);
  console.println("Read pixels to buffer success, size: " + arrayBuffer.byteLength); 
  pixelMap.readPixelsToBuffer(arrayBuffer)
    .then((): void => console.println("ASYNC Read pixels to buffer success, size: " + arrayBuffer.byteLength));

  console.println("TEST Picture begin");
  const picture = image.createPicture(pixelMap);
  if (picture != undefined) {
    console.println("Create picture success");
  }
  const picturePixelMap = picture.getMainPixelmap();
  const pictureInfo = picturePixelMap.getImageInfoSync();
  console.println(`Picture PixelMap image info: ${pictureInfo.size.width}, ${pictureInfo.size.height}, ${pictureInfo.pixelFormat}, ${pictureInfo.alphaType}`);
  
  const regionAsync: image.Region = {
    size: { width: 1, height: 1 },
    x: 256,
    y: 256
  }
  pixelMap.crop(regionAsync)
    .then((): void => {
      const croppedInfo = pixelMap.getImageInfoSync();
      console.println(`ASYNC Cropped image info: ${croppedInfo.size.width}, ${croppedInfo.size.height}`);
    });

  console.println("====== Sync methods completed ======")
}