import type { Bytes } from "../../core/bytes/ByteSource";

/** 24-bit BMP with top-down rows (negative height), which the raw decoder and most viewers read. */
export function encodeBmp24(width: number, height: number, rgbTopDown: Uint8Array): Bytes {
  const stride = Math.ceil((width * 3) / 4) * 4;
  const file = new Uint8Array(54 + stride * height);
  const view = new DataView(file.buffer);
  file[0] = 0x42;
  file[1] = 0x4d;
  view.setUint32(2, file.length, true);
  view.setUint32(10, 54, true);
  view.setUint32(14, 40, true);
  view.setInt32(18, width, true);
  view.setInt32(22, -height, true);
  view.setUint16(26, 1, true);
  view.setUint16(28, 24, true);
  view.setUint32(34, stride * height, true);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const from = (y * width + x) * 3;
      const to = 54 + y * stride + x * 3;
      file[to] = rgbTopDown[from + 2];
      file[to + 1] = rgbTopDown[from + 1];
      file[to + 2] = rgbTopDown[from];
    }
  }
  return file;
}
