import type { Finding } from "../../core/analysis/finding";
import type { ByteSource } from "../../core/bytes/ByteSource";
import { ImageDecodeError, type ChannelName, type DecodeResult } from "../image";

export interface BmpHeader {
  declaredFileSize: number;
  pixelOffset: number;
  headerSize: number;
  width: number;
  /** Absolute row count. */
  height: number;
  topDown: boolean;
  bitCount: number;
  compression: number;
  colorsUsed: number;
  /** Offset of the height field, for patching. */
  heightFieldOffset: number;
  widthFieldOffset: number;
  /** BITMAPCOREHEADER stores 16-bit dimensions; later headers use 32-bit. */
  dimensionFieldSize: 2 | 4;
}

export interface BmpStructure {
  header?: BmpHeader;
  rowStride: number;
  findings: Finding[];
}

const SUPPORTED_BIT_COUNTS = [1, 4, 8, 24, 32];

export function bmpRowStride(width: number, bitCount: number): number {
  return Math.floor((bitCount * width + 31) / 32) * 4;
}

export async function parseBmp(source: ByteSource): Promise<BmpStructure> {
  const findings: Finding[] = [];
  const head = await source.read(0, 54);
  if (head.length < 26 || head[0] !== 0x42 || head[1] !== 0x4d) {
    findings.push({ id: "bmp.signature", severity: "strong", message: 'Not a BMP file (missing "BM")' });
    return { rowStride: 0, findings };
  }
  const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const headerSize = view.getUint32(14, true);
  let header: BmpHeader;
  if (headerSize === 12) {
    header = {
      declaredFileSize: view.getUint32(2, true),
      pixelOffset: view.getUint32(10, true),
      headerSize,
      width: view.getUint16(18, true),
      height: view.getUint16(20, true),
      topDown: false,
      bitCount: view.getUint16(24, true),
      compression: 0,
      colorsUsed: 0,
      widthFieldOffset: 18,
      heightFieldOffset: 20,
      dimensionFieldSize: 2,
    };
  } else if (headerSize >= 40 && head.length >= 54) {
    const signedHeight = view.getInt32(22, true);
    header = {
      declaredFileSize: view.getUint32(2, true),
      pixelOffset: view.getUint32(10, true),
      headerSize,
      width: view.getInt32(18, true),
      height: Math.abs(signedHeight),
      topDown: signedHeight < 0,
      bitCount: view.getUint16(28, true),
      compression: view.getUint32(30, true),
      colorsUsed: view.getUint32(46, true),
      widthFieldOffset: 18,
      heightFieldOffset: 22,
      dimensionFieldSize: 4,
    };
  } else {
    findings.push({ id: "bmp.header", severity: "strong", message: `Unsupported BMP header size ${headerSize}` });
    return { rowStride: 0, findings };
  }

  const rowStride = header.width > 0 ? bmpRowStride(header.width, header.bitCount) : 0;
  if (header.width <= 0 || header.height === 0) {
    findings.push({
      id: "bmp.dimensions",
      severity: "strong",
      message: `Invalid dimensions ${header.width}×${header.height}`,
      span: { offset: header.widthFieldOffset, length: header.dimensionFieldSize * 2 },
    });
  }
  if (header.declaredFileSize !== source.size) {
    findings.push({
      id: "bmp.filesize",
      severity: "medium",
      message: `Header declares ${header.declaredFileSize} bytes but the file is ${source.size} bytes`,
      span: { offset: 2, length: 4 },
    });
  }
  if (rowStride > 0 && header.compression === 0) {
    const expected = rowStride * header.height;
    const available = source.size - header.pixelOffset;
    if (available > expected) {
      const fullRows = Math.floor(available / rowStride);
      findings.push({
        id: "bmp.extra-rows",
        ruleId: "bmp.rows",
        severity: fullRows > header.height ? "strong" : "medium",
        message:
          fullRows > header.height
            ? `Pixel data holds ${fullRows} rows but the header says ${header.height}: the height may have been reduced`
            : `${available - expected} byte(s) after the pixel data`,
        span: { offset: header.pixelOffset + expected, length: available - expected },
        evidence: [
          {
            kind: "consistency",
            tier: fullRows > header.height ? "strong" : "medium",
            detail: `${available} bytes of pixel data from offset ${header.pixelOffset}; ${header.width}×${header.height} at ${rowStride} bytes per row needs only ${expected}`,
            span: { offset: header.heightFieldOffset, length: header.dimensionFieldSize },
          },
        ],
        suggestion:
          fullRows > header.height
            ? { operationId: "bmp.set-dimensions", params: { height: fullRows }, label: `Set height to ${fullRows}` }
            : { operationId: "bytes.slice", params: { offset: header.pixelOffset + expected, length: -1 }, label: "Extract trailing data" },
      });
    } else if (available < expected) {
      findings.push({
        id: "bmp.short",
        severity: "medium",
        message: `Pixel data is ${expected - available} byte(s) shorter than the dimensions require`,
      });
    }
  }
  return { header, rowStride, findings };
}

export async function decodeBmp(source: ByteSource, structure: BmpStructure, maxPixels = 100_000_000): Promise<DecodeResult> {
  const { header, rowStride } = structure;
  if (!header) throw new ImageDecodeError("Not a valid BMP");
  if (header.compression !== 0) throw new ImageDecodeError(`BMP compression ${header.compression} is not supported yet`);
  if (!SUPPORTED_BIT_COUNTS.includes(header.bitCount)) {
    throw new ImageDecodeError(`${header.bitCount}-bit BMP is not supported yet`);
  }
  if (header.width <= 0 || header.height <= 0) throw new ImageDecodeError("Invalid BMP dimensions");
  if (header.width * header.height > maxPixels) {
    throw new ImageDecodeError(`${header.width}×${header.height} exceeds the ${maxPixels.toLocaleString()} pixel limit`);
  }

  const warnings: string[] = [];
  const { width, height, bitCount } = header;
  const channels: readonly ChannelName[] = bitCount === 24 ? ["B", "G", "R"] : bitCount === 32 ? ["B", "G", "R", "A"] : ["I"];
  const count = channels.length;
  const data = await source.read(Math.min(header.pixelOffset, source.size), rowStride * height);
  if (data.length < rowStride * height) {
    warnings.push(`Pixel data is short: ${data.length} of ${rowStride * height} bytes; missing pixels are zero`);
  }

  const samples = new Uint8Array(width * height * count);
  for (let y = 0; y < height; y++) {
    const stored = header.topDown ? y : height - 1 - y;
    const row = data.subarray(stored * rowStride, (stored + 1) * rowStride);
    for (let x = 0; x < width; x++) {
      const target = (y * width + x) * count;
      if (bitCount >= 8) {
        const bytesPerPixel = bitCount >> 3;
        for (let c = 0; c < count; c++) samples[target + c] = row[x * bytesPerPixel + c] ?? 0;
      } else {
        const bit = x * bitCount;
        samples[target] = ((row[bit >> 3] ?? 0) >> (8 - bitCount - (bit & 7))) & ((1 << bitCount) - 1);
      }
    }
  }

  let palette: Uint8Array | undefined;
  if (bitCount <= 8) {
    const entrySize = header.headerSize === 12 ? 3 : 4;
    const entries = header.colorsUsed || 1 << bitCount;
    const raw = await source.read(14 + header.headerSize, Math.min(entries, 256) * entrySize);
    palette = new Uint8Array(256 * 4);
    for (let i = 0; i < 256; i++) palette[i * 4 + 3] = 255;
    for (let i = 0; i * entrySize + 2 < raw.length; i++) {
      palette[i * 4] = raw[i * entrySize + 2];
      palette[i * 4 + 1] = raw[i * entrySize + 1];
      palette[i * 4 + 2] = raw[i * entrySize];
    }
  }

  return {
    image: { format: "bmp", width, height, channels, bitDepth: 8 > bitCount ? bitCount : 8, samples, ...(palette ? { palette } : {}) },
    warnings,
  };
}
