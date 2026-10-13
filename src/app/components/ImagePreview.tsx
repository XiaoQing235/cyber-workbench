import { useEffect, useMemo, useRef, useState } from "react";
import type { Suggestion } from "../../core/analysis/finding";
import type { ByteSource } from "../../core/bytes/ByteSource";
import { decodeImage } from "../../formats/decode";
import { bitPlaneRgba, toRgba, type DecodedImage, type DecodeResult } from "../../formats/image";

const MAX_PREVIEW_PIXELS = 40_000_000;
/** Small images are scaled up by a whole factor (crisp pixels) until about this many CSS pixels across. */
const SMALL_IMAGE_TARGET = 320;
const MAX_SCALE = 16;
const CHANNEL_ORDER = "RGBAYI";
const BUTTON = "rounded border border-slate-300 bg-white px-2 py-0.5 hover:bg-slate-100";

interface Plane {
  channel: number;
  name: string;
  bit: number;
}

/** Every bit of every channel, in R G B A order, least significant bit first. */
function listPlanes(image: DecodedImage): Plane[] {
  return [...image.channels.entries()]
    .sort(([, a], [, b]) => CHANNEL_ORDER.indexOf(a) - CHANNEL_ORDER.indexOf(b))
    .flatMap(([channel, name]) => Array.from({ length: image.bitDepth }, (_, bit) => ({ channel, name, bit })));
}

interface Props {
  source: ByteSource;
  /** Proposes extracting the bit plane on view with `image.lsb`. */
  onExtract?: (suggestion: Suggestion) => void;
}

/** Display-only rendering of raw-decoded samples; analysis never reads pixels back from Canvas. */
export function ImagePreview({ source, onExtract }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [decoded, setDecoded] = useState<DecodeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ignoreAlphaChoice, setIgnoreAlphaChoice] = useState<boolean | null>(null);
  const [planeIndex, setPlaneIndex] = useState(-1);
  const planes = useMemo(() => (decoded ? listPlanes(decoded.image) : []), [decoded]);
  const plane = planeIndex >= 0 ? planes[planeIndex] : undefined;

  useEffect(() => {
    let cancelled = false;
    decodeImage(source, { maxPixels: MAX_PREVIEW_PIXELS }).then(
      (result) => {
        if (!cancelled) setDecoded(result);
      },
      (reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [source]);

  // 32-bit BMP alpha is usually unused padding, so it is ignored unless the user opts in.
  const ignoreAlpha = ignoreAlphaChoice ?? decoded?.image.format === "bmp";

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!decoded || !canvas) return;
    const { image } = decoded;
    canvas.width = image.width;
    canvas.height = image.height;
    const rgba = plane ? bitPlaneRgba(image, plane.channel, plane.bit) : toRgba(image, ignoreAlpha);
    canvas.getContext("2d")?.putImageData(new ImageData(rgba, image.width, image.height), 0, 0);
  }, [decoded, ignoreAlpha, plane]);

  if (error) return <p className="text-sm text-red-700">Cannot decode image: {error}</p>;
  if (!decoded) return <p className="text-sm text-slate-500">Decoding…</p>;

  const { image, warnings } = decoded;
  const hasAlpha = image.channels.includes("A") || image.palette !== undefined;
  const scale = Math.max(1, Math.min(MAX_SCALE, Math.floor(SMALL_IMAGE_TARGET / Math.max(image.width, image.height))));
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-3 text-xs text-slate-600">
        <span>
          {image.format.toUpperCase()} · {image.width}×{image.height} · channels {image.channels.join("")} ·{" "}
          {image.bitDepth}-bit{scale > 1 && ` · shown at ${scale}×`}
        </span>
        {hasAlpha && !plane && (
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={ignoreAlpha} onChange={(event) => setIgnoreAlphaChoice(event.target.checked)} />
            Ignore alpha (show RGB hidden under transparent pixels)
          </label>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-1 text-xs text-slate-600">
        <span className="mr-1">View</span>
        <button
          className={BUTTON}
          title="Previous bit plane"
          onClick={() => setPlaneIndex((index) => (index < 0 ? planes.length - 1 : index - 1))}
        >
          ◀
        </button>
        <select
          aria-label="Bit plane"
          className="rounded border border-slate-300 px-1 py-0.5"
          value={planeIndex}
          onChange={(event) => setPlaneIndex(Number(event.target.value))}
        >
          <option value={-1}>Normal</option>
          {planes.map((option, index) => (
            <option key={index} value={index}>
              {option.name} bit {option.bit}
            </option>
          ))}
        </select>
        <button
          className={BUTTON}
          title="Next bit plane"
          onClick={() => setPlaneIndex((index) => (index + 1 >= planes.length ? -1 : index + 1))}
        >
          ▶
        </button>
        {plane && onExtract && (
          <button
            className={BUTTON}
            onClick={() =>
              onExtract({
                operationId: "image.lsb",
                params: { channels: plane.name, bit: plane.bit },
                label: "Extract bits",
              })
            }
          >
            Extract these bits →
          </button>
        )}
      </div>
      {warnings.map((warning) => (
        <p key={warning} className="text-xs text-amber-700">
          {warning}
        </p>
      ))}
      <div className="max-h-[480px] w-fit max-w-full overflow-auto rounded border border-slate-200 bg-[repeating-conic-gradient(#e2e8f0_0_25%,#fff_0_50%)] bg-[length:16px_16px] p-2">
        <canvas ref={canvasRef} className="max-w-full [image-rendering:pixelated]" style={{ width: image.width * scale }} />
      </div>
      <p className="text-xs text-slate-500">Preview only. Stego operations read the raw samples, not this canvas.</p>
    </div>
  );
}
