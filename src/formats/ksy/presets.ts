/** Built-in .ksy schemas, written for this project (MIT). They double as examples of the supported subset. */

export const PRESETS: Record<string, string> = {
  png: `meta:
  id: png
  title: PNG image
  file-extension: png
  endian: be
  encoding: ASCII
doc: |
  PNG signature and chunks. Every chunk CRC is verified with the -checksum
  extension, and editing a field recomputes it.
seq:
  - id: magic
    contents: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
  - id: chunks
    type: chunk
    repeat: until
    repeat-until: _.type == "IEND" or _io.eof
types:
  chunk:
    seq:
      - id: len
        type: u4
      - id: type
        type: str
        size: 4
      - id: body
        size: len
        type:
          switch-on: type
          cases:
            '"IHDR"': ihdr
            '"PLTE"': plte
            '"tEXt"': text
            '"zTXt"': compressed_text
            '"tIME"': time
            '"pHYs"': phys
            '"gAMA"': gama
      - id: crc
        type: u4
        doc: CRC-32 of the type and body.
        -checksum:
          algorithm: crc32
          start: _io.pos - len - 4
          end: _io.pos
  ihdr:
    seq:
      - id: width
        type: u4
      - id: height
        type: u4
      - id: bit_depth
        type: u1
      - id: color_type
        type: u1
        enum: color_type
      - id: compression_method
        type: u1
      - id: filter_method
        type: u1
      - id: interlace_method
        type: u1
  plte:
    seq:
      - id: entries
        type: rgb
        repeat: eos
  rgb:
    seq:
      - id: r
        type: u1
      - id: g
        type: u1
      - id: b
        type: u1
  text:
    seq:
      - id: keyword
        type: strz
        encoding: ISO-8859-1
      - id: text
        type: str
        size-eos: true
        encoding: ISO-8859-1
  compressed_text:
    seq:
      - id: keyword
        type: strz
        encoding: ISO-8859-1
      - id: compression_method
        type: u1
      - id: text
        size-eos: true
        process: zlib
        type: latin1_text
  latin1_text:
    seq:
      - id: value
        type: str
        size-eos: true
        encoding: ISO-8859-1
  time:
    seq:
      - id: year
        type: u2
      - id: month
        type: u1
      - id: day
        type: u1
      - id: hour
        type: u1
      - id: minute
        type: u1
      - id: second
        type: u1
  phys:
    seq:
      - id: pixels_per_unit_x
        type: u4
      - id: pixels_per_unit_y
        type: u4
      - id: unit
        type: u1
        enum: phys_unit
  gama:
    seq:
      - id: gamma_int
        type: u4
    instances:
      gamma:
        value: gamma_int / 100000.0
enums:
  color_type:
    0: greyscale
    2: truecolor
    3: indexed
    4: greyscale_alpha
    6: truecolor_alpha
  phys_unit:
    0: unknown
    1: meter
`,

  bmp: `meta:
  id: bmp
  title: BMP image
  file-extension: bmp
  endian: le
doc: |
  BMP file header, BITMAPINFOHEADER (or a later version) and colour table.
  pixels covers everything from the pixel offset on; compare its size with
  expected_pixel_bytes to spot rows hidden by a reduced height.
seq:
  - id: file_header
    type: file_header
  - id: dib_header
    type: dib_header
  - id: color_table
    type: bgrx
    repeat: expr
    repeat-expr: 'dib_header.colors_used != 0 ? dib_header.colors_used : (dib_header.bits_per_pixel <= 8 ? 1 << dib_header.bits_per_pixel : 0)'
instances:
  pixels:
    pos: file_header.pixel_offset
    size-eos: true
  expected_pixel_bytes:
    value: 'dib_header.row_size * (dib_header.height < 0 ? -dib_header.height : dib_header.height)'
types:
  file_header:
    seq:
      - id: magic
        contents: BM
      - id: file_size
        type: u4
      - id: reserved1
        type: u2
      - id: reserved2
        type: u2
      - id: pixel_offset
        type: u4
  dib_header:
    seq:
      - id: header_size
        type: u4
        valid:
          min: 40
      - id: width
        type: s4
      - id: height
        type: s4
        doc: Negative means the rows are stored top-down.
      - id: planes
        type: u2
      - id: bits_per_pixel
        type: u2
      - id: compression
        type: u4
        enum: compression
      - id: image_size
        type: u4
      - id: x_pixels_per_meter
        type: s4
      - id: y_pixels_per_meter
        type: s4
      - id: colors_used
        type: u4
      - id: colors_important
        type: u4
      - id: extra
        size: header_size - 40
        if: header_size > 40
    instances:
      row_size:
        value: (bits_per_pixel * width + 31) / 32 * 4
  bgrx:
    seq:
      - id: b
        type: u1
      - id: g
        type: u1
      - id: r
        type: u1
      - id: reserved
        type: u1
enums:
  compression:
    0: rgb
    1: rle8
    2: rle4
    3: bitfields
    4: jpeg
    5: png
    6: alpha_bitfields
`,

  gif: `meta:
  id: gif
  title: GIF image
  file-extension: gif
  endian: le
  encoding: ASCII
doc: GIF header, colour tables and the block stream (extensions, images, trailer).
seq:
  - id: magic
    contents: GIF
  - id: version
    type: str
    size: 3
  - id: screen
    type: logical_screen
  - id: global_color_table
    type: rgb
    repeat: expr
    repeat-expr: 2 << (screen.flags & 7)
    if: screen.flags & 0x80 != 0
  - id: blocks
    type: block
    repeat: until
    repeat-until: _.block_type == block_type::trailer or _io.eof
types:
  logical_screen:
    seq:
      - id: width
        type: u2
      - id: height
        type: u2
      - id: flags
        type: u1
      - id: bg_color_index
        type: u1
      - id: pixel_aspect_ratio
        type: u1
  rgb:
    seq:
      - id: r
        type: u1
      - id: g
        type: u1
      - id: b
        type: u1
  block:
    seq:
      - id: block_type
        type: u1
        enum: block_type
        valid:
          any-of: [block_type::extension, block_type::image, block_type::trailer]
      - id: body
        type:
          switch-on: block_type
          cases:
            block_type::extension: extension
            block_type::image: image
  extension:
    seq:
      - id: label
        type: u1
        enum: extension_label
      - id: body
        type:
          switch-on: label
          cases:
            extension_label::graphic_control: graphic_control
            extension_label::comment: text_sub_blocks
            _: sub_blocks
  graphic_control:
    seq:
      - id: block_size
        contents: [4]
      - id: flags
        type: u1
      - id: delay_time
        type: u2
        doc: In hundredths of a second.
      - id: transparent_index
        type: u1
      - id: terminator
        contents: [0]
  image:
    seq:
      - id: left
        type: u2
      - id: top
        type: u2
      - id: width
        type: u2
      - id: height
        type: u2
      - id: flags
        type: u1
      - id: local_color_table
        type: rgb
        repeat: expr
        repeat-expr: 2 << (flags & 7)
        if: flags & 0x80 != 0
      - id: lzw_min_code_size
        type: u1
      - id: data
        type: sub_blocks
  sub_blocks:
    seq:
      - id: blocks
        type: sub_block
        repeat: until
        repeat-until: _.len == 0
  sub_block:
    seq:
      - id: len
        type: u1
      - id: data
        size: len
  text_sub_blocks:
    seq:
      - id: blocks
        type: text_sub_block
        repeat: until
        repeat-until: _.len == 0
  text_sub_block:
    seq:
      - id: len
        type: u1
      - id: text
        type: str
        size: len
enums:
  block_type:
    0x21: extension
    0x2c: image
    0x3b: trailer
  extension_label:
    0x01: plain_text
    0xf9: graphic_control
    0xfe: comment
    0xff: application
`,

  wav: `meta:
  id: wav
  title: WAV audio (RIFF)
  file-extension: wav
  endian: le
  encoding: ASCII
doc: RIFF/WAVE container with fmt, LIST/INFO and data chunks (odd sizes are padded).
seq:
  - id: riff
    contents: RIFF
  - id: file_size
    type: u4
  - id: wave
    contents: WAVE
  - id: chunks
    type: chunk
    repeat: eos
types:
  chunk:
    seq:
      - id: id
        type: str
        size: 4
      - id: len
        type: u4
      - id: body
        size: len
        type:
          switch-on: id
          cases:
            '"fmt "': fmt
            '"LIST"': list
      - id: pad
        size: 'len % 2 == 1 and not _io.eof ? 1 : 0'
        doc: Odd-sized chunks are padded to an even length (some writers omit it at the end of the file).
  fmt:
    seq:
      - id: format
        type: u2
        enum: format
      - id: channels
        type: u2
      - id: sample_rate
        type: u4
      - id: byte_rate
        type: u4
      - id: block_align
        type: u2
      - id: bits_per_sample
        type: u2
      - id: extra
        size-eos: true
  list:
    seq:
      - id: list_type
        type: str
        size: 4
      - id: items
        type: list_item
        repeat: eos
  list_item:
    seq:
      - id: id
        type: str
        size: 4
      - id: len
        type: u4
      - id: value
        type: strz
        size: len
      - id: pad
        size: len % 2
enums:
  format:
    1: pcm
    3: ieee_float
    6: alaw
    7: mulaw
    0xfffe: extensible
`,

  zip: `meta:
  id: zip
  title: ZIP archive
  file-extension: zip
  endian: le
  encoding: UTF-8
doc: |
  ZIP records in file order: local files, central directory, end record.
  Entries written with data descriptors (flag bit 3) cannot be walked this way.
  Bit 0 of flags is the encryption flag (fake encryption sets it alone).
seq:
  - id: sections
    type: section
    repeat: until
    repeat-until: _.section_type == section_type::end_of_central_dir or _io.eof
types:
  section:
    seq:
      - id: magic
        contents: PK
      - id: section_type
        type: u2
        enum: section_type
        valid:
          any-of: [section_type::local_file, section_type::central_dir_entry, section_type::end_of_central_dir, section_type::data_descriptor]
      - id: body
        type:
          switch-on: section_type
          cases:
            section_type::local_file: local_file
            section_type::central_dir_entry: central_dir_entry
            section_type::end_of_central_dir: end_of_central_dir
            section_type::data_descriptor: data_descriptor
  local_file:
    seq:
      - id: version_needed
        type: u2
      - id: flags
        type: u2
      - id: compression
        type: u2
        enum: compression
      - id: mod_time
        type: u2
      - id: mod_date
        type: u2
      - id: crc32
        type: u4
      - id: compressed_size
        type: u4
      - id: uncompressed_size
        type: u4
      - id: name_len
        type: u2
      - id: extra_len
        type: u2
      - id: name
        type: str
        size: name_len
      - id: extra
        size: extra_len
      - id: data
        size: compressed_size
  central_dir_entry:
    seq:
      - id: version_made_by
        type: u2
      - id: version_needed
        type: u2
      - id: flags
        type: u2
      - id: compression
        type: u2
        enum: compression
      - id: mod_time
        type: u2
      - id: mod_date
        type: u2
      - id: crc32
        type: u4
      - id: compressed_size
        type: u4
      - id: uncompressed_size
        type: u4
      - id: name_len
        type: u2
      - id: extra_len
        type: u2
      - id: comment_len
        type: u2
      - id: disk_start
        type: u2
      - id: internal_attrs
        type: u2
      - id: external_attrs
        type: u4
      - id: local_header_offset
        type: u4
      - id: name
        type: str
        size: name_len
      - id: extra
        size: extra_len
      - id: comment
        type: str
        size: comment_len
  end_of_central_dir:
    seq:
      - id: disk_number
        type: u2
      - id: central_dir_disk
        type: u2
      - id: entries_on_disk
        type: u2
      - id: entries_total
        type: u2
      - id: central_dir_size
        type: u4
      - id: central_dir_offset
        type: u4
      - id: comment_len
        type: u2
      - id: comment
        type: str
        size: comment_len
  data_descriptor:
    seq:
      - id: crc32
        type: u4
      - id: compressed_size
        type: u4
      - id: uncompressed_size
        type: u4
enums:
  section_type:
    0x0201: central_dir_entry
    0x0403: local_file
    0x0605: end_of_central_dir
    0x0807: data_descriptor
  compression:
    0: stored
    8: deflate
    9: deflate64
    12: bzip2
    14: lzma
    93: zstd
    99: aes
`,
};

export function sniffFormat(head: Uint8Array): string | null {
  const ascii = String.fromCharCode(...head.subarray(0, 12));
  if (ascii.startsWith("\x89PNG")) return "png";
  if (ascii.startsWith("GIF8")) return "gif";
  if (ascii.startsWith("RIFF") && ascii.slice(8, 12) === "WAVE") return "wav";
  if (ascii.startsWith("PK\x03\x04") || ascii.startsWith("PK\x05\x06")) return "zip";
  if (ascii.startsWith("BM")) return "bmp";
  return null;
}
