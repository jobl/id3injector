# id3injector

[![Test](https://github.com/jobl/id3injector/actions/workflows/test.yml/badge.svg)](https://github.com/jobl/id3injector/actions/workflows/test.yml)
[![Lint](https://github.com/jobl/id3injector/actions/workflows/lint.yml/badge.svg)](https://github.com/jobl/id3injector/actions/workflows/lint.yml)
[![Release](https://img.shields.io/github/v/release/jobl/id3injector)](https://github.com/jobl/id3injector/releases/latest)
[![Go](https://img.shields.io/badge/go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](UNLICENSE)

ID3v2.4 timed metadata injector for MPEG Transport Streams. Works with any TS stream and follows the HLS timed metadata convention (stream type 0x15) supported by Apple, ExoPlayer, hls.js, Shaka Player, and most broadcast toolchains. Supports static metadata files, live injection via FIFO or HTTP, and real-time piped streams.

Single static binary, zero runtime dependencies.

**Tested on:**
- Ubuntu 22.04.5 LTS (amd64)
- Ubuntu 24.04.3 LTS (amd64)
- macOS 15.5 (arm64)

## Installation

```bash
go install github.com/jobl/id3injector@latest
```

Or download a pre-built binary from [Releases](https://github.com/jobl/id3injector/releases).

### Building from source

```bash
git clone https://github.com/jobl/id3injector.git
cd id3injector
make build
```

Cross-compile for any platform:

```bash
GOOS=linux GOARCH=amd64 make build
GOOS=windows GOARCH=amd64 make build
GOOS=darwin GOARCH=arm64 make build
```

## Usage

```
id3injector – ID3v2.4 timed metadata injector for MPEG TS

Usage: id3injector [-i file] [-o file] [-e file] [-d]

Input and output are auto-inferred from pipes when omitted.

  -i string     Input MPEG TS file (auto: stdin when piped)
  -o string     Output file (auto: stdout when piped)
  -e string     Timed metadata file
  -metastart N  Starting continuity counter for metadata packets (0-15, default 0)
  -repeat N     Inject metadata every N seconds (live)
  -text string  Text to inject with -repeat
  -live         Stream metadata from -e continuously (for FIFOs)
  -listen addr  HTTP listen address (e.g. :8080 or 127.0.0.1:8080)
  -v            Verbose: stream table, duration, and ID3 tag listing
  -d            Debug output (protocol-level)
  -version      Print version and exit
```

All diagnostics go to stderr, so piped binary output is clean.

The tool prints its resolved settings on startup:

```
** input:     stdin
** output:    stdout
```

## Examples

Inject metadata into a file:

```bash
id3injector -i input.ts -o output.ts -e metadata.txt
```

Validate a stream (no output, no metadata):

```bash
id3injector -i input.ts
id3injector -i input.ts -v            # verbose: stream table + ID3 tags
id3injector -i input.ts -d            # protocol-level debug
```

Pipe from ffmpeg, inject, and play:

```bash
ffmpeg -re -i input.ts -c copy -f mpegts pipe:1 \
  | id3injector -e metadata.txt \
  | ffplay pipe:0
```

When piping, `-i` and `-o` are optional. Stdin and stdout are detected automatically:

```bash
curl -s https://example.com/stream.ts | id3injector -v
```

When injecting, id3injector modifies the PMT to add a metadata elementary stream (stream type 0x15, ID3v2.4 in PES) with metadata_pointer_descriptor and metadata_descriptor. The metadata PID is auto-assigned as the highest existing PID + 1.

## Metadata format

Plain text file, one entry per line, compatible with Apple `mediafilesegmenter`:

```
<seconds> <format> <content>
```

| Field | Description |
|-------|-------------|
| `seconds` | Time offset in seconds (decimals supported for sub-second precision, e.g. `1.5`, `0.1`) |
| `format` | `plaintext` (auto-wrapped as TPE1) or `id3` (raw ID3 file) |
| `content` | Text string (plaintext) or filename (id3) |

Example:

```
0 plaintext Station: Radio One
0.5 plaintext Ad: Sponsor
30 plaintext Now Playing: Song Title
60 id3 /path/to/custom.id3
```

Times are converted to PTS ticks (90 kHz) internally, giving ~11 microsecond resolution. Lines do not need to be sorted; they are ordered chronologically at parse time.

## ID3 frame types

The `plaintext` format wraps text as a **TPE1** (artist/performer) ID3v2.4 frame. This is the simplest option and works with most HLS players.

For other ID3 frame types like **TXXX**, **PRIV**, or **GEOB**, use one of these approaches:

1. **`id3` format in metadata files**: point to a pre-built `.id3` file:

```
0 id3 /path/to/custom-txxx.id3
```

2. **`id3_base64` via HTTP**: post any raw ID3 tag as base64:

```bash
# Build a TXXX tag (e.g. with a script or library) and inject it
TAG=$(python3 -c "
import struct
desc = b'adType'
val = b'preroll'
payload = b'\x03' + desc + b'\x00' + val  # UTF-8 encoding
frame = b'TXXX' + struct.pack('>I', len(payload)) + b'\x00\x00' + payload
size = len(frame)
header = b'ID3\x04\x00\x00' + bytes([
    (size >> 21) & 0x7f, (size >> 14) & 0x7f,
    (size >> 7) & 0x7f, size & 0x7f])
import base64; print(base64.b64encode(header + frame).decode())
")

curl -X POST localhost:8080/inject -d "{\"id3_base64\":\"$TAG\"}"
```

3. **Any language/tool** that produces an ID3v2.4 binary can feed tags via the HTTP endpoint or as `.id3` files.

| Frame | Use case | Built-in? |
|-------|----------|-----------|
| TPE1 | Simple text (song title, station name) | Yes (`plaintext`) |
| TXXX | Structured key-value pairs (ad cues, analytics) | Via `id3`/`id3_base64` |
| PRIV | Vendor-specific binary (tracking, DRM) | Via `id3`/`id3_base64` |
| GEOB | Arbitrary binary + MIME type | Via `id3`/`id3_base64` |

> **Note:** All ID3 tags must fit in a single TS packet (max ~170 bytes). This is sufficient for text metadata but not for large binary payloads like album art.

## Live injection

Three live injection methods are available and can be combined with each other and with static metadata files.

### Repeat (`-repeat`)

Inject the same tag at a fixed interval:

```bash
# Inject "Radio One" every 5 seconds into a live ffmpeg stream
ffmpeg -re -i input.ts -c copy -f mpegts pipe:1 \
  | id3injector -repeat 5 -text "Radio One" \
  | ffplay pipe:0
```

### FIFO (`-live -e`)

Stream metadata lines from a named pipe. Another process writes lines at any time and they are injected immediately:

```bash
# Set up the FIFO
mkfifo /tmp/meta_fifo

# Start the pipeline (keeps reading from the FIFO)
ffmpeg -re -i input.ts -c copy -f mpegts pipe:1 \
  | id3injector -live -e /tmp/meta_fifo \
  | ffplay pipe:0 &

# Inject on demand from another terminal (persistent writer)
exec 3>/tmp/meta_fifo          # open once, keep open
echo "Breaking News" >&3
echo "Now Playing: New Song" >&3
exec 3>&-                      # close when done
```

Plain text lines are auto-wrapped as TPE1 ID3 tags. The full `<seconds> <format> <content>` syntax is also accepted, but the time field is ignored since tags are always injected at the next available PTS.

> **Tip:** Each `echo ... > /tmp/meta_fifo` opens and closes the pipe, which
> causes EOF and stops the reader after one line. Use a persistent file
> descriptor (`exec 3>`) as shown above, or pipe a long-lived process into
> the FIFO:
>
> ```bash
> tail -f events.log > /tmp/meta_fifo
> ```
>
> Every line appended to `events.log` is then injected in real time.

### HTTP (`-listen`)

Built-in HTTP server that accepts `POST /inject` requests with JSON payloads:

```bash
# Start with HTTP control on port 8080
ffmpeg -re -i input.ts -c copy -f mpegts pipe:1 \
  | id3injector -listen :8080 \
  | ffplay pipe:0 &

# Inject via HTTP from anywhere
curl -X POST localhost:8080/inject -d '{"text":"Breaking News"}'
curl -X POST localhost:8080/inject -d '{"text":"Now Playing: Song Title"}'

# Or inject a raw ID3 tag (base64-encoded)
curl -X POST localhost:8080/inject -d '{"id3_base64":"SUQzBAA..."}'
```

### Combining sources

All methods can be active simultaneously:

```bash
ffmpeg -re -i input.ts -c copy -f mpegts pipe:1 \
  | id3injector \
      -e metadata.txt \
      -repeat 10 -text "Station ID" \
      -listen :8080 \
  | ffplay pipe:0
```

## Testing & verification

### Run the test suite

```bash
make test             # runs go test -race ./...
```

### Quick end-to-end test

Generate a test stream, inject metadata, and verify the output:

```bash
# 1. Create a 5-second test stream
ffmpeg -f lavfi -i testsrc=duration=5:size=320x240:rate=30 \
       -f lavfi -i sine=frequency=440:duration=5:sample_rate=44100 \
       -c:v libx264 -c:a aac -f mpegts input.ts

# 2. Create a metadata file
cat > metadata.txt <<EOF
0 plaintext Hello World
0.5 plaintext Track: Song A
2 plaintext Track: Song B
3 plaintext Breaking News
4 plaintext Goodbye
EOF

# 3. Inject
id3injector -i input.ts -o output.ts -e metadata.txt

# 4. Validate with id3injector itself
id3injector -i output.ts -v
```

### Verifying with ffprobe

ffprobe can inspect the injected ID3 metadata at several levels of detail.

**List all streams** to confirm the `timed_id3` data stream exists:

```bash
ffprobe -show_streams output.ts 2>/dev/null | grep -A5 codec_name=timed_id3
```

**Show ID3 packets** with timestamps:

```bash
ffprobe -show_packets -select_streams d output.ts 2>/dev/null
```

Each packet shows `pts_time` (when the tag appears) and `size` (ID3 frame size in bytes).

**Extract the raw ID3 payload** to verify tag content:

```bash
ffprobe -show_data -show_packets -select_streams d output.ts 2>/dev/null
```

The hex dump in each packet contains the raw ID3v2.4 frame. Look for the `TPE1` header followed by UTF-8 text.

**Read ID3 frames as data** using ffmpeg:

```bash
ffmpeg -i output.ts -map 0:d -f data -c copy - 2>/dev/null | strings
```

Extracts all ID3 data and pipes through `strings` to show the plaintext content.

**Full stream report** (programs, PIDs, codecs, durations):

```bash
ffprobe -show_format -show_programs -show_streams output.ts
```

### Testing a live pipeline

```bash
# Pipe through id3injector and play in real time
ffmpeg -re -f lavfi -i testsrc=duration=10:size=320x240:rate=30 \
       -f lavfi -i sine=frequency=440:duration=10:sample_rate=44100 \
       -c:v libx264 -c:a aac -f mpegts pipe:1 \
  | id3injector -repeat 2 -text "Live Tag" \
  | ffplay pipe:0
```

## License

This is free and unencumbered software released into the public domain. See [UNLICENSE](UNLICENSE).
