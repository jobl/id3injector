package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --------------------------------------------------------------------
// CRC32
// --------------------------------------------------------------------

func TestCalculateCRC_KnownVectors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint32
	}{
		{
			name: "empty",
			data: []byte{},
			want: 0xFFFFFFFF,
		},
		{
			// MPEG-2 CRC32 of the single byte 0x00
			name: "single zero",
			data: []byte{0x00},
			want: 0x4E08BFB4,
		},
		{
			// CRC of data that already includes a valid CRC should be 0.
			name: "self-check PAT-style",
			data: func() []byte {
				// Minimal PAT section: table_id(0) + flags/length + body
				section := []byte{
					0x00,       // table_id
					0xB0, 0x0D, // section_syntax=1, private=0, reserved=11, length=13
					0x00, 0x01, // transport_stream_id
					0xC1,       // reserved=11, version=0, current_next=1
					0x00, 0x00, // section_number, last_section_number
					0x00, 0x01, // program_number=1
					0xE0, 0x20, // reserved=111, PMT PID=0x20
				}
				crc := calculateCRC(section)
				b := make([]byte, 4)
				binary.BigEndian.PutUint32(b, crc)
				section = append(section, b...)
				return section
			}(),
			want: 0x00000000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateCRC(tt.data)
			if got != tt.want {
				t.Errorf("calculateCRC() = 0x%08X, want 0x%08X", got, tt.want)
			}
		})
	}
}

// --------------------------------------------------------------------
// Syncsafe encoding
// --------------------------------------------------------------------

func TestEncodeSyncsafe(t *testing.T) {
	tests := []struct {
		input int
		want  [4]byte
	}{
		{0, [4]byte{0, 0, 0, 0}},
		{127, [4]byte{0, 0, 0, 127}},
		{128, [4]byte{0, 0, 1, 0}},        // 128 = 0x80 -> syncsafe 0x0100
		{256, [4]byte{0, 0, 2, 0}},        // 256 = bit 8 set
		{16383, [4]byte{0, 0, 127, 127}},  // max 14-bit
		{16384, [4]byte{0, 1, 0, 0}},      // 2^14
	}

	for _, tt := range tests {
		got := encodeSyncsafe(tt.input)
		if got != tt.want {
			t.Errorf("encodeSyncsafe(%d) = %v, want %v", tt.input, got, tt.want)
		}
		// Verify each byte has MSB clear (syncsafe property)
		for i, b := range got {
			if b > 0x7F {
				t.Errorf("encodeSyncsafe(%d)[%d] = 0x%02X, MSB set (not syncsafe)", tt.input, i, b)
			}
		}
	}
}

func TestEncodeSyncsafe_RoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 42, 127, 128, 255, 1000, 16383, 16384, 100000} {
		ss := encodeSyncsafe(size)
		decoded := (int(ss[0]) << 21) | (int(ss[1]) << 14) | (int(ss[2]) << 7) | int(ss[3])
		if decoded != size {
			t.Errorf("round-trip failed for %d: encoded=%v, decoded=%d", size, ss, decoded)
		}
	}
}

// --------------------------------------------------------------------
// ID3 frame generation
// --------------------------------------------------------------------

func TestGenerateID3Frame_Valid(t *testing.T) {
	tag, err := generateID3Frame("Hello")
	if err != nil {
		t.Fatalf("generateID3Frame error: %v", err)
	}

	// Must start with "ID3"
	if string(tag[:3]) != "ID3" {
		t.Errorf("ID3 header missing, got %v", tag[:3])
	}
	// Version 2.4
	if tag[3] != 4 || tag[4] != 0 {
		t.Errorf("version = %d.%d, want 2.4", tag[3], tag[4])
	}
	// Flags byte must be 0
	if tag[5] != 0 {
		t.Errorf("flags = 0x%02X, want 0x00", tag[5])
	}
	// Tag size is syncsafe at bytes 6-9
	tagSize := (int(tag[6]) << 21) | (int(tag[7]) << 14) | (int(tag[8]) << 7) | int(tag[9])
	if tagSize != len(tag)-10 {
		t.Errorf("tag size = %d, want %d (len=%d - 10)", tagSize, len(tag)-10, len(tag))
	}
	// Must contain "TPE1"
	if string(tag[10:14]) != "TPE1" {
		t.Errorf("frame ID = %q, want TPE1", string(tag[10:14]))
	}
	// Must end with null terminator
	if tag[len(tag)-1] != 0 {
		t.Error("missing null terminator")
	}
	// UTF-8 encoding byte
	if tag[20] != 3 {
		t.Errorf("encoding byte = %d, want 3 (UTF-8)", tag[20])
	}
}

func TestGenerateID3Frame_TooLong(t *testing.T) {
	// Content that would produce an ID3 tag exceeding maxID3TagSize
	long := make([]byte, maxID3TagSize)
	for i := range long {
		long[i] = 'A'
	}
	_, err := generateID3Frame(string(long))
	if err == nil {
		t.Error("expected error for oversized content")
	}
}

func TestGenerateID3Frame_Empty(t *testing.T) {
	tag, err := generateID3Frame("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(tag[:3]) != "ID3" {
		t.Error("ID3 header missing for empty content")
	}
}

// --------------------------------------------------------------------
// Meta frame (TS packet) generation
// --------------------------------------------------------------------

func TestGenerateMetaFrames_SinglePacket(t *testing.T) {
	id3, _ := generateID3Frame("Test")
	rawPTS := [5]byte{0x21, 0x00, 0x07, 0xE1, 0x01}
	data, numPkts := generateMetaFrames(id3, 0x102, rawPTS, 5)

	if numPkts != 1 {
		t.Fatalf("numPackets = %d, want 1", numPkts)
	}
	if len(data) != packetSize {
		t.Fatalf("data length = %d, want %d", len(data), packetSize)
	}
	frame := data[:packetSize]
	if frame[0] != syncByte {
		t.Errorf("sync byte = 0x%02X, want 0x%02X", frame[0], syncByte)
	}
	// PID
	pid := int(binary.BigEndian.Uint16(frame[1:3]) & pidMask)
	if pid != 0x102 {
		t.Errorf("PID = 0x%X, want 0x102", pid)
	}
	// PUSI must be set
	if frame[1]&0x40 == 0 {
		t.Error("payload unit start indicator not set")
	}
	// CC
	if frame[3]&0x0F != 5 {
		t.Errorf("CC = %d, want 5", frame[3]&0x0F)
	}
	// PES start code (after adaptation field)
	pesStart := 4
	if frame[3]&0x20 != 0 {
		pesStart = 4 + 1 + int(frame[4])
	}
	if frame[pesStart] != 0 || frame[pesStart+1] != 0 || frame[pesStart+2] != 1 {
		t.Errorf("PES start code not found at offset %d", pesStart)
	}
	// stream_id = private_stream_1
	if frame[pesStart+3] != 0xBD {
		t.Errorf("stream_id = 0x%02X, want 0xBD", frame[pesStart+3])
	}
}

func TestGenerateMetaFrames_CCWrap(t *testing.T) {
	id3, _ := generateID3Frame("X")
	data, _ := generateMetaFrames(id3, 0x100, [5]byte{}, 16)
	frame := data[:packetSize]
	// CC > 15 should wrap to 0
	if cc := frame[3] & 0x0F; cc != 0 {
		t.Errorf("CC = %d, want 0 (wrapped from 16)", cc)
	}
}

func TestGenerateMetaFrames_MultiPacket(t *testing.T) {
	// Create a tag larger than what fits in a single packet (~170 bytes)
	bigContent := make([]byte, 500)
	for i := range bigContent {
		bigContent[i] = byte('A' + i%26)
	}
	// Build a raw ID3 tag manually
	tag := append([]byte("ID3\x04\x00\x00\x00\x00\x03\x76"), bigContent...) // ~510 bytes

	rawPTS := [5]byte{0x21, 0x00, 0x07, 0xE1, 0x01}
	data, numPkts := generateMetaFrames(tag, 0x103, rawPTS, 0)

	if numPkts < 2 {
		t.Fatalf("expected multiple packets, got %d", numPkts)
	}
	if len(data) != numPkts*packetSize {
		t.Fatalf("data length = %d, want %d", len(data), numPkts*packetSize)
	}

	// Verify all packets have correct sync byte and PID
	for p := 0; p < numPkts; p++ {
		pkt := data[p*packetSize : (p+1)*packetSize]
		if pkt[0] != syncByte {
			t.Errorf("packet %d: sync byte = 0x%02X, want 0x%02X", p, pkt[0], syncByte)
		}
		pid := int(binary.BigEndian.Uint16(pkt[1:3]) & pidMask)
		if pid != 0x103 {
			t.Errorf("packet %d: PID = 0x%X, want 0x103", p, pid)
		}
	}

	// First packet must have PUSI set
	if data[1]&0x40 == 0 {
		t.Error("first packet: PUSI not set")
	}
	// Continuation packets must have PUSI clear
	for p := 1; p < numPkts; p++ {
		if data[p*packetSize+1]&0x40 != 0 {
			t.Errorf("packet %d: PUSI should not be set", p)
		}
	}

	// Verify continuity counters increment
	for p := 0; p < numPkts; p++ {
		expectedCC := p & 0x0F
		actualCC := int(data[p*packetSize+3] & 0x0F)
		if actualCC != expectedCC {
			t.Errorf("packet %d: CC = %d, want %d", p, actualCC, expectedCC)
		}
	}

	// Extract the ID3 tag back from the packets and verify it matches
	var extracted []byte
	for p := 0; p < numPkts; p++ {
		pkt := data[p*packetSize : (p+1)*packetSize]
		payloadStart := 4
		if pkt[3]&0x20 != 0 { // adaptation field present
			payloadStart = 4 + 1 + int(pkt[4])
		}
		if p == 0 {
			// Skip PES header (14 bytes)
			payloadStart += pesHeaderSize
		}
		extracted = append(extracted, pkt[payloadStart:packetSize]...)
	}

	// The extracted data should start with our ID3 tag
	if len(extracted) < len(tag) {
		t.Fatalf("extracted %d bytes, need at least %d", len(extracted), len(tag))
	}
	if string(extracted[:3]) != "ID3" {
		t.Error("extracted data does not start with ID3 header")
	}
	if !bytes.Equal(extracted[:len(tag)], tag) {
		t.Error("extracted ID3 tag does not match original")
	}
}

func TestGenerateMetaFrames_BoundaryExact(t *testing.T) {
	// Create a tag that exactly fills the first packet (no stuffing needed)
	exactSize := firstPacketPayload - pesHeaderSize // 170 bytes
	tag := make([]byte, exactSize)
	copy(tag, "ID3\x04\x00\x00")
	for i := 6; i < len(tag); i++ {
		tag[i] = byte(i)
	}

	data, numPkts := generateMetaFrames(tag, 0x100, [5]byte{}, 0)
	if numPkts != 1 {
		t.Fatalf("expected 1 packet for exact fit, got %d", numPkts)
	}
	if len(data) != packetSize {
		t.Fatalf("data length = %d, want %d", len(data), packetSize)
	}
}

func TestGenerateMetaFrames_BoundaryPlusOne(t *testing.T) {
	// One byte over single-packet capacity forces a second packet
	overSize := firstPacketPayload - pesHeaderSize + 1
	tag := make([]byte, overSize)
	copy(tag, "ID3\x04\x00\x00")

	data, numPkts := generateMetaFrames(tag, 0x100, [5]byte{}, 0)
	if numPkts != 2 {
		t.Fatalf("expected 2 packets, got %d", numPkts)
	}
	if len(data) != 2*packetSize {
		t.Fatalf("data length = %d, want %d", len(data), 2*packetSize)
	}
}

// --------------------------------------------------------------------
// parseFrame round-trip
// --------------------------------------------------------------------

func TestParseFrame_RoundTrip(t *testing.T) {
	id3, _ := generateID3Frame("RoundTrip")
	rawPTS := [5]byte{0x21, 0x00, 0x07, 0xE1, 0x01}
	data, _ := generateMetaFrames(id3, 0x102, rawPTS, 3)
	frame := data[:packetSize]

	var parsed parsedFrame
	parseFrame(frame, &parsed)

	if parsed.Type != framePES {
		t.Fatalf("expected framePES, got %d", parsed.Type)
	}
	if parsed.PID != 0x102 {
		t.Errorf("PID = 0x%X, want 0x102", parsed.PID)
	}
	if parsed.CC != 3 {
		t.Errorf("CC = %d, want 3", parsed.CC)
	}
	if !parsed.HasTimestamp {
		t.Error("expected HasTimestamp to be true")
	}
	if parsed.RawTimestamp != rawPTS {
		t.Errorf("raw PTS = %v, want %v", parsed.RawTimestamp, rawPTS)
	}
	if parsed.Err != nil {
		t.Errorf("unexpected error: %s", parsed.Err)
	}
}

func TestParseFrame_BadSync(t *testing.T) {
	frame := make([]byte, packetSize)
	frame[0] = 0x00 // not 0x47
	var parsed parsedFrame
	parseFrame(frame, &parsed)
	if parsed.Type != frameIncorrect {
		t.Errorf("expected frameIncorrect, got %d", parsed.Type)
	}
}

func TestParseFrame_AdaptationOnly(t *testing.T) {
	frame := make([]byte, packetSize)
	frame[0] = syncByte
	frame[1] = 0x00
	frame[2] = 0x50 // PID = 0x50
	frame[3] = 0x20 // adaptation_field_control = 2 (adaptation only)
	var parsed parsedFrame
	parseFrame(frame, &parsed)
	if parsed.Type != frameUnknown {
		t.Errorf("expected frameUnknown for adaptation-only, got %d", parsed.Type)
	}
}

// --------------------------------------------------------------------
// PSI section header + CRC
// --------------------------------------------------------------------

func TestParseSectionHeader_Valid(t *testing.T) {
	// Build a minimal valid section inside a pointer-field payload
	section := []byte{
		0x00,       // table_id = PAT
		0xB0, 0x0D, // flags + section_length = 13
		0x00, 0x01, // table_id_extension
		0xC1,       // reserved + version=0 + current_next=1
		0x00, 0x00, // section_number, last_section_number
		0x00, 0x01, // program_number
		0xE0, 0x20, // reserved + PMT PID
	}
	crc := calculateCRC(section)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, crc)
	section = append(section, b...)

	payload := append([]byte{0x00}, section...) // pointer field = 0

	hdr := parseSectionHeader(payload, 1)
	if hdr == nil {
		t.Fatal("expected non-nil header")
	}
	if hdr.tableID != 0 {
		t.Errorf("tableID = %d, want 0", hdr.tableID)
	}
	if hdr.sectionLen != 13 {
		t.Errorf("sectionLen = %d, want 13", hdr.sectionLen)
	}
	if err := hdr.verifyCRC(); err != nil {
		t.Errorf("CRC check failed: %v", err)
	}
}

func TestParseSectionHeader_CorruptCRC(t *testing.T) {
	section := []byte{
		0x00, 0xB0, 0x0D,
		0x00, 0x01, 0xC1, 0x00, 0x00,
		0x00, 0x01, 0xE0, 0x20,
		0xDE, 0xAD, 0xBE, 0xEF, // bad CRC
	}
	payload := append([]byte{0x00}, section...)

	hdr := parseSectionHeader(payload, 1)
	if hdr == nil {
		t.Fatal("expected non-nil header")
	}
	if err := hdr.verifyCRC(); err == nil {
		t.Error("expected CRC failure, got success")
	}
}

func TestParseSectionHeader_NoPayloadStart(t *testing.T) {
	payload := []byte{0x00, 0x00, 0xB0, 0x05, 0x00, 0x01, 0xC1, 0x00, 0x00}
	hdr := parseSectionHeader(payload, 0) // payloadStart = 0
	if hdr != nil {
		t.Error("expected nil when payloadStart != 1")
	}
}

// --------------------------------------------------------------------
// modifyPMT
// --------------------------------------------------------------------

func buildMinimalPMT() []byte {
	pkt := make([]byte, packetSize)
	for i := range pkt {
		pkt[i] = 0xFF
	}

	// TS header: sync, PID=0x20, payload only, CC=0
	pkt[0] = syncByte
	pkt[1] = 0x40 // PUSI=1
	pkt[2] = 0x20 // PID=0x20
	pkt[3] = 0x10 // adaptation_field_control=01, CC=0

	// Pointer field
	pkt[4] = 0x00

	// PMT section starts at byte 5
	section := pkt[5:]

	section[0] = 0x02       // table_id = PMT
	section[1] = 0xB0       // section_syntax=1, private=0, reserved=11
	sectionLen := 18        // 5(header after length) + 0(prog_info) + 5(1 stream, no ES info) + 4(CRC) + 4 padding = just 18
	section[2] = byte(sectionLen)
	section[3] = 0x00       // program_number high
	section[4] = 0x01       // program_number low = 1
	section[5] = 0xC1       // reserved + version=0 + current_next=1
	section[6] = 0x00       // section_number
	section[7] = 0x00       // last_section_number
	section[8] = 0xE1       // reserved + PCR PID high (0x100)
	section[9] = 0x00       // PCR PID low
	section[10] = 0xF0      // reserved + program_info_length high
	section[11] = 0x00      // program_info_length low = 0

	// One elementary stream: type=27 (H.264), PID=0x100, ES_info_length=0
	section[12] = 27        // stream_type
	section[13] = 0xE1      // reserved + PID high (0x100)
	section[14] = 0x00      // PID low
	section[15] = 0xF0      // reserved + ES_info_length high
	section[16] = 0x00      // ES_info_length low = 0

	// CRC at offset 17
	crc := calculateCRC(section[:17])
	binary.BigEndian.PutUint32(section[17:21], crc)

	return pkt
}

func TestModifyPMT_AutoPID(t *testing.T) {
	pmt := buildMinimalPMT()
	mod, metaPID := modifyPMT(pmt, 0)

	if metaPID != 0x101 {
		t.Errorf("auto-detected PID = 0x%X, want 0x101", metaPID)
	}
	if mod[0] != syncByte {
		t.Error("sync byte missing in modified PMT")
	}

	// Parse the modified PMT to verify it's structurally valid
	var parsed parsedFrame
	parseFrame(mod, &parsed)
	if parsed.Type != framePMT {
		t.Fatalf("modified PMT not recognized as PMT, type=%d", parsed.Type)
	}
	if parsed.Err != nil {
		t.Errorf("modified PMT has error: %s", parsed.Err)
	}

	// Should have 2 streams now (original H.264 + metadata)
	if len(parsed.Streams) != 2 {
		t.Errorf("stream count = %d, want 2", len(parsed.Streams))
	}

	// Last stream should be metadata (type=21)
	if len(parsed.Streams) >= 2 {
		ms := parsed.Streams[1]
		if ms.Type != 21 {
			t.Errorf("metadata stream type = %d, want 21", ms.Type)
		}
		if ms.PID != 0x101 {
			t.Errorf("metadata stream PID = 0x%X, want 0x101", ms.PID)
		}
	}
}

func TestModifyPMT_VersionIncrement(t *testing.T) {
	pmt := buildMinimalPMT()
	mod, _ := modifyPMT(pmt, 0)

	// Original version is 0; modified should be 1
	origVersion := (pmt[10] >> 1) & 0x1F
	newVersion := (mod[10] >> 1) & 0x1F
	if newVersion != origVersion+1 {
		t.Errorf("version = %d, want %d", newVersion, origVersion+1)
	}
}

func TestModifyPMT_ExplicitPID(t *testing.T) {
	pmt := buildMinimalPMT()
	_, metaPID := modifyPMT(pmt, 0x200)
	if metaPID != 0x200 {
		t.Errorf("explicit PID = 0x%X, want 0x200", metaPID)
	}
}

// --------------------------------------------------------------------
// Metadata file parsing
// --------------------------------------------------------------------

func TestParseMetadataFile_Valid(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "meta.txt")
	if err := os.WriteFile(f, []byte("5 plaintext Hello\n0 plaintext First\n3 plaintext Middle\n"), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := parseMetadataFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	// Should be sorted by Moment (PTS ticks: 0s=0, 3s=270000, 5s=450000)
	if entries[0].Moment != 0 || entries[1].Moment != 3*clockFrequency || entries[2].Moment != 5*clockFrequency {
		t.Errorf("sort order wrong: %d, %d, %d", entries[0].Moment, entries[1].Moment, entries[2].Moment)
	}
}

func TestParseMetadataFile_Empty(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(f, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := parseMetadataFile(f)
	if err == nil {
		t.Error("expected error for empty file")
	}
}

func TestParseMetadataFile_MalformedLine(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(f, []byte("not a valid line\n"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := parseMetadataFile(f)
	if err == nil {
		t.Error("expected error for malformed file")
	}
	if err != nil && !strings.Contains(err.Error(), "line 1") {
		t.Errorf("expected line number in error, got: %s", err)
	}
}

func TestParseMetadataFile_LargeTag(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "big.txt")
	// 500-char plaintext: large but within limits (multi-packet capable now)
	big := make([]byte, 500)
	for i := range big {
		big[i] = 'A'
	}
	if err := os.WriteFile(f, []byte("0 plaintext "+string(big)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := parseMetadataFile(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].Tag) < 500 {
		t.Errorf("tag too small: %d bytes", len(entries[0].Tag))
	}
}

func TestParseMetadataFile_NotFound(t *testing.T) {
	_, err := parseMetadataFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// --------------------------------------------------------------------
// parseMetaLine
// --------------------------------------------------------------------

func TestParseMetaLine_Valid(t *testing.T) {
	tests := []struct {
		line       string
		wantMoment int64 // in PTS ticks (90kHz)
		wantTag    bool
	}{
		{"0 plaintext Hello", 0, true},
		{"42 plaintext World", 42 * clockFrequency, true},
		{"1.5 plaintext Half", int64(1.5 * clockFrequency), true},
		{"0.1 plaintext Tenth", int64(0.1 * clockFrequency), true},
	}
	for _, tt := range tests {
		moment, tag, err := parseMetaLine(tt.line)
		if err != nil {
			t.Errorf("parseMetaLine(%q) error: %v", tt.line, err)
			continue
		}
		if moment != tt.wantMoment {
			t.Errorf("parseMetaLine(%q) moment = %d, want %d", tt.line, moment, tt.wantMoment)
		}
		if tt.wantTag && len(tag) == 0 {
			t.Errorf("parseMetaLine(%q) returned empty tag", tt.line)
		}
		// Tag should be a valid ID3 frame
		if len(tag) >= 3 && string(tag[:3]) != "ID3" {
			t.Errorf("parseMetaLine(%q) tag doesn't start with ID3", tt.line)
		}
	}
}

func TestParseMetaLine_Invalid(t *testing.T) {
	tests := []string{
		"",
		"not valid",
		"abc plaintext hello",
		"-1 plaintext hello",
	}
	for _, line := range tests {
		_, _, err := parseMetaLine(line)
		if err == nil {
			t.Errorf("parseMetaLine(%q) expected error", line)
		}
	}
}

func TestParseMetaLine_UnknownFormat(t *testing.T) {
	_, _, err := parseMetaLine("0 mp3 something")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}

// --------------------------------------------------------------------
// Live channel injection
// --------------------------------------------------------------------

func TestInjector_LiveChannel(t *testing.T) {
	// Build a minimal injected frame to test the channel drain.
	id3, _ := generateID3Frame("LiveTest")
	rawPTS := [5]byte{0x21, 0x00, 0x07, 0xE1, 0x01}

	// Create a buffer to capture output
	var buf strings.Builder
	ch := make(chan []byte, 8)

	inj := &injector{
		writer:  bufio.NewWriterSize(&buf, 4096),
		tagCh:  ch,
		metaPID: 0x102,
		metaCC:  0,
	}

	// Send a tag before calling handleFrame
	ch <- id3

	// Create a PES frame with a valid timestamp so handleFrame triggers the drain
	data, _ := generateMetaFrames(id3, 0x100, rawPTS, 0)
	frame := data[:packetSize]

	var parsed parsedFrame
	parseFrame(frame, &parsed)
	if !parsed.HasTimestamp {
		t.Fatal("test frame must have a timestamp")
	}

	if err := inj.handleFrame(frame, &parsed, 1); err != nil {
		t.Fatalf("handleFrame error: %v", err)
	}

	if err := inj.writer.Flush(); err != nil {
		t.Fatalf("flush error: %v", err)
	}

	if inj.injected != 1 {
		t.Errorf("injected = %d, want 1", inj.injected)
	}

	// Output should contain at least 2 packets: the live injection + the original frame
	outBytes := buf.Len()
	if outBytes < 2*packetSize {
		t.Errorf("output = %d bytes, want >= %d", outBytes, 2*packetSize)
	}
}

func TestInjector_LiveChannel_Empty(t *testing.T) {
	// When the channel is empty, handleFrame should not inject anything
	id3, _ := generateID3Frame("NoLive")
	rawPTS := [5]byte{0x21, 0x00, 0x07, 0xE1, 0x01}

	var buf strings.Builder
	ch := make(chan []byte, 8)

	inj := &injector{
		writer:  bufio.NewWriterSize(&buf, 4096),
		tagCh:  ch,
		metaPID: 0x102,
	}

	data, _ := generateMetaFrames(id3, 0x100, rawPTS, 0)
	frame := data[:packetSize]
	var parsed parsedFrame
	parseFrame(frame, &parsed)

	if err := inj.handleFrame(frame, &parsed, 1); err != nil {
		t.Fatalf("handleFrame error: %v", err)
	}
	inj.writer.Flush()

	if inj.injected != 0 {
		t.Errorf("injected = %d, want 0 (channel was empty)", inj.injected)
	}
}

// --------------------------------------------------------------------
// HTTP inject endpoint
// --------------------------------------------------------------------

func TestHTTPInject_Text(t *testing.T) {
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(newInjectHandler(ch))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/inject", "application/json",
		strings.NewReader(`{"text":"Hello World"}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case tag := <-ch:
		if len(tag) < 3 || string(tag[:3]) != "ID3" {
			t.Error("received tag is not a valid ID3 frame")
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for tag on channel")
	}
}

func TestHTTPInject_BadJSON(t *testing.T) {
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(newInjectHandler(ch))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/inject", "application/json",
		strings.NewReader(`not json`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// --------------------------------------------------------------------
// streamMetadataLines
// --------------------------------------------------------------------

func TestStreamMetadataLines(t *testing.T) {
	input := "0 plaintext First\n0 plaintext Second\n"
	r := strings.NewReader(input)
	ch := make(chan []byte, 8)

	go streamMetadataLines(r, ch)

	for i, want := range []string{"First", "Second"} {
		select {
		case tag := <-ch:
			if len(tag) < 3 || string(tag[:3]) != "ID3" {
				t.Errorf("tag %d: not a valid ID3 frame", i)
			}
			// The tag should contain the text
			if !strings.Contains(string(tag), want) {
				t.Errorf("tag %d: expected to contain %q", i, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for tag %d", i)
		}
	}
}

func TestStreamMetadataLines_PlainText(t *testing.T) {
	// Plain text lines (no "0 plaintext" prefix) should be auto-wrapped as ID3.
	input := "Hello\nWorld\n"
	r := strings.NewReader(input)
	ch := make(chan []byte, 8)

	go streamMetadataLines(r, ch)

	for i, want := range []string{"Hello", "World"} {
		select {
		case tag := <-ch:
			if len(tag) < 3 || string(tag[:3]) != "ID3" {
				t.Errorf("tag %d: not a valid ID3 frame", i)
			}
			if !strings.Contains(string(tag), want) {
				t.Errorf("tag %d: expected to contain %q", i, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for tag %d", i)
		}
	}
}

func TestHTTPInject_QueueFull(t *testing.T) {
	ch := make(chan []byte) // unbuffered — always full
	handler := newInjectHandler(ch)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	body := `{"text":"overflow"}`
	resp, err := http.Post(srv.URL+"/inject", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", resp.StatusCode)
	}
}

// --------------------------------------------------------------------
// parseFrame: PAT / PMT detection
// --------------------------------------------------------------------

// buildMinimalPAT builds a valid single-program PAT packet pointing to pmtPID.
func buildMinimalPAT(pmtPID int, cc int) []byte {
	pkt := make([]byte, packetSize)
	pkt[0] = syncByte
	pkt[1] = 0x40 // PUSI=1, PID=0 (PAT)
	pkt[2] = 0x00
	pkt[3] = 0x10 | byte(cc&0x0F) // adaptation_field_control=01

	// Pointer field
	pkt[4] = 0x00

	// PAT section
	section := pkt[5:]
	section[0] = 0x00       // table_id = PAT
	section[1] = 0xB0       // section_syntax=1, reserved=11
	section[2] = 0x0D       // section_length = 13
	section[3] = 0x00       // transport_stream_id high
	section[4] = 0x01       // transport_stream_id low
	section[5] = 0xC1       // reserved + version=0 + current_next=1
	section[6] = 0x00       // section_number
	section[7] = 0x00       // last_section_number
	section[8] = 0x00       // program_number high
	section[9] = 0x01       // program_number low = 1
	section[10] = 0xE0 | byte((pmtPID>>8)&0x1F)
	section[11] = byte(pmtPID & 0xFF)

	crc := calculateCRC(section[:12])
	binary.BigEndian.PutUint32(section[12:16], crc)
	return pkt
}

// buildPESPacket builds a minimal PES packet with PTS on the given PID.
func buildPESPacket(pid int, pts int64, cc int) []byte {
	pkt := make([]byte, packetSize)
	pkt[0] = syncByte
	pkt[1] = 0x40 | byte((pid>>8)&0x1F) // PUSI=1
	pkt[2] = byte(pid & 0xFF)
	pkt[3] = 0x10 | byte(cc&0x0F) // payload only

	// PES start code
	pkt[4] = 0x00
	pkt[5] = 0x00
	pkt[6] = 0x01
	pkt[7] = 0xE0 // stream_id = video

	// PES length (0 = unbounded for video)
	pkt[8] = 0x00
	pkt[9] = 0x00

	// PES header flags: marker=10, PTS_DTS_flags=10
	pkt[10] = 0x80
	pkt[11] = 0x80 // PTS only
	pkt[12] = 0x05 // PES header data length

	// Encode PTS (marker nibble=0010, then PTS bits)
	pkt[13] = byte(0x20|((pts>>29)&0x0E)) | 1
	pkt[14] = byte((pts >> 22) & 0xFF)
	pkt[15] = byte(((pts>>14)&0xFE) | 1)
	pkt[16] = byte((pts >> 7) & 0xFF)
	pkt[17] = byte(((pts<<1)&0xFE) | 1)

	return pkt
}

func TestParseFrame_PAT(t *testing.T) {
	pkt := buildMinimalPAT(0x1000, 0)
	var parsed parsedFrame
	parseFrame(pkt, &parsed)

	if parsed.Type != framePAT {
		t.Fatalf("expected framePAT, got %d", parsed.Type)
	}
	if parsed.PID != 0 {
		t.Errorf("PAT PID = %d, want 0", parsed.PID)
	}
	if len(parsed.Programs) != 1 {
		t.Fatalf("programs = %d, want 1", len(parsed.Programs))
	}
	if parsed.Programs[0].ID != 1 {
		t.Errorf("program ID = %d, want 1", parsed.Programs[0].ID)
	}
	if parsed.Programs[0].PMTPID != 0x1000 {
		t.Errorf("PMT PID = 0x%X, want 0x1000", parsed.Programs[0].PMTPID)
	}
	if parsed.Err != nil {
		t.Errorf("unexpected error: %s", parsed.Err)
	}
}

func TestParseFrame_PMT(t *testing.T) {
	pkt := buildMinimalPMT() // from existing helper, PID=0x20 with one H.264 stream at PID=0x100
	var parsed parsedFrame
	parseFrame(pkt, &parsed)

	if parsed.Type != framePMT {
		t.Fatalf("expected framePMT, got %d", parsed.Type)
	}
	if len(parsed.Streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(parsed.Streams))
	}
	if parsed.Streams[0].Type != 27 {
		t.Errorf("stream type = %d, want 27 (H.264)", parsed.Streams[0].Type)
	}
	if parsed.Streams[0].PID != 0x100 {
		t.Errorf("stream PID = 0x%X, want 0x100", parsed.Streams[0].PID)
	}
	if parsed.Err != nil {
		t.Errorf("unexpected error: %s", parsed.Err)
	}
}

func TestParseFrame_PES_Timestamp(t *testing.T) {
	pkt := buildPESPacket(0x100, 90000, 0) // PTS = 1 second
	var parsed parsedFrame
	parseFrame(pkt, &parsed)

	if parsed.Type != framePES {
		t.Fatalf("expected framePES, got %d", parsed.Type)
	}
	if !parsed.HasTimestamp {
		t.Fatal("expected HasTimestamp = true")
	}
	if parsed.Timestamp != 90000 {
		t.Errorf("PTS = %d, want 90000", parsed.Timestamp)
	}
}

func TestParseFrame_Continuation(t *testing.T) {
	pkt := make([]byte, packetSize)
	pkt[0] = syncByte
	pkt[1] = 0x01 // PUSI=0, PID=0x100
	pkt[2] = 0x00
	pkt[3] = 0x11 // adaptation_field_control=01, CC=1

	var parsed parsedFrame
	parseFrame(pkt, &parsed)
	if !parsed.Continuation {
		t.Error("expected Continuation = true for PUSI=0, adaptCtrl=1")
	}
}

// --------------------------------------------------------------------
// modifyPMT CRC verification
// --------------------------------------------------------------------

func TestModifyPMT_ValidCRC(t *testing.T) {
	pmt := buildMinimalPMT()
	mod, _ := modifyPMT(pmt, 0)

	// Re-parse the modified PMT and verify its CRC
	var parsed parsedFrame
	parseFrame(mod, &parsed)
	if parsed.Type != framePMT {
		t.Fatalf("modified packet not recognized as PMT, type=%d", parsed.Type)
	}

	// Extract section and verify CRC
	payload := mod[4:] // pointer field + section
	hdr := parseSectionHeader(payload, 1)
	if hdr == nil {
		t.Fatal("cannot parse section header from modified PMT")
	}
	if err := hdr.verifyCRC(); err != nil {
		t.Errorf("modified PMT has bad CRC: %v", err)
	}
}

// --------------------------------------------------------------------
// HTTP inject: base64 path
// --------------------------------------------------------------------

func TestHTTPInject_Base64(t *testing.T) {
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(newInjectHandler(ch))
	defer srv.Close()

	// Build a real ID3 tag and base64-encode it
	id3, err := generateID3Frame("Base64Test")
	if err != nil {
		t.Fatalf("generateID3Frame error: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(id3)

	resp, err := http.Post(srv.URL+"/inject", "application/json",
		strings.NewReader(`{"id3_base64":"`+b64+`"}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case tag := <-ch:
		if !bytes.Equal(tag, id3) {
			t.Errorf("received tag differs from sent tag (len %d vs %d)", len(tag), len(id3))
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for tag on channel")
	}
}

func TestHTTPInject_BadBase64(t *testing.T) {
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(newInjectHandler(ch))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/inject", "application/json",
		strings.NewReader(`{"id3_base64":"not-valid-base64!@#"}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHTTPInject_OversizedBase64(t *testing.T) {
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(newInjectHandler(ch))
	defer srv.Close()

	// Build a tag larger than maxID3TagSize
	big := make([]byte, maxID3TagSize+1)
	b64 := base64.StdEncoding.EncodeToString(big)

	resp, err := http.Post(srv.URL+"/inject", "application/json",
		strings.NewReader(`{"id3_base64":"`+b64+`"}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestHTTPInject_EmptyBody(t *testing.T) {
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(newInjectHandler(ch))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/inject", "application/json",
		strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("POST error: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for empty body", resp.StatusCode)
	}
}

// --------------------------------------------------------------------
// End-to-end: inject → re-parse → verify
// --------------------------------------------------------------------

// buildMinimalTSStream constructs a valid TS stream with a PAT, PMT,
// and several PES packets with incrementing PTS values.
func buildMinimalTSStream(numPES int) []byte {
	const (
		pmtPID   = 0x1000
		videoPID = 0x100
	)
	var stream []byte

	// PAT
	stream = append(stream, buildMinimalPAT(pmtPID, 0)...)

	// PMT with one video stream
	pmt := make([]byte, packetSize)
	pmt[0] = syncByte
	pmt[1] = 0x40 | byte((pmtPID>>8)&0x1F)
	pmt[2] = byte(pmtPID & 0xFF)
	pmt[3] = 0x10 // payload only, CC=0

	pmt[4] = 0x00 // pointer field

	section := pmt[5:]
	section[0] = 0x02       // table_id = PMT
	section[1] = 0xB0       // section_syntax=1
	section[2] = 18         // section_length
	section[3] = 0x00       // program_number high
	section[4] = 0x01       // program_number low
	section[5] = 0xC1       // version=0, current_next=1
	section[6] = 0x00       // section_number
	section[7] = 0x00       // last_section_number
	section[8] = 0xE0 | byte((videoPID>>8)&0x1F) // PCR PID
	section[9] = byte(videoPID & 0xFF)
	section[10] = 0xF0      // program_info_length = 0
	section[11] = 0x00
	// Stream entry: H.264
	section[12] = 27 // stream_type
	section[13] = 0xE0 | byte((videoPID>>8)&0x1F)
	section[14] = byte(videoPID & 0xFF)
	section[15] = 0xF0 // ES_info_length = 0
	section[16] = 0x00
	crc := calculateCRC(section[:17])
	binary.BigEndian.PutUint32(section[17:21], crc)

	stream = append(stream, pmt...)

	// PES packets with incrementing PTS (1s apart)
	for i := 0; i < numPES; i++ {
		pts := int64(i) * clockFrequency // 0s, 1s, 2s, ...
		stream = append(stream, buildPESPacket(videoPID, pts, i)...)
	}

	return stream
}

func TestEndToEnd_InjectAndVerify(t *testing.T) {
	// Build a stream with PAT + PMT + 5 video PES packets (0s–4s)
	input := buildMinimalTSStream(5)

	// Prepare metadata: inject at t=0 and t=2
	metaDir := t.TempDir()
	metaFile := filepath.Join(metaDir, "meta.txt")
	if err := os.WriteFile(metaFile, []byte("0 plaintext HelloE2E\n2 plaintext SecondTag\n"), 0644); err != nil {
		t.Fatal(err)
	}

	meta, err := parseMetadataFile(metaFile)
	if err != nil {
		t.Fatalf("parseMetadataFile: %v", err)
	}

	// Run the injector
	var outBuf bytes.Buffer
	inj := &injector{
		writer:   bufio.NewWriterSize(&outBuf, 64*1024),
		metaData: meta,
		metaCC:   0,
	}

	reader := bufio.NewReader(bytes.NewReader(input))
	pmtPIDs := map[int]bool{}
	buf := make([]byte, packetSize)
	var parsed parsedFrame
	frames := 0
	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			break
		}
		parseFrame(buf, &parsed)

		// Track PMT PIDs from PAT
		if parsed.Type == framePAT {
			for _, p := range parsed.Programs {
				if p.ID != 0 {
					pmtPIDs[p.PMTPID] = true
				}
			}
		}
		// Set type to framePMT if PID matches
		if pmtPIDs[parsed.PID] && parsed.Type != framePAT {
			parsed.Type = framePMT
		}

		if err := inj.handleFrame(buf, &parsed, frames); err != nil {
			t.Fatalf("handleFrame error at frame %d: %v", frames, err)
		}
		frames++
	}
	inj.writer.Flush()

	if inj.injected != 2 {
		t.Fatalf("injected = %d, want 2", inj.injected)
	}

	// Verify the output stream
	output := outBuf.Bytes()
	if len(output)%packetSize != 0 {
		t.Fatalf("output size %d not a multiple of %d", len(output), packetSize)
	}

	outputFrames := len(output) / packetSize
	expectedFrames := frames + 2 // original frames + 2 injected
	if outputFrames != expectedFrames {
		t.Errorf("output frames = %d, want %d (original %d + 2 injected)", outputFrames, expectedFrames, frames)
	}

	// Re-parse the output: verify PMT has metadata stream and ID3 tags exist
	var (
		foundMetaStream bool
		id3Count        int
		metaPID         int
		outPMTpids      = map[int]bool{}
	)

	var outParsed parsedFrame
	for off := 0; off < len(output); off += packetSize {
		pkt := output[off : off+packetSize]
		parseFrame(pkt, &outParsed)

		if outParsed.Type == framePAT {
			for _, p := range outParsed.Programs {
				if p.ID != 0 {
					outPMTpids[p.PMTPID] = true
				}
			}
		}
		if outPMTpids[outParsed.PID] && outParsed.Type != framePAT {
			outParsed.Type = framePMT
			parseFrame(pkt, &outParsed)
		}

		if outParsed.Type == framePMT {
			for _, s := range outParsed.Streams {
				if s.Type == 21 { // timed metadata
					foundMetaStream = true
					metaPID = s.PID
				}
			}
		}

		// Check for ID3 content in PES packets
		if outParsed.Type == framePES && outParsed.PayloadOffset > 0 {
			payload := pkt[outParsed.PayloadOffset:]
			if len(payload) >= 14 && payload[0] == 0 && payload[1] == 0 && payload[2] == 1 && payload[3] == 0xBD {
				// private_stream_1 — look for ID3 inside
				pesHdrLen := int(payload[8])
				dataStart := 9 + pesHdrLen
				if dataStart < len(payload) {
					data := payload[dataStart:]
					if len(data) >= 3 && string(data[:3]) == "ID3" {
						id3Count++
					}
				}
			}
		}
	}

	if !foundMetaStream {
		t.Error("modified PMT does not contain a timed metadata stream (type=21)")
	}
	if metaPID == 0 {
		t.Error("metadata PID not found in PMT")
	}
	if id3Count != 2 {
		t.Errorf("found %d ID3 tags in output, want 2", id3Count)
	}
}

func TestEndToEnd_MultiPacketInject(t *testing.T) {
	// Build a stream with PAT + PMT + 3 video PES packets (0s, 1s, 2s)
	input := buildMinimalTSStream(3)

	// Create a large ID3 tag (~500 bytes) that requires multiple TS packets
	payload := make([]byte, 480)
	for i := range payload {
		payload[i] = byte('A' + i%26)
	}
	framePayload := 1 + len(payload) + 1 // encoding + text + null
	tagBody := 10 + framePayload
	tag := make([]byte, 0, 10+tagBody)
	// ID3v2.4 header
	tag = append(tag, 'I', 'D', '3', 4, 0, 0)
	ss := encodeSyncsafe(tagBody)
	tag = append(tag, ss[0], ss[1], ss[2], ss[3])
	// TPE1 frame header
	tag = append(tag, 'T', 'P', 'E', '1')
	fs := encodeSyncsafe(framePayload)
	tag = append(tag, fs[0], fs[1], fs[2], fs[3])
	tag = append(tag, 0, 0) // frame flags
	tag = append(tag, 3)    // UTF-8
	tag = append(tag, payload...)
	tag = append(tag, 0) // null terminator

	// Verify the tag is larger than single-packet capacity
	if len(tag) <= firstPacketPayload-pesHeaderSize {
		t.Fatalf("test tag (%d bytes) should exceed single packet capacity (%d)",
			len(tag), firstPacketPayload-pesHeaderSize)
	}

	// Prepare a metadata entry at t=0
	meta := []metaEntry{{Moment: 0, Tag: tag}}

	// Run the injector
	var outBuf bytes.Buffer
	inj := &injector{
		writer:   bufio.NewWriterSize(&outBuf, 64*1024),
		metaData: meta,
		metaCC:   0,
	}

	reader := bufio.NewReader(bytes.NewReader(input))
	pmtPIDs := map[int]bool{}
	buf := make([]byte, packetSize)
	var parsed parsedFrame
	frames := 0
	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			break
		}
		parseFrame(buf, &parsed)
		if parsed.Type == framePAT {
			for _, p := range parsed.Programs {
				if p.ID != 0 {
					pmtPIDs[p.PMTPID] = true
				}
			}
		}
		if pmtPIDs[parsed.PID] && parsed.Type != framePAT {
			parsed.Type = framePMT
		}
		if err := inj.handleFrame(buf, &parsed, frames); err != nil {
			t.Fatalf("handleFrame error at frame %d: %v", frames, err)
		}
		frames++
	}
	inj.writer.Flush()

	if inj.injected != 1 {
		t.Fatalf("injected = %d, want 1", inj.injected)
	}

	// Verify output is valid TS
	output := outBuf.Bytes()
	if len(output)%packetSize != 0 {
		t.Fatalf("output size %d not a multiple of %d", len(output), packetSize)
	}

	// Calculate expected packets for the multi-packet ID3
	_, expectedPkts := generateMetaFrames(tag, 0x101, [5]byte{}, 0)
	if expectedPkts < 2 {
		t.Fatalf("expected multi-packet injection, got %d packets", expectedPkts)
	}

	expectedFrames := frames + expectedPkts
	outputFrames := len(output) / packetSize
	if outputFrames != expectedFrames {
		t.Errorf("output frames = %d, want %d (original %d + %d injected)",
			outputFrames, expectedFrames, frames, expectedPkts)
	}

	// Find the metadata PID from the modified PMT
	var metaPID int
	outPMTpids := map[int]bool{}
	var outParsed parsedFrame
	for off := 0; off < len(output); off += packetSize {
		pkt := output[off : off+packetSize]
		parseFrame(pkt, &outParsed)
		if outParsed.Type == framePAT {
			for _, p := range outParsed.Programs {
				if p.ID != 0 {
					outPMTpids[p.PMTPID] = true
				}
			}
		}
		if outPMTpids[outParsed.PID] && outParsed.Type != framePAT {
			outParsed.Type = framePMT
			parseFrame(pkt, &outParsed)
		}
		if outParsed.Type == framePMT {
			for _, s := range outParsed.Streams {
				if s.Type == 21 {
					metaPID = s.PID
				}
			}
		}
	}

	if metaPID == 0 {
		t.Fatal("metadata PID not found in modified PMT")
	}

	// Reassemble the multi-packet PES payload from all metadata PID packets
	var pesPayload []byte
	for off := 0; off < len(output); off += packetSize {
		pkt := output[off : off+packetSize]
		if pkt[0] != syncByte {
			continue
		}
		pid := int(binary.BigEndian.Uint16(pkt[1:3]) & pidMask)
		if pid != metaPID {
			continue
		}
		payloadStart := 4
		if pkt[3]&0x20 != 0 { // adaptation field
			payloadStart = 4 + 1 + int(pkt[4])
		}
		if pkt[3]&0x10 != 0 { // has payload
			pesPayload = append(pesPayload, pkt[payloadStart:]...)
		}
	}

	// Parse the reassembled PES to extract the ID3 tag
	if len(pesPayload) < pesHeaderSize {
		t.Fatalf("PES payload too short: %d bytes", len(pesPayload))
	}
	// Verify PES start code
	if pesPayload[0] != 0 || pesPayload[1] != 0 || pesPayload[2] != 1 || pesPayload[3] != 0xBD {
		t.Fatalf("bad PES start code: %x", pesPayload[:4])
	}
	// Skip PES header to get ID3 data
	pesHdrDataLen := int(pesPayload[8])
	id3Start := 9 + pesHdrDataLen
	if id3Start >= len(pesPayload) {
		t.Fatalf("PES header extends beyond payload")
	}
	extractedID3 := pesPayload[id3Start:]

	// Verify the extracted ID3 tag matches the original
	if len(extractedID3) < len(tag) {
		t.Fatalf("extracted ID3 too short: %d bytes, want at least %d", len(extractedID3), len(tag))
	}
	if !bytes.Equal(extractedID3[:len(tag)], tag) {
		t.Error("extracted ID3 tag does not match original")
		// Show first mismatch for debugging
		for i := 0; i < len(tag); i++ {
			if extractedID3[i] != tag[i] {
				t.Errorf("first mismatch at byte %d: got 0x%02X, want 0x%02X", i, extractedID3[i], tag[i])
				break
			}
		}
	}

	// Verify the payload text is intact
	if !bytes.Contains(extractedID3, payload) {
		t.Error("original payload text not found in extracted ID3 tag")
	}
}

func TestEndToEnd_CheckOnly(t *testing.T) {
	// Verify that a stream built from our helpers parses cleanly
	input := buildMinimalTSStream(3)

	reader := bufio.NewReader(bytes.NewReader(input))
	buf := make([]byte, packetSize)
	var parsed parsedFrame
	var frames, errCount int

	for {
		_, err := io.ReadFull(reader, buf)
		if err != nil {
			break
		}
		parseFrame(buf, &parsed)
		if parsed.Err != nil {
			errCount++
		}
		if parsed.Type == frameIncorrect {
			t.Errorf("frame %d: frameIncorrect: %s", frames, parsed.Err)
		}
		frames++
	}

	// PAT + PMT + 3 PES = 5 frames
	if frames != 5 {
		t.Errorf("frames = %d, want 5", frames)
	}
	if errCount != 0 {
		t.Errorf("errCount = %d, want 0", errCount)
	}
}

// --------------------------------------------------------------------
// Input validation guards
// --------------------------------------------------------------------

func TestOpenInput_SyncByteCheck(t *testing.T) {
	// Write a file that is 188 bytes but does NOT start with 0x47
	tmp := filepath.Join(t.TempDir(), "bad.ts")
	data := make([]byte, packetSize)
	data[0] = 0x00
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatal(err)
	}
	_, _, err := openInput(tmp)
	if err == nil || !strings.Contains(err.Error(), "not an MPEG TS file") {
		t.Errorf("expected sync byte error, got: %v", err)
	}
}

func TestOpenInput_ValidSyncByte(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "good.ts")
	data := make([]byte, packetSize)
	data[0] = syncByte
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatal(err)
	}
	reader, closer, err := openInput(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closer()
	if reader == nil {
		t.Fatal("reader is nil")
	}
}

func TestOpenInput_FileSizeNotMultiple(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "short.ts")
	data := make([]byte, 100) // not a multiple of 188
	data[0] = syncByte
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		t.Fatal(err)
	}
	_, _, err := openInput(tmp)
	if err == nil || !strings.Contains(err.Error(), "file size must be a multiple") {
		t.Errorf("expected file size error, got: %v", err)
	}
}
