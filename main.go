package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MPEG TS protocol constants.
const (
	packetSize     = 188
	clockFrequency = 90000
	syncByte       = 0x47

	pidMask        = 0x1FFF
	sectionLenMask = 0x03FF
	maxCCValue     = 15

	// Hard limit: PES packet length is a 16-bit field (65535),
	// minus 8 bytes PES header overhead = 65527 bytes of ID3 data.
	// Tags larger than 170 bytes are automatically split across multiple packets.
	maxID3TagSize = 65527

	// TS payload sizes (packet minus headers).
	firstPacketPayload       = 184 // 188 - 4 (TS header)
	continuationPayload      = 184 // 188 - 4 (TS header)
	pesHeaderSize            = 14  // PES header (9) + PTS (5)
)

// PMT section offsets (relative to section start, after pointer field).
const (
	pmtVersionByte = 5  // version_number + current_next_indicator
	pmtProgInfoLen = 10 // program_info_length (2 bytes)
	pmtFixedHeader = 12 // first byte after the fixed header
)

// frameType identifies the kind of TS packet.
type frameType int

const (
	frameUnknown    frameType = iota
	frameIncorrect
	framePAT
	framePES
	framePMT
)

var (
	be      = binary.BigEndian
	version = "dev" // set via -ldflags "-X main.version=..."
)

// debug enables protocol-level debug logging.
var debug bool

func dbgf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
}

// MPEG-2 CRC32 lookup table.
var crc32Table [256]uint32

func init() {
	const poly = 0x04C11DB7
	for i := range crc32Table {
		crc := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if crc&0x80000000 != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
		crc32Table[i] = crc
	}
}

func calculateCRC(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = (crc << 8) ^ crc32Table[((crc>>24)^uint32(b))&0xFF]
	}
	return crc
}

// HLS timed metadata descriptors (stream type 0x15, ID3v2.4 in PES).
var (
	// Program-level metadata_pointer_descriptor.
	appleMetaDescriptor = []byte{
		37, 15,
		0xFF, 0xFF, 0x49, 0x44, 0x33, 0x20, 0xFF, 0x49,
		0x44, 0x33, 0x20, 0x00, 0x1F, 0x00, 0x01,
	}

	// Stream entry constants.
	appleMetaStreamType byte = 21 // MetaData carried in PES
	appleMetaESInfoLen  byte = 15 // ES_info_length for the metadata entry

	// ES-level metadata_descriptor.
	appleMetaESDescriptor = []byte{
		38, 13,
		0xFF, 0xFF, 0x49, 0x44, 0x33, 0x20, 0xFF, 0x49,
		0x44, 0x33, 0x20, 0x00, 0x0F,
	}
)

// --------------------------------------------------------------------
// Types
// --------------------------------------------------------------------

// parsedFrame holds the result of parsing a single TS packet.
type parsedFrame struct {
	Type          frameType
	PID           int
	CC            int
	Err           error
	Programs      []patProgram // PAT
	Streams       []pmtStream  // PMT
	PCRPID        int          // PMT
	TableSnap     []byte       // PMT
	Timestamp     int64        // PES
	RawTimestamp   [5]byte     // PES
	HasTimestamp   bool        // PES
	PayloadOffset int          // payload start offset
	Continuation  bool         // PUSI=0 continuation packet
}

type patProgram struct{ ID, PMTPID int }
type pmtStream struct {
	PID  int
	Type byte
}
type metaEntry struct {
	Moment int64 // time offset in PTS ticks (90kHz)
	Tag    []byte
}
type program struct {
	PMTPID  int
	PCRPID  int
	PMTSnap []byte
	Streams map[int]byte
}

// sectionHeader holds the common PSI section header fields.
type sectionHeader struct {
	tableID    byte
	sectionLen int
	data       []byte // full section starting at table_id
}

// --------------------------------------------------------------------
// Shared PSI section header
// --------------------------------------------------------------------

// parseSectionHeader parses the common header shared by PAT and PMT.
// Returns nil if the payload does not start a valid PSI section.
func parseSectionHeader(payload []byte, payloadStart uint16) *sectionHeader {
	if len(payload) < 1 || payloadStart != 1 || payload[0] != 0 {
		return nil
	}
	section := payload[1:] // skip pointer field
	if len(section) < 8 {
		return nil
	}

	w := be.Uint16(section[1:3])
	sectionLen := int(w & sectionLenMask)

	if debug {
		dbgf("8 bits: Table ID = %d", section[0])
		dbgf("1 bit: Section syntax = %d, Private = %d, Reserved = %d",
			(w>>15)&1, (w>>14)&1, (w>>12)&3)
		dbgf("10 bits: Section length = %d", sectionLen)
	}

	if 3+sectionLen > len(section) {
		return nil
	}

	if debug {
		b := section[5]
		dbgf("Table ID ext = %d, Version = %d, Current/next = %d, Section %d/%d",
			be.Uint16(section[3:5]), (b>>1)&31, b&1, section[6], section[7])
	}

	return &sectionHeader{
		tableID:    section[0],
		sectionLen: sectionLen,
		data:       section,
	}
}

// verifyCRC checks the CRC32 of the section.
func (h *sectionHeader) verifyCRC() error {
	end := 3 + h.sectionLen
	if end > len(h.data) {
		return fmt.Errorf("section extends beyond payload")
	}
	if debug {
		if crcOfs := end - 4; crcOfs >= 0 {
			dbgf("** CRC contained = 0x%x", be.Uint32(h.data[crcOfs:crcOfs+4]))
		}
	}
	if calculateCRC(h.data[:end]) == 0 {
		if debug {
			dbgf("** CRC OK")
		}
		return nil
	}
	if debug {
		dbgf("** CRC FAILED")
	}
	return fmt.Errorf("CRC mismatch")
}

// --------------------------------------------------------------------
// Frame parsing
// --------------------------------------------------------------------

func parseFrame(frame []byte, result *parsedFrame) {
	// Reset all fields for reuse.
	*result = parsedFrame{}

	defer func() {
		if r := recover(); r != nil {
			result.Type = frameIncorrect
			result.Err = fmt.Errorf("malformed packet: %v", r)
		}
	}()

	if frame[0] != syncByte {
		result.Type = frameIncorrect
		result.Err = errors.New("sync byte missing")
		return
	}
	result.Type = frameUnknown

	header := be.Uint16(frame[1:3])
	payloadStart := (header >> 14) & 1
	result.PID = int(header & pidMask)

	flags := frame[3]
	adaptCtrl := (flags >> 4) & 3
	result.CC = int(flags & 0x0F)

	if result.PID == 0 {
		result.Type = framePAT
	}

	// Determine payload offset
	switch adaptCtrl {
	case 0: // reserved
		return
	case 1:
		result.PayloadOffset = 4
	case 2: // adaptation only
		if debug {
			dbgf("** Adaptation only, no payload")
		}
		return
	case 3: // adaptation + payload
		if len(frame) < 5 {
			result.Type = frameIncorrect
			result.Err = errors.New("frame too short")
			return
		}
		adaptLen := int(frame[4])
		result.PayloadOffset = 5 + adaptLen
		if result.PayloadOffset >= packetSize {
			return
		}
	}

	// Continuation packets (PUSI=0)
	if payloadStart == 0 && adaptCtrl == 1 {
		result.Continuation = true
		payload := frame[result.PayloadOffset:]
		if len(payload) >= 3 && payload[0] == 0 && payload[1] == 0 && payload[2] == 1 && result.Type == frameUnknown {
			result.Type = framePES
		}
		return
	}

	// Full debug logging for non-continuation packets
	if debug {
		dbgf("==== TS HEADER ====")
		dbgf("TEI=%d PUSI=%d Priority=%d PID=%d(0x%x)",
			(header>>15)&1, payloadStart, (header>>13)&1, result.PID, result.PID)
		dbgf("Scrambling=%d AdaptCtrl=%d CC=%d", (flags>>6)&3, adaptCtrl, result.CC)
		if adaptCtrl == 3 {
			dbgf("** Adaptation len=%d, payload at %d", int(frame[4]), result.PayloadOffset)
		}
	}

	payload := frame[result.PayloadOffset:]

	// PES detection: start code prefix 00 00 01
	if len(payload) >= 3 && payload[0] == 0 && payload[1] == 0 && payload[2] == 1 && result.Type == frameUnknown {
		result.Type = framePES
	}

	switch result.Type {
	case framePAT:
		parsePAT(payload, payloadStart, result)
	case framePES:
		parsePES(payload, result)
	default:
		parsePMT(payload, payloadStart, result)
	}
}

func parsePAT(payload []byte, payloadStart uint16, result *parsedFrame) {
	if debug {
		dbgf("==== PAT ====")
	}
	hdr := parseSectionHeader(payload, payloadStart)
	if hdr == nil {
		result.Type = frameUnknown
		return
	}

	section := hdr.data
	loopEnd := 3 + hdr.sectionLen - 4
	for i := 8; i < loopEnd; i += 4 {
		if i+4 > len(section) {
			break
		}
		progID := int(be.Uint16(section[i : i+2]))
		pid := int(be.Uint16(section[i+2:i+4]) & pidMask)
		if debug {
			dbgf("  Program %d -> PID %d (0x%x)", progID, pid, pid)
		}
		result.Programs = append(result.Programs, patProgram{ID: progID, PMTPID: pid})
	}

	if err := hdr.verifyCRC(); err != nil {
		result.Err = err
	}
}

func parsePES(payload []byte, result *parsedFrame) {
	if len(payload) < 14 {
		result.Type = frameUnknown
		return
	}

	if debug {
		dbgf("==== PES ==== stream_id=0x%x length=%d", payload[3], be.Uint16(payload[4:6]))
	}

	// Marker bits must be '10'
	if (payload[6]>>6)&3 != 2 {
		result.Type = frameUnknown
		return
	}

	ptsDtsFlags := (payload[7] >> 6) & 3
	if debug {
		dbgf("PTS/DTS flags=%d, PES header len=%d", ptsDtsFlags, payload[8])
	}

	if ptsDtsFlags != 2 && ptsDtsFlags != 3 {
		return
	}

	// Validate PTS marker nibble
	expectedMarker := byte(2)
	if ptsDtsFlags == 3 {
		expectedMarker = 3
	}
	if (payload[9]>>4)&0x0F != expectedMarker {
		return
	}

	// Extract PTS
	five := (int64(payload[9]) << 32) | (int64(payload[10]) << 24) |
		(int64(payload[11]) << 16) | (int64(payload[12]) << 8) | int64(payload[13])
	pts := ((five >> 3) & (0x0007 << 30)) |
		((five >> 2) & (0x7fff << 15)) |
		((five >> 1) & 0x7fff)

	if debug {
		dbgf("PTS = %d (%.3fs)", pts, float64(pts)/float64(clockFrequency))
	}

	result.Timestamp = pts
	result.HasTimestamp = true
	copy(result.RawTimestamp[:], payload[9:14])

	// Debug: detect ID3 in PES payload
	if debug {
		pesHeaderLen := int(payload[8])
		if dataStart := 9 + pesHeaderLen; dataStart < len(payload) {
			data := payload[dataStart:]
			if len(data) >= 3 && data[0] == 'I' && data[1] == 'D' && data[2] == '3' {
				dbgf("** ID3 metadata at PTS %.3fs", float64(pts)/float64(clockFrequency))
			}
		}
	}
}

// parsePMT attempts to parse the payload as a PMT section.
// Non-PMT tables are silently ignored (Type set to frameUnknown).
func parsePMT(payload []byte, payloadStart uint16, result *parsedFrame) {
	hdr := parseSectionHeader(payload, payloadStart)
	if hdr == nil {
		result.Type = frameUnknown
		return
	}

	// Detect PMT: table_id==2, private_bit==0, reserved==3
	w := be.Uint16(hdr.data[1:3])
	if hdr.tableID != 2 || (w>>14)&1 != 0 || (w>>12)&3 != 3 {
		result.Type = frameUnknown
		return
	}
	result.Type = framePMT
	if debug {
		dbgf("==== PMT ====")
	}

	section := hdr.data
	if len(section) < 12 {
		result.Type = frameUnknown
		return
	}

	result.PCRPID = int(be.Uint16(section[8:10]) & pidMask)
	progInfoLen := int(be.Uint16(section[10:12]) & sectionLenMask)
	if debug {
		dbgf("PCR PID = %d", result.PCRPID)
		dbgf("Program info length = %d", progInfoLen)
	}

	if 12+progInfoLen > len(section) {
		result.Type = frameUnknown
		return
	}

	// Log program-level descriptors
	if debug {
		for i := 12; i < 12+progInfoLen; {
			if i+2 > len(section) {
				break
			}
			tag, dlen := section[i], int(section[i+1])
			if i+2+dlen > len(section) {
				break
			}
			dbgf("  Descriptor tag=%d len=%d", tag, dlen)
			i += 2 + dlen
		}
	}

	// Elementary stream entries
	tableEnd := 3 + hdr.sectionLen - 4 - 1
	if tableEnd >= len(section) {
		result.Type = frameUnknown
		return
	}

	i := 12 + progInfoLen
	if i <= tableEnd {
		result.TableSnap = append([]byte{}, section[i:tableEnd+1]...)
	}

	for i <= tableEnd {
		if i+5 > len(section) {
			break
		}
		sType := section[i]
		sPID := int(be.Uint16(section[i+1:i+3]) & pidMask)
		esInfoLen := int(be.Uint16(section[i+3:i+5]) & sectionLenMask)
		if debug {
			dbgf("  Stream type=%d PID=%d(0x%x) ES_info=%d", sType, sPID, sPID, esInfoLen)

			// Log ES-level descriptors
			for ii := i + 5; ii < i+5+esInfoLen; {
				if ii+2 > len(section) {
					break
				}
				dtag, dlen := section[ii], int(section[ii+1])
				if ii+2+dlen > len(section) {
					break
				}
				dbgf("    ES descriptor tag=%d len=%d", dtag, dlen)
				ii += 2 + dlen
			}
		}

		result.Streams = append(result.Streams, pmtStream{PID: sPID, Type: sType})
		i += 5 + esInfoLen
	}

	if err := hdr.verifyCRC(); err != nil {
		result.Err = err
	}
}

// --------------------------------------------------------------------
// Frame generation
// --------------------------------------------------------------------

func encodeSyncsafe(size int) [4]byte {
	return [4]byte{
		byte((size >> 21) & 0x7F),
		byte((size >> 14) & 0x7F),
		byte((size >> 7) & 0x7F),
		byte(size & 0x7F),
	}
}

// generateID3Frame creates a minimal ID3v2.4 frame with a TPE1 tag.
func generateID3Frame(content string) ([]byte, error) {
	framePayload := 1 + len(content) + 1 // encoding byte + text + null
	tagBody := 10 + framePayload         // frame header + payload
	totalSize := 10 + 10 + framePayload  // ID3 header + frame header + payload

	if totalSize > maxID3TagSize {
		return nil, fmt.Errorf("content too long: ID3 tag would be %d bytes (max %d)", totalSize, maxID3TagSize)
	}

	f := make([]byte, 0, totalSize)

	// ID3v2.4 header (10 bytes)
	f = append(f, 'I', 'D', '3', 4, 0, 0)
	ss := encodeSyncsafe(tagBody)
	f = append(f, ss[0], ss[1], ss[2], ss[3])

	// Frame header (10 bytes): TPE1 + size + flags
	f = append(f, 'T', 'P', 'E', '1')
	fs := encodeSyncsafe(framePayload)
	f = append(f, fs[0], fs[1], fs[2], fs[3])
	f = append(f, 0, 0) // frame flags

	// Frame payload: encoding byte + text + null terminator
	f = append(f, 3) // UTF-8
	f = append(f, content...)
	f = append(f, 0) // null terminator
	return f, nil
}

// generateMetaFrames creates one or more 188-byte TS packets with PES-wrapped ID3 metadata.
// Small tags (<=170 bytes) produce a single packet; larger tags are split across multiple.
// Returns the concatenated packets and the number of packets (for CC tracking).
func generateMetaFrames(metaTag []byte, metaPID int, rawPTS [5]byte, cc int) ([]byte, int) {
	pesPayloadLen := pesHeaderSize + len(metaTag) // PES header + ID3 data
	id3DataInFirst := firstPacketPayload - pesHeaderSize
	if id3DataInFirst < 0 {
		id3DataInFirst = 0
	}

	numPackets := 1
	if len(metaTag) > id3DataInFirst {
		remaining := len(metaTag) - id3DataInFirst
		numPackets += (remaining + continuationPayload - 1) / continuationPayload
	}

	out := make([]byte, numPackets*packetSize)

	// Fill with 0xFF (adaptation field stuffing)
	for i := range out {
		out[i] = 0xFF
	}

	// --- First packet: TS header + PES header + PTS + start of ID3 ---
	f := out[0:packetSize]

	// TS header with PUSI=1
	f[0] = syncByte
	be.PutUint16(f[1:3], 0x4000|uint16(metaPID&pidMask))

	if numPackets == 1 {
		// Single packet: use adaptation field for stuffing
		stuffLen := firstPacketPayload - pesPayloadLen
		if stuffLen > 0 {
			f[3] = byte(0x30 | (cc & 0x0F)) // adaptation + payload
			f[4] = byte(stuffLen - 1)        // adaptation_field_length
			if stuffLen > 1 {
				f[5] = 0x00 // adaptation flags (no PCR, etc.)
				// remaining stuffing bytes already 0xFF
			}
			pesStart := 4 + stuffLen
			writePESHeader(f[pesStart:], rawPTS, len(metaTag))
			copy(f[pesStart+pesHeaderSize:], metaTag)
		} else {
			f[3] = byte(0x10 | (cc & 0x0F)) // payload only
			writePESHeader(f[4:], rawPTS, len(metaTag))
			copy(f[4+pesHeaderSize:], metaTag)
		}
		return out, 1
	}

	// Multi-packet: first packet is fully filled (no stuffing)
	f[3] = byte(0x10 | (cc & 0x0F)) // payload only
	writePESHeader(f[4:], rawPTS, len(metaTag))
	tagOffset := copy(f[4+pesHeaderSize:], metaTag[:id3DataInFirst])
	tagOffset = id3DataInFirst

	// --- Continuation packets ---
	for p := 1; p < numPackets; p++ {
		cc = (cc + 1) & 0x0F
		pkt := out[p*packetSize : (p+1)*packetSize]

		pkt[0] = syncByte
		be.PutUint16(pkt[1:3], uint16(metaPID&pidMask)) // PUSI=0

		remaining := len(metaTag) - tagOffset
		chunkSize := continuationPayload
		if remaining < chunkSize {
			chunkSize = remaining
		}

		if chunkSize < continuationPayload {
			// Last packet: use adaptation field for stuffing
			stuffLen := continuationPayload - chunkSize
			pkt[3] = byte(0x30 | (cc & 0x0F)) // adaptation + payload
			pkt[4] = byte(stuffLen - 1)
			if stuffLen > 1 {
				pkt[5] = 0x00
			}
			copy(pkt[4+stuffLen:], metaTag[tagOffset:tagOffset+chunkSize])
		} else {
			pkt[3] = byte(0x10 | (cc & 0x0F)) // payload only
			copy(pkt[4:], metaTag[tagOffset:tagOffset+chunkSize])
		}
		tagOffset += chunkSize
	}

	return out, numPackets
}

// writePESHeader writes the 14-byte PES header (9 header + 5 PTS) at dst.
func writePESHeader(dst []byte, rawPTS [5]byte, id3Len int) {
	dst[0] = 0x00
	dst[1] = 0x00
	dst[2] = 0x01
	dst[3] = 0xBD // private_stream_1

	// PES packet length = 3 (header flags) + 5 (PTS) + id3Len
	pesLen := 3 + 5 + id3Len
	if pesLen > 65535 {
		pesLen = 0 // unbounded (per MPEG-2 spec)
	}
	be.PutUint16(dst[4:6], uint16(pesLen))

	dst[6] = 0x84 // PES header flags
	dst[7] = 0x80 // PTS flag
	dst[8] = 0x05 // PES header data length (5 bytes of PTS)

	// PTS marker nibble = 0010 (PTS only)
	dst[9] = (rawPTS[0] & 0x0F) | 0x20
	copy(dst[10:14], rawPTS[1:])
}

// modifyPMT adds a timed metadata stream entry to a PMT packet.
// Returns the modified frame and the metadata stream PID.
func modifyPMT(original []byte, metaPID int) ([]byte, int) {
	mod := bytes.Repeat([]byte{0xFF}, packetSize)

	const secBase = 5 // TS header (4) + pointer field (1)
	sectionLen := int(be.Uint16(original[secBase+1:secBase+3]) & sectionLenMask)
	copy(mod[:secBase+pmtFixedHeader], original[:secBase+pmtFixedHeader])

	// Increment version (5 bits, wraps mod 32)
	vOfs := secBase + pmtVersionByte
	vb := mod[vOfs]
	v := ((vb >> 1) & 0x1F + 1) & 0x1F
	mod[vOfs] = (vb & 0xC1) | (v << 1)
	if debug {
		dbgf("PMT version %d -> %d", (vb>>1)&0x1F, v)
	}

	piOfs := secBase + pmtProgInfoLen
	oldProgInfoLen := int(be.Uint16(original[piOfs:piOfs+2]) & sectionLenMask)
	streamBase := secBase + pmtFixedHeader
	ptr := streamBase
	if oldProgInfoLen > 0 {
		copy(mod[streamBase:streamBase+oldProgInfoLen], original[streamBase:streamBase+oldProgInfoLen])
		ptr = streamBase + oldProgInfoLen
	}

	// Append program-level metadata descriptor
	extra := copy(mod[ptr:], appleMetaDescriptor)
	ptr += extra
	mod[piOfs+1] = byte(oldProgInfoLen + extra)

	tableEnd := sectionLen + secBase - 2

	// Auto-detect metadata PID: highest existing + 1
	if metaPID <= 0 {
		highest := 0
		for i := streamBase + oldProgInfoLen; i <= tableEnd; {
			if i+5 > packetSize {
				break
			}
			sid := int(be.Uint16(original[i+1:i+3]) & pidMask)
			if sid > highest {
				highest = sid
			}
			i += 5 + int(be.Uint16(original[i+3:i+5])&sectionLenMask)
		}
		metaPID = highest + 1
		if debug {
			dbgf("** Auto-selected metadata PID = %d", metaPID)
		}
	}

	// Copy original stream entries
	srcStart := streamBase + oldProgInfoLen
	n := copy(mod[ptr:], original[srcStart:tableEnd+1])
	ptr += n

	// Append metadata stream entry
	mod[ptr] = appleMetaStreamType
	ptr++
	be.PutUint16(mod[ptr:ptr+2], 0xE000|uint16(metaPID&pidMask))
	ptr += 2
	be.PutUint16(mod[ptr:ptr+2], 0xF000|uint16(appleMetaESInfoLen))
	ptr += 2
	extra += 5

	n = copy(mod[ptr:], appleMetaESDescriptor)
	ptr += n
	extra += n

	// Update section length
	mod[secBase+2] = byte(int(mod[secBase+2]) + extra)

	// CRC32
	crc := calculateCRC(mod[secBase:ptr])
	be.PutUint32(mod[ptr:ptr+4], crc)
	if debug {
		dbgf("** PMT CRC = 0x%x", crc)
	}

	return mod, metaPID
}

// --------------------------------------------------------------------
// Injector — encapsulates inject-mode state
// --------------------------------------------------------------------

type injector struct {
	writer    *bufio.Writer
	tagCh       chan []byte  // injection queue for live sources
	metaData  []metaEntry // static metadata entries
	metaPID   int
	metaCC    int
	basePTS   int64 // first PTS seen
	hasBase   bool
	injected  int
}

func (inj *injector) writeMetaFrame(tag []byte, rawPTS [5]byte, count int) error {
	data, numPackets := generateMetaFrames(tag, inj.metaPID, rawPTS, inj.metaCC)
	fmt.Fprintf(os.Stderr, "Inserting ID3 frame after frame %d (tag=%d bytes, packets=%d)\n", count, len(tag), numPackets)
	if _, err := inj.writer.Write(data); err != nil {
		return fmt.Errorf("write error: %w", err)
	}
	inj.injected++
	inj.metaCC = (inj.metaCC + numPackets) & 0x0F
	return nil
}

func (inj *injector) handleFrame(frame []byte, parsed *parsedFrame, count int) error {
	if parsed.Type == framePMT {
		mod, pid := modifyPMT(frame, inj.metaPID)
		copy(frame, mod)
		if inj.metaPID == 0 {
			inj.metaPID = pid
		}
	}

	if parsed.HasTimestamp {
		if !inj.hasBase {
			inj.basePTS = parsed.Timestamp
			inj.hasBase = true
		}

		// Static file mode: inject by time offset
		if len(inj.metaData) > 0 && inj.metaPID > 0 {
			elapsed := parsed.Timestamp - inj.basePTS
			if elapsed >= inj.metaData[0].Moment {
				if err := inj.writeMetaFrame(inj.metaData[0].Tag, parsed.RawTimestamp, count); err != nil {
					return err
				}
				inj.metaData = inj.metaData[1:]
			}
		}

		// Live channel: drain pending tags
		if inj.tagCh != nil && inj.metaPID > 0 {
		drain:
			for {
				select {
				case tag := <-inj.tagCh:
					if err := inj.writeMetaFrame(tag, parsed.RawTimestamp, count); err != nil {
						return err
					}
				default:
					break drain
				}
			}
		}
	}

	_, err := inj.writer.Write(frame)
	return err
}

// --------------------------------------------------------------------
// Metadata parsing
// --------------------------------------------------------------------

// parseMetaLine parses a "<seconds> <plaintext|id3> <content>" line
// and returns the time as PTS ticks and the ID3 tag bytes.
func parseMetaLine(line string) (moment int64, tag []byte, err error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return 0, nil, fmt.Errorf("empty line")
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		return 0, nil, fmt.Errorf("invalid format")
	}
	sec, err := strconv.ParseFloat(parts[0], 64)
	if err != nil || sec < 0 {
		return 0, nil, fmt.Errorf("invalid moment: %s", parts[0])
	}
	moment = int64(sec * clockFrequency)

	format, content := strings.ToLower(parts[1]), parts[2]
	switch format {
	case "plaintext":
		tag, err := generateID3Frame(content)
		if err != nil {
			return 0, nil, err
		}
		return moment, tag, nil
	case "id3":
		data, err := os.ReadFile(content)
		if err != nil {
			return 0, nil, fmt.Errorf("cannot read ID3 file: %w", err)
		}
		if len(data) > maxID3TagSize {
			return 0, nil, fmt.Errorf("ID3 file too large (%d > %d bytes)", len(data), maxID3TagSize)
		}
		return moment, data, nil
	default:
		return 0, nil, fmt.Errorf("unknown format: %s", format)
	}
}

// parseMetadataFile reads and parses a static timed metadata file.
func parseMetadataFile(filename string) ([]metaEntry, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open metadata file: %w", err)
	}

	var entries []metaEntry
	for i, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		moment, tag, err := parseMetaLine(line)
		if err != nil {
			return nil, fmt.Errorf("metadata line %d: %w", i+1, err)
		}
		entries = append(entries, metaEntry{Moment: moment, Tag: tag})
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("empty metadata file")
	}
	slices.SortFunc(entries, func(a, b metaEntry) int {
		switch {
		case a.Moment < b.Moment:
			return -1
		case a.Moment > b.Moment:
			return 1
		default:
			return 0
		}
	})
	return entries, nil
}

// streamMetadataLines reads lines from r and sends parsed ID3 tags to ch.
// Accepts plain text (auto-wrapped as TPE1) or full "<seconds> <format> <content>" syntax.
func streamMetadataLines(r io.Reader, ch chan<- []byte) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Try structured format first, fall back to plain text.
		_, tag, err := parseMetaLine(line)
		if err != nil {
			tag, err = generateID3Frame(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "live metadata: %s\n", err)
				continue
			}
		}
		ch <- tag
	}
}

// newInjectHandler creates the HTTP handler for live metadata injection.
func newInjectHandler(ch chan<- []byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /inject", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text      string `json:"text"`
			ID3Base64 string `json:"id3_base64"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 128*1024) // 128 KB request limit
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		var tag []byte
		switch {
		case req.Text != "":
			t, err := generateID3Frame(req.Text)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			tag = t
		case req.ID3Base64 != "":
			data, err := base64.StdEncoding.DecodeString(req.ID3Base64)
			if err != nil {
				http.Error(w, "invalid base64: "+err.Error(), http.StatusBadRequest)
				return
			}
			if len(data) > maxID3TagSize {
				http.Error(w, fmt.Sprintf("ID3 tag too large (%d > %d bytes)", len(data), maxID3TagSize), http.StatusBadRequest)
				return
			}
			tag = data
		default:
			http.Error(w, "provide 'text' or 'id3_base64'", http.StatusBadRequest)
			return
		}

		select {
		case ch <- tag:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
		default:
			http.Error(w, "queue full, try again later", http.StatusServiceUnavailable)
		}
	})
	return mux
}

// startHTTPServer binds the listen address and starts an HTTP control server.
// Returns an error if the port cannot be bound (e.g. already in use).
// The server shuts down gracefully when ctx is cancelled.
func startHTTPServer(ctx context.Context, addr string, ch chan<- []byte) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("cannot start HTTP server: %w", err)
	}
	srv := &http.Server{Handler: newInjectHandler(ch)}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	fmt.Fprintf(os.Stderr, "** HTTP control listening on %s\n", ln.Addr())
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "HTTP server error: %s\n", err)
		}
	}()
	return nil
}

// --------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------

// streamTypeName returns a human-readable name for an MPEG TS stream type byte.
func streamTypeName(t byte) string {
	switch t {
	case 0x01:
		return "MPEG-1 Video"
	case 0x02:
		return "MPEG-2 Video"
	case 0x03:
		return "MPEG-1 Audio"
	case 0x04:
		return "MPEG-2 Audio"
	case 0x06:
		return "Private Data"
	case 0x0F:
		return "AAC Audio"
	case 0x11:
		return "AAC-LATM Audio"
	case 0x15:
		return "ID3 Metadata"
	case 0x1B:
		return "H.264 Video"
	case 0x24:
		return "H.265 Video"
	case 0x81:
		return "AC-3 Audio"
	case 0x87:
		return "E-AC-3 Audio"
	default:
		return fmt.Sprintf("Unknown (0x%02X)", t)
	}
}

// validateListenAddr checks that addr is a valid host:port for net.Listen.
func validateListenAddr(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %s", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port in %q: must be 1-65535", addr)
	}
	if host != "" {
		if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid IP in %q: %s is not a valid IPv4 or IPv6 address", addr, host)
		}
	}
	return nil
}

// isPipe returns true if f is connected to a pipe (not a terminal).
func isPipe(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) == 0
}

// openInput opens the input file or stdin and returns a buffered reader + closer.
func openInput(filename string) (*bufio.Reader, func(), error) {
	var reader *bufio.Reader
	var closer func()

	if filename == "-" {
		reader = bufio.NewReaderSize(os.Stdin, 64*1024)
		closer = func() {}
	} else {
		stat, err := os.Stat(filename)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot stat input: %w", err)
		}
		if stat.Size()%packetSize != 0 {
			return nil, nil, fmt.Errorf("broken MPEG TS: file size must be a multiple of %d", packetSize)
		}
		f, err := os.Open(filename)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open input: %w", err)
		}
		reader = bufio.NewReaderSize(f, 64*1024)
		closer = func() { f.Close() }
	}

	// Verify first byte is a TS sync byte
	first, err := reader.Peek(1)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read input: %w", err)
	}
	if first[0] != syncByte {
		return nil, nil, fmt.Errorf("not an MPEG TS file (first byte 0x%02X, expected 0x%02X)", first[0], syncByte)
	}

	return reader, closer, nil
}

// streamStats holds per-stream counters and program info.
type streamStats struct {
	pidPackets map[int]int
	ccCounters map[int]int // last CC per PID
	ccErrors   map[int]int
	programs   map[int]*program
	firstPTS   int64
	lastPTS    int64
	id3Count   int
}

// trackCC checks the continuity counter for the given frame.
func (s *streamStats) trackCC(parsed *parsedFrame) {
	if prev, ok := s.ccCounters[parsed.PID]; ok {
		if expected := (prev + 1) & 0x0F; parsed.CC != expected {
			if debug {
				dbgf("** CC mismatch PID %d: got %d, want %d", parsed.PID, parsed.CC, expected)
			}
			s.ccErrors[parsed.PID]++
		}
	}
	s.ccCounters[parsed.PID] = parsed.CC
}

// detectID3 checks a PES packet for an ID3 tag and reports it.
func (s *streamStats) detectID3(pkt []byte, parsed *parsedFrame) {
	if parsed.Type != framePES || parsed.PayloadOffset <= 0 {
		return
	}
	payload := pkt[parsed.PayloadOffset:]
	if len(payload) <= 9 {
		return
	}
	pesHeaderLen := int(payload[8])
	dataStart := 9 + pesHeaderLen
	if dataStart+3 > len(payload) || payload[dataStart] != 'I' || payload[dataStart+1] != 'D' || payload[dataStart+2] != '3' {
		return
	}
	s.id3Count++
	if parsed.HasTimestamp {
		fmt.Fprintf(os.Stderr, "  ID3 tag at PTS %.3fs (PID %d)\n",
			float64(parsed.Timestamp)/float64(clockFrequency), parsed.PID)
	} else {
		fmt.Fprintf(os.Stderr, "  ID3 tag (PID %d)\n", parsed.PID)
	}
}

// trackPAT records programs discovered from a PAT packet.
func (s *streamStats) trackPAT(parsed *parsedFrame) {
	for _, p := range parsed.Programs {
		if _, exists := s.programs[p.ID]; !exists {
			s.programs[p.ID] = &program{Streams: make(map[int]byte)}
		}
		if s.programs[p.ID].PMTPID == 0 {
			s.programs[p.ID].PMTPID = p.PMTPID
		}
	}
}

// trackPMT records streams discovered from a PMT packet.
func (s *streamStats) trackPMT(parsed *parsedFrame) error {
	for _, prog := range s.programs {
		if prog.PMTPID == parsed.PID {
			if prog.PMTSnap == nil {
				prog.PMTSnap = append([]byte{}, parsed.TableSnap...)
				prog.PCRPID = parsed.PCRPID
			} else if !bytes.Equal(prog.PMTSnap, parsed.TableSnap) {
				return fmt.Errorf("PMT changing over time is not supported")
			}
			for _, st := range parsed.Streams {
				prog.Streams[st.PID] = st.Type
			}
			break
		}
	}
	return nil
}

// printReport prints the final summary.
func printReport(frames, errCount int, stats *streamStats, verbose bool, injected int, elapsed time.Duration) {
	streamCount := 0
	for _, p := range stats.programs {
		streamCount += len(p.Streams)
	}

	fmt.Fprintf(os.Stderr, "\nParsed %d MPEG TS frames with %d errors\n", frames, errCount)
	fmt.Fprintf(os.Stderr, "Total of %d programs and %d streams\n", len(stats.programs), streamCount)

	if verbose {
		if stats.firstPTS >= 0 && stats.lastPTS >= 0 {
			dur := float64(stats.lastPTS-stats.firstPTS) / float64(clockFrequency)
			fmt.Fprintf(os.Stderr, "Duration: %.3fs (PTS %d – %d)\n", dur, stats.firstPTS, stats.lastPTS)
		}

		fmt.Fprintf(os.Stderr, "\n  %-8s %-20s %8s %6s\n", "PID", "Type", "Packets", "CC Err")
		fmt.Fprintf(os.Stderr, "  %-8s %-20s %8s %6s\n", "---", "----", "-------", "------")
		fmt.Fprintf(os.Stderr, "  %-8d %-20s %8d %6d\n", 0, "PAT", stats.pidPackets[0], stats.ccErrors[0])

		for progID, prog := range stats.programs {
			fmt.Fprintf(os.Stderr, "  %-8d %-20s %8d %6d\n",
				prog.PMTPID, fmt.Sprintf("PMT (prog %d)", progID),
				stats.pidPackets[prog.PMTPID], stats.ccErrors[prog.PMTPID])
			for pid, stype := range prog.Streams {
				name := streamTypeName(stype)
				if pid == prog.PCRPID {
					name += " (PCR)"
				}
				fmt.Fprintf(os.Stderr, "  %-8d %-20s %8d %6d\n",
					pid, name, stats.pidPackets[pid], stats.ccErrors[pid])
			}
		}

		shown := map[int]bool{0: true}
		for _, prog := range stats.programs {
			shown[prog.PMTPID] = true
			for pid := range prog.Streams {
				shown[pid] = true
			}
		}
		for pid, count := range stats.pidPackets {
			if !shown[pid] {
				fmt.Fprintf(os.Stderr, "  %-8d %-20s %8d %6d\n",
					pid, "Other", count, stats.ccErrors[pid])
			}
		}

		if stats.id3Count > 0 {
			fmt.Fprintf(os.Stderr, "\nFound %d existing ID3 metadata tags\n", stats.id3Count)
		}
	}

	if injected >= 0 {
		fmt.Fprintf(os.Stderr, "Injected %d frames\n", injected)
	}
	fmt.Fprintf(os.Stderr, "Finished in %.3fms\n", float64(elapsed)/float64(time.Millisecond))
}

// --------------------------------------------------------------------
// Main
// --------------------------------------------------------------------

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run() error {
	inputFile := flag.String("i", "", "Input MPEG TS file (use - for stdin)")
	outputFile := flag.String("o", "", "Output file (use - for stdout)")
	metaFile := flag.String("e", "", "Timed metadata file")
	metaStart := flag.Int("metastart", 0, "Starting continuity counter for metadata packets (0-15)")
	verboseFlag := flag.Bool("v", false, "Verbose: show stream table, timestamps, and ID3 tags")
	dbgFlag := flag.Bool("d", false, "Debug output (protocol-level)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	repeatSec := flag.Float64("repeat", 0, "Inject metadata every N seconds (live)")
	repeatText := flag.String("text", "", "Text to inject with -repeat")
	liveFlag := flag.Bool("live", false, "Stream metadata from -e continuously (for FIFOs)")
	listenAddr := flag.String("listen", "", "HTTP listen address (e.g. :8080 or 127.0.0.1:8080)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "id3injector %s – ID3v2.4 timed metadata injector for MPEG TS\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [-i file] [-o file] [-e file] [-d]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Input and output are auto-inferred from pipes when omitted.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("id3injector %s\n", version)
		return nil
	}

	if *dbgFlag {
		debug = true
	}

	// ---- Auto-infer input ----
	if *inputFile == "" {
		if isPipe(os.Stdin) {
			*inputFile = "-"
		} else {
			flag.Usage()
			return fmt.Errorf("no input: specify -i or pipe data to stdin")
		}
	}

	// ---- Auto-infer output ----
	outputExplicit := *outputFile != ""
	if *outputFile == "" && isPipe(os.Stdout) {
		*outputFile = "-"
	}

	// ---- Validate flags ----
	if *repeatSec < 0 {
		return fmt.Errorf("-repeat must be positive")
	}
	if *metaStart < 0 || *metaStart > maxCCValue {
		return fmt.Errorf("-metastart must be 0-%d", maxCCValue)
	}
	if *repeatSec > 0 && *repeatText == "" {
		return fmt.Errorf("-repeat requires -text")
	}
	if *liveFlag && *metaFile == "" {
		return fmt.Errorf("-live requires -e")
	}
	if *listenAddr != "" {
		if err := validateListenAddr(*listenAddr); err != nil {
			return err
		}
	}

	// ---- Determine inject vs check ----
	hasMetaSource := *metaFile != "" || *repeatSec > 0 || *listenAddr != ""
	inject := outputExplicit || hasMetaSource

	// ---- Print settings ----
	inputDesc := *inputFile
	if inputDesc == "-" {
		inputDesc = "stdin"
	}
	fmt.Fprintf(os.Stderr, "** %-10s %s\n", "input:", inputDesc)
	if inject && *outputFile != "" {
		outputDesc := *outputFile
		if outputDesc == "-" {
			outputDesc = "stdout"
		}
		fmt.Fprintf(os.Stderr, "** %-10s %s\n", "output:", outputDesc)
	}

	// ---- Validate combinations ----
	if inject && *outputFile == "" {
		return fmt.Errorf("output required: specify -o or pipe stdout")
	}
	if *inputFile != "-" && *outputFile != "-" && *inputFile != "" && *outputFile != "" {
		inAbs, err1 := filepath.Abs(*inputFile)
		outAbs, err2 := filepath.Abs(*outputFile)
		if err1 == nil && err2 == nil && inAbs == outAbs {
			return fmt.Errorf("input and output must be different files")
		}
	}
	hasLiveSource := *repeatSec > 0 || *listenAddr != ""
	if inject && *metaFile == "" && !hasLiveSource {
		return fmt.Errorf("specify metadata file (-e), or use -repeat/-listen for live mode")
	}
	if *metaFile != "" && !*liveFlag {
		if fi, err := os.Stat(*metaFile); err == nil && fi.Mode()&os.ModeNamedPipe != 0 {
			return fmt.Errorf("-e %s is a FIFO; add -live to stream from it", *metaFile)
		}
	}

	// ---- Context for live goroutines ----
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---- Set up injector ----
	var inj *injector
	if inject {
		var outWriter io.Writer
		if *outputFile == "-" {
			outWriter = os.Stdout
		} else {
			if _, err := os.Stat(*outputFile); err == nil {
				return fmt.Errorf("output file %s already exists (remove it first or use a different path)", *outputFile)
			}
			outFile, err := os.Create(*outputFile)
			if err != nil {
				return fmt.Errorf("cannot create output: %w", err)
			}
			defer outFile.Close()
			outWriter = outFile
		}

		inj = &injector{
			writer: bufio.NewWriterSize(outWriter, 64*1024),
			metaCC: *metaStart,
		}

		// Load static metadata file
		if *metaFile != "" && !*liveFlag {
			meta, err := parseMetadataFile(*metaFile)
			if err != nil {
				return err
			}
			inj.metaData = meta
			fmt.Fprintf(os.Stderr, "** Imported %d metadata tags\n", len(meta))
		}

		// Create live channel
		if *repeatSec > 0 || *liveFlag || *listenAddr != "" {
			inj.tagCh = make(chan []byte, 64)
		}

		// Repeat mode: ticker goroutine
		if *repeatSec > 0 {
			tag, err := generateID3Frame(*repeatText)
			if err != nil {
				return fmt.Errorf("-text: %w", err)
			}
			interval := time.Duration(*repeatSec * float64(time.Second))
			fmt.Fprintf(os.Stderr, "** Repeat mode: injecting every %v\n", interval)
			go func() {
				ticker := time.NewTicker(interval)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						inj.tagCh <- tag
					case <-ctx.Done():
						return
					}
				}
			}()
		}

		// FIFO / live streaming mode
		if *liveFlag {
			f, err := os.Open(*metaFile)
			if err != nil {
				return fmt.Errorf("cannot open metadata source: %w", err)
			}
			fmt.Fprintf(os.Stderr, "** Live mode: streaming metadata from %s\n", *metaFile)
			go func() {
				defer f.Close()
				streamMetadataLines(f, inj.tagCh)
			}()
			// Close FIFO on context cancel
			go func() {
				<-ctx.Done()
				f.Close()
			}()
		}

		// HTTP control server
		if *listenAddr != "" {
			if err := startHTTPServer(ctx, *listenAddr, inj.tagCh); err != nil {
				return err
			}
		}
	}

	// ---- Open input ----
	reader, closeInput, err := openInput(*inputFile)
	if err != nil {
		return err
	}
	defer closeInput()

	// ---- Main loop ----
	verbose := *verboseFlag || *dbgFlag
	var (
		frames, errCount int
		dbgSkipped     int
	)
	stats := &streamStats{
		pidPackets: map[int]int{},
		ccCounters: map[int]int{},
		ccErrors:   map[int]int{},
		programs:   map[int]*program{},
		firstPTS:   -1,
		lastPTS:    -1,
	}
	start := time.Now()

	buf := make([]byte, packetSize)
	var parsed parsedFrame
	for {
		if _, err := io.ReadFull(reader, buf); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read error at frame %d: %w", frames, err)
		}

		parseFrame(buf, &parsed)

		if parsed.Err != nil {
			fmt.Fprintf(os.Stderr, "Error at frame %d: %s\n", frames, parsed.Err)
			errCount++
		}
		if parsed.Type == frameIncorrect {
			continue
		}
		frames++
		stats.pidPackets[parsed.PID]++

		// Count continuation packets for debug summary
		if debug {
			if parsed.Continuation {
				dbgSkipped++
			} else if dbgSkipped > 0 {
				dbgf("    ... skipped %d continuation packets", dbgSkipped)
				dbgSkipped = 0
			}
		}

		// CC tracking
		stats.trackCC(&parsed)

		// PTS tracking
		if parsed.HasTimestamp {
			if stats.firstPTS < 0 {
				stats.firstPTS = parsed.Timestamp
			}
			stats.lastPTS = parsed.Timestamp
		}

		// ID3 detection (verbose)
		if verbose {
			stats.detectID3(buf, &parsed)
		}

		// Track programs and streams
		if parsed.Type == framePAT {
			stats.trackPAT(&parsed)
		}
		if parsed.Type == framePMT {
			if err := stats.trackPMT(&parsed); err != nil {
				return err
			}
		}

		// Inject
		if inj != nil {
			if err := inj.handleFrame(buf, &parsed, frames); err != nil {
				return err
			}
		}
	}

	// Flush remaining debug skip count
	if debug && dbgSkipped > 0 {
		dbgf("    ... skipped %d continuation packets", dbgSkipped)
	}

	if inj != nil {
		if err := inj.writer.Flush(); err != nil {
			return fmt.Errorf("flush: %w", err)
		}
	}

	injected := -1
	if inj != nil {
		injected = inj.injected
	}
	printReport(frames, errCount, stats, verbose, injected, time.Since(start))
	return nil
}
