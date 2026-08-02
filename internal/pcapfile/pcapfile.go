// Package pcapfile loads an Ethernet capture into a form the transmit loop can
// replay without allocating.
//
// It uses gopacket's pure-Go pcapgo reader, so Wireblast has no libpcap or cgo
// dependency and a static binary works anywhere.
//
// The whole file is read and validated before the dataplane starts. A broken
// or unsupported capture should cost you an error message, never a bounced
// link and a half-started run.
package pcapfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Limits on what will be loaded.
const (
	// MinFrame is the smallest thing that can be an Ethernet frame: two MAC
	// addresses and an EtherType.
	MinFrame = 14
	// MaxFrame is the largest frame that can be transmitted. It matches the
	// biggest UMEM frame Wireblast will configure.
	MaxFrame = 16384
	// MaxPackets bounds how much of a capture is loaded into memory, so
	// pointing Wireblast at a 40 GB capture fails politely instead of
	// exhausting the machine.
	MaxPackets = 2_000_000
)

// record is one frame's place in the flat backing store.
type record struct {
	off uint32
	len uint32
	// gap is the time between the previous frame and this one, as the capture
	// recorded it. Zero for the first frame.
	gap time.Duration
}

// File is a loaded capture, ready to replay.
//
// Frames live in one contiguous byte slice with an index alongside, so replay
// is a slice expression and a copy — no per-packet allocation, and the frames
// stay adjacent in memory for the cache's benefit.
type File struct {
	path string

	data []byte
	recs []record

	minLen, maxLen int
	meanLen        int
	span           time.Duration

	// truncated counts records whose captured bytes were fewer than the
	// original packet length, i.e. cut short by the capture's snaplen.
	truncated int
	// skipped counts records that could not be replayed at all.
	skipped int
}

// Load reads and validates a capture file.
func Load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture: %w", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<20)
	src, linkType, err := openReader(r, path)
	if err != nil {
		return nil, err
	}
	if linkType != layers.LinkTypeEthernet {
		return nil, fmt.Errorf(
			"%s has link type %v, but Wireblast can only replay Ethernet captures. "+
				"Re-capture with an Ethernet interface, or convert the file first", path, linkType)
	}

	out := &File{path: path, minLen: MaxFrame + 1}
	var first, prev time.Time
	for i := 0; ; i++ {
		data, ci, err := src.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A trailing partial record is common in a capture that was cut
			// off; anything else is worth reporting with its position.
			if errors.Is(err, io.ErrUnexpectedEOF) && len(out.recs) > 0 {
				out.skipped++
				break
			}
			return nil, fmt.Errorf("%s: reading packet %d: %w", path, i+1, err)
		}
		if len(out.recs) >= MaxPackets {
			return nil, fmt.Errorf("%s holds more than %d packets, which is more than Wireblast "+
				"will load into memory. Trim it with `editcap -c %d`", path, MaxPackets, MaxPackets)
		}

		switch {
		case len(data) < MinFrame:
			return nil, fmt.Errorf("%s: packet %d is %d bytes, too short to be an Ethernet frame",
				path, i+1, len(data))
		case len(data) > MaxFrame:
			return nil, fmt.Errorf("%s: packet %d is %d bytes, larger than the %d-byte maximum "+
				"Wireblast can transmit", path, i+1, len(data), MaxFrame)
		}
		if ci.Length > len(data) {
			out.truncated++
		}

		gap := time.Duration(0)
		if !prev.IsZero() && !ci.Timestamp.IsZero() {
			if d := ci.Timestamp.Sub(prev); d > 0 {
				gap = d
			}
		}
		if !ci.Timestamp.IsZero() {
			if first.IsZero() {
				first = ci.Timestamp
			}
			prev = ci.Timestamp
		}

		out.recs = append(out.recs, record{off: uint32(len(out.data)), len: uint32(len(data)), gap: gap})
		out.data = append(out.data, data...)
		out.minLen = min(out.minLen, len(data))
		out.maxLen = max(out.maxLen, len(data))
	}

	if len(out.recs) == 0 {
		return nil, fmt.Errorf("%s contains no packets", path)
	}
	if !first.IsZero() && !prev.IsZero() {
		out.span = prev.Sub(first)
	}
	out.meanLen = len(out.data) / len(out.recs)
	return out, nil
}

// openReader picks the pcap or pcapng reader by sniffing the file's magic.
func openReader(r *bufio.Reader, path string) (packetReader, layers.LinkType, error) {
	magic, err := r.Peek(4)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	// pcapng section header block; everything else is classic pcap, whose own
	// reader rejects a bad magic with a clear message.
	if magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a {
		ng, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: not a readable pcapng file: %w", path, err)
		}
		return ng, ng.LinkType(), nil
	}
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: not a readable pcap or pcapng file: %w", path, err)
	}
	return pr, pr.LinkType(), nil
}

// packetReader is the bit of pcapgo's readers Wireblast uses.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

// Len is how many frames the capture holds.
func (f *File) Len() int { return len(f.recs) }

// Frame returns the i-th frame and the gap the capture recorded before it. The
// returned slice aliases the backing store and must not be modified.
func (f *File) Frame(i int) ([]byte, time.Duration) {
	r := f.recs[i]
	return f.data[r.off : r.off+r.len], r.gap
}

// MaxLen is the largest frame in the capture, in bytes.
func (f *File) MaxLen() int { return f.maxLen }

// MinLen is the smallest frame in the capture, in bytes.
func (f *File) MinLen() int { return f.minLen }

// MeanLen is the mean frame size, used as the rate limiter's estimate.
func (f *File) MeanLen() int { return f.meanLen }

// Span is the wall-clock duration the capture covers.
func (f *File) Span() time.Duration { return f.span }

// Truncated is how many frames were cut short by the capture's snaplen. Those
// replay as the bytes that were actually captured, which is shorter than what
// the original host sent.
func (f *File) Truncated() int { return f.truncated }

// Bytes is the total size of the loaded frames.
func (f *File) Bytes() int { return len(f.data) }

// Describe summarises the capture for the review screen and the dashboard.
func (f *File) Describe() string {
	s := fmt.Sprintf("%s: %d packets, %d-%d bytes (mean %d)",
		f.path, len(f.recs), f.minLen, f.maxLen, f.meanLen)
	if f.span > 0 {
		s += fmt.Sprintf(", spanning %s", f.span.Round(time.Millisecond))
	}
	if f.truncated > 0 {
		s += fmt.Sprintf(", %d truncated by snaplen", f.truncated)
	}
	return s
}

// Warnings lists things about the capture the user should know before
// replaying it.
func (f *File) Warnings() []string {
	var out []string
	if f.truncated > 0 {
		out = append(out, fmt.Sprintf(
			"%d of %d packets were truncated by the capture's snapshot length. They will be "+
				"replayed at their captured size, which is shorter than the original packet.",
			f.truncated, len(f.recs)))
	}
	if f.skipped > 0 {
		out = append(out, fmt.Sprintf(
			"the capture ends with %d incomplete record(s), which were skipped.", f.skipped))
	}
	return out
}
