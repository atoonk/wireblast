// Package statsexport writes stable, machine-readable run statistics.
package statsexport

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/atoonk/wireblast/internal/stats"
)

// SchemaVersion changes only when the record contract changes incompatibly.
const SchemaVersion = 1

// Format selects the output encoding.
type Format string

const (
	FormatCSV   Format = "csv"
	FormatJSONL Format = "jsonl"
)

// Writer serializes snapshots. It is not safe for concurrent use.
type Writer struct {
	format Format
	csv    *csv.Writer
	json   *json.Encoder
}

// New creates an exporter and writes the CSV header when needed.
func New(format Format, out io.Writer) (*Writer, error) {
	w := &Writer{format: format}
	switch format {
	case FormatCSV:
		w.csv = csv.NewWriter(out)
		if err := w.csv.Write(csvHeader); err != nil {
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
		w.csv.Flush()
		if err := w.csv.Error(); err != nil {
			return nil, fmt.Errorf("flush CSV header: %w", err)
		}
	case FormatJSONL:
		w.json = json.NewEncoder(out)
	default:
		return nil, fmt.Errorf("unknown statistics format %q", format)
	}
	return w, nil
}

// Sample writes one periodic aggregate record.
func (w *Writer) Sample(s *stats.Snapshot) error {
	return w.write(aggregate("sample", s))
}

// Final writes the lifetime aggregate followed by one record per queue.
func (w *Writer) Final(s *stats.Snapshot) error {
	if err := w.write(aggregate("final", s)); err != nil {
		return err
	}
	for _, q := range s.Kernel.PerQueue {
		queue := q.Queue
		r := baseRecord("queue_final", s)
		r.QueueID = &queue
		r.KernelRXDescriptors = q.RxPackets
		r.KernelTXDescriptors = q.TxPackets
		r.RXDropped = q.RxDropped
		r.RXRingFull = q.RxRingFull
		if err := w.write(r); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes buffered output.
func (w *Writer) Close() error {
	if w.csv == nil {
		return nil
	}
	w.csv.Flush()
	if err := w.csv.Error(); err != nil {
		return fmt.Errorf("flush CSV statistics: %w", err)
	}
	return nil
}

func (w *Writer) write(r record) error {
	switch w.format {
	case FormatCSV:
		if err := w.csv.Write(r.csv()); err != nil {
			return fmt.Errorf("write CSV statistics: %w", err)
		}
		w.csv.Flush()
		if err := w.csv.Error(); err != nil {
			return fmt.Errorf("flush CSV statistics: %w", err)
		}
	case FormatJSONL:
		if err := w.json.Encode(r); err != nil {
			return fmt.Errorf("write JSONL statistics: %w", err)
		}
	}
	return nil
}

type record struct {
	SchemaVersion int     `json:"schema_version"`
	RecordType    string  `json:"record_type"`
	TimestampUTC  string  `json:"timestamp_utc"`
	Elapsed       float64 `json:"elapsed_seconds"`
	State         string  `json:"state"`
	Transmits     bool    `json:"transmits"`
	QueueID       *int    `json:"queue_id,omitempty"`

	TXPackets uint64  `json:"tx_packets"`
	TXBytes   uint64  `json:"tx_bytes"`
	TXUDP     uint64  `json:"tx_udp"`
	TXTCP     uint64  `json:"tx_tcp"`
	TXOther   uint64  `json:"tx_other"`
	TXErrors  uint64  `json:"tx_errors"`
	TXPPS     float64 `json:"tx_pps"`
	TXL1BPS   float64 `json:"tx_l1_bps"`
	TXL2BPS   float64 `json:"tx_l2_bps"`

	RXPackets uint64  `json:"rx_packets"`
	RXBytes   uint64  `json:"rx_bytes"`
	RXUDP     uint64  `json:"rx_udp"`
	RXTCP     uint64  `json:"rx_tcp"`
	RXOther   uint64  `json:"rx_other"`
	RXDrops   uint64  `json:"rx_drops"`
	RXPPS     float64 `json:"rx_pps"`
	RXL1BPS   float64 `json:"rx_l1_bps"`
	RXL2BPS   float64 `json:"rx_l2_bps"`

	KernelQueues        int    `json:"kernel_queues"`
	KernelRXDescriptors uint64 `json:"kernel_rx_descriptors"`
	KernelTXDescriptors uint64 `json:"kernel_tx_descriptors"`
	RXDropped           uint64 `json:"rx_dropped"`
	RXRingFull          uint64 `json:"rx_ring_full"`
	RXFillRingEmpty     uint64 `json:"rx_fill_ring_empty_descs"`
	RXInvalidDescs      uint64 `json:"rx_invalid_descs"`
	TXInvalidDescs      uint64 `json:"tx_invalid_descs"`
	TXRingEmpty         uint64 `json:"tx_ring_empty_descs"`
}

func baseRecord(kind string, s *stats.Snapshot) record {
	timestamp := ""
	if !s.At.IsZero() {
		timestamp = s.At.UTC().Format(time.RFC3339Nano)
	}
	return record{
		SchemaVersion: SchemaVersion,
		RecordType:    kind,
		TimestampUTC:  timestamp,
		Elapsed:       s.Elapsed.Seconds(),
		State:         s.State.String(),
		Transmits:     s.Transmits,
	}
}

func aggregate(kind string, s *stats.Snapshot) record {
	r := baseRecord(kind, s)
	r.TXPackets, r.TXBytes = s.TotalTX.Packets, s.TotalTX.Bytes
	r.TXUDP, r.TXTCP, r.TXOther = s.TotalTX.UDP, s.TotalTX.TCP, s.TotalTX.Other
	r.TXErrors = s.TotalTX.Errors
	r.TXPPS, r.TXL1BPS, r.TXL2BPS = s.TXRate.PPS, s.TXRate.WireBPS, s.TXRate.FrameBPS
	r.RXPackets, r.RXBytes = s.TotalRX.Packets, s.TotalRX.Bytes
	r.RXUDP, r.RXTCP, r.RXOther = s.TotalRX.UDP, s.TotalRX.TCP, s.TotalRX.Other
	r.RXDrops = s.TotalRX.Drops
	r.RXPPS, r.RXL1BPS, r.RXL2BPS = s.RXRate.PPS, s.RXRate.WireBPS, s.RXRate.FrameBPS
	r.KernelQueues = s.Kernel.Queues
	r.KernelRXDescriptors, r.KernelTXDescriptors = s.Kernel.RxPackets, s.Kernel.TxPackets
	r.RXDropped, r.RXRingFull = s.Kernel.RxDropped, s.Kernel.RxRingFull
	r.RXFillRingEmpty, r.RXInvalidDescs = s.Kernel.RxFillRingEmpty, s.Kernel.RxInvalidDescs
	r.TXInvalidDescs, r.TXRingEmpty = s.Kernel.TxInvalidDescs, s.Kernel.TxRingEmpty
	return r
}

var csvHeader = []string{
	"schema_version", "record_type", "timestamp_utc", "elapsed_seconds", "state", "transmits", "queue_id",
	"tx_packets", "tx_bytes", "tx_udp", "tx_tcp", "tx_other", "tx_errors", "tx_pps", "tx_l1_bps", "tx_l2_bps",
	"rx_packets", "rx_bytes", "rx_udp", "rx_tcp", "rx_other", "rx_drops", "rx_pps", "rx_l1_bps", "rx_l2_bps",
	"kernel_queues", "kernel_rx_descriptors", "kernel_tx_descriptors", "rx_dropped", "rx_ring_full", "rx_fill_ring_empty_descs",
	"rx_invalid_descs", "tx_invalid_descs", "tx_ring_empty_descs",
}

func (r record) csv() []string {
	queue := ""
	if r.QueueID != nil {
		queue = strconv.Itoa(*r.QueueID)
	}
	u := strconv.FormatUint
	f := func(v float64) string { return strconv.FormatFloat(v, 'f', 6, 64) }
	return []string{
		strconv.Itoa(r.SchemaVersion), r.RecordType, r.TimestampUTC, f(r.Elapsed), r.State,
		strconv.FormatBool(r.Transmits), queue,
		u(r.TXPackets, 10), u(r.TXBytes, 10), u(r.TXUDP, 10), u(r.TXTCP, 10), u(r.TXOther, 10), u(r.TXErrors, 10),
		f(r.TXPPS), f(r.TXL1BPS), f(r.TXL2BPS),
		u(r.RXPackets, 10), u(r.RXBytes, 10), u(r.RXUDP, 10), u(r.RXTCP, 10), u(r.RXOther, 10), u(r.RXDrops, 10),
		f(r.RXPPS), f(r.RXL1BPS), f(r.RXL2BPS),
		strconv.Itoa(r.KernelQueues), u(r.KernelRXDescriptors, 10), u(r.KernelTXDescriptors, 10), u(r.RXDropped, 10),
		u(r.RXRingFull, 10), u(r.RXFillRingEmpty, 10), u(r.RXInvalidDescs, 10), u(r.TXInvalidDescs, 10), u(r.TXRingEmpty, 10),
	}
}
