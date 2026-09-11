package statsexport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/wireblast/internal/stats"
)

func fixture() *stats.Snapshot {
	return &stats.Snapshot{
		At:        time.Date(2026, 8, 10, 12, 30, 0, 123, time.FixedZone("test", 2*60*60)),
		Elapsed:   1500 * time.Millisecond,
		State:     stats.StateRunning,
		Transmits: true,
		TotalTX: stats.Totals{
			Packets: 100, Bytes: 6400, UDP: 90, TCP: 5, Other: 5, Errors: 7,
		},
		TotalRX: stats.Totals{
			Packets: 80, Bytes: 5120, UDP: 70, TCP: 5, Other: 5, Drops: 11,
		},
		TXRate: stats.Rates{PPS: 99.5, FrameBPS: 50_944, WireBPS: 66_864},
		RXRate: stats.Rates{PPS: 79.5, FrameBPS: 40_704, WireBPS: 53_424},
		Kernel: stats.Kernel{
			Queues: 2, RxPackets: 80, TxPackets: 100,
			RxDropped: 3, RxRingFull: 8, RxFillRingEmpty: 9,
			RxInvalidDescs: 4, TxInvalidDescs: 7, TxRingEmpty: 6,
			PerQueue: []stats.KernelQueue{
				{Queue: 0, RxPackets: 50, TxPackets: 60, RxDropped: 1, RxRingFull: 2,
					RxFillRingEmpty: 3, RxInvalidDescs: 4, TxInvalidDescs: 5, TxRingEmpty: 6},
				{Queue: 1, RxPackets: 30, TxPackets: 40, RxDropped: 2, RxRingFull: 6},
			},
		},
	}
}

func TestCSVWritesStableAggregateAndQueueRecords(t *testing.T) {
	var out bytes.Buffer
	w, err := New(FormatCSV, &out)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Sample(fixture()); err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if err := w.Final(fixture()); err != nil {
		t.Fatalf("Final: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v\n%s", err, out.String())
	}
	if len(rows) != 5 {
		t.Fatalf("rows = %d, want header + sample + final + 2 queues", len(rows))
	}
	header := index(rows[0])
	assertCSV(t, header, rows[1], "record_type", "sample")
	assertCSV(t, header, rows[1], "timestamp_utc", "2026-08-10T10:30:00.000000123Z")
	assertCSV(t, header, rows[1], "elapsed_seconds", "1.500000")
	assertCSV(t, header, rows[1], "tx_packets", "100")
	assertCSV(t, header, rows[1], "tx_l1_bps", "66864.000000")
	assertCSV(t, header, rows[1], "rx_dropped", "3")
	assertCSV(t, header, rows[1], "rx_fill_ring_empty_descs", "9")
	assertCSV(t, header, rows[1], "tx_ring_empty_descs", "6")
	assertCSV(t, header, rows[2], "record_type", "final")
	assertCSV(t, header, rows[3], "record_type", "queue_final")
	assertCSV(t, header, rows[3], "queue_id", "0")
	assertCSV(t, header, rows[3], "rx_fill_ring_empty_descs", "3")
	assertCSV(t, header, rows[3], "rx_invalid_descs", "4")
	assertCSV(t, header, rows[3], "tx_invalid_descs", "5")
	assertCSV(t, header, rows[3], "tx_ring_empty_descs", "6")
	assertCSV(t, header, rows[4], "queue_id", "1")
}

func TestSchemaNamesRingProgressAsDescriptors(t *testing.T) {
	var out bytes.Buffer
	w, err := New(FormatCSV, &out)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Final(fixture()); err != nil {
		t.Fatalf("Final: %v", err)
	}

	rows, err := csv.NewReader(strings.NewReader(out.String())).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	header := index(rows[0])
	for _, name := range []string{"kernel_rx_descriptors", "kernel_tx_descriptors"} {
		if _, ok := header[name]; !ok {
			t.Errorf("CSV header is missing descriptor field %q", name)
		}
	}
	for _, old := range []string{"kernel_rx_packets", "kernel_tx_packets"} {
		if _, ok := header[old]; ok {
			t.Errorf("CSV header still calls ring descriptors packets: %q", old)
		}
	}
	assertCSV(t, header, rows[1], "kernel_rx_descriptors", "80")
	assertCSV(t, header, rows[1], "kernel_tx_descriptors", "100")
	assertCSV(t, header, rows[2], "kernel_rx_descriptors", "50")
	assertCSV(t, header, rows[2], "kernel_tx_descriptors", "60")
}

func TestJSONLWritesTheSameVersionedSchema(t *testing.T) {
	var out bytes.Buffer
	w, err := New(FormatJSONL, &out)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Sample(fixture()); err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if err := w.Final(fixture()); err != nil {
		t.Fatalf("Final: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dec := json.NewDecoder(&out)
	var records []map[string]any
	for {
		var record map[string]any
		if err := dec.Decode(&record); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		records = append(records, record)
	}
	if len(records) != 4 {
		t.Fatalf("records = %d, want sample + final + 2 queues", len(records))
	}
	if got := records[0]["schema_version"]; got != float64(SchemaVersion) {
		t.Errorf("schema_version = %v, want %d", got, SchemaVersion)
	}
	if got := records[0]["record_type"]; got != "sample" {
		t.Errorf("record_type = %v, want sample", got)
	}
	if got := records[0]["rx_invalid_descs"]; got != float64(4) {
		t.Errorf("rx_invalid_descs = %v, want 4", got)
	}
	if got := records[0]["rx_fill_ring_empty_descs"]; got != float64(9) {
		t.Errorf("rx_fill_ring_empty_descs = %v, want 9", got)
	}
	if got := records[0]["tx_ring_empty_descs"]; got != float64(6) {
		t.Errorf("tx_ring_empty_descs = %v, want 6", got)
	}
	if _, ok := records[0]["rx_fill_ring_empty"]; ok {
		t.Error("JSONL record must use the exact rx_fill_ring_empty_descs UAPI name")
	}
	if _, ok := records[0]["tx_ring_empty"]; ok {
		t.Error("JSONL record must use the exact tx_ring_empty_descs UAPI name")
	}
	if got := records[0]["kernel_rx_descriptors"]; got != float64(80) {
		t.Errorf("kernel_rx_descriptors = %v, want 80", got)
	}
	if _, ok := records[0]["kernel_rx_packets"]; ok {
		t.Error("JSONL record must not call ring descriptors packets")
	}
	if _, ok := records[0]["kernel_tx_packets"]; ok {
		t.Error("JSONL record must not call ring descriptors packets")
	}
	if _, ok := records[0]["queue_id"]; ok {
		t.Error("aggregate JSON record should omit queue_id")
	}
	if got := records[2]["queue_id"]; got != float64(0) {
		t.Errorf("first queue_id = %v, want 0", got)
	}
}

func TestNewRejectsUnknownFormat(t *testing.T) {
	if _, err := New(Format("xml"), io.Discard); err == nil {
		t.Fatal("New(xml) should fail")
	}
}

func TestNewReportsCSVHeaderWriteFailure(t *testing.T) {
	if _, err := New(FormatCSV, failWriter{}); err == nil {
		t.Fatal("New(csv) should report a header write failure")
	}
}

func TestJSONLReportsRecordWriteFailure(t *testing.T) {
	w, err := New(FormatJSONL, failWriter{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := w.Sample(fixture()); err == nil {
		t.Fatal("Sample should report a record write failure")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) {
	return 0, errors.New("disk full")
}

func index(header []string) map[string]int {
	out := make(map[string]int, len(header))
	for i, name := range header {
		out[name] = i
	}
	return out
}

func assertCSV(t *testing.T, header map[string]int, row []string, field, want string) {
	t.Helper()
	i, ok := header[field]
	if !ok {
		t.Fatalf("missing CSV field %q", field)
	}
	if i >= len(row) {
		t.Fatalf("row has %d columns, field %q needs column %d", len(row), field, i)
	}
	if got := row[i]; got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}
