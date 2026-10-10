package sensors

import (
	"encoding/binary"
	"testing"
)

// buildFanEvent encodes one fanotify event as the kernel does for a group
// with FAN_REPORT_DFID_NAME.
func buildFanEvent(mask uint64, pid int32, infoType byte, fsid [8]byte, htype int32, handle []byte, name string) []byte {
	ne := binary.NativeEndian
	rec := make([]byte, fanInfoHeaderLen+fanFsidLen+fanHandleHdrLen, 64)
	rec[0] = infoType
	copy(rec[fanInfoHeaderLen:], fsid[:])
	ne.PutUint32(rec[fanInfoHeaderLen+fanFsidLen:], uint32(len(handle)))
	ne.PutUint32(rec[fanInfoHeaderLen+fanFsidLen+4:], uint32(htype))
	rec = append(rec, handle...)
	if infoType == fanInfoTypeDFIDName {
		rec = append(rec, name...)
		rec = append(rec, 0)
	}
	for len(rec)%4 != 0 {
		rec = append(rec, 0)
	}
	ne.PutUint16(rec[2:4], uint16(len(rec)))

	meta := make([]byte, fanMetadataLen)
	ne.PutUint32(meta[0:4], uint32(fanMetadataLen+len(rec)))
	meta[4] = fanMetadataVersion
	ne.PutUint16(meta[6:8], fanMetadataLen)
	ne.PutUint64(meta[8:16], mask)
	ne.PutUint32(meta[16:20], ^uint32(0)) // FAN_NOFD
	ne.PutUint32(meta[20:24], uint32(pid))
	return append(meta, rec...)
}

func TestParseFanotifyEvents(t *testing.T) {
	fsid := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	h1 := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	h2 := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	buf := buildFanEvent(fanMovedTo, 4242, fanInfoTypeDFIDName, fsid, 1, h1, "ld.so.preload")
	buf = append(buf, buildFanEvent(fanCreate|fanCloseWrite, 7, fanInfoTypeDFIDName, fsid, 0x81, h2, "libx.so.1")...)
	buf = append(buf, buildFanEvent(fanCreate|fanOnDir, 9, fanInfoTypeDFID, fsid, 1, h1, "")...)

	recs, err := parseFanotifyEvents(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	r := recs[0]
	if r.Mask != fanMovedTo || r.Pid != 4242 || !r.HasDir || r.Fsid != fsid || r.HandleType != 1 ||
		string(r.Handle) != string(h1) || r.Name != "ld.so.preload" {
		t.Errorf("record 0 = %+v", r)
	}
	r = recs[1]
	if r.Mask != fanCreate|fanCloseWrite || r.Pid != 7 || r.HandleType != 0x81 ||
		string(r.Handle) != string(h2) || r.Name != "libx.so.1" {
		t.Errorf("record 1 = %+v", r)
	}
	r = recs[2]
	if !r.HasDir || r.Name != "" || r.Mask&fanOnDir == 0 {
		t.Errorf("record 2 (DFID without name) = %+v", r)
	}
}

func TestParseFanotifyEventsRejectsMalformed(t *testing.T) {
	fsid := [8]byte{}
	good := buildFanEvent(fanDelete, 1, fanInfoTypeDFIDName, fsid, 1, []byte{1, 2, 3, 4}, "x.so")

	if _, err := parseFanotifyEvents(good[:fanMetadataLen-1]); err == nil {
		t.Error("short header accepted")
	}

	badVers := append([]byte(nil), good...)
	badVers[4] = 2
	if _, err := parseFanotifyEvents(badVers); err == nil {
		t.Error("wrong metadata version accepted")
	}

	// event_len past the end of the buffer
	if _, err := parseFanotifyEvents(good[:len(good)-4]); err == nil {
		t.Error("truncated event accepted")
	}

	// handle_bytes larger than the record
	overrun := append([]byte(nil), good...)
	binary.NativeEndian.PutUint32(overrun[fanMetadataLen+fanInfoHeaderLen+fanFsidLen:], 4096)
	if _, err := parseFanotifyEvents(overrun); err == nil {
		t.Error("file handle overrunning its record accepted")
	}

	// Every prefix must parse or fail cleanly, never panic.
	for n := 0; n <= len(good); n++ {
		parseFanotifyEvents(good[:n])
	}
}

func TestFileOp(t *testing.T) {
	tests := []struct {
		mask   uint64
		exists bool
		want   string
	}{
		{fanCloseWrite, true, "write"},
		{fanCreate, true, "create"},
		{fanCreate | fanCloseWrite, true, "create"},
		{fanMovedTo, true, "rename"},
		{fanDelete, false, "delete"},
		{fanDelete, true, "delete"}, // deleted, then recreated by an event not yet read
		{fanDelete | fanCreate, true, "create"},
		{fanDelete | fanCreate, false, "delete"},
		{fanDelete | fanMovedTo, true, "rename"},
		{fanDelete | fanMovedTo, false, "delete"},
	}
	for _, tt := range tests {
		if got := fileOp(tt.mask, tt.exists); got != tt.want {
			t.Errorf("fileOp(%#x, %v) = %q, want %q", tt.mask, tt.exists, got, tt.want)
		}
	}
}

func TestFileBaseline(t *testing.T) {
	b := newFileBaseline()
	b.setIfAbsent("/etc/ld.so.preload", "sha256:a")
	if old := b.swap("/etc/ld.so.preload", "sha256:b"); old != "sha256:a" {
		t.Errorf("first change OldHash = %q, want the baseline", old)
	}
	// A late startup hash must not overwrite what an event recorded.
	b.setIfAbsent("/etc/ld.so.preload", "sha256:stale")
	if old := b.swap("/etc/ld.so.preload", ""); old != "sha256:b" {
		t.Errorf("OldHash after a change = %q, want sha256:b", old)
	}
	if old := b.swap("/etc/ld.so.preload", "sha256:c"); old != "" {
		t.Errorf("OldHash after delete = %q, want empty", old)
	}
	b.setIfAbsent("/x", "")
	if b.len() != 1 {
		t.Errorf("baseline holds %d paths, want 1", b.len())
	}
}
