package sensors

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

// Parsing of fanotify events from a group created with FAN_REPORT_DFID_NAME,
// kept free of syscalls so it can be unit tested on any OS. The constants
// mirror include/uapi/linux/fanotify.h.
const (
	fanCloseWrite = 0x8
	fanMovedTo    = 0x80
	fanCreate     = 0x100
	fanDelete     = 0x200
	fanQOverflow  = 0x4000
	fanOnDir      = 0x40000000

	fanMetadataVersion = 3
	fanMetadataLen     = 24 // struct fanotify_event_metadata

	fanInfoTypeFID      = 1
	fanInfoTypeDFIDName = 2
	fanInfoTypeDFID     = 3

	fanInfoHeaderLen = 4 // struct fanotify_event_info_header
	fanFsidLen       = 8 // __kernel_fsid_t
	fanHandleHdrLen  = 8 // struct file_handle without f_handle
)

// fanRecord is one fanotify event: the mask, the PID of the process that
// caused it, and the directory (as a file handle) and entry name it concerns.
type fanRecord struct {
	Mask       uint64
	Pid        int32
	HasDir     bool    // a DFID or DFID_NAME info record was present
	Fsid       [8]byte // filesystem of the directory
	HandleType int32
	Handle     []byte // f_handle bytes of the directory
	Name       string // entry name within the directory; "" without DFID_NAME
}

// parseFanotifyEvents decodes a buffer returned by read(2) on a fanotify
// group. Each event is struct fanotify_event_metadata followed by info
// records; with FAN_REPORT_DFID_NAME the record of interest is
// FAN_EVENT_INFO_TYPE_DFID_NAME: fsid, struct file_handle, then the
// NUL-terminated entry name, padded to the record length.
func parseFanotifyEvents(buf []byte) ([]fanRecord, error) {
	ne := binary.NativeEndian
	var out []fanRecord
	for off := 0; off < len(buf); {
		if len(buf)-off < fanMetadataLen {
			return out, fmt.Errorf("short event header at offset %d", off)
		}
		ev := buf[off:]
		eventLen := int(ne.Uint32(ev[0:4]))
		vers := ev[4]
		metaLen := int(ne.Uint16(ev[6:8]))
		if vers != fanMetadataVersion {
			return out, fmt.Errorf("fanotify metadata version %d, want %d", vers, fanMetadataVersion)
		}
		if eventLen < fanMetadataLen || eventLen > len(ev) || metaLen < fanMetadataLen || metaLen > eventLen {
			return out, fmt.Errorf("bad event length %d (metadata %d) at offset %d", eventLen, metaLen, off)
		}
		rec := fanRecord{
			Mask: ne.Uint64(ev[8:16]),
			Pid:  int32(ne.Uint32(ev[20:24])),
		}
		for info := ev[metaLen:eventLen]; len(info) >= fanInfoHeaderLen; {
			infoType := info[0]
			infoLen := int(ne.Uint16(info[2:4]))
			if infoLen < fanInfoHeaderLen || infoLen > len(info) {
				return out, fmt.Errorf("bad info record length %d at offset %d", infoLen, off)
			}
			body := info[fanInfoHeaderLen:infoLen]
			switch infoType {
			case fanInfoTypeDFIDName, fanInfoTypeDFID:
				if len(body) < fanFsidLen+fanHandleHdrLen {
					return out, fmt.Errorf("short fid record at offset %d", off)
				}
				copy(rec.Fsid[:], body[:fanFsidLen])
				fh := body[fanFsidLen:]
				hlen := int(ne.Uint32(fh[0:4]))
				if fanHandleHdrLen+hlen > len(fh) {
					return out, fmt.Errorf("file handle length %d overruns record at offset %d", hlen, off)
				}
				rec.HandleType = int32(ne.Uint32(fh[4:8]))
				rec.Handle = append([]byte(nil), fh[fanHandleHdrLen:fanHandleHdrLen+hlen]...)
				rec.HasDir = true
				if infoType == fanInfoTypeDFIDName {
					name := fh[fanHandleHdrLen+hlen:]
					if i := bytes.IndexByte(name, 0); i >= 0 {
						name = name[:i]
					}
					rec.Name = string(name)
				}
			}
			info = info[infoLen:]
		}
		out = append(out, rec)
		off += eventLen
	}
	return out, nil
}

// fileOp names what happened to a directory entry. fanotify merges queued
// events for the same entry from the same process, so a mask can carry
// several bits; exists says whether the entry exists now.
func fileOp(mask uint64, exists bool) string {
	if mask&fanDelete != 0 && (!exists || mask&(fanCreate|fanMovedTo) == 0) {
		return "delete"
	}
	if mask&fanMovedTo != 0 {
		return "rename"
	}
	if mask&fanCreate != 0 {
		return "create"
	}
	return "write"
}

// fileBaseline holds the last known content hash of each watched file. It is
// filled at sensor start and updated on every event, so an event's OldHash is
// the hash recorded before this change.
type fileBaseline struct {
	mu     sync.Mutex
	hashes map[string]string
}

func newFileBaseline() *fileBaseline {
	return &fileBaseline{hashes: make(map[string]string)}
}

// setIfAbsent records a startup hash unless an event already recorded a newer
// one for the path.
func (b *fileBaseline) setIfAbsent(path, hash string) {
	if hash == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.hashes[path]; !ok {
		b.hashes[path] = hash
	}
}

// swap records newHash for path ("" forgets the path) and returns the hash
// it replaces, or "" if none was known.
func (b *fileBaseline) swap(path, newHash string) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	old := b.hashes[path]
	if newHash == "" {
		delete(b.hashes, path)
	} else {
		b.hashes[path] = newHash
	}
	return old
}

func (b *fileBaseline) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.hashes)
}
