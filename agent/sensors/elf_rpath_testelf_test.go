package sensors

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"
)

// rpathWWriteELF writes a minimal 64-bit ELF file at path whose dynamic
// section has DT_RUNPATH runpath: just enough for debug/elf to read it, so
// tests need no C compiler. It cannot be executed.
func rpathWWriteELF(t *testing.T, path, runpath string) {
	t.Helper()
	le := binary.LittleEndian
	align8 := func(b *bytes.Buffer) {
		for b.Len()%8 != 0 {
			b.WriteByte(0)
		}
	}

	var body bytes.Buffer
	body.Write(make([]byte, 64)) // ELF header, filled in below

	dynstrOff := body.Len()
	dynstr := "\x00" + runpath + "\x00"
	body.WriteString(dynstr)
	align8(&body)

	dynOff := body.Len()
	for _, d := range [][2]uint64{
		{uint64(elf.DT_RUNPATH), 1}, // offset of runpath in .dynstr
		{uint64(elf.DT_STRTAB), 0},
		{uint64(elf.DT_NULL), 0},
	} {
		binary.Write(&body, le, d)
	}
	dynSize := body.Len() - dynOff

	shstrOff := body.Len()
	shstr := "\x00.dynstr\x00.dynamic\x00.shstrtab\x00"
	body.WriteString(shstr)
	align8(&body)

	shOff := body.Len()
	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: uint64(dynstrOff), Size: uint64(len(dynstr)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: uint64(dynOff), Size: uint64(dynSize), Link: 1, Addralign: 8, Entsize: 16},
		{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: uint64(shstrOff), Size: uint64(len(shstr)), Addralign: 1},
	}
	for _, s := range sections {
		binary.Write(&body, le, s)
	}

	hdr := elf.Header64{
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     uint64(shOff),
		Ehsize:    64,
		Shentsize: 64,
		Shnum:     uint16(len(sections)),
		Shstrndx:  3,
	}
	copy(hdr.Ident[:], elf.ELFMAG)
	hdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	hdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	hdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	var hb bytes.Buffer
	binary.Write(&hb, le, hdr)

	out := body.Bytes()
	copy(out, hb.Bytes())
	if err := os.WriteFile(path, out, 0o755); err != nil {
		t.Fatal(err)
	}

	// The fixture must parse as intended.
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("test ELF does not parse: %v", err)
	}
	defer f.Close()
	if got, err := f.DynString(elf.DT_RUNPATH); err != nil || len(got) != 1 || got[0] != runpath {
		t.Fatalf("test ELF RUNPATH = %q, %v; want %q", got, err, runpath)
	}
}
