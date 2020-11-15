package interp

import (
	"fmt"
	"github.com/cilium/ebpf/asm"
	"testing"
)

func TestLoadStoreFuns(t *testing.T) {
	m := NewMachine(make(asm.Instructions, 0))
	w := uint64(0x11223344_55667788)

	m.store(0, w, asm.DWord)
	if l := m.load(0, asm.DWord); l != w {
		t.Errorf("expected %x, got %x", w, l)
	}
	if l := m.load(0, asm.Word); l != w&0xFFFFFFFF {
		t.Errorf("expected %x, got %x", w&0xFFFFFFFF, l)
	}
	if l := m.load(4, asm.Word); l != w>>32 {
		t.Errorf("expected %x, got %x", w>>32, l)
	}
	if l := m.load(0, asm.Half); l != w&0xFFFF {
		t.Errorf("expected %x, got %x", w&0xFFFF, l)
	}
	if l := m.load(0, asm.Byte); l != w&0xFF {
		t.Errorf("expected %x, got %x", w&0xFF, l)
	}

	// FIXME: don't assume little endian.
	m.store(0, 0xEF, asm.Byte)
	m.store(1, 0xCD, asm.Byte)
	m.store(2, 0x89AB, asm.Half)
	m.store(4, 0x0123_4567, asm.Word)

	w = 0x01234567_89ABCDEF
	if l := m.load(0, asm.DWord); l != w {
		t.Errorf("expected %x, got %x", w, l)
	}
}

func TestLoadImm(t *testing.T) {
	instrs := []asm.Instruction{
		asm.LoadImm(asm.R0, 0xAB, asm.Byte),
		asm.LoadImm(asm.R1, 0xABCD, asm.Half),
		asm.LoadImm(asm.R2, 0x0123_ABCD, asm.Word),
		asm.LoadImm(asm.R3, 0x0123_4567_89AB_CDEF, asm.DWord),
		asm.Return(),
	}
	m := NewMachine(instrs)
	m.Run(0)

	if m.registers[asm.R0] != 0xAB {
		t.Errorf("LoadImm8 fail")
	}
	if m.registers[asm.R1] != 0xABCD {
		t.Errorf("LoadImm16 fail")
	}
	if m.registers[asm.R2] != 0x0123_ABCD {
		t.Errorf("LoadImm32 fail")
	}
	if m.registers[asm.R3] != 0x0123_4567_89AB_CDEF {
		t.Errorf("LoadImm64 fail")
	}
}

func TestLoadAbs(t *testing.T) {
	instrs := []asm.Instruction{
		asm.LoadAbs(4, asm.DWord),
		asm.Return(),
	}
	m := NewMachine(instrs)
	m.StoreWord(0, 0x0000_1111_2222_3333)
	m.StoreWord(8, 0xAAAA_BBBB_CCCC_DDDD)
	m.Run(0)

	// In memory (little endian):
	// 3333 2222 1111 0000 DDDD CCCC BBBB AAAA
	//           ^^^^^^^^^^^^^^^^^^^
	expected := uint64(0xCCCC_DDDD_0000_1111)

	if m.registers[asm.R0] != expected {
		t.Errorf("LoadAbs fail: expected %x, got %x", expected, m.registers[asm.R0])
	}
}

func TestALU(t *testing.T) {
	// TODO: tests aren't very principled. Neg not tested properly. Swap missing.
	// Sign extend of ArSh not tested.
	instrs := []asm.Instruction{
		asm.LoadImm(asm.R0, 0xfefefefc, asm.DWord),
		asm.LoadImm(asm.R1, 0xc0c0c0c1, asm.DWord),
		asm.Add.Reg(asm.R0, asm.R1),
		asm.Sub.Imm(asm.R0, 0xc0c0),
		asm.LoadImm(asm.R2, 2, asm.DWord),
		asm.Mul.Reg(asm.R0, asm.R2),
		asm.Div.Imm(asm.R0, 4),
		asm.RSh.Imm(asm.R0, 3),
		asm.LSh.Imm(asm.R0, 2),
		asm.Neg.Imm(asm.R0, 0),
		asm.Neg.Imm(asm.R0, 0),
		asm.Mod.Imm(asm.R0, 0xfefefe),
		asm.Mov.Reg(asm.R1, asm.R0),
		asm.ArSh.Imm(asm.R1, 2),
		asm.And.Imm(asm.R1, 0xababab),
		asm.Xor.Imm(asm.R1, 0x3f3f3f),
		asm.Or.Imm(asm.R1, 0xff0000),
		asm.Return(),
	}
	m := NewMachine(instrs)
	m.Run(0)

	var expected uint64 = (((((((((0xfefefefc + 0xc0c0c0c1 - 0xc0c0) * 2) / 4) >> 3) << 2) % 0xfefefe) >> 2) & 0xababab) ^ 0x3f3f3f) | 0xff0000

	if m.registers[asm.R1] != expected {
		t.Errorf("TestALU fail: expected %x, got %x", expected, m.registers[asm.R0])
	}
}

func TestJump(t *testing.T) {
	// TODO not complete
	instrs := []asm.Instruction{
		asm.Ja.Label("skip"),
		asm.Return(),
		asm.Instruction{}.Sym("skip"),
		asm.LoadImm(asm.R1, 5, asm.DWord),

		asm.JEq.Imm(asm.R1, 5, "jeq"),
		asm.Return(),
		asm.Instruction{}.Sym("jeq"),

		asm.JGT.Imm(asm.R1, 4, "jgt"),
		asm.Return(),
		asm.Instruction{}.Sym("jgt"),

		asm.JGE.Imm(asm.R1, 5, "jge"),
		asm.Return(),
		asm.Instruction{}.Sym("jge"),

		asm.JSet.Imm(asm.R1, 0xff, "jset"),
		asm.Return(),
		asm.Instruction{}.Sym("jset"),

		asm.JNE.Imm(asm.R1, 3, "jne"),
		asm.Return(),
		asm.Instruction{}.Sym("jne"),

		asm.JSGT.Imm(asm.R1, -3, "jsgt"),
		asm.Return(),
		asm.Instruction{}.Sym("jsgt"),

		asm.JSGE.Imm(asm.R1, -3, "jsge"),
		asm.Return(),
		asm.Instruction{}.Sym("jsge"),

		asm.LoadImm(asm.R0, 0x1234, asm.DWord),
		asm.Return(),
	}
	fixupJumps(instrs)
	m := NewMachine(instrs)
	m.Run(0)

	if m.registers[asm.R0] != 0x1234 {
		t.Errorf("TestJump failed")
	}
}

func fixupJumps(insns asm.Instructions) error {
	// adapted from ebpf/linker.go.
	symbolOffsets := make(map[string]asm.RawInstructionOffset)
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins

		if ins.Symbol == "" {
			continue
		}

		if _, ok := symbolOffsets[ins.Symbol]; ok {
			return fmt.Errorf("duplicate symbol %s", ins.Symbol)
		}

		symbolOffsets[ins.Symbol] = iter.Offset
	}

	iter = insns.Iterate()
	for iter.Next() {
		i := iter.Index
		offset := iter.Offset
		ins := iter.Ins

		switch {
		case ins.OpCode.Class() == asm.JumpClass && ins.Offset == -1:
			// Rewrite jump to label
			jumpOffset, ok := symbolOffsets[ins.Reference]
			if !ok {
				return fmt.Errorf("instruction %d: reference to missing symbol %s", i, ins.Reference)
			}

			ins.Offset = int16(jumpOffset - offset - 1)
		}
	}

	return nil
}
