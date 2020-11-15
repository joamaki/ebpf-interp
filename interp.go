package interp

// A toy user-space eBPF interpreter

import (
	"fmt"
	"github.com/cilium/ebpf/asm"
	"time"
	"unsafe"
)

const MemorySize = 8 * 1024 * 1024

type Machine struct {
	instructions []asm.Instruction
	memory       [MemorySize]byte
	stopped      bool
	pc           uint64
	registers    [11]uint64
}

func (m *Machine) String() string {
	return fmt.Sprintf(
		"PC=%d [ %v ]\n"+
			"R0=%016x R1=%016x R2=%016x R3=%016x R4=%016x\n"+
			"R5=%016x R6=%016x R7=%016x R8=%016x R9=%016x\n"+
			"R10=%016x\n",
		m.pc, m.instructions[m.pc], m.registers[asm.R0], m.registers[asm.R1], m.registers[asm.R2],
		m.registers[asm.R3], m.registers[asm.R4], m.registers[asm.R5],
		m.registers[asm.R6], m.registers[asm.R7], m.registers[asm.R8],
		m.registers[asm.R9], m.registers[asm.R10])
}

func NewMachine(instructions asm.Instructions) *Machine {
	m := &Machine{
		instructions: instructions,
	}
	m.registers[asm.RFP] = MemorySize
	return m
}

func (m *Machine) SetMemory(ptr uint64, data []byte) {
	copy(m.memory[ptr:], data)
}

func (m *Machine) Run(arg int64, debug bool) int64 {
	m.registers[asm.R1] = uint64(arg)
	for !m.stopped {
		if debug {
			fmt.Print(m)
		}
		m.Step()
	}
	return int64(m.registers[asm.R0])
}

func (m *Machine) Step() {
	instr := m.instructions[m.pc]
	m.pc++

	op := instr.OpCode
	switch op.Class() {
	case asm.LdClass, asm.LdXClass:
		switch op.Mode() {
		case asm.ImmMode:
			m.registers[instr.Dst] = uint64(instr.Constant)

		case asm.AbsMode:
			m.registers[instr.Dst] =
				m.load(int64(m.registers[asm.R6])+instr.Constant, op.Size())

		case asm.IndMode:
			m.registers[instr.Dst] =
				m.load(int64(m.registers[asm.R6])+int64(m.registers[instr.Src])+instr.Constant, op.Size())

		case asm.MemMode:
			m.registers[instr.Dst] =
				m.load(int64(m.registers[instr.Src])+int64(instr.Offset), op.Size())

		default:
			panic("bad load mode")

		}
	case asm.StClass, asm.StXClass:
		switch op.Mode() {
		case asm.ImmMode:
			m.store(int64(m.registers[instr.Dst])+int64(instr.Offset), uint64(instr.Constant), op.Size())
		case asm.MemMode:
			m.store(int64(m.registers[instr.Dst])+int64(instr.Offset), uint64(m.registers[instr.Src]), op.Size())
		case asm.XAddMode:
			m.store(
				int64(m.registers[instr.Dst]),
				m.registers[instr.Src]+m.load(int64(m.registers[instr.Dst]), op.Size()),
				op.Size())

		default:
			panic("bad store mode")
		}

	case asm.ALUClass, asm.ALU64Class:
		if op.ALUOp() == asm.Swap {
			m.swap(&instr)
		} else {
			m.alu(&instr)
		}

	case asm.JumpClass:
		var doJump = false
		sourceValue := m.sourceValue(&instr)
		dst := m.registers[instr.Dst]
		switch op.JumpOp() {
		case asm.Ja:
			doJump = true
		case asm.JEq:
			doJump = dst == sourceValue
		case asm.JGT:
			doJump = dst > sourceValue
		case asm.JGE:
			doJump = dst >= sourceValue
		case asm.JSet:
			doJump = (dst & sourceValue) != 0
		case asm.JNE:
			doJump = dst != sourceValue
		case asm.JSGT:
			doJump = int64(dst) > m.sourceValueSigned(&instr)
		case asm.JSGE:
			doJump = int64(dst) >= m.sourceValueSigned(&instr)
		case asm.JLT:
			doJump = dst < sourceValue
		case asm.JLE:
			doJump = dst <= sourceValue
		case asm.JSLT:
			doJump = int64(dst) < m.sourceValueSigned(&instr)
		case asm.JSLE:
			doJump = int64(dst) <= m.sourceValueSigned(&instr)
		case asm.Call:
			m.call(asm.BuiltinFunc(instr.Constant))
		case asm.Exit:
			m.stopped = true
		}
		if doJump {
			m.pc += uint64(instr.Offset)
		}
	}
}

func (m *Machine) swap(instr *asm.Instruction) {
	v := m.registers[instr.Dst]
	switch instr.Constant {
	case 16:
		m.registers[instr.Dst] = uint64((uint16(v) & 0x00FF << 8) | (uint16(v)&0xFF00)>>8)
	case 32:
		m.registers[instr.Dst] = uint64((uint32(v) & 0x000000FF << 24) | (uint32(v)&0x0000FF00)<<8 | (uint32(v)&0x00FF0000)>>8 | (uint32(v)&0xFF000000)>>24)
	case 64:
		panic("TODO Swap 64")
	default:
		panic("bad endian")
	}

}

func (m *Machine) alu(instr *asm.Instruction) {
	op := instr.OpCode
	value := m.sourceValue(instr)
	if op.Class() == asm.ALUClass {
		// FIXME test that all 32bit ops work correctly.
		value &= 0x00000000FFFFFFFF
	}
	switch op.ALUOp() {
	case asm.Add:
		m.registers[instr.Dst] += value
	case asm.Sub:
		m.registers[instr.Dst] -= value
	case asm.Mul:
		m.registers[instr.Dst] *= value
	case asm.Div:
		m.registers[instr.Dst] /= value
	case asm.Or:
		m.registers[instr.Dst] |= value
	case asm.And:
		m.registers[instr.Dst] &= value
	case asm.LSh:
		m.registers[instr.Dst] <<= value
	case asm.RSh:
		m.registers[instr.Dst] >>= value
	case asm.Neg:
		m.registers[instr.Dst] = -m.registers[instr.Dst]
	case asm.Mod:
		m.registers[instr.Dst] %= value
	case asm.Xor:
		m.registers[instr.Dst] ^= value
	case asm.Mov:
		m.registers[instr.Dst] = value
	case asm.ArSh:
		m.registers[instr.Dst] = uint64(int64(m.registers[instr.Dst]) >> value)
	default:
		panic("unhandled ALUOp: " + op.ALUOp().String())
	}
	if op.Class() == asm.ALUClass {
		m.registers[instr.Dst] &= 0x00000000FFFFFFFF
	}
}

func (m *Machine) call(fn asm.BuiltinFunc) {
	switch fn {
	case asm.FnKtimeGetNs:
		m.registers[asm.R0] = uint64(time.Now().UnixNano())
	case asm.FnTracePrintk:
		start := m.registers[asm.R1]
		length := m.registers[asm.R2]
		s := string(m.memory[start : start+length])
		fmt.Printf("DEBUG: %v\n", s)
	default:
		panic("unhandled builtin: " + fn.String())
	}
}

func (m *Machine) sourceValue(instr *asm.Instruction) uint64 {
	switch instr.OpCode.Source() {
	case asm.RegSource:
		return m.registers[instr.Src]
	case asm.ImmSource:
		return uint64(instr.Constant)
	default:
		panic(fmt.Sprintf("bad Source: %v", instr.OpCode.Source()))
	}
}

func (m *Machine) sourceValueSigned(instr *asm.Instruction) int64 {
	switch instr.OpCode.Source() {
	case asm.RegSource:
		return int64(m.registers[instr.Src])
	case asm.ImmSource:
		return int64(instr.Constant)
	default:
		panic("bad Source")
	}
}

func sizeMask(size asm.Size) int64 {
	return (1 << (8 * size.Sizeof())) - 1
}

func (m *Machine) load(addr int64, size asm.Size) uint64 {
	switch size {
	case asm.Byte:
		return uint64(m.memory[addr])
	case asm.Half:
		return uint64(*(*uint16)(unsafe.Pointer(&m.memory[addr])))
	case asm.Word:
		return uint64(*(*uint32)(unsafe.Pointer(&m.memory[addr])))
	case asm.DWord:
		return *(*uint64)(unsafe.Pointer(&m.memory[addr]))
	default:
		panic("unhandled load")
	}
}

func (m *Machine) store(addr int64, value uint64, size asm.Size) {
	switch size {
	case asm.Byte:
		m.memory[addr] = byte(value)
	case asm.Half:
		*(*uint16)(unsafe.Pointer(&m.memory[addr])) = uint16(value)
	case asm.Word:
		*(*uint32)(unsafe.Pointer(&m.memory[addr])) = uint32(value)
	case asm.DWord:
		*(*uint64)(unsafe.Pointer(&m.memory[addr])) = value
	}
}

func (m *Machine) StoreWord(addr int64, value uint64) {
	*(*uint64)(unsafe.Pointer(&m.memory[addr])) = value
}
