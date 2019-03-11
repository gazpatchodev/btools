package tx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	"bitbucket.org/simon_ordish/cryptolib"
)

const (
	// 0x01-0x4b = The next opcode bytes is data to be pushed onto the stack
	opPUSHDATA1   byte = 0x4c // The next byte contains the number of bytes to be pushed onto the stack.
	opPUSHDATA2   byte = 0x4d // The next two bytes contain the number of bytes to be pushed onto the stack in little endian order.
	opPUSHDATA4   byte = 0x4e // The next four bytes contain the number of bytes to be pushed onto the stack in little endian order.
	opRETURN      byte = 0x6a
	opDUP         byte = 0x76
	opEQUALVERIFY byte = 0x88
	opHASH160     byte = 0xa9
	opCHECKSIG    byte = 0xac
)

// Input holds all input data
type Input struct {
	PrevOutput [32]byte
	Index      uint32
	amount     uint64
	Script     []byte
}

func (in *Input) dumpHex(w io.Writer) {
	var sequence uint32 = 0xffffffff

	binary.Write(w, binary.LittleEndian, in.PrevOutput)
	binary.Write(w, binary.LittleEndian, in.Index)
	binary.Write(w, binary.LittleEndian, cryptolib.VarInt(len(in.Script)))
	binary.Write(w, binary.LittleEndian, in.Script)
	binary.Write(w, binary.LittleEndian, sequence)
}

// An Output contains the reward and the script.
type Output struct {
	Amount uint64
	Script []byte
}

func (out *Output) dumpHex(w io.Writer) {
	binary.Write(w, binary.LittleEndian, out.Amount)
	binary.Write(w, binary.LittleEndian, cryptolib.VarInt(len(out.Script)))
	binary.Write(w, binary.LittleEndian, out.Script)
}

// A Stack holds an arbitary length of bytes prefixed by the appropriate PUSH command.
type Stack struct {
	Data []byte
}

// NewStack returns an empty stack
func NewStack() *Stack {
	return &Stack{}
}

func (st *Stack) pushData(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("Cannot push zero-length data")
	}

	var push []byte

	l := len(data)
	if l <= 0x4b { // 75 bytes
		push = append(push, byte(l))
	} else if l <= 0xFF {
		push = append(push, opPUSHDATA1)
		push = append(push, byte(l))
	} else if l <= 0xFFFF {
		push = append(push, opPUSHDATA2) // 2 bytes for size - little endian
		lenBytes := make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBytes, uint16(l))
		push = append(push, lenBytes...)
	} else {
		push = append(push, opPUSHDATA4) // 4 bytes for size - little endian
		lenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(l))
		push = append(push, lenBytes...)
	}

	push = append(push, data...)

	st.Data = append(st.Data, push...)

	return nil
}

// A Transaction has a slice of Inputs and a slice of Outputs
type Transaction struct {
	ins  []Input
	outs []Output
}

// New creates a new Transaction instance
func New() *Transaction {
	return &Transaction{}
}

func (tx *Transaction) addInput(utxo []byte, index uint32, amount uint64, script []byte) error {
	i := Input{
		Index:  index,
		amount: amount,
	}
	copy(i.PrevOutput[:], utxo)
	i.Script = script

	tx.ins = append(tx.ins, i)

	return nil
}

func (tx *Transaction) addOutput(satoshis uint64, destination string) error {

	script, _ := cryptolib.AddressToScript(destination)
	o := Output{
		Amount: satoshis,
		Script: script,
	}
	tx.outs = append(tx.outs, o)

	return nil
}

func (tx *Transaction) addOPReturn(data []byte) error {
	o := Output{
		Amount: 0,
		Script: []byte{opRETURN},
	}
	o.Script = append(o.Script, data...)

	tx.outs = append(tx.outs, o)

	return nil
}

func (tx *Transaction) getHash() string {
	b := tx.toHex()
	b = append(b, []byte{0x01, 0x00, 0x00, 0x00}...) // SIGHASH_ALL = 0x01000000
	h := cryptolib.Sha256d(b)

	return hex.EncodeToString(cryptolib.ReverseBytes(h))
}

func (tx *Transaction) toHex() []byte {
	var buffer bytes.Buffer
	w := bufio.NewWriter(&buffer)

	var version uint32 = 1
	binary.Write(w, binary.LittleEndian, version)

	binary.Write(w, binary.LittleEndian, cryptolib.VarInt(len(tx.ins)))
	for _, in := range tx.ins {
		in.dumpHex(w)
	}

	binary.Write(w, binary.LittleEndian, cryptolib.VarInt(len(tx.outs)))
	for _, out := range tx.outs {
		out.dumpHex(w)
	}

	var lockTime uint32 // 0x00
	binary.Write(w, binary.LittleEndian, lockTime)

	w.Flush()

	return buffer.Bytes()
}
