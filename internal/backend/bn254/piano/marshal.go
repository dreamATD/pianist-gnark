// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piano

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// WriteTo writes binary encoding of Proof to w
func (proof *Proof) WriteTo(w io.Writer) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

// ReadFrom reads binary representation of Proof from r
func (proof *Proof) ReadFrom(r io.Reader) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func WriteFrArray(w io.Writer, array []fr.Element) (int64, error) {
	size := uint64(len(array))
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, size)
	fmt.Println("write size", size)
	n, err := w.Write(sizeBuf)
	if err != nil {
		return int64(n), err
	}
	buf := make([]byte, 32*size)
	for i := uint64(0); i < size; i++ {
		bytes := array[i].Bytes()
		copy(buf[i*32:(i+1)*32], bytes[:])
	}
	n, err = w.Write(buf)
	if uint64(n) != uint64(32*size) {
		return int64(n), fmt.Errorf("error writing fr array")
	}
	return int64(n), err
}
func ReadFrArray(r io.Reader) ([]fr.Element, error) {
	sizeBuf := make([]byte, 8)

	_, err := r.Read(sizeBuf)
	if err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint64(sizeBuf)
	fmt.Println("size", size)
	bytesRead := 0
	bytesConsumed := 0
	array := make([]fr.Element, size)
	//256MB buffer
	buf := make([]byte, 256*1024*1024)
	ptr := 0
	for i := uint64(0); i < size; i++ {
		if bytesConsumed == bytesRead {
			if (size*32 - uint64(bytesConsumed)) > uint64(len(buf)) {
				tmp, _ := r.Read(buf)
				if len(buf) != tmp {
					panic("not enough bytes read")
					return nil, fmt.Errorf("error reading fr array")
				}
				bytesRead += tmp
			} else {
				tmp, _ := r.Read(buf[:(32*size - uint64(bytesConsumed))])
				if (32*size - uint64(bytesConsumed)) != uint64(tmp) {
					panic("not enough bytes read")
					return nil, fmt.Errorf("error reading fr array")
				}
				bytesRead += tmp
			}
			ptr = 0
		}
		array[i].SetBytes(buf[ptr*32 : (ptr+1)*32])
		bytesConsumed += 32
		ptr += 1
	}
	buf = nil
	return array, nil
}

func WriteInt64Array(w io.Writer, array []int64) (int64, error) {
	size := uint64(len(array))
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, size)
	n, err := w.Write(sizeBuf)
	if err != nil {
		return int64(n), err
	}
	buf := make([]byte, 8*size)
	for i := uint64(0); i < size; i++ {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], uint64(array[i]))
	}
	n, err = w.Write(buf)
	return int64(n), err
}

func ReadInt64Array(r io.Reader) ([]int64, error) {
	sizeBuf := make([]byte, 8)
	_, err := r.Read(sizeBuf)
	if err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint64(sizeBuf)
	buf := make([]byte, 8*size)
	_, err = r.Read(buf)
	if err != nil {
		return nil, err
	}
	array := make([]int64, size)
	for i := uint64(0); i < size; i++ {
		array[i] = int64(binary.LittleEndian.Uint64(buf[i*8 : (i+1)*8]))
	}
	return array, nil
}

// WriteTo writes binary encoding of ProvingKey to w
func (pk *ProvingKey) WriteTo(w io.Writer) (n int64, err error) {
	//Will not write pk.Vk

	//Write Ql, Qr, Qm, Qo
	n, err = WriteFrArray(w, pk.Ql)
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.Qr)
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.Qm)
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.Qo)
	if err != nil {
		return n, err
	}

	//Write CQk, LQk
	n, err = WriteFrArray(w, pk.CQk)
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.LQk)
	if err != nil {
		return n, err
	}

	// Write Domain
	pk.Domain[0].WriteTo(w)
	pk.Domain[1].WriteTo(w)

	//Write Permutation
	n, err = WriteInt64Array(w, pk.Permutation)
	if err != nil {
		return n, err
	}

	//Write EvaluationPermutationBigDomainBitReversed
	singleSize := pk.Domain[1].Cardinality
	n, err = WriteFrArray(w, pk.EvaluationPermutationBigDomainBitReversed[0:singleSize])
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.EvaluationPermutationBigDomainBitReversed[singleSize:2*singleSize])
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.EvaluationPermutationBigDomainBitReversed[2*singleSize:3*singleSize])
	if err != nil {
		return n, err
	}
	//Write S1Canonical, S2Canonical, S3Canonical
	n, err = WriteFrArray(w, pk.S1Canonical)
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.S2Canonical)
	if err != nil {
		return n, err
	}
	n, err = WriteFrArray(w, pk.S3Canonical)
	if err != nil {
		return n, err
	}

	return n, nil
}

// ReadFrom reads from binary representation in r into ProvingKey
func (pk *ProvingKey) ReadFrom(r io.Reader) (int64, error) {
	//Read Ql, Qr, Qm, Qo
	var err error
	pk.Ql, err = ReadFrArray(r)
	if err != nil {
		return 0, err
	}
	pk.Qr, err = ReadFrArray(r)
	if err != nil {
		return 0, err
	}
	pk.Qm, err = ReadFrArray(r)
	if err != nil {
		return 0, err
	}
	pk.Qo, err = ReadFrArray(r)
	if err != nil {
		return 0, err
	}
	//Read CQk, LQk
	pk.CQk, err = ReadFrArray(r)
	if err != nil {
		return 0, err
	}
	pk.LQk, err = ReadFrArray(r)
	if err != nil {
		return 0, err
	}
	//Read Domain
	pk.Domain[0].ReadFrom(r)
	pk.Domain[1].ReadFrom(r)
	//Read Permutation
	pk.Permutation, err = ReadInt64Array(r)
	if err != nil {
		return 0, err
	}
	return 0, nil
}

func uint64ArrayToBytes(a []uint64) []byte {
	b := make([]byte, 8*len(a))
	for i := 0; i < len(a); i++ {
		binary.LittleEndian.PutUint64(b[i*8:], a[i])
	}
	return b
}
func BytesToUint64Array(b []byte) []uint64 {
	a := make([]uint64, len(b)/8)
	for i := 0; i < len(a); i++ {
		a[i] = binary.LittleEndian.Uint64(b[i*8:])
	}
	return a
}

func G1AffineToBytes(p bn254.G1Affine) []byte {
	XBytes := uint64ArrayToBytes(p.X[:])
	YBytes := uint64ArrayToBytes(p.Y[:])
	return append(XBytes, YBytes...)
}

func G1AffineArrayToBytes(a []bn254.G1Affine) []byte {
	b := make([]byte, 0)
	for _, v := range a {
		b = append(b, G1AffineToBytes(v)...)
	}
	return b
}

func BytesToG1Affine(b []byte) bn254.G1Affine {
	var p bn254.G1Affine
	copy(p.X[:], BytesToUint64Array(b[:32]))
	copy(p.Y[:], BytesToUint64Array(b[32:]))
	return p
}

func BytesToG1AffineArray(b []byte) []bn254.G1Affine {
	a := make([]bn254.G1Affine, len(b)/64)
	for i := 0; i < len(a); i++ {
		a[i] = BytesToG1Affine(b[i*64 : (i+1)*64])
	}
	return a
}

// WriteTo writes binary encoding of VerifyingKey to w
func (vk *VerifyingKey) WriteTo(w io.Writer) (n int64, err error) {
	// Write vk.Size
	sizeBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBuf, uint64(vk.Size))
	_, err = w.Write(sizeBuf)
	if err != nil {
		return 0, err
	}
	// Write vk.SizeInv
	sizeInvBuf := vk.SizeInv.Bytes()
	_, err = w.Write(sizeInvBuf[:])
	if err != nil {
		return 0, err
	}
	//Write Generator
	GeneratorBuf := vk.Generator.Bytes()
	_, err = w.Write(GeneratorBuf[:])
	if err != nil {
		return 0, err
	}
	//Write NbPublicVariables
	nbPublicVariablesBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(nbPublicVariablesBuf, uint64(vk.NbPublicVariables))
	_, err = w.Write(nbPublicVariablesBuf)
	if err != nil {
		return 0, err
	}
	//Write KZGSRS
	vk.KZGSRS.WriteTo(w)
	//Write CosetShift
	CosetShiftBuf := vk.CosetShift.Bytes()
	_, err = w.Write(CosetShiftBuf[:])
	if err != nil {
		return 0, err
	}
	//Write S
	SBuf := G1AffineArrayToBytes(vk.S[:])
	_, err = w.Write(SBuf)
	if err != nil {
		return 0, err
	}
	//Write Ql, Qr, Qm, Qo, Qk
	QlBuf := G1AffineToBytes(vk.Ql)
	_, err = w.Write(QlBuf[:])
	if err != nil {
		return 0, err
	}
	QrBuf := G1AffineToBytes(vk.Qr)
	_, err = w.Write(QrBuf[:])
	if err != nil {
		return 0, err
	}
	QmBuf := G1AffineToBytes(vk.Qm)
	_, err = w.Write(QmBuf[:])
	if err != nil {
		return 0, err
	}
	QoBuf := G1AffineToBytes(vk.Qo)
	_, err = w.Write(QoBuf[:])
	if err != nil {
		return 0, err
	}
	QkBuf := G1AffineToBytes(vk.Qk)
	_, err = w.Write(QkBuf[:])

	if err != nil {
		return 0, err
	}
	return 0, nil
}

// ReadFrom reads from binary representation in r into VerifyingKey
func (vk *VerifyingKey) ReadFrom(r io.Reader) (int64, error) {
	//Read Size
	sizeBuf := make([]byte, 8)
	_, err := r.Read(sizeBuf)
	if err != nil {
		return 0, err
	}
	vk.Size = binary.LittleEndian.Uint64(sizeBuf)
	//Read SizeInv
	sizeInvBuf := make([]byte, 32)
	_, err = r.Read(sizeInvBuf)
	if err != nil {
		panic(err)
	}
	vk.SizeInv.SetBytes(sizeInvBuf)
	//Read Generator
	GeneratorBuf := make([]byte, 32)
	_, err = r.Read(GeneratorBuf)
	if err != nil {
		panic(err)
	}
	vk.Generator.SetBytes(GeneratorBuf)
	//Read NbPublicVariables
	nbPublicVariablesBuf := make([]byte, 8)
	_, err = r.Read(nbPublicVariablesBuf)
	if err != nil {
		panic(err)
	}
	vk.NbPublicVariables = binary.LittleEndian.Uint64(nbPublicVariablesBuf)
	//Read KZGSRS
	vk.KZGSRS.ReadFrom(r)
	//Read CosetShift
	CosetShiftBuf := make([]byte, 32)
	_, err = r.Read(CosetShiftBuf)
	if err != nil {
		panic(err)
	}
	vk.CosetShift.SetBytes(CosetShiftBuf)
	//Read S
	SBuf := make([]byte, 3*64)
	_, err = r.Read(SBuf)
	if err != nil {
		panic(err)
	}
	res := BytesToG1AffineArray(SBuf)
	for i := 0; i < 3; i++ {
		vk.S[i] = res[i]
	}
	//Read Ql, Qr, Qm, Qo, Qk
	QlBuf := make([]byte, 64)
	_, err = r.Read(QlBuf)
	if err != nil {
		panic(err)
	}
	vk.Ql = BytesToG1Affine(QlBuf)
	QrBuf := make([]byte, 64)
	_, err = r.Read(QrBuf)
	if err != nil {
		panic(err)
	}
	vk.Qr = BytesToG1Affine(QrBuf)
	QmBuf := make([]byte, 64)
	_, err = r.Read(QmBuf)
	if err != nil {
		panic(err)
	}
	vk.Qm = BytesToG1Affine(QmBuf)
	QoBuf := make([]byte, 64)
	_, err = r.Read(QoBuf)
	if err != nil {
		panic(err)
	}
	vk.Qo = BytesToG1Affine(QoBuf)
	QkBuf := make([]byte, 64)
	_, err = r.Read(QkBuf)
	if err != nil {
		panic(err)
	}
	vk.Qk = BytesToG1Affine(QkBuf)
	return 0, nil
}
