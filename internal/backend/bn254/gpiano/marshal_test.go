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

// Modifications Copyright 2023 Tianyi Liu and Tiancheng Xie

package gpiano

import (
	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"bytes"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func TestProvingKeySerialization(t *testing.T) {
	// create a random vk
	var vk VerifyingKey
	vk.SizeY = 10
	vk.SizeYInv.SetOne()
	vk.SizeX = 42
	vk.SizeXInv = fr.One()
	vk.SizeXInv.Add(&vk.SizeXInv, &vk.SizeXInv)

	_, _, g1gen, _ := curve.Generators()
	vk.Sy[0] = g1gen
	vk.Sy[1] = g1gen
	vk.Sy[2] = g1gen
	vk.Sx[0] = g1gen
	vk.Sx[1] = g1gen
	vk.Sx[2] = g1gen
	vk.Ql = g1gen
	vk.Qr = g1gen
	vk.Qm = g1gen
	vk.Qo = g1gen
	vk.Qk = g1gen
	vk.NbPublicVariables = 8000

	// random pk
	var pk ProvingKey
	pk.Vk = &vk
	pk.Domain[0] = *fft.NewDomain(42)
	pk.Domain[1] = *fft.NewDomain(8 * 42)
	pk.Ql = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qr = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qm = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qo = make([]fr.Element, pk.Domain[0].Cardinality)
	pk.Qk = make([]fr.Element, pk.Domain[0].Cardinality)

	for i := 0; i < 12; i++ {
		pk.Ql[i].SetOne().Neg(&pk.Ql[i])
		pk.Qr[i].SetOne()
		pk.Qo[i].SetUint64(42)
	}

	pk.PermutationY = make([]int64, 3*globalDomain[0].Cardinality)
	pk.PermutationX = make([]int64, 3*pk.Domain[0].Cardinality)
	pk.PermutationY[0] = -12
	pk.PermutationX[0] = -11
	pk.PermutationY[len(pk.PermutationY)-1] = 8888
	pk.PermutationX[len(pk.PermutationX)-1] = 8889

	var buf bytes.Buffer
	written, err := pk.WriteTo(&buf)
	if err != nil {
		t.Fatal("coudln't serialize", err)
	}

	var reconstructed ProvingKey

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("coudln't deserialize", err)
	}

	if !reflect.DeepEqual(&pk, &reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}

func TestVerifyingKeySerialization(t *testing.T) {
	// create a random vk
	var vk VerifyingKey
	vk.SizeY = 10
	vk.SizeYInv.SetOne()
	vk.SizeX = 42
	vk.SizeXInv = fr.One()
	vk.SizeXInv.Add(&vk.SizeXInv, &vk.SizeXInv)

	_, _, g1gen, _ := curve.Generators()
	vk.Sy[0] = g1gen
	vk.Sy[1] = g1gen
	vk.Sy[2] = g1gen
	vk.Sx[0] = g1gen
	vk.Sx[1] = g1gen
	vk.Sx[2] = g1gen
	vk.Ql = g1gen
	vk.Qr = g1gen
	vk.Qm = g1gen
	vk.Qo = g1gen
	vk.Qk = g1gen

	var buf bytes.Buffer
	written, err := vk.WriteTo(&buf)
	if err != nil {
		t.Fatal("coudln't serialize", err)
	}

	var reconstructed VerifyingKey

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("coudln't deserialize", err)
	}

	if !reflect.DeepEqual(&vk, &reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}
